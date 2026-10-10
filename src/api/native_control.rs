//! Closed native control routes. Authentication is enforced before proxy classification.
use super::ApiImpl;
use crate::{sandbox::NativeControlRequest, types::SandboxId};
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
#[derive(Clone, Copy)]
pub(crate) struct CallerDigest(pub [u8; 32]);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    epoch: String,
    operation_id: String,
    request: NativeControlRequest,
}
/// Only the canonical, complete route belongs to this API. No host-header routing.
pub(crate) fn route_id(path: &str) -> Option<SandboxId> {
    let id = path
        .strip_prefix("/sandboxes/")?
        .strip_suffix("/native/control")?;
    let parsed = SandboxId::parse_str(id).ok()?;
    (parsed.to_string() == id).then_some(parsed)
}
pub(crate) fn is_native_route(path: &str) -> bool {
    path == "/sandboxes/native/create" || route_id(path).is_some()
}
pub(crate) fn router<I>(state: I) -> Router
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/sandboxes/native/create",
            get(create_capability::<I>).post(create_unavailable),
        )
        .route(
            "/sandboxes/{sandbox_id}/native/control",
            get(capability::<I>).post(control::<I>),
        )
        .layer(axum::extract::DefaultBodyLimit::max(65536))
        .with_state(state)
}
async fn create_capability<I>(
    State(state): State<I>,
    Extension(_): Extension<CallerDigest>,
) -> Response
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    Json(
        json!({"server_incarnation": state.as_ref().orchestrator().native_create_incarnation(),
        "available": false, "worker_fence": null, "reason": "worker_authority_unavailable"}),
    )
    .into_response()
}
async fn create_unavailable(
    Extension(_): Extension<CallerDigest>,
    _body: axum::body::Bytes,
) -> Response {
    // No authority or allocator is installed: never reserve or start a VM.
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}
async fn capability<I>(
    State(state): State<I>,
    Path(raw): Path<String>,
    Extension(_): Extension<CallerDigest>,
) -> Response
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    let Some(id) = canonical(&raw) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match state.as_ref().orchestrator().native_control_for(id).await {
        Some(control) => {
            Json(json!({"epoch":control.epoch(),"operations":control.operations(),"pending":[]}))
                .into_response()
        }
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
struct RequestCustody {
    control: crate::sandbox::NativeControl,
    digest: [u8; 32],
    epoch: String,
    operation_id: String,
    complete: bool,
}
impl Drop for RequestCustody {
    fn drop(&mut self) {
        if !self.complete {
            self.control
                .uncertain(self.digest, &self.epoch, self.operation_id.clone());
        }
    }
}
async fn control<I>(
    State(state): State<I>,
    Path(raw): Path<String>,
    Extension(digest): Extension<CallerDigest>,
    body: Result<Json<ControlRequest>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_request"})),
            )
                .into_response()
        }
    };
    let Some(id) = canonical(&raw) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(control) = state.as_ref().orchestrator().native_control_for(id).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if uuid::Uuid::parse_str(&body.epoch)
        .ok()
        .is_none_or(|id| id.to_string() != body.epoch)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_epoch"})),
        )
            .into_response();
    }
    if body.epoch != control.epoch() {
        return (StatusCode::CONFLICT, Json(json!({"error":"stale_epoch"}))).into_response();
    }
    if body.operation_id.is_empty()
        || body.operation_id.len() > 64
        || !body
            .operation_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        || !body.operation_id.as_bytes()[0].is_ascii_alphanumeric()
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let caller_operation = body.operation_id.clone();
    let mut custody = RequestCustody {
        control: control.clone(),
        digest: digest.0,
        epoch: body.epoch.clone(),
        operation_id: caller_operation.clone(),
        complete: false,
    };
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    match tokio::time::timeout_at(
        tokio::time::Instant::from_std(until),
        control.dispatch(digest.0, &body.epoch, body.operation_id, body.request),
    )
    .await
    {
        Ok(Ok(value)) if std::time::Instant::now() < until => {
            custody.complete = true;
            Json(value).into_response()
        }
        Ok(Err(_)) => {
            // A completed refusal did not lose this HTTP future's custody.
            // Actual I/O failures retain their actor-owned uncertainty markers.
            custody.complete = true;
            (
                StatusCode::CONFLICT,
                Json(json!({"error":"original_unavailable","query_original":true})),
            )
                .into_response()
        }
        _ => {
            control.uncertain(digest.0, &body.epoch, caller_operation);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({"error":"deadline","query_original":true})),
            )
                .into_response()
        }
    }
}
fn canonical(raw: &str) -> Option<SandboxId> {
    let id = SandboxId::parse_str(raw).ok()?;
    (id.to_string() == raw).then_some(id)
}
