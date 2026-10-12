use super::{proxy::tests::build_api_with_auth_retained, server};
use crate::{sandbox::NativeControl, types::SandboxId};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
const KEY: &str = "e2b_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn request(id: SandboxId, body: Value, key: bool, duplicate: bool) -> Request<Body> {
    let mut r = Request::builder()
        .method("POST")
        .uri(format!("/sandboxes/{id}/native/control"))
        .header("content-type", "application/json")
        .header("host", format!("8000-{id}.native.example.invalid"))
        .body(Body::from(body.to_string()))
        .unwrap();
    if key {
        r.headers_mut().append("x-api-key", KEY.parse().unwrap());
    }
    if duplicate {
        r.headers_mut().append("x-api-key", KEY.parse().unwrap());
    }
    r
}
fn exec(epoch: &str, operation: &str, command: &str) -> Value {
    json!({"epoch":epoch,"operation_id":operation,"request":{"kind":"exec","command":command,"args":[],"env":{},"cwd":null,"timeout_ms":2000}})
}
async fn value(r: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(r.into_body(), 65536).await.unwrap()).unwrap()
}
#[tokio::test]
async fn native_api_missing_duplicate_key_and_proxy_host_never_dispatch() {
    let (api, _root) =
        build_api_with_auth_retained(vec!["native.example.invalid".into()], KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(17);
    let public_epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let mut peer = BufReader::new(peer);
    let mut line = String::new();
    let missing = app
        .clone()
        .oneshot(request(
            id,
            exec(&public_epoch, "a", "/bin/echo"),
            false,
            false,
        ))
        .await
        .unwrap();
    let duplicate = app
        .clone()
        .oneshot(request(
            id,
            exec(&public_epoch, "a", "/bin/echo"),
            true,
            true,
        ))
        .await
        .unwrap();
    let no_effect = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    control.close_test();
    drop(peer);
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(duplicate.status(), StatusCode::UNAUTHORIZED);
    assert!(no_effect);
}
#[tokio::test]
async fn native_api_lost_response_retry_has_original_uuid_and_payload_drift_refuses() {
    let (api, _root) =
        build_api_with_auth_retained(vec!["native.example.invalid".into()], KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(18);
    let public_epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let mut peer = BufReader::new(peer);
    let first = app
        .clone()
        .oneshot(request(
            id,
            exec(&public_epoch, "same", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = value(first).await;
    let mut line = String::new();
    peer.read_line(&mut line).await.unwrap();
    let sent: Value = serde_json::from_str(&line).unwrap();
    // Treat the first HTTP response as lost: retry retains the same actor owner.
    let second = app
        .clone()
        .oneshot(request(
            id,
            exec(&public_epoch, "same", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    let second = value(second).await;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(KEY.as_bytes()).into();
    let before = control
        .original_truth_test(digest, "same")
        .expect("original actor owner");
    let drift = app
        .clone()
        .oneshot(request(
            id,
            exec(&public_epoch, "same", "/bin/cat"),
            true,
            false,
        ))
        .await
        .unwrap();
    let after = control
        .original_truth_test(digest, "same")
        .expect("same original actor owner");
    let third = app
        .clone()
        .oneshot(request(
            id,
            exec(&public_epoch, "same", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    let third = value(third).await;
    line.clear();
    let no_repeat = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    control.close_test();
    drop(peer);
    assert_eq!(first["operation_id"], second["operation_id"]);
    assert_eq!(sent["operation_id"], first["operation_id"]);
    assert_eq!(sent["kind"], "exec");
    assert_eq!(drift.status(), StatusCode::CONFLICT);
    assert!(
        !before.0 && !before.1,
        "real nonterminal original must be known before refusal"
    );
    assert_eq!(
        before, after,
        "FP refusal must preserve original truth and cumulative custody"
    );
    assert_eq!(
        first["operation_id"], third["operation_id"],
        "legitimate original retry remains usable"
    );
    assert!(no_repeat);
}
#[tokio::test]
async fn native_api_closed_lifecycle_gate_and_stale_epoch_cannot_admit() {
    let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(19);
    let public_epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let mut peer = BufReader::new(peer);
    control.close_admission();
    let closed = app
        .clone()
        .oneshot(request(
            id,
            exec(&public_epoch, "closed", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    let stale = app
        .clone()
        .oneshot(request(
            id,
            exec(&uuid::Uuid::now_v7().to_string(), "stale", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    let mut line = String::new();
    let no_effect = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    control.reopen_admission().unwrap();
    let live = app
        .oneshot(request(
            id,
            exec(&public_epoch, "after-rollback", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    peer.read_line(&mut line).await.unwrap();
    let sent: Value = serde_json::from_str(&line).unwrap();
    control.close_test();
    drop(peer);
    assert_eq!(closed.status(), StatusCode::CONFLICT);
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert!(no_effect);
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(sent["kind"], "exec");
}
#[test]
fn native_api_route_and_payload_are_closed() {
    let id = SandboxId::new();
    let route = format!("/sandboxes/{id}/native/control");
    assert_eq!(super::native_control::route_id(&route), Some(id));
    for bad in [
        format!("{route}/"),
        route.to_uppercase(),
        format!("/proxy{route}"),
        format!("{route}?extra"),
    ] {
        assert!(super::native_control::route_id(&bad).is_none());
    }
    assert!(
        serde_json::from_value::<crate::sandbox::NativeControlRequest>(
            json!({"kind":"query","auth_token":"secret"})
        )
        .is_err()
    );
}

#[tokio::test]
async fn native_api_stop_closes_saved_original_client_before_new_mutation() {
    let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(23);
    let public_epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let stopped = api.orchestrator().delete_sandbox(id).await;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(KEY.as_bytes()).into();
    let request =
        serde_json::from_value(exec(&public_epoch, "late", "/bin/echo")["request"].clone())
            .unwrap();
    let denied = control
        .dispatch(digest, &public_epoch, "late".into(), request)
        .await
        .is_err();
    let mut peer = BufReader::new(peer);
    let mut line = String::new();
    let no_effect = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    let route_removed = api.orchestrator().native_control_for(id).await.is_none();
    control.close_test();
    drop(peer);
    assert!(stopped.is_ok() && denied && no_effect && route_removed);
}

#[tokio::test]
async fn native_api_lifecycle_backend_boundaries_close_admission_and_keep_epoch_on_rollback() {
    use crate::sandbox::mock::{MockAction, MockOperation};
    use futures::FutureExt;
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    for operation in [
        MockOperation::Stop,
        MockOperation::Pause,
        MockOperation::Snapshot,
    ] {
        let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
        let id = SandboxId::new();
        let (control, peer) = NativeControl::test_pair(29);
        let public_epoch = control.epoch().to_owned();
        let behavior = api
            .orchestrator()
            .set_native_control_for_test(id, control.clone())
            .await;
        let closed = Arc::new(AtomicBool::new(false));
        let observed = closed.clone();
        let original = control.clone();
        behavior.set_on_operation(
            operation,
            Arc::new(move || {
                let request = serde_json::from_value(
                    exec(original.epoch(), "at-boundary", "/bin/echo")["request"].clone(),
                )
                .unwrap();
                let result = original
                    .dispatch(
                        Sha256::digest(KEY.as_bytes()).into(),
                        original.epoch(),
                        "at-boundary".into(),
                        request,
                    )
                    .now_or_never();
                observed.store(result.is_some_and(|r| r.is_err()), Ordering::Release);
            }),
        );
        behavior.push_action(
            operation,
            MockAction::Fail {
                message: "controlled lifecycle rejection".into(),
            },
        );
        let failed = match operation {
            MockOperation::Stop => api.orchestrator().delete_sandbox(id).await.is_err(),
            MockOperation::Pause => api.orchestrator().pause_sandbox(id).await.is_err(),
            MockOperation::Snapshot => api.orchestrator().capture_snapshot(id).await.is_err(),
            _ => unreachable!(),
        };
        let retained = api.orchestrator().native_control_for(id).await;
        let epoch = retained.as_ref().map(|c| c.epoch().to_owned());
        if operation == MockOperation::Stop {
            let retained = retained
                .as_ref()
                .expect("failed Stop retains original control");
            let request = serde_json::from_value(
                exec(retained.epoch(), "after-failed-stop", "/bin/echo")["request"].clone(),
            )
            .unwrap();
            assert!(
                retained
                    .dispatch(
                        Sha256::digest(KEY.as_bytes()).into(),
                        retained.epoch(),
                        "after-failed-stop".into(),
                        request,
                    )
                    .await
                    .is_err(),
                "retained query route must not reopen new effect admission"
            );
        }
        let mut peer = BufReader::new(peer);
        let mut line = String::new();
        let no_effect = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            peer.read_line(&mut line),
        )
        .await
        .is_err();
        control.close_test();
        drop(peer);
        assert!(
            failed && closed.load(Ordering::Acquire) && no_effect,
            "controlled backend boundary {operation:?}"
        );
        assert_eq!(
            epoch,
            Some(public_epoch),
            "rollback must preserve original publication epoch"
        );
    }
}

#[tokio::test]
async fn native_api_fresh_orchestrator_old_epoch_cannot_dispatch_new_incarnation() {
    let (api_a, _root_a) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let (api_b, _root_b) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let id = SandboxId::new();
    let (control_a, peer_a) = NativeControl::test_unpublished_pair();
    let (control_b, peer_b) = NativeControl::test_unpublished_pair();
    let published_a = api_a
        .orchestrator()
        .publish_native_control_for_test(id, control_a.clone())
        .await;
    let published_b = api_b
        .orchestrator()
        .publish_native_control_for_test(id, control_b.clone())
        .await;
    let app_a = server::new(api_a);
    let app_b = server::new(api_b);
    let capability = |id| {
        Request::builder()
            .method("GET")
            .uri(format!("/sandboxes/{id}/native/control"))
            .header("x-api-key", KEY)
            .body(Body::empty())
            .unwrap()
    };
    let cap_a = value(app_a.clone().oneshot(capability(id)).await.unwrap()).await;
    let cap_b = value(app_b.clone().oneshot(capability(id)).await.unwrap()).await;
    let mut body = exec("", "same-original", "/bin/echo");
    body["epoch"] = cap_a["epoch"].clone();
    let first = app_a
        .oneshot(request(id, body.clone(), true, false))
        .await
        .unwrap();
    let mut peer_a = BufReader::new(peer_a);
    let mut line = String::new();
    peer_a.read_line(&mut line).await.unwrap();
    let first_frame: Value = serde_json::from_str(&line).unwrap();
    let stale = app_b.oneshot(request(id, body, true, false)).await.unwrap();
    let mut peer_b = BufReader::new(peer_b);
    line.clear();
    let no_new_effect = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer_b.read_line(&mut line),
    )
    .await
    .is_err();
    let distinct_epoch = cap_a["epoch"] != cap_b["epoch"];
    control_a.close_test();
    control_b.close_test();
    drop(peer_a);
    drop(peer_b);
    assert!(
        published_a
            && published_b
            && first.status() == StatusCode::OK
            && first_frame["kind"] == "exec"
    );
    assert!(
        stale.status() == StatusCode::CONFLICT && no_new_effect && distinct_epoch,
        "stale_refused={} no_new_effect={no_new_effect} distinct_epoch={distinct_epoch}",
        stale.status() == StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn native_api_epoch_rejects_numeric_foreign_and_noncanonical_before_effect() {
    let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(31);
    let epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let mut numeric = exec(&epoch, "numeric", "/bin/echo");
    numeric["epoch"] = json!(31);
    let numeric = app
        .clone()
        .oneshot(request(id, numeric, true, false))
        .await
        .unwrap();
    let foreign = app
        .clone()
        .oneshot(request(
            id,
            exec(&uuid::Uuid::nil().to_string(), "foreign", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    let noncanonical = uuid::Uuid::parse_str(&epoch).unwrap().simple().to_string();
    let noncanonical = app
        .clone()
        .oneshot(request(
            id,
            exec(&noncanonical, "noncanonical", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    let mut peer = BufReader::new(peer);
    let mut line = String::new();
    let no_effect = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    let valid = app
        .oneshot(request(id, exec(&epoch, "valid", "/bin/echo"), true, false))
        .await
        .unwrap();
    let valid_status = valid.status();
    let response = value(valid).await;
    peer.read_line(&mut line).await.unwrap();
    let frame: Value = serde_json::from_str(&line).unwrap();
    control.close_test();
    drop(peer);
    assert_eq!(numeric.status(), StatusCode::BAD_REQUEST);
    assert_eq!(foreign.status(), StatusCode::CONFLICT);
    assert_eq!(noncanonical.status(), StatusCode::BAD_REQUEST);
    assert!(no_effect);
    assert_eq!(valid_status, StatusCode::OK);
    assert_eq!(response["epoch"], epoch);
    assert_eq!(frame["session_id"], epoch);
    assert_eq!(frame["kind"], "exec");
}

#[tokio::test]
async fn native_api_keyed_stat_admits_one_original_and_exact_retry_never_rebegins() {
    let (api, _root) =
        build_api_with_auth_retained(vec!["native.example.invalid".into()], KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(37);
    let epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let body =
        json!({"epoch":epoch,"operation_id":"stat-original","request":{"kind":"stat","path":"."}});
    let missing = app
        .clone()
        .oneshot(request(id, body.clone(), false, false))
        .await
        .unwrap();
    let duplicate = app
        .clone()
        .oneshot(request(id, body.clone(), true, true))
        .await
        .unwrap();
    let mut stale = body.clone();
    stale["epoch"] = json!(uuid::Uuid::now_v7().to_string());
    let stale = app
        .clone()
        .oneshot(request(id, stale, true, false))
        .await
        .unwrap();
    let mut extra = body.clone();
    extra["request"]["unexpected"] = json!(true);
    let extra = app
        .clone()
        .oneshot(request(id, extra, true, false))
        .await
        .unwrap();
    let mut peer = BufReader::new(peer);
    let mut line = String::new();
    let rejected_zero_effect = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    let first = app
        .clone()
        .oneshot(request(id, body.clone(), true, false))
        .await
        .unwrap();
    let first_status = first.status();
    let first = value(first).await;
    line.clear();
    let frame = match tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => serde_json::from_str::<Value>(&line).ok(),
        _ => None,
    };
    let retry = app.oneshot(request(id, body, true, false)).await.unwrap();
    let retry_status = retry.status();
    let retry = value(retry).await;
    line.clear();
    let no_rebegin = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    control.close_test();
    drop(peer);
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(duplicate.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(extra.status(), StatusCode::BAD_REQUEST);
    assert!(rejected_zero_effect);
    let admitted = first_status == StatusCode::OK && first["kind"] == "accepted";
    let original_wire = frame.as_ref().is_some_and(|f| {
        f["kind"] == "file_stat"
            && f["session_id"] == epoch
            && f["operation_id"] == first["operation_id"]
            && f["payload"] == json!({"path":"."})
    });
    let original_retry = retry_status == StatusCode::OK
        && retry["operation_id"] == first["operation_id"]
        && retry["session_id"] == first["session_id"];
    assert!(admitted&&original_wire&&original_retry&&no_rebegin,"admitted={admitted} original_wire={original_wire} original_retry={original_retry} no_rebegin={no_rebegin}");
}

fn metadata_version() -> Value {
    json!({"device":1,"inode":2,"size":0,"mtime_seconds":0,"mtime_nanos":0,"ctime_seconds":0,"ctime_nanos":0})
}
fn metadata_entry(name: &str) -> Value {
    json!({"name":name,"type":"file","path":name,"size":0,"mode":0o100600,"permissions":"rw-------","owner":"1000","group":"1000","modified_time":{"seconds":0,"nanos":0},"symlink_target":null,"version":metadata_version()})
}
async fn metadata_frame(peer: &mut BufReader<tokio::io::DuplexStream>) -> Value {
    let mut line = String::new();
    tokio::time::timeout(std::time::Duration::from_secs(1), peer.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}
async fn metadata_reply(
    peer: &mut BufReader<tokio::io::DuplexStream>,
    original: &Value,
    kind: &str,
    payload: Value,
) {
    let mut wire=serde_json::to_vec(&json!({"kind":kind,"session_id":original["session_id"],"operation_id":original["operation_id"],"payload":payload})).unwrap();
    wire.push(b'\n');
    peer.get_mut().write_all(&wire).await.unwrap();
}
async fn metadata_http_roundtrip(
    app: axum::Router,
    id: SandboxId,
    epoch: &str,
    key: &str,
    phase: Value,
    peer: &mut BufReader<tokio::io::DuplexStream>,
    reply: (&Value, &str, Value),
) -> (StatusCode, Value, Value) {
    let body = json!({"epoch":epoch,"operation_id":key,"request":phase});
    let task =
        tokio::spawn(async move { app.oneshot(request(id, body, true, false)).await.unwrap() });
    let wire = metadata_frame(peer).await;
    metadata_reply(peer, reply.0, reply.1, reply.2).await;
    let response = task.await.unwrap();
    let status = response.status();
    (status, value(response).await, wire)
}
#[tokio::test]
async fn native_api_list_early_summary_pages_retry_illegal_boundary_and_final_slot() {
    let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(43);
    let epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let mut peer = BufReader::new(peer);
    let begin =
        json!({"epoch":epoch,"operation_id":"list-original","request":{"kind":"list","path":"."}});
    let response = app
        .clone()
        .oneshot(request(id, begin.clone(), true, false))
        .await
        .unwrap();
    let accepted = value(response).await;
    let original = metadata_frame(&mut peer).await;
    let entries = json!([metadata_entry("a"), metadata_entry("b")]);
    let sha = guest_lexical_test_digest(entries.clone());
    let summary = json!({"path":".","count":2,"snapshot_sha256":sha,"version":metadata_version()});
    let (summary_status, early, query) = metadata_http_roundtrip(
        app.clone(),
        id,
        &epoch,
        "list-original",
        json!({"kind":"query"}),
        &mut peer,
        (&original, "list_result", summary.clone()),
    )
    .await;
    let retry = app
        .clone()
        .oneshot(request(id, begin, true, false))
        .await
        .unwrap();
    let retry = value(retry).await;
    let invalid=app.clone().oneshot(request(id,json!({"epoch":epoch,"operation_id":"list-original","request":{"kind":"list_next","cursor":99}}),true,false)).await.unwrap();
    let second=app.clone().oneshot(request(id,json!({"epoch":epoch,"operation_id":"queued-stat","request":{"kind":"stat","path":"missing"}}),true,false)).await.unwrap();
    let second = value(second).await;
    let mut line = String::new();
    let held = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    let mut pages = Vec::new();
    let mut wire_ok = true;
    for cursor in 0..2 {
        let page = json!({"path":".","cursor":cursor,"next_cursor":cursor+1,"count":2,"entries":[entries[cursor as usize]],"snapshot_sha256":sha,"version":metadata_version()});
        let (status, response, wire) = metadata_http_roundtrip(
            app.clone(),
            id,
            &epoch,
            "list-original",
            json!({"kind":"list_next","cursor":cursor}),
            &mut peer,
            (&original, "list_page", page.clone()),
        )
        .await;
        wire_ok &= status == StatusCode::OK
            && wire["kind"] == "list_next"
            && wire["operation_id"] == original["operation_id"]
            && response["result"]["cursor"] == cursor;
        pages.push(page);
    }
    let dispatched = metadata_frame(&mut peer).await;
    metadata_reply(
        &mut peer,
        &dispatched,
        "file_stat_result",
        json!({"path":"missing","entry":null}),
    )
    .await;
    let projected=app.clone().oneshot(request(id,json!({"epoch":epoch,"operation_id":"list-original","request":{"kind":"list_page","cursor":0}}),true,false)).await.unwrap();
    let projected = value(projected).await;
    let (final_status, final_result, final_query) = metadata_http_roundtrip(
        app.clone(),
        id,
        &epoch,
        "list-original",
        json!({"kind":"query"}),
        &mut peer,
        (&original, "list_result", summary),
    )
    .await;
    let mut drift = json!({"epoch":epoch,"operation_id":"list-original","request":{"kind":"list","path":"different"}});
    let drift_response = app
        .clone()
        .oneshot(request(id, drift.take(), true, false))
        .await
        .unwrap();
    let preserved=app.clone().oneshot(request(id,json!({"epoch":epoch,"operation_id":"list-original","request":{"kind":"list_page","cursor":0}}),true,false)).await.unwrap();
    let preserved = value(preserved).await;
    line.clear();
    let no_rebegin = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    control.close_test();
    drop(peer);
    assert_eq!(original["kind"], "list_begin");
    assert_eq!(accepted["operation_id"], retry["operation_id"]);
    assert_eq!(summary_status, StatusCode::OK);
    assert_eq!(query["kind"], "query");
    assert_eq!(early["result"]["complete"], false);
    assert_eq!(invalid.status(), StatusCode::CONFLICT);
    assert!(held && wire_ok && no_rebegin);
    assert_eq!(dispatched["operation_id"], second["operation_id"]);
    assert_eq!(projected["result"]["entries"], pages[0]["entries"]);
    assert_eq!(final_status, StatusCode::OK);
    assert_eq!(final_result["result"]["complete"], true);
    assert_eq!(final_query["operation_id"], original["operation_id"]);
    assert_eq!(drift_response.status(), StatusCode::CONFLICT);
    assert_eq!(preserved, projected);
}
#[tokio::test]
async fn native_api_empty_list_mkdir_and_lifecycle_metadata_gate() {
    use sha2::{Digest, Sha256};
    let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(47);
    let epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let mut peer = BufReader::new(peer);
    let empty = app
        .clone()
        .oneshot(request(
            id,
            json!({"epoch":epoch,"operation_id":"empty","request":{"kind":"list","path":"."}}),
            true,
            false,
        ))
        .await
        .unwrap();
    let empty = value(empty).await;
    let original = metadata_frame(&mut peer).await;
    let sha = format!("{:x}", Sha256::digest(b"[]"));
    metadata_reply(&mut peer,&original,"list_page",json!({"path":".","cursor":0,"next_cursor":0,"count":0,"entries":[],"snapshot_sha256":sha,"version":metadata_version()})).await;
    let (_, response, next) = metadata_http_roundtrip(
        app.clone(),
        id,
        &epoch,
        "empty",
        json!({"kind":"list_next","cursor":0}),
        &mut peer,
        (
            &original,
            "list_result",
            json!({"path":".","count":0,"snapshot_sha256":sha,"version":metadata_version()}),
        ),
    )
    .await;
    let mkdir = app
        .clone()
        .oneshot(request(
            id,
            json!({"epoch":epoch,"operation_id":"directory","request":{"kind":"mkdir","path":"d"}}),
            true,
            false,
        ))
        .await
        .unwrap();
    let mkdir = value(mkdir).await;
    let mkdir_wire = metadata_frame(&mut peer).await;
    let mut entry = metadata_entry("d");
    entry["type"] = json!("directory");
    entry["mode"] = json!(0o040700);
    entry["permissions"] = json!("rwx------");
    metadata_reply(
        &mut peer,
        &mkdir_wire,
        "make_dir_result",
        json!({"path":"d","entry":entry.clone()}),
    )
    .await;
    let (_, result, query) = metadata_http_roundtrip(
        app.clone(),
        id,
        &epoch,
        "directory",
        json!({"kind":"query"}),
        &mut peer,
        (
            &mkdir_wire,
            "make_dir_result",
            json!({"path":"d","entry":entry}),
        ),
    )
    .await;
    control.close_admission();
    let mut denied = true;
    for kind in ["stat", "list", "mkdir"] {
        let r=app.clone().oneshot(request(id,json!({"epoch":epoch,"operation_id":format!("closed-{kind}"),"request":{"kind":kind,"path":"x"}}),true,false)).await.unwrap();
        denied &= r.status() == StatusCode::CONFLICT;
    }
    let mut line = String::new();
    let no_effect = tokio::time::timeout(
        std::time::Duration::from_millis(30),
        peer.read_line(&mut line),
    )
    .await
    .is_err();
    control.close_test();
    drop(peer);
    assert_eq!(empty["operation_id"], next["operation_id"]);
    assert_eq!(response["result"]["complete"], true);
    assert_eq!(
        response["result"]["kind"], "list_result",
        "empty final must project actual authenticated ListResult, not cached Page0"
    );
    assert_eq!(mkdir_wire["kind"], "make_dir");
    assert_eq!(mkdir["operation_id"], query["operation_id"]);
    assert_eq!(result["result"]["kind"], "make_dir_result");
    assert!(denied && no_effect);
}

#[tokio::test]
async fn native_api_metadata_query_status_cannot_refresh_cached_receipt() {
    let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(53);
    let epoch = control.epoch().to_owned();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let mut peer = BufReader::new(peer);
    let admitted=app.clone().oneshot(request(id,json!({"epoch":epoch,"operation_id":"stat-known","request":{"kind":"stat","path":"missing"}}),true,false)).await.unwrap();
    let admitted = value(admitted).await;
    let original = metadata_frame(&mut peer).await;
    metadata_reply(
        &mut peer,
        &original,
        "file_stat_result",
        json!({"path":"missing","entry":null}),
    )
    .await;
    let (_, first, _) = metadata_http_roundtrip(
        app.clone(),
        id,
        &epoch,
        "stat-known",
        json!({"kind":"query"}),
        &mut peer,
        (
            &original,
            "file_stat_result",
            json!({"path":"missing","entry":null}),
        ),
    )
    .await;
    let body = json!({"epoch":epoch,"operation_id":"stat-known","request":{"kind":"query"}});
    let mut query =
        tokio::spawn(async move { app.oneshot(request(id, body, true, false)).await.unwrap() });
    let query_frame = metadata_frame(&mut peer).await;
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(KEY.as_bytes()).into();
    let before_status = control.original_truth_test(digest, "stat-known").unwrap().2;
    metadata_reply(&mut peer, &original, "status", json!({"state":"terminal"})).await;
    let status_consumed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if control
                .original_truth_test(digest, "stat-known")
                .is_some_and(|truth| truth.2 > before_status)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let response = tokio::time::timeout(std::time::Duration::from_millis(30), &mut query).await;
    let stays_pending = response.is_err();
    let projected_old = match response {
        Ok(Ok(response)) => {
            let status = response.status();
            let value = value(response).await;
            status == StatusCode::OK && value["result"]["kind"] == "file_stat_result"
        }
        _ => false,
    };
    if stays_pending {
        query.abort();
        let _ = query.await;
    }
    control.close_test();
    drop(peer);
    assert_eq!(admitted["operation_id"], query_frame["operation_id"]);
    assert_eq!(query_frame["kind"], "query");
    assert_eq!(first["result"]["kind"], "file_stat_result");
    assert!(
        status_consumed && stays_pending && !projected_old,
        "status_consumed={status_consumed} stays_pending={stays_pending} projected_old={projected_old}"
    );
}

fn guest_lexical_test_digest(value: serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    fn lexical(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let sorted: std::collections::BTreeMap<_, _> = map
                    .into_iter()
                    .map(|(key, value)| (key, lexical(value)))
                    .collect();
                serde_json::Value::Object(sorted.into_iter().collect())
            }
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(lexical).collect())
            }
            value => value,
        }
    }
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&lexical(value)).unwrap())
    )
}

#[tokio::test]
async fn native_api_capability_omits_downloads_without_actual_protected_backing() {
    let (api, _root) =
        build_api_with_auth_retained(vec!["native.example.invalid".into()], KEY).await;
    // The existing constructor installs a real actor/pipe with download_spool=None.
    // This is a backing-capability boundary, not physical guest authentication proof.
    let (control, peer) = NativeControl::test_pair(49);
    let id = SandboxId::new();
    api.orchestrator()
        .set_native_control_for_test(id, control.clone())
        .await;
    let app = server::new(api);
    let capability = Request::builder()
        .method("GET")
        .uri(format!("/sandboxes/{id}/native/control"))
        .header("x-api-key", KEY)
        .header("host", format!("8000-{id}.native.example.invalid"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(capability).await.unwrap();
    let successful = response.status().is_success();
    let body = value(response).await;
    let operations = body["operations"].as_array().unwrap();
    let exec_available = operations.iter().any(|v| v == "exec");
    let downloads_advertised = operations.iter().any(|v| {
        matches!(
            v.as_str(),
            Some("download_begin" | "download_receive" | "download_read")
        )
    });
    let directory_advertised = operations
        .iter()
        .any(|v| v.as_str().is_some_and(|s| s.starts_with("directory_")));
    // Close the exact actor before the failing RED assertion.
    control.close_test();
    drop(peer);
    assert!(successful && exec_available && !downloads_advertised && !directory_advertised,
        "successful={successful} exec_available={exec_available} downloads_advertised={downloads_advertised} directory_advertised={directory_advertised}");
}

#[tokio::test]
async fn native_create_collection_exposes_authenticated_original_incarnation_without_vm_effects() {
    let (api, _root) =
        build_api_with_auth_retained(vec!["native.example.invalid".into()], KEY).await;
    let app = server::new(api);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/sandboxes/native/create")
                .header("x-api-key", KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let successful = response.status() == StatusCode::OK;
    let raw = to_bytes(response.into_body(), 65536).await.unwrap();
    let payload = serde_json::from_slice::<Value>(&raw).ok();
    let incarnation = payload
        .as_ref()
        .and_then(|v| v["server_incarnation"].as_str());
    let canonical_incarnation = incarnation.is_some_and(|s| {
        uuid::Uuid::parse_str(s).is_ok_and(|id| id.to_string() == s && id.get_version_num() == 7)
    });
    let unavailable = payload.as_ref().is_some_and(|v| {
        v["available"] == false
            && v["worker_fence"].is_null()
            && v["reason"] == "worker_authority_unavailable"
            && v.as_object().is_some_and(|o| o.len() == 4)
    });
    let post = app.oneshot(Request::builder().method("POST")
        .uri("/sandboxes/native/create").header("x-api-key", KEY)
        .header("content-type", "application/json")
        .body(Body::from(json!({"server_incarnation":incarnation.unwrap_or("00000000-0000-7000-8000-000000000001"),
            "worker_fence":null,"operation_id":"original-create",
            "request":{"kind":"create","profile_allocation_id":"unallocated",
                "resources":{"cpu":1,"memory":128,"disk":0},"user":"1000",
                "cwd":"/workspace","timeout_ms":30000}}).to_string())).unwrap())
        .await.unwrap();
    let post_refused = post.status() == StatusCode::SERVICE_UNAVAILABLE;
    assert!(successful && canonical_incarnation && unavailable && post_refused,
        "successful={successful} canonical_incarnation={canonical_incarnation} unavailable={unavailable} post_refused={post_refused}");
}

#[tokio::test]
async fn native_create_unavailable_collection_auth_bounds_and_incarnation_are_stable() {
    let (api, _root) =
        build_api_with_auth_retained(vec!["native.example.invalid".into()], KEY).await;
    let app = server::new(api);
    let proxy_id = SandboxId::new();
    for duplicate in [false, true] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/sandboxes/native/create")
            .header("host", format!("8000-{proxy_id}.native.example.invalid"))
            .body(Body::from(vec![b'x'; 65537]))
            .unwrap();
        if duplicate {
            request
                .headers_mut()
                .append("x-api-key", KEY.parse().unwrap());
            request
                .headers_mut()
                .append("x-api-key", KEY.parse().unwrap());
        }
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let get = || {
        Request::builder()
            .uri("/sandboxes/native/create")
            .header("x-api-key", KEY)
            .header("host", format!("8000-{proxy_id}.native.example.invalid"))
            .body(Body::empty())
            .unwrap()
    };
    let first = value(app.clone().oneshot(get()).await.unwrap()).await;
    let second = value(app.clone().oneshot(get()).await.unwrap()).await;
    assert_eq!(first, second);
    let oversized = Request::builder()
        .method("POST")
        .uri("/sandboxes/native/create")
        .header("x-api-key", KEY)
        .body(Body::from(vec![b'x'; 65537]))
        .unwrap();
    assert_eq!(
        app.oneshot(oversized).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(super::native_control::is_native_route(
        "/sandboxes/native/create"
    ));
    assert!(!super::native_control::is_native_route(
        "/sandboxes/native/create/"
    ));
}

#[tokio::test]
async fn native_api_failed_stop_keeps_original_query_sealed_until_retry() {
    use crate::sandbox::mock::{MockAction, MockOperation};
    let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
    let owner = api.orchestrator();
    let id = SandboxId::new();
    let (control, peer) = NativeControl::test_pair(31);
    let epoch = control.epoch().to_owned();
    let behavior = owner.set_native_control_for_test(id, control.clone()).await;
    let app = server::new(api);
    let mut peer = BufReader::new(peer);
    let admitted = app
        .clone()
        .oneshot(request(
            id,
            exec(&epoch, "original", "/bin/echo"),
            true,
            false,
        ))
        .await
        .unwrap();
    assert_eq!(admitted.status(), StatusCode::OK);
    let admitted = value(admitted).await;
    let original = metadata_frame(&mut peer).await;
    behavior.push_action(
        MockOperation::Stop,
        MockAction::Fail {
            message: "original stop uncertain".into(),
        },
    );
    let failed = owner.delete_sandbox(id).await.is_err();
    let retained_epoch = owner
        .native_control_for(id)
        .await
        .map(|c| c.epoch().to_owned());
    let denied = app
        .clone()
        .oneshot(request(id, exec(&epoch, "new", "/bin/echo"), true, false))
        .await
        .unwrap();
    let denied = denied.status() != StatusCode::OK;
    let query_body = json!({"epoch":epoch,"operation_id":"original","request":{"kind":"query"}});
    let query_app = app.clone();
    let query = tokio::spawn(async move {
        query_app
            .oneshot(request(id, query_body, true, false))
            .await
            .unwrap()
    });
    let query_frame = metadata_frame(&mut peer).await;
    metadata_reply(
        &mut peer,
        &original,
        "status",
        json!({"state":"running","acked_sequence":0}),
    )
    .await;
    let queried = query.await.unwrap();
    let query_ok = queried.status() == StatusCode::OK;
    let queried = value(queried).await;
    let retired = owner.delete_sandbox(id).await.is_ok();
    let removed = owner.native_control_for(id).await.is_none();
    control.close_test();
    drop(peer);
    assert!(failed && denied && query_ok && retired && removed);
    assert_eq!(retained_epoch.as_deref(), Some(epoch.as_str()));
    assert_eq!(query_frame["kind"], "query");
    assert_eq!(query_frame["operation_id"], original["operation_id"]);
    assert_eq!(queried["result"]["operation_id"], admitted["operation_id"]);
    assert_eq!(queried["result"]["state"], "running");
    assert_eq!(behavior.stop_calls(), 2);
}

// Real original actor + authenticated public API; lifecycle backend faults are
// scripted. This does not claim physical VM capture or Stop qualification.
#[tokio::test]
async fn native_api_terminal_capture_failed_stop_retains_original_query_and_output() {
    use crate::orchestrator::SandboxState;
    use crate::sandbox::mock::{MockAction, MockOperation};
    use std::time::Duration;
    for operation in [MockOperation::Pause, MockOperation::Snapshot] {
        let (api, _root) = build_api_with_auth_retained(Vec::new(), KEY).await;
        let owner = api.orchestrator();
        let id = SandboxId::new();
        let (control, peer) = NativeControl::test_pair(41);
        let epoch = control.epoch().to_owned();
        let behavior = owner.set_native_control_for_test(id, control.clone()).await;
        let capacity = owner.metrics_snapshot().await.unwrap();
        assert!(capacity.allocated_cpu > 0 && capacity.allocated_memory_bytes > 0);
        let app = server::new(api);
        let mut peer = BufReader::new(peer);
        let admitted = app
            .clone()
            .oneshot(request(
                id,
                exec(&epoch, "original", "/bin/echo"),
                true,
                false,
            ))
            .await
            .unwrap();
        assert_eq!(admitted.status(), StatusCode::OK);
        let admitted = value(admitted).await;
        let original = metadata_frame(&mut peer).await;
        assert_eq!(original["kind"], "exec");
        metadata_reply(
            &mut peer,
            &original,
            "output",
            json!({"sequence":0,"stream":"stdout","data":"eA=="}),
        )
        .await;
        let retained_output = metadata_frame(&mut peer).await;
        assert_eq!(retained_output["kind"], "retain_ack");
        assert_eq!(retained_output["operation_id"], original["operation_id"]);
        behavior.push_action(
            operation,
            MockAction::FailTerminal {
                message: "terminal original capture".into(),
            },
        );
        behavior.push_action(
            MockOperation::Stop,
            MockAction::Fail {
                message: "original Stop unknown".into(),
            },
        );
        let failed = tokio::time::timeout(Duration::from_secs(2), async {
            if operation == MockOperation::Pause {
                owner.pause_sandbox(id).await
            } else {
                owner.capture_snapshot(id).await.map(|_| ())
            }
        })
        .await
        .expect("bounded terminal capture");
        assert!(failed.is_err());
        assert_eq!(
            owner.get_sandbox(&id).await.unwrap().unwrap().state,
            SandboxState::Killing
        );
        // Same backend Arc and Stop{capture_failed:true} are separately checked
        // by the orchestrator terminal-capture regressions; no custody getter.
        assert_eq!(owner.metrics_snapshot().await.unwrap(), capacity);
        assert_eq!(behavior.stop_calls(), 1);
        assert_eq!(
            owner
                .native_control_for(id)
                .await
                .map(|c| c.epoch().to_owned())
                .as_deref(),
            Some(epoch.as_str())
        );
        let denied = app
            .clone()
            .oneshot(request(id, exec(&epoch, "new", "/bin/echo"), true, false))
            .await
            .unwrap();
        assert_ne!(denied.status(), StatusCode::OK);
        let query = tokio::spawn({
            let app = app.clone();
            let epoch = epoch.clone();
            async move {
                app.oneshot(request(
                    id,
                    json!({"epoch":epoch,"operation_id":"original","request":{"kind":"query"}}),
                    true,
                    false,
                ))
                .await
                .unwrap()
            }
        });
        let query_frame = metadata_frame(&mut peer).await;
        // A forbidden second Exec would be the next frame and fail this check.
        assert_eq!(query_frame["kind"], "query");
        assert_eq!(query_frame["session_id"], original["session_id"]);
        assert_eq!(query_frame["operation_id"], original["operation_id"]);
        metadata_reply(
            &mut peer,
            &original,
            "status",
            json!({"state":"running","acked_sequence":0}),
        )
        .await;
        let queried = tokio::time::timeout(Duration::from_secs(2), query)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(queried.status(), StatusCode::OK);
        let queried = value(queried).await;
        assert_eq!(queried["result"]["operation_id"], admitted["operation_id"]);
        let output = app.clone().oneshot(request(id, json!({"epoch":epoch,"operation_id":"original","request":{"kind":"exec_read","stream":"stdout","offset":0,"length":1}}), true, false)).await.unwrap();
        assert_eq!(output.status(), StatusCode::OK);
        let output = value(output).await;
        assert_eq!(output["kind"], "output");
        assert_eq!(output["session_id"], original["session_id"]);
        assert_eq!(output["operation_id"], original["operation_id"]);
        assert_eq!(output["data"], "eA==");
        assert_eq!(output["retained_bytes"], 1);
        assert_eq!(owner.metrics_snapshot().await.unwrap(), capacity);
        tokio::time::timeout(Duration::from_secs(2), owner.delete_sandbox(id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(behavior.stop_calls(), 2);
        assert!(owner.get_sandbox(&id).await.unwrap().is_none());
        assert!(owner.native_control_for(id).await.is_none());
        let released = owner.metrics_snapshot().await.unwrap();
        assert_eq!(released.allocated_cpu, 0);
        assert_eq!(released.allocated_memory_bytes, 0);
        let mut extra = String::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), peer.read_line(&mut extra))
                .await
                .is_err()
        );
        control.close_test();
        drop(peer);
    }
}
