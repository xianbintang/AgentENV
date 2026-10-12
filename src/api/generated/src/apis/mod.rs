/// Send future returned by generated object-safe API declarations.
pub type ApiFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub mod admin;
pub mod default;
pub mod sandboxes;
pub mod snapshots;
pub mod templates;
pub mod volumes;

/// API Key Authentication - Header.
#[async_trait::async_trait]
pub trait ApiKeyAuthHeader {
    type Claims;

    /// Extracting Claims from Header. Return None if the Claims are invalid.
    fn extract_claims_from_header<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        headers: &'life1 axum::http::header::HeaderMap,
        key: &'life2 str,
    ) -> ApiFuture<'async_trait, Option<Self::Claims>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BasicAuthKind {
    Basic,
    Bearer,
}

/// API Key Authentication - Authentication Header.
/// For `Basic token` and `Bearer token`
#[async_trait::async_trait]
pub trait ApiAuthBasic {
    type Claims;

    /// Extracting Claims from Header. Return None if the Claims are invalid.
    fn extract_claims_from_auth_header<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        kind: BasicAuthKind,
        headers: &'life1 axum::http::header::HeaderMap,
        key: &'life2 str,
    ) -> ApiFuture<'async_trait, Option<Self::Claims>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait;
}

// Error handler for unhandled errors.
#[async_trait::async_trait]
pub trait ErrorHandler<E: std::fmt::Debug + Send + Sync + 'static = ()> {
    #[allow(unused_variables)]
    #[tracing::instrument(skip_all)]
    async fn handle_error(
        &self,
        method: &::http::Method,
        host: &headers::Host,
        cookies: &axum_extra::extract::CookieJar,
        error: E,
    ) -> Result<axum::response::Response, http::StatusCode> {
        tracing::error!("Unhandled error: {:?}", error);
        axum::response::Response::builder()
            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::empty())
            .map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)
    }
}
