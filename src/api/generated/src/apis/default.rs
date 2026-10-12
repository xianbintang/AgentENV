use async_trait::async_trait;
use axum::extract::*;
use axum_extra::extract::CookieJar;
use bytes::Bytes;
use headers::Host;
use http::Method;
use serde::{Deserialize, Serialize};

use crate::{models, types::*};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum HealthGetResponse {
    /// The service is healthy
    Status204_TheServiceIsHealthy,
    /// Authentication error
    Status401_AuthenticationError(models::Error),
}

/// Default
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Default<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    /// Health check.
    ///
    /// HealthGet - GET /health
    fn health_get<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
    ) -> super::ApiFuture<'async_trait, Result<HealthGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait;
}
