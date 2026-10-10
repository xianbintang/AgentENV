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
pub enum SnapshotsGetResponse {
    /// Successfully returned snapshots
    Status200_SuccessfullyReturnedSnapshots {
        body: Vec<models::SnapshotInfo>,
        x_next_token: Option<String>,
    },
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SnapshotsSnapshotIdGetResponse {
    /// Successfully returned the snapshot
    Status200_SuccessfullyReturnedTheSnapshot(models::SnapshotInfo),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

/// Snapshots
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Snapshots<E: std::fmt::Debug + Send + Sync + 'static = ()>:
    super::ErrorHandler<E>
{
    type Claims;

    /// List snapshots.
    ///
    /// SnapshotsGet - GET /snapshots
    fn snapshots_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        query_params: &'life5 models::SnapshotsGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<SnapshotsGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// SnapshotsSnapshotIdGet - GET /snapshots/{snapshotID}
    fn snapshots_snapshot_id_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SnapshotsSnapshotIdGetPathParams,
    ) -> super::ApiFuture<'async_trait, Result<SnapshotsSnapshotIdGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;
}
