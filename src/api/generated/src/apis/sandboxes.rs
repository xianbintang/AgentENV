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
pub enum SandboxesColdPostResponse {
    /// The sandbox was created successfully
    Status201_TheSandboxWasCreatedSuccessfully {
        body: models::Sandbox,
        x_agentenv_sandbox_id: Option<String>,
    },
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesGetResponse {
    /// Successfully returned all running sandboxes
    Status200_SuccessfullyReturnedAllRunningSandboxes(Vec<models::ListedSandbox>),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesMetricsGetResponse {
    /// Successfully returned all running sandboxes with metrics
    Status200_SuccessfullyReturnedAllRunningSandboxesWithMetrics(models::SandboxesWithMetrics),
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
pub enum SandboxesPostResponse {
    /// The sandbox was created successfully
    Status201_TheSandboxWasCreatedSuccessfully {
        body: models::Sandbox,
        x_agentenv_sandbox_id: Option<String>,
    },
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdConnectPostResponse {
    /// The sandbox was already running
    Status200_TheSandboxWasAlreadyRunning(models::Sandbox),
    /// The sandbox was resumed successfully
    Status201_TheSandboxWasResumedSuccessfully(models::Sandbox),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdCustomExtensionParamsGetResponse {
    /// The current custom extension params
    Status200_TheCurrentCustomExtensionParams(
        std::collections::HashMap<String, crate::types::Object>,
    ),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdCustomExtensionParamsPatchResponse {
    /// The updated full custom extension params
    Status200_TheUpdatedFullCustomExtensionParams(
        std::collections::HashMap<String, crate::types::Object>,
    ),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdDeleteResponse {
    /// The sandbox was killed successfully
    Status204_TheSandboxWasKilledSuccessfully,
    /// Not found
    Status404_NotFound(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdForkPostResponse {
    /// The sandbox was snapshotted and the forks were attempted; each entry reports one fork's outcome
    Status201_TheSandboxWasSnapshottedAndTheForksWereAttempted(Vec<models::SandboxForkResult>),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdGetResponse {
    /// Successfully returned the sandbox
    Status200_SuccessfullyReturnedTheSandbox(models::SandboxDetail),
    /// Not found
    Status404_NotFound(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdMetricsGetResponse {
    /// Successfully returned the sandbox metrics
    Status200_SuccessfullyReturnedTheSandboxMetrics(Vec<models::SandboxMetric>),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdNetworkPutResponse {
    /// Successfully updated the sandbox network configuration
    Status204_SuccessfullyUpdatedTheSandboxNetworkConfiguration,
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdPausePostResponse {
    /// The sandbox was paused successfully and can be resumed
    Status204_TheSandboxWasPausedSuccessfullyAndCanBeResumed,
    /// Conflict
    Status409_Conflict(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdRefreshesPostResponse {
    /// Successfully refreshed the sandbox
    Status204_SuccessfullyRefreshedTheSandbox,
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdResumePostResponse {
    /// The sandbox was resumed successfully
    Status201_TheSandboxWasResumedSuccessfully(models::Sandbox),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
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
pub enum SandboxesSandboxIdSnapshotsPostResponse {
    /// Snapshot created successfully
    Status201_SnapshotCreatedSuccessfully(models::SnapshotInfo),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum SandboxesSandboxIdTimeoutPostResponse {
    /// Successfully set the sandbox timeout
    Status204_SuccessfullySetTheSandboxTimeout,
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum V2SandboxesGetResponse {
    /// Successfully returned all running sandboxes
    Status200_SuccessfullyReturnedAllRunningSandboxes {
        body: Vec<models::ListedSandbox>,
        x_next_token: Option<String>,
        x_total_running: Option<i32>,
    },
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum V2SandboxesPostResponse {
    /// The sandbox was created successfully
    Status201_TheSandboxWasCreatedSuccessfully {
        body: models::Sandbox,
        x_agentenv_sandbox_id: Option<String>,
    },
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum V2SandboxesSandboxIdConnectPostResponse {
    /// The sandbox was already running
    Status200_TheSandboxWasAlreadyRunning(models::Sandbox),
    /// The sandbox was resumed successfully
    Status201_TheSandboxWasResumedSuccessfully(models::Sandbox),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum V2SandboxesSandboxIdLogsGetResponse {
    /// Successfully returned the sandbox logs
    Status200_SuccessfullyReturnedTheSandboxLogs(models::SandboxLogsV2Response),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

/// Sandboxes
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Sandboxes<E: std::fmt::Debug + Send + Sync + 'static = ()>:
    super::ErrorHandler<E>
{
    type Claims;

    /// SandboxesColdPost - POST /sandboxes-cold
    fn sandboxes_cold_post<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        body: &'life5 models::NewColdSandbox,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesColdPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// List running sandboxes.
    ///
    /// SandboxesGet - GET /sandboxes
    fn sandboxes_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        query_params: &'life5 models::SandboxesGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// List sandbox metrics.
    ///
    /// SandboxesMetricsGet - GET /sandboxes/metrics
    fn sandboxes_metrics_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        query_params: &'life5 models::SandboxesMetricsGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesMetricsGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Create sandbox.
    ///
    /// SandboxesPost - POST /sandboxes
    fn sandboxes_post<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        body: &'life5 models::NewSandbox,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Connect sandbox.
    ///
    /// SandboxesSandboxIdConnectPost - POST /sandboxes/{sandboxID}/connect
    fn sandboxes_sandbox_id_connect_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdConnectPostPathParams,
        body: &'life6 models::ConnectSandbox,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdConnectPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// SandboxesSandboxIdCustomExtensionParamsGet - GET /sandboxes/{sandboxID}/custom-extension-params
    fn sandboxes_sandbox_id_custom_extension_params_get<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdCustomExtensionParamsGetPathParams,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdCustomExtensionParamsGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// SandboxesSandboxIdCustomExtensionParamsPatch - PATCH /sandboxes/{sandboxID}/custom-extension-params
    fn sandboxes_sandbox_id_custom_extension_params_patch<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdCustomExtensionParamsPatchPathParams,
        body: &'life6 std::collections::HashMap<String, crate::types::Object>,
    ) -> super::ApiFuture<
        'async_trait,
        Result<SandboxesSandboxIdCustomExtensionParamsPatchResponse, E>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Kill sandbox.
    ///
    /// SandboxesSandboxIdDelete - DELETE /sandboxes/{sandboxID}
    fn sandboxes_sandbox_id_delete<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdDeletePathParams,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdDeleteResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Fork sandbox.
    ///
    /// SandboxesSandboxIdForkPost - POST /sandboxes/{sandboxID}/fork
    fn sandboxes_sandbox_id_fork_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdForkPostPathParams,
        body: &'life6 Option<models::SandboxForkRequest>,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdForkPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Sandbox.
    ///
    /// SandboxesSandboxIdGet - GET /sandboxes/{sandboxID}
    fn sandboxes_sandbox_id_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdGetPathParams,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Sandbox metrics.
    ///
    /// SandboxesSandboxIdMetricsGet - GET /sandboxes/{sandboxID}/metrics
    fn sandboxes_sandbox_id_metrics_get<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdMetricsGetPathParams,
        query_params: &'life6 models::SandboxesSandboxIdMetricsGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdMetricsGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Update sandbox network.
    ///
    /// SandboxesSandboxIdNetworkPut - PUT /sandboxes/{sandboxID}/network
    fn sandboxes_sandbox_id_network_put<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdNetworkPutPathParams,
        body: &'life6 models::SandboxNetworkUpdateConfig,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdNetworkPutResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Pause sandbox.
    ///
    /// SandboxesSandboxIdPausePost - POST /sandboxes/{sandboxID}/pause
    fn sandboxes_sandbox_id_pause_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdPausePostPathParams,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdPausePostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Refresh sandbox.
    ///
    /// SandboxesSandboxIdRefreshesPost - POST /sandboxes/{sandboxID}/refreshes
    fn sandboxes_sandbox_id_refreshes_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdRefreshesPostPathParams,
        body: &'life6 Option<models::SandboxRefreshRequest>,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdRefreshesPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Resume sandbox.
    ///
    /// SandboxesSandboxIdResumePost - POST /sandboxes/{sandboxID}/resume
    fn sandboxes_sandbox_id_resume_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdResumePostPathParams,
        body: &'life6 models::ResumedSandbox,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdResumePostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Create snapshot.
    ///
    /// SandboxesSandboxIdSnapshotsPost - POST /sandboxes/{sandboxID}/snapshots
    fn sandboxes_sandbox_id_snapshots_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdSnapshotsPostPathParams,
        body: &'life6 models::SandboxSnapshotRequest,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdSnapshotsPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Set sandbox timeout.
    ///
    /// SandboxesSandboxIdTimeoutPost - POST /sandboxes/{sandboxID}/timeout
    fn sandboxes_sandbox_id_timeout_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::SandboxesSandboxIdTimeoutPostPathParams,
        body: &'life6 Option<models::SandboxTimeoutRequest>,
    ) -> super::ApiFuture<'async_trait, Result<SandboxesSandboxIdTimeoutPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// List sandboxes (v2).
    ///
    /// V2SandboxesGet - GET /v2/sandboxes
    fn v2_sandboxes_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        query_params: &'life5 models::V2SandboxesGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<V2SandboxesGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Create sandbox (v2).
    ///
    /// V2SandboxesPost - POST /v2/sandboxes
    fn v2_sandboxes_post<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        body: &'life5 models::NewSandboxV2,
    ) -> super::ApiFuture<'async_trait, Result<V2SandboxesPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Connect sandbox (v2).
    ///
    /// V2SandboxesSandboxIdConnectPost - POST /v2/sandboxes/{sandboxID}/connect
    fn v2_sandboxes_sandbox_id_connect_post<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::V2SandboxesSandboxIdConnectPostPathParams,
        body: &'life6 Option<models::ConnectSandboxV2>,
    ) -> super::ApiFuture<'async_trait, Result<V2SandboxesSandboxIdConnectPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Sandbox logs (v2).
    ///
    /// V2SandboxesSandboxIdLogsGet - GET /v2/sandboxes/{sandboxID}/logs
    fn v2_sandboxes_sandbox_id_logs_get<
        'life0,
        'life1,
        'life2,
        'life3,
        'life4,
        'life5,
        'life6,
        'async_trait,
    >(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::V2SandboxesSandboxIdLogsGetPathParams,
        query_params: &'life6 models::V2SandboxesSandboxIdLogsGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<V2SandboxesSandboxIdLogsGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;
}
