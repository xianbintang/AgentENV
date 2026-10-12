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
pub enum TemplatesAliasesAliasGetResponse {
    /// Successfully queried template by alias
    Status200_SuccessfullyQueriedTemplateByAlias(models::TemplateAliasResponse),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Forbidden
    Status403_Forbidden(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum TemplatesGetResponse {
    /// Successfully returned all templates
    Status200_SuccessfullyReturnedAllTemplates(Vec<models::Template>),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum TemplatesTemplateIdBuildsBuildIdBuilderDeleteResponse {
    /// Builder released
    Status204_BuilderReleased,
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
pub enum TemplatesTemplateIdBuildsBuildIdBuilderPutResponse {
    /// Builder preparation accepted
    Status202_BuilderPreparationAccepted {
        body: models::TemplateBuilder,
        x_agentenv_build_id: Option<String>,
    },
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Concurrent build limit reached
    Status429_ConcurrentBuildLimitReached(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum TemplatesTemplateIdBuildsBuildIdLogsGetResponse {
    /// Successfully returned the template build logs
    Status200_SuccessfullyReturnedTheTemplateBuildLogs(models::TemplateBuildLogsResponse),
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
pub enum TemplatesTemplateIdBuildsBuildIdStatusGetResponse {
    /// Successfully returned the template
    Status200_SuccessfullyReturnedTheTemplate(models::TemplateBuildInfo),
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
pub enum TemplatesTemplateIdDeleteResponse {
    /// The template was deleted successfully
    Status204_TheTemplateWasDeletedSuccessfully,
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Conflict
    Status409_Conflict(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum TemplatesTemplateIdGetResponse {
    /// Successfully returned the template with its builds
    Status200_SuccessfullyReturnedTheTemplateWithItsBuilds {
        body: models::TemplateWithBuilds,
        x_next_token: Option<String>,
    },
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
pub enum V2TemplatesGetResponse {
    /// Successfully returned all templates
    Status200_SuccessfullyReturnedAllTemplates {
        body: Vec<models::Template>,
        x_next_token: Option<String>,
    },
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Forbidden
    Status403_Forbidden(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum V2TemplatesTemplateIdBuildsBuildIdPostResponse {
    /// The build has started
    Status202_TheBuildHasStarted,
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
pub enum V3TemplatesPostResponse {
    /// The build was requested successfully
    Status202_TheBuildWasRequestedSuccessfully(models::TemplateRequestResponseV3),
    /// Bad request
    Status400_BadRequest(models::Error),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

/// Templates
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Templates<E: std::fmt::Debug + Send + Sync + 'static = ()>:
    super::ErrorHandler<E>
{
    type Claims;

    /// Check template alias.
    ///
    /// TemplatesAliasesAliasGet - GET /templates/aliases/{alias}
    fn templates_aliases_alias_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::TemplatesAliasesAliasGetPathParams,
    ) -> super::ApiFuture<'async_trait, Result<TemplatesAliasesAliasGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// List templates.
    ///
    /// TemplatesGet - GET /templates
    fn templates_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        query_params: &'life5 models::TemplatesGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<TemplatesGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Cancel a template build and release its worker.
    ///
    /// TemplatesTemplateIdBuildsBuildIdBuilderDelete - DELETE /templates/{templateID}/builds/{buildID}/builder
    fn templates_template_id_builds_build_id_builder_delete<
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
        path_params: &'life5 models::TemplatesTemplateIdBuildsBuildIdBuilderDeletePathParams,
    ) -> super::ApiFuture<
        'async_trait,
        Result<TemplatesTemplateIdBuildsBuildIdBuilderDeleteResponse, E>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Prepare the BuildKit worker for a template build.
    ///
    /// TemplatesTemplateIdBuildsBuildIdBuilderPut - PUT /templates/{templateID}/builds/{buildID}/builder
    fn templates_template_id_builds_build_id_builder_put<
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
        path_params: &'life5 models::TemplatesTemplateIdBuildsBuildIdBuilderPutPathParams,
        body: &'life6 models::TemplateBuilderRequest,
    ) -> super::ApiFuture<'async_trait, Result<TemplatesTemplateIdBuildsBuildIdBuilderPutResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Template build logs.
    ///
    /// TemplatesTemplateIdBuildsBuildIdLogsGet - GET /templates/{templateID}/builds/{buildID}/logs
    fn templates_template_id_builds_build_id_logs_get<
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
        path_params: &'life5 models::TemplatesTemplateIdBuildsBuildIdLogsGetPathParams,
        query_params: &'life6 models::TemplatesTemplateIdBuildsBuildIdLogsGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<TemplatesTemplateIdBuildsBuildIdLogsGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Template build status.
    ///
    /// TemplatesTemplateIdBuildsBuildIdStatusGet - GET /templates/{templateID}/builds/{buildID}/status
    fn templates_template_id_builds_build_id_status_get<
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
        path_params: &'life5 models::TemplatesTemplateIdBuildsBuildIdStatusGetPathParams,
        query_params: &'life6 models::TemplatesTemplateIdBuildsBuildIdStatusGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<TemplatesTemplateIdBuildsBuildIdStatusGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Delete template.
    ///
    /// TemplatesTemplateIdDelete - DELETE /templates/{templateID}
    fn templates_template_id_delete<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::TemplatesTemplateIdDeletePathParams,
    ) -> super::ApiFuture<'async_trait, Result<TemplatesTemplateIdDeleteResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// List template builds.
    ///
    /// TemplatesTemplateIdGet - GET /templates/{templateID}
    fn templates_template_id_get<
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
        path_params: &'life5 models::TemplatesTemplateIdGetPathParams,
        query_params: &'life6 models::TemplatesTemplateIdGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<TemplatesTemplateIdGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// List templates (v2).
    ///
    /// V2TemplatesGet - GET /v2/templates
    fn v2_templates_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        query_params: &'life5 models::V2TemplatesGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<V2TemplatesGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Start template build (v2).
    ///
    /// V2TemplatesTemplateIdBuildsBuildIdPost - POST /v2/templates/{templateID}/builds/{buildID}
    fn v2_templates_template_id_builds_build_id_post<
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
        path_params: &'life5 models::V2TemplatesTemplateIdBuildsBuildIdPostPathParams,
        body: &'life6 models::TemplateBuildStartV2,
    ) -> super::ApiFuture<'async_trait, Result<V2TemplatesTemplateIdBuildsBuildIdPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        'life6: 'async_trait,
        Self: 'async_trait;

    /// Create template (v3).
    ///
    /// V3TemplatesPost - POST /v3/templates
    fn v3_templates_post<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        body: &'life5 models::TemplateBuildRequestV3,
    ) -> super::ApiFuture<'async_trait, Result<V3TemplatesPostResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;
}
