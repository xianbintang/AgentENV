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
pub enum NodesGetResponse {
    /// Successfully returned all nodes
    Status200_SuccessfullyReturnedAllNodes(Vec<models::Node>),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum NodesNodeIdGetResponse {
    /// Successfully returned the node
    Status200_SuccessfullyReturnedTheNode(models::NodeDetail),
    /// Authentication error
    Status401_AuthenticationError(models::Error),
    /// Not found
    Status404_NotFound(models::Error),
    /// Server error
    Status500_ServerError(models::Error),
}

/// Admin
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Admin<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    type Claims;

    /// List nodes.
    ///
    /// NodesGet - GET /nodes
    fn nodes_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        query_params: &'life5 models::NodesGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<NodesGetResponse, E>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        'life4: 'async_trait,
        'life5: 'async_trait,
        Self: 'async_trait;

    /// Node info.
    ///
    /// NodesNodeIdGet - GET /nodes/{nodeID}
    fn nodes_node_id_get<'life0, 'life1, 'life2, 'life3, 'life4, 'life5, 'life6, 'async_trait>(
        &'life0 self,

        method: &'life1 Method,
        host: &'life2 Host,
        cookies: &'life3 CookieJar,
        claims: &'life4 Self::Claims,
        path_params: &'life5 models::NodesNodeIdGetPathParams,
        query_params: &'life6 models::NodesNodeIdGetQueryParams,
    ) -> super::ApiFuture<'async_trait, Result<NodesNodeIdGetResponse, E>>
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
