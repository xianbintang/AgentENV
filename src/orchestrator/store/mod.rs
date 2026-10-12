mod in_memory;
mod metadata;

use futures::future::BoxFuture;
use std::collections::HashMap;
use std::time::SystemTime;

use async_trait::async_trait;

use crate::orchestrator::SandboxState;
use crate::types::SandboxId;

pub use in_memory::InMemoryMetadataStore;
pub use metadata::{NewTimeout, SandboxMetadata, SandboxTimeoutAction};

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug)]
pub struct MetadataUpdateResult {
    pub previous: SandboxMetadata,
    pub current: SandboxMetadata,
}

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("store backend error: {source}")]
    Backend {
        #[source]
        source: anyhow::Error,
    },
    #[error("sandbox {sandbox_id} not found")]
    SandboxNotFound { sandbox_id: SandboxId },
    #[error("sandbox {sandbox_id} already exists")]
    SandboxAlreadyExists { sandbox_id: SandboxId },
    #[error(
        "sandbox {sandbox_id} state conflict: expected one of {expected_states:?}, got {actual_state:?}"
    )]
    StateConflict {
        sandbox_id: SandboxId,
        expected_states: Vec<SandboxState>,
        actual_state: SandboxState,
    },
}

/// The filter criteria for listing sandboxes in the metadata store.
///
/// The returned sandboxes must match `states` (if specified) and include `user_metadata` (if specified),
/// but must not match `excluded_states` (if specified).
#[derive(Clone, Debug, Default)]
pub struct SandboxListFilter {
    pub states: Option<Vec<SandboxState>>,
    pub excluded_states: Option<Vec<SandboxState>>,
    pub user_metadata: Option<HashMap<String, String>>,
    /// Include only sandboxes created at or after this instant.
    pub started_after: Option<SystemTime>,
    /// Include only sandboxes whose snapshot ID or alias matches this value.
    pub template: Option<String>,
}

impl SandboxListFilter {
    pub fn matches_all() -> Self {
        Self::default()
    }
}

#[async_trait]
pub trait MetadataStore: Send + Sync {
    fn add<'life0, 'async_trait>(
        &'life0 self,
        metadata: SandboxMetadata,
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    fn update<'life0, 'async_trait>(
        &'life0 self,
        metadata: SandboxMetadata,
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    /// Updates the sandbox state to `new_state` if the current state is one of `expected_states`.
    /// Returns the PREVIOUS sandbox state on success.
    fn update_state_if_state<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
        new_state: SandboxState,
        expected_states: &'life2 [SandboxState],
    ) -> BoxFuture<'async_trait, Result<SandboxState>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait;
    /// Atomically updates sandbox metadata using the latest stored value if the
    /// current state is one of `expected_states`.
    ///
    /// The update callback is synchronous by design: store implementations may
    /// run it while holding their metadata lock, so callers must not perform
    /// async work inside the callback.
    fn update_if_state<'life0, 'life1, 'life2, 'async_trait, F>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
        expected_states: &'life2 [SandboxState],
        update: F,
    ) -> BoxFuture<'async_trait, Result<MetadataUpdateResult>>
    where
        F: FnOnce(&mut SandboxMetadata) + Send,
        F: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait;
    fn get<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
    ) -> BoxFuture<'async_trait, Result<Option<SandboxMetadata>>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;
    fn remove<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
    ) -> BoxFuture<'async_trait, Result<Option<SandboxMetadata>>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;
    fn list<'life0, 'async_trait>(
        &'life0 self,
    ) -> BoxFuture<'async_trait, Result<Vec<SandboxMetadata>>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    fn list_with_callback<'life0, 'async_trait, F>(
        &'life0 self,
        callback: F,
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        F: FnMut(&SandboxMetadata) + Send,
        F: 'async_trait,
        'life0: 'async_trait,
        Self: 'async_trait;
    fn list_filtered<'life0, 'async_trait>(
        &'life0 self,
        filter: SandboxListFilter,
    ) -> BoxFuture<'async_trait, Result<Vec<SandboxMetadata>>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    fn list_expired<'life0, 'async_trait>(
        &'life0 self,
        now: SystemTime,
    ) -> BoxFuture<'async_trait, Result<Vec<SandboxMetadata>>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    fn list_ids<'life0, 'async_trait>(
        &'life0 self,
    ) -> BoxFuture<'async_trait, Result<Vec<SandboxId>>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    /// Waits until the sandbox state is no longer any of the given `transitional_states`,
    /// then returns the latest metadata.
    ///
    /// Returns `Ok(None)` if the sandbox was removed while waiting.
    /// Returns immediately (without blocking) if the sandbox is already in a non-transitional state.
    fn wait_while_in_states<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
        transitional_states: &'life2 [SandboxState],
    ) -> BoxFuture<'async_trait, Result<Option<SandboxMetadata>>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait;
}
