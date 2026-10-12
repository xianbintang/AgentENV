mod file_backed;
#[cfg(test)]
mod mock;

use async_trait::async_trait;
use futures::future::BoxFuture;
use std::path::{Path, PathBuf};

use crate::orchestrator::store::SandboxMetadata;
use crate::sandbox::{PausedSandboxState, SandboxBackendFactory};
use crate::types::SandboxId;

pub use file_backed::FileBackedSandboxPersister;
#[cfg(test)]
pub(crate) use mock::{RecordingCall, RecordingPersister};

pub type PersistenceResult<T> = std::result::Result<T, SandboxPersistenceError>;

#[derive(Debug, thiserror::Error)]
pub enum SandboxPersistenceError {
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid sandbox record: {reason}")]
    InvalidRecord {
        reason: String,
        #[source]
        source: Option<anyhow::Error>,
    },
    #[error("invalid paused sandbox runtime state: {reason}")]
    RuntimeState { reason: &'static str },
    #[error("paused sandbox store operation failed: {operation}: {source}")]
    Store {
        operation: &'static str,
        #[source]
        source: anyhow::Error,
    },
}

impl SandboxPersistenceError {
    pub(super) fn io(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(super) fn store(operation: &'static str, source: anyhow::Error) -> Self {
        Self::Store { operation, source }
    }
}

#[async_trait]
/// Persistence interface for sandbox records and artifacts.
pub trait SandboxPersister: Send + Sync {
    /// Load all persisted sandbox metadata.
    fn load_all<'life0, 'life1, 'async_trait, F>(
        &'life0 self,
        factory: &'life1 F,
    ) -> BoxFuture<'async_trait, PersistenceResult<Vec<SandboxMetadata>>>
    where
        F: SandboxBackendFactory,
        F: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    /// Allocate an UNIQUE directory for sandbox artifacts.
    ///
    /// `None` means persistence is disabled and the sandbox backend should manage
    /// the lifecycle of its temporary artifacts.
    fn allocate_artifact_root<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
    ) -> BoxFuture<'async_trait, PersistenceResult<Option<PathBuf>>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    /// Persist metadata and runtime state for a paused sandbox.
    fn persist_paused<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        metadata: &'life1 SandboxMetadata,
        artifact_root: Option<&'life2 Path>,
        paused_state: &'life3 dyn PausedSandboxState,
    ) -> BoxFuture<'async_trait, PersistenceResult<()>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait;

    /// Mark a paused sandbox as resuming.
    fn mark_resuming<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
    ) -> BoxFuture<'async_trait, PersistenceResult<()>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    /// Roll back a resuming mark after a failed resume attempt.
    fn rollback_resuming<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
    ) -> BoxFuture<'async_trait, PersistenceResult<()>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    /// Delete the persistence record for a sandbox.
    fn delete_record<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
    ) -> BoxFuture<'async_trait, PersistenceResult<()>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    /// Delete the persistence record and all associated artifacts.
    fn delete_record_and_artifacts<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sandbox_id: &'life1 SandboxId,
    ) -> BoxFuture<'async_trait, PersistenceResult<()>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;
}

#[derive(Default)]
pub struct DisabledSandboxPersister;

#[async_trait]
impl SandboxPersister for DisabledSandboxPersister {
    async fn load_all<F>(&self, _factory: &F) -> PersistenceResult<Vec<SandboxMetadata>>
    where
        F: SandboxBackendFactory,
    {
        Ok(Vec::new())
    }

    async fn allocate_artifact_root(
        &self,
        _sandbox_id: &SandboxId,
    ) -> PersistenceResult<Option<PathBuf>> {
        Ok(None)
    }

    async fn persist_paused(
        &self,
        _metadata: &SandboxMetadata,
        _artifact_root: Option<&Path>,
        _paused_state: &dyn PausedSandboxState,
    ) -> PersistenceResult<()> {
        Ok(())
    }

    async fn mark_resuming(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn rollback_resuming(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn delete_record(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn delete_record_and_artifacts(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }
}
