//! Bounded reference custody for imported static native bundles. Never deletes inputs.
use super::store::RuntimeImageOwner;
use crate::{sandbox::NativeArtifactDescriptor, types::SandboxId};
use anyhow::{anyhow, ensure, Result};
use std::sync::{Arc, Mutex, OnceLock};
const RECORDS: usize = 32;
const FD_TICKETS: usize = 8192;
const OWNERS: usize = 128;
const METADATA_TICKET: usize = 1024 * 1024;
const METADATA_CAP: usize = 32 * 1024 * 1024;
struct Original {
    owner: RuntimeImageOwner,
    bundle: Arc<NativeArtifactDescriptor>,
}

#[derive(Default)]
struct State {
    originals: Vec<Original>,
    owners: Vec<(RuntimeImageOwner, Arc<NativeArtifactDescriptor>)>,
    running: Vec<(SandboxId, Arc<NativeArtifactDescriptor>)>,
    tickets: usize,
    metadata: usize,
}
#[derive(Default)]
pub(crate) struct NativeArtifactStore {
    state: Mutex<State>,
}
impl std::fmt::Debug for NativeArtifactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeArtifactStore { imported_only: true }")
    }
}
impl NativeArtifactStore {
    pub(crate) fn shared() -> Arc<Self> {
        static STORE: OnceLock<Arc<NativeArtifactStore>> = OnceLock::new();
        STORE.get_or_init(|| Arc::new(Self::default())).clone()
    }
    fn original_owner(owner: &RuntimeImageOwner) -> RuntimeImageOwner {
        match owner {
            RuntimeImageOwner::NativeFailedLaunchDebt { original, .. } => {
                RuntimeImageOwner::StartingSandbox(*original)
            }
            _ => owner.clone(),
        }
    }
    pub(crate) async fn pin(
        &self,
        owner: RuntimeImageOwner,
        bundles: Vec<Arc<NativeArtifactDescriptor>>,
    ) -> Result<()> {
        ensure!(bundles.len() <= 2, "native bundle bound");
        for bundle in bundles {
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow!("native custody lock"))?;
                if let Some(original) = state
                    .originals
                    .iter()
                    .find(|original| original.bundle.same_namespace(&bundle))
                {
                    ensure!(
                        Arc::ptr_eq(&original.bundle, &bundle)
                            && original.bundle.same_original(&bundle)
                            && original.owner == Self::original_owner(&owner),
                        "native original drift"
                    );
                } else {
                    ensure!(
                        !matches!(owner, RuntimeImageOwner::NativeFailedLaunchDebt { .. }),
                        "native debt original not reserved"
                    );
                    ensure!(
                        state.originals.len() < RECORDS
                            && state.tickets + NativeArtifactDescriptor::FD_TICKET <= FD_TICKETS
                            && state.metadata + METADATA_TICKET <= METADATA_CAP,
                        "native custody capacity"
                    );
                    state.originals.try_reserve(1)?;
                    state.owners.try_reserve(1)?;
                    ensure!(
                        state.owners.len() + state.running.len() < OWNERS,
                        "native owner capacity"
                    );
                    // Permanent original/ticket installed before capture effects or await.
                    state.tickets += NativeArtifactDescriptor::FD_TICKET;
                    state.metadata += METADATA_TICKET;
                    state.originals.push(Original {
                        owner: Self::original_owner(&owner),
                        bundle: bundle.clone(),
                    });
                }
                ensure!(
                    !state
                        .owners
                        .iter()
                        .any(|(existing, b)| Arc::ptr_eq(b, &bundle)
                            && Self::original_owner(existing) != Self::original_owner(&owner)),
                    "native foreign owner"
                );
                if !state
                    .owners
                    .iter()
                    .any(|(existing, b)| existing == &owner && Arc::ptr_eq(b, &bundle))
                {
                    ensure!(
                        state.owners.len() + state.running.len() < OWNERS,
                        "native owner capacity"
                    );
                    state.owners.try_reserve(1)?;
                    state.owners.push((owner.clone(), bundle.clone()));
                }
            }
            if !matches!(owner, RuntimeImageOwner::NativeFailedLaunchDebt { .. }) {
                #[cfg(not(test))]
                tokio::task::spawn_blocking(move || bundle.capture()).await??;
                #[cfg(test)]
                bundle.observed_capture().await?;
            }
        }
        Ok(())
    }
    pub(crate) fn promote(
        &self,
        id: SandboxId,
        bundles: Vec<Arc<NativeArtifactDescriptor>>,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native custody lock"))?;
        for bundle in bundles {
            ensure!(
                state
                    .originals
                    .iter()
                    .any(|v| Arc::ptr_eq(&v.bundle, &bundle)
                        && v.owner == RuntimeImageOwner::StartingSandbox(id)),
                "native original not reserved"
            );
            // Retained capture truth is valid after admission expiry; no new capture/claim.
            ensure!(bundle.is_captured(), "native capture unavailable");
            if !state
                .running
                .iter()
                .any(|(existing, b)| *existing == id && Arc::ptr_eq(b, &bundle))
            {
                ensure!(
                    state.owners.len() + state.running.len() < OWNERS,
                    "native owner capacity"
                );
                state.running.try_reserve(1)?;
                state.running.push((id, bundle));
            }
        }
        Ok(())
    }
    pub(crate) fn retire_running(
        &self,
        id: SandboxId,
        bundles: Vec<Arc<NativeArtifactDescriptor>>,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native custody lock"))?;
        for bundle in &bundles {
            ensure!(
                state
                    .originals
                    .iter()
                    .any(|v| Arc::ptr_eq(&v.bundle, bundle)
                        && v.owner == RuntimeImageOwner::StartingSandbox(id)),
                "native retirement original mismatch"
            );
        }
        state.running.retain(|(existing, b)| {
            !(*existing == id && bundles.iter().any(|v| Arc::ptr_eq(v, b)))
        });
        // Explicit logical owner retirement only; original capture/tickets never refunded.
        Ok(())
    }
    pub(crate) fn release(&self, owner: &RuntimeImageOwner) {
        if let Ok(mut state) = self.state.lock() {
            state.owners.retain(|(existing, _)| existing != owner);
        }
        // Original records, FD tickets and captures are retained tombstones: no refund/GC.
    }
    #[cfg(test)]
    pub(crate) fn check_retired_capture(&self, id: SandboxId) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native custody lock"))?;
        ensure!(
            state.originals.len() == 1,
            "qualification expected one original imported bundle"
        );
        let original = &state.originals[0];
        ensure!(
            original.owner == RuntimeImageOwner::StartingSandbox(id)
                && original.bundle.is_captured(),
            "qualification original captured bundle required"
        );
        ensure!(
            state.owners.is_empty() && state.running.is_empty(),
            "qualification native logical owners not retired"
        );
        ensure!(
            state.tickets == NativeArtifactDescriptor::FD_TICKET
                && state.metadata == METADATA_TICKET,
            "qualification original tickets not retained"
        );
        original.bundle.verify_captured()?;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn custody(&self) -> (usize, usize, usize, usize, usize) {
        let state = self.state.lock().expect("native test custody lock");
        (
            state.originals.len(),
            state.owners.len(),
            state.running.len(),
            state.tickets,
            state.metadata,
        )
    }
    // No inferred release on omission from maintenance. Unknown originals stay protected.
}

#[async_trait::async_trait]
impl super::store::RuntimeImageRefs for NativeArtifactStore {
    async fn pin(
        &self,
        owner: RuntimeImageOwner,
        artifacts: crate::sandbox::RuntimeArtifactSet,
    ) -> Result<()> {
        let (paths, native) = artifacts.split();
        ensure!(paths.is_empty(), "native store refuses OverlayBD artifacts");
        NativeArtifactStore::pin(self, owner, native).await
    }
    async fn promote_native_running(
        &self,
        id: SandboxId,
        artifacts: crate::sandbox::RuntimeArtifactSet,
    ) -> Result<()> {
        let (paths, native) = artifacts.split();
        ensure!(paths.is_empty(), "native store refuses OverlayBD artifacts");
        self.promote(id, native)
    }
    async fn retire_native_running(
        &self,
        id: SandboxId,
        artifacts: crate::sandbox::RuntimeArtifactSet,
    ) -> Result<()> {
        let (paths, native) = artifacts.split();
        ensure!(paths.is_empty(), "native store refuses OverlayBD artifacts");
        self.retire_running(id, native)
    }
    async fn unpin_best_effort(&self, owner: RuntimeImageOwner) {
        self.release(&owner);
    }
    async fn reconcile_paused(&self, live: &[SandboxId]) -> Result<()> {
        ensure!(live.is_empty(), "native imported pause unsupported");
        Ok(())
    }
    async fn maintain_running(
        &self,
        running: Vec<(SandboxId, crate::sandbox::RuntimeArtifactSet)>,
    ) -> Result<()> {
        for (id, artifacts) in running {
            let (paths, native) = artifacts.split();
            ensure!(paths.is_empty(), "native store refuses OverlayBD artifacts");
            self.promote(id, native)?;
        }
        Ok(())
    }
}
