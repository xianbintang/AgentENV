use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use tokio::sync::{broadcast, oneshot, watch, Mutex, OnceCell, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, trace, warn};

use crate::cfg::ConfigManager;
use crate::image::cache::{
    local_image_services_from_global_config, RuntimeImageOwner, RuntimeImageRefs,
};
use crate::sandbox::{
    CustomExtensionClient, CustomExtensionParams, EnvdAccessToken, FirecrackerSandboxFactory,
    FreshSandboxBuildSpec, PausedSandboxState, RuntimeArtifactSet, SandboxAccessTokenGenerator,
    SandboxBackend, SandboxBackendFactory, SandboxCaptureError, SandboxForkSpec,
    SandboxLaunchConfig, SandboxLogEntry, SandboxNetworkPolicy, SandboxRuntimeInfo,
};
use crate::snapshot::SnapshotRuntimeVersions;
use crate::types::{bytes_to_mib_ceil, SandboxId, SandboxResources};
use crate::volume::VolumeManager;

use super::launch_plan::{CreateLaunchSource, LaunchPlan};
use super::metrics::{
    aggregate_resource_metrics, OrchestratorCounters, OrchestratorMetrics, SandboxContribution,
};
use super::persistence::{DisabledSandboxPersister, FileBackedSandboxPersister, SandboxPersister};
use super::proxy::{ProxyLookupResult, ProxyRoute, ProxyRouteTable, ProxyTarget};
use super::store::*;
use super::types::{
    CreateSandboxRequest, SandboxForkChildSpec, SandboxLaunchSource, SandboxLifecycleEvent,
    SandboxLifecycleEventType, SandboxState, SnapshotCaptureResult,
};
use super::{OrchestratorError, Result, SandboxForkOutcome, SandboxOperation};

#[path = "sandbox_metrics.rs"]
mod sandbox_metrics;
use crate::logging::LogLevel;
use crate::sandbox::logs::log_query_window;
use sandbox_metrics::SandboxMetrics;

type SandboxHandle = Arc<Mutex<Box<dyn SandboxBackend>>>;
#[derive(Clone, Default)]
enum DeleteProgress {
    #[default]
    Capture,
    Stop {
        capture_failed: bool,
    },
    Release {
        capture_failed: bool,
        retiring_native: Option<RuntimeArtifactSet>,
    },
    Done,
}

#[derive(Clone)]
struct FailedLaunchDebt {
    sandbox_id: SandboxId,
    handle: SandboxHandle,
    metadata: Option<SandboxMetadata>,
    create: bool,
    expected_state: Option<SandboxState>,
    pin_ready: bool,
    artifacts: RuntimeArtifactSet,
}

// Instance-bound provenance of genuine failed-launch cleanup, not a create
// allocator or durable registry. Slots are never evicted, refunded or inferred
// from a caller-supplied ID. Exhaustion retains the original heavy owner debt.
const CLEANUP_PROVENANCE_CAP: usize = 32;
#[derive(Clone, Copy)]
struct CleanupProvenance {
    sandbox_id: SandboxId,
    retired: bool,
}
#[derive(Clone, Copy)]
struct CleanupHistory {
    slots: [Option<CleanupProvenance>; CLEANUP_PROVENANCE_CAP],
}
impl Default for CleanupHistory {
    fn default() -> Self {
        Self {
            slots: [None; CLEANUP_PROVENANCE_CAP],
        }
    }
}
impl CleanupHistory {
    // Transactional fixed-capacity reservation before any batch cleanup effect.
    fn reserve(&mut self, originals: impl Iterator<Item = SandboxId>) -> Result<()> {
        let mut candidate = *self;
        for sandbox_id in originals {
            if let Some(slot) = candidate
                .slots
                .iter_mut()
                .flatten()
                .find(|slot| slot.sandbox_id == sandbox_id)
            {
                slot.retired = false;
            } else {
                let slot = candidate
                    .slots
                    .iter_mut()
                    .find(|slot| slot.is_none())
                    .ok_or(OrchestratorError::FailedLaunchCleanupCapacity)?;
                *slot = Some(CleanupProvenance {
                    sandbox_id,
                    retired: false,
                });
            }
        }
        *self = candidate;
        Ok(())
    }
    fn mark_retired(&mut self, sandbox_id: SandboxId) -> Result<()> {
        let slot = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.sandbox_id == sandbox_id)
            .ok_or_else(|| {
                OrchestratorError::InternalError("cleanup original provenance unavailable".into())
            })?;
        slot.retired = true;
        Ok(())
    }
    fn retired(&self, sandbox_id: SandboxId) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|slot| slot.sandbox_id == sandbox_id && slot.retired)
    }
}

/// Maximum time to wait for a sandbox to leave a transitional state.
/// Guards against indefinite blocking when a sandbox's in-progress operation
/// never completes (e.g. the task holding the state panics without rolling back).
const WAIT_TRANSITION_TIMEOUT: Duration = Duration::from_secs(60);
const SANDBOX_EVENT_CHANNEL_CAPACITY: usize = 1024;
const MAX_SANDBOX_LOG_LIMIT: usize = 1000;
const SANDBOX_LOG_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
enum ShutdownOutcome {
    Success,
    Failed(String),
}

impl ShutdownOutcome {
    fn from_result(result: Result<()>) -> Self {
        match result {
            Ok(()) => Self::Success,
            Err(OrchestratorError::InternalError(message)) => Self::Failed(message),
            Err(err) => Self::Failed(err.to_string()),
        }
    }

    fn as_result(&self) -> Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::Failed(message) => Err(OrchestratorError::InternalError(message.clone())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailedLaunchStage {
    Registered,
    TransitionalPersisted,
    RunningPersisted,
}

impl FailedLaunchStage {
    fn rollback_expected_state(self, plan: &LaunchPlan) -> Option<SandboxState> {
        match self {
            Self::Registered => None,
            Self::TransitionalPersisted => Some(plan.transitional_state()),
            Self::RunningPersisted => Some(SandboxState::Running),
        }
    }
}

pub struct Orchestrator<
    S: MetadataStore = InMemoryMetadataStore,
    F: SandboxBackendFactory = FirecrackerSandboxFactory,
    P: SandboxPersister = FileBackedSandboxPersister,
> {
    store: S,
    factory: F,
    persister: P,
    sandboxes: RwLock<HashMap<SandboxId, SandboxHandle>>,
    template_build_ids: RwLock<HashSet<SandboxId>>,
    deletions: Mutex<HashMap<SandboxId, Arc<Mutex<DeleteProgress>>>>,
    failed_launch_debts: RwLock<HashMap<SandboxId, FailedLaunchDebt>>,
    failed_launch_cleanup: Mutex<()>,
    cleanup_provenance: std::sync::Mutex<CleanupHistory>,
    proxy_routes: RwLock<ProxyRouteTable>,
    native_create_incarnation: uuid::Uuid,
    native_requester: Option<std::sync::Mutex<crate::sandbox::NativeIssuerRequester>>,
    native_ingress: OnceCell<Arc<crate::sandbox::native_worker_ingress::IngressOwner>>,
    next_proxy_route_version: AtomicU64,
    counters: OrchestratorCounters,
    sandbox_metrics: Mutex<SandboxMetrics>,
    sandbox_event_tx: broadcast::Sender<SandboxLifecycleEvent>,
    default_sandbox_timeout: Duration,
    is_shutting_down: std::sync::atomic::AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    shutdown_outcome: OnceCell<ShutdownOutcome>,
    image_refs: Arc<dyn RuntimeImageRefs>,
    access_tokens: SandboxAccessTokenGenerator,
    volume_manager: Option<Arc<VolumeManager>>,
}

impl Orchestrator<InMemoryMetadataStore, FirecrackerSandboxFactory, DisabledSandboxPersister> {
    pub async fn with_in_memory_store() -> Arc<Self> {
        Self::new(
            InMemoryMetadataStore::new(),
            FirecrackerSandboxFactory::new(),
            DisabledSandboxPersister,
        )
        .await
        .expect("in-memory orchestrator should never fail to initialize")
    }
}

impl<F> Orchestrator<InMemoryMetadataStore, F>
where
    F: SandboxBackendFactory,
{
    pub async fn with_file_backed_store_and_factory(factory: F) -> Result<Arc<Self>> {
        let config = ConfigManager::global_config();
        let store = InMemoryMetadataStore::new();
        let persister = FileBackedSandboxPersister::new(
            config.orchestrator.persisted_sandbox_store_path.clone(),
            config.virtualization_mode,
        );
        Self::new(store, factory, persister).await
    }

    pub async fn with_file_backed_store_factory_and_volumes(
        factory: F,
        volume_manager: Arc<VolumeManager>,
    ) -> Result<Arc<Self>> {
        let config = ConfigManager::global_config();
        let store = InMemoryMetadataStore::new();
        let persister = FileBackedSandboxPersister::new(
            config.orchestrator.persisted_sandbox_store_path.clone(),
            config.virtualization_mode,
        );
        let image_refs = local_image_services_from_global_config().runtime_refs;
        Self::new_inner_with_volumes(store, factory, persister, image_refs, Some(volume_manager))
            .await
    }
}

impl<S, F, P> Orchestrator<S, F, P>
where
    S: MetadataStore + 'static,
    F: SandboxBackendFactory,
    P: SandboxPersister + 'static,
{
    pub async fn new(store: S, factory: F, persister: P) -> Result<Arc<Self>> {
        let image_refs = local_image_services_from_global_config().runtime_refs;
        Self::new_inner(store, factory, persister, image_refs).await
    }

    #[cfg(test)]
    pub(crate) async fn new_native_api_fixture(
        store: S,
        factory: F,
        persister: P,
    ) -> Result<Arc<Self>> {
        // These API fixtures own no image artifacts: their backend is a mock
        // and their authenticated actor peer is an in-memory pipe. Keep the
        // real orchestrator initialization without opening the global image DB.
        Self::new_inner(
            store,
            factory,
            persister,
            Arc::new(crate::image::cache::test_support::RecordingRuntimeImageRefs::default()),
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn new_native_qualification_fixture(
        store: S,
        factory: F,
        persister: P,
        image_refs: Arc<dyn RuntimeImageRefs>,
    ) -> Result<Arc<Self>> {
        Self::new_inner(store, factory, persister, image_refs).await
    }

    async fn new_inner(
        store: S,
        factory: F,
        persister: P,
        image_refs: Arc<dyn RuntimeImageRefs>,
    ) -> Result<Arc<Self>> {
        Self::new_inner_with_volumes(store, factory, persister, image_refs, None).await
    }

    async fn new_inner_with_volumes(
        store: S,
        factory: F,
        persister: P,
        image_refs: Arc<dyn RuntimeImageRefs>,
        volume_manager: Option<Arc<VolumeManager>>,
    ) -> Result<Arc<Self>> {
        let app_config = ConfigManager::global_config();
        let config = &app_config.orchestrator;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (sandbox_event_tx, _sandbox_event_rx) =
            broadcast::channel(SANDBOX_EVENT_CHANNEL_CAPACITY);

        // Restore persisted sandboxes from the previous run, keeping the paused
        // ones (with their state) for the paused-protection reconcile below.
        let persisted = persister.load_all(&factory).await?;
        let managed_seed_must_exist = persisted_sandboxes_require_managed_seed(&persisted);
        let access_tokens = tokio::task::spawn_blocking(move || {
            SandboxAccessTokenGenerator::load_or_create(app_config, managed_seed_must_exist)
        })
        .await
        .context("join sandbox access-token seed loader")??;
        let restored_paused: Vec<(SandboxId, Arc<dyn PausedSandboxState>)> = persisted
            .iter()
            .filter(|metadata| metadata.state == SandboxState::Paused)
            .filter_map(|metadata| {
                metadata
                    .paused_state
                    .as_ref()
                    .map(|paused_state| (metadata.id, Arc::clone(paused_state)))
            })
            .collect();
        for metadata in persisted {
            store.add(metadata).await?;
        }

        let native_create_incarnation = uuid::Uuid::now_v7();
        let native_requester = if let Some(path) = &app_config.native_issuer_requester {
            if !app_config.is_native_root() {
                return Err(
                    anyhow::anyhow!("native issuer requires explicit native-root mode").into(),
                );
            }
            Some(std::sync::Mutex::new(
                crate::sandbox::NativeIssuerRequester::install(
                    path,
                    native_create_incarnation,
                    std::time::Instant::now() + Duration::from_secs(3),
                )?,
            ))
        } else {
            None
        };
        let orchestrator = Arc::new(Self {
            store,
            factory,
            persister,
            sandboxes: RwLock::new(HashMap::new()),
            template_build_ids: RwLock::new(HashSet::new()),
            deletions: Mutex::new(HashMap::new()),
            failed_launch_debts: RwLock::new(HashMap::new()),
            failed_launch_cleanup: Mutex::new(()),
            cleanup_provenance: std::sync::Mutex::new(CleanupHistory::default()),
            proxy_routes: RwLock::new(ProxyRouteTable::default()),
            native_create_incarnation,
            native_requester,
            native_ingress: OnceCell::new(),
            next_proxy_route_version: AtomicU64::new(1),
            counters: OrchestratorCounters::default(),
            sandbox_metrics: Mutex::new(SandboxMetrics::default()),
            sandbox_event_tx,
            default_sandbox_timeout: Duration::from_secs(config.default_sandbox_timeout_secs),
            is_shutting_down: std::sync::atomic::AtomicBool::new(false),
            shutdown_tx,
            shutdown_outcome: OnceCell::new(),
            image_refs,
            access_tokens,
            volume_manager,
        });

        if app_config.native_worker_ingress {
            let seed = {
                orchestrator
                    .native_requester
                    .as_ref()
                    .context("native ingress requires requester")?
                    .lock()
                    .map_err(|_| anyhow::anyhow!("native requester poisoned"))?
                    .ingress_seed()?
            }; // No requester mutex is held while bootstrap waits for Worker.
            let owner = if app_config.native_worker_provision {
                crate::sandbox::native_worker_ingress::IngressOwner::prepare_provisioned(
                    seed,
                    Arc::downgrade(&orchestrator),
                )?
            } else {
                crate::sandbox::native_worker_ingress::IngressOwner::prepare(
                    seed,
                    Arc::downgrade(&orchestrator),
                )?
            };
            orchestrator
                .native_ingress
                .set(owner.clone())
                .map_err(|_| anyhow::anyhow!("native ingress already owned"))?;
            owner.activate()?;
            owner.wait_ready().await?;
        }

        Self::start_metrics_task(&orchestrator);

        // Start the auto-evict task.
        let evict_interval = Duration::from_millis(config.auto_evict_interval_ms);
        Self::start_auto_evict_task(Arc::clone(&orchestrator), evict_interval, shutdown_rx);

        // Reconcile durable paused protection, then start maintenance (fail-closed).
        let gc = app_config.image.cache.gc_schedule();
        if gc.enabled {
            match orchestrator
                .reconcile_paused_at_startup(&restored_paused)
                .await
            {
                Ok(()) => {
                    Self::start_local_image_maintenance_task(
                        Arc::clone(&orchestrator),
                        gc.interval,
                        orchestrator.shutdown_tx.subscribe(),
                    );
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        "local image protection reconcile failed at startup; not starting maintenance (fail-closed)"
                    );
                }
            }
        }

        Ok(orchestrator)
    }

    async fn run_cancellation_safe<T>(
        self: &Arc<Self>,
        operation: &'static str,
        sandbox_id: SandboxId,
        future: impl std::future::Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = future.await;
            if tx.send(result).is_err() {
                debug!(
                    sandbox_id = %sandbox_id,
                    operation,
                    "operation completed after caller stopped waiting"
                );
            }
        });

        rx.await.map_err(|err| {
            OrchestratorError::InternalError(format!(
                "operation task ended before reporting result: {err}"
            ))
        })?
    }

    async fn protect_image_refs(
        &self,
        owner: RuntimeImageOwner,
        artifacts: RuntimeArtifactSet,
        context: &'static str,
    ) -> Result<()> {
        self.image_refs
            .pin(owner, artifacts)
            .await
            .map_err(|error| {
                OrchestratorError::InternalError(format!("pin {context} image refs: {error:#}"))
            })
    }

    async fn release_image_refs(&self, owner: RuntimeImageOwner) {
        self.image_refs.unpin_best_effort(owner).await;
    }

    async fn publish_sandbox_volume_backings(
        &self,
        sandbox_id: SandboxId,
        volume_ids: &[String],
    ) -> Result<()> {
        let Some(manager) = self.volume_manager.as_ref() else {
            return Ok(());
        };
        manager
            .recover_and_publish_backings(&sandbox_id.to_string(), volume_ids)
            .await
            .map_err(|error| OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::SnapshotVolumes,
                source: error.into(),
            })
    }

    async fn finalize_terminal_volumes(&self, metadata: &SandboxMetadata) {
        let Some(manager) = self.volume_manager.as_ref() else {
            return;
        };
        let volume_ids = metadata.volume_mounts.values().cloned().collect::<Vec<_>>();
        if volume_ids.is_empty() {
            return;
        }
        let owner = metadata.id.to_string();
        if let Err(error) = manager
            .recover_and_publish_backings(&owner, &volume_ids)
            .await
        {
            warn!(sandbox_id = %metadata.id, %error, "failed to publish volumes during terminal sandbox cleanup");
        }
        if let Err(error) = manager.replace_owner_for(&owner, None, &volume_ids).await {
            warn!(sandbox_id = %metadata.id, %error, "failed to release volumes during terminal sandbox cleanup");
        }
    }

    /// Snapshot the running set's local runtime artifacts for maintenance.
    async fn collect_running_artifacts(&self) -> Vec<(SandboxId, RuntimeArtifactSet)> {
        let handles = {
            self.sandboxes
                .read()
                .await
                .iter()
                .map(|(sandbox_id, handle)| (*sandbox_id, Arc::clone(handle)))
                .collect::<Vec<_>>()
        };
        let mut running = Vec::with_capacity(handles.len());
        for (sandbox_id, handle) in handles {
            let artifacts = {
                let sandbox = handle.lock().await;
                sandbox.runtime_info().runtime_artifacts
            };
            running.push((sandbox_id, artifacts));
        }
        running.extend(
            self.failed_launch_debts
                .read()
                .await
                .iter()
                .map(|(id, debt)| (*id, debt.artifacts.clone())),
        );
        running
    }

    /// Fail-closed startup reconcile before maintenance can run: durably protect
    /// every restored paused sandbox, then drop orphaned paused protection.
    async fn reconcile_paused_at_startup(
        &self,
        restored_paused: &[(SandboxId, Arc<dyn PausedSandboxState>)],
    ) -> Result<()> {
        let mut live_paused = Vec::with_capacity(restored_paused.len());
        for (sandbox_id, paused_state) in restored_paused {
            self.protect_image_refs(
                RuntimeImageOwner::PausedSandbox(*sandbox_id),
                paused_state.runtime_artifacts(),
                "paused sandbox",
            )
            .await?;
            live_paused.push(*sandbox_id);
        }
        self.image_refs
            .reconcile_paused(&live_paused)
            .await
            .map_err(|error| {
                OrchestratorError::InternalError(format!(
                    "reconcile local image protection: {error:#}"
                ))
            })
    }

    /// Creates and starts a new sandbox from a resolved launch source.
    ///
    /// This call only returns after the sandbox is fully ready and persisted
    /// as `Running`, so callers can treat a successful return as immediately
    /// usable without additional polling.
    /// Reservations are original Worker authority receipts, not sandbox/READY claims.
    /// The retained Orchestrator owns the synchronous intent and reciprocal peer.
    pub fn native_reserve_original(
        &self,
        request: &[u8],
        epoch: u64,
        until: std::time::Instant,
    ) -> anyhow::Result<crate::sandbox::ReservedGrant> {
        anyhow::ensure!(
            std::time::Instant::now() < until,
            "late original reserve dispatch"
        );
        let mut requester = self
            .native_requester
            .as_ref()
            .context("native issuer unavailable")?
            .lock()
            .map_err(|_| anyhow::anyhow!("native issuer owner poisoned"))?;
        anyhow::ensure!(
            std::time::Instant::now() < until,
            "late original reserve owner admission"
        );
        requester.reserve_until(request, epoch, until)
    }
    pub fn native_query_original(
        &self,
        operation_id: &str,
    ) -> anyhow::Result<crate::sandbox::ReservedGrant> {
        self.native_requester
            .as_ref()
            .context("native issuer unavailable")?
            .lock()
            .map_err(|_| anyhow::anyhow!("native issuer owner poisoned"))?
            .query(operation_id)
    }

    pub(crate) async fn native_execute_original(
        self: &Arc<Self>,
        original: crate::sandbox::native_worker_ingress::OriginalExecution<'_>,
        permit: tokio::sync::OwnedRwLockReadGuard<()>,
        commit: impl FnOnce(
                &crate::sandbox::NativeControl,
                [u8; 32],
                &str,
                String,
                crate::sandbox::NativeControlRequest,
                std::time::Instant,
            ) -> anyhow::Result<serde_json::Value>
            + Send,
    ) -> anyhow::Result<(
        crate::sandbox::native_worker_ingress::Completion,
        Vec<u8>,
        Vec<u8>,
    )> {
        let crate::sandbox::native_worker_ingress::OriginalExecution {
            request,
            epoch,
            digest,
            canonical,
            sandbox,
            peer_domain,
        } = original;
        use crate::sandbox::native_worker_ingress::{Completion, FixedLaunch};
        use crate::sandbox::NativeControlRequest as Request;
        use base64::{engine::general_purpose::STANDARD, Engine};
        use sha2::{Digest, Sha256};
        let plan = FixedLaunch::parse(canonical).context("closed execution plan refused")?;
        let expires = self
            .native_requester
            .as_ref()
            .context("requester absent")?
            .lock()
            .map_err(|_| anyhow::anyhow!("requester poisoned"))?
            .original_execution_binding(request, epoch, digest, canonical, sandbox)?;
        let control = self
            .native_control_for(sandbox)
            .await
            .context("actual native control unavailable")?;
        let mut domain = Sha256::new();
        domain.update(b"scheduler-native-fixed-execution-v1");
        domain.update(peer_domain);
        domain.update(epoch.to_be_bytes());
        let caller: [u8; 32] = domain.finalize().into();
        let operation = digest.to_owned();
        let native_epoch = control.epoch().to_owned();
        anyhow::ensure!(
            std::time::Instant::now() < expires,
            "late execution admission"
        );
        let accepted = commit(
            &control,
            caller,
            &native_epoch,
            operation.clone(),
            Request::Exec {
                command: plan.plan.command.clone(),
                args: plan.plan.args.clone(),
                env: plan.plan.env.clone().into_iter().collect(),
                cwd: Some(plan.plan.cwd.clone()),
                timeout_ms: plan.plan.timeout_ms,
            },
            expires,
        )?;
        // Stop's original admission barrier may proceed only after keyed Exec
        // admission is retained in this SAME actor.
        drop(permit);
        let session = accepted["session_id"]
            .as_str()
            .context("exec identity absent")?
            .to_owned();
        let exec_id = accepted["operation_id"]
            .as_str()
            .context("exec identity absent")?
            .to_owned();
        loop {
            anyhow::ensure!(
                std::time::Instant::now() < expires,
                "execution observation expired"
            );
            let envelope = control
                .dispatch(caller, &native_epoch, operation.clone(), Request::Query {})
                .await?;
            anyhow::ensure!(
                envelope["epoch"].as_str() == Some(&native_epoch)
                    && envelope["caller_operation_id"].as_str() == Some(&operation),
                "execution route drift"
            );
            let status = envelope["result"].clone();
            anyhow::ensure!(
                status["session_id"].as_str() == Some(&session)
                    && status["operation_id"].as_str() == Some(&exec_id),
                "execution identity drift"
            );
            if status["terminal"] == true && status["process_absent"] == true {
                let state = status["state"].as_str().context("terminal state absent")?;
                let exit = status["exit_code"]
                    .as_i64()
                    .context("terminal exit absent")?;
                anyhow::ensure!(
                    (state == "succeeded" && exit == 0) || (state == "failed" && exit != 0),
                    "non-business terminal"
                );
                let out = status["stdout_bytes"]
                    .as_u64()
                    .context("terminal length absent")?;
                let err = status["stderr_bytes"]
                    .as_u64()
                    .context("terminal length absent")?;
                anyhow::ensure!(
                    out.checked_add(err).is_some_and(|n| n <= 65536),
                    "legacy output budget"
                );
                let mut outputs = Vec::new();
                for (stream, len) in [("stdout", out), ("stderr", err)] {
                    let mut bytes = Vec::with_capacity(len as usize);
                    while bytes.len() < len as usize {
                        anyhow::ensure!(
                            std::time::Instant::now() < expires,
                            "output observation expired"
                        );
                        let value = control
                            .dispatch(
                                caller,
                                &native_epoch,
                                operation.clone(),
                                Request::ExecRead {
                                    stream: stream.into(),
                                    offset: bytes.len(),
                                    length: (len as usize - bytes.len()).min(2048),
                                },
                            )
                            .await?;
                        anyhow::ensure!(
                            value["session_id"].as_str() == Some(&session)
                                && value["operation_id"].as_str() == Some(&exec_id)
                                && value["stream"].as_str() == Some(stream)
                                && value["offset"].as_u64() == Some(bytes.len() as u64)
                                && value["retained_bytes"].as_u64() == Some(len),
                            "output identity drift"
                        );
                        let chunk =
                            STANDARD.decode(value["data"].as_str().context("output missing")?)?;
                        anyhow::ensure!(
                            !chunk.is_empty()
                                && chunk.len() <= 2048
                                && bytes.len() + chunk.len() <= len as usize,
                            "output bounds"
                        );
                        bytes.extend(chunk);
                    }
                    outputs.push(bytes);
                }
                let again = control
                    .dispatch(caller, &native_epoch, operation.clone(), Request::Query {})
                    .await?;
                anyhow::ensure!(
                    again["epoch"].as_str() == Some(&native_epoch)
                        && again["caller_operation_id"].as_str() == Some(&operation)
                        && again["result"] == status
                        && std::time::Instant::now() < expires,
                    "terminal changed or expired"
                );
                let stderr = outputs.pop().unwrap();
                let stdout = outputs.pop().unwrap();
                let receipt = Completion {
                    plan_sha256: plan.plan_sha256,
                    caller_sha256: caller.iter().map(|b| format!("{b:02x}")).collect(),
                    native_epoch,
                    route_epoch: control.route_epoch(),
                    session_id: session,
                    operation_id: exec_id,
                    state: state.into(),
                    exit_code: i32::try_from(exit)?,
                    process_absent: true,
                    terminal: true,
                    acked_sequence: status["acked_sequence"]
                        .as_u64()
                        .context("terminal cursor absent")?,
                    stdout_bytes: out,
                    stderr_bytes: err,
                    stdout_sha256: format!("{:x}", Sha256::digest(&stdout)),
                    stderr_sha256: format!("{:x}", Sha256::digest(&stderr)),
                };
                return Ok((receipt, stdout, stderr));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    pub(crate) async fn native_cancel_fixed_execution(
        &self,
        sandbox: crate::types::SandboxId,
        epoch: u64,
        digest: &str,
        peer_domain: [u8; 32],
    ) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};
        let control = self
            .native_control_for(sandbox)
            .await
            .context("native control unavailable")?;
        let mut domain = Sha256::new();
        domain.update(b"scheduler-native-fixed-execution-v1");
        domain.update(peer_domain);
        domain.update(epoch.to_be_bytes());
        let caller: [u8; 32] = domain.finalize().into();
        let _ = control
            .dispatch(
                caller,
                control.epoch(),
                digest.to_owned(),
                crate::sandbox::NativeControlRequest::Cancel {},
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn native_stop_original(
        self: &Arc<Self>,
        request: &[u8],
        epoch: u64,
        digest: &str,
        until: std::time::Instant,
    ) -> anyhow::Result<(Arc<crate::sandbox::NativeExecutionStopped>, String)> {
        let binding = || -> anyhow::Result<_> {
            self.native_requester
                .as_ref()
                .context("native requester unavailable")?
                .lock()
                .map_err(|_| anyhow::anyhow!("native requester poisoned"))?
                .original_stop_binding(request, epoch, digest)
        };
        let (id, cached, grant_sha) = binding()?;
        if let Some(cached) = cached {
            return Ok((cached, grant_sha));
        }
        anyhow::ensure!(std::time::Instant::now() < until, "original stop deadline");
        // The ingress StopJob retains this entire future. No detached delete task,
        // no timeout dropping physical cleanup and no new reservation.
        let _cleanup = self
            .delete_sandbox_inner_with_stop_until(id, Some(until))
            .await;
        let (_, stopped, grant_sha) = binding()?;
        Ok((
            stopped.context("original execution stop remains unknown")?,
            grant_sha,
        ))
    }

    /// Dispatches only a previously authenticated original Worker reservation.
    /// HTTP callers cannot inject a grant or choose a new profile/SandboxId.
    pub async fn native_launch_original(
        self: &Arc<Self>,
        operation_id: &str,
        canonical_launch: &[u8],
    ) -> Result<SandboxMetadata> {
        let material = self
            .native_requester
            .as_ref()
            .context("native issuer unavailable")?
            .lock()
            .map_err(|_| anyhow::anyhow!("native issuer owner poisoned"))?
            .begin_launch(operation_id, canonical_launch, &self.factory)?;
        let id = material.id;
        let this = Arc::clone(self);
        let operation_id = operation_id.to_owned();
        self.run_cancellation_safe("native original create", id, async move {
            let context = crate::snapshot::CommandContext {
                user: Some("1000".into()),
                workdir: "/workspace".into(),
                ..Default::default()
            };
            let resources = crate::types::SandboxResources {
                cpu_count: 1,
                memory_mib: material.memory_mib,
                disk_size_mib: 0,
            };
            let build = FreshSandboxBuildSpec {
                image_config_path: material.rootfs_path,
                context: context.clone(),
                resources,
                extra_drives: Vec::new(),
                extra_boot_args: None,
            };
            let launch = SandboxLaunchConfig {
                sandbox_id: id,
                snapshot_id: material.rootfs_sha256.clone(),
                ..Default::default()
            };
            let metadata = SandboxMetadata {
                id,
                snapshot_id: material.rootfs_sha256,
                resources,
                context,
                virtualization_mode: ConfigManager::global_config().virtualization_mode,
                runtime_versions: configured_runtime_versions(),
                timeout_action: SandboxTimeoutAction::Delete,
                ..Default::default()
            };
            let remaining = material
                .expires
                .checked_duration_since(std::time::Instant::now())
                .context("native original Worker expired")?;
            let plan = LaunchPlan::for_create_fresh(
                id,
                build,
                launch,
                metadata,
                NewTimeout::Set(remaining),
            );
            let result = this
                .launch_sandbox_owned(plan, Some((material.owner, material.expires)))
                .await?;
            let receipt = serde_json::to_vec(&result).context("native original Ready encode")?;
            this.native_requester
                .as_ref()
                .unwrap()
                .lock()
                .map_err(|_| anyhow::anyhow!("native issuer owner poisoned"))?
                .cache_ready(&operation_id, receipt)?;
            Ok(result)
        })
        .await
    }

    #[cfg(test)]
    pub(crate) fn qualification_native_original_expiry(
        &self,
        operation_id: &str,
    ) -> Option<std::time::Instant> {
        self.native_requester
            .as_ref()?
            .lock()
            .ok()?
            .qualification_original_expiry(operation_id)
    }

    #[cfg(test)]
    pub(crate) fn qualification_native_original_sandbox_id(
        &self,
        operation_id: &str,
    ) -> Option<SandboxId> {
        self.native_requester
            .as_ref()?
            .lock()
            .ok()?
            .original_sandbox_id(operation_id)
            .map(SandboxId::from_uuid)
    }

    #[cfg(test)]
    pub(crate) fn qualification_native_original_owner(
        &self,
        operation_id: &str,
    ) -> Option<SandboxHandle> {
        self.native_requester
            .as_ref()?
            .lock()
            .ok()?
            .qualification_original_owner(operation_id)
    }

    #[cfg(test)]
    pub(crate) async fn qualification_native_registered_owner(
        &self,
        id: SandboxId,
    ) -> Option<SandboxHandle> {
        self.sandboxes.read().await.get(&id).cloned()
    }

    #[cfg(test)]
    pub(crate) fn qualification_native_requester_retire_identity(&self) -> anyhow::Result<()> {
        self.native_requester
            .as_ref()
            .context("native issuer unavailable")?
            .lock()
            .map_err(|_| anyhow::anyhow!("native issuer owner poisoned"))?
            .retire_identity()
    }

    fn retire_native_original_owner(
        &self,
        id: SandboxId,
        handle: &SandboxHandle,
        stopped: Option<Arc<crate::sandbox::NativeExecutionStopped>>,
    ) -> anyhow::Result<()> {
        if let Some(requester) = &self.native_requester {
            requester
                .lock()
                .map_err(|_| anyhow::anyhow!("native requester poisoned"))?
                .retire_backend_owner(id, handle, stopped)?;
        }
        Ok(())
    }
    pub(crate) fn native_create_incarnation(&self) -> uuid::Uuid {
        self.native_create_incarnation
    }

    pub async fn create_sandbox(
        self: &Arc<Self>,
        request: CreateSandboxRequest,
    ) -> Result<SandboxMetadata> {
        let sandbox_id = SandboxId::new();
        let this = Arc::clone(self);
        self.run_cancellation_safe("create", sandbox_id, async move {
            this.create_sandbox_inner(sandbox_id, request, false).await
        })
        .await
    }

    pub(crate) async fn create_template_builder(
        self: &Arc<Self>,
        build_id: SandboxId,
        request: CreateSandboxRequest,
    ) -> Result<SandboxMetadata> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("create_builder", build_id, async move {
            this.create_sandbox_inner(build_id, request, true).await
        })
        .await
    }

    #[tracing::instrument(
        name = "create_sandbox",
        skip(self, request),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn create_sandbox_inner(
        self: Arc<Self>,
        sandbox_id: SandboxId,
        request: CreateSandboxRequest,
        template_builder: bool,
    ) -> Result<SandboxMetadata> {
        if let Err(err) = self.ensure_accepting_lifecycle_operations() {
            self.counters.record_create_fail(1);
            return Err(err);
        }

        let CreateSandboxRequest {
            source,
            timeout,
            timeout_action,
            user_metadata,
            env_vars,
            auto_resume,
            network_policy,
            custom_extension_params,
            secure,
            volume_mounts,
            extra_drives: launch_extra_drives,
            extra_drives_in_snapshot,
        } = request;
        let envd_access_token = secure.then(|| self.access_tokens.generate(sandbox_id));
        info!(timeout = ?timeout, "creating sandbox");

        let result = match source {
            SandboxLaunchSource::Snapshot(snapshot) => {
                let record = snapshot.record();
                let committed = snapshot.committed();
                let configured_mode = ConfigManager::global_config().virtualization_mode;
                if committed.virtualization_mode != configured_mode {
                    self.counters.record_create_fail(1);
                    return Err(OrchestratorError::VirtualizationModeMismatch {
                        resource: format!("snapshot {}", record.id),
                        resource_mode: committed.virtualization_mode,
                        node_mode: configured_mode,
                    });
                }
                let launch_image_configs = committed.image_configs.clone();
                let mut extra_mmds = serde_json::Map::new();
                if !launch_image_configs.is_empty() {
                    extra_mmds.insert("imageConfigs".to_string(), launch_image_configs.to_value());
                };
                // Effective custom config: a launch-provided value overrides the
                // one persisted in the source snapshot; otherwise inherit it.
                // Store the effective value so publishing a snapshot from this
                // sandbox keeps the inherited config instead of dropping it.
                let effective_custom_extension_params = custom_extension_params
                    .clone()
                    .or_else(|| committed.custom_extension_params.clone());
                let launch_config = SandboxLaunchConfig {
                    sandbox_id,
                    snapshot_id: record.id.to_string(),
                    env_vars,
                    network: network_policy.runtime_policy(),
                    extra_mmds,
                    custom_extension_params: effective_custom_extension_params.clone(),
                    envd_access_token: envd_access_token.clone(),
                    extra_drives: launch_extra_drives.clone(),
                    extra_drives_in_snapshot,
                };

                let transitional_metadata = SandboxMetadata {
                    id: sandbox_id,
                    template_builder,
                    snapshot_id: record.id.to_string(),
                    snapshot_alias: record.alias.as_ref().map(ToString::to_string),
                    virtualization_mode: committed.virtualization_mode,
                    runtime_versions: committed.runtime_versions.clone(),
                    resources: *snapshot.resources(),
                    context: committed.context.clone(),
                    startup: committed.startup.clone(),
                    image_configs: launch_image_configs,
                    timeout_action,
                    auto_resume,
                    user_metadata,
                    network_policy,
                    custom_extension_params: effective_custom_extension_params,
                    volume_mounts: volume_mounts.clone(),
                    secure,
                    ..Default::default()
                };

                self.launch_sandbox(LaunchPlan::for_create_from_snapshot(
                    sandbox_id,
                    snapshot,
                    launch_config,
                    transitional_metadata,
                    NewTimeout::Set(timeout.unwrap_or(self.default_sandbox_timeout)),
                ))
                .await
            }
            SandboxLaunchSource::Image {
                image_ref,
                overlaybd_config_path,
                context,
                resources,
                mut extra_drives,
                extra_boot_args,
                image_configs,
            } => {
                let context = *context;
                extra_drives.extend(launch_extra_drives);
                let resources = resources.unwrap_or_else(default_fresh_sandbox_resources);
                let launch_image_configs = *image_configs;
                let mut extra_mmds = serde_json::Map::new();
                if !launch_image_configs.is_empty() {
                    extra_mmds.insert("imageConfigs".to_string(), launch_image_configs.to_value());
                };
                let launch_config = SandboxLaunchConfig {
                    sandbox_id,
                    snapshot_id: image_ref.clone(),
                    env_vars,
                    network: network_policy.runtime_policy(),
                    extra_mmds,
                    custom_extension_params: custom_extension_params.clone(),
                    envd_access_token,
                    extra_drives: Vec::new(),
                    extra_drives_in_snapshot: false,
                };
                let build_spec = FreshSandboxBuildSpec {
                    image_config_path: overlaybd_config_path,
                    context: context.clone(),
                    resources,
                    extra_drives,
                    extra_boot_args,
                };

                let transitional_metadata = SandboxMetadata {
                    id: sandbox_id,
                    template_builder,
                    snapshot_id: image_ref,
                    snapshot_alias: None,
                    virtualization_mode: ConfigManager::global_config().virtualization_mode,
                    runtime_versions: configured_runtime_versions(),
                    resources,
                    context,
                    image_configs: launch_image_configs,
                    timeout_action,
                    auto_resume,
                    user_metadata,
                    network_policy,
                    custom_extension_params,
                    volume_mounts,
                    secure,
                    ..Default::default()
                };

                self.launch_sandbox(LaunchPlan::for_create_fresh(
                    sandbox_id,
                    build_spec,
                    launch_config,
                    transitional_metadata,
                    NewTimeout::Set(timeout.unwrap_or(self.default_sandbox_timeout)),
                ))
                .await
            }
        };

        match result {
            Ok(metadata) => {
                self.counters.record_create_success(1);
                self.publish_sandbox_event(
                    SandboxLifecycleEventType::Create,
                    metadata.id,
                    metadata.resources,
                );
                Ok(metadata)
            }
            Err(err) => {
                self.counters.record_create_fail(1);
                Err(err)
            }
        }
    }

    /// Forks a running sandbox into multiple new sandboxes on the same node.
    pub async fn fork_sandbox(
        self: &Arc<Self>,
        source_sandbox_id: SandboxId,
        count: u32,
        new_timeout: NewTimeout,
    ) -> Result<Vec<SandboxForkOutcome>> {
        if self
            .store
            .get(&source_sandbox_id)
            .await?
            .is_some_and(|metadata| !metadata.volume_mounts.is_empty())
        {
            return Err(OrchestratorError::InternalError(
                "fork with volume mounts requires volume-aware child specs".to_string(),
            ));
        }
        let child_specs = (0..count)
            .map(|_| SandboxForkChildSpec {
                sandbox_id: SandboxId::new(),
                ..Default::default()
            })
            .collect();
        self.fork_sandbox_with_specs(source_sandbox_id, child_specs, new_timeout)
            .await
    }

    pub async fn fork_sandbox_with_specs(
        self: &Arc<Self>,
        source_sandbox_id: SandboxId,
        child_specs: Vec<SandboxForkChildSpec>,
        new_timeout: NewTimeout,
    ) -> Result<Vec<SandboxForkOutcome>> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("fork", source_sandbox_id, async move {
            this.fork_sandbox_inner(source_sandbox_id, child_specs, new_timeout)
                .await
        })
        .await
    }

    #[tracing::instrument(
        name = "fork_sandbox",
        skip(self, child_specs),
        fields(source_sandbox_id = %source_sandbox_id, count = child_specs.len())
    )]
    async fn fork_sandbox_inner(
        self: Arc<Self>,
        source_sandbox_id: SandboxId,
        child_specs: Vec<SandboxForkChildSpec>,
        new_timeout: NewTimeout,
    ) -> Result<Vec<SandboxForkOutcome>> {
        self.ensure_accepting_lifecycle_operations()?;

        let count = u32::try_from(child_specs.len())
            .map_err(|_| OrchestratorError::InternalError("too many fork children".to_string()))?;
        let mut child_ids = HashSet::with_capacity(child_specs.len());
        for child in &child_specs {
            if child.sandbox_id == source_sandbox_id || !child_ids.insert(child.sandbox_id) {
                return Err(OrchestratorError::InternalError(
                    "fork child sandbox IDs must be unique and differ from the source".to_string(),
                ));
            }
            if self.store.get(&child.sandbox_id).await?.is_some() {
                return Err(OrchestratorError::InternalError(format!(
                    "fork child sandbox {} already exists",
                    child.sandbox_id
                )));
            }
        }
        info!("forking sandboxes");

        let source_handle = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&source_sandbox_id).cloned()
        }
        .ok_or(OrchestratorError::SandboxNotFound(source_sandbox_id))?;

        let source_metadata = self
            .store
            .update_if_state(&source_sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.state = SandboxState::Forking
            })
            .await
            .map_err(|err| match err {
                StoreError::StateConflict { actual_state, .. } => match actual_state {
                    SandboxState::Killing => OrchestratorError::SandboxNotFound(source_sandbox_id),
                    _ => OrchestratorError::InvalidSandboxState {
                        sandbox_id: source_sandbox_id,
                        state: actual_state,
                    },
                },
                err => OrchestratorError::from(err),
            })?
            .previous;

        let backend_specs = child_specs
            .iter()
            .map(|child| SandboxForkSpec {
                sandbox_id: child.sandbox_id,
                envd_access_token: source_metadata
                    .secure
                    .then(|| self.access_tokens.generate(child.sandbox_id)),
                extra_drives: child.extra_drives.clone(),
                replace_drive_ids: child.replace_drive_ids.clone(),
            })
            .collect::<Vec<_>>();

        // Start to fork the sandbox.
        // This is a single operation that will return a list of results for each child sandbox.
        let fork_result = {
            let mut sandbox = source_handle.lock().await;
            sandbox.fork(&backend_specs).await
        };
        let forked_backends = match fork_result {
            Ok(forked_backends) => forked_backends,
            Err(err) => {
                warn!(error = ?err, "failed to fork sandbox");
                self.counters.record_create_fail(u64::from(count));
                if err.is_terminal() {
                    self.detach_sandbox_handle_and_route(&source_sandbox_id)
                        .await;
                    let _ = {
                        let mut sandbox = source_handle.lock().await;
                        sandbox.stop().await
                    };
                    self.finalize_terminal_volumes(&source_metadata).await;
                    self.store.remove(&source_sandbox_id).await?;
                } else {
                    let _ = self
                        .store
                        .update_state_if_state(
                            &source_sandbox_id,
                            SandboxState::Running,
                            &[SandboxState::Forking],
                        )
                        .await;
                }
                return Err(OrchestratorError::SandboxOperationFailed {
                    sandbox_id: source_sandbox_id,
                    operation: SandboxOperation::Fork,
                    source: err.into(),
                });
            }
        };

        // Restore the source sandbox's state to Running.
        if let Err(err) = self
            .store
            .update_state_if_state(
                &source_sandbox_id,
                SandboxState::Running,
                &[SandboxState::Forking],
            )
            .await
        {
            warn!(error = ?err, "failed to restore source sandbox metadata after fork");
        }

        // Register each forked sandbox in the store and runtime, and publish events.
        let mut outcomes = Vec::with_capacity(child_specs.len());
        let mut successes = 0u64;
        let now = SystemTime::now();
        for (child, backend) in child_specs.into_iter().zip(forked_backends) {
            let sandbox_id = child.sandbox_id;
            let backend = match backend {
                Ok(backend) => backend,
                Err(err) => {
                    warn!(%sandbox_id, error = ?err, "failed to start forked sandbox");
                    outcomes.push(Err(Self::fork_child_error(sandbox_id, err)));
                    continue;
                }
            };

            let mut metadata = source_metadata.clone();
            metadata.id = sandbox_id;
            metadata.state = SandboxState::Running;
            metadata.created_at = now;
            metadata.paused_state = None;
            metadata.volume_mounts = child.volume_mounts;
            metadata.update_timeout(new_timeout);

            let proxy_target = match Self::proxy_target_from_sandbox(backend.as_ref()) {
                Ok(proxy_target) => proxy_target,
                Err(err) => {
                    Self::stop_failed_fork(backend, sandbox_id).await;
                    outcomes.push(Err(Self::fork_child_error(
                        sandbox_id,
                        anyhow::Error::new(err),
                    )));
                    continue;
                }
            };
            if let Err(err) = self.store.add(metadata.clone()).await {
                warn!(%sandbox_id, error = ?err, "failed to register forked sandbox");
                Self::stop_failed_fork(backend, sandbox_id).await;
                outcomes.push(Err(Self::fork_child_error(
                    sandbox_id,
                    anyhow::Error::new(err),
                )));
                continue;
            }
            self.sandboxes
                .write()
                .await
                .insert(metadata.id, Arc::new(Mutex::new(backend)));
            self.upsert_proxy_route(metadata.id, proxy_target).await;
            self.publish_sandbox_event(
                SandboxLifecycleEventType::Fork,
                metadata.id,
                metadata.resources,
            );
            successes += 1;
            outcomes.push(Ok(metadata));
        }

        self.counters.record_create_success(successes);
        self.counters
            .record_create_fail(u64::from(count) - successes);
        Ok(outcomes)
    }

    fn fork_child_error(sandbox_id: SandboxId, source: anyhow::Error) -> OrchestratorError {
        OrchestratorError::SandboxOperationFailed {
            sandbox_id,
            operation: SandboxOperation::Fork,
            source,
        }
    }

    async fn stop_failed_fork(mut backend: Box<dyn SandboxBackend>, sandbox_id: SandboxId) {
        if let Err(err) = backend.stop().await {
            warn!(%sandbox_id, error = ?err, "failed to stop unsuccessful fork");
        }
    }

    /// Retrieves the metadata for a sandbox by its ID.
    #[tracing::instrument(skip(self), fields(sandbox_id = %sandbox_id))]
    pub async fn get_sandbox(&self, sandbox_id: &SandboxId) -> Result<Option<SandboxMetadata>> {
        if let Some(metadata) = self.store.get(sandbox_id).await? {
            return Ok(Some(metadata));
        }
        Ok(self
            .failed_launch_debts
            .read()
            .await
            .values()
            .find(|debt| &debt.sandbox_id == sandbox_id)
            .and_then(|debt| debt.metadata.clone()))
    }

    /// Lists all sandboxes with their metadata.
    #[tracing::instrument(skip(self))]
    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxMetadata>> {
        self.list_sandboxes_filtered(SandboxListFilter::matches_all())
            .await
    }

    /// Lists all sandbox IDs currently tracked by the store.
    pub async fn list_sandbox_ids(&self) -> Result<Vec<SandboxId>> {
        // Reserve builder routing while its image is resolving and while the
        // final template is publishing, even when no VM is currently running.
        let mut ids: HashSet<_> = self.store.list_ids().await?.into_iter().collect();
        ids.extend(self.template_build_ids.read().await.iter().copied());
        ids.extend(
            self.failed_launch_debts
                .read()
                .await
                .values()
                .map(|debt| debt.sandbox_id),
        );
        Ok(ids.into_iter().collect())
    }

    pub(crate) async fn register_template_build(&self, id: SandboxId) {
        self.template_build_ids.write().await.insert(id);
    }

    pub(crate) async fn unregister_template_build(&self, id: SandboxId) {
        self.template_build_ids.write().await.remove(&id);
    }

    /// Lists sandboxes that match the provided filter criteria:
    /// - If `states` is provided, only sandboxes in those states will be included.
    /// - If `user_metadata` is provided, only sandboxes whose user metadata contains
    ///   all the specified key-value pairs will be included.
    /// - If `started_after` is provided, only sandboxes created at or after that instant
    ///   will be included.
    /// - If `template` is provided, only sandboxes using the matching snapshot ID or alias
    ///   will be included.
    #[tracing::instrument(skip(self, filter))]
    pub async fn list_sandboxes_filtered(
        &self,
        filter: SandboxListFilter,
    ) -> Result<Vec<SandboxMetadata>> {
        let mut metadata = self.store.list_filtered(filter.clone()).await?;
        for debt in self.failed_launch_debts.read().await.values() {
            if let Some(row) = &debt.metadata {
                if !metadata.iter().any(|record| record.id == row.id)
                    && filter
                        .states
                        .as_ref()
                        .is_none_or(|states| states.contains(&row.state))
                    && !filter
                        .excluded_states
                        .as_ref()
                        .is_some_and(|states| states.contains(&row.state))
                    && filter.user_metadata.as_ref().is_none_or(|required| {
                        row.user_metadata.as_ref().is_some_and(|actual| {
                            required
                                .iter()
                                .all(|(key, value)| actual.get(key) == Some(value))
                        })
                    })
                    && filter
                        .started_after
                        .is_none_or(|after| row.created_at >= after)
                    && filter.template.as_ref().is_none_or(|template| {
                        row.snapshot_id == *template
                            || row.snapshot_alias.as_deref() == Some(template.as_str())
                    })
                {
                    metadata.push(row.clone());
                }
            }
        }
        Ok(metadata
            .into_iter()
            .filter(|metadata| !metadata.template_builder)
            .collect())
    }

    pub fn get_envd_access_token(&self, metadata: &SandboxMetadata) -> Option<EnvdAccessToken> {
        metadata
            .secure
            .then(|| self.access_tokens.generate(metadata.id))
    }

    pub fn validate_envd_access_token(&self, sandbox_id: SandboxId, candidate: &str) -> bool {
        self.access_tokens.matches(sandbox_id, candidate)
    }

    pub fn traffic_access_token(&self, sandbox_id: SandboxId) -> String {
        self.access_tokens.generate_traffic(sandbox_id)
    }

    pub fn validate_traffic_access_token(&self, sandbox_id: SandboxId, candidate: &str) -> bool {
        self.access_tokens.matches_traffic(sandbox_id, candidate)
    }

    /// Resolves the current proxyability of a sandbox without touching the sandbox mutex.
    #[tracing::instrument(skip(self), fields(sandbox_id = %sandbox_id))]
    pub async fn proxy_lookup_for(&self, sandbox_id: &SandboxId) -> Result<ProxyLookupResult> {
        if let Some(route) = self.proxy_routes.read().await.route(sandbox_id).cloned() {
            trace!(
                version = route.version(),
                "resolved running proxy target from runtime table"
            );
            return Ok(match route.target() {
                Some(target) => ProxyLookupResult::Ready(target.clone()),
                None => ProxyLookupResult::NativeControl,
            });
        }

        let metadata = self.get_sandbox(sandbox_id).await?;
        Ok(match metadata {
            None => {
                debug!("sandbox has no runtime route or persisted metadata");
                ProxyLookupResult::NotFound
            }
            Some(metadata) if metadata.state == SandboxState::Running => {
                warn!("running sandbox is missing a runtime proxy route");
                ProxyLookupResult::RouteMissing
            }
            Some(metadata) if metadata.state == SandboxState::Paused => {
                debug!(auto_resume = metadata.auto_resume, "sandbox is paused");
                ProxyLookupResult::Paused {
                    auto_resume: metadata.auto_resume,
                }
            }
            Some(metadata) => {
                debug!(state = ?metadata.state, "sandbox exists but is not proxyable");
                ProxyLookupResult::Unavailable(metadata.state)
            }
        })
    }

    /// Updates the keep-alive timeout for a RUNNING sandbox.
    /// If `timeout` is `None`, default timeout will be applied.
    /// If `allow_shorter` is `false`, the update will be skipped if the new TTL is not longer than the existing TTL.
    ///
    /// When the sandbox is in a transitional state that may resolve to `Running`,
    /// this method waits for the transition to complete before re-evaluating the state.
    #[tracing::instrument(skip(self), fields(sandbox_id = %sandbox_id, allow_shorter = allow_shorter))]
    pub async fn keep_alive_for(
        &self,
        sandbox_id: SandboxId,
        timeout: Option<Duration>,
        allow_shorter: bool,
    ) -> Result<Option<SandboxMetadata>> {
        self.ensure_accepting_lifecycle_operations()?;

        if timeout.is_none() {
            debug!("applying default timeout for keep-alive");
        } else {
            debug!(?timeout, "updating keep-alive timeout");
        }
        let valid_timeout = timeout.unwrap_or(self.default_sandbox_timeout);

        let mut metadata = match self.store.get(&sandbox_id).await? {
            Some(metadata) => metadata,
            None => return Err(OrchestratorError::SandboxNotFound(sandbox_id)),
        };

        // If the sandbox is in a transitional state that may lead to Running,
        // wait for the transition to complete before checking whether the
        // keep-alive is applicable.
        if matches!(
            metadata.state,
            SandboxState::Creating
                | SandboxState::Resuming
                | SandboxState::Snapshotting
                | SandboxState::Forking
        ) {
            debug!(state = ?metadata.state, "sandbox in transitional state, waiting before applying keep-alive");
            metadata = self.wait_for_transition(sandbox_id, metadata.state).await?;
        }

        if metadata.state != SandboxState::Running {
            info!(state = ?metadata.state, "cannot update keep-alive timeout in non-running state");
            return Err(OrchestratorError::InvalidSandboxState {
                sandbox_id,
                state: metadata.state,
            });
        }

        let mut timeout_updated = false;
        let update_result = self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                let new_expire_time = SystemTime::now().checked_add(valid_timeout);
                if !allow_shorter {
                    if let Some(current_expire) = metadata.expires_at {
                        if let Some(new_expire) = new_expire_time {
                            if new_expire <= current_expire {
                                info!(
                                    current_expire = ?current_expire,
                                    new_expire = ?new_expire,
                                    "new timeout is not longer than current timeout, skipping update",
                                );
                                return;
                            }
                        }
                    }
                }

                metadata.set_timeout(Some(valid_timeout));
                timeout_updated = true;
            })
            .await
            .map_err(|err| match err {
                StoreError::StateConflict { actual_state, .. } => {
                    info!(state = ?actual_state, "keep-alive update failed due to state conflict");
                    OrchestratorError::InvalidSandboxState {
                        sandbox_id,
                        state: actual_state,
                    }
                }
                other => OrchestratorError::from(other),
            })?;
        if timeout_updated {
            info!(?valid_timeout, "sandbox keep-alive timeout updated");
        }

        Ok(Some(update_result.current))
    }

    /// Stops and deletes the sandbox with the given ID.
    ///
    /// If the sandbox is currently in a transitional state, this method waits for
    /// the in-progress operation to finish before proceeding with deletion, preventing
    /// races where an ongoing operation might overwrite the `Killing` state.
    pub async fn delete_sandbox(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("delete", sandbox_id, async move {
            this.delete_sandbox_inner(sandbox_id).await
        })
        .await
    }

    async fn deletion_progress(&self, sandbox_id: SandboxId) -> Arc<Mutex<DeleteProgress>> {
        self.deletions
            .lock()
            .await
            .entry(sandbox_id)
            .or_default()
            .clone()
    }

    #[tracing::instrument(
        name = "delete_sandbox",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn delete_sandbox_inner(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        self.delete_sandbox_inner_with_stop_until(sandbox_id, None)
            .await
    }

    async fn delete_sandbox_inner_with_stop_until(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        stop_until: Option<std::time::Instant>,
    ) -> Result<()> {
        if let Some(ingress) = self.native_ingress.get() {
            let operation = {
                self.native_requester
                    .as_ref()
                    .context("native requester unavailable")?
                    .lock()
                    .map_err(|_| anyhow::anyhow!("native requester poisoned"))?
                    .original_operation_for_sandbox(sandbox_id.into_inner())
            };
            if let Some(operation) = operation {
                ingress
                    .fence_original(
                        &operation,
                        stop_until
                            .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(30)),
                    )
                    .await?;
            }
        }
        info!("deleting sandbox");
        let deletion = self.deletion_progress(sandbox_id).await;
        let mut progress = deletion.lock().await;
        if stop_until.is_some_and(|until| std::time::Instant::now() >= until) {
            return Err(OrchestratorError::InternalError(
                "original stop admission deadline".into(),
            ));
        }
        match *progress {
            DeleteProgress::Done => return Ok(()),
            DeleteProgress::Capture => {}
            _ => {
                return self
                    .delete_sandbox_impl(
                        sandbox_id,
                        SandboxState::Killing,
                        &mut progress,
                        stop_until,
                    )
                    .await
            }
        }
        self.retry_failed_launch_debts(Some(sandbox_id)).await?;
        if self.store.get(&sandbox_id).await?.is_none() {
            let original_retired = self
                .cleanup_provenance
                .lock()
                .map_err(|_| {
                    OrchestratorError::InternalError("cleanup provenance lock unavailable".into())
                })?
                .retired(sandbox_id);
            // A past owner retirement cannot acknowledge a replacement's absence.
            let registry = self.sandboxes.read().await;
            let debts = self.failed_launch_debts.read().await;
            return if original_retired
                && !registry.contains_key(&sandbox_id)
                && !debts.values().any(|debt| debt.sandbox_id == sandbox_id)
            {
                Ok(())
            } else {
                Err(OrchestratorError::SandboxNotFound(sandbox_id))
            };
        }

        // Attempt to transition to Killing, retrying after waiting whenever we
        // find the sandbox in a transitional state.
        let previous_state = loop {
            // A terminal capture can hand off Stop while we waited for its
            // state transition. Re-read the phase under this same mutex.
            match *progress {
                DeleteProgress::Done => return Ok(()),
                DeleteProgress::Capture => {}
                _ => {
                    return self
                        .delete_sandbox_impl(
                            sandbox_id,
                            SandboxState::Killing,
                            &mut progress,
                            stop_until,
                        )
                        .await
                }
            }
            match self
                .store
                .update_state_if_state(
                    &sandbox_id,
                    SandboxState::Killing,
                    &[SandboxState::Running, SandboxState::Paused],
                )
                .await
            {
                Ok(previous_state) => break previous_state,
                Err(StoreError::StateConflict { actual_state, .. }) => match actual_state {
                    SandboxState::Killing => {
                        debug!("sandbox already in killing state, waiting for delete to finish");
                        match self
                            .wait_for_transition(sandbox_id, SandboxState::Killing)
                            .await
                        {
                            Ok(_) => {
                                // The in-flight delete rolled back to a stable state.
                                // Retry the Killing CAS rather than letting multiple
                                // deleters run concurrently.
                                continue;
                            }
                            Err(OrchestratorError::SandboxNotFound(_)) => {
                                info!("sandbox was deleted by a concurrent delete");
                                return Ok(());
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    SandboxState::Creating
                    | SandboxState::Snapshotting
                    | SandboxState::Forking
                    | SandboxState::Pausing
                    | SandboxState::Resuming => {
                        // An in-progress operation is currently holding the sandbox in this
                        // transitional state.  Wait for it to finish so our Killing transition
                        // doesn't race with the final state write from that operation.
                        debug!(
                            state = ?actual_state,
                            "sandbox in transitional state, waiting before deletion"
                        );
                        // The capture owner needs this mutex to publish its
                        // closed Stop handoff. Never wait on its state while
                        // preventing that handoff from completing.
                        drop(progress);
                        let transition = self.wait_for_transition(sandbox_id, actual_state).await;
                        progress = deletion.lock().await;
                        match transition {
                            Ok(_) => {
                                // Recheck the handed-off phase before the CAS.
                                continue;
                            }
                            Err(OrchestratorError::SandboxNotFound(_)) => {
                                // Sandbox was removed while we waited (e.g. by
                                // another concurrent delete).
                                info!("sandbox was deleted while waiting for transitional state");
                                return Ok(());
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    _ => {
                        return Err(OrchestratorError::from(StoreError::StateConflict {
                            sandbox_id,
                            expected_states: vec![SandboxState::Running, SandboxState::Paused],
                            actual_state,
                        }));
                    }
                },
                Err(err) => {
                    if matches!(err, StoreError::SandboxNotFound { .. }) {
                        self.deletions.lock().await.remove(&sandbox_id);
                    }
                    return Err(OrchestratorError::from(err));
                }
            }
        };

        self.delete_sandbox_impl(sandbox_id, previous_state, &mut progress, stop_until)
            .await
    }

    async fn claim_expired_running_sandbox(
        &self,
        sandbox_id: SandboxId,
        cutoff: SystemTime,
        claimed_state: SandboxState,
    ) -> Result<bool> {
        match self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                if metadata.is_expired(cutoff) {
                    metadata.state = claimed_state;
                }
            })
            .await
        {
            Ok(update) if update.current.state == claimed_state => Ok(true),
            Ok(update) => {
                debug!(
                    expires_at = ?update.current.expires_at,
                    ?cutoff,
                    "skipping auto-eviction because sandbox expiry was updated"
                );
                Ok(false)
            }
            Err(StoreError::StateConflict { actual_state, .. }) => {
                debug!(
                    state = ?actual_state,
                    "skipping auto-eviction because sandbox state changed"
                );
                Ok(false)
            }
            Err(StoreError::SandboxNotFound { .. }) => {
                debug!("skipping auto-eviction because sandbox no longer exists");
                Ok(false)
            }
            Err(err) => Err(OrchestratorError::from(err)),
        }
    }

    async fn delete_sandbox_impl(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        previous_state: SandboxState,
        progress: &mut DeleteProgress,
        stop_until: Option<std::time::Instant>,
    ) -> Result<()> {
        let metadata = self.store.get(&sandbox_id).await?;
        let optional_cache = metadata
            .as_ref()
            .is_some_and(|record| record.template_builder);
        let volume_ids = metadata
            .map(|metadata| metadata.volume_mounts.into_values().collect::<Vec<_>>())
            .unwrap_or_default();
        if stop_until.is_some_and(|until| std::time::Instant::now() >= until) {
            return Err(OrchestratorError::InternalError(
                "original stop dispatch deadline".into(),
            ));
        }
        self.close_native_admission(sandbox_id).await;
        let (handle, removed_route) = self.detach_sandbox_handle_and_route(&sandbox_id).await;
        let mut capture_error = None;

        if matches!(progress, DeleteProgress::Capture) {
            let mut volumes_frozen = false;
            let capture_result: std::result::Result<(), SandboxCaptureError> = async {
                if let Some(handle) = handle.as_ref() {
                    if previous_state == SandboxState::Running && !volume_ids.is_empty() {
                        handle.lock().await.freeze_and_snapshot_volumes().await?;
                        volumes_frozen = true;
                    }
                }
                self.publish_sandbox_volume_backings(sandbox_id, &volume_ids)
                    .await
                    .map_err(|error| SandboxCaptureError::recoverable(error.into()))
            }
            .await;
            if let Err(mut error) = capture_result {
                if volumes_frozen && !error.is_terminal() && !optional_cache {
                    if let Some(handle) = handle.as_ref() {
                        if let Err(thaw_error) = handle.lock().await.thaw_volumes().await {
                            error = SandboxCaptureError::terminal(anyhow::anyhow!(
                                "delete failed: {error}; thaw failed: {thaw_error:#}"
                            ));
                        }
                    }
                }
                // Builder caches are optional; still stop and release the worker on capture failure.
                if !error.is_terminal() && !optional_cache {
                    if let Some(handle) = handle {
                        self.sandboxes.write().await.insert(sandbox_id, handle);
                    }
                    self.restore_proxy_route(sandbox_id, removed_route).await;
                    self.store
                        .update_state_if_state(
                            &sandbox_id,
                            previous_state,
                            &[SandboxState::Killing],
                        )
                        .await?;
                    return Err(OrchestratorError::SandboxOperationFailed {
                        sandbox_id,
                        operation: SandboxOperation::Stop,
                        source: error.into(),
                    });
                }
                warn!(
                    ?error,
                    "volume capture failed; stopping sandbox and failing its volumes"
                );
                capture_error = Some(error);
            }
            *progress = DeleteProgress::Stop {
                capture_failed: capture_error.is_some(),
            };
        }

        let cleanup: anyhow::Result<()> = async {
            if let DeleteProgress::Stop { capture_failed } = *progress {
                let retiring_native = if let Some(handle) = handle.as_ref() {
                    let mut sandbox = handle.lock().await;
                    if stop_until.is_some_and(|until| std::time::Instant::now() >= until) {
                        anyhow::bail!("original stop physical dispatch deadline");
                    }
                    let artifacts = sandbox.runtime_info().runtime_artifacts;
                    sandbox.stop().await?;
                    let stopped = sandbox.native_execution_stopped();
                    drop(sandbox);
                    self.retire_native_original_owner(sandbox_id, handle, stopped)?;
                    Some(artifacts)
                } else {
                    None
                };
                *progress = DeleteProgress::Release {
                    capture_failed,
                    retiring_native,
                };
            }
            if let DeleteProgress::Release {
                capture_failed,
                retiring_native,
            } = progress.clone()
            {
                if let Some(manager) = self.volume_manager.as_ref() {
                    let owner = sandbox_id.to_string();
                    // An incomplete restack may leave image.json pointing at old
                    // layers. Never publish that backing as a successful capture.
                    if capture_failed {
                        manager.fail_backings(&owner, &volume_ids).await?;
                    }
                    manager.replace_owner_for(&owner, None, &volume_ids).await?;
                }
                self.remove_deleted_sandbox(sandbox_id, retiring_native)
                    .await?;
                *progress = DeleteProgress::Done;
            }
            Ok(())
        }
        .await;
        if let Err(error) = cleanup {
            if matches!(progress, DeleteProgress::Stop { .. }) {
                if let Some(handle) = handle {
                    self.sandboxes.write().await.insert(sandbox_id, handle);
                    // Stop failure is not proof of physical retirement. Preserve
                    // the original native query capability without reopening
                    // admission or changing the resumable Killing/Stop phase.
                    if let Some(route) = removed_route.filter(|route| route.target().is_none()) {
                        let mut routes = self.proxy_routes.write().await;
                        if let Some(control) = route.native_control().cloned() {
                            routes.publish_control(sandbox_id, control, route.version());
                        } else {
                            routes.publish_native(sandbox_id, route.version());
                        }
                    }
                }
            }
            warn!(?error, "sandbox deletion needs a cleanup retry");
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::Stop,
                source: error,
            });
        }
        if let Some(error) = capture_error.filter(|_| !optional_cache) {
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::Stop,
                source: error.into(),
            });
        }
        Ok(())
    }

    async fn remove_deleted_sandbox(
        &self,
        sandbox_id: SandboxId,
        retiring_native: Option<RuntimeArtifactSet>,
    ) -> Result<()> {
        let metadata = self.store.remove(&sandbox_id).await?;
        if let Some(metadata) = metadata {
            self.publish_sandbox_event(
                SandboxLifecycleEventType::Delete,
                metadata.id,
                metadata.resources,
            );
        }
        let persistence_retired = match self
            .persister
            .delete_record_and_artifacts(&sandbox_id)
            .await
        {
            Ok(()) => true,
            Err(err) => {
                warn!(error=?err,"failed to delete persisted sandbox state");
                false
            }
        };
        if persistence_retired {
            if let Some(artifacts) = retiring_native {
                self.image_refs
                    .retire_native_running(sandbox_id, artifacts)
                    .await?;
            }
        }
        self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
            .await;
        self.deletions.lock().await.remove(&sandbox_id);
        info!("sandbox deleted");

        Ok(())
    }

    /// Stops every known sandbox and tears down in-memory runtime state.
    ///
    /// This is single-flight: the first caller performs cleanup and subsequent
    /// callers wait for the same outcome rather than starting duplicate work.
    ///
    /// Cleanup itself is still best-effort: the executor keeps attempting
    /// remaining sandboxes even if individual deletions fail, then returns an
    /// error if any sandbox could not be cleaned up after several passes.
    #[tracing::instrument(skip(self))]
    pub async fn shutdown(self: &Arc<Self>) -> Result<()> {
        let was_already_shutting_down = self.is_shutting_down.swap(true, Ordering::AcqRel);
        let _ = self.shutdown_tx.send_replace(true);

        if !was_already_shutting_down {
            info!("orchestrator shutdown requested; stopping all sandboxes");
        }

        let this = Arc::clone(self);
        let outcome = self
            .shutdown_outcome
            .get_or_init(|| async move {
                ShutdownOutcome::from_result(
                    async {
                        if let Some(ingress) = this.native_ingress.get() {
                            ingress
                                .seal(std::time::Instant::now() + Duration::from_secs(30))
                                .await?;
                        }
                        this.run_shutdown_cleanup().await
                    }
                    .await,
                )
            })
            .await;

        outcome.as_result()
    }

    /// Pauses a running sandbox by taking a snapshot and stopping its VM.
    ///
    /// If another `pause_sandbox` call is already in progress for the same
    /// sandbox (`Pausing` state), this call waits for it to complete and then
    /// returns the outcome rather than duplicating the work.
    pub async fn pause_sandbox(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("pause", sandbox_id, async move {
            this.pause_sandbox_inner(sandbox_id).await
        })
        .await
    }

    #[tracing::instrument(
        name = "pause_sandbox",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn pause_sandbox_inner(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        info!("pausing sandbox");
        match self
            .store
            .update_state_if_state(&sandbox_id, SandboxState::Pausing, &[SandboxState::Running])
            .await
        {
            Ok(_) => {}
            Err(StoreError::StateConflict { actual_state, .. }) => {
                return match actual_state {
                    // Another task is already performing the pause.  Wait for
                    // it to finish and then report the final outcome.
                    SandboxState::Pausing => self.join_concurrent_pause(sandbox_id).await,
                    SandboxState::Paused => Ok(()),
                    SandboxState::Killing => {
                        info!("sandbox is being deleted while pausing");
                        Err(OrchestratorError::SandboxNotFound(sandbox_id))
                    }
                    _ => {
                        info!(state = ?actual_state, "cannot pause sandbox in current state");
                        Err(OrchestratorError::InvalidSandboxState {
                            sandbox_id,
                            state: actual_state,
                        })
                    }
                };
            }
            Err(err) => return Err(OrchestratorError::from(err)),
        }

        self.pause_sandbox_impl(sandbox_id).await
    }

    async fn pause_sandbox_impl(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        self.close_native_admission(sandbox_id).await;

        // Pin paused runtime artifacts before detaching from the running set.
        let runtime_artifacts = {
            let handle = self.sandboxes.read().await.get(&sandbox_id).cloned();
            match handle {
                Some(handle) => {
                    let sandbox = handle.lock().await;
                    sandbox.runtime_info().runtime_artifacts
                }
                None => RuntimeArtifactSet::empty(),
            }
        };
        if let Err(error) = self
            .protect_image_refs(
                RuntimeImageOwner::PausedSandbox(sandbox_id),
                runtime_artifacts,
                "paused sandbox",
            )
            .await
        {
            warn!(error = %error, "failed to protect paused runtime artifacts; keeping sandbox Running");
            let _ = self
                .store
                .update_state_if_state(&sandbox_id, SandboxState::Running, &[SandboxState::Pausing])
                .await;
            self.reopen_native_admission(sandbox_id).await;
            return Err(error);
        }

        // Allocate persistence space while the running handle and route are
        // still attached. Allocation does not mutate the backend, so failure
        // only needs to restore metadata and release the temporary image refs.
        let artifact_root = match self.persister.allocate_artifact_root(&sandbox_id).await {
            Ok(artifact_root) => artifact_root,
            Err(err) => {
                warn!(error = ?err, "failed to allocate paused sandbox artifact root");
                self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
                    .await;
                let _ = self
                    .store
                    .update_state_if_state(
                        &sandbox_id,
                        SandboxState::Running,
                        &[SandboxState::Pausing],
                    )
                    .await;
                self.reopen_native_admission(sandbox_id).await;
                return Err(OrchestratorError::from(err));
            }
        };

        let (handle, removed_proxy_route) = self.detach_sandbox_handle_and_route(&sandbox_id).await;

        let Some(handle) = handle else {
            warn!("sandbox handle not found while pausing, removing from store");
            self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
                .await;
            if let Some(metadata) = self.store.get(&sandbox_id).await? {
                self.finalize_terminal_volumes(&metadata).await;
            }
            self.store.remove(&sandbox_id).await?;
            return Err(OrchestratorError::SandboxNotFound(sandbox_id));
        };

        // Pause the sandbox and capture the paused state for resuming later.
        let paused_state_result = {
            let mut sandbox = handle.lock().await;
            sandbox.pause(artifact_root.as_deref()).await
        };

        // If pausing failed, attempt to put the sandbox back and return an error.
        let paused_state = match paused_state_result {
            Ok(s) => s,
            Err(err) => {
                warn!(error = ?err, "failed to pause sandbox");
                if err.is_terminal() {
                    // The handle was already detached from `self.sandboxes`
                    // before `pause()`. Its runtime may have been mutated; retain
                    // it only in the closed Killing/Stop cleanup phase.
                    if let Err(stop_err) = self
                        .retire_terminal_capture(sandbox_id, &handle, removed_proxy_route)
                        .await
                    {
                        warn!(error = ?stop_err, "terminal pause cleanup retained for retry");
                    }
                } else {
                    self.sandboxes.write().await.insert(sandbox_id, handle);
                    self.restore_proxy_route(sandbox_id, removed_proxy_route)
                        .await;
                    let _ = self
                        .store
                        .update_state_if_state(
                            &sandbox_id,
                            SandboxState::Running,
                            &[SandboxState::Pausing],
                        )
                        .await;
                }
                self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
                    .await;
                return Err(OrchestratorError::SandboxOperationFailed {
                    sandbox_id,
                    operation: SandboxOperation::Pause,
                    source: err.into(),
                });
            }
        };

        let persisted_metadata = {
            let mut metadata = self
                .store
                .get(&sandbox_id)
                .await?
                .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
            metadata.state = SandboxState::Paused;
            metadata.paused_state = Some(paused_state.clone());
            metadata
        };
        if let Err(err) = self
            .persister
            .persist_paused(
                &persisted_metadata,
                artifact_root.as_deref(),
                paused_state.as_ref(),
            )
            .await
        {
            warn!(error = ?err, "failed to persist paused sandbox state");
            let resume_result = {
                let mut sandbox = handle.lock().await;
                sandbox.resume().await
            };
            if let Err(resume_err) = resume_result {
                warn!(error = ?resume_err, "failed to resume sandbox after pause failure");
                let stop_result = {
                    let mut sandbox = handle.lock().await;
                    sandbox.stop().await
                };
                if let Err(stop_err) = stop_result {
                    warn!(error = ?stop_err, "failed to stop sandbox after pause failure");
                }
                if let Ok(Some(metadata)) = self.store.get(&sandbox_id).await {
                    self.finalize_terminal_volumes(&metadata).await;
                }
                if let Err(error) = self.store.remove(&sandbox_id).await {
                    warn!(error = ?error, "failed to remove sandbox after pause failure");
                }
            } else {
                self.sandboxes.write().await.insert(sandbox_id, handle);
                self.restore_proxy_route(sandbox_id, removed_proxy_route)
                    .await;
                let _ = self
                    .store
                    .update_state_if_state(
                        &sandbox_id,
                        SandboxState::Running,
                        &[SandboxState::Pausing],
                    )
                    .await;
            }
            self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
                .await;
            return Err(OrchestratorError::InternalError(format!(
                "failed to persist paused sandbox state: {err:#}"
            )));
        }
        let resources = persisted_metadata.resources;
        self.store.update(persisted_metadata.clone()).await?;

        // Stop the sandbox to free up resources.
        let stop_result = {
            let mut sandbox = handle.lock().await;
            sandbox.stop().await
        };
        if let Err(err) = stop_result {
            warn!(error = ?err, "failed to stop sandbox after pausing");
        }
        self.publish_sandbox_event(SandboxLifecycleEventType::Pause, sandbox_id, resources);
        info!("sandbox paused");

        Ok(())
    }

    /// Resumes a paused sandbox from its snapshot.
    ///
    /// If another `resume_sandbox` call is already in progress (`Resuming`
    /// state), this call waits for the ongoing resume to finish and then
    /// returns the actual outcome (either `Running` or an error) rather than
    /// duplicating the work. On success the sandbox is ready for use when this
    /// method returns.
    pub async fn resume_sandbox(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("resume", sandbox_id, async move {
            this.resume_sandbox_inner(sandbox_id, timeout).await
        })
        .await
    }

    #[tracing::instrument(
        name = "resume_sandbox",
        skip(self),
        fields(sandbox_id = %sandbox_id, timeout = ?timeout)
    )]
    async fn resume_sandbox_inner(
        self: Arc<Self>,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        self.ensure_accepting_lifecycle_operations()?;

        info!("resuming sandbox");
        let mut metadata = self
            .store
            .get(&sandbox_id)
            .await?
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;

        // If another resume is in progress, wait for it to complete and
        // re-evaluate the resulting stable state.
        if metadata.state == SandboxState::Resuming {
            metadata = self
                .wait_for_transition(sandbox_id, SandboxState::Resuming)
                .await?;
        }

        match metadata.state {
            SandboxState::Killing => {
                return Err(OrchestratorError::SandboxNotFound(sandbox_id));
            }
            SandboxState::Running => {
                // Already running — just update the timeout if requested and return.
                return self.maybe_update_running_timeout(sandbox_id, timeout).await;
            }
            SandboxState::Paused => {}
            state => {
                return Err(OrchestratorError::InvalidSandboxState { sandbox_id, state });
            }
        }

        let node_mode = ConfigManager::global_config().virtualization_mode;
        if metadata.virtualization_mode != node_mode {
            return Err(OrchestratorError::VirtualizationModeMismatch {
                resource: format!("paused sandbox {sandbox_id}"),
                resource_mode: metadata.virtualization_mode,
                node_mode,
            });
        }

        match self
            .store
            .update_state_if_state(&sandbox_id, SandboxState::Resuming, &[SandboxState::Paused])
            .await
        {
            Ok(_) => {}
            Err(StoreError::StateConflict { actual_state, .. }) => {
                return match actual_state {
                    SandboxState::Running => {
                        // Another task already completed the resume.
                        self.maybe_update_running_timeout(sandbox_id, timeout).await
                    }
                    SandboxState::Resuming => {
                        // A second concurrent resume snuck in between our state
                        // read and CAS.  Wait for it and return the outcome.
                        self.join_concurrent_resume(sandbox_id, timeout).await
                    }
                    SandboxState::Killing => {
                        info!("sandbox is being deleted while resuming");
                        Err(OrchestratorError::SandboxNotFound(sandbox_id))
                    }
                    _ => {
                        info!(state = ?actual_state, "cannot resume sandbox in current state");
                        Err(OrchestratorError::InvalidSandboxState {
                            sandbox_id,
                            state: actual_state,
                        })
                    }
                };
            }
            Err(err) => return Err(OrchestratorError::from(err)),
        }

        if let Err(err) = self.persister.mark_resuming(&sandbox_id).await {
            warn!(error = ?err, "failed to mark persisted sandbox record as resuming");
            let _ = self
                .store
                .update_state_if_state(&sandbox_id, SandboxState::Paused, &[SandboxState::Resuming])
                .await;
            return Err(OrchestratorError::InternalError(format!(
                "failed to mark persisted sandbox record as resuming: {err:#}"
            )));
        }

        let paused_state = metadata.paused_state.as_ref().ok_or_else(|| {
            warn!("missing paused state while resuming");
            OrchestratorError::InternalError("missing paused state".to_string())
        })?;

        let resumed = self
            .launch_sandbox(LaunchPlan::for_resume(
                sandbox_id,
                Arc::clone(paused_state),
                timeout,
                metadata.resources,
                metadata
                    .secure
                    .then(|| self.access_tokens.generate(metadata.id)),
            ))
            .await;
        if let Ok(metadata) = resumed.as_ref() {
            self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
                .await;
            self.publish_sandbox_event(
                SandboxLifecycleEventType::Resume,
                metadata.id,
                metadata.resources,
            );
        }
        resumed
    }

    /// Captures a snapshot of a running sandbox.
    pub async fn capture_snapshot(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
    ) -> Result<SnapshotCaptureResult> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("snapshot", sandbox_id, async move {
            this.capture_snapshot_inner(sandbox_id).await
        })
        .await
    }

    async fn begin_snapshot_operation(&self, sandbox_id: SandboxId) -> Result<SandboxHandle> {
        self.ensure_accepting_lifecycle_operations()?;
        self.store
            .update_state_if_state(
                &sandbox_id,
                SandboxState::Snapshotting,
                &[SandboxState::Running],
            )
            .await
            .map_err(|error| match error {
                StoreError::StateConflict {
                    actual_state: SandboxState::Killing,
                    ..
                } => OrchestratorError::SandboxNotFound(sandbox_id),
                StoreError::StateConflict { actual_state, .. } => {
                    OrchestratorError::InvalidSandboxState {
                        sandbox_id,
                        state: actual_state,
                    }
                }
                error => OrchestratorError::from(error),
            })?;

        self.close_native_admission(sandbox_id).await;
        if let Some(handle) = self.sandboxes.read().await.get(&sandbox_id).cloned() {
            return Ok(handle);
        }
        warn!("sandbox handle not found while snapshotting, removing from store");
        self.detach_sandbox_handle_and_route(&sandbox_id).await;
        if let Some(metadata) = self.store.get(&sandbox_id).await? {
            self.finalize_terminal_volumes(&metadata).await;
        }
        self.store.remove(&sandbox_id).await?;
        Err(OrchestratorError::SandboxNotFound(sandbox_id))
    }

    // The lifecycle caller is cancellation-safe. Install the SAME backend and
    // resumable Stop phase before cleanup; failure must not drop the last owner
    // or publish the failed capture as Paused/Running. Admission stays closed.
    async fn retire_terminal_capture(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
        removed_route: Option<ProxyRoute>,
    ) -> Result<()> {
        // Preserve only the original closed native observation route. The
        // recoverable restore helper would reopen admission and is forbidden.
        let mut sandboxes = self.sandboxes.write().await;
        sandboxes.insert(sandbox_id, Arc::clone(handle));
        if let Some(route) = removed_route.filter(|route| route.target().is_none()) {
            let mut routes = self.proxy_routes.write().await;
            if let Some(control) = route.native_control().cloned() {
                control.close_admission();
                routes.publish_control(sandbox_id, control, route.version());
            } else {
                routes.publish_native(sandbox_id, route.version());
            }
        }
        drop(sandboxes);
        let deletion = self.deletion_progress(sandbox_id).await;
        let mut progress = deletion.lock().await;
        if !matches!(*progress, DeleteProgress::Capture) {
            return Err(OrchestratorError::InternalError(
                "terminal capture cleanup already owned".into(),
            ));
        }
        *progress = DeleteProgress::Stop {
            capture_failed: true,
        };
        self.store
            .update_state_if_state(
                &sandbox_id,
                SandboxState::Killing,
                &[SandboxState::Pausing, SandboxState::Snapshotting],
            )
            .await?;
        self.delete_sandbox_impl(sandbox_id, SandboxState::Killing, &mut progress, None)
            .await
    }

    async fn fail_snapshot_operation<T>(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
        error: SandboxCaptureError,
        operation: SandboxOperation,
    ) -> Result<T> {
        warn!(?error, ?operation, "sandbox snapshot operation failed");
        if error.is_terminal() {
            let (_, removed_route) = self.detach_sandbox_handle_and_route(&sandbox_id).await;
            if let Err(stop_error) = self
                .retire_terminal_capture(sandbox_id, handle, removed_route)
                .await
            {
                warn!(
                    ?stop_error,
                    ?operation,
                    "terminal snapshot cleanup retained for retry"
                );
            }
        } else {
            let _ = self
                .store
                .update_state_if_state(
                    &sandbox_id,
                    SandboxState::Running,
                    &[SandboxState::Snapshotting],
                )
                .await;
            self.reopen_native_admission(sandbox_id).await;
        }
        Err(OrchestratorError::SandboxOperationFailed {
            sandbox_id,
            operation,
            source: error.into(),
        })
    }

    async fn finish_snapshot_operation(&self, sandbox_id: SandboxId) -> Result<()> {
        self.store
            .update_state_if_state(
                &sandbox_id,
                SandboxState::Running,
                &[SandboxState::Snapshotting],
            )
            .await?;
        self.reopen_native_admission(sandbox_id).await;
        Ok(())
    }

    /// Seals writable persistent-volume uppers without capturing the VM's
    /// rootfs, memory, or device state so callers can clone them locally.
    pub async fn snapshot_volume_mounts(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("snapshot_volumes", sandbox_id, async move {
            this.snapshot_volume_mounts_inner(sandbox_id).await
        })
        .await
    }

    #[tracing::instrument(
        name = "snapshot_volume_mounts",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn snapshot_volume_mounts_inner(self: Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let handle = self.begin_snapshot_operation(sandbox_id).await?;
        if let Err(error) = {
            let mut sandbox = handle.lock().await;
            sandbox.snapshot_volumes().await
        } {
            return self
                .fail_snapshot_operation(
                    sandbox_id,
                    &handle,
                    error,
                    SandboxOperation::SnapshotVolumes,
                )
                .await;
        }
        self.finish_snapshot_operation(sandbox_id).await
    }

    #[tracing::instrument(
        name = "capture_snapshot",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn capture_snapshot_inner(
        self: Arc<Self>,
        sandbox_id: SandboxId,
    ) -> Result<SnapshotCaptureResult> {
        info!("capturing sandbox snapshot");
        let handle = self.begin_snapshot_operation(sandbox_id).await?;
        let result = {
            let mut sandbox = handle.lock().await;
            sandbox.snapshot().await
        };
        let captured_snapshot = match result {
            Ok(captured_snapshot) => captured_snapshot,
            Err(error) => {
                return self
                    .fail_snapshot_operation(sandbox_id, &handle, error, SandboxOperation::Snapshot)
                    .await;
            }
        };

        self.finish_snapshot_operation(sandbox_id).await?;
        let metadata = match self.store.get(&sandbox_id).await? {
            Some(metadata) => metadata,
            None => {
                warn!("sandbox disappeared after snapshotting");
                return Err(OrchestratorError::SandboxNotFound(sandbox_id));
            }
        };

        self.reopen_native_admission(sandbox_id).await;
        info!("snapshot captured");
        Ok(SnapshotCaptureResult {
            metadata,
            captured_snapshot,
        })
    }

    pub async fn replace_sandbox_network_policy(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        network_policy: SandboxNetworkPolicy,
    ) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("update_network", sandbox_id, async move {
            this.replace_sandbox_network_policy_inner(sandbox_id, network_policy)
                .await
        })
        .await
    }

    #[tracing::instrument(
        name = "replace_sandbox_network_policy",
        skip(self, network_policy),
        fields(sandbox_id = %sandbox_id))
    ]
    async fn replace_sandbox_network_policy_inner(
        &self,
        sandbox_id: SandboxId,
        mut network_policy: SandboxNetworkPolicy,
    ) -> Result<()> {
        let metadata = self
            .store
            .get(&sandbox_id)
            .await?
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
        if metadata.state != SandboxState::Running {
            return Err(OrchestratorError::InvalidSandboxState {
                sandbox_id,
                state: metadata.state,
            });
        }
        network_policy.allow_public_traffic = metadata.network_policy.allow_public_traffic;

        let sandbox = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&sandbox_id).cloned()
        }
        .ok_or_else(|| OrchestratorError::SandboxOperationConflict {
            sandbox_id,
            operation: SandboxOperation::UpdateNetwork,
        })?;

        let runtime_policy = network_policy.runtime_policy();

        let update_result = {
            let mut sandbox = sandbox.lock().await;
            sandbox.update_network_policy(runtime_policy).await
        };
        update_result.map_err(|source| OrchestratorError::SandboxOperationFailed {
            sandbox_id,
            operation: SandboxOperation::UpdateNetwork,
            source,
        })?;

        self.store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.network_policy = network_policy;
            })
            .await?;

        Ok(())
    }

    /// Patch the custom extension params of a running sandbox.
    ///
    /// The patch document is passed through verbatim to the custom
    /// extension's patch-params hook, which returns the updated full params.
    /// On hook failure the sandbox keeps its previous params and the
    /// metadata store is left untouched. Returns the new full params (`None`
    /// means empty params).
    pub async fn patch_sandbox_custom_extension_params(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        patch: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CustomExtensionParams>> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("patch_custom_extension_params", sandbox_id, async move {
            this.patch_sandbox_custom_extension_params_inner(sandbox_id, patch)
                .await
        })
        .await
    }

    #[tracing::instrument(
        name = "patch_sandbox_custom_extension_params",
        skip(self, patch),
        fields(sandbox_id = %sandbox_id))
    ]
    async fn patch_sandbox_custom_extension_params_inner(
        &self,
        sandbox_id: SandboxId,
        patch: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CustomExtensionParams>> {
        let metadata = self
            .store
            .get(&sandbox_id)
            .await?
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
        if metadata.state != SandboxState::Running {
            return Err(OrchestratorError::InvalidSandboxState {
                sandbox_id,
                state: metadata.state,
            });
        }

        let sandbox = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&sandbox_id).cloned()
        }
        .ok_or_else(|| OrchestratorError::SandboxOperationConflict {
            sandbox_id,
            operation: SandboxOperation::PatchCustomExtensionParams,
        })?;

        // Invoke the extension's patch-params hook here (the backend only
        // stores the approved value). The sandbox lock is not held during
        // the hook call so pause/stop are not blocked on extension latency.
        let client = CustomExtensionClient::global().ok_or_else(|| {
            OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::PatchCustomExtensionParams,
                source: anyhow::anyhow!(
                    "custom extension is not configured ([custom_extension].url is unset)"
                ),
            }
        })?;
        let new_params = client
            .hook_patch_params(sandbox_id, patch)
            .await
            .map_err(|source| OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::PatchCustomExtensionParams,
                source,
            })?;

        {
            let mut sandbox = sandbox.lock().await;
            sandbox.update_custom_extension_params(new_params.clone());
        }

        // NOTE: a concurrent pause may have transitioned the sandbox since the entry check,
        // so this may fail. But it's acceptable since extension state should be transient like network policy
        self.store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.custom_extension_params = new_params.clone();
            })
            .await
            .map_err(|err| match err {
                // Lost a race against a concurrent state transition (e.g.
                // pause): report it as a conflict instead of a 500.
                StoreError::StateConflict {
                    sandbox_id,
                    actual_state,
                    ..
                } => OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: actual_state,
                },
                other => OrchestratorError::from(other),
            })?;

        Ok(new_params)
    }

    /// Returns the current orchestrator metrics snapshot.
    ///
    /// Counter fields are read atomically; resource fields are aggregated by
    /// scanning the metadata store, so the returned snapshot is always
    /// consistent with the orchestrator's current set of sandboxes.
    pub async fn metrics_snapshot(&self) -> Result<OrchestratorMetrics> {
        let mut metrics = OrchestratorMetrics::default();
        self.store
            .list_with_callback(|metadata| {
                aggregate_resource_metrics(
                    &mut metrics,
                    SandboxContribution::new(metadata.state, metadata.resources),
                );
            })
            .await?;
        metrics.create_successes = self.counters.create_successes();
        metrics.create_fails = self.counters.create_fails();
        Ok(metrics)
    }

    pub fn subscribe_sandbox_events(&self) -> broadcast::Receiver<SandboxLifecycleEvent> {
        self.sandbox_event_tx.subscribe()
    }

    fn publish_sandbox_event(
        &self,
        event_type: SandboxLifecycleEventType,
        sandbox_id: SandboxId,
        resources: SandboxResources,
    ) {
        let event = SandboxLifecycleEvent {
            event_type,
            sandbox_id,
            resources,
        };
        let _ = self.sandbox_event_tx.send(event);
    }

    /// Waits for `sandbox_id` to leave `transitional_state`, then returns the
    /// resulting metadata. Returns `SandboxNotFound` if the sandbox is removed
    /// while waiting, or `InvalidSandboxState` if the sandbox is still in the
    /// transitional state after the [`WAIT_TRANSITION_TIMEOUT`] elapses.
    async fn wait_for_transition(
        &self,
        sandbox_id: SandboxId,
        transitional_state: SandboxState,
    ) -> Result<SandboxMetadata> {
        let states = [transitional_state];
        let wait = self.store.wait_while_in_states(&sandbox_id, &states);
        match tokio::time::timeout(WAIT_TRANSITION_TIMEOUT, wait).await {
            Ok(Ok(Some(m))) => Ok(m),
            Ok(Ok(None)) => Err(OrchestratorError::SandboxNotFound(sandbox_id)),
            Ok(Err(e)) => Err(OrchestratorError::from(e)),
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    state = ?transitional_state,
                    "timed out waiting for sandbox to leave transitional state"
                );
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: transitional_state,
                })
            }
        }
    }

    /// Applies `timeout` to `metadata` and persists the change if the sandbox
    /// is still `Running`. Returns the updated metadata. If `timeout` is `None`,
    /// the timeout will be cleared, which indicates no expiration.
    async fn maybe_update_running_timeout(
        &self,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        let update_result = self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.update_timeout(timeout);
            })
            .await
            .map_err(|err| match err {
                StoreError::StateConflict { actual_state, .. } => {
                    info!(state = ?actual_state, "cannot update timeout for sandbox in current state");
                    OrchestratorError::InvalidSandboxState {
                        sandbox_id,
                        state: actual_state,
                    }
                }
                other => OrchestratorError::from(other),
            })?;
        Ok(update_result.current)
    }

    /// Joins a concurrent pause already in progress for the same sandbox.
    /// Waits for the `Pausing` state to resolve and maps the final state to
    /// the appropriate `Ok(())` / `Err(...)` result.
    async fn join_concurrent_pause(&self, sandbox_id: SandboxId) -> Result<()> {
        debug!("concurrent pause in progress, waiting for completion");
        let m = self
            .wait_for_transition(sandbox_id, SandboxState::Pausing)
            .await?;
        match m.state {
            SandboxState::Paused => {
                debug!("concurrent pause succeeded");
                Ok(())
            }
            SandboxState::Running => {
                info!("concurrent pause failed; sandbox returned to running state");
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: SandboxState::Running,
                })
            }
            SandboxState::Killing => {
                info!("sandbox is being deleted after concurrent pause attempt");
                Err(OrchestratorError::SandboxNotFound(sandbox_id))
            }
            other => {
                info!(state = ?other, "unexpected state after waiting for concurrent pause");
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: other,
                })
            }
        }
    }

    /// Joins a concurrent resume already in progress for the same sandbox.
    /// Waits for the `Resuming` state to resolve, then applies `timeout` if
    /// the sandbox reached `Running`, and returns the final metadata.
    async fn join_concurrent_resume(
        &self,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        debug!("concurrent resume in progress, waiting for completion");
        let m = self
            .wait_for_transition(sandbox_id, SandboxState::Resuming)
            .await?;
        match m.state {
            SandboxState::Running => self.maybe_update_running_timeout(sandbox_id, timeout).await,
            SandboxState::Paused => {
                info!("concurrent resume failed; sandbox returned to paused state");
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: SandboxState::Paused,
                })
            }
            SandboxState::Killing => {
                info!("sandbox is being deleted while resuming");
                Err(OrchestratorError::SandboxNotFound(sandbox_id))
            }
            state => {
                info!(state = ?state, "unexpected state after waiting for concurrent resume");
                Err(OrchestratorError::InvalidSandboxState { sandbox_id, state })
            }
        }
    }

    /// Automatically pauses or stops sandboxes whose timeout has expired.
    async fn evict_expired_sandboxes(self: &Arc<Self>) -> Result<Vec<SandboxId>> {
        if self.is_shutting_down() {
            debug!("skipping auto-evict because orchestrator is shutting down");
            return Ok(Vec::new());
        }

        let eviction_cutoff = SystemTime::now();
        let expired = self.store.list_expired(eviction_cutoff).await?;
        let mut evicted_ids = Vec::new();

        for metadata in expired {
            if metadata.state != SandboxState::Running {
                continue;
            }
            let claimed_state = match metadata.timeout_action {
                SandboxTimeoutAction::Pause => SandboxState::Pausing,
                SandboxTimeoutAction::Delete => SandboxState::Killing,
            };
            // Use the same operation lock as explicit deletion before claiming Killing.
            let deletion = self.deletion_progress(metadata.id).await;
            let mut progress = deletion.lock().await;
            let result = match self
                .claim_expired_running_sandbox(metadata.id, eviction_cutoff, claimed_state)
                .await
            {
                Ok(true) => match metadata.timeout_action {
                    SandboxTimeoutAction::Pause => self.pause_sandbox_impl(metadata.id).await,
                    SandboxTimeoutAction::Delete => {
                        self.delete_sandbox_impl(
                            metadata.id,
                            SandboxState::Running,
                            &mut progress,
                            None,
                        )
                        .await
                    }
                }
                .map(|_| true),
                Ok(false) => Ok(false),
                Err(err) => Err(err),
            };
            match result {
                Ok(true) => evicted_ids.push(metadata.id),
                Ok(false) => continue,
                Err(err) => warn!(
                    sandbox_id = %metadata.id,
                    action = ?metadata.timeout_action,
                    error = ?err,
                    "failed to auto-evict expired sandbox"
                ),
            }
        }

        Ok(evicted_ids)
    }

    /// Starts a background task that periodically evicts expired sandboxes.
    /// The eviction policy is defined by the sandbox's [`timeout_action`](SandboxMetadata::timeout_action).
    fn start_auto_evict_task(
        this: Arc<Self>,
        evict_interval: Duration,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let Ok(runtime_handle) = tokio::runtime::Handle::try_current() else {
            warn!("auto-evict task not started: no Tokio runtime available");
            return;
        };

        let this = Arc::downgrade(&this);
        runtime_handle.spawn(async move {
            let mut ticker = tokio::time::interval(evict_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            debug!("auto-evict task started with interval {:?}", evict_interval);

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("auto-evict task stopping because orchestrator is shutting down");
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let Some(this) = this.upgrade() else {
                            debug!("auto-evict task stopping because orchestrator was dropped");
                            break;
                        };
                        if let Err(err) = this.evict_expired_sandboxes().await {
                            warn!("auto-evict task failed: {err}");
                        }
                    }
                }
            }
        });
    }

    /// Starts a background task that periodically runs local image maintenance
    /// (capacity eviction + fail-closed GC) over the current running set.
    fn start_local_image_maintenance_task(
        this: Arc<Self>,
        interval: Duration,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let Ok(runtime_handle) = tokio::runtime::Handle::try_current() else {
            warn!("local image maintenance task not started: no Tokio runtime available");
            return;
        };

        let this = Arc::downgrade(&this);
        runtime_handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            info!(interval = ?interval, "local image maintenance task started");

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("local image maintenance task stopping because orchestrator is shutting down");
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let Some(this) = this.upgrade() else {
                            debug!("local image maintenance task stopping because orchestrator was dropped");
                            break;
                        };

                        let running = this.collect_running_artifacts().await;
                        if let Err(err) = this.image_refs.maintain_running(running).await {
                            warn!("local image maintenance pass failed: {err:#}");
                        }
                    }
                }
            }
        });
    }

    #[tracing::instrument(skip(self, plan))]
    async fn launch_sandbox(self: &Arc<Self>, plan: LaunchPlan) -> Result<SandboxMetadata> {
        self.launch_sandbox_owned(plan, None).await
    }
    async fn launch_sandbox_owned(
        self: &Arc<Self>,
        plan: LaunchPlan,
        prepared: Option<(SandboxHandle, std::time::Instant)>,
    ) -> Result<SandboxMetadata> {
        self.ensure_accepting_lifecycle_operations()?;

        let sandbox_id = plan.sandbox_id();
        let transitional_state = plan.transitional_state();

        // Build and start the sandbox first, before making any state changes, so that we don't
        // have to roll back any persisted state if the build fails.
        // Meanwhile, the start process can be overlapped with the initial state persistence.
        let expiry = prepared.as_ref().map(|p| p.1);
        let native_prepared = prepared.is_some();
        let handle = if let Some((owner, _)) = prepared {
            owner
        } else {
            match self.build_sandbox(&plan) {
                Ok(sandbox) => Arc::new(Mutex::new(sandbox)),
                Err(err) => {
                    self.rollback_failed_launch_metadata(&plan, transitional_state)
                        .await;
                    return Err(err);
                }
            }
        };
        if native_prepared {
            let mut registry = self.sandboxes.write().await;
            if let std::collections::hash_map::Entry::Vacant(entry) = registry.entry(sandbox_id) {
                entry.insert(handle.clone());
            } else {
                drop(registry);
                self.retain_failed_launch_debt(&plan, handle, FailedLaunchStage::Registered)
                    .await;
                return Err(OrchestratorError::InternalError(
                    "native original owner registration conflict".into(),
                ));
            }
        }
        let mut sandbox = handle.lock().await;
        // Protect artifacts before the backend opens them.
        let startup_artifacts = sandbox.startup_artifacts();
        if let Err(err) = self
            .protect_image_refs(
                RuntimeImageOwner::StartingSandbox(sandbox_id),
                startup_artifacts,
                "starting sandbox",
            )
            .await
        {
            warn!(error = %format_args!("{err:#}"), "failed to protect starting runtime artifacts");
            drop(sandbox);
            if native_prepared {
                self.retain_failed_launch_debt(&plan, handle, FailedLaunchStage::Registered)
                    .await;
            }
            self.rollback_failed_launch_metadata(&plan, transitional_state)
                .await;
            return Err(err);
        }
        if let Err(source) = sandbox.start_nowait().await {
            warn!(error = %format_args!("{source:#}"), "failed to start sandbox");
            drop(sandbox);
            self.retain_unregistered_failed_launch_handle(&plan, handle.clone())
                .await;
            let _ = self.retry_failed_launch_debts(Some(sandbox_id)).await;
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::Start,
                source,
            });
        }
        debug!("sandbox start requested");

        // If the orchestrator started shutting down, stop here before we persist any state.
        if self.is_shutting_down() {
            info!("orchestrator started shutting down just after starting the sandbox");
            drop(sandbox);
            self.retain_unregistered_failed_launch_handle(&plan, handle.clone())
                .await;
            let _ = self.retry_failed_launch_debts(Some(sandbox_id)).await;
            return Err(OrchestratorError::ShuttingDown);
        }

        let runtime_resources =
            resources_with_runtime_info(plan.resources(), sandbox.runtime_info());
        let transitional_metadata = plan.transitional_metadata().map(|metadata| {
            let mut metadata = metadata.clone();
            metadata.resources = runtime_resources;
            metadata
        });

        // Store the sandbox handle in memory.
        drop(sandbox);
        let registered = if native_prepared {
            true
        } else {
            let mut registry = self.sandboxes.write().await;
            if let std::collections::hash_map::Entry::Vacant(entry) = registry.entry(sandbox_id) {
                entry.insert(Arc::clone(&handle));
                true
            } else {
                false
            }
        };
        if !registered {
            self.retain_failed_launch_debt(&plan, handle, FailedLaunchStage::Registered)
                .await;
            return Err(OrchestratorError::InternalError(
                "launch owner registration conflict; original owners retained".into(),
            ));
        }

        // Keep startup protection until readiness and route publication succeed.
        // Persist the sandbox metadata if needed (during creation).
        if let Some(metadata) = transitional_metadata.as_ref() {
            if let Err(err) = self.store.add(metadata.clone()).await {
                warn!(error = %format_args!("{err:#}"), "failed to persist sandbox metadata; cleaning up");
                self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::Registered)
                    .await;
                return Err(OrchestratorError::from(err));
            }
        }

        // Check for shutdown again before we wait for the sandbox to become ready.
        if self.is_shutting_down() {
            info!("orchestrator started shutting down before sandbox became ready");
            self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                .await;
            return Err(OrchestratorError::ShuttingDown);
        }

        // Wait for the sandbox to be ready
        let wait_result = {
            let sandbox = handle.lock().await;
            sandbox.wait_for_ready().await
        };
        if let Err(source) = wait_result {
            warn!(error = %format_args!("{source:#}"), "sandbox failed to become ready");
            self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                .await;
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::WaitReady,
                source,
            });
        }

        // Check for shutdown again before we persist the final state and publish the proxy route.
        if self.is_shutting_down() {
            info!("orchestrator started shutting down while sandbox was becoming ready");
            self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                .await;
            return Err(OrchestratorError::ShuttingDown);
        }

        // Running acquires the same capture before final metadata/publication or Starting release.
        let running_artifacts = handle.lock().await.runtime_info().runtime_artifacts;
        if let Err(error) = self
            .image_refs
            .promote_native_running(sandbox_id, running_artifacts)
            .await
        {
            self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                .await;
            return Err(OrchestratorError::from(error));
        }
        let launch_timeout = if let Some(until) = expiry {
            match until.checked_duration_since(std::time::Instant::now()) {
                Some(remaining) => NewTimeout::Set(remaining),
                None => {
                    self.cleanup_failed_launch(
                        &plan,
                        handle,
                        FailedLaunchStage::TransitionalPersisted,
                    )
                    .await;
                    return Err(OrchestratorError::InternalError(
                        "native original Worker expiry before Ready publication".into(),
                    ));
                }
            }
        } else {
            plan.timeout()
        };
        let final_metadata = match self
            .store
            .update_if_state(
                &sandbox_id,
                std::slice::from_ref(&transitional_state),
                move |metadata| {
                    metadata.resources = runtime_resources;
                    metadata.state = SandboxState::Running;
                    metadata.update_timeout(launch_timeout);
                },
            )
            .await
        {
            Ok(update) => update.current,
            Err(err) => {
                warn!(error = %format_args!("{err:#}"), "failed to persist final sandbox metadata after launch");
                self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                    .await;
                return Err(OrchestratorError::from(err));
            }
        };

        let proxy_target = {
            let sandbox = handle.lock().await;
            if sandbox.native_control_ready() && sandbox.host_interaction_ip().is_none() {
                None
            } else {
                match Self::proxy_target_from_sandbox(sandbox.as_ref()) {
                    Ok(proxy_target) => Some(proxy_target),
                    Err(err) => {
                        warn!(error = %format_args!("{err:#}"), "sandbox became ready without a proxy target; rolling back launch");
                        drop(sandbox);
                        self.cleanup_failed_launch(
                            &plan,
                            handle,
                            FailedLaunchStage::RunningPersisted,
                        )
                        .await;
                        return Err(err);
                    }
                }
            }
        };
        let published = match proxy_target {
            Some(target) => {
                self.upsert_proxy_route_if_current_handle(sandbox_id, &handle, target)
                    .await
            }
            None => {
                self.publish_native_control_if_current_handle(sandbox_id, &handle)
                    .await
            }
        };
        if !published {
            debug!("skipping runtime proxy route publication because sandbox handle is stale");
        }

        if matches!(plan, LaunchPlan::Resume(_)) {
            if let Err(err) = self.persister.delete_record(&sandbox_id).await {
                warn!(error = %format_args!("{err:#}"), "failed to delete persisted sandbox record after resume");
            }
        }

        self.release_image_refs(RuntimeImageOwner::StartingSandbox(sandbox_id))
            .await;
        info!("sandbox launch completed");
        Ok(final_metadata)
    }

    fn build_sandbox(&self, plan: &LaunchPlan) -> Result<Box<dyn SandboxBackend>> {
        let build_result = match plan {
            LaunchPlan::Create(plan) => match &plan.source {
                CreateLaunchSource::Snapshot { snapshot } => self
                    .factory
                    .build_from_snapshot(snapshot, plan.launch_config.clone()),
                CreateLaunchSource::Fresh { build_spec } => self
                    .factory
                    .build((**build_spec).clone(), plan.launch_config.clone()),
            },
            LaunchPlan::Resume(plan) => self.factory.build_from_paused_state(
                plan.sandbox_id,
                plan.paused_state.as_ref(),
                plan.envd_access_token.clone(),
            ),
        };
        build_result.map_err(|source| {
            warn!(error = %format_args!("{source:#}"), "failed to build sandbox");
            OrchestratorError::SandboxOperationFailed {
                sandbox_id: plan.sandbox_id(),
                operation: SandboxOperation::Build,
                source,
            }
        })
    }

    async fn retain_unregistered_failed_launch_handle(
        &self,
        plan: &LaunchPlan,
        handle: SandboxHandle,
    ) {
        let sandbox_id = plan.sandbox_id();
        // The cancellation-shielded launch task retains its local owner until
        // this serialized publication installs registry, debt and metadata together.
        let _cleanup = self.failed_launch_cleanup.lock().await;
        self.retain_failed_launch_debt_locked(
            plan,
            Arc::clone(&handle),
            FailedLaunchStage::TransitionalPersisted,
        )
        .await;
        let mut registry = self.sandboxes.write().await;
        let registered = match registry.entry(sandbox_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(handle);
                true
            }
            std::collections::hash_map::Entry::Occupied(entry) => Arc::ptr_eq(entry.get(), &handle),
        };
        if !registered {
            return;
        }
        // Resume already has Resuming metadata. Failed fresh start must retain
        // Creating metadata so lookup cannot report absent while resources live.
        if let Some(metadata) = plan.transitional_metadata() {
            if let Err(error) = self.store.add(metadata.clone()).await {
                warn!(error = %format_args!("{error:#}"), "failed to persist retained launch owner; cleanup debt remains in registry");
            }
        }
    }

    async fn retain_failed_launch_debt(
        &self,
        plan: &LaunchPlan,
        handle: SandboxHandle,
        stage: FailedLaunchStage,
    ) {
        let _cleanup = self.failed_launch_cleanup.lock().await;
        self.retain_failed_launch_debt_locked(plan, handle, stage)
            .await;
    }

    fn failed_debt_image_owner(
        debt: SandboxId,
        original: SandboxId,
        artifacts: &RuntimeArtifactSet,
    ) -> RuntimeImageOwner {
        if artifacts.has_native() {
            RuntimeImageOwner::NativeFailedLaunchDebt { debt, original }
        } else {
            RuntimeImageOwner::StartingSandbox(debt)
        }
    }
    // Caller holds failed_launch_cleanup across this and any registry publication.
    async fn retain_failed_launch_debt_locked(
        &self,
        plan: &LaunchPlan,
        handle: SandboxHandle,
        stage: FailedLaunchStage,
    ) {
        let artifacts = {
            let sandbox = handle.lock().await;
            sandbox
                .startup_artifacts()
                .union(sandbox.runtime_info().runtime_artifacts)
        };
        let fallback_metadata = if let Some(metadata) = plan.transitional_metadata() {
            Some(metadata.clone())
        } else {
            self.store.get(&plan.sandbox_id()).await.ok().flatten()
        };
        let mut debts = self.failed_launch_debts.write().await;
        if debts
            .values()
            .any(|debt| Arc::ptr_eq(&debt.handle, &handle))
        {
            return;
        }
        let id = loop {
            let id = SandboxId::new();
            if !debts.contains_key(&id) {
                break id;
            }
        };
        debts.insert(
            id,
            FailedLaunchDebt {
                sandbox_id: plan.sandbox_id(),
                handle: Arc::clone(&handle),
                metadata: fallback_metadata,
                create: matches!(plan, LaunchPlan::Create(_)),
                expected_state: stage.rollback_expected_state(plan),
                pin_ready: false,
                artifacts: artifacts.clone(),
            },
        );
        drop(debts);
        let pin_ready = self
            .protect_image_refs(
                Self::failed_debt_image_owner(id, plan.sandbox_id(), &artifacts),
                artifacts,
                "failed launch debt",
            )
            .await
            .is_ok();
        if !pin_ready {
            warn!("debt protection unresolved; retaining original owner and startup references");
        }
        if let Some(debt) = self.failed_launch_debts.write().await.get_mut(&id) {
            debt.pin_ready = pin_ready;
        }
    }

    /// One finite stop attempt per retained original owner, including displaced
    /// handles. No registry replacement or shared rollback is allowed for a stale owner.
    async fn retry_failed_launch_debts(&self, selected: Option<SandboxId>) -> Result<()> {
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        let _cleanup = tokio::time::timeout_at(until, self.failed_launch_cleanup.lock())
            .await
            .map_err(|_| OrchestratorError::InternalError("failed launch cleanup busy".into()))?;
        let debts: Vec<_> = self
            .failed_launch_debts
            .read()
            .await
            .iter()
            .filter(|(_, debt)| selected.is_none_or(|id| id == debt.sandbox_id))
            .map(|(id, debt)| (*id, debt.clone()))
            .collect();
        self.cleanup_provenance
            .lock()
            .map_err(|_| {
                OrchestratorError::InternalError("cleanup provenance lock unavailable".into())
            })?
            .reserve(debts.iter().map(|(_, debt)| debt.sandbox_id))?;
        let mut unresolved = false;
        for (id, debt) in debts {
            if !debt.pin_ready {
                let protected = tokio::time::timeout_at(until, async {
                    self.protect_image_refs(
                        Self::failed_debt_image_owner(id, debt.sandbox_id, &debt.artifacts),
                        debt.artifacts.clone(),
                        "failed launch debt retry",
                    )
                    .await
                })
                .await;
                if !matches!(protected, Ok(Ok(()))) {
                    unresolved = true;
                    continue;
                }
                if let Some(current) = self.failed_launch_debts.write().await.get_mut(&id) {
                    current.pin_ready = true;
                }
            }
            let result = tokio::time::timeout_at(until, async {
                let mut backend = debt.handle.lock().await;
                backend.stop().await?;
                Ok::<_, anyhow::Error>(backend.native_execution_stopped())
            })
            .await;
            let stopped = match result {
                Ok(Ok(stopped)) => stopped,
                _ => {
                    unresolved = true;
                    continue;
                }
            };
            if self
                .retire_native_original_owner(debt.sandbox_id, &debt.handle, stopped)
                .is_err()
            {
                unresolved = true;
                continue;
            }
            let mut registry = self.sandboxes.write().await;
            let current = {
                match registry.get(&debt.sandbox_id) {
                    Some(handle) if Arc::ptr_eq(handle, &debt.handle) => true,
                    Some(_) | None => false,
                }
            };
            let metadata = self.store.get(&debt.sandbox_id).await?;
            let owns_metadata = metadata.as_ref().is_none_or(|metadata| {
                debt.metadata.as_ref().is_some_and(|original| {
                    original.created_at == metadata.created_at
                        && original.snapshot_id == metadata.snapshot_id
                })
            });
            let mut deleted_original =
                current && owns_metadata && debt.create && metadata.is_none();
            if current && owns_metadata {
                self.proxy_routes.write().await.remove(&debt.sandbox_id);
                if let Some(metadata) = metadata {
                    if debt.create
                        && debt
                            .expected_state
                            .is_none_or(|expected| metadata.state == expected)
                    {
                        self.store.remove(&debt.sandbox_id).await?;
                        deleted_original = true;
                    } else if !debt.create {
                        if let Some(expected) = debt.expected_state {
                            self.store
                                .update_state_if_state(
                                    &debt.sandbox_id,
                                    SandboxState::Paused,
                                    &[expected],
                                )
                                .await?;
                            self.persister.rollback_resuming(&debt.sandbox_id).await?;
                        }
                    }
                }
                self.image_refs
                    .retire_native_running(debt.sandbox_id, debt.artifacts.clone())
                    .await?;
                self.release_image_refs(RuntimeImageOwner::StartingSandbox(debt.sandbox_id))
                    .await;
            }
            if current {
                registry.remove(&debt.sandbox_id);
            }
            drop(registry);
            // The unique debt pin is independent of any replacement's image owner.
            self.failed_launch_debts.write().await.remove(&id);
            self.release_image_refs(Self::failed_debt_image_owner(
                id,
                debt.sandbox_id,
                &debt.artifacts,
            ))
            .await;
            // No other original owner for this ID may remain. Record completion
            // only after this real stop/metadata/persistence/pin retirement.
            let remaining = self.failed_launch_debts.read().await;
            if deleted_original
                && !debt.artifacts.has_native()
                && !remaining
                    .values()
                    .any(|other| other.sandbox_id == debt.sandbox_id)
                && !self.sandboxes.read().await.contains_key(&debt.sandbox_id)
                && self.store.get(&debt.sandbox_id).await?.is_none()
            {
                self.cleanup_provenance
                    .lock()
                    .map_err(|_| {
                        OrchestratorError::InternalError(
                            "cleanup provenance lock unavailable".into(),
                        )
                    })?
                    .mark_retired(debt.sandbox_id)?;
            }
        }
        if unresolved {
            return Err(OrchestratorError::InternalError(
                "failed launch cleanup debt unresolved".into(),
            ));
        }
        Ok(())
    }

    async fn cleanup_failed_launch(
        &self,
        plan: &LaunchPlan,
        handle: SandboxHandle,
        stage: FailedLaunchStage,
    ) {
        self.retain_failed_launch_debt(plan, handle, stage).await;
        let _ = self
            .retry_failed_launch_debts(Some(plan.sandbox_id()))
            .await;
    }

    async fn rollback_failed_launch_metadata(
        &self,
        plan: &LaunchPlan,
        expected_state: SandboxState,
    ) {
        self.release_image_refs(RuntimeImageOwner::StartingSandbox(plan.sandbox_id()))
            .await;
        match plan {
            LaunchPlan::Create(_) => {
                if let Err(err) = self.store.remove(&plan.sandbox_id()).await {
                    warn!(error = %format_args!("{err:#}"), "failed to remove sandbox metadata during launch rollback");
                }
            }
            LaunchPlan::Resume(_) => {
                if let Err(err) = self
                    .store
                    .update_state_if_state(
                        &plan.sandbox_id(),
                        SandboxState::Paused,
                        std::slice::from_ref(&expected_state),
                    )
                    .await
                {
                    warn!(error = %format_args!("{err:#}"), "failed to restore sandbox metadata during launch rollback");
                }
                if let Err(err) = self.persister.rollback_resuming(&plan.sandbox_id()).await {
                    warn!(error = %format_args!("{err:#}"), "failed to restore persisted sandbox record lifecycle during launch rollback");
                }
            }
        }
    }

    fn proxy_target_from_sandbox(sandbox: &dyn SandboxBackend) -> Result<ProxyTarget> {
        sandbox
            .host_interaction_ip()
            .map(ProxyTarget::new)
            .ok_or_else(|| {
                warn!("sandbox started without an interaction IP");
                OrchestratorError::InternalError(
                    "sandbox missing host interaction IP after start".to_string(),
                )
            })
    }

    async fn upsert_proxy_route(&self, sandbox_id: SandboxId, target: ProxyTarget) {
        let version = self
            .next_proxy_route_version
            .fetch_add(1, Ordering::Relaxed);
        let route = self
            .proxy_routes
            .write()
            .await
            .upsert(sandbox_id, target, version);
        debug!(
            version = route.version(),
            updated_at = ?route.updated_at(),
            host_interaction_ip = ?route.target().map(|target| target.ip),
            "updated runtime proxy route"
        );
    }

    async fn upsert_proxy_route_if_current_handle(
        &self,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
        target: ProxyTarget,
    ) -> bool {
        // Keep the lock order aligned with detach_sandbox_handle_and_route:
        // sandboxes first, then proxy_routes.
        let sandboxes = self.sandboxes.write().await;
        let Some(current_handle) = sandboxes.get(&sandbox_id) else {
            return false;
        };

        if !Arc::ptr_eq(current_handle, handle) {
            return false;
        }

        let version = self
            .next_proxy_route_version
            .fetch_add(1, Ordering::Relaxed);
        let route = self
            .proxy_routes
            .write()
            .await
            .upsert(sandbox_id, target, version);
        drop(sandboxes);

        debug!(
            version = route.version(),
            updated_at = ?route.updated_at(),
            host_interaction_ip = ?route.target().map(|target| target.ip),
            "updated runtime proxy route"
        );
        true
    }

    async fn restore_proxy_route(&self, sandbox_id: SandboxId, route: Option<ProxyRoute>) {
        let Some(route) = route else {
            return;
        };
        match route.target() {
            Some(target) => self.upsert_proxy_route(sandbox_id, target.clone()).await,
            None => {
                let mut routes = self.proxy_routes.write().await;
                if let Some(control) = route.native_control().cloned() {
                    if control.reopen_admission().is_ok() {
                        routes.publish_control(sandbox_id, control, route.version());
                    }
                } else {
                    routes.publish_native(sandbox_id, route.version());
                }
            }
        }
    }

    pub(crate) async fn native_control_for(
        &self,
        sandbox_id: SandboxId,
    ) -> Option<crate::sandbox::NativeControl> {
        let state = self.store.get(&sandbox_id).await.ok().flatten()?.state;
        if !matches!(state, SandboxState::Running | SandboxState::Killing) {
            return None;
        }
        // Killing exposes only an explicitly retained original actor. Deletion
        // sealed its admission before Stop; restoration never reopens it.
        let control = self.registered_native_control(sandbox_id).await?;
        control.available().then_some(control)
    }
    async fn registered_native_control(
        &self,
        sandbox_id: SandboxId,
    ) -> Option<crate::sandbox::NativeControl> {
        let sandboxes = self.sandboxes.read().await;
        if !sandboxes.contains_key(&sandbox_id) {
            return None;
        }
        self.proxy_routes
            .read()
            .await
            .route(&sandbox_id)?
            .native_control()
            .cloned()
    }
    async fn close_native_admission(&self, sandbox_id: SandboxId) {
        if let Some(control) = self.registered_native_control(sandbox_id).await {
            control.close_admission();
            return;
        }
        // Running persistence can precede route publication. Close the same
        // backend actor even in that interval so late publication cannot open it.
        let handle = self.sandboxes.read().await.get(&sandbox_id).cloned();
        if let Some(handle) = handle {
            if let Some(control) = handle.lock().await.native_control() {
                control.close_admission();
            }
        }
    }
    async fn reopen_native_admission(&self, sandbox_id: SandboxId) {
        if let Some(control) = self.registered_native_control(sandbox_id).await {
            let _ = control.reopen_admission();
        }
    }

    async fn publish_native_control_if_current_handle(
        &self,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
    ) -> bool {
        let control = handle.lock().await.native_control();
        let registry = self.sandboxes.read().await;
        if !registry
            .get(&sandbox_id)
            .is_some_and(|current| Arc::ptr_eq(current, handle))
        {
            return false;
        }
        let version = self
            .next_proxy_route_version
            .fetch_add(1, Ordering::Relaxed);
        let mut routes = self.proxy_routes.write().await;
        if let Some(control) = control {
            let Ok(control) = control.publish(version) else {
                return false;
            };
            routes.publish_control(sandbox_id, control, version);
        } else {
            // Existing non-native test backends may expose only the old boolean;
            // this route does not grant a public control capability.
            routes.publish_native(sandbox_id, version);
        }
        true
    }

    async fn detach_sandbox_handle_and_route(
        &self,
        sandbox_id: &SandboxId,
    ) -> (Option<SandboxHandle>, Option<ProxyRoute>) {
        // Keep the lock order aligned with upsert_proxy_route_if_current_handle:
        // sandboxes first, then proxy_routes.
        let mut sandboxes = self.sandboxes.write().await;
        let handle = sandboxes.remove(sandbox_id);

        let removed_route = self.proxy_routes.write().await.remove(sandbox_id);
        if let Some(route) = removed_route.as_ref() {
            if let Some(control) = route.native_control() {
                control.close_admission();
            }
            debug!(version = route.version(), "removed runtime proxy route");
        }

        drop(sandboxes);
        (handle, removed_route)
    }

    async fn run_shutdown_cleanup(self: &Arc<Self>) -> Result<()> {
        const MAX_SHUTDOWN_PASSES: usize = 3;
        // Debt cleanup is independent from metadata visibility and ordinary
        // preservation; never shut down networking while these owners remain.
        for _ in 0..MAX_SHUTDOWN_PASSES {
            if self.retry_failed_launch_debts(None).await.is_ok() {
                break;
            }
        }
        if !self.failed_launch_debts.read().await.is_empty() {
            return Err(OrchestratorError::InternalError(
                "shutdown retains unresolved failed launch debt".into(),
            ));
        }
        let mut last_failures = Vec::new();

        // Preserve recoverable sandboxes by pausing running VMs before process exit.
        for pass in 1..=MAX_SHUTDOWN_PASSES {
            let sandboxes = self
                .store
                .list_filtered(SandboxListFilter {
                    excluded_states: Some(vec![SandboxState::Paused]),
                    ..SandboxListFilter::matches_all()
                })
                .await?;
            if sandboxes.is_empty() {
                break;
            }
            last_failures.clear();

            info!(
                pass,
                remaining = sandboxes.len(),
                "preserving sandboxes during shutdown"
            );

            for metadata in sandboxes {
                let sandbox_id = metadata.id;
                match metadata.state {
                    SandboxState::Paused => {
                        unreachable!("paused sandboxes should have been filtered out")
                    }
                    SandboxState::Running => {
                        let result = if metadata.template_builder {
                            self.delete_sandbox_inner(sandbox_id).await
                        } else {
                            self.pause_sandbox_inner(sandbox_id).await
                        };
                        if let Err(err) = result {
                            last_failures.push(format!("{sandbox_id}: {err}"));
                        }
                    }
                    SandboxState::Creating
                    | SandboxState::Snapshotting
                    | SandboxState::Forking
                    | SandboxState::Pausing
                    | SandboxState::Resuming
                    | SandboxState::Killing => {
                        match self.wait_for_transition(sandbox_id, metadata.state).await {
                            Ok(_) | Err(OrchestratorError::SandboxNotFound(_)) => {}
                            Err(err) => {
                                warn!(
                                    sandbox_id = %sandbox_id,
                                    error = ?err,
                                    pass,
                                    "failed to wait for sandbox transition during orchestrator shutdown"
                                );
                                last_failures.push(format!("{sandbox_id}: {err}"));
                            }
                        }
                    }
                }
            }

            if last_failures.is_empty() {
                continue;
            }

            warn!(
                pass,
                failures = last_failures.len(),
                max_passes = MAX_SHUTDOWN_PASSES,
                "shutdown preservation pass completed with failures"
            );
        }

        if !last_failures.is_empty() {
            return Err(OrchestratorError::InternalError(format!(
                "failed to preserve all sandboxes during shutdown after {MAX_SHUTDOWN_PASSES} passes: {}",
                last_failures.join(", ")
            )));
        }

        // Clean up remaining network resources.
        if let Some(manager) = crate::sandbox::NetworkManager::global_if_initialized() {
            if let Err(err) = manager.shutdown() {
                warn!(error = ?err, "failed to clean up network resources during orchestrator shutdown");
            }
        }

        info!("orchestrator shutdown completed");
        Ok(())
    }

    fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::Acquire)
    }

    fn ensure_accepting_lifecycle_operations(&self) -> Result<()> {
        if self.is_shutting_down() {
            info!("rejecting lifecycle operation because orchestrator is shutting down");
            return Err(OrchestratorError::ShuttingDown);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sandbox_logs(
        &self,
        id: SandboxId,
        cursor: Option<i64>,
        limit: usize,
        backward: bool,
        level: Option<LogLevel>,
        search: Option<String>,
    ) -> Result<Vec<SandboxLogEntry>> {
        let operation = async {
            let metadata = self
                .store
                .get(&id)
                .await?
                .ok_or(OrchestratorError::SandboxNotFound(id))?;
            if metadata.state != SandboxState::Running {
                return Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id: id,
                    state: metadata.state,
                });
            }
            if limit > MAX_SANDBOX_LOG_LIMIT {
                return Err(OrchestratorError::InternalError(format!(
                    "sandbox log limit cannot exceed {MAX_SANDBOX_LOG_LIMIT}"
                )));
            }
            if limit == 0 {
                return Ok(Vec::new());
            }
            let (start, end) = log_query_window(cursor, backward);
            let start = start.max(metadata.created_at.into());
            let handle = self
                .sandboxes
                .read()
                .await
                .get(&id)
                .cloned()
                .ok_or_else(|| {
                    OrchestratorError::InternalError(
                        "sandbox runtime is transitioning; retry log query".into(),
                    )
                })?;
            let future = {
                let sandbox = handle.lock().await;
                let current = self
                    .store
                    .get(&id)
                    .await?
                    .ok_or(OrchestratorError::SandboxNotFound(id))?;
                if current.state != SandboxState::Running {
                    return Err(OrchestratorError::InvalidSandboxState {
                        sandbox_id: id,
                        state: current.state,
                    });
                }
                sandbox
                    .logs_query(start, end, limit, backward, level, search)
                    .ok_or_else(|| {
                        OrchestratorError::InternalError(
                            "sandbox backend does not support logs".into(),
                        )
                    })?
            };
            future.await.map_err(Into::into)
        };

        tokio::time::timeout(SANDBOX_LOG_QUERY_TIMEOUT, operation)
            .await
            .map_err(|_| OrchestratorError::InternalError("sandbox log query timed out".into()))?
    }
}

fn persisted_sandboxes_require_managed_seed(persisted: &[SandboxMetadata]) -> bool {
    persisted
        .iter()
        .any(|metadata| metadata.secure || !metadata.network_policy.allow_public_traffic)
}

#[cfg(test)]
impl<S, F, P> Orchestrator<S, F, P>
where
    S: MetadataStore + 'static,
    F: SandboxBackendFactory,
    P: SandboxPersister + 'static,
{
    pub(crate) async fn publish_native_control_for_test(
        &self,
        id: SandboxId,
        control: crate::sandbox::NativeControl,
    ) -> bool {
        self.set_metadata_state_for_test(id, SandboxState::Running)
            .await
            .unwrap();
        let backend = crate::sandbox::mock::MockSandboxBackend::new_with_native_control(
            Arc::new(crate::sandbox::mock::MockBehavior::new()),
            control,
        );
        let handle: SandboxHandle = Arc::new(Mutex::new(Box::new(backend)));
        self.sandboxes.write().await.insert(id, handle.clone());
        self.publish_native_control_if_current_handle(id, &handle)
            .await
    }
    #[cfg(test)]
    pub(crate) async fn set_native_control_for_test(
        &self,
        id: SandboxId,
        control: crate::sandbox::NativeControl,
    ) -> Arc<crate::sandbox::mock::MockBehavior> {
        self.set_metadata_state_for_test(id, SandboxState::Running)
            .await
            .unwrap();
        let behavior = Arc::new(crate::sandbox::mock::MockBehavior::new());
        let backend = crate::sandbox::mock::MockSandboxBackend::new(behavior.clone());
        self.sandboxes
            .write()
            .await
            .insert(id, Arc::new(Mutex::new(Box::new(backend))));
        let epoch = control.route_epoch();
        self.proxy_routes
            .write()
            .await
            .publish_control(id, control, epoch);
        behavior
    }
    #[cfg(test)]
    pub(crate) async fn set_proxy_target_for_test(
        &self,
        sandbox_id: SandboxId,
        target: ProxyTarget,
        state: SandboxState,
    ) {
        self.set_metadata_state_for_test(sandbox_id, state)
            .await
            .expect("seed proxy metadata state for test");

        if state == SandboxState::Running {
            self.upsert_proxy_route(sandbox_id, target).await;
        } else {
            let _ = self.proxy_routes.write().await.remove(&sandbox_id);
        }
    }

    pub(crate) async fn set_metadata_state_for_test(
        &self,
        sandbox_id: SandboxId,
        state: SandboxState,
    ) -> Result<()> {
        let existing = self.store.get(&sandbox_id).await?;
        match existing {
            Some(mut metadata) => {
                metadata.state = state;
                self.store.update(metadata).await?;
            }
            None => {
                let metadata = SandboxMetadata {
                    id: sandbox_id,
                    state,
                    ..Default::default()
                };
                self.store.add(metadata.clone()).await?;
            }
        }

        Ok(())
    }

    pub(crate) async fn set_auto_resume_for_test(
        &self,
        sandbox_id: &SandboxId,
        auto_resume_enabled: bool,
    ) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };

        metadata.auto_resume = auto_resume_enabled;
        self.store.update(metadata).await?;

        Ok(())
    }

    pub(crate) async fn set_secure_for_test(
        &self,
        sandbox_id: &SandboxId,
        secure: bool,
    ) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };
        metadata.secure = secure;
        self.store.update(metadata).await?;
        Ok(())
    }

    pub(crate) async fn set_template_builder_for_test(&self, sandbox_id: &SandboxId) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };
        metadata.template_builder = true;
        self.store.update(metadata).await?;
        Ok(())
    }

    pub(crate) async fn set_allow_public_traffic_for_test(
        &self,
        sandbox_id: &SandboxId,
        allow_public_traffic: bool,
    ) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };
        metadata.network_policy.allow_public_traffic = allow_public_traffic;
        self.store.update(metadata).await?;
        Ok(())
    }

    pub(crate) async fn remove_proxy_route_for_test(&self, sandbox_id: &SandboxId) {
        let _ = self.proxy_routes.write().await.remove(sandbox_id);
    }
}

fn default_fresh_sandbox_resources() -> SandboxResources {
    let config = ConfigManager::global_config();
    SandboxResources {
        cpu_count: config.machine.vcpu_count,
        memory_mib: config.machine.mem_size_mib,
        // Filled from backend runtime info after the rootfs device is created.
        disk_size_mib: 0,
    }
}

fn resources_with_runtime_info(
    mut resources: SandboxResources,
    runtime_info: SandboxRuntimeInfo,
) -> SandboxResources {
    // This API resource field tracks the rootfs block device size. Attached
    // drives are separately configured storage and are not folded into it.
    if let Some(size) = runtime_info.rootfs_virtual_size {
        resources.disk_size_mib = bytes_to_mib_ceil(size);
    }
    resources
}

fn configured_runtime_versions() -> SnapshotRuntimeVersions {
    let config = ConfigManager::global_config();
    SnapshotRuntimeVersions::new(
        config
            .kernel
            .version
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        config
            .firecracker
            .version
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        config.envd.version.clone(),
        config.resolved_tools_version().to_string(),
    )
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
