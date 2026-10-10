//! Worker-authenticated accepted SeqPacket ingress foundation.
//!
//! The opt-in native-root listener retains its original socket and accepted jobs.
//! Public HTTP create remains unavailable; no Front adapter is installed.
//! Worker issuer authority is obtained through the existing reciprocal requester;
//! packet fields never constitute a reservation grant or backend authority.

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum DiagnosticStage {
    Gate,
    Reserve,
    ReserveReturned,
    PreLaunchDeadline,
    Launch,
    Execution,
}
#[cfg(test)]
struct StageDiagnostic {
    started: Instant,
    until: Instant,
    stage: DiagnosticStage,
    ok: bool,
}
#[cfg(test)]
impl StageDiagnostic {
    fn new(until: Instant) -> Self {
        Self {
            started: Instant::now(),
            until,
            stage: DiagnosticStage::Gate,
            ok: false,
        }
    }
    fn stage(&mut self, stage: DiagnosticStage) {
        self.stage = stage;
        self.ok = false;
    }
}
#[cfg(test)]
impl Drop for StageDiagnostic {
    fn drop(&mut self) {
        eprintln!(
            "native_retained stage={:?} ok={} elapsed_ms={} remaining_ms={}",
            self.stage,
            self.ok,
            self.started.elapsed().as_millis(),
            self.until
                .saturating_duration_since(Instant::now())
                .as_millis()
        );
    }
}
use super::native_issuer::{
    alive, same, validate_peer, Endpoint, Held, Peer, Publication, RequestDto, Worker,
};
use crate::{
    orchestrator::{MetadataStore, Orchestrator, SandboxPersister},
    sandbox::SandboxBackendFactory,
};
use anyhow::{ensure, Context, Result};
use nix::sys::socket::{self, MsgFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::IoSliceMut,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;
const FRAME: usize = 8192;
const RECORDS: usize = 32;
const FIXED: usize = 128 * 1024;
const TICKET: usize = 124 * 1024;
const BUDGET: usize = 4 * 1024 * 1024;
const FIXED_COMMAND: &str = "printf 'once\\n' >> invocation-count && printf worker-real-213 > result.txt && /usr/bin/sha256sum result.txt && /bin/sleep 1";
const FAULT_WINDOW_COMMAND: &str = "printf 'once\\n' >> invocation-count && printf worker-real-213 > result.txt && /usr/bin/sha256sum result.txt && /bin/sleep 4";
const MANAGED_VM_STATE_COMMAND: &str = "printf 'once\\n' >> invocation-count && printf worker-real-213 > result.txt && /usr/bin/sha256sum result.txt && /bin/sleep 16";
const MANAGED_SNAPSHOT_COMMAND: &str = "printf 'once\\n' >> invocation-count && printf worker-real-213 > result.txt && /usr/bin/sha256sum result.txt && /bin/sleep 32";
const MANAGED_SNAPSHOT_READBACK_COMMAND: &str = "/init --qualify-snapshot-readback";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixedPlan {
    pub(crate) profile: String,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) cwd: String,
    pub(crate) env: std::collections::BTreeMap<String, String>,
    pub(crate) timeout_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixedLaunch {
    pub(crate) schema: u32,
    pub(crate) memory_mib: u32,
    pub(crate) tenant_id: u64,
    pub(crate) function_id: u64,
    pub(crate) version: u64,
    pub(crate) cpu_millicores: u64,
    pub(crate) workload_kind: u32,
    pub(crate) plan: FixedPlan,
    pub(crate) plan_sha256: String,
}
impl FixedLaunch {
    pub(crate) fn selected(profile: Option<&str>) -> Option<Self> {
        let (command, timeout_ms) = match profile {
            None => (FIXED_COMMAND, 3000),
            Some("worker-loss-window-v1") => (FAULT_WINDOW_COMMAND, 5000),
            Some("managed-vm-state-v1") => (MANAGED_VM_STATE_COMMAND, 36000),
            Some("managed-snapshot-v1" | "managed-snapshot-suspend-v2") => {
                (MANAGED_SNAPSHOT_COMMAND, 90000)
            }
            Some("managed-snapshot-readback-v3") => (MANAGED_SNAPSHOT_READBACK_COMMAND, 120000),
            Some(_) => return None,
        };
        let plan = FixedPlan {
            profile: profile.unwrap_or("fixed-v1").into(),
            command: "/bin/sh".into(),
            args: vec!["-c".into(), command.into()],
            cwd: ".".into(),
            env: Default::default(),
            timeout_ms,
        };
        let plan_sha256 = Sha256::digest(serde_json::to_vec(&plan).ok()?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Some(Self {
            schema: 2,
            memory_mib: 512,
            tenant_id: 1,
            function_id: 2,
            version: 1,
            cpu_millicores: 1000,
            workload_kind: 0,
            plan,
            plan_sha256,
        })
    }
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() > 4096 {
            return None;
        }
        let value: Self = serde_json::from_slice(raw).ok()?;
        let profile = (value.plan.profile != "fixed-v1").then_some(value.plan.profile.as_str());
        if Self::selected(profile)? != value || serde_json::to_vec(&value).ok()? != raw {
            return None;
        }
        Some(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Completion {
    pub(crate) plan_sha256: String,
    pub(crate) caller_sha256: String,
    pub(crate) native_epoch: String,
    pub(crate) route_epoch: u64,
    pub(crate) session_id: String,
    pub(crate) operation_id: String,
    pub(crate) state: String,
    pub(crate) exit_code: i32,
    pub(crate) process_absent: bool,
    pub(crate) terminal: bool,
    pub(crate) acked_sequence: u64,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
    pub(crate) stdout_sha256: String,
    pub(crate) stderr_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutputRead {
    pub(crate) stream: String,
    pub(crate) offset: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutputChunk {
    pub(crate) stream: String,
    pub(crate) offset: usize,
    pub(crate) data_hex: String,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Start,
    Query,
    Stop,
    ExecutionQuery,
    ExecutionRead,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: u32,
    kind: Kind,
    original: RequestDto,
    canonical_launch: String,
    authority_epoch: u64,
    original_sha256: String,
    #[serde(default)]
    output_read: Option<OutputRead>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    schema: u32,
    memory_mib: u32,
}
pub(crate) fn validated_launch_memory(raw: &[u8]) -> Result<u32> {
    if let Some(fixed) = FixedLaunch::parse(raw) {
        return Ok(fixed.memory_mib);
    }
    ensure!(raw.len() <= 128, "launch bound");
    let launch: Launch = serde_json::from_slice(raw)?;
    ensure!(
        launch.schema == 1
            && (128..=512).contains(&launch.memory_mib)
            && serde_json::to_vec(&launch)? == raw,
        "closed launch grammar"
    );
    Ok(launch.memory_mib)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Starting,
    Ready,
    Unknown,
    ExecutionStopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureStage {
    Gate,
    Reserve,
    PreLaunchDeadline,
    Launch,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct OrchestrationFailure {
    schema_version: u32,
    stage: FailureStage,
    kind: &'static str,
    retry_forbidden: bool,
}
fn retain_original_failure(state: &Arc<Mutex<State>>, index: usize, stage: FailureStage) {
    let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
    let record = &mut state.records[index];
    record.status = Status::Unknown;
    if record.orchestration_failure.is_none() {
        record.orchestration_failure = Some(OrchestrationFailure {
            schema_version: 1,
            stage,
            kind: "returned_error",
            retry_forbidden: true,
        });
    }
}
fn query_failure(
    schema: u32,
    status: Status,
    failure: Option<&OrchestrationFailure>,
) -> Option<&OrchestrationFailure> {
    if schema == 4 && status == Status::Unknown {
        failure
    } else {
        None
    }
}
#[derive(Clone, Serialize)]
struct ExecutionReceipt {
    grant_sha256: String,
    network_returned: bool,
    persistent_artifacts_retained: bool,
}
#[derive(Serialize)]
struct Reply<'a> {
    schema: u32,
    worker: &'a Worker,
    operation_id: &'a str,
    request_sha256: &'a str,
    server_incarnation: &'a str,
    sandbox_id: Option<&'a str>,
    status: Status,
    authority_epoch: u64,
    original_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<&'a ExecutionReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion: Option<&'a Completion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<OutputChunk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    orchestration_failure: Option<&'a OrchestrationFailure>,
}
#[derive(Debug, PartialEq, Eq)]
enum ConnectionOutcome {
    Replied,
    AdmissionRefused,
}
struct LaunchJob {
    handle: Option<JoinHandle<()>>,
    failed: bool,
}
async fn join_launch(job: &Arc<tokio::sync::Mutex<LaunchJob>>, until: Instant) -> Result<()> {
    let mut job =
        tokio::time::timeout_at(tokio::time::Instant::from_std(until), job.lock()).await?;
    ensure!(!job.failed, "original launch join debt");
    if let Some(handle) = job.handle.as_mut() {
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(until), handle).await?;
        if result.is_err() {
            job.failed = true;
            anyhow::bail!("original launch join failed");
        }
        job.handle.take();
    }
    ensure!(Instant::now() < until, "launch join completed late");
    Ok(())
}
struct Record {
    original: RequestDto,
    canonical: String,
    epoch: u64,
    digest: String,
    status: Status,
    sandbox: Option<String>,
    job: Option<Arc<tokio::sync::Mutex<LaunchJob>>>,
    admission: Arc<Admission>,
    fenced: bool,
    stop_job: Option<Arc<tokio::sync::Mutex<LaunchJob>>>,
    stop_until: Option<Instant>,
    execution: Option<ExecutionReceipt>,
    completion: Option<Completion>,
    orchestration_failure: Option<OrchestrationFailure>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
pub(crate) struct OriginalExecution<'a> {
    pub(crate) request: &'a [u8],
    pub(crate) epoch: u64,
    pub(crate) digest: &'a str,
    pub(crate) canonical: &'a [u8],
    pub(crate) sandbox: crate::types::SandboxId,
    pub(crate) peer_domain: [u8; 32],
}
struct KeyedExecution<'a> {
    caller: [u8; 32],
    native_epoch: &'a str,
    operation: String,
    request: super::NativeControlRequest,
}
struct State {
    records: Vec<Record>,
    bytes: usize,
    closed: bool,
}
impl State {
    fn commit_execution(
        &self,
        index: usize,
        control: &super::NativeControl,
        keyed: KeyedExecution<'_>,
        expires: Instant,
    ) -> Result<serde_json::Value> {
        ensure!(
            Instant::now() < expires
                && !self.closed
                && !self.records.get(index).context("original absent")?.fenced,
            "original execution fenced"
        );
        control.admit_exec(
            keyed.caller,
            keyed.native_epoch,
            keyed.operation,
            keyed.request,
        )
    }
}
struct Admission {
    closed: std::sync::atomic::AtomicBool,
    gate: Arc<tokio::sync::RwLock<()>>,
    close_until: OnceLock<Instant>,
}
impl Admission {
    fn new() -> Self {
        Self {
            closed: std::sync::atomic::AtomicBool::new(false),
            gate: Arc::new(tokio::sync::RwLock::new(())),
            close_until: OnceLock::new(),
        }
    }
    fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    async fn permit(&self, until: Instant) -> Result<tokio::sync::OwnedRwLockReadGuard<()>> {
        let permit = tokio::time::timeout_at(
            tokio::time::Instant::from_std(until),
            self.gate.clone().read_owned(),
        )
        .await?;
        ensure!(
            !self.closed.load(std::sync::atomic::Ordering::SeqCst) && Instant::now() < until,
            "original dispatch closed or expired"
        );
        Ok(permit)
    }
    async fn barrier(&self, until: Instant) -> Result<()> {
        let until = until.min(*self.close_until.get_or_init(|| until));
        self.close();
        let guard =
            tokio::time::timeout_at(tokio::time::Instant::from_std(until), self.gate.write())
                .await?;
        ensure!(Instant::now() < until, "close barrier completed late");
        drop(guard);
        Ok(())
    }
}
/// Single lifetime owner. Dropping it seals admission and retains jobs/pins.
/// No durable restart adoption, physical retirement or listener ownership is
/// inferred by this volatile bridge.
struct Ingress {
    state: Arc<Mutex<State>>,
    admission: Arc<Admission>,
    endpoint: Arc<Endpoint>,
    endpoint_pin: Arc<Held>,
    root: Arc<Publication>,
    sdk_incarnation: String,
    peer: Mutex<Option<Arc<Peer>>>,
}
struct Debt {
    _state: Arc<Mutex<State>>,
    _endpoint: Arc<Endpoint>,
    _endpoint_pin: Arc<Held>,
    _root: Arc<Publication>,
    _peer: Option<Arc<Peer>>,
    _admission: Arc<Admission>,
}
static INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static DEBT: OnceLock<Mutex<Option<Debt>>> = OnceLock::new();
impl Drop for Ingress {
    fn drop(&mut self) {
        self.admission.close();
        self.state.lock().unwrap_or_else(|p| p.into_inner()).closed = true;
        *DEBT
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Debt {
            _state: self.state.clone(),
            _endpoint: self.endpoint.clone(),
            _endpoint_pin: self.endpoint_pin.clone(),
            _root: self.root.clone(),
            _peer: self
                .peer
                .get_mut()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
            _admission: self.admission.clone(),
        });
    }
}
impl Ingress {
    /// Called only by the protected native-root lifecycle, using its actual
    /// requester publication and genuine Orchestrator incarnation. The endpoint
    /// is the protected Worker issuer endpoint, not an identity supplied by a peer.
    fn install(
        root: Arc<Publication>,
        endpoint_path: &Path,
        sdk_incarnation: String,
    ) -> Result<Self> {
        root.root_valid()?;
        let (pin, raw) = Held::load(endpoint_path)?;
        let endpoint: Endpoint = serde_json::from_slice(&raw)?;
        use std::os::unix::fs::MetadataExt;
        ensure!(
            endpoint.schema == 1
                && endpoint.peer_uid == 0
                && endpoint.peer_pid > 0
                && endpoint.start_tick > 0
                && endpoint.exe_sha256.len() == 64
                && endpoint
                    .exe_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && endpoint.namespace_device == root.root_pin.dev()
                && endpoint.namespace_inode == root.root_pin.ino()
                && endpoint.socket_path == root.root_path.join("native-issuer/i.sock"),
            "protected Worker endpoint grammar"
        );

        ensure!(
            endpoint_path.parent() == Some(root.root_path.as_path()),
            "endpoint outside original namespace"
        );
        ensure!(
            uuid::Uuid::parse_str(&sdk_incarnation)?.to_string() == sdk_incarnation,
            "noncanonical SDK incarnation"
        );
        let mut records = Vec::new();
        records.try_reserve_exact(RECORDS)?;
        ensure!(
            !INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst),
            "ingress already installed"
        );
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                records,
                bytes: FIXED,
                closed: false,
            })),
            admission: Arc::new(Admission::new()),
            endpoint: Arc::new(endpoint),
            endpoint_pin: Arc::new(pin),
            root,
            sdk_incarnation,
            peer: Mutex::new(None),
        })
    }
    /// Successful completion is a dispatch barrier, not physical retirement.
    /// Timeout/cancellation leaves admission permanently closed and jobs retained.
    pub(crate) async fn seal(&self, until: Instant) -> Result<()> {
        self.admission.close();
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("ingress poisoned"))?
            .closed = true;
        self.admission.barrier(until).await?;
        let jobs = {
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("ingress poisoned"))?
                .records
                .iter()
                .filter_map(|r| r.job.clone())
                .collect::<Vec<_>>()
        };
        for job in jobs {
            join_launch(&job, until).await?;
        }
        let stops = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("ingress poisoned"))?;
            state
                .records
                .iter()
                .filter_map(|r| r.stop_job.clone().map(|job| (job, r.stop_until.unwrap())))
                .collect::<Vec<_>>()
        };
        for (job, first_until) in stops {
            join_launch(&job, until.min(first_until)).await?;
        }
        Ok(())
    }
    async fn fence_original(&self, operation: &str, until: Instant) -> Result<()> {
        let (admission, job) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("ingress poisoned"))?;
            let Some(r) = state
                .records
                .iter_mut()
                .find(|r| r.original.context.operation_id == operation)
            else {
                return Ok(());
            };
            r.fenced = true;
            r.status = Status::Unknown;
            r.admission.close();
            (r.admission.clone(), r.job.clone())
        };
        admission.barrier(until).await?;
        if let Some(job) = job {
            join_launch(&job, until).await?;
        }
        Ok(())
    }
    /// One actual accepted socket, one bounded packet and one response. Caller
    /// installs this accepted FD before invoking; nonblocking status is required,
    /// never changed on an inherited OFD. Caller cancellation closes transport
    /// only: the original launch task/Orchestrator is independently retained.
    async fn serve<S, F, P>(
        &self,
        fd: OwnedFd,
        orchestrator: Arc<Orchestrator<S, F, P>>,
        until: Instant,
    ) -> Result<ConnectionOutcome>
    where
        S: MetadataStore + 'static,
        F: SandboxBackendFactory + 'static,
        P: SandboxPersister + 'static,
    {
        ensure!(
            Instant::now() < until && until <= Instant::now() + Duration::from_secs(3),
            "ingress exchange deadline"
        );
        ensure!(
            orchestrator.native_create_incarnation().to_string() == self.sdk_incarnation,
            "SDK incarnation changed"
        );
        let flags = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFL)?;
        ensure!(
            flags & nix::libc::O_NONBLOCK != 0,
            "blocking ingress refused"
        );
        self.endpoint_pin.verify()?;
        let peer = {
            let mut original = self
                .peer
                .lock()
                .map_err(|_| anyhow::anyhow!("ingress peer poisoned"))?;
            if original.is_none() {
                *original = Some(Arc::new(validate_peer(
                    &fd,
                    &self.endpoint,
                    &self.root,
                    until,
                )?));
            }
            original.as_ref().unwrap().clone()
        };
        peer.revalidate(&fd, &self.endpoint, &self.root, until)?;
        let mut raw = [0u8; FRAME + 1];
        let n = loop {
            ensure!(Instant::now() < until, "ingress receive deadline");
            alive(&peer.pidfd)?;
            let mut iov = [IoSliceMut::new(&mut raw)];
            match socket::recvmsg::<()>(fd.as_raw_fd(), &mut iov, None, MsgFlags::MSG_DONTWAIT) {
                Ok(m) => {
                    ensure!(
                        m.bytes > 0
                            && m.bytes <= FRAME
                            && !m
                                .flags
                                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC),
                        "ingress ancillary/truncation refused"
                    );
                    break m.bytes;
                }
                Err(nix::errno::Errno::EAGAIN) => tokio::task::yield_now().await,
                Err(e) => return Err(e.into()),
            }
        };
        self.endpoint_pin.verify()?;
        peer.revalidate(&fd, &self.endpoint, &self.root, until)?;
        let wire: Wire = serde_json::from_slice(&raw[..n])?;
        validate(&wire, &self.endpoint.worker, &self.sdk_incarnation)?;
        let operation = wire.original.context.operation_id.clone();
        let response = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("ingress poisoned"))?;
            ensure!(Instant::now() < until, "late ingress admission");
            let existing = state
                .records
                .iter()
                .position(|r| r.original.context.operation_id == operation);
            let index = if let Some(index) = existing {
                let old = &state.records[index];
                ensure!(
                    old.digest == wire.original_sha256
                        && old.epoch == wire.authority_epoch
                        && old.canonical == wire.canonical_launch,
                    "original payload drift"
                );
                index
            } else {
                // Authenticated and closed immutable wire, but no original record:
                // Query/Stop cannot reserve a ticket or dispatch an effect. Close this
                // connection without manufacturing a business Unknown receipt.
                if let Some(outcome) = missing_original_outcome(wire.kind) {
                    return Ok(outcome);
                }
                ensure!(
                    wire.kind == Kind::Start && !state.closed,
                    "unknown original or closed ingress"
                );
                ensure!(
                    state.records.len() < RECORDS
                        && state.bytes.checked_add(TICKET).is_some_and(|b| b <= BUDGET),
                    "ingress capacity"
                );
                state.bytes += TICKET;
                let index = state.records.len();
                state.records.push(Record {
                    original: wire.original,
                    canonical: wire.canonical_launch,
                    epoch: wire.authority_epoch,
                    digest: wire.original_sha256,
                    status: Status::Unknown,
                    sandbox: None,
                    job: None,
                    admission: Arc::new(Admission::new()),
                    fenced: false,
                    stop_job: None,
                    stop_until: None,
                    execution: None,
                    completion: None,
                    orchestration_failure: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                });
                let retained = self.state.clone();
                let sdk = orchestrator.clone();
                let admission = self.admission.clone();
                let original_admission = state.records[index].admission.clone();
                let original = serde_json::to_vec(&state.records[index].original)?;
                let canonical = state.records[index].canonical.clone();
                let epoch = state.records[index].epoch;
                let peer_domain = self.endpoint_pin.digest;
                let original_digest = state.records[index].digest.clone();
                let (start, gate) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(async move {
                    #[cfg(test)]
                    let mut diagnostic = StageDiagnostic::new(until);
                    let permit = async {
                        gate.await?;
                        admission.permit(until).await
                    }
                    .await;
                    let _permit = match permit {
                        Ok(permit) => permit,
                        Err(_) => {
                            retain_original_failure(&retained, index, FailureStage::Gate);
                            return;
                        }
                    };
                    let _original_permit = match original_admission.permit(until).await {
                        Ok(permit) => permit,
                        Err(_) => {
                            retain_original_failure(&retained, index, FailureStage::Gate);
                            return;
                        }
                    };
                    // Genuine reciprocal Worker reservation precedes every backend
                    // effect; native_launch_original retains its original owner.
                    let mut failure_stage = FailureStage::Reserve;
                    let result = async {
                        ensure!(Instant::now() < until, "late original reserve dispatch");
                        #[cfg(test)]
                        diagnostic.stage(DiagnosticStage::Reserve);
                        let reserved = sdk.native_reserve_original(&original, epoch, until);
                        #[cfg(test)]
                        {
                            diagnostic.stage(DiagnosticStage::ReserveReturned);
                            diagnostic.ok = reserved.is_ok();
                            eprintln!(
                                "native_retained stage=ReserveReturned ok={} remaining_ms={}",
                                reserved.is_ok(),
                                until.saturating_duration_since(Instant::now()).as_millis()
                            );
                        }
                        reserved?;
                        failure_stage = FailureStage::PreLaunchDeadline;
                        #[cfg(test)]
                        diagnostic.stage(DiagnosticStage::PreLaunchDeadline);
                        ensure!(Instant::now() < until, "late original launch dispatch");
                        #[cfg(test)]
                        diagnostic.stage(DiagnosticStage::Launch);
                        failure_stage = FailureStage::Launch;
                        sdk.native_launch_original(&operation, canonical.as_bytes())
                            .await
                            .map_err(anyhow::Error::from)
                    }
                    .await;
                    let meta = match result {
                        Ok(meta) => meta,
                        Err(_) => {
                            retain_original_failure(&retained, index, failure_stage);
                            return;
                        }
                    };
                    {
                        let mut state = retained.lock().unwrap_or_else(|p| p.into_inner());
                        let r = &mut state.records[index];
                        if r.fenced {
                            r.status = Status::Unknown;
                            return;
                        }
                        r.sandbox = Some(meta.id.to_string());
                        r.status = Status::Ready;
                    }
                    #[cfg(test)]
                    {
                        diagnostic.ok = true;
                    }
                    if FixedLaunch::parse(canonical.as_bytes()).is_some() {
                        let commit_owner = retained.clone();
                        #[cfg(test)]
                        diagnostic.stage(DiagnosticStage::Execution);
                        let execution = sdk
                            .native_execute_original(
                                OriginalExecution {
                                    request: &original,
                                    epoch,
                                    digest: &original_digest,
                                    canonical: canonical.as_bytes(),
                                    sandbox: meta.id,
                                    peer_domain,
                                },
                                _original_permit,
                                move |control,
                                      caller,
                                      native_epoch,
                                      operation,
                                      request,
                                      expires| {
                                    let state = commit_owner.lock().map_err(|_| {
                                        anyhow::anyhow!("original admission poisoned")
                                    })?;
                                    // Same actual SDK State fence through synchronous
                                    // start_keyed admission; Stop cannot pass in between.
                                    state.commit_execution(
                                        index,
                                        control,
                                        KeyedExecution {
                                            caller,
                                            native_epoch,
                                            operation,
                                            request,
                                        },
                                        expires,
                                    )
                                },
                            )
                            .await;
                        #[cfg(test)]
                        {
                            diagnostic.ok = execution.is_ok();
                        }
                        if let Ok((receipt, stdout, stderr)) = execution {
                            let mut state = retained.lock().unwrap_or_else(|p| p.into_inner());
                            let r = &mut state.records[index];
                            // Preserve immutable business evidence independently of Stop.
                            if r.completion.is_none() {
                                r.completion = Some(receipt);
                                r.stdout = stdout;
                                r.stderr = stderr;
                            }
                        }
                    }
                });
                state.records[index].job = Some(Arc::new(tokio::sync::Mutex::new(LaunchJob {
                    handle: Some(task),
                    failed: false,
                })));
                state.records[index].status = Status::Starting;
                let _ = start.send(());
                index
            };
            if wire.kind == Kind::Stop && state.records[index].stop_job.is_none() {
                let r = &mut state.records[index];
                r.fenced = true;
                r.status = Status::Unknown;
                r.admission.close();
                let stop_until = Instant::now() + Duration::from_secs(30);
                r.stop_until = Some(stop_until);
                let admission = r.admission.clone();
                let launch_job = r.job.clone();
                let original = serde_json::to_vec(&r.original)?;
                let epoch = r.epoch;
                let digest = r.digest.clone();
                let retained = self.state.clone();
                let sdk = orchestrator.clone();
                let peer_domain = self.endpoint_pin.digest;
                let sandbox = r.sandbox.clone();
                let fixed = FixedLaunch::parse(r.canonical.as_bytes()).is_some();
                let (start, gate) = tokio::sync::oneshot::channel();
                let handle = tokio::spawn(async move {
                    let outcome = async {
                        gate.await?;
                        admission.barrier(stop_until).await?;
                        if fixed {
                            if let Some(id) = sandbox {
                                // The actor retains keyed cancellation; a refusal stays debt.
                                let _ = sdk
                                    .native_cancel_fixed_execution(
                                        crate::types::SandboxId::from_uuid(uuid::Uuid::parse_str(
                                            &id,
                                        )?),
                                        epoch,
                                        &digest,
                                        peer_domain,
                                    )
                                    .await;
                            }
                        }
                        if let Some(job) = launch_job {
                            join_launch(&job, stop_until).await?;
                        }
                        // Do not timeout/drop this future: the SAME retained job
                        // owns physical cleanup even after observation expires.
                        sdk.native_stop_original(&original, epoch, &digest, stop_until)
                            .await
                    }
                    .await;
                    let mut state = retained.lock().unwrap_or_else(|p| p.into_inner());
                    let r = &mut state.records[index];
                    if let Ok((stopped, grant_sha256)) = outcome {
                        r.sandbox = Some(stopped.sandbox_id().to_string());
                        r.execution = Some(ExecutionReceipt {
                            grant_sha256,
                            network_returned: stopped.network_returned(),
                            persistent_artifacts_retained: stopped.persistent_artifacts_retained(),
                        });
                        if Instant::now() < stop_until {
                            r.status = Status::ExecutionStopped;
                        }
                    }
                });
                r.stop_job = Some(Arc::new(tokio::sync::Mutex::new(LaunchJob {
                    handle: Some(handle),
                    failed: false,
                })));
                let _ = start.send(());
            }
            // Exact repeated Start/Stop is observation-only; no second job.
            let r = &state.records[index];
            let output = if let Some(read) = wire.output_read.as_ref() {
                ensure!(
                    wire.kind == Kind::ExecutionRead && r.completion.is_some(),
                    "output original incomplete"
                );
                let bytes = match read.stream.as_str() {
                    "stdout" => &r.stdout,
                    "stderr" => &r.stderr,
                    _ => anyhow::bail!("output stream refused"),
                };
                ensure!(read.offset <= bytes.len(), "output offset refused");
                let end = read.offset.saturating_add(2048).min(bytes.len());
                Some(OutputChunk {
                    stream: read.stream.clone(),
                    offset: read.offset,
                    data_hex: bytes[read.offset..end]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                })
            } else {
                None
            };
            serde_json::to_vec(&Reply {
                schema: wire.schema,
                worker: &r.original.context.target,
                operation_id: &r.original.context.operation_id,
                request_sha256: &r.original.request_sha256,
                server_incarnation: &r.original.server_incarnation,
                sandbox_id: r.sandbox.as_deref(),
                status: project_status(wire.schema, r.status, r.stop_job.is_some()),
                authority_epoch: r.epoch,
                original_sha256: &r.digest,
                completion: if wire.schema == 3 {
                    r.completion.as_ref()
                } else {
                    None
                },
                output,
                orchestration_failure: query_failure(
                    wire.schema,
                    project_status(wire.schema, r.status, r.stop_job.is_some()),
                    r.orchestration_failure.as_ref(),
                ),
                execution: if wire.schema == 2 && matches!(r.status, Status::ExecutionStopped) {
                    r.execution.as_ref()
                } else {
                    None
                },
            })?
        };
        ensure!(response.len() <= FRAME, "ingress response bound");
        self.endpoint_pin.verify()?;
        peer.revalidate(&fd, &self.endpoint, &self.root, until)?;
        loop {
            ensure!(Instant::now() < until, "ingress reply deadline");
            alive(&peer.pidfd)?;
            match socket::send(
                fd.as_raw_fd(),
                &response,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            ) {
                Ok(n) => {
                    ensure!(n == response.len(), "short ingress packet");
                    break;
                }
                Err(nix::errno::Errno::EAGAIN) => tokio::task::yield_now().await,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(ConnectionOutcome::Replied)
    }
}
// Called only after reciprocal authentication, full closed-wire validation,
// original digest binding and the admission deadline check.
fn missing_original_outcome(kind: Kind) -> Option<ConnectionOutcome> {
    match kind {
        Kind::Query | Kind::Stop | Kind::ExecutionQuery | Kind::ExecutionRead => {
            Some(ConnectionOutcome::AdmissionRefused)
        }
        Kind::Start => None,
    }
}
// Schema 1 keeps the original closed Start/Query reply vocabulary. A stopped
// original can never project Ready to an older reader. Schema 2 is explicitly
// negotiated by Stop or Query and alone carries the narrow execution receipt.
fn project_status(schema: u32, status: Status, stopping: bool) -> Status {
    if matches!(schema, 1 | 4) && (stopping || matches!(status, Status::ExecutionStopped)) {
        Status::Unknown
    } else {
        status
    }
}
fn validate(w: &Wire, worker: &Worker, sdk: &str) -> Result<()> {
    ensure!(
        matches!(
            (w.schema, w.kind),
            (1, Kind::Start | Kind::Query)
                | (2, Kind::Stop | Kind::Query)
                | (3, Kind::ExecutionQuery | Kind::ExecutionRead)
                | (4, Kind::Query)
        ) && w.authority_epoch > 0
            && w.original.context.target == *worker
            && w.original.server_incarnation == sdk,
        "original ingress binding"
    );
    ensure!(
        w.original.schema == 1
            && w.original.kind == "grant"
            && w.original.context.protocol_major == 2
            && !w.original.context.operation_id.is_empty()
            && w.original.context.operation_id.len() <= 64,
        "original grammar"
    );
    validated_launch_memory(w.canonical_launch.as_bytes())?;
    if let Some(fixed) = FixedLaunch::parse(w.canonical_launch.as_bytes()) {
        ensure!(
            fixed.tenant_id == w.original.tenant_id,
            "execution tenant drift"
        );
    }
    ensure!(
        (w.kind == Kind::ExecutionRead) == w.output_read.is_some(),
        "output grammar refused"
    );
    if w.schema == 3 {
        ensure!(
            FixedLaunch::parse(w.canonical_launch.as_bytes()).is_some(),
            "execution plan absent"
        );
    }
    ensure!(
        format!("{:x}", Sha256::digest(w.canonical_launch.as_bytes())) == w.original.request_sha256
            && format!("{:x}", Sha256::digest(serde_json::to_vec(&w.original)?))
                == w.original_sha256,
        "original digest drift"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_fixed_execution_plans_preserve_exact_legacy_mapping_and_hash() {
        for profile in [
            None,
            Some("worker-loss-window-v1"),
            Some("managed-vm-state-v1"),
            Some("managed-snapshot-v1"),
            Some("managed-snapshot-suspend-v2"),
            Some("managed-snapshot-readback-v3"),
        ] {
            let plan = FixedLaunch::selected(profile).unwrap();
            let raw = serde_json::to_vec(&plan).unwrap();
            assert_eq!(FixedLaunch::parse(&raw), Some(plan.clone()));
            assert_eq!(validated_launch_memory(&raw).unwrap(), 512);
            let mut drift = plan.clone();
            drift.tenant_id = 2;
            assert!(validated_launch_memory(&serde_json::to_vec(&drift).unwrap()).is_err());
            drift = plan;
            drift.plan.args[1].push_str("; true");
            assert!(validated_launch_memory(&serde_json::to_vec(&drift).unwrap()).is_err());
        }
    }
    #[test]
    fn execution_observation_requires_negotiated_bound_fixed_plan_and_read_cursor() {
        let mut w = wire();
        let plan = FixedLaunch::selected(None).unwrap();
        w.canonical_launch = serde_json::to_string(&plan).unwrap();
        w.original.request_sha256 = format!("{:x}", Sha256::digest(w.canonical_launch.as_bytes()));
        w.original_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&w.original).unwrap())
        );
        w.schema = 3;
        w.kind = Kind::ExecutionQuery;
        assert!(validate(
            &w,
            &w.original.context.target,
            &w.original.server_incarnation
        )
        .is_ok());
        w.kind = Kind::ExecutionRead;
        assert!(validate(
            &w,
            &w.original.context.target,
            &w.original.server_incarnation
        )
        .is_err());
        w.output_read = Some(OutputRead {
            stream: "stdout".into(),
            offset: 0,
        });
        assert!(validate(
            &w,
            &w.original.context.target,
            &w.original.server_incarnation
        )
        .is_ok());
        w.schema = 1;
        assert!(validate(
            &w,
            &w.original.context.target,
            &w.original.server_incarnation
        )
        .is_err());
    }
    #[tokio::test]
    async fn original_state_fence_prevents_late_exec_and_same_actor_admits_once() {
        let (control, _peer) = super::super::NativeControl::test_pair(7);
        let w = wire();
        let mut state = State {
            records: vec![Record {
                original: w.original,
                canonical: w.canonical_launch,
                epoch: w.authority_epoch,
                digest: w.original_sha256,
                status: Status::Ready,
                sandbox: None,
                job: None,
                admission: Arc::new(Admission::new()),
                fenced: true,
                stop_job: None,
                stop_until: None,
                execution: None,
                completion: None,
                orchestration_failure: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }],
            bytes: FIXED + TICKET,
            closed: false,
        };
        let command = || super::super::NativeControlRequest::Exec {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), "printf once".into()],
            env: Default::default(),
            cwd: Some(".".into()),
            timeout_ms: 3000,
        };
        let caller = [9; 32];
        assert!(state
            .commit_execution(
                0,
                &control,
                KeyedExecution {
                    caller,
                    native_epoch: control.epoch(),
                    operation: "original-exec".into(),
                    request: command()
                },
                Instant::now() + Duration::from_secs(2)
            )
            .is_err());
        assert!(control
            .original_truth_test(caller, "original-exec")
            .is_none());
        state.records[0].fenced = false;
        assert!(state
            .commit_execution(
                0,
                &control,
                KeyedExecution {
                    caller,
                    native_epoch: control.epoch(),
                    operation: "expired-exec".into(),
                    request: command()
                },
                Instant::now()
            )
            .is_err());
        assert!(control
            .original_truth_test(caller, "expired-exec")
            .is_none());
        let first = state
            .commit_execution(
                0,
                &control,
                KeyedExecution {
                    caller,
                    native_epoch: control.epoch(),
                    operation: "original-exec".into(),
                    request: command(),
                },
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        let same = state
            .commit_execution(
                0,
                &control,
                KeyedExecution {
                    caller,
                    native_epoch: control.epoch(),
                    operation: "original-exec".into(),
                    request: command(),
                },
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(first, same);
        let truth = control
            .original_truth_test(caller, "original-exec")
            .unwrap();
        assert_eq!(truth.3, 1);
        assert_eq!(truth.5, 1);
        state.records[0].fenced = true;
        assert!(state
            .commit_execution(
                0,
                &control,
                KeyedExecution {
                    caller,
                    native_epoch: control.epoch(),
                    operation: "late-exec".into(),
                    request: command()
                },
                Instant::now() + Duration::from_secs(2)
            )
            .is_err());
        assert!(control.original_truth_test(caller, "late-exec").is_none());
        // Actual in-process actor admission/fence only; no VM effect claimed.
        control.close_test();
    }
    // Admission race model only: no Worker authority, VM or transport success.
    #[tokio::test]
    async fn seal_between_old_check_and_dispatch_prevents_callback() {
        let admission = Arc::new(Admission::new());
        let (checked, check) = tokio::sync::oneshot::channel();
        let (release, paused) = tokio::sync::oneshot::channel();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let original = admission.clone();
        let observed = calls.clone();
        let task = tokio::spawn(async move {
            assert!(!original.closed.load(std::sync::atomic::Ordering::SeqCst));
            checked.send(()).unwrap();
            paused.await.unwrap();
            if let Ok(_permit) = original
                .permit(Instant::now() + Duration::from_secs(1))
                .await
            {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        check.await.unwrap();
        admission
            .barrier(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        release.send(()).unwrap();
        task.await.unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn successful_seal_waits_for_original_dispatch_permit() {
        let admission = Admission::new();
        let permit = admission
            .permit(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let mut close = Box::pin(admission.barrier(Instant::now() + Duration::from_secs(1)));
        tokio::select! { biased; _=&mut close=>panic!("barrier passed live dispatch"), _=tokio::task::yield_now()=>{} }
        assert!(admission.closed.load(std::sync::atomic::Ordering::SeqCst));
        drop(permit);
        close.await.unwrap();
        assert!(admission
            .permit(Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
    }
    #[tokio::test]
    async fn cancelled_launch_join_keeps_the_actual_handle() {
        let (release, wait) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = wait.await;
        });
        let job = Arc::new(tokio::sync::Mutex::new(LaunchJob {
            handle: Some(handle),
            failed: false,
        }));
        let original = job.clone();
        let waiter = tokio::spawn(async move {
            join_launch(&original, Instant::now() + Duration::from_secs(1)).await
        });
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(job.lock().await.handle.is_some());
        release.send(()).unwrap();
        join_launch(&job, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(job.lock().await.handle.is_none());
    }
    #[tokio::test]
    async fn retry_cannot_renew_first_close_deadline() {
        let admission = Admission::new();
        assert!(admission
            .barrier(Instant::now() - Duration::from_secs(1))
            .await
            .is_err());
        assert!(admission
            .barrier(Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
        assert!(admission.closed.load(std::sync::atomic::Ordering::SeqCst));
    }
    fn wire() -> Wire {
        let original:RequestDto=serde_json::from_value(serde_json::json!({"schema":1,"kind":"grant","context":{"protocol_major":2,"target":{"environment_id":"owned","environment_generation":1,"node_id":1,"node_generation":1,"incarnation":"original-worker"},"request_id":1,"operation_id":"original","attempt_id":"attempt","remaining_budget_ms":3000,"traceparent":""},"lease":{"reservation_id":"lease","slot_index":0,"slot_generation":1,"partition_id":1},"tenant_id":1,"registration_generation":1,"server_incarnation":"11111111-1111-1111-1111-111111111111","profile_allocation_id":"profile","request_sha256":format!("{:x}",Sha256::digest(br#"{"schema":1,"memory_mib":128}"#))})).unwrap();
        Wire {
            schema: 1,
            kind: Kind::Start,
            canonical_launch: "{\"schema\":1,\"memory_mib\":128}".into(),
            authority_epoch: 1,
            output_read: None,
            original_sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&original).unwrap())
            ),
            original,
        }
    }
    #[test]
    fn full_original_digest_binds_lease_and_launch() {
        let mut w = wire();
        let worker = w.original.context.target.clone();
        let sdk = w.original.server_incarnation.clone();
        validate(&w, &worker, &sdk).unwrap();
        w.original.lease.slot_generation += 1;
        assert!(validate(&w, &worker, &sdk).is_err());
        let mut w = wire();
        w.canonical_launch = "{\"memory_mib\":128,\"schema\":1}".into();
        assert!(validate(&w, &worker, &sdk).is_err());
        assert!(validate(&wire(), &worker, "22222222-2222-2222-2222-222222222222").is_err());
    }
    #[test]
    fn stop_requires_explicit_version_two_and_start_stays_version_one() {
        let mut w = wire();
        let worker = w.original.context.target.clone();
        let sdk = w.original.server_incarnation.clone();
        w.kind = Kind::Stop;
        assert!(validate(&w, &worker, &sdk).is_err());
        w.schema = 2;
        validate(&w, &worker, &sdk).unwrap();
        w.kind = Kind::Query;
        validate(&w, &worker, &sdk).unwrap();
        w.schema = 1;
        validate(&w, &worker, &sdk).unwrap();
        w.schema = 2;
        w.kind = Kind::Start;
        assert!(validate(&w, &worker, &sdk).is_err());
        w.schema = 3;
        w.kind = Kind::Query;
        assert!(validate(&w, &worker, &sdk).is_err());
    }
    #[tokio::test]
    async fn retained_original_task_error_is_query4_sticky_without_execution() {
        for stage in [
            FailureStage::Gate,
            FailureStage::Reserve,
            FailureStage::PreLaunchDeadline,
            FailureStage::Launch,
        ] {
            let w = wire();
            let state = Arc::new(Mutex::new(State {
                records: vec![Record {
                    original: w.original.clone(),
                    canonical: w.canonical_launch.clone(),
                    epoch: w.authority_epoch,
                    digest: w.original_sha256.clone(),
                    status: Status::Starting,
                    sandbox: None,
                    job: None,
                    admission: Arc::new(Admission::new()),
                    fenced: false,
                    stop_job: None,
                    stop_until: None,
                    execution: None,
                    completion: None,
                    orchestration_failure: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }],
                bytes: FIXED + TICKET,
                closed: false,
            }));
            let (release, gate) = tokio::sync::oneshot::channel();
            let owner = state.clone();
            let task = tokio::spawn(async move {
                // The retained task actually returns an error through its owned
                // gate; no assignment of a fake successful receipt or VM effect.
                let result: Result<()> = async {
                    gate.await?;
                    anyhow::bail!("test retained error")
                }
                .await;
                if result.is_err() {
                    retain_original_failure(&owner, 0, stage);
                }
            });
            let job = Arc::new(tokio::sync::Mutex::new(LaunchJob {
                handle: Some(task),
                failed: false,
            }));
            state.lock().unwrap().records[0].job = Some(job.clone());
            assert!(state.lock().unwrap().records[0]
                .orchestration_failure
                .is_none());
            release.send(()).unwrap();
            join_launch(&job, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();
            {
                let mut state = state.lock().unwrap();
                let r = &mut state.records[0];
                assert_eq!(r.status, Status::Unknown);
                let failure = r.orchestration_failure.as_ref().unwrap();
                assert_eq!(failure.stage, stage);
                let bytes = serde_json::to_vec(failure).unwrap();
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(value["schema_version"], 1);
                assert_eq!(value["kind"], "returned_error");
                assert_eq!(value["retry_forbidden"], true);
                for schema in 1..=3 {
                    assert!(query_failure(schema, r.status, Some(failure)).is_none());
                }
                assert!(query_failure(4, r.status, Some(failure)).is_some());
                assert!(query_failure(4, Status::Ready, Some(failure)).is_none());
                // Same original Stop fence retains failure and charged records.
                r.fenced = true;
                r.admission.close();
                assert!(r.execution.is_none() && r.completion.is_none());
                // Actual failure remains immutable after the raw stopped status
                // projects to Unknown for schema4. This is wire projection, not
                // a claim of physical Stop qualification.
                r.status = Status::ExecutionStopped;
                let projected = project_status(4, r.status, true);
                assert_eq!(projected, Status::Unknown);
                let mut reply = Reply {
                    schema: 4,
                    worker: &r.original.context.target,
                    operation_id: &r.original.context.operation_id,
                    request_sha256: &r.original.request_sha256,
                    server_incarnation: &r.original.server_incarnation,
                    sandbox_id: r.sandbox.as_deref(),
                    status: projected,
                    authority_epoch: r.epoch,
                    original_sha256: &r.digest,
                    execution: None,
                    completion: None,
                    output: None,
                    orchestration_failure: query_failure(
                        4,
                        projected,
                        r.orchestration_failure.as_ref(),
                    ),
                };
                let queried: serde_json::Value =
                    serde_json::from_slice(&serde_json::to_vec(&reply).unwrap()).unwrap();
                assert_eq!(queried["status"], "unknown");
                assert_eq!(queried["orchestration_failure"], value);
                assert!(queried.get("execution").is_none());
                let stopped = ExecutionReceipt {
                    grant_sha256: "a".repeat(64),
                    network_returned: false,
                    persistent_artifacts_retained: true,
                };
                reply.schema = 2;
                reply.status = project_status(2, r.status, true);
                reply.execution = Some(&stopped);
                reply.orchestration_failure =
                    query_failure(2, reply.status, r.orchestration_failure.as_ref());
                let narrow: serde_json::Value =
                    serde_json::from_slice(&serde_json::to_vec(&reply).unwrap()).unwrap();
                assert_eq!(narrow["status"], "execution_stopped");
                assert_eq!(narrow["execution"]["grant_sha256"], "a".repeat(64));
                assert_eq!(narrow["execution"]["persistent_artifacts_retained"], true);
                assert!(narrow.get("orchestration_failure").is_none());
                assert!(query_failure(
                    2,
                    project_status(2, r.status, true),
                    r.orchestration_failure.as_ref()
                )
                .is_none());
                assert!(r.stdout.is_empty() && r.stderr.is_empty());
                assert!(r
                    .job
                    .as_ref()
                    .is_some_and(|retained| Arc::ptr_eq(retained, &job)));
                assert_eq!(state.bytes, FIXED + TICKET);
            }
            retain_original_failure(&state, 0, FailureStage::Launch);
            assert_eq!(
                state.lock().unwrap().records[0]
                    .orchestration_failure
                    .as_ref()
                    .unwrap()
                    .stage,
                stage
            );
            let mut query = wire();
            query.schema = 4;
            query.kind = Kind::Query;
            assert!(validate(
                &query,
                &query.original.context.target,
                &query.original.server_incarnation
            )
            .is_ok());
            for kind in [
                Kind::Start,
                Kind::Stop,
                Kind::ExecutionQuery,
                Kind::ExecutionRead,
            ] {
                query.kind = kind;
                assert!(validate(
                    &query,
                    &query.original.context.target,
                    &query.original.server_incarnation
                )
                .is_err());
            }
        }
    }

    #[test]
    fn legacy_query_after_stop_omits_receipt_and_never_projects_ready() {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum LegacyStatus {
            Starting,
            Ready,
            Unknown,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyReply {
            schema: u32,
            worker: Worker,
            operation_id: String,
            request_sha256: String,
            server_incarnation: String,
            sandbox_id: Option<String>,
            status: LegacyStatus,
            authority_epoch: u64,
            original_sha256: String,
        }
        let w = wire();
        let receipt = ExecutionReceipt {
            grant_sha256: "a".repeat(64),
            network_returned: false,
            persistent_artifacts_retained: true,
        };
        for status in [
            Status::Starting,
            Status::Ready,
            Status::Unknown,
            Status::ExecutionStopped,
        ] {
            let mut reply = Reply {
                schema: 1,
                worker: &w.original.context.target,
                operation_id: &w.original.context.operation_id,
                request_sha256: &w.original.request_sha256,
                server_incarnation: &w.original.server_incarnation,
                sandbox_id: Some("original-sandbox"),
                status: project_status(1, status, true),
                authority_epoch: w.authority_epoch,
                original_sha256: &w.original_sha256,
                execution: None,
                completion: None,
                orchestration_failure: None,
                output: None,
            };
            let raw = serde_json::to_vec(&reply).unwrap();
            let old: LegacyReply = serde_json::from_slice(&raw).unwrap();
            assert!(matches!(old.status, LegacyStatus::Unknown));
            assert_eq!(old.schema, 1);
            assert!(old.worker == w.original.context.target);
            assert_eq!(old.operation_id, w.original.context.operation_id);
            assert_eq!(old.request_sha256, w.original.request_sha256);
            assert_eq!(old.server_incarnation, w.original.server_incarnation);
            assert_eq!(old.sandbox_id.as_deref(), Some("original-sandbox"));
            assert_eq!(old.authority_epoch, w.authority_epoch);
            assert_eq!(old.original_sha256, w.original_sha256);
            reply.schema = 2;
            reply.status = Status::ExecutionStopped;
            reply.execution = Some(&receipt);
            let raw = serde_json::to_vec(&reply).unwrap();
            assert!(serde_json::from_slice::<LegacyReply>(&raw).is_err());
            let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(value["schema"], 2);
            assert_eq!(value["status"], "execution_stopped");
            assert_eq!(value["execution"]["grant_sha256"], receipt.grant_sha256);
        }
        assert_eq!(project_status(1, Status::Ready, false), Status::Ready);
        assert_eq!(
            project_status(2, Status::ExecutionStopped, true),
            Status::ExecutionStopped
        );
    }
    #[test]
    fn wire_rejects_duplicate_or_unknown_authority_fields() {
        assert!(serde_json::from_str::<Wire>("{\"schema\":1,\"schema\":1}").is_err());
        assert!(
            serde_json::from_str::<Launch>("{\"schema\":1,\"memory_mib\":128,\"grant\":{}}")
                .is_err()
        );
    }
}

/// Seed from the SAME installed requester publication; no path can mint it.
pub(crate) struct IngressSeed {
    root: Arc<Publication>,
    endpoint_path: std::path::PathBuf,
    incarnation: String,
}
impl IngressSeed {
    pub(super) fn new(
        root: Arc<Publication>,
        endpoint_path: std::path::PathBuf,
        incarnation: String,
    ) -> Self {
        Self {
            root,
            endpoint_path,
            incarnation,
        }
    }
}
struct TransportJob<T = ()> {
    handle: Option<JoinHandle<Result<T>>>,
    failed: bool,
}
impl<T> TransportJob<T> {
    fn new(handle: JoinHandle<Result<T>>) -> Self {
        Self {
            handle: Some(handle),
            failed: false,
        }
    }
    async fn settle(&mut self, until: Instant) -> Result<()> {
        ensure!(
            !self.failed,
            "original transport task failed; custody retained"
        );
        if let Some(handle) = self.handle.as_mut() {
            let result =
                tokio::time::timeout_at(tokio::time::Instant::from_std(until), handle).await?;
            // Completion consumed the JoinHandle even when its output is Err.
            // Remove it before propagating; a retry must never poll it twice.
            self.handle.take();
            if !matches!(&result, Ok(Ok(_))) {
                self.failed = true;
            }
            result??;
        }
        Ok(())
    }
}
struct SocketCustody {
    root: Arc<Publication>,
    listener: Option<Arc<OwnedFd>>,
    socket_calling: bool,
    socket_pin: Option<std::fs::Metadata>,
    socket_file: Option<std::fs::File>,
    publication_calling: bool,
    publication: Option<std::fs::File>,
    publication_pin: Option<std::fs::Metadata>,
    activation_pin: Option<Arc<Held>>,
}
struct ListenerState {
    stop: std::sync::atomic::AtomicBool,
    resources: Mutex<SocketCustody>,
    ingress: Mutex<Option<Arc<Ingress>>>,
    connections: tokio::sync::Mutex<Vec<Option<TransportJob<ConnectionOutcome>>>>,
    bootstrap: tokio::sync::watch::Sender<Option<bool>>,
}
/// Retains bootstrap, accepted jobs and original namespace/socket custody.
/// Bootstrap failure stays unavailable; no implicit retry or socket adoption.
pub(crate) struct IngressOwner {
    state: Arc<ListenerState>,
    task: tokio::sync::Mutex<TransportJob>,
    activate: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    close_until: OnceLock<Instant>,
    bootstrap_until: Arc<OnceLock<Instant>>,
    provision_until: Instant,
}
struct ListenerDebt {
    _state: Arc<ListenerState>,
    _task: TransportJob,
}
static LISTENER_DEBT: OnceLock<Mutex<Option<ListenerDebt>>> = OnceLock::new();
impl Drop for IngressOwner {
    fn drop(&mut self) {
        self.state
            .stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        *LISTENER_DEBT
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(ListenerDebt {
            _state: self.state.clone(),
            _task: std::mem::replace(
                self.task.get_mut(),
                TransportJob {
                    handle: None,
                    failed: true,
                },
            ),
        });
    }
}
impl IngressOwner {
    /// Start gate is opened only after the Orchestrator owns this object.
    pub(crate) fn prepare<S, F, P>(
        seed: IngressSeed,
        sdk: std::sync::Weak<Orchestrator<S, F, P>>,
    ) -> Result<Arc<Self>>
    where
        S: MetadataStore + 'static,
        F: SandboxBackendFactory + 'static,
        P: SandboxPersister + 'static,
    {
        Self::prepare_inner(seed, sdk, false)
    }
    /// Own a one-shot provisioning task before waiting for actual Service activation.
    pub(crate) fn prepare_provisioned<S, F, P>(
        seed: IngressSeed,
        sdk: std::sync::Weak<Orchestrator<S, F, P>>,
    ) -> Result<Arc<Self>>
    where
        S: MetadataStore + 'static,
        F: SandboxBackendFactory + 'static,
        P: SandboxPersister + 'static,
    {
        Self::prepare_inner(seed, sdk, true)
    }
    fn prepare_inner<S, F, P>(
        seed: IngressSeed,
        sdk: std::sync::Weak<Orchestrator<S, F, P>>,
        provisioned: bool,
    ) -> Result<Arc<Self>>
    where
        S: MetadataStore + 'static,
        F: SandboxBackendFactory + 'static,
        P: SandboxPersister + 'static,
    {
        ensure!(LISTENER_DEBT.get().is_none(), "prior ingress listener debt");
        let mut slots = Vec::new();
        slots.try_reserve_exact(RECORDS)?;
        slots.resize_with(RECORDS, || None);
        let state = Arc::new(ListenerState {
            stop: std::sync::atomic::AtomicBool::new(false),
            resources: Mutex::new(SocketCustody {
                root: seed.root.clone(),
                listener: None,
                socket_calling: false,
                socket_pin: None,
                socket_file: None,
                publication_calling: false,
                publication: None,
                publication_pin: None,
                activation_pin: None,
            }),
            ingress: Mutex::new(None),
            connections: tokio::sync::Mutex::new(slots),
            bootstrap: tokio::sync::watch::channel(None).0,
        });
        let (tx, rx) = tokio::sync::oneshot::channel();
        let retained = state.clone();
        let bootstrap_until = Arc::new(OnceLock::new());
        let provision_until = Instant::now() + Duration::from_secs(30);
        if !provisioned {
            let _ = bootstrap_until.set(Instant::now() + Duration::from_secs(3));
        }
        let task_bootstrap = bootstrap_until.clone();
        let task = tokio::spawn(async move {
            let activated = rx.await;
            if activated.is_err()
                && provisioned
                && retained.stop.load(std::sync::atomic::Ordering::SeqCst)
            {
                retained.bootstrap.send_replace(Some(false));
                return Ok(());
            }
            activated?;
            let result = async {
                let prepared = if provisioned {
                    match wait_activation(&retained, &seed, provision_until).await? {
                        ProvisionOutcome::Activated(ingress) => Some(ingress),
                        ProvisionOutcome::Closed => {
                            retained.bootstrap.send_replace(Some(false));
                            return Ok(());
                        }
                    }
                } else {
                    None
                };
                let until = if provisioned {
                    begin_bootstrap(&task_bootstrap, provision_until, Instant::now())?
                } else {
                    *task_bootstrap
                        .get()
                        .context("original bootstrap deadline absent")?
                };
                retained.bootstrap.send_replace(None);
                run_listener(retained.clone(), seed, sdk, until, prepared).await
            }
            .await;
            if let Err(error) = &result {
                let errno = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .and_then(std::io::Error::raw_os_error);
                tracing::error!(
                    phase = "native_ingress_bootstrap",
                    errno,
                    "native ingress bootstrap refused"
                );
                retained.bootstrap.send_replace(Some(false));
                tracing::error!(
                    phase = "native_ingress_listener",
                    "native ingress remains unavailable with retained custody"
                );
            }
            result
        });
        Ok(Arc::new(Self {
            state,
            task: tokio::sync::Mutex::new(TransportJob::new(task)),
            activate: Mutex::new(Some(tx)),
            close_until: OnceLock::new(),
            bootstrap_until,
            provision_until,
        }))
    }
    pub(crate) fn activate(&self) -> Result<()> {
        self.activate
            .lock()
            .map_err(|_| anyhow::anyhow!("ingress activation poisoned"))?
            .take()
            .context("ingress already activated")?
            .send(())
            .map_err(|_| anyhow::anyhow!("ingress bootstrap unavailable"))
    }
    pub(crate) async fn wait_ready(&self) -> Result<()> {
        let mut ready = self.state.bootstrap.subscribe();
        loop {
            let until = self
                .bootstrap_until
                .get()
                .copied()
                .unwrap_or(self.provision_until);
            ensure!(
                Instant::now() < until,
                "native ingress bootstrap completed late"
            );
            if let Some(value) = *ready.borrow_and_update() {
                ensure!(value, "native ingress bootstrap failed");
                return Ok(());
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(until), ready.changed())
                .await??;
        }
    }
    /// Close listener first, join all actual transport jobs, then dispatch barrier.
    /// Any failure retains all owned resources; successful cleanup only unlinks
    /// these two created names, never requester identity or physical VM artifacts.
    pub(crate) async fn seal(&self, until: Instant) -> Result<()> {
        let until = until.min(*self.close_until.get_or_init(|| until));
        self.state
            .stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // A prepared provision owner may still own the unsent start gate.
        // Releasing it wakes the SAME retained task to observe clean closure.
        if self.bootstrap_until.get().is_none() {
            self.activate
                .lock()
                .map_err(|_| anyhow::anyhow!("ingress activation poisoned"))?
                .take();
        }
        let ingress = self
            .state
            .ingress
            .lock()
            .map_err(|_| anyhow::anyhow!("ingress poisoned"))?
            .clone();
        if let Some(ingress) = &ingress {
            ingress.admission.close();
            ingress
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("ingress poisoned"))?
                .closed = true;
        }
        let mut task =
            tokio::time::timeout_at(tokio::time::Instant::from_std(until), self.task.lock())
                .await?;
        task.settle(until).await?;
        let mut connections = tokio::time::timeout_at(
            tokio::time::Instant::from_std(until),
            self.state.connections.lock(),
        )
        .await?;
        for slot in connections.iter_mut() {
            if let Some(job) = slot.as_mut() {
                job.settle(until).await?;
                slot.take();
            }
        }
        drop(connections);
        if let Some(ingress) = ingress {
            ingress.seal(until).await?;
        }
        retire_socket(&self.state, until)
    }
    pub(crate) async fn fence_original(&self, operation: &str, until: Instant) -> Result<()> {
        let ingress = self
            .state
            .ingress
            .lock()
            .map_err(|_| anyhow::anyhow!("ingress poisoned"))?
            .clone();
        if let Some(ingress) = ingress {
            ingress.fence_original(operation, until).await?;
        }
        Ok(())
    }
}
fn begin_bootstrap(
    clock: &OnceLock<Instant>,
    provision_until: Instant,
    now: Instant,
) -> Result<Instant> {
    ensure!(now < provision_until, "original provision deadline expired");
    let until = now + Duration::from_secs(3);
    clock
        .set(until)
        .map_err(|_| anyhow::anyhow!("bootstrap already activated"))?;
    Ok(until)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    schema: u32,
    server_incarnation: String,
    endpoint_sha256: String,
}
impl Activation {
    fn validate(&self, incarnation: &str, digest: &[u8; 32]) -> Result<()> {
        ensure!(
            self.schema == 1
                && self.server_incarnation == incarnation
                && uuid::Uuid::parse_str(incarnation)?.to_string() == incarnation
                && self.endpoint_sha256
                    == digest
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
            "Service activation binding refused"
        );
        Ok(())
    }
}
enum ProvisionOutcome {
    Activated(Arc<Ingress>),
    Closed,
}
async fn wait_activation(
    state: &Arc<ListenerState>,
    seed: &IngressSeed,
    until: Instant,
) -> Result<ProvisionOutcome> {
    let path = seed.root.root_path.join("worker-activation.json");
    // This is a separate, one-shot provisioning phase. No bootstrap or exchange
    // timer exists yet, and no reservation is issued by this readiness evidence.
    loop {
        ensure!(Instant::now() < until, "Worker provision deadline");
        if state.stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(ProvisionOutcome::Closed);
        }
        seed.root.valid()?;
        match std::fs::symlink_metadata(&path) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let (activation_pin, raw) = Held::load(&path)?;
    let activation: Activation = serde_json::from_slice(&raw)?;
    let activation_pin = Arc::new(activation_pin);
    state
        .resources
        .lock()
        .map_err(|_| anyhow::anyhow!("activation custody poisoned"))?
        .activation_pin = Some(activation_pin.clone());
    let ingress = Arc::new(Ingress::install(
        seed.root.clone(),
        &seed.endpoint_path,
        seed.incarnation.clone(),
    )?);
    *state
        .ingress
        .lock()
        .map_err(|_| anyhow::anyhow!("ingress poisoned"))? = Some(ingress.clone());
    activation.validate(&seed.incarnation, &ingress.endpoint_pin.digest)?;
    ensure!(Instant::now() < until, "late Service activation");
    let fd = socket::socket(
        socket::AddressFamily::Unix,
        socket::SockType::SeqPacket,
        socket::SockFlag::SOCK_NONBLOCK | socket::SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    match socket::connect(
        fd.as_raw_fd(),
        &socket::UnixAddr::new(&ingress.endpoint.socket_path)?,
    ) {
        Ok(()) | Err(nix::errno::Errno::EINPROGRESS) => {}
        Err(error) => return Err(error.into()),
    }
    // Authenticate the real Node without sending Start, Query, or a forged grant.
    // The Service treats this closed empty connection as a refused exchange.
    let peer = validate_peer(&fd, &ingress.endpoint, &seed.root, until)?;
    peer.revalidate(&fd, &ingress.endpoint, &seed.root, until)?;
    *ingress
        .peer
        .lock()
        .map_err(|_| anyhow::anyhow!("ingress peer poisoned"))? = Some(Arc::new(peer));
    activation_pin.verify()?;
    ingress.endpoint_pin.verify()?;
    ensure!(
        Instant::now() < until && !state.stop.load(std::sync::atomic::Ordering::SeqCst),
        "provisioning closed before activation"
    );
    Ok(ProvisionOutcome::Activated(ingress))
}

async fn run_listener<S, F, P>(
    state: Arc<ListenerState>,
    seed: IngressSeed,
    sdk: std::sync::Weak<Orchestrator<S, F, P>>,
    until: Instant,
    prepared: Option<Arc<Ingress>>,
) -> Result<()>
where
    S: MetadataStore + 'static,
    F: SandboxBackendFactory + 'static,
    P: SandboxPersister + 'static,
{
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // SDK publication already exists. Worker may now install its issuer and
    // publish the protected endpoint. No requester mutex is held while waiting.
    loop {
        if state.stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        seed.root.valid()?;
        match std::fs::symlink_metadata(&seed.endpoint_path) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(Instant::now() < until, "Worker endpoint bootstrap deadline");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let ingress = match prepared {
        Some(ingress) => {
            ingress.endpoint_pin.verify()?;
            state
                .resources
                .lock()
                .map_err(|_| anyhow::anyhow!("activation custody poisoned"))?
                .activation_pin
                .as_ref()
                .context("activation custody absent")?
                .verify()?;
            ingress
        }
        None => Arc::new(Ingress::install(
            seed.root.clone(),
            &seed.endpoint_path,
            seed.incarnation.clone(),
        )?),
    };
    *state
        .ingress
        .lock()
        .map_err(|_| anyhow::anyhow!("ingress poisoned"))? = Some(ingress.clone());
    let socket_path = seed.root.root_path.join("native-worker-ingress.sock");
    let address = socket::UnixAddr::new(&socket_path)?; // AF_UNIX bound before bind.
    let listener = {
        let mut custody = state
            .resources
            .lock()
            .map_err(|_| anyhow::anyhow!("ingress custody poisoned"))?;
        custody.root.valid()?;
        ensure!(
            !state.stop.load(std::sync::atomic::Ordering::SeqCst) && Instant::now() < until,
            "bootstrap closed"
        );
        let fd = Arc::new(socket::socket(
            socket::AddressFamily::Unix,
            socket::SockType::SeqPacket,
            socket::SockFlag::SOCK_NONBLOCK | socket::SockFlag::SOCK_CLOEXEC,
            None,
        )?);
        custody.listener = Some(fd.clone());
        custody.socket_calling = true;
        socket::bind(fd.as_raw_fd(), &address)?;
        let pin = std::fs::symlink_metadata(&socket_path)?;
        ensure!(
            pin.mode() & 0o170000 == 0o140000
                && pin.uid() == 0
                && pin.gid() == 0
                && pin.nlink() == 1,
            "created ingress socket capture refused"
        );
        custody.socket_file = Some(std::fs::File::from(
            nix::fcntl::open(
                &socket_path,
                nix::fcntl::OFlag::O_PATH
                    | nix::fcntl::OFlag::O_NOFOLLOW
                    | nix::fcntl::OFlag::O_CLOEXEC,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .context("native ingress socket direct O_PATH open")?,
        ));
        ensure!(
            same(&pin, &custody.socket_file.as_ref().unwrap().metadata()?),
            "created socket FD drift"
        );
        custody.socket_pin = Some(pin);
        custody.root.root_valid()?;
        socket::listen(fd.as_ref(), socket::Backlog::new(32)?)?;
        let sdk = sdk.upgrade().context("original Orchestrator unavailable")?;
        ensure!(
            sdk.native_create_incarnation().to_string() == seed.incarnation,
            "SDK incarnation replaced"
        );
        let (_, _, exe_sha) = super::native_issuer::exe(std::process::id(), until)?;
        let raw = serde_json::to_vec(
            &serde_json::json!({"schema":1,"server_incarnation":seed.incarnation,"peer_pid":std::process::id(),"peer_uid":0,"start_tick":super::native_issuer::tick(std::process::id())?,"exe_sha256":exe_sha,"cgroup_path":super::native_issuer::cgroup(std::process::id())?,"socket_path":socket_path,"socket_device":custody.socket_pin.as_ref().unwrap().dev(),"socket_inode":custody.socket_pin.as_ref().unwrap().ino(),"namespace_device":seed.root.root_pin.dev(),"namespace_inode":seed.root.root_pin.ino(),"worker":ingress.endpoint.worker}),
        )?;
        ensure!(
            raw.len() <= FRAME && Instant::now() < until,
            "ingress publication bounds"
        );
        custody.publication_calling = true;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(seed.root.root_path.join("native-worker-ingress.json"))?;
        custody.publication = Some(file);
        let file = custody.publication.as_mut().unwrap();
        use std::io::Write;
        let initial = file.metadata()?;
        ensure!(
            initial.is_file()
                && initial.uid() == 0
                && initial.gid() == 0
                && initial.nlink() == 1
                && initial.mode() & 0o777 == 0o600,
            "ingress publication owner"
        );
        file.write_all(&raw)?;
        file.sync_all()?;
        custody.publication_pin = Some(file.metadata()?);
        ensure!(
            same(
                custody.publication_pin.as_ref().unwrap(),
                &std::fs::symlink_metadata(seed.root.root_path.join("native-worker-ingress.json"))?
            ),
            "ingress publication replaced"
        );
        custody.root.root.sync_all()?;
        ensure!(Instant::now() < until, "late ingress publication");
        fd
    };
    ensure!(
        Instant::now() < until && !state.stop.load(std::sync::atomic::Ordering::SeqCst),
        "bootstrap closed before readiness"
    );
    state.bootstrap.send_replace(Some(true));
    loop {
        if state.stop.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        {
            let custody = state
                .resources
                .lock()
                .map_err(|_| anyhow::anyhow!("activation custody poisoned"))?;
            if let Some(pin) = &custody.activation_pin {
                pin.verify()?;
            }
        }
        // Every accepted FD has an existing fixed slot; no detached task list.
        let mut slots = state.connections.lock().await;
        for slot in slots.iter_mut() {
            if slot.as_ref().is_some_and(|job| {
                job.failed || job.handle.as_ref().is_some_and(JoinHandle::is_finished)
            }) {
                slot.as_mut()
                    .unwrap()
                    .settle(Instant::now() + Duration::from_secs(3))
                    .await?;
                slot.take();
            }
        }
        let Some(index) = slots.iter().position(Option::is_none) else {
            drop(slots);
            tokio::time::sleep(Duration::from_millis(1)).await;
            continue;
        };
        seed.root.valid()?;
        let fd = match socket::accept4(
            listener.as_raw_fd(),
            socket::SockFlag::SOCK_NONBLOCK | socket::SockFlag::SOCK_CLOEXEC,
        ) {
            Ok(fd) => {
                use std::os::fd::FromRawFd;
                // SAFETY: successful nix accept4 returns a new exclusively owned
                // raw descriptor. It is transferred exactly once into OwnedFd.
                unsafe { OwnedFd::from_raw_fd(fd) }
            }
            Err(nix::errno::Errno::EAGAIN) => {
                drop(slots);
                tokio::time::sleep(Duration::from_millis(1)).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let sdk = sdk.upgrade().context("original Orchestrator unavailable")?;
        let original = ingress.clone();
        let accepted_until = Instant::now() + Duration::from_secs(3);
        let (tx, rx) = tokio::sync::oneshot::channel();
        slots[index] = Some(TransportJob::new(tokio::spawn(async move {
            rx.await?;
            original.serve(fd, sdk, accepted_until).await
        })));
        let _ = tx.send(());
    }
    Ok(())
}
fn retire_socket(state: &ListenerState, until: Instant) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut custody = state
        .resources
        .lock()
        .map_err(|_| anyhow::anyhow!("ingress custody poisoned"))?;
    custody.root.valid()?;
    ensure!(Instant::now() < until, "ingress retirement deadline");
    if custody.publication_calling {
        let pin = custody
            .publication_pin
            .as_ref()
            .context("ingress publication capture debt")?;
        let file = custody
            .publication
            .as_ref()
            .context("ingress publication FD debt")?;
        ensure!(
            same(pin, &file.metadata()?)
                && same(
                    pin,
                    &std::fs::symlink_metadata(
                        custody.root.root_path.join("native-worker-ingress.json")
                    )?
                ),
            "ingress publication replaced"
        );
    }
    if custody.socket_calling {
        let pin = custody
            .socket_pin
            .as_ref()
            .context("ingress socket capture debt")?;
        ensure!(
            same(
                pin,
                &std::fs::symlink_metadata(
                    custody.root.root_path.join("native-worker-ingress.sock")
                )?
            ),
            "ingress socket replaced"
        );
        ensure!(
            custody
                .listener
                .as_ref()
                .is_some_and(|fd| Arc::strong_count(fd) == 1),
            "ingress listener still held"
        );
    }
    // Validate both created entries before first unlink. Partial interruption is
    // retained debt, never pathname retry/adoption or recursive cleanup.
    if custody.publication_calling {
        nix::unistd::unlinkat(
            &custody.root.root,
            "native-worker-ingress.json",
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )?;
        ensure!(
            custody.publication.as_ref().unwrap().metadata()?.nlink() == 0,
            "ingress publication unlink unconfirmed"
        );
        custody.publication.take();
        custody.publication_pin.take();
        custody.publication_calling = false;
    }
    custody.root.root_valid()?;
    ensure!(Instant::now() < until, "socket retirement deadline");
    if custody.socket_calling {
        let pin = custody.socket_pin.as_ref().context("socket capture debt")?;
        ensure!(
            same(
                pin,
                &custody
                    .socket_file
                    .as_ref()
                    .context("socket FD debt")?
                    .metadata()?
            ) && same(
                pin,
                &std::fs::symlink_metadata(
                    custody.root.root_path.join("native-worker-ingress.sock")
                )?
            ),
            "socket changed before unlink"
        );
        nix::unistd::unlinkat(
            &custody.root.root,
            "native-worker-ingress.sock",
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )?;
        ensure!(
            custody.socket_file.as_ref().unwrap().metadata()?.nlink() == 0
                && !custody
                    .root
                    .root_path
                    .join("native-worker-ingress.sock")
                    .try_exists()?,
            "socket unlink unconfirmed"
        );
        custody.listener.take();
        custody.socket_file.take();
        custody.socket_pin.take();
        custody.socket_calling = false;
    }
    custody.root.root.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod transport_settlement_tests {
    use super::*;
    #[tokio::test]
    async fn retained_stop_job_survives_cancelled_waiter_and_concurrent_joins() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(tokio::sync::Notify::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let handle = {
            let calls = calls.clone();
            let done = done.clone();
            let entered = entered.clone();
            tokio::spawn(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                entered.notify_one();
                done.notified().await;
            })
        };
        let job = Arc::new(tokio::sync::Mutex::new(LaunchJob {
            handle: Some(handle),
            failed: false,
        }));
        entered.notified().await;
        let first_until = Instant::now() + Duration::from_secs(1);
        let waiter = {
            let job = job.clone();
            tokio::spawn(async move { join_launch(&job, first_until).await })
        };
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(job.lock().await.handle.is_some());
        let a = {
            let job = job.clone();
            tokio::spawn(async move { join_launch(&job, first_until).await })
        };
        let b = {
            let job = job.clone();
            tokio::spawn(async move { join_launch(&job, first_until).await })
        };
        done.notify_one();
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(job.lock().await.handle.is_none());
        // This tests actual task custody, not a physical execution-stop token.
    }

    #[tokio::test]
    async fn expired_stop_observation_keeps_original_job_without_replacement() {
        let done = Arc::new(tokio::sync::Notify::new());
        let handle = {
            let done = done.clone();
            tokio::spawn(async move {
                done.notified().await;
            })
        };
        let job = Arc::new(tokio::sync::Mutex::new(LaunchJob {
            handle: Some(handle),
            failed: false,
        }));
        let original_until = Instant::now();
        assert!(join_launch(&job, original_until).await.is_err());
        assert!(job.lock().await.handle.is_some());
        assert!(join_launch(&job, original_until).await.is_err());
        done.notify_one();
        // Cleanup of the test's actual task, not a renewed production deadline.
        let handle = job.lock().await.handle.take().unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn expected_refusal_consumes_actual_job_without_sticky_failure() {
        // Real accepted-job settlement for both missing-original admission
        // outcomes; this is not an authenticated socket qualification.
        assert!(missing_original_outcome(Kind::Start).is_none());
        for kind in [Kind::Query, Kind::Stop] {
            let until = Instant::now() + Duration::from_secs(1);
            let mut job = TransportJob::new(tokio::spawn(async move {
                Ok(missing_original_outcome(kind).unwrap())
            }));
            job.settle(until).await.unwrap();
            assert!(job.handle.is_none() && !job.failed);
            job.settle(until).await.unwrap();
            assert!(job.handle.is_none() && !job.failed);
        }
    }
    #[tokio::test]
    async fn failed_accepted_task_is_sticky_across_repeated_seal_join() {
        let until = Instant::now() + Duration::from_secs(1);
        let mut job = TransportJob::<ConnectionOutcome>::new(tokio::spawn(async {
            anyhow::bail!("actual accepted task failure")
        }));
        assert!(job.settle(until).await.is_err());
        assert!(job.handle.is_none() && job.failed);
        assert!(job.settle(until).await.is_err());
        assert!(job.handle.is_none() && job.failed);
    }
    #[test]
    fn activation_rejects_stale_incarnation_endpoint_drift_and_unknown_schema() {
        let incarnation = "01900000-0000-7000-8000-000000000001";
        let digest = [7u8; 32];
        let mut activation = Activation {
            schema: 1,
            server_incarnation: incarnation.into(),
            endpoint_sha256: "07".repeat(32),
        };
        activation.validate(incarnation, &digest).unwrap();
        assert!(activation
            .validate("01900000-0000-7000-8000-000000000002", &digest)
            .is_err());
        assert!(activation.validate(incarnation, &[8; 32]).is_err());
        activation.schema = 2;
        assert!(activation.validate(incarnation, &digest).is_err());
        assert!(serde_json::from_str::<Activation>(
            r#"{"schema":1,"server_incarnation":"fake","endpoint_sha256":"bad","grant":{}}"#
        )
        .is_err());
        activation.schema = 1;
        activation.server_incarnation = "fake".into();
        assert!(activation.validate("fake", &digest).is_err());
    }

    #[tokio::test]
    async fn cancelled_provision_observer_keeps_the_same_retained_job() {
        let (send, receive) = tokio::sync::oneshot::channel();
        let original = Arc::new(tokio::sync::Mutex::new(TransportJob::new(tokio::spawn(
            async move {
                receive.await?;
                Ok(())
            },
        ))));
        let retained = original.clone();
        let waiter = tokio::spawn(async move {
            retained
                .lock()
                .await
                .settle(Instant::now() + Duration::from_secs(3))
                .await
        });
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(original.lock().await.handle.is_some());
        send.send(()).unwrap();
        original
            .lock()
            .await
            .settle(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(original.lock().await.handle.is_none());
    }
    #[test]
    fn slow_import_has_separate_bounded_prepare_and_unchanged_one_shot_bootstrap() {
        let prepared_at = Instant::now();
        let provision_until = prepared_at + Duration::from_secs(30);
        let import_finished = prepared_at + Duration::from_secs(13);
        let clock = OnceLock::new();
        let until = begin_bootstrap(&clock, provision_until, import_finished).unwrap();
        assert_eq!(
            until.duration_since(import_finished),
            Duration::from_secs(3)
        );
        assert!(begin_bootstrap(
            &clock,
            provision_until,
            import_finished + Duration::from_secs(1)
        )
        .is_err());
        assert_eq!(clock.get().copied(), Some(until));
        let expired = OnceLock::new();
        assert!(begin_bootstrap(&expired, provision_until, provision_until).is_err());
        assert!(expired.get().is_none());
    }
    #[tokio::test]
    async fn actual_provision_owner_seal_before_receipt_joins_cleanly_without_bootstrap() {
        // No authority is minted: these real retained filesystem descriptors
        // exercise cancellation before receipt validation or listener effects.
        let directory = tempfile::tempdir().unwrap();
        let root_path = directory.path().to_path_buf();
        let root = std::fs::File::open(&root_path).unwrap();
        let file = std::fs::File::create(root_path.join("requester-identity.json")).unwrap();
        let publication = Arc::new(Publication {
            state: Some(super::super::native_issuer::PublicationState {
                root_pin: root.metadata().unwrap(),
                root,
                root_path: root_path.clone(),
                pin: Some(file.metadata().unwrap()),
                file: Some(file),
            }),
        });
        let seed = IngressSeed::new(
            publication.clone(),
            root_path.join("worker-endpoint.json"),
            "01900000-0000-7000-8000-000000000001".into(),
        );
        let owner = IngressOwner::prepare_provisioned(seed, std::sync::Weak::<Orchestrator>::new())
            .unwrap();
        owner.activate().unwrap();
        tokio::task::yield_now().await;
        assert!(!owner
            .task
            .lock()
            .await
            .handle
            .as_ref()
            .unwrap()
            .is_finished());
        assert!(owner.bootstrap_until.get().is_none());
        let until = Instant::now() + Duration::from_secs(1);
        owner.seal(until).await.unwrap();
        owner.seal(until).await.unwrap();
        let task = owner.task.lock().await;
        assert!(task.handle.is_none() && !task.failed);
        drop(task);
        assert!(owner.bootstrap_until.get().is_none());
        assert!(owner.wait_ready().await.is_err());
        assert!(owner.state.ingress.lock().unwrap().is_none());
        let custody = owner.state.resources.lock().unwrap();
        assert!(custody.listener.is_none() && custody.activation_pin.is_none());
        assert!(!custody.socket_calling && !custody.publication_calling);
        drop(custody);
        assert!(!root_path.join("native-worker-ingress.sock").exists());
        assert!(!root_path.join("native-worker-ingress.json").exists());
        assert!(publication.valid().is_ok());
    }
}
