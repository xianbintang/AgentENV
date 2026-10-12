//! Bounded custody of commands sent to the authenticated native broker.
use super::native_metadata::{MetadataCache, NativeMetadataReceipt};
use super::process::{ProcessOpts, ProcessOutput};
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, Notify},
};
const LINE: usize = 65536;
const OUTPUT: usize = 4 * 1024 * 1024;
#[derive(Clone, Debug)]
pub struct NativeIdentity {
    pub session_id: String,
    pub operation_id: String,
}
/// Authenticated broker truth for the original operation; never a VM absence proof.
#[derive(Clone, Debug)]
pub struct NativeStatus {
    pub identity: NativeIdentity,
    pub state: String,
    pub exit_code: Option<i32>,
    pub stdout_bytes: Option<u64>,
    pub stderr_bytes: Option<u64>,
    pub process_absent: bool,
    pub acked_sequence: u64,
    pub terminal: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    kind: String,
    session_id: String,
    operation_id: String,
    payload: Value,
}
#[derive(Clone, Copy)]
enum StatusTruthKind {
    Status,
    Terminal,
}
/// Authenticated HTTP caller partition; never a guest credential or caller-chosen UUID.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NativeCallerKey {
    pub(crate) api_key_sha256: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) operation_id: String,
}
/// An existing keyed actor owner; pending backing has an identity but no file result.
pub(crate) enum NativeKeyedHandle {
    Exec(NativeHandle),
    File(NativeFileHandle),
    Metadata(NativeMetadataHandle),
    Upload(NativeUploadHandle),
    Download(NativeDownloadHandle),
    Pending(NativeIdentity),
}
struct CallerRecord {
    key: NativeCallerKey,
    fingerprint: [u8; 32],
}
#[derive(Clone, Copy)]
struct MetadataPhase {
    token: u64,
    until: Instant,
    prior: (u64, u64),
    cursor: Option<u64>,
    queued: bool,
    written: bool,
    waiters: u8,
}
#[derive(Clone, Copy)]
enum MetadataResponse {
    Receipt,
    Page(u64),
}
struct MetadataPhaseLease {
    client: Arc<NativeClient>,
    id: String,
    phase: MetadataPhase,
}
impl Drop for MetadataPhaseLease {
    fn drop(&mut self) {
        let mut state = self.client.state.lock().expect("native state");
        let r = state.records.get_mut(&self.id).expect("retained metadata");
        let slot = if self.phase.cursor.is_some() {
            &mut r.metadata_next
        } else {
            &mut r.metadata_query
        };
        if let Some(p) = slot.as_mut().filter(|p| p.token == self.phase.token) {
            p.waiters -= 1;
            if p.waiters == 0 {
                if p.queued {
                    r.unknown = true;
                    r.truth_revision += 1;
                    r.notify.notify_waiters();
                } else {
                    *slot = None;
                }
            }
        }
    }
}
struct Record {
    caller: Option<CallerRecord>,
    backing_pending: bool,
    backing_failed: bool,
    backing_cancelled: Option<Arc<Mutex<bool>>>,
    kind: String,
    upload: Option<UploadRecord>,
    download: Option<DownloadRecord>,
    file_result: Option<NativeFileOutcome>,
    metadata: Option<MetadataCache>,
    file_truth_revision: u64,
    metadata_truth_revision: u64,
    metadata_next: Option<MetadataPhase>,
    metadata_query: Option<MetadataPhase>,
    metadata_phase_serial: u64,
    metadata_completed_next: u64,
    metadata_completed_query: u64,
    metadata_response: Option<MetadataResponse>,
    dispatched: bool,
    _request: Value,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    chunks: Vec<(String, usize, [u8; 32])>,
    terminal: Option<Value>,
    unknown: bool,
    aborted: bool,
    cancel_intent: bool,
    acked: usize,
    ack_sent: usize,
    truth_revision: u64,
    status_truth_revision: u64,
    status_truth_kind: Option<StatusTruthKind>,
    status: Option<Value>,
    notify: Arc<Notify>,
}
struct State {
    caller_epoch: Option<u64>,
    caller_admission_closed: bool,
    records: HashMap<String, Record>,
    bytes: usize,
    chunks: usize,
    lifetime_admissions: usize,
}
/// Public identity contributes exact additional bytes to an ordinary signed
/// guest frame. This is sizing only; the captured broker owns all authentication.
#[derive(Clone, Copy)]
pub(crate) struct NativeFraming {
    signed_delta: usize,
}
impl NativeFraming {
    pub(crate) fn new(node: &str, owner: &str, generation: u64, nonce: &str) -> Result<Self> {
        let identifier = |text: &str| {
            !text.is_empty()
                && text.len() <= 64
                && text.as_bytes()[0].is_ascii_alphanumeric()
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        };
        if !identifier(node)
            || !identifier(owner)
            || !(1..1u64 << 63).contains(&generation)
            || nonce.len() != 64
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("native framing identity refused");
        }
        let additions = json!({"schema":2,"node_id":node,"owner_id":owner,"generation":generation,"guest_nonce":nonce,"auth_tag":"0".repeat(64)});
        // Joining two nonempty JSON objects replaces two braces with one comma.
        Ok(Self {
            signed_delta: serde_json::to_vec(&additions)?.len() - 1,
        })
    }
}
#[cfg(test)]
fn minimum_framing() -> NativeFraming {
    NativeFraming::new("n", "o", 1, &"a".repeat(64)).unwrap()
}

pub(crate) struct NativeClient {
    session: String,
    artifact_policy: Option<(String, bool)>,
    state: Mutex<State>,
    ready: AtomicBool,
    tx: mpsc::Sender<Envelope>,
    framing: NativeFraming,
    expires: Instant,
    _download_spool: Option<Arc<super::native_download::NativeDownloadSpool>>,
    download_admissions: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
/// Authenticated retained chunk truth, not whole-file replacement or VM absence.
#[derive(Clone)]
pub struct NativeFileOutcome {
    pub identity: NativeIdentity,
    pub path: String,
    pub offset: u64,
    pub data: Vec<u8>,
    pub sha256: String,
}
/// Original bounded file operation with retained result and query custody.
pub struct NativeFileHandle {
    client: Arc<NativeClient>,
    identity: NativeIdentity,
}
const UPLOAD_RECEIPTS: usize = 2048 * 64;
struct UploadRecord {
    progress: Option<NativeUploadProgress>,
    result: Option<NativeUploadOutcome>,
    receipts: Vec<([u8; 32], u64)>,
    confirmed: usize,
    sent_chunks: usize,
    commit_sent: bool,
    observed: bool,
    commit: Option<[u8; 32]>,
    revision: u64,
    cancelled: bool,
    stream_started: bool,
    stream_leased: bool,
}
/// Authenticated prefix for one original upload, not a whole-file completion.
#[derive(Clone)]
pub struct NativeUploadProgress {
    pub identity: NativeIdentity,
    pub received: u64,
    pub next_sequence: u64,
}
/// Whole-file authenticated receipt. Interrupted in-place uploads may leave partial bytes.
#[derive(Clone)]
pub struct NativeUploadOutcome {
    pub identity: NativeIdentity,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}
/// Authenticated observation of an original upload, including its immutable final receipt.
#[derive(Clone)]
pub enum NativeUploadObservation {
    Progress(NativeUploadProgress),
    Complete(NativeUploadOutcome),
}
/// One declared upload identity across begin, contiguous chunks and commit.
pub struct NativeUploadHandle {
    client: Arc<NativeClient>,
    identity: NativeIdentity,
}
struct UploadStreamLease {
    client: Arc<NativeClient>,
    operation_id: String,
    finished: bool,
}
impl Drop for UploadStreamLease {
    fn drop(&mut self) {
        let mut state = self.client.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&self.operation_id)
            .expect("retained upload");
        let upload = record.upload.as_mut().expect("upload record");
        upload.stream_leased = false;
        if !self.finished && upload.result.is_none() {
            upload.observed = false;
            record.unknown = true;
            record.truth_revision += 1;
            record.notify.notify_waiters();
        }
    }
}
const DOWNLOAD_RECEIPTS: usize = 192 * 1024;
struct DownloadAdmissionGuard(Arc<Mutex<bool>>);
impl Drop for DownloadAdmissionGuard {
    fn drop(&mut self) {
        *self.0.lock().expect("download admission") = true;
    }
}
struct DownloadRecord {
    spool: Arc<super::native_download::NativeSpoolFile>,
    progress: Option<NativeDownloadProgress>,
    result: Option<NativeDownloadOutcome>,
    receipts: Vec<[u8; 32]>,
    rolling: Sha256,
    requested: usize,
    retained: usize,
    guest_retained: usize,
    revision: u64,
    observed: bool,
    receiving: bool,
    receive_started: bool,
    public_receive_registered: bool,
    latest_result: bool,
    hashed_bytes: u64,
    pending_next: Option<(usize, [u8; 32], bool)>,
    pending_retain: Option<(usize, [u8; 32], bool)>,
}
impl DownloadRecord {
    fn new(spool: Arc<super::native_download::NativeSpoolFile>, receipts: Vec<[u8; 32]>) -> Self {
        Self {
            spool,
            progress: None,
            result: None,
            receipts,
            rolling: Sha256::new(),
            requested: 0,
            retained: 0,
            guest_retained: 0,
            revision: 0,
            observed: false,
            receiving: false,
            receive_started: false,
            public_receive_registered: false,
            latest_result: false,
            hashed_bytes: 0,
            pending_next: None,
            pending_retain: None,
        }
    }
}
#[derive(Clone)]
pub struct NativeDownloadProgress {
    pub identity: NativeIdentity,
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub preparing: bool,
    pub next_sequence: u64,
    pub retained_sequence: u64,
}
/// Whole-file receipt plus the exact protected host file. This is not VM absence.
#[derive(Clone)]
pub struct NativeDownloadOutcome {
    pub identity: NativeIdentity,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    spool: Arc<super::native_download::NativeSpoolFile>,
}
impl NativeDownloadOutcome {
    pub fn open_read(&self) -> Result<super::native_download::NativeDownloadReader> {
        self.spool
            .open_read()
            .map_err(|e| anyhow::anyhow!("native download published file {:?}", e))
    }
}
pub struct NativeDownloadHandle {
    client: Arc<NativeClient>,
    identity: NativeIdentity,
}
struct DownloadReceiveGuard {
    client: Arc<NativeClient>,
    id: String,
    complete: bool,
}
impl Drop for DownloadReceiveGuard {
    fn drop(&mut self) {
        let mut state = self.client.state.lock().expect("native state");
        let record = state.records.get_mut(&self.id).expect("retained download");
        let download = record.download.as_mut().expect("download record");
        download.receiving = false;
        if !self.complete && download.result.is_none() {
            download.observed = false;
            record.unknown = true;
            record.notify.notify_waiters();
        }
    }
}
impl NativeDownloadHandle {
    pub fn identity(&self) -> &NativeIdentity {
        &self.identity
    }
    pub async fn cancel(&self) -> Result<()> {
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("cancel")
        .await
    }
    pub(crate) async fn query_any(
        &self,
    ) -> Result<(
        Option<NativeDownloadProgress>,
        Option<NativeDownloadOutcome>,
    )> {
        let baseline = self.client.state.lock().expect("native state").records
            [&self.identity.operation_id]
            .download
            .as_ref()
            .expect("download record")
            .revision;
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("query")
        .await?;
        self.observe(Some(baseline)).await
    }
    pub async fn query_progress(&self) -> Result<NativeDownloadProgress> {
        let baseline = {
            let state = self.client.state.lock().expect("native state");
            state.records[&self.identity.operation_id]
                .download
                .as_ref()
                .expect("download record")
                .revision
        };
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("query")
        .await?;
        self.observe(Some(baseline))
            .await?
            .0
            .ok_or_else(|| anyhow::anyhow!("native download complete; query result"))
    }
    pub async fn query_result(&self) -> Result<NativeDownloadOutcome> {
        let baseline = {
            let state = self.client.state.lock().expect("native state");
            state.records[&self.identity.operation_id]
                .download
                .as_ref()
                .expect("download record")
                .revision
        };
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("query")
        .await?;
        self.observe(Some(baseline))
            .await?
            .1
            .ok_or_else(|| anyhow::anyhow!("native download pending; original identity retained"))
    }
    async fn observe(
        &self,
        baseline: Option<u64>,
    ) -> Result<(
        Option<NativeDownloadProgress>,
        Option<NativeDownloadOutcome>,
    )> {
        tokio::time::timeout_at(tokio::time::Instant::from_std(self.client.expires), async {
            loop {
                let notify = {
                    let state = self.client.state.lock().expect("native state");
                    state.records[&self.identity.operation_id].notify.clone()
                };
                let changed = notify.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let state = self.client.state.lock().expect("native state");
                    let record = &state.records[&self.identity.operation_id];
                    let download = record.download.as_ref().expect("download record");
                    if baseline.is_none_or(|old| download.revision > old) {
                        if record.unknown || record.aborted {
                            bail!(
                                "native download {} UNKNOWN; query original identity",
                                self.identity.operation_id
                            );
                        }
                        if baseline.is_none() || download.latest_result {
                            if let Some(result) = &download.result {
                                return Ok((None, Some(result.clone())));
                            }
                        }
                        if download.observed {
                            if let Some(progress) = &download.progress {
                                return Ok((Some(progress.clone()), None));
                            }
                        }
                    }
                    if !self.client.is_ready() {
                        bail!(
                            "native download {} transport UNKNOWN",
                            self.identity.operation_id
                        );
                    }
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "native download {} incarnation deadline",
                self.identity.operation_id
            )
        })?
    }
    /// One-use sequential receive. An uncertain phase requires explicit query;
    /// it is never restarted by resending Begin, Next, or Retain.
    pub async fn receive(&self) -> Result<NativeDownloadOutcome> {
        {
            let mut state = self.client.state.lock().expect("native state");
            let download = state
                .records
                .get_mut(&self.identity.operation_id)
                .expect("retained download")
                .download
                .as_mut()
                .expect("download record");
            if download.receive_started {
                bail!("native download receive already used");
            }
            download.receive_started = true;
            download.receiving = true;
        }
        let mut guard = DownloadReceiveGuard {
            client: self.client.clone(),
            id: self.identity.operation_id.clone(),
            complete: false,
        };
        loop {
            let (progress, result) = self.observe(None).await?;
            if let Some(result) = result {
                guard.complete = true;
                return Ok(result);
            }
            let progress = progress.expect("download progress");
            let baseline = {
                let state = self.client.state.lock().expect("native state");
                state.records[&self.identity.operation_id]
                    .download
                    .as_ref()
                    .expect("download record")
                    .revision
            };
            if !progress.preparing {
                let mut state = self.client.state.lock().expect("native state");
                if state.caller_admission_closed {
                    bail!("native caller admission closed");
                }
                let record = state
                    .records
                    .get_mut(&self.identity.operation_id)
                    .expect("retained download");
                if record.unknown || record.cancel_intent {
                    bail!(
                        "native download {} uncertain receive",
                        self.identity.operation_id
                    );
                }
                let download = record.download.as_mut().expect("download record");
                let count = progress.size.div_ceil(16384) as usize;
                let request = if count == 0 && download.pending_retain.is_none() {
                    Some(Envelope {
                        kind: "download_retain".into(),
                        session_id: self.identity.session_id.clone(),
                        operation_id: self.identity.operation_id.clone(),
                        payload: json!({"next_sequence":0}),
                    })
                } else if download.requested < count
                    && download.requested == download.retained
                    && download.requested == download.guest_retained
                    && download
                        .pending_next
                        .as_ref()
                        .is_none_or(|pending| pending.0 < download.requested)
                {
                    Some(Envelope {
                        kind: "download_next".into(),
                        session_id: self.identity.session_id.clone(),
                        operation_id: self.identity.operation_id.clone(),
                        payload: json!({"sequence":download.requested}),
                    })
                } else {
                    None
                };
                if let Some(request) = request {
                    let fingerprint = checked_frame_fingerprint(&request, self.client.framing)?;
                    if request.kind == "download_next" {
                        download.pending_next = Some((download.requested, fingerprint, false));
                    } else {
                        download.pending_retain = Some((0, fingerprint, false));
                    }
                    download.observed = false;
                    if self.client.tx.try_send(request).is_err() {
                        record.unknown = true;
                        bail!(
                            "native download {} advancement unavailable",
                            self.identity.operation_id
                        );
                    }
                }
            }
            // A pending phase needs a new authenticated observation; no local
            // revision, cancellation or cached progress can advance it.
            let (_, result) = self.observe(Some(baseline)).await?;
            if let Some(result) = result {
                guard.complete = true;
                return Ok(result);
            }
        }
    }
}
fn mark_download_advance(client: &NativeClient, frame: &Envelope) -> Result<bool> {
    let mut state = client.state.lock().expect("native state");
    if state.caller_admission_closed {
        if let Some(record) = state.records.get_mut(&frame.operation_id) {
            record.unknown = true;
            record.notify.notify_waiters();
        }
        return Ok(false);
    }
    let record = state
        .records
        .get_mut(&frame.operation_id)
        .ok_or_else(|| anyhow::anyhow!("native download missing intent"))?;
    if record.unknown || record.cancel_intent || record.aborted {
        return Ok(false);
    }
    let download = record
        .download
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("native download kind"))?;
    let fingerprint = checked_frame_fingerprint(frame, client.framing)?;
    let pending = if frame.kind == "download_next" {
        download.pending_next.as_mut()
    } else {
        download.pending_retain.as_mut()
    }
    .ok_or_else(|| anyhow::anyhow!("native download unreserved phase"))?;
    if pending.1 != fingerprint || pending.2 {
        bail!("native download phase replay refused");
    }
    pending.2 = true;
    if frame.kind == "download_next" {
        download.requested += 1;
    }
    Ok(true)
}
fn download_payload<'a>(
    event: &'a Envelope,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let payload = event
        .payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("native download payload"))?;
    if payload.len() != fields.len() || fields.iter().any(|field| !payload.contains_key(*field)) {
        bail!("native download closed payload");
    }
    Ok(payload)
}
async fn retain_download_event(
    client: &Arc<NativeClient>,
    event: &Envelope,
) -> Result<Option<Envelope>> {
    let preparing = event.kind == "download_progress" && event.payload["phase"] == "preparing";
    let fields: &[&str] = match event.kind.as_str() {
        "download_progress" if preparing => &["path", "phase", "size", "hashed_bytes"],
        "download_progress" => &[
            "path",
            "phase",
            "size",
            "sha256",
            "next_sequence",
            "retained_sequence",
        ],
        "download_chunk" => &[
            "path",
            "size",
            "sha256",
            "sequence",
            "offset",
            "data",
            "chunk_sha256",
        ],
        "download_result" => &["path", "size", "sha256", "retained_sequence"],
        _ => bail!("native download event"),
    };
    let p = download_payload(event, fields)?;
    let size = p["size"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("native download size"))?;
    let (spool, data, sequence, digest) = {
        let mut state = client.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&event.operation_id)
            .ok_or_else(|| anyhow::anyhow!("native download identity"))?;
        if record.kind != "download_begin"
            || p["path"] != record._request["path"]
            || size
                > record._request["max_bytes"]
                    .as_u64()
                    .expect("download bound")
        {
            bail!("native download source bounds");
        }
        let download = record.download.as_mut().expect("download record");
        if download
            .progress
            .as_ref()
            .is_some_and(|old| old.size != size)
        {
            bail!("native download source changed");
        }
        if preparing {
            let hashed = p["hashed_bytes"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("native download preparing prefix"))?;
            if hashed > size
                || hashed < download.hashed_bytes
                || download.progress.as_ref().is_some_and(|old| !old.preparing)
            {
                bail!("native download preparing conflict");
            }
            download.hashed_bytes = hashed;
            download.latest_result = false;
            download.progress = Some(NativeDownloadProgress {
                identity: NativeIdentity {
                    session_id: event.session_id.clone(),
                    operation_id: event.operation_id.clone(),
                },
                path: p["path"].as_str().expect("request path").into(),
                size,
                sha256: None,
                preparing: true,
                next_sequence: 0,
                retained_sequence: 0,
            });
            download.observed = true;
            download.revision += 1;
            record.unknown = false;
            record.notify.notify_waiters();
            return Ok(None);
        }
        let sha = p["sha256"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("native download hash"))?;
        if sha.len() != 64
            || !sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || download
                .progress
                .as_ref()
                .and_then(|old| old.sha256.as_deref())
                .is_some_and(|old| old != sha)
        {
            bail!("native download source hash changed");
        }
        let count = size.div_ceil(16384) as usize;
        if event.kind == "download_progress" {
            let next = usize::try_from(
                p["next_sequence"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("native download next"))?,
            )?;
            let retained = usize::try_from(
                p["retained_sequence"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("native download retained"))?,
            )?;
            if p["phase"] != "streaming"
                || next != download.receipts.len()
                || next > download.requested
                || retained < download.guest_retained
                || retained > download.retained
                || next > count
                || retained > next
                || next - retained > 1
            {
                bail!("native download prefix conflict");
            }
            download.guest_retained = retained;
            download.latest_result = false;
            download.progress = Some(NativeDownloadProgress {
                identity: NativeIdentity {
                    session_id: event.session_id.clone(),
                    operation_id: event.operation_id.clone(),
                },
                path: p["path"].as_str().expect("request path").into(),
                size,
                sha256: Some(sha.into()),
                preparing: false,
                next_sequence: next as u64,
                retained_sequence: retained as u64,
            });
            download.observed = true;
            download.revision += 1;
            record.unknown = false;
            record.notify.notify_waiters();
            return Ok(None);
        }
        if download
            .progress
            .as_ref()
            .is_none_or(|old| old.preparing || old.sha256.is_none())
        {
            bail!("native download source unobserved");
        }
        if event.kind == "download_result" {
            let retained = p["retained_sequence"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("native download result prefix"))?;
            if retained != count as u64
                || download.retained != count
                || download.receipts.len() != count
                || download.requested != count
                || download
                    .pending_retain
                    .as_ref()
                    .is_none_or(|pending| pending.0 != count || !pending.2)
                || format!("{:x}", download.rolling.clone().finalize()) != sha
            {
                bail!("native download final receipt incomplete");
            }
            if let Some(result) = &download.result {
                if result.size != size || result.sha256 != sha {
                    bail!("native download final conflict");
                }
                download.latest_result = true;
                download.revision += 1;
                record.unknown = false;
                record.notify.notify_waiters();
                return Ok(None);
            }
            (download.spool.clone(), None, count, [0; 32])
        } else {
            let sequence = usize::try_from(
                p["sequence"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("native download sequence"))?,
            )?;
            let offset = p["offset"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("native download offset"))?;
            let encoded = p["data"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("native download data"))?;
            let data = STANDARD.decode(encoded)?;
            let digest: [u8; 32] = Sha256::digest(&data).into();
            if STANDARD.encode(&data) != encoded
                || sequence >= count
                || offset != sequence as u64 * 16384
                || data.len() as u64 != (size - offset).min(16384)
                || p["chunk_sha256"] != format!("{:x}", Sha256::digest(&data))
            {
                bail!("native download chunk bounds");
            }
            if let Some(old) = download.receipts.get(sequence) {
                if *old != digest {
                    bail!("native download chunk drift");
                }
                return Ok(None);
            }
            if sequence != download.retained
                || sequence + 1 != download.requested
                || sequence != download.receipts.len()
                || download
                    .pending_next
                    .as_ref()
                    .is_none_or(|pending| pending.0 != sequence || !pending.2)
            {
                bail!("native download unrequested chunk");
            }
            (download.spool.clone(), Some(data), sequence, digest)
        }
    };
    if let Some(data) = data {
        let next_hash = {
            let state = client.state.lock().expect("native state");
            let mut hash = state.records[&event.operation_id]
                .download
                .as_ref()
                .expect("download record")
                .rolling
                .clone();
            hash.update(&data);
            hash
        };
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(client.expires),
            spool.write_chunk(sequence as u64 * 16384, data),
        )
        .await
        .map_err(|_| anyhow::anyhow!("native download write deadline"))?
        .map_err(|e| anyhow::anyhow!("native download write {:?}", e))?;
        if Instant::now() >= client.expires {
            bail!("native download write expired");
        }
        let ack = Envelope {
            kind: "download_retain".into(),
            session_id: event.session_id.clone(),
            operation_id: event.operation_id.clone(),
            payload: json!({"next_sequence":sequence+1}),
        };
        let fingerprint = checked_frame_fingerprint(&ack, client.framing)?;
        let mut state = client.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&event.operation_id)
            .expect("retained download");
        let download = record.download.as_mut().expect("download record");
        download.rolling = next_hash;
        download.receipts.push(digest);
        download.retained += 1;
        download.pending_retain = Some((sequence + 1, fingerprint, false));
        download.observed = false;
        record.notify.notify_waiters();
        Ok(Some(ack))
    } else {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(client.expires),
            spool.seal(
                size,
                p["sha256"].as_str().expect("validated hash"),
                client.expires,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("native download seal deadline"))?
        .map_err(|e| anyhow::anyhow!("native download seal {:?}", e))?;
        if Instant::now() >= client.expires {
            bail!("native download publish expired");
        }
        let mut state = client.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&event.operation_id)
            .expect("retained download");
        let download = record.download.as_mut().expect("download record");
        download.result = Some(NativeDownloadOutcome {
            identity: NativeIdentity {
                session_id: event.session_id.clone(),
                operation_id: event.operation_id.clone(),
            },
            path: p["path"].as_str().expect("request path").into(),
            size,
            sha256: p["sha256"].as_str().expect("validated hash").into(),
            spool,
        });
        download.latest_result = true;
        download.revision += 1;
        download.observed = true;
        record.unknown = false;
        record.notify.notify_waiters();
        Ok(None)
    }
}
pub(crate) struct NativeHandle {
    client: Arc<NativeClient>,
    pub identity: NativeIdentity,
}
/// Translate the public workspace path into the guest's confined relative wire path.
/// This preflight runs before allocating an operation identity or retaining a request.
fn native_cwd(input: Option<&str>) -> Result<&str> {
    let path = match input {
        None | Some("/workspace" | "/workspace/") => ".",
        Some(path) => path.strip_prefix("/workspace/").unwrap_or(path),
    };
    if path.is_empty() || path.len() > 512 || path.contains('\0') || path.contains('\\') {
        bail!("native cwd refused");
    }
    if path != "."
        && (path.starts_with('/')
            || path.split('/').count() > 16
            || path
                .split('/')
                .any(|part| matches!(part, "" | "." | "..") || part.len() > 64))
    {
        bail!("native cwd refused");
    }
    Ok(path)
}

/// Validate the guest Exec grammar before identity allocation or actor effects.
fn native_exec_payload(cmd: &str, args: &[&str], opts: &ProcessOpts) -> Result<Value> {
    if args.len() > 63 || cmd.is_empty() {
        bail!("native argv refused");
    }
    let mut argv_bytes = 0;
    for arg in std::iter::once(cmd).chain(args.iter().copied()) {
        if arg.len() > 4096 || arg.contains('\0') {
            bail!("native argv refused");
        }
        argv_bytes += arg.len();
    }
    if argv_bytes > 32768 {
        bail!("native argv bounds");
    }
    let cwd = native_cwd(opts.cwd.as_deref())?;
    if opts.envs.len() > 32 {
        bail!("native environment bounds");
    }
    let mut env_bytes = 0;
    for (key, value) in &opts.envs {
        if key.is_empty()
            || key.len() > 64
            || !(key.as_bytes()[0].is_ascii_alphabetic() || key.starts_with('_'))
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || value.len() > 4096
            || value.contains('\0')
        {
            bail!("native environment refused");
        }
        env_bytes += key.len() + value.len();
    }
    if env_bytes > 16384 {
        bail!("native environment bounds");
    }
    let timeout_ms = opts
        .timeout
        .map(|duration| duration.as_millis().min(240000) as u64)
        .unwrap_or(240000);
    if timeout_ms == 0 {
        bail!("native timeout refused");
    }
    Ok(
        json!({"argv": std::iter::once(cmd).chain(args.iter().copied()).collect::<Vec<_>>(), "cwd": cwd, "env": opts.envs, "timeout_ms": timeout_ms}),
    )
}

fn native_file_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || path.contains('\0')
        || path.contains('\\')
        || path.split('/').count() > 16
        || path
            .split('/')
            .any(|part| matches!(part, "" | "." | "..") || part.len() > 64)
    {
        bail!("native file path refused");
    }
    Ok(())
}
fn native_file_range(offset: u64, length: u64) -> Result<()> {
    if length > 16384
        || offset
            .checked_add(length)
            .is_none_or(|end| end > 32 * 1024 * 1024)
    {
        bail!("native file range refused");
    }
    Ok(())
}

fn retained_value_charge(value: &Value) -> usize {
    let owned = match value {
        Value::String(s) => s.capacity(),
        Value::Array(values) => {
            values.capacity() * std::mem::size_of::<Value>()
                + values.iter().map(retained_value_charge).sum::<usize>()
        }
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| key.capacity() + 128 + retained_value_charge(value))
            .sum(),
        _ => 0,
    };
    std::mem::size_of::<Value>() + owned
}

impl NativeClient {
    #[cfg(test)]
    pub(crate) fn install<R, W>(
        reader: R,
        writer: W,
        expires: Instant,
        framing: NativeFraming,
    ) -> Arc<Self>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::install_with_downloads(reader, writer, expires, framing, None)
    }
    #[cfg(test)]
    pub(crate) fn install_with_downloads<R, W>(
        reader: R,
        writer: W,
        expires: Instant,
        framing: NativeFraming,
        download_spool: Option<Arc<super::native_download::NativeDownloadSpool>>,
    ) -> Arc<Self>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::install_policy(reader, writer, expires, framing, download_spool, None)
    }
    /// Called only by the protected profile path after the pinned broker READY.
    pub(crate) fn install_authenticated_profile<R, W>(
        reader: R,
        writer: W,
        expires: Instant,
        framing: NativeFraming,
        download_spool: Option<Arc<super::native_download::NativeDownloadSpool>>,
        agent_sha256: String,
        directory_declared: bool,
    ) -> Arc<Self>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::install_policy(
            reader,
            writer,
            expires,
            framing,
            download_spool,
            Some((agent_sha256, directory_declared)),
        )
    }
    fn install_policy<R, W>(
        reader: R,
        writer: W,
        expires: Instant,
        framing: NativeFraming,
        download_spool: Option<Arc<super::native_download::NativeDownloadSpool>>,
        artifact_policy: Option<(String, bool)>,
    ) -> Arc<Self>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(32);
        let client = Arc::new(Self {
            session: uuid::Uuid::now_v7().to_string(),
            artifact_policy,
            state: Mutex::new(State {
                caller_epoch: None,
                caller_admission_closed: false,
                records: HashMap::new(),
                bytes: 0,
                chunks: 0,
                lifetime_admissions: 0,
            }),
            ready: AtomicBool::new(true),
            tx,
            framing,
            expires,
            _download_spool: download_spool,
            download_admissions: tokio::sync::Mutex::new(Vec::new()),
        });
        tokio::spawn(actor(client.clone(), reader, writer, rx, expires));
        client
    }
    pub(crate) fn download_available(&self) -> bool {
        self._download_spool.is_some()
    }
    pub(crate) fn directory_available(&self) -> bool {
        // Declaration is policy, not evidence that DirectoryApply is implemented.
        const IMPLEMENTED_AND_QUALIFIED: bool = false;
        IMPLEMENTED_AND_QUALIFIED
            && self
                .artifact_policy
                .as_ref()
                .is_some_and(|(sha, declared)| *declared && sha.len() == 64)
    }
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    /// Called only after the broker child has actually been reaped. Cancellation
    /// leaves borrowed join handles and exact spool allocations retained for retry.
    pub(crate) async fn retire_downloads(&self) -> Result<()> {
        self.close();
        let mut jobs = self.download_admissions.lock().await;
        while let Some(job) = jobs.last_mut() {
            let result = job.await;
            jobs.pop();
            result.map_err(|_| anyhow::anyhow!("native download admission owner failed"))?;
        }
        if let Some(spool) = &self._download_spool {
            spool
                .cleanup_pending()
                .await
                .map_err(|e| anyhow::anyhow!("native download cleanup {:?}", e))?;
        }
        Ok(())
    }
    pub(crate) fn close(&self) {
        self.ready.store(false, Ordering::Release);
        self.fail();
    }
    fn fail(&self) {
        self.ready.store(false, Ordering::Release);
        let mut state = self.state.lock().expect("native state");
        for record in state.records.values_mut() {
            if record.terminal.is_none()
                && record.file_result.is_none()
                && !record.metadata.as_ref().is_some_and(|m| m.complete)
                && !record.upload.as_ref().is_some_and(|u| u.result.is_some())
                && !record
                    .download
                    .as_ref()
                    .is_some_and(|download| download.result.is_some())
            {
                record.unknown = true;
                record.notify.notify_waiters();
            }
        }
    }
    /// A duplicate returns the original typed owner and performs no pipe I/O.
    pub(crate) fn incarnation(&self) -> &str {
        &self.session
    }
    pub(crate) fn bind_caller_epoch(&self, epoch: u64) -> Result<()> {
        let mut state = self.state.lock().expect("native state");
        if epoch == 0 || state.caller_epoch.is_some_and(|old| old != epoch) {
            bail!("native caller epoch refused");
        }
        state.caller_epoch = Some(epoch);
        Ok(())
    }
    pub(crate) fn close_caller_admission(&self) {
        self.state
            .lock()
            .expect("native state")
            .caller_admission_closed = true;
    }
    pub(crate) fn reopen_caller_admission(&self, epoch: u64) -> Result<()> {
        let mut state = self.state.lock().expect("native state");
        if state.caller_epoch != Some(epoch) || !self.is_ready() || Instant::now() >= self.expires {
            bail!("native caller admission unavailable");
        }
        state.caller_admission_closed = false;
        Ok(())
    }
    pub(crate) fn start_keyed(
        self: &Arc<Self>,
        key: NativeCallerKey,
        cmd: &str,
        args: &[&str],
        opts: &ProcessOpts,
    ) -> Result<NativeHandle> {
        if !cmd.starts_with('/') {
            bail!("native command refused");
        }
        let payload = native_exec_payload(cmd, args, opts)?;
        let (identity, _) = self.reserve_owned("exec", payload, None, None, Some(key), false)?;
        Ok(NativeHandle {
            client: self.clone(),
            identity,
        })
    }
    pub(crate) fn start_metadata(
        self: &Arc<Self>,
        kind: &str,
        path: &str,
        key: Option<NativeCallerKey>,
    ) -> Result<NativeMetadataHandle> {
        super::native_metadata::path(path)?;
        if !matches!(kind, "file_stat" | "make_dir" | "list_begin") {
            bail!("native metadata kind");
        }
        let (identity, _) =
            self.reserve_owned(kind, json!({"path":path}), None, None, key, false)?;
        Ok(NativeMetadataHandle {
            client: self.clone(),
            identity,
        })
    }
    pub(crate) fn start_file_read_keyed(
        self: &Arc<Self>,
        key: NativeCallerKey,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<NativeFileHandle> {
        native_file_path(path)?;
        native_file_range(offset, length)?;
        if length == 0 {
            bail!("native file read range refused");
        }
        let (identity, _) = self.reserve_owned(
            "file_read",
            json!({"path":path,"offset":offset,"length":length}),
            None,
            None,
            Some(key),
            false,
        )?;
        Ok(NativeFileHandle {
            client: self.clone(),
            identity,
        })
    }
    pub(crate) fn start_file_write_keyed(
        self: &Arc<Self>,
        key: NativeCallerKey,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<NativeFileHandle> {
        native_file_path(path)?;
        native_file_range(offset, data.len() as u64)?;
        let (identity, _) = self.reserve_owned(
            "file_write",
            json!({"path":path,"offset":offset,"data":STANDARD.encode(data)}),
            None,
            None,
            Some(key),
            false,
        )?;
        Ok(NativeFileHandle {
            client: self.clone(),
            identity,
        })
    }
    pub(crate) fn start_upload_keyed(
        self: &Arc<Self>,
        key: NativeCallerKey,
        path: &str,
        size: u64,
        sha256: &str,
        create_parents: bool,
    ) -> Result<NativeUploadHandle> {
        native_file_path(path)?;
        if size > 32 * 1024 * 1024
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("native upload declaration refused");
        }
        let (identity, _) = self.reserve_owned(
            "upload_begin",
            json!({"path":path,"size":size,"sha256":sha256,"create_parents":create_parents}),
            None,
            None,
            Some(key),
            false,
        )?;
        Ok(NativeUploadHandle {
            client: self.clone(),
            identity,
        })
    }
    /// Observe the already frozen caller identity without allocation or effects.
    pub(crate) fn keyed_backing_pending(&self, key: &NativeCallerKey) -> Result<bool> {
        let identity = self
            .keyed_identity(key)?
            .ok_or_else(|| anyhow::anyhow!("native original absent"))?;
        let state = self.state.lock().expect("native state");
        let record = &state.records[&identity.operation_id];
        if record.kind != "download_begin" {
            bail!("native original kind refused");
        }
        Ok(record.backing_pending
            && !record.backing_failed
            && !record.unknown
            && !record.aborted
            && !record.cancel_intent
            && !state.caller_admission_closed
            && !record
                .backing_cancelled
                .as_ref()
                .is_some_and(|flag| *flag.lock().expect("download cancellation"))
            && self.is_ready()
            && Instant::now() < self.expires)
    }
    #[cfg(test)]
    pub(crate) fn keyed_truth_for_test(
        &self,
        key: &NativeCallerKey,
    ) -> Option<(bool, bool, u64, usize, usize, usize)> {
        let identity = self.keyed_identity(key).ok().flatten()?;
        let state = self.state.lock().expect("native state");
        let record = &state.records[&identity.operation_id];
        Some((
            record.unknown,
            record.terminal.is_some(),
            record.truth_revision,
            state.records.len(),
            state.bytes,
            state.lifetime_admissions,
        ))
    }
    pub(crate) fn mark_keyed_uncertain(&self, key: &NativeCallerKey) {
        let Ok(Some(identity)) = self.keyed_identity(key) else {
            return;
        };
        let mut state = self.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&identity.operation_id)
            .expect("retained original");
        if record.terminal.is_none()
            && record.file_result.is_none()
            && !record.metadata.as_ref().is_some_and(|m| m.complete)
            && !record.upload.as_ref().is_some_and(|v| v.result.is_some())
            && !record.download.as_ref().is_some_and(|v| v.result.is_some())
        {
            record.unknown = true;
            record.notify.notify_waiters();
        }
    }
    pub(crate) fn keyed_output(
        self: &Arc<Self>,
        key: &NativeCallerKey,
        stream: &str,
        offset: usize,
        length: usize,
    ) -> Result<Value> {
        if length == 0 || length > 16384 {
            bail!("native output bounds");
        }
        let id = self
            .keyed_identity(key)?
            .ok_or_else(|| anyhow::anyhow!("native original absent"))?;
        let state = self.state.lock().expect("native state");
        let record = &state.records[&id.operation_id];
        if record.kind != "exec" {
            bail!("native original kind refused");
        }
        let bytes = match stream {
            "stdout" => &record.stdout,
            "stderr" => &record.stderr,
            _ => bail!("native output stream refused"),
        };
        if offset > bytes.len() {
            bail!("native output bounds");
        }
        let end = offset.saturating_add(length).min(bytes.len());
        Ok(
            json!({"kind":"output","session_id":id.session_id,"operation_id":id.operation_id,"stream":stream,"offset":offset,"data":STANDARD.encode(&bytes[offset..end]),"retained_bytes":bytes.len()}),
        )
    }
    pub(crate) async fn register_keyed_receive(
        self: &Arc<Self>,
        key: &NativeCallerKey,
    ) -> Result<NativeIdentity> {
        let Some(NativeKeyedHandle::Download(handle)) = self.keyed_handle(key)? else {
            bail!("native download original unavailable");
        };
        let id = handle.identity.clone();
        let mut jobs = self
            .download_admissions
            .try_lock()
            .map_err(|_| anyhow::anyhow!("native download registration closing"))?;
        {
            let mut state = self.state.lock().expect("native state");
            let closed = state.caller_admission_closed;
            let record = state
                .records
                .get_mut(&id.operation_id)
                .expect("retained download");
            let download = record.download.as_mut().expect("download record");
            if download.public_receive_registered || download.result.is_some() {
                return Ok(id);
            }
            if closed
                || record.unknown
                || record.cancel_intent
                || !self.is_ready()
                || Instant::now() >= self.expires
            {
                bail!("native download receive unavailable");
            }
            download.public_receive_registered = true;
        }
        jobs.push(tokio::spawn(async move {
            let _ = handle.receive().await;
        }));
        Ok(id)
    }
    pub(crate) fn keyed_identity(&self, key: &NativeCallerKey) -> Result<Option<NativeIdentity>> {
        let state = self.state.lock().expect("native state");
        if state.caller_epoch.is_some_and(|epoch| epoch != key.epoch) {
            bail!("native caller epoch refused");
        }
        Ok(state
            .records
            .iter()
            .find(|(_, r)| r.caller.as_ref().is_some_and(|c| c.key == *key))
            .map(|(id, _)| NativeIdentity {
                session_id: self.session.clone(),
                operation_id: id.clone(),
            }))
    }
    /// Retrieve the original typed owner without a second operation registry.
    pub(crate) fn keyed_handle(
        self: &Arc<Self>,
        key: &NativeCallerKey,
    ) -> Result<Option<NativeKeyedHandle>> {
        let Some(identity) = self.keyed_identity(key)? else {
            return Ok(None);
        };
        let state = self.state.lock().expect("native state");
        let record = &state.records[&identity.operation_id];
        let owner = match record.kind.as_str() {
            "exec" => NativeKeyedHandle::Exec(NativeHandle {
                client: self.clone(),
                identity,
            }),
            "file_stat" | "make_dir" | "list_begin" => {
                NativeKeyedHandle::Metadata(NativeMetadataHandle {
                    client: self.clone(),
                    identity,
                })
            }
            "file_read" | "file_write" => NativeKeyedHandle::File(NativeFileHandle {
                client: self.clone(),
                identity,
            }),
            "upload_begin" => NativeKeyedHandle::Upload(NativeUploadHandle {
                client: self.clone(),
                identity,
            }),
            "download_begin"
                if record.download.is_some()
                    && !record.backing_pending
                    && !record.backing_failed =>
            {
                NativeKeyedHandle::Download(NativeDownloadHandle {
                    client: self.clone(),
                    identity,
                })
            }
            "download_begin" => NativeKeyedHandle::Pending(identity),
            _ => bail!("native original kind unsupported"),
        };
        Ok(Some(owner))
    }
    /// Cancel only the frozen original; pending backing is retained until joined.
    pub(crate) async fn cancel_keyed(
        self: &Arc<Self>,
        key: &NativeCallerKey,
    ) -> Result<NativeIdentity> {
        let identity = self
            .keyed_identity(key)?
            .ok_or_else(|| anyhow::anyhow!("native original absent"))?;
        NativeHandle {
            client: self.clone(),
            identity: identity.clone(),
        }
        .control("cancel")
        .await?;
        Ok(identity)
    }
    pub(crate) async fn start_download_keyed(
        self: &Arc<Self>,
        key: NativeCallerKey,
        path: &str,
        max_bytes: u64,
    ) -> Result<NativeDownloadHandle> {
        self.start_download_keyed_inner(key, path, max_bytes, || {})
            .await
    }
    async fn start_download_keyed_inner(
        self: &Arc<Self>,
        key: NativeCallerKey,
        path: &str,
        max_bytes: u64,
        before_backing: impl FnOnce() + Send + 'static,
    ) -> Result<NativeDownloadHandle> {
        native_file_path(path)?;
        if max_bytes > 32 * 1024 * 1024 {
            bail!("native download admission refused");
        }
        let spool = self
            ._download_spool
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native download capability unavailable"))?;
        let payload = json!({"path":path,"max_bytes":max_bytes});
        let (identity, fresh) = self.reserve_owned(
            "download_begin",
            payload.clone(),
            None,
            None,
            Some(key),
            true,
        )?;
        if !fresh {
            return self.await_keyed_download(identity).await;
        }
        let cancelled = Arc::new(Mutex::new(false));
        {
            let mut state = self.state.lock().expect("native state");
            state
                .records
                .get_mut(&identity.operation_id)
                .expect("reserved keyed download")
                .backing_cancelled = Some(cancelled.clone());
        }
        let guard = DownloadAdmissionGuard(cancelled.clone());
        let mut registrations = match self.download_admissions.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                self.fail_keyed_backing(&identity);
                bail!("native download admission closing");
            }
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let client = self.clone();
        let retained_identity = identity.clone();
        let job = tokio::spawn(async move {
            let prepared: Result<Vec<[u8; 32]>> = (|| {
                let mut receipts = Vec::new();
                receipts.try_reserve_exact(2048)?;
                if receipts.capacity() > 2048 {
                    bail!("native download receipt capacity");
                }
                Ok(receipts)
            })();
            let result = match prepared {
                Err(error) => Err(error),
                Ok(receipts) => match spool.allocate_inner(max_bytes, before_backing).await {
                    Err(error) => Err(anyhow::anyhow!("native download backing {:?}", error)),
                    Ok(file) => {
                        let file = Arc::new(file);
                        let installed: Result<()> = (|| {
                            let mut state = client.state.lock().expect("native state");
                            let admission_closed = state.caller_admission_closed;
                            let record = state
                                .records
                                .get_mut(&retained_identity.operation_id)
                                .expect("reserved keyed download");
                            // Retain actual allocation before subsequent cancellation,
                            // admission checks or queueing can fail.
                            record.download = Some(DownloadRecord::new(file.clone(), receipts));
                            if admission_closed
                                || *cancelled.lock().expect("keyed download cancellation")
                                || record.cancel_intent
                                || record.aborted
                                || Instant::now() >= client.expires
                                || !client.is_ready()
                            {
                                bail!("native download admission expired or cancelled");
                            }
                            let envelope = Envelope {
                                kind: "download_begin".into(),
                                session_id: client.session.clone(),
                                operation_id: retained_identity.operation_id.clone(),
                                payload,
                            };
                            if client.tx.try_send(envelope).is_err() {
                                bail!("native download dispatch unavailable");
                            }
                            record.backing_pending = false;
                            record.notify.notify_waiters();
                            Ok(())
                        })();
                        if let Err(error) = installed {
                            let _ = file.cleanup().await;
                            Err(error)
                        } else {
                            Ok(NativeDownloadHandle {
                                client: client.clone(),
                                identity: retained_identity.clone(),
                            })
                        }
                    }
                },
            };
            if result.is_err() {
                client.fail_keyed_backing(&retained_identity);
            }
            if let Err(Ok(handle)) = sender.send(result) {
                let _ = handle.cancel().await;
            }
        });
        registrations.push(job);
        drop(registrations);
        let result =
            tokio::time::timeout_at(tokio::time::Instant::from_std(self.expires), receiver)
                .await
                .map_err(|_| anyhow::anyhow!("native download admission deadline"))?
                .map_err(|_| anyhow::anyhow!("native download admission closed"))?;
        drop(guard);
        result
    }
    fn fail_keyed_backing(&self, identity: &NativeIdentity) {
        let mut state = self.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&identity.operation_id)
            .expect("reserved keyed download");
        record.backing_pending = false;
        record.backing_failed = true;
        record.unknown = true;
        record.notify.notify_waiters();
    }
    async fn await_keyed_download(
        self: &Arc<Self>,
        identity: NativeIdentity,
    ) -> Result<NativeDownloadHandle> {
        tokio::time::timeout_at(tokio::time::Instant::from_std(self.expires), async {
            loop {
                let notify = self.state.lock().expect("native state").records
                    [&identity.operation_id]
                    .notify
                    .clone();
                let changed = notify.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let state = self.state.lock().expect("native state");
                    let record = &state.records[&identity.operation_id];
                    if !record.backing_pending {
                        if record.download.is_some() && !record.aborted && !record.backing_failed {
                            return Ok(NativeDownloadHandle {
                                client: self.clone(),
                                identity: identity.clone(),
                            });
                        }
                        bail!("native original download remains unknown");
                    }
                    if !self.is_ready() {
                        bail!("native original download unavailable");
                    }
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("native original download deadline"))?
    }

    pub(crate) fn start(
        self: &Arc<Self>,
        cmd: &str,
        args: &[&str],
        opts: &ProcessOpts,
    ) -> Result<NativeHandle> {
        if !self.is_ready() || !cmd.starts_with('/') {
            bail!("native command refused");
        }
        let payload = native_exec_payload(cmd, args, opts)?;
        let identity = self.reserve("exec", payload)?;
        Ok(NativeHandle {
            client: self.clone(),
            identity,
        })
    }
    pub(crate) fn start_file_read(
        self: &Arc<Self>,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<NativeFileHandle> {
        native_file_path(path)?;
        native_file_range(offset, length)?;
        if length == 0 {
            bail!("native file read range refused");
        }
        let identity = self.reserve(
            "file_read",
            json!({"path":path,"offset":offset,"length":length}),
        )?;
        Ok(NativeFileHandle {
            client: self.clone(),
            identity,
        })
    }
    pub(crate) fn start_file_write(
        self: &Arc<Self>,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<NativeFileHandle> {
        native_file_path(path)?;
        native_file_range(offset, data.len() as u64)?;
        let identity = self.reserve(
            "file_write",
            json!({"path":path,"offset":offset,"data":STANDARD.encode(data)}),
        )?;
        Ok(NativeFileHandle {
            client: self.clone(),
            identity,
        })
    }
    pub(crate) async fn start_download(
        self: &Arc<Self>,
        path: &str,
        max_bytes: u64,
    ) -> Result<NativeDownloadHandle> {
        self.start_download_inner(path, max_bytes, || {}).await
    }
    async fn start_download_inner(
        self: &Arc<Self>,
        path: &str,
        max_bytes: u64,
        before_backing: impl FnOnce() + Send + 'static,
    ) -> Result<NativeDownloadHandle> {
        native_file_path(path)?;
        if max_bytes > 32 * 1024 * 1024 || Instant::now() >= self.expires || !self.is_ready() {
            bail!("native download admission refused");
        }
        let spool = self
            ._download_spool
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native download capability unavailable"))?;
        let payload = json!({"path":path,"max_bytes":max_bytes});
        let preflight = Envelope {
            kind: "download_begin".into(),
            session_id: self.session.clone(),
            operation_id: "0".repeat(36),
            payload: payload.clone(),
        };
        checked_frame_fingerprint(&preflight, self.framing)?;
        let mut receipts = Vec::new();
        receipts.try_reserve_exact(2048)?;
        if receipts.capacity() > 2048 {
            bail!("native download receipt capacity");
        }
        let mut registrations = self
            .download_admissions
            .try_lock()
            .map_err(|_| anyhow::anyhow!("native download admission closing"))?;
        if !self.is_ready() {
            bail!("native download admission closing");
        }
        {
            let mut state = self.state.lock().expect("native state");
            if state.lifetime_admissions >= 32
                || state
                    .bytes
                    .checked_add(DOWNLOAD_RECEIPTS)
                    .is_none_or(|n| n > OUTPUT)
            {
                bail!("native download retention capacity");
            }
            state.lifetime_admissions += 1;
            state.bytes += DOWNLOAD_RECEIPTS;
        }
        let cancelled = Arc::new(Mutex::new(false));
        let guard = DownloadAdmissionGuard(cancelled.clone());
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let client = self.clone();
        let job = tokio::spawn(async move {
            let allocation = spool.allocate_inner(max_bytes, before_backing).await;
            let result = match allocation {
                Err(error) => Err(anyhow::anyhow!("native download backing {:?}", error)),
                Ok(file) => {
                    let file = Arc::new(file);
                    let abandoned = *cancelled.lock().expect("download admission");
                    if abandoned || Instant::now() >= client.expires || !client.is_ready() {
                        let _ = file.cleanup().await;
                        Err(anyhow::anyhow!(
                            "native download admission expired or cancelled"
                        ))
                    } else {
                        let record = DownloadRecord::new(file.clone(), receipts);
                        match client.reserve_inner(
                            "download_begin",
                            payload,
                            Some(record),
                            Some(&cancelled),
                        ) {
                            Ok(identity) => Ok(NativeDownloadHandle {
                                client: client.clone(),
                                identity,
                            }),
                            Err(error) => {
                                let _ = file.cleanup().await;
                                Err(error)
                            }
                        }
                    }
                }
            };
            if let Err(Ok(handle)) = sender.send(result) {
                let _ = handle.cancel().await;
            }
        });
        registrations.push(job);
        drop(registrations);
        let result =
            tokio::time::timeout_at(tokio::time::Instant::from_std(self.expires), receiver)
                .await
                .map_err(|_| anyhow::anyhow!("native download admission deadline"))?
                .map_err(|_| anyhow::anyhow!("native download admission closed"))?;
        drop(guard);
        result
    }
    pub(crate) fn start_upload(
        self: &Arc<Self>,
        path: &str,
        size: u64,
        sha256: &str,
        create_parents: bool,
    ) -> Result<NativeUploadHandle> {
        native_file_path(path)?;
        if size > 32 * 1024 * 1024
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("native upload declaration refused");
        }
        let identity = self.reserve(
            "upload_begin",
            json!({"path":path,"size":size,"sha256":sha256,"create_parents":create_parents}),
        )?;
        Ok(NativeUploadHandle {
            client: self.clone(),
            identity,
        })
    }
    fn reserve(&self, kind: &str, payload: Value) -> Result<NativeIdentity> {
        self.reserve_inner(kind, payload, None, None)
    }
    fn reserve_inner(
        &self,
        kind: &str,
        payload: Value,
        download: Option<DownloadRecord>,
        cancelled: Option<&Mutex<bool>>,
    ) -> Result<NativeIdentity> {
        self.reserve_owned(kind, payload, download, cancelled, None, false)
            .map(|(identity, _)| identity)
    }
    fn reserve_owned(
        &self,
        kind: &str,
        payload: Value,
        download: Option<DownloadRecord>,
        cancelled: Option<&Mutex<bool>>,
        key: Option<NativeCallerKey>,
        backing_pending: bool,
    ) -> Result<(NativeIdentity, bool)> {
        let cancellation = cancelled.map(|flag| flag.lock().expect("download admission"));
        if cancellation.as_ref().is_some_and(|flag| **flag) {
            bail!("native download admission cancelled");
        }
        let mut envelope = Envelope {
            kind: kind.into(),
            session_id: self.session.clone(),
            operation_id: String::new(),
            payload,
        };
        // UUID wire spelling is always 36 unescaped ASCII bytes. Check the full
        // newline frame before allocating that identity, including JSON escaping.
        let ipc_body = serde_json::to_vec(&envelope)?.len() + 36;
        if ipc_body + 1 > LINE || ipc_body + self.framing.signed_delta > LINE {
            bail!("native command bounds");
        }
        let mut state = self.state.lock().expect("native state");
        let caller = if let Some(key) = key {
            if key.epoch == 0
                || key.operation_id.is_empty()
                || key.operation_id.len() > 64
                || !key.operation_id.as_bytes()[0].is_ascii_alphanumeric()
                || !key
                    .operation_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                || state.caller_epoch.is_some_and(|epoch| epoch != key.epoch)
            {
                bail!("native caller identity refused");
            }
            let fingerprint: [u8; 32] =
                Sha256::digest(serde_json::to_vec(&(kind, &envelope.payload))?).into();
            if let Some((id, old)) = state
                .records
                .iter()
                .find(|(_, r)| r.caller.as_ref().is_some_and(|c| c.key == key))
            {
                if old.caller.as_ref().expect("matched caller").fingerprint != fingerprint {
                    bail!("native caller original request changed");
                }
                return Ok((
                    NativeIdentity {
                        session_id: self.session.clone(),
                        operation_id: id.clone(),
                    },
                    false,
                ));
            }
            Some(CallerRecord { key, fingerprint })
        } else {
            None
        };
        if state.caller_admission_closed || !self.is_ready() || Instant::now() >= self.expires {
            bail!("native admission unavailable");
        }
        // Include owned key and frozen request storage in the same cumulative
        // retention ledger. No second registry, refund, or retry allocation.
        let caller_charge = caller.as_ref().map_or(0, |c| {
            std::mem::size_of::<CallerRecord>()
                + c.key.operation_id.capacity()
                + retained_value_charge(&envelope.payload)
        });
        let resource_charge = if kind == "upload_begin" {
            UPLOAD_RECEIPTS
        } else if kind == "list_begin" {
            512 * 1024
        } else if matches!(kind, "file_stat" | "make_dir") {
            32 * 1024
        } else if backing_pending {
            DOWNLOAD_RECEIPTS
        } else {
            0
        };
        let charge = caller_charge
            .checked_add(resource_charge)
            .filter(|n| state.bytes.checked_add(*n).is_some_and(|v| v <= OUTPUT))
            .ok_or_else(|| anyhow::anyhow!("native keyed retention capacity"))?;
        if download.is_none() && state.lifetime_admissions >= 32 {
            bail!("native operation capacity");
        }
        let upload = if kind == "upload_begin" {
            let mut receipts = Vec::new();
            receipts.try_reserve_exact(2048)?;
            if receipts.capacity() > 2048 {
                bail!("native upload receipt capacity");
            }
            Some(UploadRecord {
                progress: None,
                result: None,
                receipts,
                confirmed: 0,
                sent_chunks: 0,
                commit_sent: false,
                observed: false,
                commit: None,
                revision: 0,
                cancelled: false,
                stream_started: false,
                stream_leased: false,
            })
        } else {
            None
        };
        let metadata = if matches!(kind, "file_stat" | "make_dir" | "list_begin") {
            Some(MetadataCache::new(kind == "list_begin")?)
        } else {
            None
        };
        if download.is_none() {
            state.lifetime_admissions += 1;
        }
        state.bytes += charge;
        if let Some(caller) = &caller {
            state.caller_epoch = Some(caller.key.epoch);
        }
        let id = uuid::Uuid::now_v7().to_string();
        envelope.operation_id = id.clone();
        state.records.insert(
            id.clone(),
            Record {
                caller,
                backing_pending,
                backing_failed: false,
                backing_cancelled: None,
                kind: kind.into(),
                upload,
                download,
                file_result: None,
                metadata,
                file_truth_revision: 0,
                metadata_truth_revision: 0,
                metadata_next: None,
                metadata_query: None,
                metadata_phase_serial: 0,
                metadata_completed_next: 0,
                metadata_completed_query: 0,
                metadata_response: None,
                dispatched: false,
                _request: envelope.payload.clone(),
                stdout: Vec::new(),
                stderr: Vec::new(),
                chunks: Vec::new(),
                terminal: None,
                unknown: false,
                aborted: false,
                cancel_intent: false,
                acked: 0,
                ack_sent: 0,
                truth_revision: 0,
                status_truth_revision: 0,
                status_truth_kind: None,
                status: None,
                notify: Arc::new(Notify::new()),
            },
        );
        // Identity and request are frozen before the actor can perform pipe I/O.
        if !backing_pending && self.tx.try_send(envelope).is_err() {
            state.records.get_mut(&id).unwrap().unknown = true;
        }
        Ok((
            NativeIdentity {
                session_id: self.session.clone(),
                operation_id: id,
            },
            true,
        ))
    }
}
impl NativeHandle {
    pub(crate) async fn control(&self, kind: &str) -> Result<()> {
        if !matches!(kind, "query" | "cancel") {
            bail!("native control refused");
        }
        let mut state = self.client.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&self.identity.operation_id)
            .expect("retained operation");
        if record.aborted {
            return Ok(());
        }
        if kind == "cancel" {
            if record.terminal.is_some()
                || record.file_result.is_some()
                || record.metadata.as_ref().is_some_and(|m| m.complete)
                || record
                    .download
                    .as_ref()
                    .is_some_and(|download| download.result.is_some())
                || record
                    .upload
                    .as_ref()
                    .is_some_and(|upload| upload.result.is_some())
            {
                return Ok(());
            }
            // The same lock linearizes original cancellation against dispatch.
            record.cancel_intent = true;
            if let Some(cancelled) = &record.backing_cancelled {
                *cancelled.lock().expect("keyed download cancellation") = true;
            }
            if let Some(download) = record.download.as_mut() {
                download.observed = false;
            }
            if let Some(upload) = record.upload.as_mut() {
                upload.cancelled = true;
                upload.observed = false;
            }
            if !record.dispatched {
                record.aborted = true;
                record.notify.notify_waiters();
                return Ok(());
            }
            record.unknown = true;
            record.truth_revision += 1;
            record.notify.notify_waiters();
        }
        if record.backing_pending {
            return Ok(());
        }
        let message = Envelope {
            kind: kind.into(),
            session_id: self.identity.session_id.clone(),
            operation_id: self.identity.operation_id.clone(),
            payload: json!({}),
        };
        if self.client.tx.try_send(message).is_err() {
            record.unknown = true;
            record.truth_revision += 1;
            record.notify.notify_waiters();
            bail!(
                "native operation {} control unavailable",
                self.identity.operation_id
            );
        }
        Ok(())
    }
    pub(crate) async fn query_status(&self) -> Result<NativeStatus> {
        let revision = self.client.state.lock().expect("native state").records
            [&self.identity.operation_id]
            .status_truth_revision;
        self.control("query").await?;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let notify = self.client.state.lock().expect("native state").records
                    [&self.identity.operation_id]
                    .notify
                    .clone();
                let changed = notify.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let state = self.client.state.lock().expect("native state");
                    let record = &state.records[&self.identity.operation_id];
                    if record.status_truth_revision > revision {
                        // Kind and revision identify the same authenticated
                        // response. Cached completion remains separate for wait().
                        let (terminal, value) = match record.status_truth_kind {
                            Some(StatusTruthKind::Terminal) => (true, record.terminal.as_ref()),
                            Some(StatusTruthKind::Status) => (false, record.status.as_ref()),
                            None => bail!("native truth absent"),
                        };
                        let value = value.ok_or_else(|| anyhow::anyhow!("native truth absent"))?;
                        return Ok(NativeStatus {
                            identity: self.identity.clone(),
                            state: value["state"].as_str().unwrap_or("unknown").to_owned(),
                            exit_code: value["exit_code"]
                                .as_i64()
                                .and_then(|v| i32::try_from(v).ok()),
                            stdout_bytes: value["stdout_bytes"].as_u64(),
                            stderr_bytes: value["stderr_bytes"].as_u64(),
                            process_absent: terminal && value["process_absent"] == true,
                            acked_sequence: record.acked as u64,
                            terminal,
                        });
                    }
                    if !self.client.is_ready() || record.aborted {
                        bail!(
                            "native operation {} query unavailable",
                            self.identity.operation_id
                        );
                    }
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "native operation {} query deadline",
                self.identity.operation_id
            )
        })?
    }
    pub(crate) async fn wait(&self) -> Result<ProcessOutput> {
        loop {
            let notify = {
                self.client.state.lock().expect("native state").records[&self.identity.operation_id]
                    .notify
                    .clone()
            };
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.client.state.lock().expect("native state");
                let record = &state.records[&self.identity.operation_id];
                if record.aborted {
                    bail!(
                        "native operation {} cancelled before dispatch",
                        self.identity.operation_id
                    );
                }
                if record.unknown {
                    bail!(
                        "native operation {} UNKNOWN; query original identity",
                        self.identity.operation_id
                    );
                }
                if let Some(terminal) = &record.terminal {
                    let code = terminal
                        .get("exit_code")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "native operation {} cancelled or timed out",
                                self.identity.operation_id
                            )
                        })?;
                    return Ok(ProcessOutput {
                        stdout: String::from_utf8_lossy(&record.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&record.stderr).into_owned(),
                        exit_code: i32::try_from(code)?,
                    });
                }
            }
            changed.await;
        }
    }
}
impl NativeUploadHandle {
    pub fn identity(&self) -> &NativeIdentity {
        &self.identity
    }
    pub async fn cancel(&self) -> Result<()> {
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("cancel")
        .await
    }
    pub async fn wait_ready(&self) -> Result<NativeUploadProgress> {
        match self.observe(None).await? {
            NativeUploadObservation::Progress(progress) => Ok(progress),
            NativeUploadObservation::Complete(_) => bail!("native upload already complete"),
        }
    }
    /// Obtain new authenticated truth; never retransmit begin, chunk or commit.
    pub async fn query(&self) -> Result<NativeUploadObservation> {
        let revision = {
            let state = self.client.state.lock().expect("native state");
            let record = &state.records[&self.identity.operation_id];
            if record.aborted || !record.dispatched || !self.client.is_ready() {
                bail!(
                    "native upload {} query unavailable",
                    self.identity.operation_id
                );
            }
            record.truth_revision
        };
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("query")
        .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.observe(Some(revision)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "native upload {} query deadline",
                self.identity.operation_id
            )
        })?
    }
    async fn observe(&self, revision: Option<u64>) -> Result<NativeUploadObservation> {
        loop {
            let notify = self.client.state.lock().expect("native state").records
                [&self.identity.operation_id]
                .notify
                .clone();
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.client.state.lock().expect("native state");
                let record = &state.records[&self.identity.operation_id];
                let upload = record.upload.as_ref().expect("upload record");
                if record.aborted {
                    bail!(
                        "native upload {} cancelled before dispatch",
                        self.identity.operation_id
                    );
                }
                if revision.is_none_or(|r| record.truth_revision > r) {
                    if revision.is_none_or(|r| upload.revision > r) {
                        if let Some(result) = &upload.result {
                            return Ok(NativeUploadObservation::Complete(result.clone()));
                        }
                        if !record.unknown && upload.observed {
                            if let Some(progress) = &upload.progress {
                                return Ok(NativeUploadObservation::Progress(progress.clone()));
                            }
                        }
                    }
                    if revision.is_some() || record.unknown || upload.cancelled {
                        bail!(
                            "native upload {} incomplete; query original identity",
                            self.identity.operation_id
                        );
                    }
                }
                if !self.client.is_ready() {
                    bail!(
                        "native upload {} UNKNOWN; query original identity",
                        self.identity.operation_id
                    );
                }
            }
            changed.await;
        }
    }
    pub(crate) async fn write_chunk_at(
        &self,
        sequence: u64,
        data: &[u8],
    ) -> Result<NativeUploadObservation> {
        let duplicate = {
            let state = self.client.state.lock().expect("native state");
            let record = &state.records[&self.identity.operation_id];
            let upload = record.upload.as_ref().expect("upload record");
            if sequence > upload.receipts.len() as u64 {
                bail!("native upload sequence refused");
            }
            if sequence < upload.receipts.len() as u64 {
                let frame = Envelope {
                    kind: "upload_chunk".into(),
                    session_id: self.identity.session_id.clone(),
                    operation_id: self.identity.operation_id.clone(),
                    payload: json!({"sequence":sequence,"data":STANDARD.encode(data),"sha256":format!("{:x}",Sha256::digest(data))}),
                };
                if checked_frame_fingerprint(&frame, self.client.framing)?
                    != upload.receipts[sequence as usize].0
                {
                    bail!("native upload original chunk changed");
                }
                true
            } else {
                false
            }
        };
        if duplicate {
            return self.query().await;
        }
        self.write_chunk_inner(data, false, Some(sequence))
            .await
            .map(NativeUploadObservation::Progress)
    }
    pub async fn write_chunk(&self, data: &[u8]) -> Result<NativeUploadProgress> {
        self.write_chunk_inner(data, false, None).await
    }
    async fn write_chunk_inner(
        &self,
        data: &[u8],
        stream: bool,
        sequence: Option<u64>,
    ) -> Result<NativeUploadProgress> {
        let until = (Instant::now() + std::time::Duration::from_secs(3)).min(self.client.expires);
        if Instant::now() >= until {
            bail!("native upload chunk admission deadline");
        }
        if data.is_empty() || data.len() > 16384 {
            bail!("native upload chunk bounds");
        }
        let (revision, expected_sequence, expected_end) = {
            let mut state = self.client.state.lock().expect("native state");
            if state.caller_admission_closed {
                bail!("native caller admission closed");
            }
            let record = state
                .records
                .get_mut(&self.identity.operation_id)
                .expect("retained upload");
            let upload = record.upload.as_mut().expect("upload record");
            if sequence.is_some_and(|n| n != upload.receipts.len() as u64)
                || upload.stream_leased != stream
                || record.unknown
                || record.aborted
                || !self.client.is_ready()
                || !record.dispatched
                || !upload.observed
                || upload.confirmed != upload.receipts.len()
                || upload.commit.is_some()
                || upload.result.is_some()
                || upload.cancelled
                || upload.receipts.len() >= 2048
            {
                bail!(
                    "native upload {} advancement unavailable; query original identity",
                    self.identity.operation_id
                );
            }
            let previous = upload.receipts.last().map_or(0, |receipt| receipt.1);
            let end = previous
                .checked_add(data.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("native upload size overflow"))?;
            if end > record._request["size"].as_u64().expect("declared size") {
                bail!("native upload declared size exceeded");
            }
            let frame = Envelope {
                kind: "upload_chunk".into(),
                session_id: self.identity.session_id.clone(),
                operation_id: self.identity.operation_id.clone(),
                payload: json!({"sequence":upload.receipts.len(),"data":STANDARD.encode(data),"sha256":format!("{:x}",Sha256::digest(data))}),
            };
            let fingerprint = checked_frame_fingerprint(&frame, self.client.framing)?;
            upload.receipts.push((fingerprint, end));
            upload.observed = false;
            let revision = record.truth_revision;
            if self.client.tx.try_send(frame).is_err() {
                record.unknown = true;
                record.truth_revision += 1;
                record.notify.notify_waiters();
            }
            (revision, upload.receipts.len() as u64, end)
        };
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(until),
            self.wait_chunk_prefix(revision, expected_sequence, expected_end, until),
        )
        .await
        {
            Ok(Ok(progress)) => {
                if Instant::now() >= until {
                    self.mark_uncertain();
                    bail!("native upload original chunk deadline");
                }
                Ok(progress)
            }
            Ok(Err(error)) => Err(error),
            Err(_) => {
                self.mark_uncertain();
                bail!(
                    "native upload {} chunk deadline; query original identity",
                    self.identity.operation_id
                );
            }
        }
    }
    // A full authenticated earlier prefix is allowed while waiting for this
    // one frozen receipt. Notification/heartbeat cannot renew the outer deadline
    // or dispatch another write/query. UNKNOWN/cancellation is never ignored.
    async fn wait_chunk_prefix(
        &self,
        revision: u64,
        expected_sequence: u64,
        expected_end: u64,
        until: Instant,
    ) -> Result<NativeUploadProgress> {
        loop {
            if Instant::now() >= until {
                self.mark_uncertain();
                bail!("native upload original chunk deadline");
            }
            let notify = self.client.state.lock().expect("native state").records
                [&self.identity.operation_id]
                .notify
                .clone();
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.client.state.lock().expect("native state");
                let record = &state.records[&self.identity.operation_id];
                let upload = record.upload.as_ref().expect("upload record");
                if record.unknown
                    || record.aborted
                    || record.cancel_intent
                    || upload.cancelled
                    || !self.client.is_ready()
                {
                    bail!("native upload original chunk remains unknown or cancelled");
                }
                if record.truth_revision > revision && upload.revision > revision {
                    if upload.result.is_some() {
                        bail!("native upload unexpected completion");
                    }
                    if upload.observed {
                        let progress = upload
                            .progress
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("native upload receipt absent"))?;
                        let count = usize::try_from(progress.next_sequence)?;
                        let received = if count == 0 {
                            Some(0)
                        } else {
                            upload.receipts.get(count - 1).map(|r| r.1)
                        };
                        if progress.identity.session_id != self.identity.session_id
                            || progress.identity.operation_id != self.identity.operation_id
                            || progress.next_sequence > expected_sequence
                            || count != upload.confirmed
                            || count > upload.sent_chunks
                            || received != Some(progress.received)
                            || progress.received > expected_end
                        {
                            bail!(
                                "native upload receipt prefix refused expected_sequence={} observed_sequence={} expected_bytes={} observed_bytes={}",
                                expected_sequence,
                                progress.next_sequence,
                                expected_end,
                                progress.received
                            );
                        }
                        if progress.next_sequence == expected_sequence
                            && progress.received == expected_end
                        {
                            if Instant::now() >= until {
                                // Release the state guard before marking the
                                // original uncertain under the same mutex.
                                drop(state);
                                self.mark_uncertain();
                                bail!("native upload original chunk deadline");
                            }
                            return Ok(progress.clone());
                        }
                    }
                }
            }
            changed.await;
        }
    }
    /// Freeze and send commit once. Repeated calls return cached completion only.
    pub(crate) async fn commit_once(&self) -> Result<NativeUploadObservation> {
        let existing = {
            let state = self.client.state.lock().expect("native state");
            let upload = state.records[&self.identity.operation_id]
                .upload
                .as_ref()
                .expect("upload record");
            upload.commit.is_some() || upload.result.is_some()
        };
        if existing {
            self.query().await
        } else {
            self.commit().await.map(NativeUploadObservation::Complete)
        }
    }
    pub async fn commit(&self) -> Result<NativeUploadOutcome> {
        self.commit_inner(false).await
    }
    async fn commit_inner(&self, stream: bool) -> Result<NativeUploadOutcome> {
        {
            let mut state = self.client.state.lock().expect("native state");
            let admission_closed = state.caller_admission_closed;
            let record = state
                .records
                .get_mut(&self.identity.operation_id)
                .expect("retained upload");
            let upload = record.upload.as_mut().expect("upload record");
            if let Some(result) = &upload.result {
                return Ok(result.clone());
            }
            if admission_closed {
                bail!("native caller admission closed");
            }
            if upload.stream_leased != stream
                || record.unknown
                || record.aborted
                || !self.client.is_ready()
                || !record.dispatched
                || !upload.observed
                || upload.confirmed != upload.receipts.len()
                || upload.commit.is_some()
                || upload.cancelled
                || upload.receipts.last().map_or(0, |r| r.1)
                    != record._request["size"].as_u64().expect("declared size")
            {
                bail!(
                    "native upload {} commit unavailable; query original identity",
                    self.identity.operation_id
                );
            }
            let frame = Envelope {
                kind: "upload_commit".into(),
                session_id: self.identity.session_id.clone(),
                operation_id: self.identity.operation_id.clone(),
                payload: json!({"size":record._request["size"],"sha256":record._request["sha256"]}),
            };
            upload.commit = Some(checked_frame_fingerprint(&frame, self.client.framing)?);
            upload.observed = false;
            if self.client.tx.try_send(frame).is_err() {
                record.unknown = true;
                record.truth_revision += 1;
                record.notify.notify_waiters();
            }
        }
        match tokio::time::timeout(std::time::Duration::from_secs(3), self.wait()).await {
            Ok(result) => result,
            Err(_) => {
                self.mark_uncertain();
                bail!(
                    "native upload {} commit deadline; query original identity",
                    self.identity.operation_id
                );
            }
        }
    }
    /// Stream once from a fresh declared upload using one 16KiB buffer.
    /// Cancellation/error retains the original handle and uncertain intent;
    /// resuming a consumed reader requires explicit query and low-level calls.
    pub async fn upload_from<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<NativeUploadOutcome> {
        let (size, expected_sha) = {
            let mut state = self.client.state.lock().expect("native state");
            let record = state
                .records
                .get_mut(&self.identity.operation_id)
                .expect("retained upload");
            let upload = record.upload.as_mut().expect("upload record");
            if !self.client.is_ready()
                || Instant::now() >= self.client.expires
                || record.unknown
                || record.aborted
                || record.cancel_intent
                || upload.stream_started
                || upload.stream_leased
                || !upload.receipts.is_empty()
                || upload.commit.is_some()
                || upload.result.is_some()
            {
                bail!(
                    "native upload {} stream admission refused",
                    self.identity.operation_id
                );
            }
            upload.stream_started = true;
            upload.stream_leased = true;
            (
                record._request["size"].as_u64().expect("declared size"),
                record._request["sha256"]
                    .as_str()
                    .expect("declared digest")
                    .to_owned(),
            )
        };
        let mut lease = UploadStreamLease {
            client: self.client.clone(),
            operation_id: self.identity.operation_id.clone(),
            finished: false,
        };
        let result =
            tokio::time::timeout_at(tokio::time::Instant::from_std(self.client.expires), async {
                let initial = self.wait_ready().await?;
                if initial.received != 0 || initial.next_sequence != 0 {
                    bail!("native upload stream requires fresh prefix");
                }
                let mut buffer = vec![0u8; 16384];
                let mut remaining = size;
                let mut hash = Sha256::new();
                while remaining != 0 {
                    let wanted = usize::try_from(remaining.min(16384))?;
                    let mut filled = 0;
                    while filled < wanted {
                        if Instant::now() >= self.client.expires {
                            bail!("native upload incarnation expired");
                        }
                        match reader.read(&mut buffer[filled..wanted]).await {
                            Ok(0) => bail!("native upload source truncated"),
                            Ok(count) => filled += count,
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            Err(_) => bail!("native upload source read failed"),
                        }
                    }
                    hash.update(&buffer[..filled]);
                    self.write_chunk_inner(&buffer[..filled], true, None)
                        .await?;
                    remaining -= filled as u64;
                }
                loop {
                    if Instant::now() >= self.client.expires {
                        bail!("native upload incarnation expired");
                    }
                    match reader.read(&mut buffer[..1]).await {
                        Ok(0) => break,
                        Ok(_) => bail!("native upload source exceeds declaration"),
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => bail!("native upload source read failed"),
                    }
                }
                if format!("{:x}", hash.finalize()) != expected_sha {
                    bail!("native upload source digest mismatch");
                }
                self.commit_inner(true).await
            })
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "native upload {} incarnation deadline",
                    self.identity.operation_id
                )
            })?;
        if result.is_ok() {
            lease.finished = true;
        }
        result
    }
    fn mark_uncertain(&self) {
        let mut state = self.client.state.lock().expect("native state");
        let record = state
            .records
            .get_mut(&self.identity.operation_id)
            .expect("retained upload");
        if record
            .upload
            .as_ref()
            .expect("upload record")
            .result
            .is_none()
        {
            record.unknown = true;
            record.upload.as_mut().expect("upload record").observed = false;
            record.truth_revision += 1;
            record.notify.notify_waiters();
        }
    }
    /// Wait for retained final truth without sending an effect.
    pub async fn wait(&self) -> Result<NativeUploadOutcome> {
        loop {
            let notify = self.client.state.lock().expect("native state").records
                [&self.identity.operation_id]
                .notify
                .clone();
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.client.state.lock().expect("native state");
                let record = &state.records[&self.identity.operation_id];
                let upload = record.upload.as_ref().expect("upload record");
                if let Some(result) = &upload.result {
                    return Ok(result.clone());
                }
                if record.unknown || record.aborted || upload.cancelled || !self.client.is_ready() {
                    bail!(
                        "native upload {} incomplete; query original identity",
                        self.identity.operation_id
                    );
                }
            }
            changed.await;
        }
    }
}
fn mark_upload_advance(client: &NativeClient, frame: &Envelope) -> Result<bool> {
    let mut state = client.state.lock().expect("native state");
    if state.caller_admission_closed {
        if let Some(record) = state.records.get_mut(&frame.operation_id) {
            record.unknown = true;
            record.notify.notify_waiters();
        }
        return Ok(false);
    }
    let record = state
        .records
        .get_mut(&frame.operation_id)
        .ok_or_else(|| anyhow::anyhow!("native upload missing intent"))?;
    let upload = record
        .upload
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("native upload kind mismatch"))?;
    if !record.dispatched || upload.result.is_some() {
        bail!("native upload advancement identity");
    }
    if record.unknown || record.aborted || upload.cancelled {
        return Ok(false);
    }
    let fingerprint = checked_frame_fingerprint(frame, client.framing)?;
    if frame.kind == "upload_chunk" {
        let sequence = frame.payload["sequence"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("native upload sequence"))?;
        let sequence = usize::try_from(sequence)?;
        if sequence != upload.sent_chunks
            || upload
                .receipts
                .get(sequence)
                .is_none_or(|r| r.0 != fingerprint)
            || upload.commit_sent
        {
            bail!("native upload chunk intent conflict");
        }
        upload.sent_chunks += 1;
    } else {
        if upload.commit != Some(fingerprint)
            || upload.commit_sent
            || upload.sent_chunks != upload.receipts.len()
            || upload.confirmed != upload.receipts.len()
        {
            bail!("native upload commit intent conflict");
        }
        upload.commit_sent = true;
    }
    Ok(true)
}
fn retain_upload_event(record: &mut Record, event: &Envelope) -> Result<()> {
    let payload = event
        .payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("native upload payload"))?;
    let expected: &[&str] = if event.kind == "upload_progress" {
        &["path", "size", "sha256", "received", "next_sequence"]
    } else {
        &["path", "size", "sha256"]
    };
    if record.kind != "upload_begin"
        || !record.dispatched
        || payload.len() != expected.len()
        || expected.iter().any(|field| !payload.contains_key(*field))
        || ["path", "size", "sha256"]
            .iter()
            .any(|field| event.payload[*field] != record._request[*field])
    {
        bail!("native upload receipt identity");
    }
    let upload = record
        .upload
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("native upload receipt kind"))?;
    if event.kind == "upload_progress" {
        let count = usize::try_from(
            event.payload["next_sequence"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("native upload prefix"))?,
        )?;
        if count < upload.confirmed
            || count > upload.sent_chunks
            || count > upload.receipts.len()
            || upload.result.is_some()
        {
            bail!("native upload prefix bounds");
        }
        let received = if count == 0 {
            0
        } else {
            upload.receipts[count - 1].1
        };
        if event.payload["received"].as_u64() != Some(received) {
            bail!("native upload byte prefix");
        }
        upload.confirmed = count;
        upload.observed = true;
        upload.progress = Some(NativeUploadProgress {
            identity: NativeIdentity {
                session_id: event.session_id.clone(),
                operation_id: event.operation_id.clone(),
            },
            received,
            next_sequence: count as u64,
        });
    } else {
        if !upload.commit_sent
            || upload.commit.is_none()
            || upload.confirmed != upload.receipts.len()
            || upload.receipts.last().map_or(0, |r| r.1)
                != record._request["size"].as_u64().expect("declared size")
        {
            bail!("native upload result incomplete");
        }
        upload.result = Some(NativeUploadOutcome {
            identity: NativeIdentity {
                session_id: event.session_id.clone(),
                operation_id: event.operation_id.clone(),
            },
            path: record._request["path"]
                .as_str()
                .expect("declared path")
                .to_owned(),
            size: record._request["size"].as_u64().expect("declared size"),
            sha256: record._request["sha256"]
                .as_str()
                .expect("declared digest")
                .to_owned(),
        });
    }
    record.truth_revision += 1;
    upload.revision = record.truth_revision;
    record.unknown = false;
    record.notify.notify_waiters();
    Ok(())
}
fn checked_frame_fingerprint(frame: &Envelope, framing: NativeFraming) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(frame)?;
    if bytes.len() + 1 > LINE || bytes.len() + framing.signed_delta > LINE {
        bail!("native command bounds");
    }
    Ok(Sha256::digest(bytes).into())
}
#[derive(Clone)]
pub struct NativeMetadataHandle {
    client: Arc<NativeClient>,
    identity: NativeIdentity,
}
impl NativeMetadataHandle {
    pub fn identity(&self) -> &NativeIdentity {
        &self.identity
    }
    pub async fn cancel(&self) -> Result<()> {
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("cancel")
        .await
    }
    pub async fn query(&self) -> Result<NativeMetadataReceipt> {
        self.phase(None).await
    }
    pub async fn wait(&self) -> Result<NativeMetadataReceipt> {
        let until = self.deadline();
        let result = self.observe(None, None, until).await;
        self.finish_deadline(result, until)
    }
    pub fn complete(&self) -> bool {
        self.client.state.lock().expect("native state").records[&self.identity.operation_id]
            .metadata
            .as_ref()
            .is_some_and(|c| c.complete)
    }
    /// Project only bytes already validated and retained for this original cursor.
    pub fn cached_page(&self, cursor: u64) -> Result<super::native_metadata::NativeListPage> {
        let state = self.client.state.lock().expect("native state");
        let r = &state.records[&self.identity.operation_id];
        if r.kind != "list_begin" {
            bail!("native original is not a list");
        }
        r.metadata.as_ref().expect("metadata").page(cursor)
    }
    pub async fn next(&self, cursor: u64) -> Result<NativeMetadataReceipt> {
        self.phase(Some(cursor)).await
    }
    fn reserve_phase(&self, cursor: Option<u64>) -> Result<(MetadataPhaseLease, bool)> {
        let until = self.deadline();
        let mut state = self.client.state.lock().expect("native state");
        let closed = state.caller_admission_closed;
        let r = state
            .records
            .get_mut(&self.identity.operation_id)
            .expect("original metadata");
        if Instant::now() >= until || r.aborted || r.cancel_intent || !self.client.is_ready() {
            bail!("native metadata phase unavailable");
        }
        if let Some(cursor) = cursor {
            if closed
                || r.unknown
                || r.kind != "list_begin"
                || !r.metadata.as_ref().expect("metadata").boundary(cursor)
            {
                bail!("native list boundary unavailable");
            }
            if r.metadata_query.is_some() {
                bail!("native metadata query pending");
            }
        } else if r
            .metadata_next
            .is_some_and(|p| Instant::now() < p.until && !(r.unknown && p.waiters == 0))
        {
            bail!("native metadata page pending");
        }
        let existing = if cursor.is_some() {
            r.metadata_next.as_mut()
        } else {
            r.metadata_query.as_mut()
        };
        if let Some(p) = existing {
            if p.cursor != cursor || Instant::now() >= p.until || p.waiters == 32 {
                bail!("native metadata distinct or expired phase");
            }
            p.waiters += 1;
            let phase = *p;
            return Ok((
                MetadataPhaseLease {
                    client: self.client.clone(),
                    id: self.identity.operation_id.clone(),
                    phase,
                },
                false,
            ));
        }
        r.metadata_phase_serial = r
            .metadata_phase_serial
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("native metadata phase capacity"))?;
        let phase = MetadataPhase {
            token: r.metadata_phase_serial,
            until,
            prior: (r.metadata_truth_revision, r.truth_revision),
            cursor,
            queued: false,
            written: false,
            waiters: 1,
        };
        if cursor.is_some() {
            r.metadata_next = Some(phase);
        } else {
            r.metadata_query = Some(phase);
        }
        Ok((
            MetadataPhaseLease {
                client: self.client.clone(),
                id: self.identity.operation_id.clone(),
                phase,
            },
            true,
        ))
    }
    async fn phase(&self, cursor: Option<u64>) -> Result<NativeMetadataReceipt> {
        let (lease, fresh) = self.reserve_phase(cursor)?;
        let phase = lease.phase;
        let result = async {
            if fresh {
                {
                    let mut state = self.client.state.lock().expect("native state");
                    let r = state
                        .records
                        .get_mut(&self.identity.operation_id)
                        .expect("metadata");
                    let slot = if cursor.is_some() {
                        &mut r.metadata_next
                    } else {
                        &mut r.metadata_query
                    };
                    if let Some(p) = slot.as_mut().filter(|p| p.token == phase.token) {
                        p.queued = true;
                    }
                }
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(phase.until),
                    self.client.tx.send(Envelope {
                        kind: if cursor.is_some() {
                            "list_next"
                        } else {
                            "query"
                        }
                        .into(),
                        session_id: self.identity.session_id.clone(),
                        operation_id: self.identity.operation_id.clone(),
                        payload: cursor
                            .map_or_else(|| json!({}), |cursor| json!({"cursor":cursor})),
                    }),
                )
                .await??;
            }
            self.observe_phase(phase).await
        }
        .await;
        let result = self.finish_deadline(result, phase.until);
        drop(lease);
        result
    }
    async fn observe_phase(&self, phase: MetadataPhase) -> Result<NativeMetadataReceipt> {
        loop {
            let notify = self.client.state.lock().expect("native state").records
                [&self.identity.operation_id]
                .notify
                .clone();
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.client.state.lock().expect("native state");
                let r = &state.records[&self.identity.operation_id];
                let c = r.metadata.as_ref().expect("metadata");
                if Instant::now() >= phase.until {
                    bail!("native metadata deadline");
                }
                let completed = if phase.cursor.is_some() {
                    r.metadata_completed_next
                } else {
                    r.metadata_completed_query
                };
                if completed >= phase.token {
                    if let Some(cursor) = phase.cursor {
                        if let Some(NativeMetadataReceipt::ListResult(summary)) = &c.receipt {
                            if cursor == summary.count {
                                return Ok(NativeMetadataReceipt::ListResult(summary.clone()));
                            }
                        }
                        if let Ok(page) = c.page(cursor) {
                            return Ok(NativeMetadataReceipt::ListPage(page));
                        }
                    }
                    match r.metadata_response {
                        Some(MetadataResponse::Page(cursor)) if phase.cursor.is_none() => {
                            return Ok(NativeMetadataReceipt::ListPage(c.page(cursor)?))
                        }
                        _ => {}
                    }
                    if let Some(receipt) = &c.receipt {
                        return Ok(receipt.clone());
                    }
                    bail!("native metadata receipt absent");
                }
                if r.aborted
                    || r.cancel_intent
                    || (r.unknown && r.truth_revision > phase.prior.1)
                    || !self.client.is_ready()
                {
                    bail!("native metadata UNKNOWN");
                }
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(phase.until), changed).await?;
        }
    }
    fn deadline(&self) -> Instant {
        self.client
            .expires
            .min(Instant::now() + std::time::Duration::from_secs(3))
    }
    fn finish_deadline(
        &self,
        result: Result<NativeMetadataReceipt>,
        until: Instant,
    ) -> Result<NativeMetadataReceipt> {
        if Instant::now() >= until {
            let mut state = self.client.state.lock().expect("native state");
            let r = state
                .records
                .get_mut(&self.identity.operation_id)
                .expect("original metadata");
            r.unknown = true;
            r.notify.notify_waiters();
            bail!("native metadata deadline");
        }
        result
    }
    async fn observe(
        &self,
        prior: Option<(u64, u64)>,
        cursor: Option<u64>,
        until: Instant,
    ) -> Result<NativeMetadataReceipt> {
        loop {
            let notify = self.client.state.lock().expect("native state").records
                [&self.identity.operation_id]
                .notify
                .clone();
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.client.state.lock().expect("native state");
                let r = &state.records[&self.identity.operation_id];
                let c = r.metadata.as_ref().expect("metadata");
                if Instant::now() >= until {
                    bail!("native metadata deadline");
                }
                if r.aborted
                    || r.cancel_intent
                    || (r.unknown && prior.is_none_or(|p| r.truth_revision > p.1))
                {
                    bail!("native metadata UNKNOWN");
                }
                if prior.is_none_or(|p| r.metadata_truth_revision > p.0) {
                    if let Some(cursor) = cursor {
                        if let Some(NativeMetadataReceipt::ListResult(summary)) = &c.receipt {
                            if cursor == summary.count {
                                return Ok(NativeMetadataReceipt::ListResult(summary.clone()));
                            }
                        }
                        if let Ok(page) = c.page(cursor) {
                            return Ok(NativeMetadataReceipt::ListPage(page));
                        }
                    } else if let Some(receipt) = &c.receipt {
                        return Ok(receipt.clone());
                    } else if let Ok(page) = c.page(0) {
                        return Ok(NativeMetadataReceipt::ListPage(page));
                    }
                }
                if !self.client.is_ready() {
                    bail!("native metadata UNKNOWN");
                }
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(until), changed).await?;
        }
    }
}
impl NativeFileHandle {
    /// Frozen original operation identity; callers cannot redirect this handle.
    pub fn identity(&self) -> &NativeIdentity {
        &self.identity
    }
    pub async fn cancel(&self) -> Result<()> {
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("cancel")
        .await
    }
    pub async fn query_result(&self) -> Result<NativeFileOutcome> {
        let revision = {
            let state = self.client.state.lock().expect("native state");
            let record = &state.records[&self.identity.operation_id];
            if record.aborted || !record.dispatched || !self.client.is_ready() {
                bail!(
                    "native file {} query unavailable",
                    self.identity.operation_id
                );
            }
            record.truth_revision
        };
        NativeHandle {
            client: self.client.clone(),
            identity: self.identity.clone(),
        }
        .control("query")
        .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.observe(Some(revision)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("native file {} query deadline", self.identity.operation_id))?
    }
    pub async fn wait(&self) -> Result<NativeFileOutcome> {
        self.observe(None).await
    }
    async fn observe(&self, revision: Option<u64>) -> Result<NativeFileOutcome> {
        loop {
            let notify = self.client.state.lock().expect("native state").records
                [&self.identity.operation_id]
                .notify
                .clone();
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.client.state.lock().expect("native state");
                let record = &state.records[&self.identity.operation_id];
                if record.aborted {
                    bail!(
                        "native file {} cancelled before dispatch",
                        self.identity.operation_id
                    );
                }
                if revision.is_none_or(|prior| record.truth_revision > prior) {
                    if revision.is_none_or(|prior| record.file_truth_revision > prior) {
                        if let Some(result) = &record.file_result {
                            return Ok(result.clone());
                        }
                    }
                    if revision.is_some() || record.unknown {
                        bail!(
                            "native file {} incomplete; query original identity",
                            self.identity.operation_id
                        );
                    }
                }
                if !self.client.is_ready() {
                    bail!(
                        "native file {} UNKNOWN; query original identity",
                        self.identity.operation_id
                    );
                }
            }
            changed.await;
        }
    }
}
fn validate_file_result(record: &Record, event: &Envelope) -> Result<NativeFileOutcome> {
    if !record.dispatched || record.aborted {
        bail!("native file result before dispatch");
    }
    let fields = event
        .payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("native file result shape"))?;
    if fields.len() != 4
        || !["path", "offset", "data", "sha256"]
            .iter()
            .all(|key| fields.contains_key(*key))
        || event.payload["path"] != record._request["path"]
        || event.payload["offset"] != record._request["offset"]
    {
        bail!("native file result identity");
    }
    let encoded = event.payload["data"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("native file data"))?;
    if encoded.len() > 21848 {
        bail!("native file result bounds");
    }
    let data = STANDARD.decode(encoded)?;
    if data.len() > 16384 || STANDARD.encode(&data) != encoded {
        bail!("native file encoding");
    }
    let digest = format!("{:x}", Sha256::digest(&data));
    if event.payload["sha256"].as_str() != Some(digest.as_str()) {
        bail!("native file digest");
    }
    match record.kind.as_str() {
        "file_read" if data.len() as u64 <= record._request["length"].as_u64().unwrap_or(0) => {}
        "file_write" if event.payload["data"] == record._request["data"] => {}
        _ => bail!("native file result scope"),
    }
    if record
        .file_result
        .as_ref()
        .is_some_and(|old| old.data != data || old.sha256 != digest)
    {
        bail!("native file result conflict");
    }
    Ok(NativeFileOutcome {
        identity: NativeIdentity {
            session_id: event.session_id.clone(),
            operation_id: event.operation_id.clone(),
        },
        path: record._request["path"]
            .as_str()
            .expect("frozen file path")
            .into(),
        offset: record._request["offset"]
            .as_u64()
            .expect("frozen file offset"),
        data,
        sha256: digest,
    })
}
fn effect(kind: &str) -> bool {
    matches!(
        kind,
        "exec"
            | "file_read"
            | "file_write"
            | "upload_begin"
            | "download_begin"
            | "file_stat"
            | "make_dir"
            | "list_begin"
    )
}
/// Dispatch and dequeue consult the already-frozen cancellation intent, rather
/// than waiting for the actor to consume a later cancel message.
fn abort_undispatched_cancelled(client: &NativeClient, id: &str) -> bool {
    let mut state = client.state.lock().expect("native state");
    let Some(record) = state.records.get_mut(id) else {
        return false;
    };
    if !record.dispatched && record.cancel_intent {
        record.aborted = true;
        record.notify.notify_waiters();
        return true;
    }
    false
}
fn mark_dispatched(client: &NativeClient, id: &str) -> bool {
    let mut state = client.state.lock().expect("native state");
    if state.caller_admission_closed {
        if let Some(record) = state.records.get_mut(id) {
            record.unknown = true;
            record.notify.notify_waiters();
        }
        return false;
    }
    let record = state.records.get_mut(id).expect("reserved native record");
    // Freeze dispatch and local cancellation under the same registry lock.
    if !record.dispatched && record.cancel_intent {
        record.aborted = true;
        record.notify.notify_waiters();
        return false;
    }
    record.dispatched = true;
    true
}
/// Carry survives select cancellation; no unbounded read_line allocation.
pub(crate) async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    carry: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    read_line_clock(
        reader,
        carry,
        &mut None,
        Instant::now() + std::time::Duration::from_secs(240),
    )
    .await
}
async fn read_line_clock<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    carry: &mut Vec<u8>,
    deadline: &mut Option<Instant>,
    expires: Instant,
) -> Result<Vec<u8>> {
    loop {
        let until = deadline.unwrap_or(expires).min(expires);
        if Instant::now() >= until {
            bail!("native read deadline");
        }
        let bytes =
            tokio::time::timeout_at(tokio::time::Instant::from_std(until), reader.fill_buf())
                .await??;
        if bytes.is_empty() {
            bail!("native pipe closed");
        }
        let until = *deadline.get_or_insert_with(|| {
            (Instant::now() + std::time::Duration::from_secs(3)).min(expires)
        });
        if Instant::now() >= until {
            bail!("native read deadline");
        }
        let end = bytes.iter().position(|v| *v == b'\n');
        let count = end.map(|n| n + 1).unwrap_or(bytes.len());
        if carry.len() + count > LINE {
            bail!("native pipe bounds");
        }
        carry.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            if Instant::now() >= until || Instant::now() >= expires {
                bail!("native read deadline");
            }
            carry.pop();
            *deadline = None;
            return Ok(std::mem::take(carry));
        }
    }
}

async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Envelope,
    expires: Instant,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(message)?;
    if bytes.len() + 1 > LINE {
        bail!("native pipe bounds");
    }
    bytes.push(b'\n');
    let until = expires.min(Instant::now() + std::time::Duration::from_secs(3));
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(until),
        writer.write_all(&bytes),
    )
    .await??;
    if Instant::now() >= until {
        bail!("native write deadline");
    }
    Ok(())
}
fn metadata_phase_written(client: &NativeClient, id: &str, cursor: Option<u64>) {
    let mut state = client.state.lock().expect("native state");
    let r = state.records.get_mut(id).expect("original phase");
    let slot = if cursor.is_some() {
        &mut r.metadata_next
    } else {
        &mut r.metadata_query
    };
    if let Some(p) = slot.as_mut().filter(|p| p.cursor == cursor && p.queued) {
        p.written = true;
    }
}
async fn actor<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    client: Arc<NativeClient>,
    mut reader: R,
    mut writer: W,
    mut rx: mpsc::Receiver<Envelope>,
    expires: Instant,
) {
    let mut carry = Vec::new();
    let mut frame_deadline: Option<Instant> = None;
    let mut queued = VecDeque::<Envelope>::new();
    let mut active: Option<String> = None;
    let result: Result<()> = async {
        loop {
            if Instant::now() >= frame_deadline.unwrap_or(expires).min(expires) { bail!("native frame deadline"); }
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(expires)) => bail!("native incarnation expired"),
                request = rx.recv() => { let request = request.ok_or_else(|| anyhow::anyhow!("native actor closed"))?; if !client.is_ready() { bail!("native actor closed"); }
                    if abort_undispatched_cancelled(&client,&request.operation_id) {
                        // Cancellation is frozen in the record before the control
                        // message is consumed; neither begin nor stale cancel crosses IPC.
                    }
                    else if matches!(request.kind.as_str(),"download_next"|"download_retain") {
                        if active.as_deref()!=Some(request.operation_id.as_str()) {bail!("native download inactive advancement");}
                        if mark_download_advance(&client,&request)? {send(&mut writer,&request,frame_deadline.unwrap_or(expires).min(expires)).await?;}
                    }
                    else if matches!(request.kind.as_str(),"upload_chunk"|"upload_commit") {
                        if active.as_deref()!=Some(request.operation_id.as_str()) {bail!("native upload inactive advancement");}
                        if mark_upload_advance(&client,&request)? {send(&mut writer,&request,frame_deadline.unwrap_or(expires).min(expires)).await?;}
                    }
                    else if request.kind=="list_next" {
                        let allowed_until={let state=client.state.lock().expect("native state");let record=state.records.get(&request.operation_id).ok_or_else(||anyhow::anyhow!("native list owner"))?;
                            if !state.caller_admission_closed&&!record.unknown&&!record.cancel_intent&&record.kind=="list_begin" {record.metadata_next.filter(|p|p.queued&&p.cursor==request.payload["cursor"].as_u64()&&Instant::now()<p.until).map(|p|p.until)}else{None}};
                        if let Some(until)=allowed_until {send(&mut writer,&request,until.min(frame_deadline.unwrap_or(expires)).min(expires)).await?;metadata_phase_written(&client,&request.operation_id,request.payload["cursor"].as_u64());}
                    }
                    else if effect(&request.kind) && active.is_some() { queued.push_back(request); }
                    else if let Some(index) = queued.iter().position(|pending| pending.operation_id == request.operation_id) {
                        if request.kind == "cancel" { queued.remove(index); let mut state = client.state.lock().expect("native state"); let record = state.records.get_mut(&request.operation_id).expect("reserved native record"); record.aborted = true; record.notify.notify_waiters(); }
                        // A queued query observes the locally reserved identity; no guest effect exists yet.
                    } else { if effect(&request.kind) { if !mark_dispatched(&client,&request.operation_id) {continue;} active = Some(request.operation_id.clone()); } let until=if request.kind=="query" {let state=client.state.lock().expect("native state");state.records.get(&request.operation_id).and_then(|r|r.metadata_query).map_or(expires,|p|p.until)}else{expires};send(&mut writer, &request, until.min(frame_deadline.unwrap_or(expires)).min(expires)).await?;if request.kind=="query" {metadata_phase_written(&client,&request.operation_id,None);} } },
                line = read_line_clock(&mut reader, &mut carry, &mut frame_deadline, expires) => {
                    if Instant::now() >= expires { bail!("native incarnation expired"); }
                    let event: Envelope = serde_json::from_slice(&line?)?;
                    if event.session_id != client.session { bail!("native identity mismatch"); }
                    let download_event=matches!(event.kind.as_str(),"download_progress"|"download_chunk"|"download_result");
                    let download_ack=if download_event {retain_download_event(&client,&event).await?}else{None};
                    if event.kind=="download_result" && active.as_deref()==Some(event.operation_id.as_str()) {active=None;}
                    let ack = if download_event {download_ack} else {
                        let mut state = client.state.lock().expect("native state");
                        let total = state.bytes;
                        let chunk_total = state.chunks;
                        let record = state.records.get_mut(&event.operation_id).ok_or_else(|| anyhow::anyhow!("native unknown identity"))?;
                        if let Some(prefix) = event.payload.get("acked_sequence") {
                            let prefix = prefix.as_u64().ok_or_else(|| anyhow::anyhow!("native acknowledgement prefix"))?;
                            let prefix = usize::try_from(prefix)?;
                            if prefix < record.acked || prefix > record.chunks.len() || prefix > record.ack_sent { bail!("native acknowledgement prefix bounds"); }
                            record.acked = prefix;
                        }
                        match event.kind.as_str() {
                            "output" => {
                                if record.kind!="exec" { bail!("native file output refused"); }
                                let sequence = event.payload["sequence"].as_u64().ok_or_else(|| anyhow::anyhow!("native sequence"))? as usize;
                                let stream = event.payload["stream"].as_str().ok_or_else(|| anyhow::anyhow!("native stream"))?;
                                let data = STANDARD.decode(event.payload["data"].as_str().ok_or_else(|| anyhow::anyhow!("native output"))?)?;
                                if data.is_empty() || data.len()>16384 || !matches!(stream,"stdout"|"stderr") { bail!("native output bounds"); }
                                if sequence < record.chunks.len() { if record.chunks[sequence] != (stream.to_owned(), data.len(), Sha256::digest(&data).into()) { bail!("native output conflict"); } }
                                else { if sequence != record.chunks.len() || total+data.len()>OUTPUT || chunk_total>=4096 { bail!("native retention bounds"); }
                                    if stream=="stdout" { record.stdout.extend_from_slice(&data); } else { record.stderr.extend_from_slice(&data); } record.chunks.push((stream.to_owned(),data.len(),Sha256::digest(&data).into())); state.bytes+=data.len(); state.chunks+=1; }
                                Some(Envelope { kind:"retain_ack".into(), session_id:client.session.clone(), operation_id:event.operation_id, payload:json!({"sequence":sequence}) })
                            },
                            "terminal" => {
                                if record.kind!="exec" { bail!("native file terminal refused"); }
                                if event.payload["process_absent"] != true || event.payload["stdout_bytes"].as_u64()!=Some(record.stdout.len() as u64) || event.payload["stderr_bytes"].as_u64()!=Some(record.stderr.len() as u64) { bail!("native terminal incomplete"); }
                                let status=event.payload["state"].as_str().unwrap_or("");
                                if !matches!(status,"succeeded"|"failed"|"cancelled"|"timed_out") { bail!("native terminal state"); }
                                let code = event.payload["exit_code"].as_i64();
                                if matches!(status,"succeeded"|"failed") && (!code.is_some_and(|v| (-255..=255).contains(&v)) || (code==Some(0)) != (status=="succeeded")) { bail!("native terminal exit"); }
                                if record.terminal.as_ref().is_some_and(|old| ["state","exit_code","stdout_bytes","stderr_bytes","process_absent"].iter().any(|field| old[*field] != event.payload[*field])) { bail!("native terminal conflict"); }
                                record.terminal=Some(event.payload); record.truth_revision+=1; record.status_truth_revision=record.truth_revision; record.status_truth_kind=Some(StatusTruthKind::Terminal); record.unknown=false; record.notify.notify_waiters();
                                if active.as_deref()==Some(event.operation_id.as_str()) { active=None; } None
                            },
                            "upload_progress" | "upload_result" => {
                                retain_upload_event(record,&event)?;
                                if event.kind=="upload_result" && active.as_deref()==Some(event.operation_id.as_str()) {active=None;}
                                None
                            },
                            "file_stat_result" | "make_dir_result" | "list_page" | "list_result" => {
                                if !record.dispatched||record.aborted||record.cancel_intent {bail!("native metadata receipt owner");}
                                let cache=record.metadata.as_mut().ok_or_else(||anyhow::anyhow!("native metadata kind"))?;
                                cache.retain(&record.kind,record._request["path"].as_str().expect("metadata path"),&event.kind,&event.payload)?;
                                let complete=cache.complete;
                                record.truth_revision+=1;record.metadata_truth_revision=record.truth_revision;
                                record.metadata_response=Some(if event.kind=="list_page" {MetadataResponse::Page(event.payload["cursor"].as_u64().expect("validated cursor"))}else{MetadataResponse::Receipt});
                                if let Some(p)=record.metadata_next {if p.written&&((event.kind=="list_page"&&p.cursor==event.payload["cursor"].as_u64()&&p.cursor!=event.payload["count"].as_u64())||(event.kind=="list_result"&&p.cursor==event.payload["count"].as_u64())) {record.metadata_completed_next=p.token;record.metadata_next=None;}}
                                if let Some(p)=record.metadata_query {if p.written {record.metadata_completed_query=p.token;record.metadata_query=None;}}
                                record.unknown=false;record.notify.notify_waiters();
                                if complete&&active.as_deref()==Some(event.operation_id.as_str()){active=None;} None
                            },
                            "file_result" => {
                                let result=validate_file_result(record,&event)?;
                                let newly_retained=record.file_result.is_none();
                                if newly_retained && total+result.data.len()>OUTPUT { bail!("native file retention bounds"); }
                                let retained_bytes=if newly_retained {result.data.len()} else {0};
                                record.file_result=Some(result); record.truth_revision+=1; record.file_truth_revision=record.truth_revision; record.unknown=false; record.notify.notify_waiters();
                                state.bytes+=retained_bytes;
                                if active.as_deref()==Some(event.operation_id.as_str()) { active=None; } None
                            },
                            "error" => { if let Some(upload)=record.upload.as_mut() {upload.observed=false;}
                                if let Some(download)=record.download.as_mut(){download.observed=false;download.revision+=1;} record.unknown=true; record.truth_revision+=1; record.notify.notify_waiters(); None },
                            "status" => {
                                let payload=event.payload.as_object().ok_or_else(||anyhow::anyhow!("native status payload"))?;
                                if !payload.contains_key("state") || payload.keys().any(|field|!matches!(field.as_str(),"state"|"acked_sequence"))
                                    || !matches!(event.payload["state"].as_str(),Some("accepted"|"running"|"terminal"|"unknown"|"not_found")) {bail!("native status schema");}
                                if let Some(upload)=record.upload.as_mut() {upload.observed=false; record.unknown=true;}
                                if let Some(download)=record.download.as_mut(){download.observed=false;download.revision+=1;record.unknown=true;}
                                if record.kind!="exec" && event.payload["state"]=="unknown" { record.unknown=true; } record.status=Some(event.payload); record.truth_revision+=1; record.status_truth_revision=record.truth_revision; record.status_truth_kind=Some(StatusTruthKind::Status); record.notify.notify_waiters(); None },
                            "ack" => { if record.kind!="exec" { bail!("native file acknowledgement refused"); } None },
                            _ => bail!("native event refused"),
                        }
                    };
                    if let Some(ack)=ack {
                        if ack.kind=="download_retain" {
                            if mark_download_advance(&client,&ack)? {send(&mut writer,&ack,expires).await?;}
                        } else {
                        send(&mut writer,&ack,expires).await?;
                        let prefix = usize::try_from(ack.payload["sequence"].as_u64().expect("retained sequence"))? + 1;
                        let mut state = client.state.lock().expect("native state");
                        let record = state.records.get_mut(&ack.operation_id).expect("retained record");
                        record.ack_sent = record.ack_sent.max(prefix);
                        }
                    }
                    if active.is_none() {
                        while let Some(next)=queued.pop_front() {
                            if abort_undispatched_cancelled(&client,&next.operation_id) {continue;}
                            if !mark_dispatched(&client,&next.operation_id) {continue;} active=Some(next.operation_id.clone());send(&mut writer,&next,expires).await?;break;
                        }
                    }
                }
            }
        }
    }.await;
    if let Err(error) = &result {
        // Closed failure-origin diagnostic: never print arbitrary error text or wire data.
        let origin = match error.to_string().as_str() {
            "native metadata full digest" => "metadata_full_digest",
            "native metadata receipt owner" => "metadata_receipt_owner",
            "native metadata kind" => "metadata_kind",
            "native list owner" => "metadata_phase_owner",
            "native pipe closed" => "pipe_closed",
            "native read deadline" => "read_deadline",
            "native write deadline" => "write_deadline",
            "native incarnation expired" => "incarnation_expired",
            _ => "other_refusal",
        };
        eprintln!("native actor failure origin={origin}");
        client.fail();
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn native_capability_policy_cannot_enable_unqualified_directory_or_allocate_records() {
        for bound in [false, true] {
            let (stream, peer) = tokio::io::duplex(65536);
            let (reader, writer) = tokio::io::split(stream);
            let reader = tokio::io::BufReader::new(reader);
            let until = Instant::now() + std::time::Duration::from_secs(5);
            let client = if bound {
                NativeClient::install_authenticated_profile(
                    reader,
                    writer,
                    until,
                    minimum_framing(),
                    None,
                    "a".repeat(64),
                    true,
                )
            } else {
                NativeClient::install(reader, writer, until, minimum_framing())
            };
            let control = super::super::native_control::NativeControl::new(client.clone());
            assert!(!client.directory_available());
            assert!(!client.download_available());
            assert!(!control
                .operations()
                .iter()
                .any(|op| op.starts_with("download_")));
            {
                let state = client.state.lock().unwrap();
                assert!(state.records.is_empty());
                assert_eq!(state.bytes, 0);
                assert_eq!(state.lifetime_admissions, 0);
            }
            client.close();
            drop(peer);
        }
    }
    use super::*;
    use tokio::io::{split, BufReader};
    fn guest_lexical_test_digest(value: serde_json::Value) -> String {
        fn lexical(value: serde_json::Value) -> serde_json::Value {
            match value {
                serde_json::Value::Object(map) => {
                    let sorted: std::collections::BTreeMap<_, _> = map
                        .into_iter()
                        .map(|(key, value)| (key, lexical(value)))
                        .collect();
                    serde_json::Value::Object(sorted.into_iter().collect())
                }
                serde_json::Value::Array(values) => {
                    serde_json::Value::Array(values.into_iter().map(lexical).collect())
                }
                value => value,
            }
        }
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&lexical(value)).unwrap())
        )
    }
    fn fixture() -> (
        Arc<NativeClient>,
        BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    ) {
        let (host, broker) = tokio::io::duplex(131072);
        let (read, write) = split(host);
        let (peer_read, peer_write) = split(broker);
        (
            NativeClient::install(
                BufReader::new(read),
                write,
                Instant::now() + std::time::Duration::from_secs(30),
                minimum_framing(),
            ),
            BufReader::new(peer_read),
            peer_write,
        )
    }
    async fn receive<R: AsyncBufRead + Unpin>(read: &mut R) -> Envelope {
        serde_json::from_slice(&read_line(read, &mut Vec::new()).await.unwrap()).unwrap()
    }
    async fn metadata_admission_ticket(kind: &str, expected: usize) {
        let (client, mut read, _write) = fixture();
        let identity = client.reserve(kind, json!({"path":"."})).unwrap();
        let ticket = client.state.lock().unwrap().bytes;
        let frame = receive(&mut read).await;
        let owned_mutation = effect(kind);
        client.close();
        assert_eq!(frame.kind, kind);
        assert_eq!(frame.operation_id, identity.operation_id);
        assert!(
            ticket >= expected && owned_mutation,
            "ticket={ticket} expected={expected} owned_mutation={owned_mutation}"
        );
    }
    #[tokio::test]
    async fn native_metadata_stat_reserves_ticket_before_actual_dispatch() {
        metadata_admission_ticket("file_stat", 32768).await;
    }
    #[tokio::test]
    async fn native_metadata_mkdir_reserves_ticket_before_actual_dispatch() {
        metadata_admission_ticket("make_dir", 32768).await;
    }
    #[tokio::test]
    async fn native_metadata_list_reserves_ticket_before_actual_dispatch() {
        metadata_admission_ticket("list_begin", 524288).await;
    }
    #[tokio::test]
    async fn native_metadata_authenticated_summary_before_page_keeps_serial_slot() {
        let (client, mut read, mut write) = fixture();
        let list = client.start_metadata("list_begin", ".", None).unwrap();
        let original = receive(&mut read).await;
        let entry = json!({"name":"a","type":"file","path":"a","size":0,"mode":0o100600,"permissions":"rw-------","owner":"1000","group":"1000","modified_time":{"seconds":0,"nanos":0},"symlink_target":null,"version":{"device":1,"inode":2,"size":0,"mtime_seconds":0,"mtime_nanos":0,"ctime_seconds":0,"ctime_nanos":0}});
        let digest = guest_lexical_test_digest(json!([entry.clone()]));
        let version = json!({"device":1,"inode":3,"size":0,"mtime_seconds":0,"mtime_nanos":0,"ctime_seconds":0,"ctime_nanos":0});
        reply(
            &mut write,
            &Envelope {
                kind: "list_result".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: json!({"path":".","count":1,"snapshot_sha256":digest,"version":version}),
            },
        )
        .await;
        assert!(matches!(
            list.wait().await.unwrap(),
            NativeMetadataReceipt::ListResult(_)
        ));
        let next = client.start_metadata("file_stat", "missing", None).unwrap();
        let held = tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
            .await
            .is_err();
        reply(&mut write,&Envelope{kind:"list_page".into(),session_id:original.session_id.clone(),operation_id:original.operation_id.clone(),payload:json!({"path":".","cursor":0,"next_cursor":1,"count":1,"entries":[entry],"snapshot_sha256":digest,"version":version})}).await;
        let dispatched = receive(&mut read).await;
        reply(
            &mut write,
            &Envelope {
                kind: "file_stat_result".into(),
                session_id: dispatched.session_id.clone(),
                operation_id: dispatched.operation_id.clone(),
                payload: json!({"path":"missing","entry":null}),
            },
        )
        .await;
        let final_stat = next.wait().await.unwrap();
        let cache_complete = client.state.lock().unwrap().records[&original.operation_id]
            .metadata
            .as_ref()
            .unwrap()
            .complete;
        client.close();
        assert!(held && cache_complete);
        assert_eq!(dispatched.operation_id, next.identity.operation_id);
        assert!(matches!(
            final_stat,
            NativeMetadataReceipt::FileStatResult(_)
        ));
    }
    #[tokio::test]
    async fn native_metadata_late_confirmed_receipt_cannot_pass_original_deadline() {
        let (client, mut read, mut write) = fixture();
        let h = client.start_metadata("file_stat", "missing", None).unwrap();
        let req = receive(&mut read).await;
        let until = Instant::now();
        reply(
            &mut write,
            &Envelope {
                kind: "file_stat_result".into(),
                session_id: req.session_id,
                operation_id: req.operation_id.clone(),
                payload: json!({"path":"missing","entry":null}),
            },
        )
        .await;
        assert!(matches!(
            h.wait().await.unwrap(),
            NativeMetadataReceipt::FileStatResult(_)
        ));
        let observed = h.observe(None, None, until).await;
        let late = h.finish_deadline(observed, until).is_err();
        let retained = {
            let state = client.state.lock().unwrap();
            let original = &state.records[&req.operation_id];
            original.unknown
                && original.metadata.as_ref().unwrap().complete
                && state.records.len() == 1
        };
        let no_repeat =
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err();
        client.close();
        assert!(late && retained && no_repeat);
    }
    #[tokio::test]
    async fn native_metadata_pending_page_refuses_distinct_final_before_pipe_and_summary() {
        let (client, mut read, mut write) = fixture();
        let h = client.start_metadata("list_begin", ".", None).unwrap();
        let original = receive(&mut read).await;
        let entry = json!({"name":"a","type":"file","path":"a","size":0,"mode":0o100600,"permissions":"rw-------","owner":"1000","group":"1000","modified_time":{"seconds":0,"nanos":0},"symlink_target":null,"version":{"device":1,"inode":2,"size":0,"mtime_seconds":0,"mtime_nanos":0,"ctime_seconds":0,"ctime_nanos":0}});
        let sha = guest_lexical_test_digest(json!([entry.clone()]));
        let version = json!({"device":1,"inode":3,"size":0,"mtime_seconds":0,"mtime_nanos":0,"ctime_seconds":0,"ctime_nanos":0});
        let page = json!({"path":".","cursor":0,"next_cursor":1,"count":1,"entries":[entry],"snapshot_sha256":sha,"version":version});
        reply(
            &mut write,
            &Envelope {
                kind: "list_page".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: page.clone(),
            },
        )
        .await;
        assert!(matches!(
            h.wait().await.unwrap(),
            NativeMetadataReceipt::ListPage(_)
        ));
        let before = {
            let state = client.state.lock().unwrap();
            let r = &state.records[&original.operation_id];
            (
                r.unknown,
                r.truth_revision,
                state.records.len(),
                state.bytes,
                state.lifetime_admissions,
            )
        };
        let h0 = h.clone();
        let mut first = tokio::spawn(async move { h0.next(0).await });
        let first_frame = receive(&mut read).await;
        let h1 = h.clone();
        let mut distinct = tokio::spawn(async move { h1.next(1).await });
        let refusal =
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut distinct).await;
        let distinct_refused = matches!(&refusal, Ok(Ok(Err(_))));
        if refusal.is_err() {
            distinct.abort();
            let _ = distinct.await;
        }
        let second =
            tokio::time::timeout(std::time::Duration::from_millis(30), receive(&mut read)).await;
        let no_second_frame = second.is_err();
        let after = {
            let state = client.state.lock().unwrap();
            let r = &state.records[&original.operation_id];
            (
                r.unknown,
                r.truth_revision,
                state.records.len(),
                state.bytes,
                state.lifetime_admissions,
            )
        };
        reply(
            &mut write,
            &Envelope {
                kind: "list_result".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: json!({"path":".","count":1,"snapshot_sha256":sha,"version":version}),
            },
        )
        .await;
        let summary_observation =
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut first).await;
        let summary_stays_pending = summary_observation.is_err();
        if summary_stays_pending {
            reply(
                &mut write,
                &Envelope {
                    kind: "list_page".into(),
                    session_id: original.session_id.clone(),
                    operation_id: original.operation_id.clone(),
                    payload: page,
                },
            )
            .await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), &mut first).await;
        }
        if !first.is_finished() {
            first.abort();
            let _ = first.await;
        }
        client.close();
        assert_eq!(first_frame.kind, "list_next");
        assert_eq!(first_frame.operation_id, original.operation_id);
        assert!(distinct_refused&&no_second_frame&&before==after&&summary_stays_pending,"distinct_refused={distinct_refused} no_second_frame={no_second_frame} unchanged={} summary_stays_pending={summary_stays_pending}",before==after);
    }
    struct MetadataFixture {
        client: Arc<NativeClient>,
        h: NativeMetadataHandle,
        read: tokio::io::BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
        original: Envelope,
        page: Value,
        summary: Value,
    }
    async fn metadata_cached_one_page() -> MetadataFixture {
        let (client, mut read, mut write) = fixture();
        let h = client.start_metadata("list_begin", ".", None).unwrap();
        let original = receive(&mut read).await;
        let entry = json!({"name":"a","type":"file","path":"a","size":0,"mode":0o100600,"permissions":"rw-------","owner":"1000","group":"1000","modified_time":{"seconds":0,"nanos":0},"symlink_target":null,"version":{"device":1,"inode":2,"size":0,"mtime_seconds":0,"mtime_nanos":0,"ctime_seconds":0,"ctime_nanos":0}});
        let sha = guest_lexical_test_digest(json!([entry.clone()]));
        let version = json!({"device":1,"inode":3,"size":0,"mtime_seconds":0,"mtime_nanos":0,"ctime_seconds":0,"ctime_nanos":0});
        let page = json!({"path":".","cursor":0,"next_cursor":1,"count":1,"entries":[entry],"snapshot_sha256":sha,"version":version});
        let summary = json!({"path":".","count":1,"snapshot_sha256":sha,"version":version});
        reply(
            &mut write,
            &Envelope {
                kind: "list_page".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: page.clone(),
            },
        )
        .await;
        assert!(matches!(
            h.wait().await.unwrap(),
            NativeMetadataReceipt::ListPage(_)
        ));
        MetadataFixture {
            client,
            h,
            read,
            write,
            original,
            page,
            summary,
        }
    }
    #[tokio::test]
    async fn native_metadata_same_pending_joins_once_and_query_refusal_is_nonpoisoning() {
        let MetadataFixture {
            client,
            h,
            mut read,
            mut write,
            original,
            page,
            summary,
        } = metadata_cached_one_page().await;
        let a = h.clone();
        let first = tokio::spawn(async move { a.next(0).await });
        let firstframe = receive(&mut read).await;
        let before = {
            let state = client.state.lock().unwrap();
            let r = &state.records[&original.operation_id];
            (
                r.unknown,
                r.truth_revision,
                r.metadata_next.unwrap().until,
                state.bytes,
                state.records.len(),
            )
        };
        let b = h.clone();
        let second = tokio::spawn(async move { b.next(0).await });
        let query_refused = h.query().await.is_err();
        let no_second =
            tokio::time::timeout(std::time::Duration::from_millis(30), receive(&mut read))
                .await
                .is_err();
        let same_deadline = {
            let state = client.state.lock().unwrap();
            let r = &state.records[&original.operation_id];
            r.metadata_next
                .is_some_and(|p| p.until == before.2 && p.waiters == 2)
                && r.unknown == before.0
                && r.truth_revision == before.1
                && state.bytes == before.3
                && state.records.len() == before.4
        };
        reply(
            &mut write,
            &Envelope {
                kind: "list_result".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: summary,
            },
        )
        .await;
        reply(
            &mut write,
            &Envelope {
                kind: "list_page".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: page,
            },
        )
        .await;
        let joined_a = tokio::time::timeout(std::time::Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap();
        let joined_b = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap();
        client.close();
        assert_eq!(firstframe.operation_id, original.operation_id);
        assert!(query_refused && no_second && same_deadline);
        assert!(
            matches!(joined_a, Ok(NativeMetadataReceipt::ListPage(_)))
                && matches!(joined_b, Ok(NativeMetadataReceipt::ListPage(_)))
        );
    }
    #[tokio::test]
    async fn native_metadata_dropped_page_expired_join_original_query_keeps_target_no_resend() {
        let MetadataFixture {
            client,
            h,
            mut read,
            mut write,
            original,
            page,
            summary,
        } = metadata_cached_one_page().await;
        let a = h.clone();
        let first = tokio::spawn(async move { a.next(0).await });
        let firstframe = receive(&mut read).await;
        let phase = client.state.lock().unwrap().records[&original.operation_id]
            .metadata_next
            .unwrap();
        first.abort();
        let _ = first.await;
        let drop_unknown = {
            let state = client.state.lock().unwrap();
            let r = &state.records[&original.operation_id];
            r.unknown
                && r.metadata_next.is_some_and(|p| {
                    p.token == phase.token && p.until == phase.until && p.waiters == 0
                })
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(phase.until)).await;
        let expired_refused = h.next(0).await.is_err();
        let no_resend =
            tokio::time::timeout(std::time::Duration::from_millis(30), receive(&mut read))
                .await
                .is_err();
        let a = h.clone();
        let query = tokio::spawn(async move { a.query().await });
        let queryframe = receive(&mut read).await;
        reply(
            &mut write,
            &Envelope {
                kind: "list_result".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: summary,
            },
        )
        .await;
        let recovered = tokio::time::timeout(std::time::Duration::from_secs(1), query)
            .await
            .unwrap()
            .unwrap();
        let target_preserved = {
            let state = client.state.lock().unwrap();
            let r = &state.records[&original.operation_id];
            r.metadata_next.is_some_and(|p| {
                p.token == phase.token && p.cursor == Some(0) && p.until == phase.until
            }) && state.records.len() == 1
        };
        reply(
            &mut write,
            &Envelope {
                kind: "list_page".into(),
                session_id: original.session_id.clone(),
                operation_id: original.operation_id.clone(),
                payload: page,
            },
        )
        .await;
        let cleared = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if client.state.lock().unwrap().records[&original.operation_id]
                    .metadata_next
                    .is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        client.close();
        assert_eq!(firstframe.operation_id, original.operation_id);
        assert_eq!(queryframe.operation_id, original.operation_id);
        assert_eq!(queryframe.kind, "query");
        assert!(
            drop_unknown
                && expired_refused
                && no_resend
                && target_preserved
                && cleared
                && matches!(recovered, Ok(NativeMetadataReceipt::ListResult(_)))
        );
    }
    #[tokio::test]
    async fn native_download_missing_capability_refuses_before_identity_or_pipe() {
        let (client, mut read, _write) = fixture();
        assert!(client.start_download("file", 1).await.is_err());
        assert!(client.state.lock().unwrap().records.is_empty());
        assert_eq!(client.state.lock().unwrap().bytes, 0);
        assert!(client.is_ready());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), receive(&mut read))
                .await
                .is_err()
        );
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_33_chunks_retains_before_ack_one_identity_final_sha_and_original_query(
    ) {
        use std::io::Read;
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, mut peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        assert!(client.download_available());
        assert!(
            super::super::native_control::NativeControl::new(client.clone())
                .operations()
                .contains(&"download_begin")
        );
        assert!(!client.directory_available());
        let bytes = vec![0x9d; 33 * 16384];
        let sha = format!("{:x}", Sha256::digest(&bytes));
        let handle = Arc::new(
            client
                .start_download("full.bin", bytes.len() as u64)
                .await
                .unwrap(),
        );
        let begin = receive(&mut peer_reader).await;
        assert_eq!(begin.kind, "download_begin");
        let queued_exec = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        assert_eq!(begin.operation_id, handle.identity().operation_id);
        assert_eq!(client.state.lock().unwrap().bytes, 192 * 1024);
        let owned = handle.clone();
        let collecting = tokio::spawn(async move { owned.receive().await });
        let progress = |next: u64, retained: u64| Envelope {
            kind: "download_progress".into(),
            session_id: begin.session_id.clone(),
            operation_id: begin.operation_id.clone(),
            payload: json!({"path":"full.bin","phase":"streaming","size":bytes.len(),"sha256":sha,"next_sequence":next,"retained_sequence":retained}),
        };
        reply(&mut peer_writer, &progress(0, 0)).await;
        for (sequence, chunk) in bytes.chunks(16384).enumerate() {
            let next = receive(&mut peer_reader).await;
            assert_eq!(next.kind, "download_next");
            assert_eq!(next.operation_id, begin.operation_id);
            assert_eq!(next.payload["sequence"], sequence);
            reply(&mut peer_writer,&Envelope {kind:"download_chunk".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"full.bin","size":bytes.len(),"sha256":sha,"sequence":sequence,"offset":sequence*16384,"data":STANDARD.encode(chunk),"chunk_sha256":format!("{:x}",Sha256::digest(chunk))})}).await;
            let retained = receive(&mut peer_reader).await;
            assert_eq!(retained.kind, "download_retain");
            assert_eq!(retained.operation_id, begin.operation_id);
            assert_eq!(retained.payload["next_sequence"], sequence + 1);
            // Actual protected host file bytes exist before this custody ACK.
            let entry = std::fs::read_dir(namespace.path.join("native-downloads"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            let mut file = std::fs::File::open(entry.path()).unwrap();
            let mut observed = vec![0; (sequence + 1) * 16384];
            file.read_exact(&mut observed).unwrap();
            assert_eq!(observed, bytes[..observed.len()]);
            if sequence < 32 {
                reply(
                    &mut peer_writer,
                    &progress((sequence + 1) as u64, (sequence + 1) as u64),
                )
                .await;
            }
        }
        let result = Envelope {
            kind: "download_result".into(),
            session_id: begin.session_id.clone(),
            operation_id: begin.operation_id.clone(),
            payload: json!({"path":"full.bin","size":bytes.len(),"sha256":sha,"retained_sequence":33}),
        };
        reply(&mut peer_writer, &result).await;
        let outcome = collecting.await.expect("download task").unwrap();
        let exec = receive(&mut peer_reader).await;
        assert_eq!(exec.kind, "exec");
        assert_eq!(exec.operation_id, queued_exec.identity.operation_id);
        let mut published = outcome.open_read().unwrap();
        let mut whole = Vec::new();
        published.read_to_end(&mut whole).unwrap();
        assert_eq!(whole, bytes);
        drop(published);
        assert_eq!(outcome.sha256, sha);
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query_result().await });
        let request = receive(&mut peer_reader).await;
        assert_eq!(request.kind, "query");
        assert_eq!(request.operation_id, begin.operation_id);
        reply(&mut peer_writer, &result).await;
        assert_eq!(query.await.expect("query task").unwrap().sha256, sha);
        spool.cleanup_pending().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_lost_next_preserves_original_query_without_replay_or_publication() {
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, mut peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        let handle = Arc::new(client.start_download("lost", 1).await.unwrap());
        let begin = receive(&mut peer_reader).await;
        let owned = handle.clone();
        let collect = tokio::spawn(async move { owned.receive().await });
        reply(&mut peer_writer,&Envelope{kind:"download_progress".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"lost","phase":"streaming","size":1,"sha256":format!("{:x}",Sha256::digest([1u8])),"next_sequence":0,"retained_sequence":0})}).await;
        let next = receive(&mut peer_reader).await;
        assert_eq!(next.kind, "download_next");
        reply(
            &mut peer_writer,
            &Envelope {
                kind: "error".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"code":"unknown"}),
            },
        )
        .await;
        assert!(collect.await.expect("collect task").is_err());
        let owned = handle.clone();
        let querying = tokio::spawn(async move { owned.query_progress().await });
        let query = receive(&mut peer_reader).await;
        assert_eq!(query.kind, "query");
        assert_eq!(query.operation_id, begin.operation_id);
        querying.abort();
        let _ = querying.await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            receive(&mut peer_reader)
        )
        .await
        .is_err());
        assert!(client
            .state
            .lock()
            .unwrap()
            .records
            .contains_key(&begin.operation_id));
        spool.cleanup_pending().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_cumulative_ticket_refuses_before_backing_uuid_and_begin() {
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, _peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        client.state.lock().unwrap().bytes = OUTPUT - DOWNLOAD_RECEIPTS + 1;
        assert!(client.start_download("file", 16384).await.is_err());
        assert_eq!(spool.reserved_bytes(), 0);
        assert!(client.state.lock().unwrap().records.is_empty());
        assert_eq!(client.state.lock().unwrap().lifetime_admissions, 0);
        assert!(client.is_ready());
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(5),
            receive(&mut peer_reader)
        )
        .await
        .is_err());
    }
    #[cfg(target_os = "linux")]
    struct DownloadTestGate {
        open: Mutex<bool>,
        changed: std::sync::Condvar,
    }
    #[cfg(target_os = "linux")]
    impl DownloadTestGate {
        fn wait(&self) {
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.changed.wait(open).unwrap();
            }
        }
        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }
    #[cfg(target_os = "linux")]
    struct DownloadTestRelease(Arc<DownloadTestGate>);
    #[cfg(target_os = "linux")]
    impl Drop for DownloadTestRelease {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    #[cfg(target_os = "linux")]
    async fn download_admission_paused(deadline: bool) {
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, _peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_millis(if deadline { 100 } else { 30000 }),
            minimum_framing(),
            Some(spool.clone()),
        );
        let gate = Arc::new(DownloadTestGate {
            open: Mutex::new(false),
            changed: std::sync::Condvar::new(),
        });
        let release = DownloadTestRelease(gate.clone());
        let (signal, observed) = tokio::sync::oneshot::channel();
        let owned = client.clone();
        let task = tokio::spawn(async move {
            owned
                .start_download_inner("paused", 16384, move || {
                    let _ = signal.send(());
                    gate.wait();
                })
                .await
        });
        observed.await.unwrap();
        assert_eq!(client.state.lock().unwrap().bytes, DOWNLOAD_RECEIPTS);
        assert!(client.state.lock().unwrap().records.is_empty());
        assert_eq!(spool.reserved_bytes(), 16384);
        if deadline {
            assert!(task.await.expect("admission task").is_err());
        } else {
            task.abort();
            assert!(matches!(task.await,Err(error) if error.is_cancelled()));
        }
        assert!(client.state.lock().unwrap().records.is_empty());
        let absence = tokio::time::timeout(
            std::time::Duration::from_millis(5),
            read_line(&mut peer_reader, &mut Vec::new()),
        )
        .await;
        assert!(!matches!(absence, Ok(Ok(_))));
        assert_eq!(spool.reserved_bytes(), 16384);
        drop(release);
        let jobs = std::mem::take(&mut *client.download_admissions.lock().await);
        for job in jobs {
            job.await.expect("retained admission owner");
        }
        assert_eq!(spool.reserved_bytes(), 0);
        assert!(client.state.lock().unwrap().records.is_empty());
        assert_eq!(client.state.lock().unwrap().bytes, DOWNLOAD_RECEIPTS);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_deadline_admission_retains_worker_until_join_and_never_begins() {
        download_admission_paused(true).await;
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_dropped_admission_retains_worker_until_join_and_never_begins() {
        download_admission_paused(false).await;
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_owner_stop_cancelled_wait_retains_admission_job_and_retries_exact_cleanup(
    ) {
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (_peer_reader, _peer_writer) = split(peer);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        let gate = Arc::new(DownloadTestGate {
            open: Mutex::new(false),
            changed: std::sync::Condvar::new(),
        });
        let release = DownloadTestRelease(gate.clone());
        let (signal, observed) = tokio::sync::oneshot::channel();
        let owned = client.clone();
        let admission = tokio::spawn(async move {
            owned
                .start_download_inner("stop-paused", 16384, move || {
                    let _ = signal.send(());
                    gate.wait();
                })
                .await
        });
        observed.await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(5),
            client.retire_downloads()
        )
        .await
        .is_err());
        assert_eq!(client.download_admissions.lock().await.len(), 1);
        assert_eq!(spool.reserved_bytes(), 16384);
        assert!(client.start_download("late", 1).await.is_err());
        assert!(client.state.lock().unwrap().records.is_empty());
        drop(release);
        assert!(admission.await.expect("admission caller").is_err());
        client.retire_downloads().await.unwrap();
        assert!(client.download_admissions.lock().await.is_empty());
        assert_eq!(spool.reserved_bytes(), 0);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_failed_protected_write_never_sends_retain_or_publishes() {
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, mut peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        let handle = Arc::new(client.start_download("guarded", 1).await.unwrap());
        let begin = receive(&mut peer_reader).await;
        let owned = handle.clone();
        let collecting = tokio::spawn(async move { owned.receive().await });
        let sha = format!("{:x}", Sha256::digest([1u8]));
        reply(&mut peer_writer,&Envelope{kind:"download_progress".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"guarded","phase":"streaming","size":1,"sha256":sha,"next_sequence":0,"retained_sequence":0})}).await;
        assert_eq!(receive(&mut peer_reader).await.kind, "download_next");
        let original = std::fs::read_dir(namespace.path.join("native-downloads"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let saved = original.with_extension("captured");
        std::fs::rename(&original, &saved).unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&original)
            .unwrap();
        reply(&mut peer_writer,&Envelope{kind:"download_chunk".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"guarded","size":1,"sha256":sha,"sequence":0,"offset":0,"data":STANDARD.encode([1u8]),"chunk_sha256":sha})}).await;
        assert!(collecting.await.expect("receive task").is_err());
        let absence = tokio::time::timeout(
            std::time::Duration::from_millis(5),
            read_line(&mut peer_reader, &mut Vec::new()),
        )
        .await;
        assert!(!matches!(absence, Ok(Ok(_))));
        assert!(client.state.lock().unwrap().records[&begin.operation_id]
            .download
            .as_ref()
            .unwrap()
            .result
            .is_none());
        assert!(spool.cleanup_pending().await.is_err());
        std::fs::remove_file(&original).unwrap();
        std::fs::rename(&saved, &original).unwrap();
        spool.cleanup_pending().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_lost_retain_queries_original_without_resending_or_success() {
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, mut peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        let handle = Arc::new(client.start_download("lost-retain", 1).await.unwrap());
        let begin = receive(&mut peer_reader).await;
        let owned = handle.clone();
        let collecting = tokio::spawn(async move { owned.receive().await });
        let sha = format!("{:x}", Sha256::digest([1u8]));
        reply(&mut peer_writer,&Envelope{kind:"download_progress".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"lost-retain","phase":"streaming","size":1,"sha256":sha,"next_sequence":0,"retained_sequence":0})}).await;
        assert_eq!(receive(&mut peer_reader).await.kind, "download_next");
        reply(&mut peer_writer,&Envelope{kind:"download_chunk".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"lost-retain","size":1,"sha256":sha,"sequence":0,"offset":0,"data":STANDARD.encode([1u8]),"chunk_sha256":sha})}).await;
        assert_eq!(receive(&mut peer_reader).await.kind, "download_retain");
        reply(
            &mut peer_writer,
            &Envelope {
                kind: "error".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"code":"unknown"}),
            },
        )
        .await;
        assert!(collecting.await.expect("receive task").is_err());
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query_progress().await });
        let request = receive(&mut peer_reader).await;
        assert_eq!(request.kind, "query");
        assert_eq!(request.operation_id, begin.operation_id);
        reply(
            &mut peer_writer,
            &Envelope {
                kind: "status".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"state":"unknown"}),
            },
        )
        .await;
        assert!(query.await.expect("query task").is_err());
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(5),
            receive(&mut peer_reader)
        )
        .await
        .is_err());
        assert!(client.state.lock().unwrap().records[&begin.operation_id]
            .download
            .as_ref()
            .unwrap()
            .result
            .is_none());
        spool.cleanup_pending().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_invalid_final_receipt_never_publishes_cached_success() {
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, mut peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        let handle = Arc::new(client.start_download("empty", 0).await.unwrap());
        let begin = receive(&mut peer_reader).await;
        let owned = handle.clone();
        let collecting = tokio::spawn(async move { owned.receive().await });
        let sha = format!("{:x}", Sha256::digest([]));
        reply(&mut peer_writer,&Envelope{kind:"download_progress".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"empty","phase":"streaming","size":0,"sha256":sha,"next_sequence":0,"retained_sequence":0})}).await;
        assert_eq!(receive(&mut peer_reader).await.kind, "download_retain");
        reply(&mut peer_writer,&Envelope{kind:"download_result".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"empty","size":0,"sha256":"a".repeat(64),"retained_sequence":0})}).await;
        assert!(collecting.await.expect("receive task").is_err());
        assert!(client.state.lock().unwrap().records[&begin.operation_id]
            .download
            .as_ref()
            .unwrap()
            .result
            .is_none());
        spool.cleanup_pending().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_same_inode_tamper_before_final_receipt_never_publishes() {
        use std::os::unix::fs::FileExt;
        let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
            return;
        };
        let spool =
            super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
        let (host, peer) = tokio::io::duplex(131072);
        let (reader, writer) = split(host);
        let (peer_reader, mut peer_writer) = split(peer);
        let mut peer_reader = BufReader::new(peer_reader);
        let client = NativeClient::install_with_downloads(
            BufReader::new(reader),
            writer,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
            Some(spool.clone()),
        );
        let handle = Arc::new(client.start_download("tampered", 1).await.unwrap());
        let begin = receive(&mut peer_reader).await;
        let owned = handle.clone();
        let receiving = tokio::spawn(async move { owned.receive().await });
        let sha = format!("{:x}", Sha256::digest([1u8]));
        reply(&mut peer_writer,&Envelope{kind:"download_progress".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"tampered","phase":"streaming","size":1,"sha256":sha,"next_sequence":0,"retained_sequence":0})}).await;
        assert_eq!(receive(&mut peer_reader).await.kind, "download_next");
        reply(&mut peer_writer,&Envelope{kind:"download_chunk".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":"tampered","size":1,"sha256":sha,"sequence":0,"offset":0,"data":STANDARD.encode([1u8]),"chunk_sha256":sha})}).await;
        assert_eq!(receive(&mut peer_reader).await.kind, "download_retain");
        let path = std::fs::read_dir(namespace.path.join("native-downloads"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let actual = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut byte = [0u8];
        actual.read_at(&mut byte, 0).unwrap();
        assert_eq!(byte, [1]);
        actual.write_at(&[2], 0).unwrap();
        actual.sync_data().unwrap();
        reply(
            &mut peer_writer,
            &Envelope {
                kind: "download_result".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"path":"tampered","size":1,"sha256":sha,"retained_sequence":1}),
            },
        )
        .await;
        assert!(
            receiving.await.expect("receive task").is_err(),
            "wire digest must not publish a different physical spool file"
        );
        assert!(client.state.lock().unwrap().records[&begin.operation_id]
            .download
            .as_ref()
            .unwrap()
            .result
            .is_none());
        spool.cleanup_pending().await.unwrap();
    }
    #[tokio::test]
    async fn default_exec_cwd_is_guest_workspace_relative() {
        let (client, mut read, _write) = fixture();
        client
            .start(
                "/bin/sh",
                &["-c", "printf qualification"],
                &ProcessOpts::default(),
            )
            .unwrap();
        let request = receive(&mut read).await;
        assert_eq!(request.kind, "exec");
        assert_eq!(
            request.payload["cwd"], ".",
            "native default must satisfy the existing guest relative-path contract"
        );
    }
    #[tokio::test]
    async fn native_cwd_scope_maps_workspace_root_prefix_and_relative_paths() {
        for (input, expected) in [
            ("/workspace", "."),
            ("/workspace/", "."),
            ("/workspace/project", "project"),
            ("/workspace/project/subdir", "project/subdir"),
            ("project/subdir", "project/subdir"),
            (".", "."),
        ] {
            let (client, mut read, _write) = fixture();
            let opts = ProcessOpts::default().with_cwd(input);
            let handle = client.start("/bin/sh", &[], &opts).unwrap();
            let request = receive(&mut read).await;
            assert_eq!(request.payload["cwd"], expected, "native cwd {input}");
            assert_eq!(request.operation_id, handle.identity.operation_id);
            assert_eq!(
                client.state.lock().unwrap().records[&request.operation_id]._request,
                request.payload
            );
        }
    }
    #[tokio::test]
    async fn native_cwd_refuses_traversal_foreign_and_invalid_paths_before_reservation() {
        let mut invalid = vec![
            "/tmp".to_owned(),
            "/workspace-other".into(),
            "/workspace/../tmp".into(),
            "../project".into(),
            "project/../other".into(),
            "project//child".into(),
            "./project".into(),
            "".into(),
            "project\\child".into(),
            "project\0child".into(),
            "/workspace//project".into(),
        ];
        invalid.push("a".repeat(65));
        invalid.push(std::iter::repeat_n("a", 17).collect::<Vec<_>>().join("/"));
        for input in invalid {
            let (client, mut read, _write) = fixture();
            assert!(
                client
                    .start(
                        "/bin/sh",
                        &[],
                        &ProcessOpts::default().with_cwd(input.clone())
                    )
                    .is_err(),
                "cwd must fail before effects: {input:?}"
            );
            assert!(client.state.lock().unwrap().records.is_empty());
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(5), receive(&mut read))
                    .await
                    .is_err()
            );
        }
    }
    async fn refuse_without_disturbing_active(cmd: &str, args: &[&str], opts: &ProcessOpts) {
        let (client, mut read, _write) = fixture();
        let active = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        let original = receive(&mut read).await;
        assert!(
            client.start(cmd, args, opts).is_err(),
            "malformed native Exec must fail preflight"
        );
        assert!(client.is_ready());
        {
            let state = client.state.lock().unwrap();
            assert_eq!(state.records.len(), 1);
            let retained = &state.records[&active.identity.operation_id];
            assert!(!retained.unknown);
            assert_eq!(retained._request, original.payload);
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), receive(&mut read))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn native_exec_authenticated_frame_bound_refuses_before_effects_and_preserves_active() {
        // Valid raw guest argv bounds, but JSON escaping reaches IPC's limit
        // before the authenticated guest envelope adds its identity and HMAC.
        let first = "\u{1}".repeat(4096);
        let second = "\u{1}".repeat(4096);
        let third = "\u{1}".repeat(2698);
        let opts = ProcessOpts::default().with_timeout(std::time::Duration::from_millis(1));
        refuse_without_disturbing_active("/bin/sh", &[&first, &second, &third], &opts).await;
    }
    #[tokio::test]
    async fn native_exec_argv_preflight_refuses_before_effects_and_preserves_active() {
        let too_many = vec![""; 64];
        refuse_without_disturbing_active("/bin/sh", &too_many, &ProcessOpts::default()).await;
        let too_long = "x".repeat(4097);
        refuse_without_disturbing_active("/bin/sh", &[&too_long], &ProcessOpts::default()).await;
        let mut aggregate = vec!["x".repeat(4096); 7];
        aggregate.push("x".repeat(4090));
        let aggregate = aggregate.iter().map(String::as_str).collect::<Vec<_>>();
        refuse_without_disturbing_active("/bin/sh", &aggregate, &ProcessOpts::default()).await;
        refuse_without_disturbing_active("/bin/\0sh", &[], &ProcessOpts::default()).await;
        refuse_without_disturbing_active("/bin/sh", &["arg\0value"], &ProcessOpts::default()).await;
        refuse_without_disturbing_active("", &[], &ProcessOpts::default()).await;
    }
    #[tokio::test]
    async fn native_exec_env_preflight_refuses_before_effects_and_preserves_active() {
        let too_many = (0..33).map(|n| (format!("K{n}"), String::new())).collect();
        refuse_without_disturbing_active(
            "/bin/sh",
            &[],
            &ProcessOpts::default().with_envs(too_many),
        )
        .await;
        for key in [
            "".to_owned(),
            "9KEY".into(),
            "K-EY".into(),
            "é".into(),
            "K\0EY".into(),
            "K".repeat(65),
        ] {
            refuse_without_disturbing_active(
                "/bin/sh",
                &[],
                &ProcessOpts::default().with_envs([(key, "v".into())].into()),
            )
            .await;
        }
        for value in ["v".repeat(4097), "value\0tail".into()] {
            refuse_without_disturbing_active(
                "/bin/sh",
                &[],
                &ProcessOpts::default().with_envs([("K".into(), value)].into()),
            )
            .await;
        }
        let aggregate = [
            ("A".into(), "v".repeat(4096)),
            ("B".into(), "v".repeat(4096)),
            ("C".into(), "v".repeat(4096)),
            ("D".into(), "v".repeat(4093)),
        ]
        .into();
        refuse_without_disturbing_active(
            "/bin/sh",
            &[],
            &ProcessOpts::default().with_envs(aggregate),
        )
        .await;
    }
    #[tokio::test]
    async fn native_exec_timeout_preflight_refuses_zero_and_submillisecond_before_effects() {
        for duration in [
            std::time::Duration::ZERO,
            std::time::Duration::from_nanos(999999),
        ] {
            refuse_without_disturbing_active(
                "/bin/sh",
                &[],
                &ProcessOpts::default().with_timeout(duration),
            )
            .await;
        }
    }
    async fn captured_request(cmd: &str, args: &[&str], opts: &ProcessOpts) -> Envelope {
        let (client, mut read, _write) = fixture();
        client.start(cmd, args, opts).unwrap();
        let request = receive(&mut read).await;
        assert_eq!(
            client.state.lock().unwrap().records[&request.operation_id]._request,
            request.payload
        );
        request
    }
    #[tokio::test]
    async fn native_exec_preflight_accepts_exact_guest_bounds_unicode_and_escaped_controls() {
        let argv_count = vec![""; 63];
        assert_eq!(
            captured_request("/bin/sh", &argv_count, &ProcessOpts::default())
                .await
                .payload["argv"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        let unicode = "é".repeat(2048);
        captured_request(
            "/bin/sh",
            &[&unicode, "", "new\nline\ttab"],
            &ProcessOpts::default(),
        )
        .await;
        let mut argv = vec!["x".repeat(4096); 7];
        argv.push("x".repeat(4089));
        let refs = argv.iter().map(String::as_str).collect::<Vec<_>>();
        let request = captured_request("/bin/sh", &refs, &ProcessOpts::default()).await;
        assert_eq!(
            request.payload["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().len())
                .sum::<usize>(),
            32768
        );
        let env_count = (0..32).map(|n| (format!("_K{n}"), String::new())).collect();
        captured_request("/bin/sh", &[], &ProcessOpts::default().with_envs(env_count)).await;
        let env = [
            ("A".into(), "v".repeat(4096)),
            ("B".into(), "v".repeat(4096)),
            ("C".into(), "v".repeat(4096)),
            ("D".into(), "v".repeat(4092)),
        ]
        .into();
        captured_request("/bin/sh", &[], &ProcessOpts::default().with_envs(env)).await;
        captured_request(
            "/bin/sh",
            &[],
            &ProcessOpts::default().with_envs(
                [
                    ("_".into(), "é\n\t".into()),
                    ("K".repeat(64), String::new()),
                ]
                .into(),
            ),
        )
        .await;
        assert_eq!(
            captured_request(
                "/bin/sh",
                &[],
                &ProcessOpts::default().with_timeout(std::time::Duration::from_millis(1))
            )
            .await
            .payload["timeout_ms"],
            1
        );
    }
    #[tokio::test]
    async fn native_cwd_accepts_newline_tab_and_unicode_per_guest_path_grammar() {
        for (input, expected) in [
            ("project\nchild", "project\nchild"),
            ("/workspace/project\tchild", "project\tchild"),
            ("工程/子目录", "工程/子目录"),
        ] {
            let request =
                captured_request("/bin/sh", &[], &ProcessOpts::default().with_cwd(input)).await;
            assert_eq!(request.payload["cwd"], expected);
        }
    }
    #[tokio::test]
    async fn retained_bytes_precede_ack_and_terminal_counts() {
        let (client, mut read, mut write) = fixture();
        let handle = client
            .start("/bin/task", &[], &ProcessOpts::default())
            .unwrap();
        let request = receive(&mut read).await;
        assert_eq!(request.kind, "exec");
        let output = Envelope {
            kind: "output".into(),
            session_id: request.session_id.clone(),
            operation_id: request.operation_id.clone(),
            payload: json!({"sequence":0,"stream":"stdout","data":"aGVsbG8="}),
        };
        send(
            &mut write,
            &output,
            Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        let ack = receive(&mut read).await;
        assert_eq!(ack.kind, "retain_ack");
        assert_eq!(
            client.state.lock().unwrap().records[&request.operation_id].stdout,
            b"hello"
        );
        send(&mut write,&Envelope {kind:"terminal".into(),session_id:request.session_id,operation_id:request.operation_id,payload:json!({"state":"succeeded","exit_code":0,"stdout_bytes":5,"stderr_bytes":0,"process_absent":true,"acked_sequence":1})},Instant::now()+std::time::Duration::from_secs(3)).await.unwrap();
        assert_eq!(handle.wait().await.unwrap().stdout, "hello");
    }
    #[tokio::test]
    async fn cancelled_wait_and_broken_pipe_retain_original_identity() {
        let (client, mut read, write) = fixture();
        let handle = client
            .start("/bin/task", &[], &ProcessOpts::default())
            .unwrap();
        let request = receive(&mut read).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), handle.wait())
                .await
                .is_err()
        );
        drop(write);
        drop(read);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), handle.wait())
                .await
                .unwrap()
                .is_err()
        );
        assert!(client
            .state
            .lock()
            .unwrap()
            .records
            .contains_key(&request.operation_id));
        assert_eq!(handle.identity.operation_id, request.operation_id);
    }
    #[tokio::test]
    async fn operations_queue_without_replaying_exec_and_bound_lifetime_records() {
        let (client, mut read, mut write) = fixture();
        let first = client
            .start("/bin/a", &[], &ProcessOpts::default())
            .unwrap();
        let second = client
            .start("/bin/b", &[], &ProcessOpts::default())
            .unwrap();
        let request = receive(&mut read).await;
        assert_eq!(request.operation_id, first.identity.operation_id);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), receive(&mut read))
                .await
                .is_err()
        );
        send(&mut write,&Envelope {kind:"terminal".into(),session_id:request.session_id,operation_id:request.operation_id,payload:json!({"state":"succeeded","exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"process_absent":true})},Instant::now()+std::time::Duration::from_secs(3)).await.unwrap();
        assert_eq!(
            receive(&mut read).await.operation_id,
            second.identity.operation_id
        );
        for _ in 2..32 {
            client
                .start("/bin/a", &[], &ProcessOpts::default())
                .unwrap();
        }
        assert!(client
            .start("/bin/a", &[], &ProcessOpts::default())
            .is_err());
    }
    #[tokio::test]
    async fn incomplete_terminal_is_unknown_not_success() {
        let (client, mut read, mut write) = fixture();
        let handle = client
            .start("/bin/a", &[], &ProcessOpts::default())
            .unwrap();
        let req = receive(&mut read).await;
        send(&mut write,&Envelope {kind:"terminal".into(),session_id:req.session_id,operation_id:req.operation_id,payload:json!({"state":"succeeded","exit_code":0,"stdout_bytes":1,"stderr_bytes":0,"process_absent":true})},Instant::now()+std::time::Duration::from_secs(3)).await.unwrap();
        assert!(handle.wait().await.is_err());
        assert!(!client.is_ready());
    }

    fn upload_progress(request: &Envelope, received: u64, next_sequence: u64) -> Envelope {
        Envelope {
            kind: "upload_progress".into(),
            session_id: request.session_id.clone(),
            operation_id: request.operation_id.clone(),
            payload: json!({"path":request.payload["path"],"size":request.payload["size"],"sha256":request.payload["sha256"],"received":received,"next_sequence":next_sequence}),
        }
    }
    #[tokio::test]
    async fn native_upload_33_chunks_one_identity_serializes_queued_exec_until_result() {
        let (client, mut read, mut write) = fixture();
        let data = vec![0x9d; 33 * 16384];
        let digest = format!("{:x}", Sha256::digest(&data));
        let handle = Arc::new(
            client
                .start_upload("nested/full.bin", data.len() as u64, &digest, true)
                .unwrap(),
        );
        let begin = receive(&mut read).await;
        assert_eq!(begin.kind, "upload_begin");
        let next = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        assert_eq!(handle.wait_ready().await.unwrap().received, 0);
        for (sequence, chunk) in data.chunks(16384).enumerate() {
            let owned = handle.clone();
            let bytes = chunk.to_vec();
            let task = tokio::spawn(async move { owned.write_chunk(&bytes).await });
            let frame = receive(&mut read).await;
            assert_eq!(frame.kind, "upload_chunk");
            assert_eq!(frame.session_id, begin.session_id);
            assert_eq!(frame.operation_id, begin.operation_id);
            assert_eq!(frame.payload["sequence"], sequence as u64);
            assert_eq!(
                STANDARD
                    .decode(frame.payload["data"].as_str().unwrap())
                    .unwrap(),
                chunk
            );
            reply(
                &mut write,
                &upload_progress(
                    &begin,
                    ((sequence + 1) * 16384) as u64,
                    (sequence + 1) as u64,
                ),
            )
            .await;
            assert_eq!(
                task.await.expect("chunk task").unwrap().next_sequence,
                (sequence + 1) as u64
            );
        }
        let owned = handle.clone();
        let commit = tokio::spawn(async move { owned.commit().await });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "upload_commit");
        assert_eq!(frame.operation_id, begin.operation_id);
        reply(&mut write,&Envelope {kind:"upload_result".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"path":begin.payload["path"],"size":begin.payload["size"],"sha256":begin.payload["sha256"]})}).await;
        let result = commit.await.expect("commit task").unwrap();
        assert_eq!(result.size, data.len() as u64);
        assert_eq!(result.sha256, digest);
        assert_eq!(result.identity.operation_id, begin.operation_id);
        let exec = receive(&mut read).await;
        assert_eq!(exec.kind, "exec");
        assert_eq!(exec.operation_id, next.identity.operation_id);
        let state = client.state.lock().unwrap();
        assert_eq!(state.records.len(), 2);
        assert_eq!(state.bytes, UPLOAD_RECEIPTS);
        assert_eq!(
            state.records[&begin.operation_id]
                .upload
                .as_ref()
                .unwrap()
                .receipts
                .len(),
            33
        );
    }
    #[tokio::test]
    async fn native_upload_lost_chunk_requires_explicit_original_query_and_never_replays() {
        let (client, mut read, mut write) = fixture();
        let digest = format!("{:x}", Sha256::digest(b"abc"));
        let handle = Arc::new(client.start_upload("lost", 3, &digest, false).unwrap());
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        handle.wait_ready().await.unwrap();
        let owned = handle.clone();
        let chunk = tokio::spawn(async move { owned.write_chunk(b"abc").await });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "upload_chunk");
        reply(
            &mut write,
            &Envelope {
                kind: "error".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"code":"io"}),
            },
        )
        .await;
        assert!(chunk.await.expect("chunk task").is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query().await });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "query");
        assert_eq!(frame.operation_id, begin.operation_id);
        reply(&mut write, &upload_progress(&begin, 3, 1)).await;
        assert!(
            matches!(query.await.expect("query task").unwrap(), NativeUploadObservation::Progress(progress) if progress.received==3)
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn native_upload_cumulative_receipts_refuse_before_admission_preserve_active() {
        let (client, mut read, _write) = fixture();
        let active = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        let original = receive(&mut read).await;
        {
            client.state.lock().unwrap().bytes = OUTPUT - UPLOAD_RECEIPTS + 1;
        }
        assert!(client
            .start_upload("full", 33554432, &"a".repeat(64), false)
            .is_err());
        {
            let state = client.state.lock().unwrap();
            assert_eq!(state.records.len(), 1);
            assert_eq!(state.bytes, OUTPUT - UPLOAD_RECEIPTS + 1);
            assert_eq!(
                state.records[&active.identity.operation_id]._request,
                original.payload
            );
            assert!(!state.records[&active.identity.operation_id].unknown);
        }
        assert!(client.is_ready());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        {
            client.state.lock().unwrap().bytes = OUTPUT - UPLOAD_RECEIPTS;
        }
        let admitted = client
            .start_upload("full", 33554432, &"a".repeat(64), false)
            .unwrap();
        let state = client.state.lock().unwrap();
        assert_eq!(state.bytes, OUTPUT);
        assert_eq!(
            state.records[&admitted.identity.operation_id]
                .upload
                .as_ref()
                .unwrap()
                .receipts
                .capacity(),
            2048
        );
    }

    struct FragmentedInput {
        bytes: Vec<u8>,
        position: usize,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl tokio::io::AsyncRead for FragmentedInput {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.reads.fetch_add(1, Ordering::SeqCst);
            let end = (this.position + 7)
                .min(this.bytes.len())
                .min(this.position + buffer.remaining());
            buffer.put_slice(&this.bytes[this.position..end]);
            this.position = end;
            std::task::Poll::Ready(Ok(()))
        }
    }
    struct StalledInput {
        entered: Arc<Notify>,
    }
    impl tokio::io::AsyncRead for StalledInput {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.entered.notify_one();
            std::task::Poll::Pending
        }
    }
    #[tokio::test]
    async fn native_upload_stream_fragmented_reads_one_id_exact_hash_and_eof() {
        let (client, mut read, mut write) = fixture();
        let bytes = vec![0xad; 33 * 16384];
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let handle = client
            .start_upload("streamed", bytes.len() as u64, &digest, false)
            .unwrap();
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        let original = begin.operation_id.clone();
        let peer = tokio::spawn(async move {
            for sequence in 0..33 {
                let frame = receive(&mut read).await;
                assert_eq!(frame.kind, "upload_chunk");
                assert_eq!(frame.operation_id, begin.operation_id);
                assert_eq!(frame.payload["sequence"], sequence);
                assert_eq!(
                    STANDARD
                        .decode(frame.payload["data"].as_str().unwrap())
                        .unwrap(),
                    vec![0xad; 16384]
                );
                reply(
                    &mut write,
                    &upload_progress(&begin, (sequence + 1) * 16384, sequence + 1),
                )
                .await;
            }
            let commit = receive(&mut read).await;
            assert_eq!(commit.kind, "upload_commit");
            assert_eq!(commit.operation_id, begin.operation_id);
            reply(
                &mut write,
                &Envelope {
                    kind: "upload_result".into(),
                    session_id: begin.session_id,
                    operation_id: begin.operation_id,
                    payload: json!({"path":"streamed","size":33*16384,"sha256":digest}),
                },
            )
            .await;
        });
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut input = FragmentedInput {
            bytes,
            position: 0,
            reads: reads.clone(),
        };
        let result = handle.upload_from(&mut input).await.unwrap();
        assert_eq!(result.identity.operation_id, original);
        assert_eq!(result.size, 33 * 16384);
        assert_eq!(input.position, 33 * 16384);
        assert!(reads.load(Ordering::SeqCst) > 33);
        peer.await.expect("stream peer");
        assert_eq!(client.state.lock().unwrap().records.len(), 1);
        assert_eq!(client.state.lock().unwrap().bytes, UPLOAD_RECEIPTS);
    }
    #[tokio::test]
    async fn native_upload_stream_source_failures_never_commit_and_second_stream_never_reads() {
        for (size, input, expected_hash, chunks) in [
            (
                4,
                b"ab".to_vec(),
                format!("{:x}", Sha256::digest(b"abcd")),
                0u64,
            ),
            (
                3,
                b"abcd".to_vec(),
                format!("{:x}", Sha256::digest(b"abc")),
                1,
            ),
            (3, b"abc".to_vec(), "a".repeat(64), 1),
        ] {
            let (client, mut read, mut write) = fixture();
            let handle = client
                .start_upload("source-failure", size, &expected_hash, false)
                .unwrap();
            let begin = receive(&mut read).await;
            reply(&mut write, &upload_progress(&begin, 0, 0)).await;
            let peer = tokio::spawn(async move {
                for _ in 0..chunks {
                    assert_eq!(receive(&mut read).await.kind, "upload_chunk");
                    reply(&mut write, &upload_progress(&begin, 3, 1)).await;
                }
                assert!(tokio::time::timeout(
                    std::time::Duration::from_millis(20),
                    receive(&mut read)
                )
                .await
                .is_err());
            });
            let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut input = FragmentedInput {
                bytes: input,
                position: 0,
                reads,
            };
            assert!(handle.upload_from(&mut input).await.is_err());
            let second_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut second = FragmentedInput {
                bytes: vec![0; 4],
                position: 0,
                reads: second_reads.clone(),
            };
            assert!(handle.upload_from(&mut second).await.is_err());
            assert_eq!(second_reads.load(Ordering::SeqCst), 0);
            peer.await.expect("source peer");
            assert_eq!(client.state.lock().unwrap().records.len(), 1);
        }
    }
    #[tokio::test]
    async fn native_upload_stream_empty_exact_eof_commits_one_original() {
        let (client, mut read, mut write) = fixture();
        let digest = format!("{:x}", Sha256::digest(b""));
        let handle = client
            .start_upload("empty-stream", 0, &digest, false)
            .unwrap();
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        let peer = tokio::spawn(async move {
            let frame = receive(&mut read).await;
            assert_eq!(frame.kind, "upload_commit");
            assert_eq!(frame.operation_id, begin.operation_id);
            reply(
                &mut write,
                &Envelope {
                    kind: "upload_result".into(),
                    session_id: begin.session_id,
                    operation_id: begin.operation_id,
                    payload: json!({"path":"empty-stream","size":0,"sha256":digest}),
                },
            )
            .await;
        });
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(handle.upload_from(&mut empty).await.unwrap().size, 0);
        peer.await.expect("empty peer");
    }
    #[tokio::test]
    async fn native_upload_stream_drop_keeps_identity_query_and_releases_low_level_lease() {
        let (client, mut read, mut write) = fixture();
        let handle = Arc::new(
            client
                .start_upload("stalled", 1, &format!("{:x}", Sha256::digest(b"x")), false)
                .unwrap(),
        );
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        let entered = Arc::new(Notify::new());
        let reader_entered = entered.clone();
        let owned = handle.clone();
        let task = tokio::spawn(async move {
            let mut reader = StalledInput {
                entered: reader_entered,
            };
            owned.upload_from(&mut reader).await
        });
        entered.notified().await;
        assert!(handle.write_chunk(b"x").await.is_err());
        assert!(handle.commit().await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        task.abort();
        match task.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("stream task must be cancelled"),
        }
        assert_eq!(handle.identity().operation_id, begin.operation_id);
        let mut restart = std::io::Cursor::new(b"x");
        assert!(handle.upload_from(&mut restart).await.is_err());
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query().await });
        assert_eq!(receive(&mut read).await.kind, "query");
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        assert!(
            matches!(query.await.expect("query task").unwrap(),NativeUploadObservation::Progress(progress) if progress.received==0)
        );
        let owned = handle.clone();
        let chunk = tokio::spawn(async move { owned.write_chunk(b"x").await });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "upload_chunk");
        assert_eq!(frame.operation_id, begin.operation_id);
        reply(&mut write, &upload_progress(&begin, 1, 1)).await;
        chunk.await.expect("manual chunk").unwrap();
    }
    #[tokio::test]
    async fn native_upload_stream_lost_chunk_returns_handle_unknown_query_only_no_restart() {
        let (client, mut read, mut write) = fixture();
        let handle = Arc::new(
            client
                .start_upload(
                    "lost-stream",
                    3,
                    &format!("{:x}", Sha256::digest(b"abc")),
                    false,
                )
                .unwrap(),
        );
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        let owned = handle.clone();
        let stream = tokio::spawn(async move {
            let mut reader = std::io::Cursor::new(b"abc");
            owned.upload_from(&mut reader).await
        });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "upload_chunk");
        reply(
            &mut write,
            &Envelope {
                kind: "error".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"code":"unknown"}),
            },
        )
        .await;
        assert!(stream.await.expect("stream task").is_err());
        let mut restart = std::io::Cursor::new(b"abc");
        assert!(handle.upload_from(&mut restart).await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query().await });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "query");
        assert_eq!(frame.operation_id, begin.operation_id);
        reply(&mut write, &upload_progress(&begin, 3, 1)).await;
        assert!(
            matches!(query.await.expect("query task").unwrap(),NativeUploadObservation::Progress(progress) if progress.received==3)
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
    }

    struct FailedInput;
    impl tokio::io::AsyncRead for FailedInput {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("fixture read failure")))
        }
    }
    #[tokio::test]
    async fn native_upload_stream_input_error_preserves_original_without_commit() {
        let (client, mut read, mut write) = fixture();
        let handle = client
            .start_upload(
                "input-error",
                1,
                &format!("{:x}", Sha256::digest(b"x")),
                false,
            )
            .unwrap();
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        assert!(handle.upload_from(&mut FailedInput).await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        let state = client.state.lock().unwrap();
        let record = &state.records[&handle.identity.operation_id];
        assert!(record.unknown);
        assert!(record.upload.as_ref().unwrap().stream_started);
        assert!(!record.upload.as_ref().unwrap().stream_leased);
        assert_eq!(state.bytes, UPLOAD_RECEIPTS);
    }
    #[tokio::test]
    async fn native_upload_stream_stalled_input_uses_fixed_incarnation_deadline() {
        let (host, peer) = tokio::io::duplex(131072);
        let (read, write) = split(host);
        let (peer_read, mut peer_write) = split(peer);
        let mut peer_read = BufReader::new(peer_read);
        let expires = Instant::now() + std::time::Duration::from_millis(100);
        let client = NativeClient::install(BufReader::new(read), write, expires, minimum_framing());
        let handle = Arc::new(
            client
                .start_upload("deadline", 1, &format!("{:x}", Sha256::digest(b"x")), false)
                .unwrap(),
        );
        let begin = receive(&mut peer_read).await;
        reply(&mut peer_write, &upload_progress(&begin, 0, 0)).await;
        let entered = Arc::new(Notify::new());
        let reader_entered = entered.clone();
        let owned = handle.clone();
        let task = tokio::spawn(async move {
            let mut reader = StalledInput {
                entered: reader_entered,
            };
            owned.upload_from(&mut reader).await
        });
        entered.notified().await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), task)
                .await
                .expect("fixed deadline bounds stream")
                .expect("stream task")
                .is_err()
        );
        assert_eq!(client.expires, expires);
        let state = client.state.lock().unwrap();
        let record = &state.records[&handle.identity.operation_id];
        assert!(record.unknown);
        assert!(record.upload.as_ref().unwrap().stream_started);
        assert!(!record.upload.as_ref().unwrap().stream_leased);
        assert_eq!(state.records.len(), 1);
    }

    #[tokio::test]
    async fn native_upload_lost_commit_original_query_recovers_cached_result_without_resend() {
        let (client, mut read, mut write) = fixture();
        let digest = format!("{:x}", Sha256::digest(b""));
        let handle = Arc::new(client.start_upload("empty", 0, &digest, false).unwrap());
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        handle.wait_ready().await.unwrap();
        let owned = handle.clone();
        let commit = tokio::spawn(async move { owned.commit().await });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "upload_commit");
        reply(
            &mut write,
            &Envelope {
                kind: "error".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"code":"unknown"}),
            },
        )
        .await;
        assert!(commit.await.expect("commit task").is_err());
        assert!(handle.commit().await.is_err());
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query().await });
        let frame = receive(&mut read).await;
        assert_eq!(frame.kind, "query");
        assert_eq!(frame.operation_id, begin.operation_id);
        reply(
            &mut write,
            &Envelope {
                kind: "upload_result".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"path":begin.payload["path"],"size":0,"sha256":digest}),
            },
        )
        .await;
        assert!(
            matches!(query.await.expect("query task").unwrap(),NativeUploadObservation::Complete(result) if result.size==0)
        );
        assert_eq!(handle.wait().await.unwrap().sha256, digest);
        assert_eq!(handle.commit().await.unwrap().sha256, digest);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        assert_eq!(client.state.lock().unwrap().bytes, UPLOAD_RECEIPTS);
    }
    #[tokio::test]
    async fn native_upload_prior_query_prefix_never_authorizes_uncertain_chunk_replay() {
        let (client, mut read, mut write) = fixture();
        let handle = Arc::new(
            client
                .start_upload(
                    "pending",
                    3,
                    &format!("{:x}", Sha256::digest(b"abc")),
                    false,
                )
                .unwrap(),
        );
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        handle.wait_ready().await.unwrap();
        let owned = handle.clone();
        let chunk = tokio::spawn(async move { owned.write_chunk(b"abc").await });
        let _ = receive(&mut read).await;
        reply(
            &mut write,
            &Envelope {
                kind: "status".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"state":"unknown"}),
            },
        )
        .await;
        assert!(chunk.await.expect("chunk task").is_err());
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query().await });
        assert_eq!(receive(&mut read).await.kind, "query");
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        assert!(
            matches!(query.await.expect("query task").unwrap(),NativeUploadObservation::Progress(progress) if progress.next_sequence==0)
        );
        assert!(handle.write_chunk(b"abc").await.is_err());
        assert!(handle.commit().await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        let state = client.state.lock().unwrap();
        assert_eq!(
            state.records[&begin.operation_id]
                .upload
                .as_ref()
                .unwrap()
                .receipts
                .len(),
            1
        );
        assert_eq!(state.bytes, UPLOAD_RECEIPTS);
    }
    #[tokio::test]
    async fn native_upload_receipts_reject_closed_schema_identity_unknown_prefix_and_early_result()
    {
        for fault in 0..6 {
            let (client, mut read, mut write) = fixture();
            let handle = client
                .start_upload("checked", 1, &"a".repeat(64), false)
                .unwrap();
            let begin = receive(&mut read).await;
            let mut event = upload_progress(&begin, 0, 0);
            match fault {
                0 => event.payload["extra"] = json!(true),
                1 => event.payload["path"] = json!("other"),
                2 => event.payload["next_sequence"] = json!(1),
                3 => event.payload["received"] = json!(1),
                4 => event.payload["size"] = json!(2),
                _ => {
                    event.kind = "upload_result".into();
                    event.payload.as_object_mut().unwrap().remove("received");
                    event
                        .payload
                        .as_object_mut()
                        .unwrap()
                        .remove("next_sequence");
                }
            }
            reply(&mut write, &event).await;
            assert!(handle.wait_ready().await.is_err());
            assert!(!client.is_ready());
            assert!(client
                .state
                .lock()
                .unwrap()
                .records
                .contains_key(&begin.operation_id));
        }
    }
    #[tokio::test]
    async fn native_upload_queued_cancel_never_dispatches_begin_after_preceding_terminal() {
        let (client, mut read, mut write) = fixture();
        let first = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        let request = receive(&mut read).await;
        let upload = client
            .start_upload(
                "never-truncated",
                0,
                &format!("{:x}", Sha256::digest(b"")),
                true,
            )
            .unwrap();
        upload.cancel().await.unwrap();
        reply(&mut write,&Envelope {kind:"terminal".into(),session_id:request.session_id.clone(),operation_id:request.operation_id.clone(),payload:json!({"state":"succeeded","exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"process_absent":true})}).await;
        first.wait().await.unwrap();
        assert!(upload.wait_ready().await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        let state = client.state.lock().unwrap();
        let record = &state.records[&upload.identity.operation_id];
        assert!(record.aborted);
        assert!(!record.dispatched);
        assert_eq!(state.bytes, UPLOAD_RECEIPTS);
    }
    #[tokio::test]
    async fn native_query_new_unknown_status_never_relabels_cached_terminal_as_fresh_truth() {
        let (client, mut read, mut write) = fixture();
        let handle = Arc::new(
            client
                .start("/bin/sh", &[], &ProcessOpts::default())
                .unwrap(),
        );
        let begin = receive(&mut read).await;
        reply(&mut write,&Envelope {kind:"terminal".into(),session_id:begin.session_id.clone(),operation_id:begin.operation_id.clone(),payload:json!({"state":"succeeded","exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"process_absent":true})}).await;
        handle.wait().await.unwrap();
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query_status().await });
        let request = receive(&mut read).await;
        assert_eq!(request.kind, "query");
        reply(
            &mut write,
            &Envelope {
                kind: "status".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"state":"unknown"}),
            },
        )
        .await;
        let status = query.await.expect("query task").unwrap();
        assert_eq!(
            status.state, "unknown",
            "fresh Status must not be replaced with cached Terminal"
        );
        assert!(!status.terminal);
        assert!(!status.process_absent);
        assert_eq!(status.identity.operation_id, begin.operation_id);
        // Fresh uncertainty does not rewrite the immutable original completion.
        handle.wait().await.unwrap();
        assert_eq!(
            client.state.lock().unwrap().records[&begin.operation_id]
                .terminal
                .as_ref()
                .unwrap()["state"],
            "succeeded"
        );
    }

    #[tokio::test]
    async fn native_query_active_cancel_never_returns_old_running_without_new_guest_truth() {
        let (client, mut read, mut write) = fixture();
        let handle = Arc::new(
            client
                .start("/bin/sh", &[], &ProcessOpts::default())
                .unwrap(),
        );
        let begin = receive(&mut read).await;
        let owned = handle.clone();
        let first = tokio::spawn(async move { owned.query_status().await });
        assert_eq!(receive(&mut read).await.kind, "query");
        reply(
            &mut write,
            &Envelope {
                kind: "status".into(),
                session_id: begin.session_id.clone(),
                operation_id: begin.operation_id.clone(),
                payload: json!({"state":"running"}),
            },
        )
        .await;
        assert_eq!(
            first.await.expect("first query task").unwrap().state,
            "running"
        );
        let owned = handle.clone();
        let mut query = tokio::spawn(async move { owned.query_status().await });
        let request = receive(&mut read).await;
        assert_eq!(request.kind, "query");
        assert_eq!(request.operation_id, begin.operation_id);
        handle.control("cancel").await.unwrap();
        assert_eq!(receive(&mut read).await.kind, "cancel");
        // The observed pipe request is the barrier: no guest response has been
        // supplied for this query or cancellation. Local intent is not new truth.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut query)
                .await
                .is_err(),
            "query must await new authenticated truth instead of cached Running"
        );
        reply(&mut write,&Envelope {kind:"terminal".into(),session_id:begin.session_id,operation_id:begin.operation_id,payload:json!({"state":"cancelled","exit_code":null,"stdout_bytes":0,"stderr_bytes":0,"process_absent":true})}).await;
        let status = query.await.expect("second query task").unwrap();
        assert_eq!(status.state, "cancelled");
        assert!(status.terminal);
        assert!(status.process_absent);
    }

    #[tokio::test]
    async fn native_exec_cancel_intent_blocks_dispatch_before_actor_reads_control() {
        let (client, mut read, _write) = fixture();
        let handle = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        // control only enqueues; the current-thread actor cannot consume it
        // before this synchronous dispatch decision.
        handle.control("cancel").await.unwrap();
        assert!(
            !mark_dispatched(&client, &handle.identity.operation_id),
            "frozen Exec cancellation must refuse dispatch"
        );
        assert!(client.state.lock().unwrap().records[&handle.identity.operation_id].aborted);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn native_file_cancel_intent_blocks_dispatch_before_actor_reads_control() {
        let (client, mut read, _write) = fixture();
        let handle = client
            .start_file_write("never-written", 0, b"owned")
            .unwrap();
        handle.cancel().await.unwrap();
        assert!(
            !mark_dispatched(&client, &handle.identity.operation_id),
            "frozen file cancellation must refuse dispatch"
        );
        assert!(client.state.lock().unwrap().records[&handle.identity.operation_id].aborted);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn native_upload_cancel_intent_blocks_dispatch_before_actor_reads_control() {
        let (client, _read, _write) = fixture();
        // This current-thread test reaches no yielding I/O before checking the
        // same guard used on new admission and on queued dequeue.
        let upload = client
            .start_upload(
                "never-truncated",
                0,
                &format!("{:x}", Sha256::digest(b"")),
                true,
            )
            .unwrap();
        upload.cancel().await.unwrap();
        assert!(abort_undispatched_cancelled(
            &client,
            &upload.identity.operation_id
        ));
        assert!(!mark_dispatched(&client, &upload.identity.operation_id));
        let state = client.state.lock().unwrap();
        let record = &state.records[&upload.identity.operation_id];
        assert!(record.aborted);
        assert!(!record.dispatched);
        assert_eq!(state.bytes, UPLOAD_RECEIPTS);
    }

    #[tokio::test]
    async fn native_upload_active_cancel_unknown_keeps_serial_owner_and_receipts() {
        let (client, mut read, mut write) = fixture();
        let upload = client
            .start_upload("active", 0, &format!("{:x}", Sha256::digest(b"")), false)
            .unwrap();
        let begin = receive(&mut read).await;
        reply(&mut write, &upload_progress(&begin, 0, 0)).await;
        upload.wait_ready().await.unwrap();
        client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        upload.cancel().await.unwrap();
        assert_eq!(receive(&mut read).await.kind, "cancel");
        reply(
            &mut write,
            &Envelope {
                kind: "status".into(),
                session_id: begin.session_id,
                operation_id: begin.operation_id,
                payload: json!({"state":"unknown"}),
            },
        )
        .await;
        assert!(upload.wait().await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        assert!(client.is_ready());
        assert_eq!(client.state.lock().unwrap().bytes, UPLOAD_RECEIPTS);
    }

    // Bounded chunk bridge only: no whole-file replacement, directory or VM proof.
    fn file_reply(request: &Envelope, data: &[u8]) -> Envelope {
        Envelope {
            kind: "file_result".into(),
            session_id: request.session_id.clone(),
            operation_id: request.operation_id.clone(),
            payload: json!({"path":request.payload["path"],"offset":request.payload["offset"],"data":STANDARD.encode(data),"sha256":format!("{:x}",Sha256::digest(data))}),
        }
    }
    async fn reply(write: &mut (impl AsyncWrite + Unpin), frame: &Envelope) {
        send(
            write,
            frame,
            Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn native_file_binary_chunks_retained_without_output_ack() {
        let bytes: Vec<u8> = (0..16384).map(|n| (n % 256) as u8).collect();
        for writing in [false, true] {
            let (client, mut read, mut write) = fixture();
            let handle = if writing {
                client.start_file_write("binary.bin", 17, &bytes).unwrap()
            } else {
                client.start_file_read("binary.bin", 17, 16384).unwrap()
            };
            let req = receive(&mut read).await;
            assert_eq!(req.kind, if writing { "file_write" } else { "file_read" });
            assert_eq!(req.operation_id, handle.identity.operation_id);
            reply(&mut write, &file_reply(&req, &bytes)).await;
            let result = handle.wait().await.unwrap();
            assert_eq!(result.identity.operation_id, req.operation_id);
            assert_eq!(result.identity.session_id, req.session_id);
            assert_eq!(result.path, "binary.bin");
            assert_eq!(result.offset, 17);
            assert_eq!(result.data, bytes);
            assert_eq!(result.sha256, format!("{:x}", Sha256::digest(&bytes)));
            // Caller delivery is not an output ACK; the actor retains repeat wait truth.
            assert_eq!(handle.wait().await.unwrap().data, bytes);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(5), receive(&mut read))
                    .await
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn native_file_original_query_requires_new_result_without_rewriting() {
        let (client, mut read, mut write) = fixture();
        let handle = Arc::new(
            client
                .start_file_write("original.bin", 0, b"\0\xff")
                .unwrap(),
        );
        let req = receive(&mut read).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), handle.wait())
                .await
                .is_err()
        );
        let queried = handle.clone();
        let query = tokio::spawn(async move { queried.query_result().await });
        let q = receive(&mut read).await;
        assert_eq!(q.kind, "query");
        assert_eq!(q.operation_id, req.operation_id);
        assert_eq!(q.session_id, req.session_id);
        assert!(!query.is_finished());
        reply(
            &mut write,
            &Envelope {
                kind: "status".into(),
                session_id: q.session_id,
                operation_id: q.operation_id,
                payload: json!({"state":"unknown","acked_sequence":0}),
            },
        )
        .await;
        assert!(query.await.unwrap().is_err());
        let queried = handle.clone();
        let query = tokio::spawn(async move { queried.query_result().await });
        let q = receive(&mut read).await;
        assert_eq!(q.kind, "query");
        assert_eq!(q.operation_id, req.operation_id);
        reply(&mut write, &file_reply(&req, b"\0\xff")).await;
        assert_eq!(query.await.unwrap().unwrap().data, b"\0\xff");
        assert_eq!(
            handle.wait().await.unwrap().identity.operation_id,
            req.operation_id
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), receive(&mut read))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn native_file_query_status_cannot_relabel_cached_result_as_new_truth() {
        let (client, mut read, mut write) = fixture();
        let handle = Arc::new(client.start_file_write("cached", 0, b"x").unwrap());
        let request = receive(&mut read).await;
        reply(&mut write, &file_reply(&request, b"x")).await;
        assert_eq!(handle.wait().await.unwrap().data, b"x");
        let owned = handle.clone();
        let query = tokio::spawn(async move { owned.query_result().await });
        let q = receive(&mut read).await;
        reply(
            &mut write,
            &Envelope {
                kind: "status".into(),
                session_id: q.session_id,
                operation_id: q.operation_id,
                payload: json!({"state":"unknown","acked_sequence":0}),
            },
        )
        .await;
        assert!(query.await.unwrap().is_err());
        assert_eq!(handle.wait().await.unwrap().data, b"x");
    }
    #[tokio::test]
    async fn native_file_exact_bounds_empty_write_and_escaped_paths_are_accepted() {
        for (path, offset, data) in [
            ("newline\n\t雪", 33554432, Vec::new()),
            ("boundary", 33538048, vec![0xff; 16384]),
        ] {
            let (client, mut read, mut write) = fixture();
            let handle = client.start_file_write(path, offset, &data).unwrap();
            let request = receive(&mut read).await;
            assert_eq!(request.payload["path"], path);
            reply(&mut write, &file_reply(&request, &data)).await;
            assert_eq!(handle.wait().await.unwrap().data, data);
        }
    }
    #[tokio::test]
    async fn native_file_eof_retains_original_unknown_without_replay() {
        let (client, mut read, mut write) = fixture();
        let handle = client.start_file_write("lost.bin", 0, b"owned").unwrap();
        let req = receive(&mut read).await;
        // split() halves share the DuplexStream; dropping only WriteHalf does
        // not close it while the retained reader is used to detect replay.
        write.shutdown().await.unwrap();
        drop(write);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), handle.wait())
                .await
                .unwrap()
                .is_err()
        );
        assert!(handle.query_result().await.is_err());
        assert_eq!(handle.identity.operation_id, req.operation_id);
        assert!(client
            .state
            .lock()
            .unwrap()
            .records
            .contains_key(&req.operation_id));
        match tokio::time::timeout(
            std::time::Duration::from_millis(5),
            read_line(&mut read, &mut Vec::new()),
        )
        .await
        {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("file write must never be replayed"),
        }
    }
    #[tokio::test]
    async fn native_file_result_rejects_wrong_kind_path_offset_base64_digest_and_bytes() {
        for invalid in 0..7 {
            let (client, mut read, mut write) = fixture();
            let handle = client.start_file_write("checked.bin", 3, b"x").unwrap();
            let req = receive(&mut read).await;
            let mut response = file_reply(&req, b"x");
            match invalid {
                0 => {
                    response.kind = "terminal".into();
                    response.payload = json!({"state":"succeeded","exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"process_absent":true});
                }
                1 => response.payload["path"] = "other.bin".into(),
                2 => response.payload["offset"] = 4.into(),
                3 => response.payload["data"] = "eA".into(),
                4 => response.payload["sha256"] = "0".repeat(64).into(),
                5 => response = file_reply(&req, b"y"),
                _ => response.payload["extra"] = true.into(),
            }
            reply(&mut write, &response).await;
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(1), handle.wait())
                    .await
                    .unwrap()
                    .is_err()
            );
            assert!(!client.is_ready());
            assert_eq!(handle.identity.operation_id, req.operation_id);
        }
        let (client, mut read, mut write) = fixture();
        let handle = client.start_file_read("bounded.bin", 0, 1).unwrap();
        let req = receive(&mut read).await;
        reply(&mut write, &file_reply(&req, b"xx")).await;
        assert!(handle.wait().await.is_err());
    }
    #[tokio::test]
    async fn native_file_preflight_bounds_preserve_active_before_reservation() {
        let (client, mut read, _write) = fixture();
        let active = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        let original = receive(&mut read).await;
        for path in [
            "",
            "/workspace/file",
            "../file",
            "a/../b",
            "a//b",
            "a\\b",
            "a\0b",
            ".",
        ] {
            assert!(client.start_file_read(path, 0, 1).is_err());
            assert!(client.start_file_write(path, 0, b"x").is_err());
        }
        assert!(client.start_file_read(&"x".repeat(65), 0, 1).is_err());
        assert!(client
            .start_file_read(&vec!["a"; 17].join("/"), 0, 1)
            .is_err());
        for (offset, length) in [(0, 0), (0, 16385), (33554432, 1), (u64::MAX, 1)] {
            assert!(client.start_file_read("valid", offset, length).is_err());
        }
        assert!(client
            .start_file_write("valid", 0, &vec![0; 16385])
            .is_err());
        assert!(client.start_file_write("valid", 33554432, b"x").is_err());
        assert!(client.start_file_write("valid", u64::MAX, b"x").is_err());
        assert!(client.is_ready());
        {
            let state = client.state.lock().unwrap();
            assert_eq!(state.records.len(), 1);
            assert_eq!(
                state.records[&active.identity.operation_id]._request,
                original.payload
            );
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), receive(&mut read))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn native_file_and_exec_share_serial_queue_and_lifetime_history() {
        let (client, mut read, mut write) = fixture();
        let first = client.start_file_write("first", 0, b"x").unwrap();
        let second = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        let req = receive(&mut read).await;
        assert_eq!(req.operation_id, first.identity.operation_id);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), receive(&mut read))
                .await
                .is_err()
        );
        reply(&mut write, &file_reply(&req, b"x")).await;
        assert_eq!(
            receive(&mut read).await.operation_id,
            second.identity.operation_id
        );
        for _ in 2..32 {
            client.start_file_read("first", 0, 1).unwrap();
        }
        assert!(client.start_file_read("first", 0, 1).is_err());
        assert!(client.start_file_write("first", 0, b"x").is_err());
        assert!(client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .is_err());
    }
    #[tokio::test]
    async fn native_file_queued_cancel_never_dispatches_after_prior_terminal() {
        let (client, mut read, mut write) = fixture();
        let first = client
            .start("/bin/sh", &[], &ProcessOpts::default())
            .unwrap();
        let queued = client.start_file_write("never-created", 0, b"x").unwrap();
        let req = receive(&mut read).await;
        assert_eq!(req.operation_id, first.identity.operation_id);
        queued.cancel().await.unwrap();
        assert!(queued.wait().await.is_err());
        reply(&mut write,&Envelope{kind:"terminal".into(),session_id:req.session_id,operation_id:req.operation_id,payload:json!({"state":"succeeded","exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"process_absent":true})}).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut read))
                .await
                .is_err()
        );
        assert!(client.is_ready());
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[tokio::test]
    async fn queued_cancel_never_dispatches_after_preceding_terminal() {
        let (host, broker) = tokio::io::duplex(131072);
        let (r, w) = tokio::io::split(host);
        let (pr, mut pw) = tokio::io::split(broker);
        let client = NativeClient::install(
            tokio::io::BufReader::new(r),
            w,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
        );
        let mut reader = tokio::io::BufReader::new(pr);
        let first = client
            .start("/bin/a", &[], &ProcessOpts::default())
            .unwrap();
        let second = client
            .start("/bin/b", &[], &ProcessOpts::default())
            .unwrap();
        let _: Envelope =
            serde_json::from_slice(&read_line(&mut reader, &mut Vec::new()).await.unwrap())
                .unwrap();
        second.control("cancel").await.unwrap();
        assert!(second.wait().await.is_err());
        send(&mut pw,&Envelope {kind:"terminal".into(),session_id:first.identity.session_id,operation_id:first.identity.operation_id,payload:json!({"state":"succeeded","exit_code":0,"stdout_bytes":0,"stderr_bytes":0,"process_absent":true})},Instant::now()+std::time::Duration::from_secs(3)).await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            read_line(&mut reader, &mut Vec::new())
        )
        .await
        .is_err());
        assert!(client.is_ready());
    }
}

#[cfg(test)]
mod acknowledgement_tests {
    use super::*;
    #[tokio::test]
    async fn repeated_terminal_can_advance_authenticated_retention_prefix() {
        let (host, broker) = tokio::io::duplex(131072);
        let (r, w) = tokio::io::split(host);
        let (pr, mut pw) = tokio::io::split(broker);
        let client = NativeClient::install(
            tokio::io::BufReader::new(r),
            w,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
        );
        let mut reader = tokio::io::BufReader::new(pr);
        let handle = client
            .start("/bin/a", &[], &ProcessOpts::default())
            .unwrap();
        let _: Envelope =
            serde_json::from_slice(&read_line(&mut reader, &mut Vec::new()).await.unwrap())
                .unwrap();
        let event = |kind: &str, payload: Value| Envelope {
            kind: kind.into(),
            session_id: handle.identity.session_id.clone(),
            operation_id: handle.identity.operation_id.clone(),
            payload,
        };
        let until = Instant::now() + std::time::Duration::from_secs(3);
        send(
            &mut pw,
            &event(
                "output",
                json!({"sequence":0,"stream":"stdout","data":"YQ=="}),
            ),
            until,
        )
        .await
        .unwrap();
        let _: Envelope =
            serde_json::from_slice(&read_line(&mut reader, &mut Vec::new()).await.unwrap())
                .unwrap();
        send(&mut pw,&event("terminal",json!({"state":"succeeded","exit_code":0,"stdout_bytes":1,"stderr_bytes":0,"process_absent":true,"acked_sequence":0})),until).await.unwrap();
        assert_eq!(handle.wait().await.unwrap().stdout, "a");
        send(&mut pw,&event("terminal",json!({"state":"succeeded","exit_code":0,"stdout_bytes":1,"stderr_bytes":0,"process_absent":true,"acked_sequence":1})),until).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if client.state.lock().unwrap().records[&handle.identity.operation_id].acked == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(client.is_ready());
        send(
            &mut pw,
            &event("status", json!({"state":"terminal","acked_sequence":2})),
            until,
        )
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while client.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!client.is_ready());
    }
}

#[cfg(test)]
mod frame_clock_tests {
    use super::*;
    #[tokio::test]
    async fn idle_does_not_start_clock_and_select_cancellation_cannot_renew_partial_line() {
        let (host, mut peer) = tokio::io::duplex(64);
        let mut reader = tokio::io::BufReader::new(host);
        let mut carry = Vec::new();
        let mut clock = None;
        let expires = Instant::now() + std::time::Duration::from_secs(30);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            read_line_clock(&mut reader, &mut carry, &mut clock, expires)
        )
        .await
        .is_err());
        assert!(clock.is_none());
        peer.write_all(b"{").await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            read_line_clock(&mut reader, &mut carry, &mut clock, expires)
        )
        .await
        .is_err());
        let first = clock.expect("first byte starts fixed deadline");
        assert_eq!(carry, b"{");
        for _ in 0..3 {
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(10),
                read_line_clock(&mut reader, &mut carry, &mut clock, expires)
            )
            .await
            .is_err());
            assert_eq!(clock, Some(first));
        }
        tokio::time::sleep_until(tokio::time::Instant::from_std(first)).await;
        peer.write_all(b"}\n").await.unwrap();
        assert!(
            read_line_clock(&mut reader, &mut carry, &mut clock, expires)
                .await
                .is_err()
        );
        assert_eq!(clock, Some(first));
    }
}

#[cfg(test)]
mod query_status_tests {
    use super::*;
    #[tokio::test]
    async fn typed_query_requires_new_authenticated_truth_for_original_identity() {
        let (host, broker) = tokio::io::duplex(131072);
        let (r, w) = tokio::io::split(host);
        let (pr, mut pw) = tokio::io::split(broker);
        let client = NativeClient::install(
            tokio::io::BufReader::new(r),
            w,
            Instant::now() + std::time::Duration::from_secs(30),
            minimum_framing(),
        );
        let mut reader = tokio::io::BufReader::new(pr);
        let handle = client
            .start("/bin/a", &[], &ProcessOpts::default())
            .unwrap();
        let _: Envelope =
            serde_json::from_slice(&read_line(&mut reader, &mut Vec::new()).await.unwrap())
                .unwrap();
        let identity = handle.identity.clone();
        let query = tokio::spawn(async move { handle.query_status().await });
        let request: Envelope =
            serde_json::from_slice(&read_line(&mut reader, &mut Vec::new()).await.unwrap())
                .unwrap();
        assert_eq!(request.kind, "query");
        assert_eq!(request.operation_id, identity.operation_id);
        assert_eq!(request.session_id, identity.session_id);
        assert!(!query.is_finished());
        send(
            &mut pw,
            &Envelope {
                kind: "status".into(),
                session_id: identity.session_id,
                operation_id: identity.operation_id,
                payload: json!({"state":"running","acked_sequence":0}),
            },
            Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        let status = query.await.unwrap().unwrap();
        assert_eq!(status.state, "running");
        assert!(!status.terminal);
        assert!(!status.process_absent);
    }
}

#[cfg(test)]
mod signed_frame_tests {
    use super::*;
    fn signed_length(
        envelope: &Envelope,
        node: &str,
        owner: &str,
        generation: u64,
        nonce: &str,
    ) -> usize {
        let mut body = serde_json::to_value(envelope).unwrap();
        let object = body.as_object_mut().unwrap();
        for (name, value) in [
            ("schema", json!(2)),
            ("node_id", json!(node)),
            ("owner_id", json!(owner)),
            ("generation", json!(generation)),
            ("guest_nonce", json!(nonce)),
            ("auth_tag", json!("0".repeat(64))),
        ] {
            object.insert(name.into(), value);
        }
        serde_json::to_vec(&body).unwrap().len()
    }
    #[tokio::test]
    async fn native_exec_actual_binding_signed_frame_accepts_65536_refuses_65537() {
        for (node, owner, generation, expected_delta) in [
            ("n".to_owned(), "o".to_owned(), 1, 214),
            ("n".repeat(64), "o".repeat(64), i64::MAX as u64, 358),
        ] {
            let nonce = "a".repeat(64);
            let framing = NativeFraming::new(&node, &owner, generation, &nonce).unwrap();
            assert_eq!(framing.signed_delta, expected_delta);
            let opts = ProcessOpts::default().with_timeout(std::time::Duration::from_millis(1));
            let first = "\u{1}".repeat(4096);
            let second = "\u{1}".repeat(4096);
            let base = Envelope {
                kind: "exec".into(),
                session_id: "00000000-0000-0000-0000-000000000000".into(),
                operation_id: "00000000-0000-0000-0000-000000000000".into(),
                payload: native_exec_payload("/bin/sh", &[&first, &second, ""], &opts).unwrap(),
            };
            let padding = LINE - signed_length(&base, &node, &owner, generation, &nonce);
            let third = format!("{}{}", "\u{1}".repeat(padding / 6), "x".repeat(padding % 6));
            let (host, broker) = tokio::io::duplex(131072);
            let (r, w) = tokio::io::split(host);
            let (pr, _pw) = tokio::io::split(broker);
            let client = NativeClient::install(
                tokio::io::BufReader::new(r),
                w,
                Instant::now() + std::time::Duration::from_secs(30),
                framing,
            );
            let mut reader = tokio::io::BufReader::new(pr);
            let active = client
                .start("/bin/sh", &[&first, &second, &third], &opts)
                .unwrap();
            let request: Envelope =
                serde_json::from_slice(&read_line(&mut reader, &mut Vec::new()).await.unwrap())
                    .unwrap();
            assert_eq!(
                signed_length(&request, &node, &owner, generation, &nonce),
                65536
            );
            let excessive = format!("{third}x");
            assert!(client
                .start("/bin/sh", &[&first, &second, &excessive], &opts)
                .is_err());
            assert!(client.is_ready());
            {
                let state = client.state.lock().unwrap();
                assert_eq!(state.records.len(), 1);
                assert_eq!(
                    state.records[&active.identity.operation_id]._request,
                    request.payload
                );
                assert!(!state.records[&active.identity.operation_id].unknown);
            }
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(5),
                read_line(&mut reader, &mut Vec::new())
            )
            .await
            .is_err());
        }
    }
    #[test]
    fn native_framing_refuses_unvalidated_public_identity() {
        let nonce = "a".repeat(64);
        for (node, owner, generation, nonce) in [
            ("".to_owned(), "o".to_owned(), 1, nonce.clone()),
            ("n".repeat(65), "o".to_owned(), 1, nonce.clone()),
            ("n".to_owned(), "owner\n".to_owned(), 1, nonce.clone()),
            ("n".to_owned(), "o".to_owned(), 0, nonce.clone()),
            ("n".to_owned(), "o".to_owned(), 1u64 << 63, nonce.clone()),
            ("n".to_owned(), "o".to_owned(), 1, "a".repeat(63)),
        ] {
            assert!(NativeFraming::new(&node, &owner, generation, &nonce).is_err());
        }
    }
}

#[cfg(test)]
#[path = "native_process_keyed_tests.rs"]
mod keyed_tests;
