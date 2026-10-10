//! Reciprocal protected Worker issuer transport; no VM or launch receipt.

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum DiagnosticStage {
    Endpoint,
    Exchange,
    ReplyDecode,
    GrantValidate,
    Deadline,
    StateVerify,
    FinalDeadline,
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
            stage: DiagnosticStage::Endpoint,
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
            "native_reserve stage={:?} ok={} elapsed_ms={} remaining_ms={}",
            self.stage,
            self.ok,
            self.started.elapsed().as_millis(),
            self.until
                .saturating_duration_since(Instant::now())
                .as_millis()
        );
    }
}
use anyhow::{ensure, Context, Result};
use nix::{
    poll::{poll, PollFd, PollFlags},
    sys::socket::{self, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr},
    unistd::{unlinkat, UnlinkatFlags},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{IoSliceMut, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

pub(super) fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
}
pub(super) fn same_anchor(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
}
pub(super) fn ancestors(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "issuer protected absolute path required"
    );
    let mut next = path.parent();
    while let Some(p) = next {
        let m = std::fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
            "issuer protected ancestry refused"
        );
        next = p.parent();
    }
    Ok(())
}
pub(super) struct Held {
    pub(super) file: File,
    pub(super) path: PathBuf,
    pub(super) pin: Metadata,
    pub(super) digest: [u8; 32],
}
impl Held {
    pub(super) fn load(path: &Path) -> Result<(Self, Vec<u8>)> {
        ancestors(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
            .open(path)?;
        let pin = file.metadata()?;
        ensure!(
            pin.is_file()
                && pin.uid() == 0
                && pin.gid() == 0
                && pin.mode() & 0o777 == 0o600
                && pin.nlink() == 1
                && pin.len() > 0
                && pin.len() <= 8192,
            "issuer protected file refused"
        );
        let mut raw = Vec::new();
        (&mut file).take(8193).read_to_end(&mut raw)?;
        ensure!(
            raw.len() as u64 == pin.len()
                && same(&pin, &file.metadata()?)
                && same(&pin, &std::fs::symlink_metadata(path)?),
            "issuer file changed"
        );
        let digest = Sha256::digest(&raw).into();
        Ok((
            Self {
                file,
                path: path.to_owned(),
                pin,
                digest,
            },
            raw,
        ))
    }
    pub(super) fn verify(&self) -> Result<()> {
        ancestors(&self.path)?;
        use std::os::unix::fs::FileExt;
        let mut raw = [0u8; 8193];
        let mut total = 0;
        loop {
            let n = self.file.read_at(&mut raw[total..], total as u64)?;
            if n == 0 {
                break;
            }
            total += n;
            ensure!(total <= 8192, "issuer input bound");
        }
        let digest: [u8; 32] = Sha256::digest(&raw[..total]).into();
        ensure!(
            digest == self.digest
                && same(&self.pin, &self.file.metadata()?)
                && same(&self.pin, &std::fs::symlink_metadata(&self.path)?),
            "issuer input changed"
        );
        Ok(())
    }
}
pub(super) struct PublicationState {
    pub(super) root: File,
    pub(super) root_path: PathBuf,
    pub(super) root_pin: Metadata,
    pub(super) file: Option<File>,
    pub(super) pin: Option<Metadata>,
}
pub(super) struct Publication {
    pub(super) state: Option<PublicationState>,
}
impl std::ops::Deref for Publication {
    type Target = PublicationState;
    fn deref(&self) -> &Self::Target {
        self.state.as_ref().expect("retained publication")
    }
}
impl std::ops::DerefMut for Publication {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state.as_mut().expect("retained publication")
    }
}
impl Drop for Publication {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            if state.file.is_some() {
                debts()
                    .lock()
                    .expect("requester publication debt")
                    .push(state);
            }
        }
    }
}
impl Publication {
    pub(super) fn new(path: &Path) -> Result<Self> {
        ancestors(&path.join("requester-identity.json"))?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        let pin = root.metadata()?;
        ensure!(
            pin.is_dir()
                && pin.uid() == 0
                && pin.gid() == 0
                && pin.mode() & 0o777 == 0o700
                && same(&pin, &std::fs::symlink_metadata(path)?),
            "issuer namespace refused"
        );
        Ok(Self {
            state: Some(PublicationState {
                root,
                root_path: path.to_owned(),
                root_pin: pin,
                file: None,
                pin: None,
            }),
        })
    }
    pub(super) fn root_valid(&self) -> Result<()> {
        ensure!(
            same_anchor(&self.root_pin, &self.root.metadata()?)
                && same_anchor(&self.root_pin, &std::fs::symlink_metadata(&self.root_path)?),
            "issuer namespace replaced"
        );
        Ok(())
    }
    pub(super) fn publish(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() <= 8192, "requester identity oversized");
        self.root_valid()?;
        let path = self.root_path.join("requester-identity.json");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        self.file = Some(file); // Custody installed before permission/stat/write failures.
        let pin = self.file.as_ref().unwrap().metadata()?;
        self.pin = Some(pin);
        ensure!(
            self.pin.as_ref().unwrap().is_file()
                && self.pin.as_ref().unwrap().uid() == 0
                && self.pin.as_ref().unwrap().gid() == 0
                && self.pin.as_ref().unwrap().nlink() == 1
                && self.pin.as_ref().unwrap().mode() & 0o777 == 0o600,
            "issuer publication ownership refused"
        );
        self.file.as_mut().unwrap().write_all(bytes)?;
        self.file.as_ref().unwrap().sync_all()?;
        self.pin = Some(self.file.as_ref().unwrap().metadata()?);
        self.root.sync_all()?;
        self.valid()
    }
    pub(super) fn valid(&self) -> Result<()> {
        self.root_valid()?;
        let pin = self
            .pin
            .as_ref()
            .context("issuer publication capture incomplete")?;
        ensure!(
            same(
                pin,
                &self
                    .file
                    .as_ref()
                    .context("issuer publication file")?
                    .metadata()?
            ) && same(
                pin,
                &std::fs::symlink_metadata(self.root_path.join("requester-identity.json"))?
            ),
            "issuer publication changed"
        );
        Ok(())
    }
    pub(super) fn retire(&mut self) -> Result<()> {
        if self.file.is_none() {
            return Ok(());
        }
        self.valid()?;
        unlinkat(
            &self.root,
            "requester-identity.json",
            UnlinkatFlags::NoRemoveDir,
        )?;
        self.file.take();
        self.pin.take();
        self.root.sync_all()?;
        Ok(())
    }
}
pub(super) fn debts() -> &'static Mutex<Vec<PublicationState>> {
    static D: OnceLock<Mutex<Vec<PublicationState>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(Vec::new()))
}
pub(super) fn proc_bytes(pid: u32, name: &str) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    File::open(format!("/proc/{pid}/{name}"))?
        .take(8193)
        .read_to_end(&mut raw)?;
    ensure!(raw.len() <= 8192, "issuer process metadata oversized");
    Ok(raw)
}
pub(super) fn tick(pid: u32) -> Result<u64> {
    let raw = proc_bytes(pid, "stat")?;
    let text = std::str::from_utf8(&raw)?;
    let rest = text.rsplit_once(')').context("issuer process stat")?.1;
    Ok(rest
        .split_whitespace()
        .nth(19)
        .context("issuer process tick")?
        .parse()?)
}
pub(super) fn cgroup(pid: u32) -> Result<PathBuf> {
    let raw = proc_bytes(pid, "cgroup")?;
    let text = std::str::from_utf8(&raw)?.trim();
    let relative = text
        .strip_prefix("0::/")
        .context("issuer cgroup v2 required")?;
    ensure!(
        !relative.is_empty()
            && relative
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != ".."),
        "issuer cgroup path refused"
    );
    Ok(Path::new("/sys/fs/cgroup").join(relative))
}
pub(super) fn exe(pid: u32, until: Instant) -> Result<(File, Metadata, String)> {
    let path = format!("/proc/{pid}/exe");
    let mut file = File::open(&path)?;
    let pin = file.metadata()?;
    ensure!(
        pin.is_file()
            && pin.uid() == 0
            && pin.gid() == 0
            && pin.nlink() == 1
            && pin.mode() & 0o022 == 0
            && pin.len() > 0
            && pin.len() <= 256 * 1024 * 1024,
        "issuer executable refused"
    );
    #[cfg(test)]
    let diagnostic_started = Instant::now();
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        ensure!(Instant::now() < until, "issuer executable deadline");
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= pin.len(), "issuer executable grew");
        hash.update(&buffer[..n]);
    }
    ensure!(
        total == pin.len()
            && same(&pin, &file.metadata()?)
            && same(&pin, &std::fs::metadata(path)?),
        "issuer executable changed"
    );
    #[cfg(test)]
    eprintln!(
        "issuer sdk hash: bytes={total} elapsed_ms={} remaining_ms={}",
        diagnostic_started.elapsed().as_millis(),
        until.saturating_duration_since(Instant::now()).as_millis()
    );
    Ok((file, pin, format!("{:x}", hash.finalize())))
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Worker {
    pub(super) environment_id: String,
    pub(super) environment_generation: u64,
    pub(super) node_id: u64,
    pub(super) node_generation: u64,
    pub(super) incarnation: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextDto {
    pub(super) protocol_major: u32,
    pub(super) target: Worker,
    pub(super) request_id: u64,
    pub(super) operation_id: String,
    pub(super) attempt_id: String,
    pub(super) remaining_budget_ms: u64,
    pub(super) traceparent: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lease {
    pub(super) reservation_id: String,
    pub(super) slot_index: u64,
    pub(super) slot_generation: u64,
    pub(super) partition_id: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestDto {
    pub(super) schema: u32,
    pub(super) kind: String,
    pub(super) context: ContextDto,
    pub(super) lease: Lease,
    pub(super) tenant_id: u64,
    pub(super) registration_generation: u64,
    pub(super) server_incarnation: String,
    pub(super) profile_allocation_id: String,
    pub(super) request_sha256: String,
}
#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub(super) schema: u32,
    pub(super) authority_epoch: u64,
    pub(super) request: RequestDto,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Endpoint {
    pub(super) schema: u32,
    pub(super) worker: Worker,
    pub(super) peer_pid: u32,
    pub(super) peer_uid: u32,
    pub(super) start_tick: u64,
    pub(super) exe_sha256: String,
    pub(super) cgroup_path: PathBuf,
    pub(super) cgroup_device: u64,
    pub(super) cgroup_inode: u64,
    pub(super) socket_device: u64,
    pub(super) socket_inode: u64,
    pub(super) namespace_device: u64,
    pub(super) namespace_inode: u64,
    pub(super) socket_path: PathBuf,
}
pub(super) struct Peer {
    pub(super) pidfd: OwnedFd,
    pub(super) executable: File,
    pub(super) executable_pin: Metadata,
    pub(super) cgroup_owner: File,
    pub(super) cgroup_pin: Metadata,
    pub(super) socket_pin: Metadata,
}
pub(super) fn alive(fd: &OwnedFd) -> Result<()> {
    let mut pollfds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    ensure!(poll(&mut pollfds, 0u8)? == 0, "issuer peer exited");
    Ok(())
}
pub(super) fn validate_peer(
    fd: &OwnedFd,
    endpoint: &Endpoint,
    root: &Publication,
    until: Instant,
) -> Result<Peer> {
    root.root_valid()?;
    ensure!(
        endpoint.schema == 1
            && endpoint.peer_uid == 0
            && endpoint.namespace_device == root.root_pin.dev()
            && endpoint.namespace_inode == root.root_pin.ino()
            && endpoint.socket_path == root.root_path.join("native-issuer/i.sock"),
        "issuer endpoint binding refused"
    );
    ancestors(&endpoint.socket_path)?;
    let socketpin = std::fs::symlink_metadata(&endpoint.socket_path)?;
    ensure!(
        socketpin.mode() & 0o170000 == 0o140000
            && socketpin.uid() == 0
            && socketpin.gid() == 0
            && socketpin.dev() == endpoint.socket_device
            && socketpin.ino() == endpoint.socket_inode,
        "issuer socket changed"
    );
    let credentials = socket::getsockopt(fd, socket::sockopt::PeerCredentials)?;
    ensure!(
        credentials.pid() as u32 == endpoint.peer_pid
            && credentials.uid() == endpoint.peer_uid
            && credentials.gid() == 0,
        "issuer reciprocal peer refused"
    );
    let pidfd = socket::getsockopt(fd, socket::sockopt::PeerPidfd)?;
    alive(&pidfd)?;
    ensure!(
        tick(endpoint.peer_pid)? == endpoint.start_tick
            && cgroup(endpoint.peer_pid)? == endpoint.cgroup_path,
        "issuer process incarnation drift"
    );
    ancestors(&endpoint.cgroup_path.join("anchor"))?;
    let group = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&endpoint.cgroup_path)?;
    let group_pin = group.metadata()?;
    ensure!(
        group_pin.dev() == endpoint.cgroup_device
            && group_pin.ino() == endpoint.cgroup_inode
            && same(
                &group_pin,
                &std::fs::symlink_metadata(&endpoint.cgroup_path)?
            ),
        "issuer cgroup owner drift"
    );
    let (executable, executable_pin, digest) = exe(endpoint.peer_pid, until)?;
    ensure!(
        digest == endpoint.exe_sha256
            && tick(endpoint.peer_pid)? == endpoint.start_tick
            && cgroup(endpoint.peer_pid)? == endpoint.cgroup_path
            && same(&group_pin, &group.metadata()?)
            && same(
                &group_pin,
                &std::fs::symlink_metadata(&endpoint.cgroup_path)?
            )
            && same(
                &socketpin,
                &std::fs::symlink_metadata(&endpoint.socket_path)?
            ),
        "issuer peer final pins changed"
    );
    alive(&pidfd)?;
    ensure!(Instant::now() < until, "issuer peer validation deadline");
    Ok(Peer {
        pidfd,
        executable,
        executable_pin,
        cgroup_owner: group,
        cgroup_pin: group_pin,
        socket_pin: socketpin,
    })
}
impl Peer {
    pub(super) fn revalidate(
        &self,
        socket_fd: &OwnedFd,
        endpoint: &Endpoint,
        root: &Publication,
        until: Instant,
    ) -> Result<()> {
        ensure!(Instant::now() < until, "issuer peer revalidation deadline");
        root.root_valid()?;
        alive(&self.pidfd)?;
        let credentials = socket::getsockopt(socket_fd, socket::sockopt::PeerCredentials)?;
        ensure!(
            credentials.pid() as u32 == endpoint.peer_pid
                && credentials.uid() == endpoint.peer_uid
                && credentials.gid() == 0,
            "issuer reciprocal peer changed"
        );
        let fresh_pidfd = socket::getsockopt(socket_fd, socket::sockopt::PeerPidfd)?;
        alive(&fresh_pidfd)?;
        ancestors(&endpoint.socket_path)?;
        ancestors(&endpoint.cgroup_path.join("anchor"))?;
        ensure!(
            tick(endpoint.peer_pid)? == endpoint.start_tick
                && cgroup(endpoint.peer_pid)? == endpoint.cgroup_path,
            "issuer peer incarnation changed"
        );
        // The trusted full SHA was established once. A protected original inode
        // must retain every numeric version field before and after each exchange.
        ensure!(
            same(&self.executable_pin, &self.executable.metadata()?)
                && same(
                    &self.executable_pin,
                    &std::fs::metadata(format!("/proc/{}/exe", endpoint.peer_pid))?
                )
                && same(&self.cgroup_pin, &self.cgroup_owner.metadata()?)
                && same(
                    &self.cgroup_pin,
                    &std::fs::symlink_metadata(&endpoint.cgroup_path)?
                )
                && same(
                    &self.socket_pin,
                    &std::fs::symlink_metadata(&endpoint.socket_path)?
                ),
            "issuer original executable or endpoint version changed"
        );
        ensure!(
            tick(endpoint.peer_pid)? == endpoint.start_tick
                && cgroup(endpoint.peer_pid)? == endpoint.cgroup_path,
            "issuer final process pins changed"
        );
        alive(&self.pidfd)?;
        alive(&fresh_pidfd)?;
        ensure!(
            Instant::now() < until,
            "issuer peer revalidation completed late"
        );
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) enum Phase {
    Setup,
    ExePre,
    Recv,
    ExePost,
}
impl Phase {
    #[cfg(test)]
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::ExePre => "exe_pre",
            Self::Recv => "recv",
            Self::ExePost => "exe_post",
        }
    }
}

#[cfg(test)]
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub(super) schema: u32,
    pub(super) status: String,
    pub(super) reason: String,
    pub(super) grant_id: (),
    pub(super) operation_id: String,
    pub(super) reservation_id: String,
    pub(super) worker: Worker,
    pub(super) authority_epoch: u64,
    pub(super) request_id: u64,
    pub(super) partition_id: u64,
    pub(super) slot_index: u64,
    pub(super) slot_generation: u64,
    pub(super) server_incarnation: String,
    pub(super) profile_allocation_id: String,
    pub(super) request_sha256: String,
}
#[cfg(test)]
pub(super) fn expected(request: &RequestDto, epoch: u64) -> Receipt {
    Receipt {
        schema: 1,
        status: "unavailable".into(),
        reason: "profile_allocation_unavailable".into(),
        grant_id: (),
        operation_id: request.context.operation_id.clone(),
        reservation_id: request.lease.reservation_id.clone(),
        worker: request.context.target.clone(),
        authority_epoch: epoch,
        request_id: request.context.request_id,
        partition_id: request.lease.partition_id,
        slot_index: request.lease.slot_index,
        slot_generation: request.lease.slot_generation,
        server_incarnation: request.server_incarnation.clone(),
        profile_allocation_id: request.profile_allocation_id.clone(),
        request_sha256: request.request_sha256.clone(),
    }
}

pub(super) fn exchange_raw(
    endpoint: &Endpoint,
    root: &Publication,
    request: &RequestDto,
    until: Instant,
    authority: &mut Option<Peer>,
    phase: &mut Phase,
) -> Result<Vec<u8>> {
    let fd = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    match socket::connect(fd.as_raw_fd(), &UnixAddr::new(&endpoint.socket_path)?) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => {}
        Err(e) => return Err(e.into()),
    }
    #[cfg(test)]
    let diagnostic_started = Instant::now();
    #[cfg(test)]
    struct Diagnostic<'a> {
        started: Instant,
        until: Instant,
        phase: &'a mut Phase,
    }
    #[cfg(test)]
    impl Drop for Diagnostic<'_> {
        fn drop(&mut self) {
            eprintln!(
                "issuer sdk exchange: stage={} elapsed_ms={} remaining_ms={}",
                self.phase.label(),
                self.started.elapsed().as_millis(),
                self.until
                    .saturating_duration_since(Instant::now())
                    .as_millis()
            );
        }
    }
    #[cfg(test)]
    let diagnostic = Diagnostic {
        started: diagnostic_started,
        until,
        phase,
    };
    #[cfg(test)]
    let phase = &mut *diagnostic.phase;
    *phase = Phase::ExePre;
    if authority.is_none() {
        *authority = Some(validate_peer(&fd, endpoint, root, until)?);
    }
    let peer = authority
        .as_ref()
        .context("issuer retained peer authority")?;
    peer.revalidate(&fd, endpoint, root, until)?;
    #[cfg(test)]
    eprintln!(
        "issuer sdk exchange: stage=validated elapsed_ms={} remaining_ms={}",
        diagnostic_started.elapsed().as_millis(),
        until.saturating_duration_since(Instant::now()).as_millis()
    );
    let raw = serde_json::to_vec(request)?;
    ensure!(raw.len() <= 8192, "issuer request oversized");
    loop {
        alive(&peer.pidfd)?;
        ensure!(Instant::now() < until, "issuer send deadline");
        match socket::send(
            fd.as_raw_fd(),
            &raw,
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
        ) {
            Ok(n) => {
                ensure!(n == raw.len(), "issuer short packet");
                break;
            }
            Err(nix::errno::Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(e.into()),
        }
    }
    #[cfg(test)]
    eprintln!(
        "issuer sdk exchange: stage=sent elapsed_ms={} remaining_ms={}",
        diagnostic_started.elapsed().as_millis(),
        until.saturating_duration_since(Instant::now()).as_millis()
    );
    *phase = Phase::Recv;
    let mut raw = [0u8; 8193];
    let n = loop {
        alive(&peer.pidfd)?;
        ensure!(Instant::now() < until, "issuer receive deadline");
        let mut slices = [IoSliceMut::new(&mut raw)];
        let message =
            socket::recvmsg::<()>(fd.as_raw_fd(), &mut slices, None, MsgFlags::MSG_DONTWAIT);
        match message {
            Ok(m) => {
                ensure!(
                    !m.flags
                        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                        && m.bytes > 0
                        && m.bytes <= 8192,
                    "issuer reply packet refused"
                );
                break m.bytes;
            }
            Err(nix::errno::Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(e.into()),
        }
    };
    *phase = Phase::ExePost;
    peer.revalidate(&fd, endpoint, root, until)?;
    alive(&peer.pidfd)?;
    ensure!(Instant::now() < until, "issuer exchange completed late");
    Ok(raw[..n].to_vec())
}

#[cfg(test)]
pub(super) fn exchange(
    endpoint: &Endpoint,
    root: &Publication,
    request: &RequestDto,
    epoch: u64,
    until: Instant,
    authority: &mut Option<Peer>,
    phase: &mut Phase,
) -> Result<Vec<u8>> {
    let raw = exchange_raw(endpoint, root, request, until, authority, phase)?;
    let actual: Receipt = serde_json::from_slice(&raw)?;
    ensure!(
        actual == expected(request, epoch),
        "issuer original closed unavailable receipt mismatch"
    );
    Ok(raw)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequesterConfig {
    schema: u32,
    namespace: PathBuf,
    endpoint_path: PathBuf,
    intent_directory: PathBuf,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Allocation {
    allocation_id: String,
    profile_path: PathBuf,
    profile_sha256: String,
    rootfs_path: PathBuf,
    config_path: PathBuf,
    credential_path: PathBuf,
    namespace: PathBuf,
    node_id: String,
    owner_id: String,
    generation: u64,
    guest_nonce: String,
    guest_cid: u32,
    kernel_sha256: String,
    rootfs_sha256: String,
    agent_sha256: String,
    config_sha256: String,
}
/// An authenticated reservation, distinct from READY or VM creation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReservedGrant {
    schema: u32,
    status: String,
    grant_id: String,
    operation_id: String,
    reservation_id: String,
    worker: Worker,
    authority_epoch: u64,
    request_id: u64,
    partition_id: u64,
    slot_index: u64,
    slot_generation: u64,
    server_incarnation: String,
    profile_allocation_id: String,
    request_sha256: String,
    tenant_id: u64,
    registration_generation: u64,
    allocation: Allocation,
    inventory_sha256: String,
    entry_sha256: String,
    boot_id: String,
    clock_namespace_device: u64,
    clock_namespace_inode: u64,
    expires_monotonic_ns: u64,
}
/// Closed Worker refusal categories; no remote message or payload is displayed.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RefusalCode {
    Deadline,
    Authority,
    Stale,
    Conflict,
    Capacity,
    Unknown,
    Closed,
    Packet,
    Io,
    Peer,
}
impl RefusalCode {
    fn category(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Authority => "authority",
            Self::Stale => "stale",
            Self::Conflict => "conflict",
            Self::Capacity => "capacity",
            Self::Unknown => "unknown",
            Self::Closed => "closed",
            Self::Packet => "packet",
            Self::Io => "io",
            Self::Peer => "peer",
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RefusedStatus {
    Refused,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalDto {
    schema: u32,
    status: RefusedStatus,
    code: RefusalCode,
}
enum IssuerReply {
    Reserved(Box<ReservedGrant>),
    Refused(RefusalCode),
}
fn decode_reply(raw: &[u8]) -> Result<IssuerReply> {
    ensure!(
        !raw.is_empty() && raw.len() <= 8192,
        "issuer reply bounds refused"
    );
    // Parse each closed DTO directly from bytes. An intermediate Value would
    // discard duplicate keys before the typed duplicate-field checks.
    if let Ok(grant) = serde_json::from_slice::<ReservedGrant>(raw) {
        return Ok(IssuerReply::Reserved(Box::new(grant)));
    }
    let refusal: RefusalDto =
        serde_json::from_slice(raw).map_err(|_| anyhow::anyhow!("issuer reply schema refused"))?;
    ensure!(refusal.schema == 1, "issuer refusal schema refused");
    let RefusedStatus::Refused = refusal.status;
    Ok(IssuerReply::Refused(refusal.code))
}
fn reserved_reply(raw: &[u8]) -> Result<ReservedGrant> {
    match decode_reply(raw)? {
        IssuerReply::Reserved(grant) => Ok(*grant),
        IssuerReply::Refused(code) => {
            anyhow::bail!("issuer worker refusal: {}", code.category())
        }
    }
}
// Linux random/boot_id is a canonical lowercase RFC-variant UUIDv4.
fn kernel_boot_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| {
        id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
            && id.hyphenated().to_string() == value
    })
}
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
impl ReservedGrant {
    fn validate(&self, r: &RequestDto, epoch: u64) -> Result<()> {
        let a = &self.allocation;
        ensure!(
            self.schema == 2
                && self.status == "reserved"
                && self.worker == r.context.target
                && self.authority_epoch == epoch
                && self.operation_id == r.context.operation_id
                && self.reservation_id == r.lease.reservation_id
                && self.request_id == r.context.request_id
                && self.partition_id == r.lease.partition_id
                && self.slot_index == r.lease.slot_index
                && self.slot_generation == r.lease.slot_generation
                && self.server_incarnation == r.server_incarnation
                && self.profile_allocation_id == r.profile_allocation_id
                && self.request_sha256 == r.request_sha256
                && self.tenant_id == r.tenant_id
                && self.registration_generation == r.registration_generation
                && self.grant_id == format!("{}:{}", self.operation_id, self.profile_allocation_id)
                && a.allocation_id == self.profile_allocation_id
                && identifier(&a.node_id)
                && identifier(&a.owner_id)
                && a.generation > 0
                && a.guest_cid >= 3
                && kernel_boot_id(&self.boot_id)
                && self.clock_namespace_inode > 0
                && self.expires_monotonic_ns > 0
                && hex(&a.guest_nonce)
                && [
                    &a.profile_sha256,
                    &a.kernel_sha256,
                    &a.rootfs_sha256,
                    &a.agent_sha256,
                    &a.config_sha256,
                    &self.inventory_sha256,
                    &self.entry_sha256
                ]
                .iter()
                .all(|s| hex(s)),
            "issuer reserved original binding refused"
        );
        for p in [
            &a.namespace,
            &a.profile_path,
            &a.rootfs_path,
            &a.config_path,
            &a.credential_path,
        ] {
            ensure!(
                p.is_absolute()
                    && p.as_os_str().len() <= 4096
                    && p.components().all(|c| matches!(
                        c,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )),
                "issuer allocation path refused"
            );
        }
        ensure!(
            a.profile_path.parent() == Some(a.namespace.as_path())
                && a.credential_path.parent() == Some(a.namespace.as_path())
                && a.rootfs_path.starts_with(&a.namespace)
                && a.config_path.starts_with(&a.namespace)
                && a.rootfs_path != a.config_path,
            "issuer allocation namespace refused"
        );
        Ok(())
    }
    fn deadline(&self) -> Result<Instant> {
        fn domain() -> Result<(String, u64, u64)> {
            let mut boot = String::new();
            File::open("/proc/sys/kernel/random/boot_id")?
                .take(65)
                .read_to_string(&mut boot)?;
            let ns = std::fs::metadata("/proc/self/ns/time")?;
            ensure!(
                ns.uid() == 0 && ns.gid() == 0,
                "issuer clock namespace owner"
            );
            Ok((boot.trim().to_owned(), ns.dev(), ns.ino()))
        }
        let expected = (
            self.boot_id.clone(),
            self.clock_namespace_device,
            self.clock_namespace_inode,
        );
        ensure!(domain()? == expected, "issuer foreign clock domain");
        let before = Instant::now();
        let clock = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
        let now = u64::try_from(clock.tv_sec())?
            .checked_mul(1_000_000_000)
            .and_then(|v| {
                u64::try_from(clock.tv_nsec())
                    .ok()
                    .and_then(|n| v.checked_add(n))
            })
            .context("issuer clock overflow")?;
        let remaining = self
            .expires_monotonic_ns
            .checked_sub(now)
            .context("issuer Worker lease expired")?;
        let until = before
            .checked_add(Duration::from_nanos(remaining))
            .context("issuer Worker deadline overflow")?;
        ensure!(
            domain()? == expected && Instant::now() < until,
            "issuer Worker clock changed or expired"
        );
        Ok(until)
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn profile_path(&self) -> &Path {
        &self.allocation.profile_path
    }
    pub fn profile_sha256(&self) -> &str {
        &self.allocation.profile_sha256
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeLaunchSpec {
    schema: u32,
    memory_mib: u32,
}
// Shared production boundary after authentic same-owner promotion.
fn launch_material_memory(canonical: &[u8]) -> Result<u32> {
    super::native_worker_ingress::validated_launch_memory(canonical)
}
/// Unforgeable per-original profile/lease capability; only retained authenticated
/// requester records can mint it. No Deserialize or public constructor.
pub struct NativeProfilePromotion {
    pub(crate) profile: super::firecracker::native_guest::NativeGuestProfile,
    pub(crate) expires: Instant,
    pub(crate) sandbox_id: crate::types::SandboxId,
    pub(crate) memory_mib: u32,
}
pub(crate) struct NativeLaunchOwner {
    pub(crate) owner: BackendOwner,
    pub(crate) id: crate::types::SandboxId,
    pub(crate) expires: Instant,
    pub(crate) rootfs_path: PathBuf,
    pub(crate) rootfs_sha256: String,
    pub(crate) memory_mib: u32,
}
type BackendOwner = std::sync::Arc<tokio::sync::Mutex<Box<dyn super::SandboxBackend>>>;
fn require_original_backend(original: Option<&BackendOwner>, actual: &BackendOwner) -> Result<()> {
    ensure!(
        original.is_some_and(|original| std::sync::Arc::ptr_eq(original, actual)),
        "native stopped original backend mismatch"
    );
    Ok(())
}

#[derive(Serialize)]
struct PromotionIntent<'a> {
    schema: u32,
    status: &'static str,
    sandbox_id: uuid::Uuid,
    grant: &'a ReservedGrant,
    launch: &'a NativeLaunchSpec,
}

#[derive(Serialize)]
struct CallingIntent<'a> {
    schema: u32,
    status: &'static str,
    sandbox_id: uuid::Uuid,
    request: &'a RequestDto,
    authority_epoch: u64,
}
struct Intent {
    request: RequestDto,
    epoch: u64,
    fingerprint: String,
    sandbox_id: uuid::Uuid,
    file: Option<File>,
    pin: Option<Metadata>,
    name: String,
    until: Instant,
    expires: Option<Instant>,
    grant: Option<ReservedGrant>,
    unknown: bool,
    promotion_started: bool,
    promotion_file: Option<File>,
    promotion_pin: Option<Metadata>,
    owner: Option<BackendOwner>,
    execution_stopped: Option<std::sync::Arc<super::firecracker::NativeExecutionStopped>>,
    launch_started: bool,
    ready_file: Option<File>,
    ready_pin: Option<Metadata>,
    ready_response: Option<Vec<u8>>,
}
/// Retained synchronous admission owner. Caller cancellation cannot cancel its
/// synchronous kernel calls; asynchronous callers must retain their blocking job.
pub struct RequesterState {
    config_pin: Held,
    publication: std::sync::Arc<Publication>,
    endpoint_path: PathBuf,
    directory: nix::fcntl::Flock<File>,
    directory_path: PathBuf,
    directory_pin: Metadata,
    incarnation: String,
    records: std::collections::BTreeMap<String, Intent>,
    peer: Option<Peer>,
    blocked: bool,
    bytes: usize,
    pending: Option<Intent>,
}
pub struct NativeIssuerRequester {
    state: Option<Box<RequesterState>>,
}
impl std::ops::Deref for NativeIssuerRequester {
    type Target = RequesterState;
    fn deref(&self) -> &Self::Target {
        self.state.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for NativeIssuerRequester {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state.as_mut().unwrap()
    }
}
impl Drop for NativeIssuerRequester {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            if retained_custody(
                state.blocked,
                !state.records.is_empty(),
                state.pending.is_some(),
            ) {
                static DEBT: OnceLock<Mutex<Option<Box<RequesterState>>>> = OnceLock::new();
                let mut debt = DEBT.get_or_init(|| Mutex::new(None)).lock().unwrap();
                assert!(debt.is_none(), "single installed requester custody");
                *debt = Some(state);
            }
        }
    }
}
static REQUESTER_INSTALLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
impl NativeIssuerRequester {
    /// Explicit protected provisioning. Existing intents are never replayed on restart.
    pub fn install(path: &Path, incarnation: uuid::Uuid, until: Instant) -> Result<Self> {
        ensure!(
            nix::unistd::geteuid().as_raw() == 0 && Instant::now() < until,
            "issuer root deadline refused"
        );
        let (config_pin, raw) = Held::load(path)?;
        let config: RequesterConfig = serde_json::from_slice(&raw)?;
        ensure!(
            config.schema == 1
                && config.endpoint_path == config.namespace.join("worker-endpoint.json")
                && config.intent_directory == config.namespace.join("sdk-create-intents"),
            "issuer configuration refused"
        );
        ancestors(&config.intent_directory.join("anchor"))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&config.intent_directory)?;
        let directory_pin = directory.metadata()?;
        ensure!(
            directory_pin.uid() == 0
                && directory_pin.gid() == 0
                && directory_pin.mode() & 0o7777 == 0o700
                && same(
                    &directory_pin,
                    &std::fs::symlink_metadata(&config.intent_directory)?
                )
                && std::fs::read_dir(&config.intent_directory)?
                    .next()
                    .is_none(),
            "issuer intent restart unavailable"
        );
        let directory =
            nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .map_err(|(_, e)| anyhow::Error::from(e))?;
        ensure!(
            !REQUESTER_INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst),
            "issuer requester already installed"
        );
        let mut publication = Publication::new(&config.namespace)?;
        let pid = std::process::id();
        let start = tick(pid)?;
        let group = cgroup(pid)?;
        let (_, _, digest) = exe(pid, until)?;
        let bytes = serde_json::to_vec(
            &serde_json::json!({"schema":1,"server_incarnation":incarnation.to_string(),"peer_pid":pid,"peer_uid":0,"start_tick":start,"exe_sha256":digest,"cgroup_path":group}),
        )?;
        ensure!(
            tick(pid)? == start && cgroup(pid)? == group,
            "issuer requester incarnation changed"
        );
        publication.publish(&bytes)?;
        config_pin.verify()?;
        Ok(Self {
            state: Some(Box::new(RequesterState {
                config_pin,
                publication: std::sync::Arc::new(publication),
                endpoint_path: config.endpoint_path,
                directory,
                directory_path: config.intent_directory,
                directory_pin,
                incarnation: incarnation.to_string(),
                records: Default::default(),
                peer: None,
                blocked: false,
                bytes: 128 * 1024,
                pending: None,
            })),
        })
    }
    fn verify(&self) -> Result<()> {
        verify_state(self)
    }
    /// Raw request is still checked by the actual Worker lease owner; it grants
    /// no local authority. Calling intent is synced before the single grant send.
    pub fn reserve(&mut self, raw: &[u8], epoch: u64) -> Result<ReservedGrant> {
        ensure!(
            !raw.is_empty() && raw.len() <= 8192,
            "issuer request bounded"
        );
        let r: RequestDto = serde_json::from_slice(raw)?;
        ensure!(
            r.schema == 1
                && r.kind == "grant"
                && r.context.protocol_major == 2
                && r.server_incarnation == self.incarnation
                && identifier(&r.context.operation_id)
                && identifier(&r.lease.reservation_id)
                && identifier(&r.profile_allocation_id)
                && hex(&r.request_sha256)
                && epoch > 0
                && (1..=3000).contains(&r.context.remaining_budget_ms),
            "issuer request binding refused"
        );
        let until = Instant::now() + Duration::from_millis(r.context.remaining_budget_ms);
        let mut original = r.clone();
        original.kind = "grant".into();
        original.context.attempt_id.clear();
        original.context.remaining_budget_ms = 0;
        original.context.traceparent.clear();
        let fingerprint = digest(&serde_json::to_vec(&(original, epoch))?);
        self.verify()?;
        if let Some(i) = &self.pending {
            if i.request.context.operation_id == r.context.operation_id {
                ensure!(
                    i.fingerprint == fingerprint,
                    "issuer pending original drift"
                );
                anyhow::bail!("issuer original Calling ambiguous; no replay");
            }
        }
        if let Some(i) = self.records.get(&r.context.operation_id) {
            ensure!(
                i.fingerprint == fingerprint && i.expires.is_none_or(|e| Instant::now() < e),
                "issuer original drift or expiry"
            );
            ensure!(!i.unknown, "issuer original unknown: query required");
            return i
                .grant
                .clone()
                .context("issuer original unknown: query required");
        }
        ensure!(
            !self.blocked
                && self.records.len() < 32
                && self.bytes + 124 * 1024 <= 4 * 1024 * 1024
                && Instant::now() < until,
            "issuer admission unavailable"
        );
        let sandbox_id = uuid::Uuid::now_v7();
        let name = format!("{}.json", self.records.len());
        let durable = serde_json::to_vec(&CallingIntent {
            schema: 1,
            status: "calling",
            sandbox_id,
            request: &r,
            authority_epoch: epoch,
        })?;
        ensure!(durable.len() <= 8192, "issuer intent bounded");
        self.bytes += 124 * 1024;
        self.blocked = true;
        self.pending = Some(Intent {
            request: r.clone(),
            epoch,
            fingerprint,
            sandbox_id,
            file: None,
            pin: None,
            name,
            until,
            expires: None,
            grant: None,
            unknown: true,
            promotion_started: false,
            promotion_file: None,
            promotion_pin: None,
            owner: None,
            execution_stopped: None,
            launch_started: false,
            ready_file: None,
            ready_pin: None,
            ready_response: None,
        });
        let name = &self.pending.as_ref().unwrap().name;
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(format!(
                "/proc/self/fd/{}/{name}",
                self.directory.as_raw_fd()
            ));
        capture_open(self.pending.as_mut().unwrap(), opened)?;
        let pin = self
            .pending
            .as_ref()
            .unwrap()
            .file
            .as_ref()
            .unwrap()
            .metadata()?;
        ensure!(
            pin.is_file()
                && pin.uid() == 0
                && pin.gid() == 0
                && pin.nlink() == 1
                && pin.mode() & 0o7777 == 0o600,
            "issuer intent initial ownership"
        );
        self.pending.as_mut().unwrap().pin = Some(pin);
        let state: &mut RequesterState = self;
        let result = (|| {
            let i = state.pending.as_mut().unwrap();
            let file = i.file.as_mut().unwrap();
            file.write_all(&durable)?;
            file.sync_all()?;
            i.pin = Some(file.metadata()?);
            state.directory.sync_all()?;
            ensure!(
                same(
                    i.pin.as_ref().unwrap(),
                    &std::fs::symlink_metadata(state.directory_path.join(&i.name))?
                ) && Instant::now() < until,
                "issuer Calling publication changed or late"
            );
            let i = state.pending.take().unwrap();
            state.records.insert(r.context.operation_id.clone(), i);
            #[cfg(test)]
            let mut diagnostic = StageDiagnostic::new(until);
            let (endpoint_pin, raw) = Held::load(&state.endpoint_path)?;
            let endpoint: Endpoint = serde_json::from_slice(&raw)?;
            ensure!(
                endpoint.worker == r.context.target,
                "issuer target mismatch"
            );
            #[cfg(test)]
            diagnostic.stage(DiagnosticStage::Exchange);
            let response = exchange_raw(
                &endpoint,
                &state.publication,
                &r,
                until,
                &mut state.peer,
                &mut Phase::Setup,
            )?;
            endpoint_pin.verify()?;
            #[cfg(test)]
            diagnostic.stage(DiagnosticStage::ReplyDecode);
            let grant = reserved_reply(&response)?;
            #[cfg(test)]
            diagnostic.stage(DiagnosticStage::GrantValidate);
            grant.validate(&r, epoch)?;
            #[cfg(test)]
            diagnostic.stage(DiagnosticStage::Deadline);
            grant.deadline()?;
            #[cfg(test)]
            diagnostic.stage(DiagnosticStage::StateVerify);
            verify_state(state)?;
            #[cfg(test)]
            diagnostic.stage(DiagnosticStage::FinalDeadline);
            ensure!(Instant::now() < until, "issuer reservation completed late");
            #[cfg(test)]
            {
                diagnostic.ok = true;
            }
            Ok(grant)
        })();
        if let Ok(grant) = &result {
            let i = state.records.get_mut(&r.context.operation_id).unwrap();
            freeze_grant(&mut i.grant, grant.clone())?;
            i.expires = Some(grant.deadline()?);
            i.unknown = false;
            state.blocked = false;
        }
        result
    }
    /// Query sends only the frozen original intent, never grant/start replay.
    pub fn query(&mut self, operation_id: &str) -> Result<ReservedGrant> {
        if self
            .pending
            .as_ref()
            .is_some_and(|i| i.request.context.operation_id == operation_id)
        {
            anyhow::bail!("issuer original Calling ambiguous; no durable exchange authority");
        }
        if let Some(i) = self.records.get_mut(operation_id) {
            i.unknown = true;
        }
        self.verify()?;
        let state: &mut RequesterState = self;
        let i = state
            .records
            .get(operation_id)
            .context("issuer original not found")?;
        ensure!(
            i.expires.is_none_or(|e| Instant::now() < e),
            "issuer original expired"
        );
        let mut request = i.request.clone();
        request.kind = "query".into();
        let until = i
            .expires
            .map_or(Instant::now() + Duration::from_secs(3), |e| {
                e.min(Instant::now() + Duration::from_secs(3))
            });
        let (pin, raw) = Held::load(&state.endpoint_path)?;
        let endpoint: Endpoint = serde_json::from_slice(&raw)?;
        ensure!(
            endpoint.worker == request.context.target,
            "issuer query target mismatch"
        );
        let raw = exchange_raw(
            &endpoint,
            &state.publication,
            &request,
            until,
            &mut state.peer,
            &mut Phase::Setup,
        )?;
        pin.verify()?;
        let grant = reserved_reply(&raw)?;
        grant.validate(&request, i.epoch)?;
        verify_state(state)?;
        ensure!(Instant::now() < until, "issuer query completed late");
        let i = state.records.get_mut(operation_id).unwrap();
        let deadline = grant.deadline()?;
        freeze_grant(&mut i.grant, grant.clone())?;
        i.expires = Some(i.expires.map_or(deadline, |e| e.min(deadline)));
        i.unknown = false;
        Ok(grant)
    }
    fn original(&self, operation_id: &str) -> Option<&Intent> {
        self.records.get(operation_id).or_else(|| {
            self.pending
                .as_ref()
                .filter(|i| i.request.context.operation_id == operation_id)
        })
    }
    pub fn original_is_unknown(&self, operation_id: &str) -> Option<bool> {
        self.original(operation_id).map(|i| i.unknown)
    }
    pub fn original_sandbox_id(&self, operation_id: &str) -> Option<uuid::Uuid> {
        self.original(operation_id).map(|i| i.sandbox_id)
    }
    pub(crate) fn original_operation_for_sandbox(&self, id: uuid::Uuid) -> Option<String> {
        self.records
            .values()
            .chain(self.pending.iter())
            .find(|i| i.sandbox_id == id)
            .map(|i| i.request.context.operation_id.clone())
    }
    pub fn original_admission_deadline(&self, operation_id: &str) -> Option<Instant> {
        self.original(operation_id).map(|i| i.until)
    }
    pub(crate) fn promote_owner(
        &mut self,
        operation_id: &str,
        canonical_launch: &[u8],
        factory: &dyn super::SandboxBackendFactory,
    ) -> Result<BackendOwner> {
        self.verify()?;
        let state: &mut RequesterState = self;
        let memory_mib = super::native_worker_ingress::validated_launch_memory(canonical_launch)?;
        let spec = NativeLaunchSpec {
            schema: 1,
            memory_mib,
        };
        let i = state
            .records
            .get_mut(operation_id)
            .context("native original not found")?;
        ensure!(
            !i.unknown && digest(canonical_launch) == i.request.request_sha256,
            "native original launch digest refused"
        );
        if let Some(owner) = &i.owner {
            return Ok(owner.clone());
        }
        ensure!(
            !i.promotion_started,
            "native original promotion unknown; no replay"
        );
        let grant = i.grant.as_ref().context("native authentic grant absent")?;
        let expires = i.expires.context("native Worker deadline absent")?;
        ensure!(Instant::now() < expires, "native Worker lease expired");
        i.promotion_started = true; // Irreversible original before any profile/file construction.
        let durable = serde_json::to_vec(&PromotionIntent {
            schema: 1,
            status: "calling",
            sandbox_id: i.sandbox_id,
            grant,
            launch: &spec,
        })?;
        ensure!(durable.len() <= 8192, "native promotion intent bounded");
        let name = format!("{}.promotion.json", i.name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(format!(
                "/proc/self/fd/{}/{name}",
                state.directory.as_raw_fd()
            ))?;
        // Exact role FD retained before all metadata/write/sync validation.
        let i = state.records.get_mut(operation_id).unwrap();
        i.promotion_file = Some(file);
        let file = i.promotion_file.as_mut().unwrap();
        let before = file.metadata()?;
        ensure!(
            before.is_file()
                && before.uid() == 0
                && before.gid() == 0
                && before.nlink() == 1
                && before.mode() & 0o7777 == 0o600,
            "native promotion file ownership"
        );
        file.write_all(&durable)?;
        file.sync_all()?;
        let pin = file.metadata()?;
        ensure!(
            same(
                &pin,
                &std::fs::symlink_metadata(state.directory_path.join(&name))?
            ),
            "native promotion publication changed"
        );
        state.directory.sync_all()?;
        state.records.get_mut(operation_id).unwrap().promotion_pin = Some(pin);
        let i = state.records.get(operation_id).unwrap();
        let grant = i.grant.as_ref().unwrap();
        let profile = super::firecracker::native_guest::NativeGuestProfile::load(
            &grant.allocation.profile_path,
        )?;
        profile.verify_reserved_source(
            &grant.allocation.profile_path,
            &grant.allocation.profile_sha256,
        )?;
        ensure!(
            profile.rootfs_path == grant.allocation.rootfs_path
                && profile.config_path == grant.allocation.config_path
                && profile.rootfs_sha256 == grant.allocation.rootfs_sha256
                && profile.config_sha256 == grant.allocation.config_sha256
                && profile.kernel_sha256 == grant.allocation.kernel_sha256
                && profile.agent_sha256 == grant.allocation.agent_sha256
                && profile.node_id == grant.allocation.node_id
                && profile.owner_id == grant.allocation.owner_id
                && profile.generation == grant.allocation.generation
                && profile.guest_nonce == grant.allocation.guest_nonce
                && profile.guest_cid == grant.allocation.guest_cid
                && profile.credential_path == grant.allocation.credential_path,
            "native reserved profile fences refused"
        );
        ensure!(
            Instant::now() < expires,
            "native capture completed beyond Worker lease"
        );
        let promotion = NativeProfilePromotion {
            profile,
            expires,
            sandbox_id: crate::types::SandboxId::from_uuid(i.sandbox_id),
            memory_mib: spec.memory_mib,
        };
        let owner = std::sync::Arc::new(tokio::sync::Mutex::new(
            factory.build_native_original(&promotion)?,
        ));
        state.records.get_mut(operation_id).unwrap().owner = Some(owner.clone()); // Before first asynchronous launch operation.
        Ok(owner)
    }

    pub(crate) fn begin_launch(
        &mut self,
        operation_id: &str,
        canonical: &[u8],
        factory: &dyn super::SandboxBackendFactory,
    ) -> Result<NativeLaunchOwner> {
        let owner = self.promote_owner(operation_id, canonical, factory)?;
        let memory_mib = launch_material_memory(canonical)?;
        let i = self.records.get_mut(operation_id).unwrap();
        ensure!(
            !i.launch_started,
            "native original launch already dispatched; query only"
        );
        i.launch_started = true;
        let allocation = &i.grant.as_ref().unwrap().allocation;
        Ok(NativeLaunchOwner {
            owner,
            id: crate::types::SandboxId::from_uuid(i.sandbox_id),
            expires: i.expires.unwrap(),
            rootfs_path: allocation.rootfs_path.clone(),
            rootfs_sha256: allocation.rootfs_sha256.clone(),
            memory_mib,
        })
    }
    pub(crate) fn cache_ready(&mut self, operation_id: &str, receipt: Vec<u8>) -> Result<()> {
        self.verify()?;
        ensure!(receipt.len() <= 8192, "native Ready receipt bound");
        let state: &mut RequesterState = self;
        let i = state
            .records
            .get_mut(operation_id)
            .context("native original Ready absent")?;
        if let Some(old) = &i.ready_response {
            ensure!(*old == receipt, "native original Ready drift");
            return Ok(());
        }
        ensure!(
            i.launch_started && i.owner.is_some() && i.expires.is_some_and(|e| Instant::now() < e),
            "native Ready ownership/expiry refused"
        );
        let name = format!("{}.ready.json", i.name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(format!(
                "/proc/self/fd/{}/{name}",
                state.directory.as_raw_fd()
            ))?;
        i.ready_file = Some(file);
        let file = i.ready_file.as_mut().unwrap();
        let h = file.metadata()?;
        ensure!(
            h.is_file()
                && h.uid() == 0
                && h.gid() == 0
                && h.nlink() == 1
                && h.mode() & 0o7777 == 0o600,
            "native Ready publication ownership"
        );
        file.write_all(&receipt)?;
        file.sync_all()?;
        let h = file.metadata()?;
        ensure!(
            same(
                &h,
                &std::fs::symlink_metadata(state.directory_path.join(name))?
            ),
            "native Ready publication changed"
        );
        state.directory.sync_all()?;
        ensure!(
            i.expires.is_some_and(|e| Instant::now() < e),
            "native Ready completed beyond Worker expiry"
        );
        i.ready_pin = Some(h);
        i.ready_response = Some(receipt);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn qualification_original_expiry(&self, operation_id: &str) -> Option<Instant> {
        self.original(operation_id).and_then(|i| i.expires)
    }

    #[cfg(test)]
    pub(crate) fn qualification_original_owner(&self, operation_id: &str) -> Option<BackendOwner> {
        self.original(operation_id).and_then(|i| i.owner.clone())
    }

    pub fn original_ready_receipt(&self, operation_id: &str) -> Option<&[u8]> {
        self.original(operation_id)
            .and_then(|i| i.ready_response.as_deref())
    }

    pub(crate) fn retire_backend_owner(
        &mut self,
        id: crate::types::SandboxId,
        actual: &BackendOwner,
        stopped: Option<std::sync::Arc<super::firecracker::NativeExecutionStopped>>,
    ) -> Result<()> {
        let Some(i) = self
            .records
            .values_mut()
            .find(|i| crate::types::SandboxId::from_uuid(i.sandbox_id) == id)
        else {
            return Ok(());
        };
        let Some(stopped) = stopped else {
            // Generic delete/stop success cannot release this original owner.
            // No producer capability is available for incomplete native startup.
            return Ok(());
        };
        require_original_backend(i.owner.as_ref(), actual)?;
        let grant = i
            .grant
            .as_ref()
            .context("native stopped original grant missing")?;
        let profile = stopped.profile();
        ensure!(
            stopped.sandbox_id() == id
                && i.launch_started
                && i.promotion_started
                && grant.operation_id == i.request.context.operation_id
                && grant.authority_epoch == i.epoch
                && profile.rootfs_path == grant.allocation.rootfs_path
                && profile.config_path == grant.allocation.config_path
                && profile.rootfs_sha256 == grant.allocation.rootfs_sha256
                && profile.config_sha256 == grant.allocation.config_sha256
                && profile.kernel_sha256 == grant.allocation.kernel_sha256
                && profile.agent_sha256 == grant.allocation.agent_sha256
                && profile.node_id == grant.allocation.node_id
                && profile.owner_id == grant.allocation.owner_id
                && profile.generation == grant.allocation.generation
                && profile.guest_nonce == grant.allocation.guest_nonce
                && profile.guest_cid == grant.allocation.guest_cid
                && profile.credential_path == grant.allocation.credential_path,
            "native stopped original grant/profile mismatch"
        );
        // The original record still owns every immutable request/grant fence,
        // including Worker lease, server incarnation, boot/time domain and hash.
        // Cache before metadata/persistence work; no storage release is implied.
        ensure!(
            i.execution_stopped
                .as_ref()
                .is_none_or(|first| std::sync::Arc::ptr_eq(first, &stopped)),
            "native stopped cached producer changed"
        );
        i.execution_stopped = Some(stopped);
        i.owner.take();
        Ok(())
    }
    /// Cleanup lookup only: never renews or revalidates launch expiry into authority.
    pub(crate) fn original_execution_binding(
        &self,
        raw: &[u8],
        epoch: u64,
        digest: &str,
        canonical: &[u8],
        sandbox: crate::types::SandboxId,
    ) -> Result<Instant> {
        let (id, stopped, _) = self.original_stop_binding(raw, epoch, digest)?;
        let request: RequestDto = serde_json::from_slice(raw)?;
        let i = self
            .original(&request.context.operation_id)
            .context("execution original absent")?;
        ensure!(
            id == sandbox
                && stopped.is_none()
                && i.ready_response.is_some()
                && self::digest(canonical) == i.request.request_sha256,
            "execution owner binding drift"
        );
        let expires = i.expires.context("execution expiry absent")?;
        ensure!(Instant::now() < expires, "execution original expired");
        Ok(expires)
    }
    pub(crate) fn original_stop_binding(
        &self,
        raw: &[u8],
        epoch: u64,
        digest: &str,
    ) -> Result<(
        crate::types::SandboxId,
        Option<std::sync::Arc<super::firecracker::NativeExecutionStopped>>,
        String,
    )> {
        let request: RequestDto = serde_json::from_slice(raw)?;
        let i = self
            .original(&request.context.operation_id)
            .context("original stop intent unavailable")?;
        let raw = serde_json::to_vec(&request)?;
        ensure!(
            i.epoch == epoch
                && serde_json::to_vec(&i.request)? == raw
                && format!("{:x}", Sha256::digest(&raw)) == digest,
            "original stop binding drift"
        );
        let grant = i
            .grant
            .as_ref()
            .context("original stop grant unavailable")?;
        ensure!(
            i.execution_stopped.is_some() || i.owner.is_some(),
            "original stop owner unavailable"
        );
        Ok((
            crate::types::SandboxId::from_uuid(i.sandbox_id),
            i.execution_stopped.clone(),
            format!("{:x}", Sha256::digest(serde_json::to_vec(grant)?)),
        ))
    }
    pub(crate) fn ingress_seed(&self) -> Result<super::native_worker_ingress::IngressSeed> {
        self.verify()?;
        Ok(super::native_worker_ingress::IngressSeed::new(
            self.publication.clone(),
            self.endpoint_path.clone(),
            self.incarnation.clone(),
        ))
    }
    pub fn retire_identity(&mut self) -> Result<()> {
        self.blocked = true;
        std::sync::Arc::get_mut(&mut self.publication)
            .context("requester publication still held by ingress owner")?
            .retire()
    }
}

fn retained_custody(blocked: bool, records: bool, pending: bool) -> bool {
    blocked || records || pending
}
fn capture_open(pending: &mut Intent, opened: std::io::Result<File>) -> Result<()> {
    pending.file = Some(opened?);
    Ok(())
}

fn freeze_grant(existing: &mut Option<ReservedGrant>, candidate: ReservedGrant) -> Result<()> {
    if let Some(original) = existing {
        ensure!(*original == candidate, "issuer original full grant drift");
    } else {
        *existing = Some(candidate);
    }
    Ok(())
}

fn verify_state(self_state: &RequesterState) -> Result<()> {
    self_state.config_pin.verify()?;
    ancestors(&self_state.directory_path.join("anchor"))?;
    ancestors(&self_state.publication.root_path.join("anchor"))?;
    self_state.publication.valid()?;
    for i in self_state.records.values() {
        for (file, pin, suffix) in [
            (&i.promotion_file, &i.promotion_pin, "promotion"),
            (&i.ready_file, &i.ready_pin, "ready"),
        ] {
            if let Some(file) = file {
                let pin = pin
                    .as_ref()
                    .context("native original phase capture ambiguous")?;
                ensure!(
                    same(pin, &file.metadata()?)
                        && same(
                            pin,
                            &std::fs::symlink_metadata(
                                self_state
                                    .directory_path
                                    .join(format!("{}.{}.json", i.name, suffix))
                            )?
                        ),
                    "native original phase changed"
                );
            }
        }

        ensure!(
            same(
                i.pin.as_ref().context("issuer intent capture incomplete")?,
                &i.file
                    .as_ref()
                    .context("issuer intent file incomplete")?
                    .metadata()?
            ) && same(
                i.pin.as_ref().context("issuer intent capture incomplete")?,
                &std::fs::symlink_metadata(self_state.directory_path.join(&i.name))?
            ),
            "issuer original intent changed"
        );
    }
    ensure!(
        same_anchor(&self_state.directory_pin, &self_state.directory.metadata()?)
            && same_anchor(
                &self_state.directory_pin,
                &std::fs::symlink_metadata(&self_state.directory_path)?
            ),
        "issuer original journal changed"
    );
    Ok(())
}

#[cfg(test)]
mod production_tests {
    use super::*;
    fn request() -> RequestDto {
        serde_json::from_value(serde_json::json!({"schema":1,"kind":"grant","context":{"protocol_major":2,"target":{"environment_id":"owned","environment_generation":1,"node_id":7,"node_generation":1,"incarnation":"worker"},"request_id":7,"operation_id":"p0.original","attempt_id":"attempt","remaining_budget_ms":3000,"traceparent":""},"lease":{"reservation_id":"p0.reservation","slot_index":0,"slot_generation":1,"partition_id":0},"tenant_id":8,"registration_generation":0,"server_incarnation":"01900000-0000-7000-8000-000000000001","profile_allocation_id":"allocation","request_sha256":"a".repeat(64)})).unwrap()
    }
    fn grant(r: &RequestDto) -> ReservedGrant {
        ReservedGrant {
            schema: 2,
            status: "reserved".into(),
            grant_id: format!("{}:{}", r.context.operation_id, r.profile_allocation_id),
            operation_id: r.context.operation_id.clone(),
            reservation_id: r.lease.reservation_id.clone(),
            worker: r.context.target.clone(),
            authority_epoch: 1,
            request_id: r.context.request_id,
            partition_id: r.lease.partition_id,
            slot_index: r.lease.slot_index,
            slot_generation: r.lease.slot_generation,
            server_incarnation: r.server_incarnation.clone(),
            profile_allocation_id: r.profile_allocation_id.clone(),
            request_sha256: r.request_sha256.clone(),
            tenant_id: r.tenant_id,
            registration_generation: r.registration_generation,
            allocation: Allocation {
                allocation_id: r.profile_allocation_id.clone(),
                profile_path: "/owned/profile.json".into(),
                profile_sha256: "b".repeat(64),
                rootfs_path: "/owned/rootfs".into(),
                config_path: "/owned/config".into(),
                credential_path: "/owned/identity.json".into(),
                namespace: "/owned".into(),
                node_id: "node".into(),
                owner_id: "owner".into(),
                generation: 1,
                guest_nonce: "c".repeat(64),
                guest_cid: 3,
                kernel_sha256: "d".repeat(64),
                rootfs_sha256: "e".repeat(64),
                agent_sha256: "f".repeat(64),
                config_sha256: "0".repeat(64),
            },
            inventory_sha256: "1".repeat(64),
            entry_sha256: "2".repeat(64),
            boot_id: "5e38523b-a082-4bfc-880c-0872bf500658".into(),
            clock_namespace_device: 1,
            clock_namespace_inode: 1,
            expires_monotonic_ns: 1,
        }
    }
    #[test]
    fn native_stop_binding_refuses_missing_and_foreign_actual_backend_arc() {
        let make = || -> BackendOwner {
            std::sync::Arc::new(tokio::sync::Mutex::new(Box::new(
                crate::sandbox::mock::MockSandboxBackend::new(std::sync::Arc::new(
                    crate::sandbox::mock::MockBehavior::default(),
                )),
            )))
        };
        let original = make();
        let same = original.clone();
        let foreign = make();
        assert!(require_original_backend(Some(&original), &same).is_ok());
        assert!(require_original_backend(Some(&original), &foreign).is_err());
        assert!(require_original_backend(None, &same).is_err());
        assert_eq!(std::sync::Arc::strong_count(&original), 2);
    }

    #[test]
    fn kernel_boot_wire_requires_canonical_v4_without_changing_server_fence() {
        let r = request();
        let mut g = grant(&r);
        assert!(g.validate(&r, 1).is_ok());
        let server = g.server_incarnation.clone();
        for refused in [
            "01900000-0000-7000-8000-000000000001",
            "5E38523B-A082-4BFC-880C-0872BF500658",
            "5e38523ba0824bfc880c0872bf500658",
            "{5e38523b-a082-4bfc-880c-0872bf500658}",
            "5e38523b-a082-4bfc-080c-0872bf500658",
            "5e38523b-a082-4bfc-c80c-0872bf500658",
            "5e38523b-a082-4bfc-880c-0872bf500658\n",
            "malformed",
        ] {
            g.boot_id = refused.into();
            assert!(g.validate(&r, 1).is_err());
            assert_eq!(g.server_incarnation, server);
        }
        g.boot_id = "5e38523b-a082-4bfc-880c-0872bf500659".into();
        assert!(g.validate(&r, 1).is_ok());
    }
    #[test]
    fn original_clock_fields_are_immutable_and_required_before_promotion() {
        let r = request();
        let original = grant(&r);
        let mut cache = Some(original.clone());
        for field in [
            "boot_id",
            "clock_namespace_inode",
            "clock_namespace_device",
            "expires_monotonic_ns",
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            value[field] = if field == "boot_id" {
                "5e38523b-a082-4bfc-880c-0872bf500659".into()
            } else {
                2.into()
            };
            let changed: ReservedGrant = serde_json::from_value(value).unwrap();
            changed.validate(&r, 1).unwrap();
            assert!(freeze_grant(&mut cache, changed).is_err());
            assert!(cache.as_ref() == Some(&original));
        }
        let mut value = serde_json::to_value(&original).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("expires_monotonic_ns");
        assert!(serde_json::from_value::<ReservedGrant>(value).is_err());
        let mut old = original.clone();
        old.schema = 1;
        assert!(old.validate(&r, 1).is_err());
        assert!(
            original.deadline().is_err(),
            "foreign clock-domain receipt cannot mint a local deadline"
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn clock_translation_model_is_conservative_and_expired_absolute_is_refused() {
        // Actual kernel clock observations, modeled receipt: no Worker grant/effect proof.
        let r = request();
        let mut receipt = grant(&r);
        let mut boot = String::new();
        File::open("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .take(65)
            .read_to_string(&mut boot)
            .unwrap();
        let ns = std::fs::metadata("/proc/self/ns/time").unwrap();
        receipt.boot_id = boot.trim().into();
        receipt.clock_namespace_device = ns.dev();
        receipt.clock_namespace_inode = ns.ino();
        let clock = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
        let upper = Instant::now() + Duration::from_secs(1);
        receipt.expires_monotonic_ns = u64::try_from(clock.tv_sec()).unwrap() * 1_000_000_000
            + u64::try_from(clock.tv_nsec()).unwrap()
            + 1_000_000_000;
        if nix::unistd::geteuid().as_raw() == 0 {
            let translated = receipt.deadline().unwrap();
            assert!(translated <= upper);
            assert!(translated > Instant::now());
        }
        receipt.expires_monotonic_ns = 1;
        assert!(receipt.deadline().is_err());
    }
    // This boundary oracle exercises the parser used after authentic promotion.
    // It grants no authority and creates no backend; begin_launch calls this
    // same helper only after authentic same-owner promotion.
    #[test]
    fn fixed_launch_material_parser_accepts_the_admitted_closed_canonical() {
        let fixed = super::super::native_worker_ingress::FixedLaunch::selected(None).unwrap();
        let canonical = serde_json::to_vec(&fixed).unwrap();
        assert_eq!(
            super::super::native_worker_ingress::validated_launch_memory(&canonical).unwrap(),
            512
        );
        // Same production boundary called by begin_launch after owner promotion.
        assert_eq!(launch_material_memory(&canonical).unwrap(), 512);
        let schema1 = br#"{"schema":1,"memory_mib":128}"#;
        assert_eq!(launch_material_memory(schema1).unwrap(), 128);
        let mut drift = serde_json::to_value(&fixed).unwrap();
        drift["plan"]["command"] = serde_json::json!("/foreign");
        assert!(launch_material_memory(&serde_json::to_vec(&drift).unwrap()).is_err());
        assert!(
            launch_material_memory(br#"{"schema":1,"memory_mib":128,"profile":"/foreign"}"#)
                .is_err()
        );
        assert!(launch_material_memory(br#"{"schema":1,"schema":1,"memory_mib":128}"#).is_err());
        let mut noncanonical = canonical.clone();
        noncanonical.push(b' ');
        assert!(launch_material_memory(&noncanonical).is_err());
    }

    #[test]
    fn native_launch_spec_is_closed_canonical_and_binds_exact_digest() {
        let canonical = br#"{"schema":1,"memory_mib":128}"#;
        let spec: NativeLaunchSpec = serde_json::from_slice(canonical).unwrap();
        assert!(serde_json::to_vec(&spec).unwrap() == canonical);
        assert!(serde_json::from_slice::<NativeLaunchSpec>(
            br#"{"schema":1,"memory_mib":128,"profile":"/foreign"}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<NativeLaunchSpec>(
            br#"{"schema":1,"schema":1,"memory_mib":128}"#
        )
        .is_err());
        assert_ne!(
            digest(canonical),
            digest(br#"{"schema":1,"memory_mib":256}"#)
        );
    }

    #[test]
    fn query_same_fence_allocation_drift_preserves_entire_first_grant() {
        let r = request();
        let original = grant(&r);
        let mut cached = Some(original.clone());
        freeze_grant(&mut cached, original.clone()).unwrap();
        let mut candidates = Vec::new();
        let mut altered = original.clone();
        altered.allocation.profile_sha256 = "3".repeat(64);
        candidates.push(altered);
        let mut altered = original.clone();
        altered.inventory_sha256 = "4".repeat(64);
        candidates.push(altered);
        let mut altered = original.clone();
        altered.entry_sha256 = "5".repeat(64);
        candidates.push(altered);
        let mut altered = original.clone();
        altered.allocation.namespace = "/foreign".into();
        altered.allocation.profile_path = "/foreign/profile.json".into();
        altered.allocation.credential_path = "/foreign/identity.json".into();
        altered.allocation.rootfs_path = "/foreign/rootfs".into();
        altered.allocation.config_path = "/foreign/config".into();
        candidates.push(altered);
        for altered in candidates {
            altered.validate(&r, 1).unwrap();
            assert!(freeze_grant(&mut cached, altered).is_err());
            assert!(cached.as_ref() == Some(&original));
        }
    }
    #[test]
    fn modeled_open_error_retains_preinstalled_calling_identity_and_drop_custody() {
        // State-model error only: no kernel failure or namespace authority minted.
        let r = request();
        let sandbox_id = uuid::Uuid::now_v7();
        let until = Instant::now() + Duration::from_secs(1);
        let mut pending = Intent {
            request: r.clone(),
            epoch: 1,
            fingerprint: "frozen".into(),
            sandbox_id,
            file: None,
            pin: None,
            name: "0.json".into(),
            until,
            expires: Some(until),
            grant: None,
            unknown: true,
            promotion_started: false,
            promotion_file: None,
            promotion_pin: None,
            owner: None,
            execution_stopped: None,
            launch_started: false,
            ready_file: None,
            ready_pin: None,
            ready_response: None,
        };
        let result = capture_open(
            &mut pending,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        );
        assert!(result.is_err());
        assert!(pending.file.is_none());
        assert!(pending.pin.is_none());
        assert_eq!(pending.request.context.operation_id, r.context.operation_id);
        assert_eq!(pending.sandbox_id, sandbox_id);
        assert_eq!(pending.name, "0.json");
        assert_eq!(pending.fingerprint, "frozen");
        assert_eq!(pending.until, until);
        assert_eq!(pending.expires, Some(until));
        assert!(pending.unknown);
        assert!(retained_custody(true, false, true));
        assert!(
            retained_custody(true, false, false),
            "blocked owner must retain actual journal lock even absent leaf capture"
        );
        assert!(!retained_custody(false, false, false));
    }

    #[test]
    fn worker_refusal_is_closed_and_never_a_reserved_grant() {
        for (wire, expected) in [
            ("deadline", RefusalCode::Deadline),
            ("authority", RefusalCode::Authority),
            ("stale", RefusalCode::Stale),
            ("conflict", RefusalCode::Conflict),
            ("capacity", RefusalCode::Capacity),
            ("unknown", RefusalCode::Unknown),
            ("closed", RefusalCode::Closed),
            ("packet", RefusalCode::Packet),
            ("io", RefusalCode::Io),
            ("peer", RefusalCode::Peer),
        ] {
            let raw = format!(r#"{{"schema":1,"status":"refused","code":"{wire}"}}"#);
            assert!(
                matches!(decode_reply(raw.as_bytes()), Ok(IssuerReply::Refused(code)) if code == expected)
            );
            assert!(reserved_reply(raw.as_bytes()).is_err());
            assert_eq!(
                reserved_reply(raw.as_bytes()).err().unwrap().to_string(),
                format!("issuer worker refusal: {wire}")
            );
        }
        for raw in [
            r#"{"schema":1,"schema":1,"status":"refused","code":"io"}"#,
            r#"{"schema":1,"status":"refused","status":"refused","code":"io"}"#,
            r#"{"schema":1,"status":"refused","code":"io","code":"io"}"#,
            r#"{"schema":1,"status":"refused","code":"io","foreign":null}"#,
            r#"{"schema":2,"status":"refused","code":"io"}"#,
            r#"{"schema":true,"status":"refused","code":"io"}"#,
            r#"{"schema":1,"status":"reserved","code":"io"}"#,
            r#"{"schema":1,"status":"refused","code":"future"}"#,
            r#"{"schema":1,"status":"refused","code":"io"} {}"#,
        ] {
            assert!(decode_reply(raw.as_bytes()).is_err());
        }
        let original = grant(&request());
        let raw = serde_json::to_vec(&original).unwrap();
        assert!(matches!(decode_reply(&raw), Ok(IssuerReply::Reserved(g)) if *g == original));
    }
    #[test]
    fn reserved_grant_closed_codec_preserves_every_original_fence() {
        let r = request();
        let g = grant(&r);
        g.validate(&r, 1).unwrap();
        let raw = serde_json::to_string(&g).unwrap();
        assert!(raw.len() <= 8192);
        for field in [
            "schema",
            "operation_id",
            "authority_epoch",
            "inventory_sha256",
            "entry_sha256",
        ] {
            let value = serde_json::to_value(&g).unwrap()[field].clone();
            let foreign = format!("{{\"{field}\":{value},{}", &raw[1..]);
            assert!(serde_json::from_str::<ReservedGrant>(&foreign).is_err());
        }
        assert!(
            serde_json::from_str::<ReservedGrant>(&raw.replacen('{', "{\"foreign\":true,", 1))
                .is_err()
        );
        let mut value = serde_json::to_value(&g).unwrap();
        for key in [
            "operation_id",
            "reservation_id",
            "server_incarnation",
            "profile_allocation_id",
            "request_sha256",
        ] {
            let prior = value[key].clone();
            value[key] = "foreign".into();
            assert!(serde_json::from_value::<ReservedGrant>(value.clone())
                .unwrap()
                .validate(&r, 1)
                .is_err());
            value[key] = prior;
        }
        let mut query = r.clone();
        query.kind = "query".into();
        g.validate(&query, 1).unwrap();
        assert!(g.validate(&query, 2).is_err());
    }
    #[test]
    fn calling_intent_captures_original_sandbox_before_exchange_and_exact_history_cap() {
        let r = request();
        let id = uuid::Uuid::now_v7();
        let bytes = serde_json::to_vec(&CallingIntent {
            schema: 1,
            status: "calling",
            sandbox_id: id,
            request: &r,
            authority_epoch: 1,
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["sandbox_id"], id.to_string());
        assert_eq!(value["status"], "calling");
        assert_eq!(
            value["request"]["context"]["operation_id"],
            r.context.operation_id
        );
        assert!(bytes.len() <= 8192);
    }
    #[test]
    fn requester_configuration_is_explicit_closed_and_never_fixture_request_authority() {
        assert!(serde_json::from_slice::<RequesterConfig>(br#"{"schema":1,"namespace":"/owned","endpoint_path":"/owned/worker-endpoint.json","intent_directory":"/owned/sdk-create-intents"}"#).is_ok());
        assert!(serde_json::from_slice::<RequesterConfig>(br#"{"schema":1,"namespace":"/owned","endpoint_path":"/owned/worker-endpoint.json","intent_directory":"/owned/sdk-create-intents","request_path":"/forged/request.json"}"#).is_err());
        assert!(serde_json::from_slice::<RequesterConfig>(br#"{"schema":1,"schema":1,"namespace":"/owned","endpoint_path":"/owned/worker-endpoint.json","intent_directory":"/owned/sdk-create-intents"}"#).is_err());
    }
}
