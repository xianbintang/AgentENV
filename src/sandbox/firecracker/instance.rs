use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use firecracker_client::models::drive::IoEngine;
use firecracker_client::models::instance_action_info::ActionType;
use firecracker_client::models::vm::State as VmState;
use firecracker_client::models::{mmds_config::Version as MmdsVersion, MmdsConfig, PartialDrive};
use firecracker_client::models::{
    Balloon, BootSource, DirtyMemoryRanges, Drive, InstanceActionInfo, Logger,
    MachineConfiguration, MemoryBackend, NetworkInterface, NetworkOverride, RateLimiter,
    SnapshotCreateParams, SnapshotLoadParams, Vm,
};
use hyper::Method;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde_json::value::RawValue;
use tokio::process::{Child, Command};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, trace, warn};

use super::mmds::MmdsMetadata;
use super::socket::UnixSocketClient;

/// Maximum size (in bytes) of the MMDS data store. The Firecracker default is
/// 51200 (50 KiB); we raise it to 1 MiB to accommodate raw image configs
/// injected via the extra MMDS metadata pass-through.
const MMDS_SIZE_LIMIT: usize = 1_048_576;
const HTTP_API_MAX_PAYLOAD_SIZE: usize = MMDS_SIZE_LIMIT;

pub(crate) struct FirecrackerInstance {
    client: UnixSocketClient,
    work_dir: PathBuf,
    socket_path: PathBuf,
    stderr_path: Option<PathBuf>,
    process: Option<Child>,
    native_socket_custody: bool,
    native_socket: Option<NativeSocketOwner>,
    native_ticket: Option<usize>,
    native_spawn: Option<tokio::task::JoinHandle<std::io::Result<Child>>>,
    native_spawn_failed: bool,
}

// Permanent admission tickets make Drop retention bounded before any native
// resource/calling transition. No allocation is needed to retain a failed owner.
struct NativeDropDebt {
    _socket: Option<NativeSocketOwner>,
    _child: Option<Child>,
    _spawn: Option<tokio::task::JoinHandle<std::io::Result<Child>>>,
}
struct NativeDebtRegistry {
    admitted: usize,
    debts: [Option<NativeDropDebt>; 32],
}
fn native_debts() -> &'static std::sync::Mutex<NativeDebtRegistry> {
    static DEBTS: std::sync::OnceLock<std::sync::Mutex<NativeDebtRegistry>> =
        std::sync::OnceLock::new();
    DEBTS.get_or_init(|| {
        std::sync::Mutex::new(NativeDebtRegistry {
            admitted: 0,
            debts: std::array::from_fn(|_| None),
        })
    })
}
struct SocketAnchor {
    path: PathBuf,
    file: fs::File,
    pin: Option<fs::Metadata>,
}
struct NativeSocketOwner {
    anchors: Vec<SocketAnchor>,
    leaf: Option<fs::File>,
    pin: Option<fs::Metadata>,
    dispatched: bool,
    unlinked: bool,
    unlink_calling: bool,
}
fn same_socket(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
impl NativeSocketOwner {
    fn check_parents(&self, until: Instant) -> Result<()> {
        anyhow::ensure!(Instant::now() < until, "native socket parent deadline");
        anyhow::ensure!(
            !self.anchors.is_empty(),
            "native socket parent capture missing"
        );
        for anchor in &self.anchors {
            let pin = anchor
                .pin
                .as_ref()
                .context("native socket partial parent capture")?;
            anyhow::ensure!(Instant::now() < until, "native socket parent stat deadline");
            let held = anchor.file.metadata()?;
            anyhow::ensure!(
                Instant::now() < until,
                "native socket parent stat completed late"
            );
            let named = fs::symlink_metadata(&anchor.path)?;
            anyhow::ensure!(
                Instant::now() < until,
                "native socket parent name completed late"
            );
            for actual in [&held, &named] {
                anyhow::ensure!(
                    actual.is_dir()
                        && actual.dev() == pin.dev()
                        && actual.ino() == pin.ino()
                        && actual.mode() == pin.mode()
                        && actual.uid() == pin.uid()
                        && actual.gid() == pin.gid()
                        && actual.nlink() == pin.nlink(),
                    "native socket parent changed"
                );
            }
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn capture(&mut self, path: &Path, until: Instant) -> Result<()> {
        self.check_parents(until)?;
        if self.leaf.is_none() {
            // O_PATH does not connect or block; retain the actual FD before fstat.
            self.leaf = Some(fs::File::from(
                nix::fcntl::open(
                    path,
                    nix::fcntl::OFlag::O_PATH
                        | nix::fcntl::OFlag::O_NOFOLLOW
                        | nix::fcntl::OFlag::O_CLOEXEC,
                    nix::sys::stat::Mode::empty(),
                )
                .context("native socket direct O_PATH open")?,
            ));
        }
        anyhow::ensure!(Instant::now() < until, "native socket open completed late");
        let held = self
            .leaf
            .as_ref()
            .unwrap()
            .metadata()
            .context("native socket held fstat")?;
        anyhow::ensure!(Instant::now() < until, "native socket stat completed late");
        anyhow::ensure!(
            held.file_type().is_socket()
                && held.uid() == 0
                && held.gid() == 0
                && held.nlink() == 1
                && held.mode() & 0o022 == 0,
            "native API socket capture refused"
        );
        anyhow::ensure!(
            same_socket(
                &held,
                &fs::symlink_metadata(path).context("native socket named lstat")?
            ),
            "native API socket name changed"
        );
        if let Some(pin) = &self.pin {
            anyhow::ensure!(same_socket(pin, &held), "native API socket identity drift");
        } else {
            self.pin = Some(held);
        }
        self.check_parents(until)
    }
    #[cfg(not(target_os = "linux"))]
    fn capture(&mut self, _path: &Path, _until: Instant) -> Result<()> {
        bail!("native socket capture requires Linux O_PATH")
    }
    fn retire(&mut self, path: &Path, until: Instant) -> Result<()> {
        anyhow::ensure!(Instant::now() < until, "native socket retirement deadline");
        if !self.dispatched {
            anyhow::ensure!(
                self.leaf.is_none() && self.pin.is_none(),
                "native socket no-effect state drift"
            );
            // This original owner never dispatched a child. This proves no
            // API socket creation by this owner, irrespective of foreign names
            // or incomplete parent capture; it does not assert path absence.
            return Ok(());
        }
        self.check_parents(until)?;
        let leaf = self
            .leaf
            .as_ref()
            .context("native socket Calling without captured FD")?;
        let pin = self
            .pin
            .as_ref()
            .context("native socket partial capture remains debt")?;
        if !self.unlinked {
            anyhow::ensure!(
                !self.unlink_calling,
                "native socket unlink remains ambiguous"
            );
            anyhow::ensure!(
                same_socket(pin, &leaf.metadata()?)
                    && same_socket(pin, &fs::symlink_metadata(path)?),
                "native socket original name refused"
            );
            self.check_parents(until)?;
            anyhow::ensure!(Instant::now() < until, "native socket unlink deadline");
            self.unlink_calling = true;
            nix::unistd::unlinkat(
                &self.anchors[0].file,
                "firecracker.socket",
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            )
            .context("native socket anchored unlinkat")?;
            self.unlinked = true; // Once the syscall succeeded, never unlink a replacement on retry.
        }
        anyhow::ensure!(
            leaf.metadata()?.nlink() == 0
                && matches!(fs::symlink_metadata(path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound),
            "native socket unlink closure refused"
        );
        anyhow::ensure!(Instant::now() < until, "native socket sync deadline");
        self.anchors[0]
            .file
            .sync_all()
            .context("native socket parent fsync")?;
        anyhow::ensure!(Instant::now() < until, "native socket sync completed late");
        self.check_parents(until)?;
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeDriveFds {
    version: u32,
    rootfs_fd: i32,
    config_fd: i32,
    kernel_fd: i32,
}
impl NativeDriveFds {
    fn validate(&self) -> Result<()> {
        let fds = [self.rootfs_fd, self.config_fd, self.kernel_fd];
        if self.version != 1
            || fds.iter().any(|n| !(3..=1024).contains(n))
            || fds[0] == fds[1]
            || fds[0] == fds[2]
            || fds[1] == fds[2]
        {
            bail!("native FD relay receipt identity");
        }
        Ok(())
    }
    pub(crate) fn rootfs(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.rootfs_fd))
    }
    pub(crate) fn config(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.config_fd))
    }
    pub(crate) fn kernel(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.kernel_fd))
    }
}
// Closed v2 request: version plus three fixed 64-byte lowercase SHA256 strings.
// Compact JSON has exactly 259 bytes; receipt remains independently bounded.
const NATIVE_RELAY_V2_MAX_PACKET: usize = 259;
async fn relay_send(
    transport: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    bytes: &[u8],
    fds: &[i32; 4],
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > NATIVE_RELAY_V2_MAX_PACKET {
        bail!("native FD relay packet bounds");
    }
    loop {
        let mut ready = transport.writable().await?;
        let result = ready.try_io(|fd| {
            nix::sys::socket::sendmsg::<()>(
                fd.get_ref().as_raw_fd(),
                &[std::io::IoSlice::new(bytes)],
                &[nix::sys::socket::ControlMessage::ScmRights(fds)],
                nix::sys::socket::MsgFlags::MSG_DONTWAIT | nix::sys::socket::MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        });
        match result {
            Err(_) => continue,
            Ok(result) => {
                if result? != bytes.len() {
                    bail!("native FD relay short packet");
                }
                return Ok(());
            }
        }
    }
}
async fn relay_receive(
    transport: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
) -> Result<Vec<u8>> {
    loop {
        let mut ready = transport.readable().await?;
        let mut bytes = [0u8; 256];
        let result = ready.try_io(|fd| {
            let mut slices = [std::io::IoSliceMut::new(&mut bytes)];
            let message = nix::sys::socket::recvmsg::<()>(
                fd.get_ref().as_raw_fd(),
                &mut slices,
                None,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            )
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
            // No ancillary buffer: unexpected rights are discarded/closed by the
            // kernel, and CTRUNC refuses the packet without raw-FD adoption.
            Ok((message.bytes, message.flags))
        });
        match result {
            Err(_) => continue,
            Ok(result) => {
                let (length, flags) = result?;
                if length == 0
                    || length > bytes.len()
                    || flags.intersects(
                        nix::sys::socket::MsgFlags::MSG_TRUNC
                            | nix::sys::socket::MsgFlags::MSG_CTRUNC,
                    )
                {
                    bail!("native FD relay receipt bounds");
                }
                return Ok(bytes[..length].to_vec());
            }
        }
    }
}

impl FirecrackerInstance {
    pub fn new(work_dir: PathBuf) -> Self {
        let socket_path = work_dir.join("firecracker.socket");
        Self {
            client: UnixSocketClient::new(socket_path.clone()),
            work_dir,
            socket_path,
            stderr_path: None,
            process: None,
            native_socket_custody: false,
            native_socket: None,
            native_ticket: None,
            native_spawn: None,
            native_spawn_failed: false,
        }
    }

    fn reserve_native_ticket(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.native_ticket.is_none(),
            "native original ticket already reserved"
        );
        {
            let mut registry = native_debts()
                .lock()
                .map_err(|_| anyhow::anyhow!("native socket debt poisoned"))?;
            anyhow::ensure!(registry.admitted < 32, "native socket lifetime capacity");
            self.native_ticket = Some(registry.admitted);
            registry.admitted += 1;
        }
        Ok(())
    }

    fn prepare_native_socket(&mut self, until: Instant) -> Result<()> {
        anyhow::ensure!(Instant::now() < until, "native socket preparation deadline");
        anyhow::ensure!(
            self.native_ticket.is_none() && self.native_socket.is_none(),
            "native socket original already admitted"
        );
        self.reserve_native_ticket()?;
        // Install partial owner before the first open/fstat. The permanent ticket
        // reserves a preallocated Drop slot for every error/cancellation path.
        self.native_socket = Some(NativeSocketOwner {
            anchors: Vec::with_capacity(32),
            leaf: None,
            pin: None,
            dispatched: false,
            unlinked: false,
            unlink_calling: false,
        });
        let owner = self.native_socket.as_mut().unwrap();
        for path in
            std::iter::once(self.work_dir.as_path()).chain(self.work_dir.ancestors().skip(1))
        {
            anyhow::ensure!(owner.anchors.len() < 32, "native socket ancestry bound");
            anyhow::ensure!(Instant::now() < until, "native socket parent open deadline");
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            owner.anchors.push(SocketAnchor {
                path: path.to_path_buf(),
                file,
                pin: None,
            });
            anyhow::ensure!(
                Instant::now() < until,
                "native socket parent open completed late"
            );
            let first = owner.anchors.len() == 1;
            let anchor = owner.anchors.last_mut().unwrap();
            let pin = anchor.file.metadata()?;
            anyhow::ensure!(
                Instant::now() < until,
                "native socket parent capture completed late"
            );
            anyhow::ensure!(
                pin.is_dir() && pin.uid() == 0 && pin.gid() == 0 && pin.mode() & 0o022 == 0,
                "native socket parent protection"
            );
            if first {
                anyhow::ensure!(
                    pin.mode() & 0o7777 == 0o700,
                    "native socket private parent required"
                );
            }
            anchor.pin = Some(pin);
        }
        owner.check_parents(until)?;
        anyhow::ensure!(
            matches!(fs::symlink_metadata(&self.socket_path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound),
            "native socket initial absence not established"
        );
        anyhow::ensure!(
            Instant::now() < until,
            "native socket initial name completed late"
        );
        Ok(())
    }

    pub fn pid(&self) -> Result<Pid> {
        let raw_pid = self
            .process
            .as_ref()
            .and_then(|child| child.id())
            .context("firecracker process is not running")?;
        let raw_pid = i32::try_from(raw_pid).context("firecracker pid does not fit in i32")?;
        Ok(Pid::from_raw(raw_pid))
    }

    pub async fn spawn_with_netns(
        &mut self,
        firecracker_binary: &Path,
        stdout_path: Option<&Path>,
        stderr_path: Option<&Path>,
        netns: Option<&Path>,
    ) -> Result<()> {
        self.spawn_internal(firecracker_binary, stdout_path, stderr_path, netns, false)
            .await
    }

    /// Start the protected single-thread FD relay; its receipt is not VM readiness.
    pub async fn spawn_native(
        &mut self,
        inputs: &super::native_guest::NativeInputs,
        vmm_sha256: &str,
        stdout_path: Option<&Path>,
        stderr_path: Option<&Path>,
    ) -> Result<NativeDriveFds> {
        if self.process.is_some() || self.native_spawn.is_some() {
            bail!("firecracker process already started");
        }
        let relay_started = std::time::Instant::now();
        let until = relay_started + std::time::Duration::from_secs(3);
        self.prepare_native_socket(Instant::from_std(until))?;
        anyhow::ensure!(
            std::time::Instant::now() < until,
            "native relay preparation deadline"
        );
        let (parent, child_socket) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC | nix::sys::socket::SockFlag::SOCK_NONBLOCK,
        )?;
        anyhow::ensure!(
            std::time::Instant::now() < until,
            "native relay socketpair completed late"
        );
        let transport = tokio::io::unix::AsyncFd::new(parent)?;
        let mut command = Command::new(format!("/proc/self/fd/{}", inputs.probe.as_raw_fd()));
        command
            .args([
                "--launch-vmm",
                "--parent-pid",
                &std::process::id().to_string(),
            ])
            .env_clear()
            .current_dir(&self.work_dir)
            .process_group(0)
            .stdin(Stdio::from(child_socket))
            .stdout(open_log_stdio(stdout_path)?)
            .stderr(match stderr_path {
                Some(_) => open_log_stdio(stderr_path)?,
                // Reuse the supervisor-owned stderr; create no unowned log file.
                None => Stdio::inherit(),
            });
        if stderr_path.is_none() {
            command.arg("--relay-diagnostics-inherited");
        }
        self.stderr_path = stderr_path.map(Path::to_path_buf);
        // This retained task keeps the scoped-spawn receiver and any returned
        // Child alive even when the caller cancels this launch future.
        anyhow::ensure!(
            std::time::Instant::now() < until,
            "native dispatch deadline"
        );
        self.native_socket.as_mut().unwrap().dispatched = true;
        self.native_socket_custody = true;
        self.native_spawn = Some(tokio::spawn(async move {
            crate::privileges::spawn_tokio_command_scoped(command, &[], || Ok(())).await
        }));
        self.reconcile_native_spawn(tokio::time::Instant::from_std(until))
            .await?;
        eprintln!(
            "native_relay_parent stage=spawned elapsed_ms={} bytes=0",
            relay_started.elapsed().as_millis()
        );
        let request = serde_json::to_vec(
            &serde_json::json!({"version":2,"vmm_sha256":vmm_sha256,"rootfs_sha256":inputs.sealed_hashes[0],"config_sha256":inputs.sealed_hashes[1]}),
        )?;
        let fds = [
            inputs.vmm.as_raw_fd(),
            inputs.rootfs.as_raw_fd(),
            inputs.config.as_raw_fd(),
            inputs.kernel.as_raw_fd(),
        ];
        let receipt = tokio::time::timeout_at(tokio::time::Instant::from_std(until), async {
            anyhow::ensure!(
                std::time::Instant::now() < until,
                "native FD relay deadline"
            );
            relay_send(&transport, &request, &fds).await?;
            eprintln!(
                "native_relay_parent stage=sent elapsed_ms={} bytes={}",
                relay_started.elapsed().as_millis(),
                request.len()
            );
            let received = relay_receive(&transport).await;
            eprintln!(
                "native_relay_parent stage=receive_returned elapsed_ms={} bytes={} success={}",
                relay_started.elapsed().as_millis(),
                received.as_ref().map_or(0, Vec::len),
                received.is_ok()
            );
            received
        })
        .await
        .context("native FD relay deadline")??;
        if std::time::Instant::now() >= until {
            bail!("native FD relay deadline");
        }
        let receipt: NativeDriveFds =
            serde_json::from_slice(&receipt).context("native FD relay receipt")?;
        receipt.validate()?;
        Ok(receipt)
    }

    async fn reconcile_native_spawn(&mut self, until: Instant) -> Result<()> {
        if Instant::now() >= until {
            bail!("native pending spawn deadline; owner retained");
        }
        if self.native_spawn_failed {
            bail!("native pending spawn still requires reconciliation");
        }
        let Some(pending) = self.native_spawn.as_mut() else {
            return Ok(());
        };
        match time::timeout_at(until, pending).await {
            Ok(Ok(Ok(child))) => {
                self.process = Some(child);
                self.native_socket_custody = true;
                self.native_spawn.take();
                if Instant::now() >= until {
                    bail!("native pending spawn completion deadline; child retained");
                }
                Ok(())
            }
            Ok(Ok(Err(error))) => {
                self.native_spawn_failed = true;
                Err(error).context("native scoped spawn failed; owner retained")
            }
            Ok(Err(_)) => {
                self.native_spawn_failed = true;
                bail!("native spawn task failed; owner retained")
            }
            Err(_) => bail!("native pending spawn deadline; owner retained"),
        }
    }

    async fn spawn_internal(
        &mut self,
        firecracker_binary: &Path,
        stdout_path: Option<&Path>,
        stderr_path: Option<&Path>,
        netns: Option<&Path>,
        captured: bool,
    ) -> Result<()> {
        if self.process.is_some() {
            bail!("firecracker process already started");
        }

        if captured {
            match fs::symlink_metadata(&self.socket_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => bail!("native API socket path already exists or cannot be inspected"),
            }
        } else if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }

        let firecracker_binary = if captured {
            firecracker_binary.to_path_buf()
        } else {
            fs::canonicalize(firecracker_binary)
                .unwrap_or_else(|_| firecracker_binary.to_path_buf())
        };
        trace!(
            binary = %firecracker_binary.display(),
            socket_path = %self.socket_path.display(),
            netns = ?netns,
            "spawning firecracker process"
        );

        let netns = netns
            .map(|netns_path| {
                fs::File::open(netns_path).with_context(|| {
                    format!(
                        "open Firecracker network namespace {}",
                        netns_path.display()
                    )
                })
            })
            .transpose()?;

        let mut cmd = Command::new(&firecracker_binary);
        cmd.process_group(0);

        cmd.arg("--api-sock")
            .arg(&self.socket_path)
            .arg("--mmds-size-limit")
            .arg(MMDS_SIZE_LIMIT.to_string())
            .arg("--http-api-max-payload-size")
            .arg(HTTP_API_MAX_PAYLOAD_SIZE.to_string())
            .stdin(Stdio::null());

        // Set Current Working Directory to the workspace
        // This is crucial for relative paths to work
        cmd.current_dir(&self.work_dir);

        let stdout = open_log_stdio(stdout_path)?;
        let stderr = open_log_stdio(stderr_path)?;
        self.stderr_path = stderr_path.map(Path::to_path_buf);

        cmd.stdout(stdout).stderr(stderr);

        let child = crate::privileges::spawn_tokio_command_scoped(cmd, &[], move || {
            if let Some(netns) = netns {
                // SAFETY: `netns` is an open network namespace descriptor and
                // this short-lived launcher thread has not spawned a child yet.
                let rc = unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        })
        .await
        .context("failed to spawn firecracker")?;
        trace!("firecracker process spawned");

        // Set oom_score_adj to maximum (1000) so the firecracker process is
        // the first candidate for OOM kill, protecting current agentenv server.
        if let Some(pid) = child.id() {
            let oom_path = format!("/proc/{pid}/oom_score_adj");
            if let Err(e) = fs::write(&oom_path, b"1000") {
                warn!(pid, oom_path, err = %e, "failed to set oom_score_adj for firecracker");
            }
        }

        self.process = Some(child);
        self.native_socket_custody = captured;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn native_smoke_exit_success(&mut self) -> Result<()> {
        let child = self
            .process
            .as_mut()
            .context("native smoke child missing")?;
        let status = time::timeout(Duration::from_secs(3), child.wait())
            .await
            .context("native smoke exit deadline")??;
        if !status.success() {
            bail!("native smoke executable exit refused");
        }
        // Keep the reaped Child until stop_native also retires socket custody.
        Ok(())
    }

    /// Waits for the Firecracker API socket to become available.
    pub async fn wait_for_ready(
        &mut self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        trace!(
            socket_path = %self.socket_path.display(),
            timeout_ms = timeout.as_millis(),
            poll_interval_ms = poll_interval.as_millis(),
            "waiting for firecracker api socket"
        );
        let start = Instant::now();
        while !self.socket_path.exists() {
            if let Some(process) = self.process.as_mut() {
                if let Some(status) = process
                    .try_wait()
                    .context("check firecracker process status")?
                {
                    bail!(
                        "firecracker exited before its API socket appeared at {} (status: {status}); stderr: {}",
                        self.socket_path.display(),
                        self.stderr_summary()
                    );
                }
            }
            if start.elapsed() > timeout {
                bail!(
                    "firecracker api socket did not appear at {} within {} ms; stderr: {}",
                    self.socket_path.display(),
                    timeout.as_millis(),
                    self.stderr_summary()
                );
            }
            time::sleep(poll_interval).await;
        }
        if let Some(owner) = self.native_socket.as_mut() {
            owner.capture(&self.socket_path, start + timeout)?;
            anyhow::ensure!(
                start.elapsed() < timeout,
                "native socket capture completed late"
            );
        } else if self.native_socket_custody {
            bail!("native socket original capture owner missing");
        }
        trace!(socket_path = %self.socket_path.display(), "firecracker api socket is ready");
        Ok(())
    }

    fn stderr_summary(&self) -> String {
        let Some(path) = self.stderr_path.as_deref() else {
            return "not captured".to_string();
        };
        match Self::read_stderr_tail(path) {
            Ok(stderr) if stderr.is_empty() => "empty".to_string(),
            Ok(stderr) => stderr,
            Err(err) => format!("unavailable ({err})"),
        }
    }

    fn read_stderr_tail(path: &Path) -> std::io::Result<String> {
        const MAX_BYTES: u64 = 4096;

        let mut file = fs::File::open(path)?;
        let bytes_to_read = file.metadata()?.len().min(MAX_BYTES);
        file.seek(SeekFrom::End(-(bytes_to_read as i64)))?;
        let mut bytes = Vec::with_capacity(bytes_to_read as usize);
        file.read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
    }

    /// Gracefully stops the Firecracker process, with a timeout for forced kill.
    /// The socket file will be cleaned up after stopping the process.
    ///
    /// This method first tries to send `SIGTERM` to allow for graceful stop,
    /// but if the process does not exit within the specified timeout, it will send `SIGKILL` to force termination.
    #[tracing::instrument(skip(self))]
    pub async fn stop(&mut self, timeout: Duration) -> Result<()> {
        debug!(
            timeout_ms = timeout.as_millis(),
            "stopping firecracker process"
        );

        if let Some(mut child) = self.process.take() {
            // First try a graceful stop with SIGTERM
            if let Some(pid) = child.id() {
                trace!(pid, "sending SIGTERM to firecracker");
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
            }

            // Wait for the process to exit, but if it doesn't within the timeout, force kill it with SIGKILL
            if time::timeout(timeout, child.wait()).await.is_err() {
                warn!("firecracker stop timed out; sending SIGKILL");
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }

        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }
        debug!("firecracker process stopped");
        Ok(())
    }

    /// Native launches retain custody until the exact child has been reaped.
    pub async fn stop_native(&mut self, timeout: Duration) -> Result<()> {
        let until = Instant::now() + timeout;
        self.reconcile_native_spawn(until).await?;
        if let Some(child) = self.process.as_mut() {
            if let Some(pid) = child.id() {
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
            }
            // Reserve part of the same total deadline for SIGKILL and actual wait.
            let left = until.saturating_duration_since(Instant::now());
            let grace = Instant::now() + left / 2;
            let reaped = match time::timeout_at(grace, child.wait()).await {
                Ok(Ok(status)) => {
                    eprintln!(
                        "native_relay_parent stage=reaped code={} success={}",
                        status.code().unwrap_or(-1),
                        status.success()
                    );
                    true
                }
                Ok(Err(_)) | Err(_) => {
                    let _ = child.start_kill();
                    match time::timeout_at(until, child.wait()).await {
                        Ok(Ok(status)) => {
                            eprintln!(
                                "native_relay_parent stage=reaped_after_kill code={} success={}",
                                status.code().unwrap_or(-1),
                                status.success()
                            );
                            true
                        }
                        _ => false,
                    }
                }
            };
            if !reaped {
                bail!("native firecracker child still requires reconciliation");
            }
            self.process.take();
        }
        if let Some(owner) = self.native_socket.as_mut() {
            owner.retire(&self.socket_path, until)?;
            anyhow::ensure!(
                Instant::now() < until,
                "native socket retirement completed late"
            );
            self.native_socket.take();
            self.native_socket_custody = false;
        } else if self.native_socket_custody {
            bail!("native socket creation without original capture owner");
        }

        Ok(())
    }

    /// Applies a CPU configuration template.
    /// Pre-boot only.
    pub async fn set_cpu_config(&self, json: &str) -> Result<()> {
        let raw: Box<RawValue> =
            serde_json::from_str(json).context("Failed to parse cpu_config_json")?;
        self.client
            .request_no_content(Method::PUT, "/cpu-config", Some(raw.as_ref()))
            .await
            .context("Failed to set CPU configuration")
    }

    /// Configures the Firecracker logger to write human-readable logs to a file.
    ///
    /// Pre-boot only and can only be set once. `level` is case-insensitive and
    /// must be one of `Error`, `Warning`, `Info`, `Debug`, `Trace`.
    pub async fn set_logger(&self, log_path: &Path, level: &str) -> Result<()> {
        let level = parse_log_level(level)?;
        let logger = Logger {
            level: Some(level),
            log_path: Some(log_path.to_string_lossy().into_owned()),
            show_level: Some(true),
            show_log_origin: Some(true),
            module: None,
        };
        self.client
            .request_no_content(Method::PUT, "/logger", Some(&logger))
            .await
            .context("Failed to configure Firecracker logger")
    }

    /// Configures the machine (vCPUs, memory, etc.)
    /// Pre-boot only.
    pub async fn set_machine_config(
        &self,
        mem_size_mib: u32,
        vcpu_count: u32,
        smt: bool,
        track_dirty_pages: bool,
    ) -> Result<()> {
        let mut machine_config = MachineConfiguration::new(mem_size_mib as i32, vcpu_count as i32);
        machine_config.smt = Some(smt);
        machine_config.track_dirty_pages = Some(track_dirty_pages);
        self.client
            .request_no_content(Method::PUT, "/machine-config", Some(&machine_config))
            .await
            .context("Failed to set machine configuration")
    }

    /// Configures the boot source (kernel, initrd, boot args).
    /// Pre-boot only.
    pub async fn set_boot_source(
        &self,
        kernel_image: &Path,
        initrd_path: Option<&Path>,
        boot_args: Option<&str>,
    ) -> Result<()> {
        let mut boot_source = BootSource::new(kernel_image.to_string_lossy().into_owned());
        boot_source.boot_args = boot_args.map(str::to_string);
        boot_source.initrd_path = initrd_path.map(|p| p.to_string_lossy().into_owned());
        self.client
            .request_no_content(Method::PUT, "/boot-source", Some(&boot_source))
            .await
            .context("Failed to set boot source")
    }

    /// Adds or updates a virtio-blk drive in the Firecracker device model.
    ///
    /// `is_root_device` must be `true` for the boot rootfs drive and `false`
    /// for any non-root extra drive. This API is only used during the
    /// pre-boot configuration phase. `rate_limiter` attaches a pre-boot limiter
    /// so throttling is in force from the guest's first I/O (a post-start PATCH
    /// would leave a brief unthrottled window).
    #[allow(clippy::too_many_arguments)]
    pub async fn add_drive(
        &self,
        drive_id: &str,
        path_on_host: &Path,
        is_root_device: bool,
        read_only: bool,
        direct: bool,
        io_engine: IoEngine,
        rate_limiter: Option<Box<RateLimiter>>,
    ) -> Result<()> {
        let mut drive = Drive::new(drive_id.to_string(), is_root_device);
        drive.path_on_host = Some(path_on_host.to_string_lossy().into_owned());
        drive.is_read_only = Some(read_only);
        drive.direct = Some(direct);
        drive.io_engine = Some(io_engine);
        drive.rate_limiter = rate_limiter;
        let path = format!("/drives/{}", drive_id);
        self.client
            .request_no_content(Method::PUT, &path, Some(&drive))
            .await
            .with_context(|| format!("Failed to add/update drive {}", drive_id))
    }

    /// Updates the rate limiter on a running VM's drive via PATCH.
    pub async fn patch_drive_rate_limiter(
        &self,
        drive_id: &str,
        rate_limiter: Box<RateLimiter>,
    ) -> Result<()> {
        let mut partial = PartialDrive::new(drive_id.to_string());
        partial.rate_limiter = Some(rate_limiter);
        let path = format!("/drives/{}", drive_id);
        self.client
            .request_no_content(Method::PATCH, &path, Some(&partial))
            .await
            .with_context(|| format!("Failed to patch rate limiter on drive {}", drive_id))
    }

    /// Updates the host backing path for a drive on a loaded snapshot.
    pub async fn patch_drive_path(&self, drive_id: &str, path_on_host: &Path) -> Result<()> {
        let mut partial = PartialDrive::new(drive_id.to_string());
        partial.path_on_host = Some(path_on_host.to_string_lossy().into_owned());
        let path = format!("/drives/{}", drive_id);
        self.client
            .request_no_content(Method::PATCH, &path, Some(&partial))
            .await
            .with_context(|| format!("Failed to patch host path on drive {}", drive_id))
    }

    /// Adds a network interface.
    /// Pre-boot only.
    pub async fn add_network_interface(
        &self,
        iface_id: &str,
        guest_mac: Option<String>,
        host_dev_name: String,
        rx_rate_limiter: Option<Box<RateLimiter>>,
        tx_rate_limiter: Option<Box<RateLimiter>>,
    ) -> Result<()> {
        let path = format!("/network-interfaces/{}", iface_id);
        let iface = NetworkInterface {
            guest_mac,
            host_dev_name: host_dev_name.clone(),
            iface_id: iface_id.to_string(),
            rx_rate_limiter,
            tx_rate_limiter,
        };
        self.client
            .request_no_content(Method::PUT, &path, Some(&iface))
            .await
            .with_context(|| format!("Failed to add network interface {}", iface_id))
    }

    /// Configures Firecracker MMDS V2 for a network interface.
    /// Pre-boot only.
    /// Configure the native guest's host-initiated VSOCK endpoint in this VM's
    /// owned working directory. Firecracker creates the fresh socket itself.
    pub async fn add_vsock(&self, guest_cid: u32, uds_path: &Path) -> Result<()> {
        if guest_cid < 3 || guest_cid == u32::MAX {
            bail!("native guest VSOCK CID is reserved");
        }
        // A literal filename avoids traversal, platform aliases and binding in
        // a foreign namespace. The native profile controls this single endpoint.
        if uds_path.to_str() != Some("native-guest.vsock") {
            bail!("native guest VSOCK path must be native-guest.vsock");
        }
        match fs::symlink_metadata(self.work_dir.join(uds_path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("native guest VSOCK endpoint already exists"),
            Err(error) => return Err(error).context("inspect native guest VSOCK endpoint"),
        }
        // The generated model uses i32 for this unsigned CID. A closed JSON
        // body preserves the actual u32 range without a narrowing cast.
        let vsock = serde_json::json!({"guest_cid":guest_cid,"uds_path":"native-guest.vsock"});
        self.client
            .request_no_content(Method::PUT, "/vsock", Some(&vsock))
            .await
            .context("configure native guest VSOCK")
    }

    pub async fn set_mmds_config(&self, iface_id: &str) -> Result<()> {
        let mut config = MmdsConfig::new(vec![iface_id.to_string()]);
        config.version = Some(MmdsVersion::V2);
        self.client
            .request_no_content(Method::PUT, "/mmds/config", Some(&config))
            .await
            .context("Failed to set MMDS configuration")
    }

    /// Creates or replaces the Firecracker MMDS data store.
    pub async fn set_mmds(&self, metadata: &MmdsMetadata) -> Result<()> {
        let payload_size = serde_json::to_vec(metadata)
            .context("Failed to serialize MMDS metadata for size validation")?
            .len();
        if payload_size > MMDS_SIZE_LIMIT {
            bail!(
                "MMDS metadata payload is {payload_size} bytes, exceeds Firecracker MMDS size limit {MMDS_SIZE_LIMIT}; imageConfigs may be too large"
            );
        }
        self.client
            .request_no_content(Method::PUT, "/mmds", Some(metadata))
            .await
            .context("Failed to set MMDS data")
    }

    /// Configures the virtio-balloon device with free page reporting enabled.
    ///
    /// Pre-boot only. Sets `amount_mib = 0` (no target inflation) and
    /// `deflate_on_oom = true` as a safety net. The primary purpose is to
    /// enable free page reporting so the guest kernel can return unused pages
    /// to the host via `MADV_DONTNEED`, reducing host memory pressure.
    pub async fn set_balloon(&self) -> Result<()> {
        let balloon = Balloon {
            amount_mib: 0,
            deflate_on_oom: true,
            stats_polling_interval_s: None,
            free_page_hinting: None,
            free_page_reporting: Some(true),
        };
        self.client
            .request_no_content(Method::PUT, "/balloon", Some(&balloon))
            .await
            .context("Failed to set balloon configuration")
    }

    /// Starts the microVM.
    pub async fn start(&self) -> Result<()> {
        let action = InstanceActionInfo::new(ActionType::InstanceStart);
        self.client
            .request_no_content(Method::PUT, "/actions", Some(&action))
            .await
            .context("Failed to start microVM")
    }

    /// Pauses the microVM.
    pub async fn pause(&self) -> Result<()> {
        let body = Vm::new(VmState::Paused);
        self.client
            .request_no_content(Method::PATCH, "/vm", Some(&body))
            .await
            .context("Failed to pause microVM")
    }

    /// Resumes the microVM.
    pub async fn resume(&self) -> Result<()> {
        let body = Vm::new(VmState::Resumed);
        self.client
            .request_no_content(Method::PATCH, "/vm", Some(&body))
            .await
            .context("Failed to resume microVM")
    }

    /// Creates a diff snapshot containing VM state only.
    ///
    /// The memory data path is handled by AgentENV through dirty memory ranges.
    #[tracing::instrument(skip(self), fields(snapshot_path = %snapshot_path.display()))]
    pub async fn create_state_only_snapshot(&self, snapshot_path: &Path) -> Result<()> {
        let mut params = SnapshotCreateParams::new(snapshot_path.to_string_lossy().into_owned());
        params.snapshot_type =
            Some(firecracker_client::models::snapshot_create_params::SnapshotType::Diff);
        self.client
            .request_no_content(Method::PUT, "/snapshot/create", Some(&params))
            .await
            .context("Failed to create state-only snapshot")
    }

    /// Returns Firecracker's dirty memory ranges for direct memory snapshot packaging.
    #[tracing::instrument(skip(self))]
    pub async fn get_dirty_memory_ranges(&self) -> Result<DirtyMemoryRanges> {
        self.client
            .request::<(), DirtyMemoryRanges>(Method::GET, "/vm/dirty-memory-ranges", None)
            .await
            .context("Failed to get dirty memory ranges")
    }

    /// Loads a snapshot with uffd memory backend.
    /// Pre-boot only.
    #[allow(dead_code)]
    #[tracing::instrument(skip(self, network_overrides), fields(snapshot_path = %snapshot_path.display(), uffd_uds_path = %uffd_uds_path.display(), network_override_count = network_overrides.len()))]
    pub async fn load_snapshot_uffd(
        &self,
        snapshot_path: &Path,
        uffd_uds_path: &Path,
        network_overrides: &[(String, String)],
    ) -> Result<()> {
        let snapshot_path = self.resolve_host_path(snapshot_path);
        let mut params = SnapshotLoadParams::new(snapshot_path.to_string_lossy().into_owned());
        params.mem_backend = Some(Box::new(MemoryBackend::new(
            firecracker_client::models::memory_backend::BackendType::Uffd,
            uffd_uds_path.to_string_lossy().into_owned(),
        )));
        params.resume_vm = Some(true);
        if !network_overrides.is_empty() {
            params.network_overrides = Some(
                network_overrides
                    .iter()
                    .map(|(iface_id, host_dev_name)| {
                        NetworkOverride::new(iface_id.clone(), host_dev_name.clone())
                    })
                    .collect(),
            );
        }
        self.client
            .request_no_content(Method::PUT, "/snapshot/load", Some(&params))
            .await
            .context("Failed to load snapshot with uffd backend")
    }

    /// Loads a snapshot with a file-backed memory backend.
    /// Pre-boot only.
    #[tracing::instrument(skip(self, network_overrides), fields(snapshot_path = %snapshot_path.display(), mem_backend_path = %mem_backend_path.display(), network_override_count = network_overrides.len()))]
    pub async fn load_snapshot_file(
        &self,
        snapshot_path: &Path,
        mem_backend_path: &Path,
        network_overrides: &[(&str, &str)],
        resume_vm: bool,
        track_dirty_pages: bool,
    ) -> Result<()> {
        let snapshot_path = self.resolve_host_path(snapshot_path);
        let mut params = SnapshotLoadParams::new(snapshot_path.to_string_lossy().into_owned());
        params.mem_backend = Some(Box::new(MemoryBackend::new(
            firecracker_client::models::memory_backend::BackendType::File,
            mem_backend_path.to_string_lossy().into_owned(),
        )));
        params.resume_vm = Some(resume_vm);
        params.track_dirty_pages = Some(track_dirty_pages);
        if !network_overrides.is_empty() {
            params.network_overrides = Some(
                network_overrides
                    .iter()
                    .map(|(iface_id, host_dev_name)| {
                        NetworkOverride::new(iface_id.to_string(), host_dev_name.to_string())
                    })
                    .collect(),
            );
        }
        self.client
            .request_no_content(Method::PUT, "/snapshot/load", Some(&params))
            .await
            .context("Failed to load snapshot with file backend")
    }

    fn resolve_host_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.work_dir.join(path)
        }
    }
}

impl Drop for FirecrackerInstance {
    fn drop(&mut self) {
        if self.native_ticket.is_some() || self.native_socket_custody || self.native_spawn.is_some()
        {
            if self.native_socket.is_some() || self.process.is_some() || self.native_spawn.is_some()
            {
                let debt = NativeDropDebt {
                    _socket: self.native_socket.take(),
                    _child: self.process.take(),
                    _spawn: self.native_spawn.take(),
                };
                let mut registry = native_debts()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(slot) = self.native_ticket {
                    // Each ticket is unique and permanent; only this instance
                    // can fill its reserved slot, exactly once in Drop.
                    registry.debts[slot] = Some(debt);
                } else {
                    // Only unadmitted cfg(test) legacy fixtures reach here.
                    // Never drop an actual child/task merely to hide that debt.
                    std::mem::forget(debt);
                }
            }
            return;
        }
        let mut had_child = false;
        if let Some(mut child) = self.process.take() {
            had_child = true;
            if let Err(err) = child.start_kill() {
                warn!(error = %err, "failed to kill sandbox process on drop");
            }
        }

        // Only remove the socket if we actually spawned/owned the process.
        if had_child {
            if let Err(err) = fs::remove_file(&self.socket_path) {
                // Ignore NotFound error as the file might have been removed already
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        path = %self.socket_path.display(),
                        error = %err,
                        "failed to remove sandbox socket on drop"
                    );
                }
            }
        }
    }
}

fn open_log_stdio(path: Option<&Path>) -> Result<Stdio> {
    let Some(path) = path else {
        return Ok(Stdio::null());
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create log directory {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open firecracker log {}", path.display()))?;
    Ok(Stdio::from(file))
}

/// Parse a case-insensitive Firecracker log level string.
fn parse_log_level(level: &str) -> Result<firecracker_client::models::logger::Level> {
    use firecracker_client::models::logger::Level;
    match level.trim().to_ascii_lowercase().as_str() {
        "error" => Ok(Level::Error),
        "warning" | "warn" => Ok(Level::Warning),
        "info" => Ok(Level::Info),
        "debug" => Ok(Level::Debug),
        "trace" => Ok(Level::Trace),
        other => bail!(
            "invalid firecracker log level '{other}'; expected one of Error, Warning, Info, Debug, Trace"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;
    use tempfile::tempdir;

    #[tokio::test]
    async fn refused_native_spawn_stop_preserves_preexisting_api_objects() -> Result<()> {
        use std::os::unix::fs::symlink;
        for dangling in [false, true] {
            let temp = tempdir()?;
            let path = temp.path().join("firecracker.socket");
            if dangling {
                symlink("missing-owned-by-other", &path)?;
            } else {
                fs::write(&path, b"original")?;
            }
            let mut instance = FirecrackerInstance::new(temp.path().into());
            let executable = fs::File::open("/bin/sh")?;
            let inputs = super::super::native_guest::NativeInputs {
                profile: std::sync::Arc::new(executable.try_clone()?),
                anchors: Vec::new(),
                pins: Vec::new(),
                profile_ancestors: 0,
                source_drives: [executable.try_clone()?, executable.try_clone()?],
                sealed_sizes: [0, 0],
                sealed_pins: [executable.metadata()?, executable.metadata()?],
                sealed_hashes: ["a".repeat(64), "b".repeat(64)],
                credential_sha256: "c".repeat(64),
                rootfs: executable.try_clone()?,
                config: executable.try_clone()?,
                kernel: executable.try_clone()?,
                probe: executable.try_clone()?,
                vmm: executable.try_clone()?,
                credential: executable,
            };
            assert!(instance
                .spawn_native(&inputs, &"a".repeat(64), None, None)
                .await
                .is_err());
            instance.stop_native(Duration::from_millis(20)).await?;
            if dangling {
                assert_eq!(
                    fs::read_link(&path)?,
                    PathBuf::from("missing-owned-by-other")
                );
            } else {
                assert_eq!(fs::read(&path)?, b"original");
            }
            assert!(instance.process.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn native_vsock_refuses_reserved_cids_and_foreign_paths_without_api() -> Result<()> {
        let temp = tempdir()?;
        let instance = FirecrackerInstance::new(temp.path().into());
        for cid in [0, 1, 2, u32::MAX] {
            assert!(instance
                .add_vsock(cid, Path::new("native-guest.vsock"))
                .await
                .unwrap_err()
                .to_string()
                .contains("CID is reserved"));
        }
        for path in [
            "",
            ".",
            "..",
            "../native-guest.vsock",
            "./native-guest.vsock",
            "/native-guest.vsock",
            "foreign.vsock",
            "native-guest.vsock/",
            "dir/native-guest.vsock",
        ] {
            assert!(instance
                .add_vsock(3, Path::new(path))
                .await
                .unwrap_err()
                .to_string()
                .contains("path must be"));
        }
        assert_eq!(fs::read_dir(temp.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn native_vsock_refuses_existing_file_and_dangling_symlink_without_adoption() -> Result<()>
    {
        let temp = tempdir()?;
        let instance = FirecrackerInstance::new(temp.path().into());
        let path = temp.path().join("native-guest.vsock");
        fs::write(&path, b"foreign")?;
        assert!(instance
            .add_vsock(3, Path::new("native-guest.vsock"))
            .await
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        assert_eq!(fs::read(&path)?, b"foreign");
        fs::remove_file(&path)?;
        std::os::unix::fs::symlink("missing-owned-elsewhere", &path)?;
        assert!(instance
            .add_vsock(3, Path::new("native-guest.vsock"))
            .await
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        assert_eq!(fs::read_link(path)?, Path::new("missing-owned-elsewhere"));
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_ready_times_out_when_socket_never_appears() {
        let temp = tempdir().expect("tempdir");
        let mut instance = FirecrackerInstance::new(temp.path().to_path_buf());

        let err = instance
            .wait_for_ready(Duration::from_millis(30), Duration::from_millis(10))
            .await
            .expect_err("missing socket should time out");

        assert!(err.to_string().contains("did not appear"));
    }

    #[tokio::test]
    async fn wait_for_ready_succeeds_when_socket_file_appears() -> Result<()> {
        let temp = tempdir()?;
        let mut instance = FirecrackerInstance::new(temp.path().to_path_buf());
        let socket_path = instance.socket_path.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            fs::write(&socket_path, b"socket").expect("create socket marker");
        });

        instance
            .wait_for_ready(Duration::from_millis(100), Duration::from_millis(10))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn stop_without_process_removes_stale_socket_file() -> Result<()> {
        let temp = tempdir()?;
        let mut instance = FirecrackerInstance::new(temp.path().to_path_buf());
        fs::write(&instance.socket_path, b"stale socket")?;

        instance.stop(Duration::from_millis(10)).await?;

        assert!(!instance.socket_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn spawn_with_netns_rejects_duplicate_start() -> Result<()> {
        let temp = tempdir()?;
        let mut instance = FirecrackerInstance::new(temp.path().to_path_buf());

        instance
            .spawn_with_netns(Path::new("/bin/true"), None, None, None)
            .await?;

        let err = instance
            .spawn_with_netns(Path::new("/bin/true"), None, None, None)
            .await
            .expect_err("second spawn should fail");

        assert!(err.to_string().contains("already started"));
        instance.stop(Duration::from_millis(10)).await?;
        Ok(())
    }

    #[tokio::test]
    async fn drop_after_spawn_removes_owned_socket_file() -> Result<()> {
        let temp = tempdir()?;
        let socket_path = {
            let mut instance = FirecrackerInstance::new(temp.path().to_path_buf());
            instance
                .spawn_with_netns(Path::new("/bin/true"), None, None, None)
                .await?;
            fs::write(&instance.socket_path, b"owned socket")?;
            instance.socket_path.clone()
        };

        assert!(!socket_path.exists());
        Ok(())
    }

    #[test]
    fn drop_without_child_keeps_unowned_socket_file() -> Result<()> {
        let temp = tempdir()?;
        let socket_path = {
            let instance = FirecrackerInstance::new(temp.path().to_path_buf());
            fs::write(&instance.socket_path, b"external socket")?;
            instance.socket_path.clone()
        };

        assert!(socket_path.exists());
        Ok(())
    }

    #[test]
    fn open_log_stdio_creates_parent_dirs_and_appends_existing_files() -> Result<()> {
        let temp = tempdir()?;
        let log_path = temp.path().join("logs").join("firecracker.log");

        let status = StdCommand::new("sh")
            .arg("-c")
            .arg("printf first")
            .stdout(open_log_stdio(Some(&log_path))?)
            .status()?;
        assert!(status.success());
        assert_eq!(fs::read_to_string(&log_path)?, "first");

        let status = StdCommand::new("sh")
            .arg("-c")
            .arg("printf second")
            .stdout(open_log_stdio(Some(&log_path))?)
            .status()?;
        assert!(status.success());
        assert_eq!(fs::read_to_string(&log_path)?, "firstsecond");

        Ok(())
    }

    #[test]
    fn resolve_host_path_uses_firecracker_work_dir_for_relative_paths() -> Result<()> {
        let temp = tempdir()?;
        let instance = FirecrackerInstance::new(temp.path().to_path_buf());

        assert_eq!(
            instance.resolve_host_path(Path::new("vm_state.bin")),
            temp.path().join("vm_state.bin")
        );
        assert_eq!(
            instance.resolve_host_path(Path::new("/tmp/vm_state.bin")),
            PathBuf::from("/tmp/vm_state.bin")
        );

        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_relay_tests {
    use super::*;
    #[tokio::test]
    async fn native_relay_transfers_exactly_four_fds_and_reads_one_closed_receipt() -> Result<()> {
        use nix::sys::socket::{
            recvmsg, send, socketpair, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag,
            SockType,
        };
        let (host, peer) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )?;
        let transport = tokio::io::unix::AsyncFd::new(host)?;
        let file = fs::File::open("/bin/true")?;
        let clones = [
            file.try_clone()?,
            file.try_clone()?,
            file.try_clone()?,
            file.try_clone()?,
        ];
        let fds = clones.each_ref().map(AsRawFd::as_raw_fd);
        let request = serde_json::to_vec(&serde_json::json!({
            "version":2,"vmm_sha256":"a".repeat(64),
            "rootfs_sha256":"b".repeat(64),"config_sha256":"c".repeat(64)
        }))?;
        assert_eq!(request.len(), NATIVE_RELAY_V2_MAX_PACKET);
        let mut oversized = request.clone();
        oversized.push(b' ');
        for rejected in [oversized.as_slice(), &[]] {
            assert!(relay_send(&transport, rejected, &fds).await.is_err());
            let mut probe = [0u8; 512];
            assert_eq!(
                nix::sys::socket::recv(peer.as_raw_fd(), &mut probe, MsgFlags::MSG_DONTWAIT),
                Err(nix::errno::Errno::EAGAIN)
            );
        }
        relay_send(&transport, &request, &fds).await?;
        let mut data = [0u8; 512];
        let mut slices = [std::io::IoSliceMut::new(&mut data)];
        let mut control = nix::cmsg_space!([i32; 4]);
        let received = recvmsg::<()>(
            peer.as_raw_fd(),
            &mut slices,
            Some(&mut control),
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
        )?;
        assert!(!received
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC));
        let length = received.bytes;
        let mut count = 0;
        let mut rights = 0;
        for message in received.cmsgs()? {
            match message {
                ControlMessageOwned::ScmRights(fds) => {
                    rights += 1;
                    count += fds.len();
                    for fd in fds {
                        nix::unistd::close(fd)?;
                    }
                }
                _ => bail!("unexpected fixture ancillary"),
            }
        }
        assert_eq!(rights, 1);
        assert_eq!(count, 4);
        assert_eq!(&data[..length], request.as_slice());
        let response = br#"{"version":1,"rootfs_fd":7,"config_fd":8,"kernel_fd":9}"#;
        assert_eq!(
            send(
                peer.as_raw_fd(),
                response,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL
            )?,
            response.len()
        );
        let mapping: NativeDriveFds = serde_json::from_slice(&relay_receive(&transport).await?)?;
        mapping.validate()?;
        assert_eq!(mapping.rootfs(), PathBuf::from("/proc/self/fd/7"));
        assert_eq!(mapping.config(), PathBuf::from("/proc/self/fd/8"));
        assert_eq!(mapping.kernel(), PathBuf::from("/proc/self/fd/9"));
        for raw in [
            br#"{"version":1,"rootfs_fd":7,"config_fd":7,"kernel_fd":9}"#.as_slice(),
            br#"{"version":1,"rootfs_fd":2,"config_fd":8,"kernel_fd":9}"#,
        ] {
            let mapping: NativeDriveFds = serde_json::from_slice(raw)?;
            assert!(mapping.validate().is_err());
        }
        assert!(serde_json::from_slice::<NativeDriveFds>(
            br#"{"version":1,"rootfs_fd":7,"config_fd":8,"kernel_fd":9,"extra":1}"#
        )
        .is_err());
        Ok(())
    }
    #[tokio::test]
    async fn native_relay_rejects_ancillary_receipt_without_adopting_fds() -> Result<()> {
        use nix::sys::socket::{
            sendmsg, socketpair, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
        };
        let (host, peer) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )?;
        let transport = tokio::io::unix::AsyncFd::new(host)?;
        let file = fs::File::open("/bin/true")?;
        sendmsg::<()>(
            peer.as_raw_fd(),
            &[std::io::IoSlice::new(b"{}")],
            &[ControlMessage::ScmRights(&[file.as_raw_fd()])],
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            None,
        )?;
        assert!(relay_receive(&transport).await.is_err());
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_spawn_cancellation_tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_native_spawn_keeps_exact_child_until_bounded_stop_reaps() -> Result<()> {
        let work = tempfile::tempdir()?;
        let mut owner = FirecrackerInstance::new(work.path().to_owned());
        owner.reserve_native_ticket()?;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let held = fs::File::open("/bin/sh")?;
        owner.native_spawn = Some(tokio::spawn(async move {
            let mut command = Command::new(format!("/proc/self/fd/{}", held.as_raw_fd()));
            command
                .args(["-c", "while :; do :; done"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let child =
                crate::privileges::spawn_tokio_command_scoped(command, &[], || Ok(())).await?;
            let pid = child
                .id()
                .ok_or_else(|| std::io::Error::other("fixture child identity absent"))?;
            ready_tx
                .send(pid)
                .map_err(|_| std::io::Error::other("fixture ready closed"))?;
            release_rx
                .await
                .map_err(|_| std::io::Error::other("fixture release closed"))?;
            Ok(child)
        }));
        let pid = ready_rx.await?;
        // Collect observations without asserting until the exact task and
        // actual child have been reconciled/reaped, even if an oracle fails.
        let cancelled = time::timeout(
            Duration::from_millis(1),
            owner.reconcile_native_spawn(Instant::now() + Duration::from_secs(3)),
        )
        .await
        .is_err();
        let held_after_cancel = owner.native_spawn.is_some() && owner.process.is_none();
        let early_stop_refused = owner.stop_native(Duration::from_millis(1)).await.is_err();
        let still_held = owner.native_spawn.is_some() && owner.process.is_none();
        let released = release_tx.send(()).is_ok();
        let uncaptured_refused = owner.stop_native(Duration::from_secs(3)).await.is_err();
        let reaped = owner.native_spawn.is_none() && owner.process.is_none();
        anyhow::ensure!(
            pid > 0
                && cancelled
                && held_after_cancel
                && early_stop_refused
                && still_held
                && released
                && uncaptured_refused
                && reaped
                && owner.native_socket_custody,
            "cancelled original child/socket custody oracle failed"
        );
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_socket_custody_tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> Result<FirecrackerInstance> {
        anyhow::ensure!(
            nix::unistd::geteuid().is_root(),
            "explicit root fixture required"
        );
        let home = PathBuf::from(
            std::env::var_os("AENV_HOME_PATH").context("protected AENV_HOME_PATH required")?,
        );
        let pin = fs::symlink_metadata(&home)?;
        anyhow::ensure!(
            pin.is_dir() && pin.uid() == 0 && pin.gid() == 0 && pin.mode() & 0o7777 == 0o700,
            "protected fixture root required"
        );
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = home.join(format!(
            ".api-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // Exclusive fixture creation; failed/ambiguous cases retain this own
        // namespace. Production never acquires cleanup authority from this path.
        std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700).create(&path)?;
        let mut instance = FirecrackerInstance::new(path);
        instance.prepare_native_socket(Instant::now() + Duration::from_secs(3))?;
        Ok(instance)
    }

    #[test]
    #[ignore = "requires explicit protected root AENV_HOME_PATH; compares actual std/open64 versus nix/open on one socket"]
    fn native_api_socket_std_and_direct_o_path_comparison() -> Result<()> {
        let mut instance = fixture()?;
        let listener = UnixListener::bind(&instance.socket_path)?;
        let until = Instant::now() + Duration::from_secs(3);
        let owner = instance.native_socket.as_mut().unwrap();
        owner.dispatched = true;
        // Install actual socket custody using the candidate path first. Any
        // later comparison refusal still leaves its original FD/anchors owned.
        owner.capture(&instance.socket_path, until)?;
        let std_result = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&instance.socket_path);
        let std_errno = std_result
            .as_ref()
            .err()
            .and_then(std::io::Error::raw_os_error);
        // Results own returned FDs before any fstat. Neither branch reopens or
        // reconstructs the production owner's pin from the comparison.
        let std_held = std_result.ok();
        let direct_result = nix::fcntl::open(
            instance.socket_path.as_path(),
            nix::fcntl::OFlag::O_PATH
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        );
        let direct_errno = direct_result.as_ref().err().map(|e| *e as i32);
        let direct_held = direct_result.ok().map(fs::File::from);
        let observed = (|| -> Result<bool> {
            anyhow::ensure!(Instant::now() < until, "socket comparison deadline");
            let pin = owner
                .pin
                .as_ref()
                .context("original comparison socket pin")?;
            let direct = direct_held
                .as_ref()
                .context("direct comparison open refused")?;
            let direct_match = same_socket(pin, &direct.metadata()?);
            let std_match = match &std_held {
                Some(file) => same_socket(pin, &file.metadata()?),
                None => std_errno == Some(libc::ENXIO),
            };
            Ok(direct_match
                && std_match
                && same_socket(pin, &fs::symlink_metadata(&instance.socket_path)?))
        })();
        eprintln!("native_socket_open_comparison std_errno={:?} direct_errno={:?} flags={} direct_owned={} std_owned={}",
            std_errno, direct_errno, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            direct_held.is_some(), std_held.is_some());
        drop(listener);
        // Exact fixture socket retirement only; this is not a VMM stop proof.
        owner.retire(&instance.socket_path, until)?;
        drop(std_held);
        drop(direct_held);
        fs::remove_dir(&instance.work_dir)?;
        instance.native_socket.take();
        instance.native_socket_custody = false;
        anyhow::ensure!(observed?, "actual socket open comparison failed");
        Ok(())
    }

    #[test]
    fn native_socket_expired_preparation_has_no_admission_or_resource() -> Result<()> {
        let mut instance =
            FirecrackerInstance::new(PathBuf::from("/never-open-expired-native-parent"));
        let refused = instance
            .prepare_native_socket(Instant::now() - Duration::from_millis(1))
            .is_err();
        anyhow::ensure!(
            refused
                && instance.native_ticket.is_none()
                && instance.native_socket.is_none()
                && instance.native_spawn.is_none(),
            "expired preparation acquired resources"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires explicit protected root AENV_HOME_PATH; actual Unix socket and child"]
    async fn native_api_socket_exact_owner_retires_only_after_actual_child_wait() -> Result<()> {
        let mut instance = fixture()?;
        let listener = UnixListener::bind(&instance.socket_path).context("socket fixture bind")?;
        instance.native_socket.as_mut().unwrap().dispatched = true;
        instance.native_socket_custody = true;
        instance.native_socket.as_mut().unwrap().capture(
            &instance.socket_path,
            Instant::now() + Duration::from_secs(3),
        )?;
        instance.process = Some(
            Command::new("/bin/true")
                .spawn()
                .context("socket fixture actual child spawn")?,
        );
        let result = async {
            instance
                .wait_for_ready(Duration::from_secs(3), Duration::from_millis(1))
                .await?;
            let original = instance
                .native_socket
                .as_ref()
                .unwrap()
                .leaf
                .as_ref()
                .unwrap()
                .try_clone()
                .context("socket fixture original O_PATH clone")?;
            instance.stop_native(Duration::from_secs(3)).await?;
            anyhow::ensure!(
                instance.process.is_none()
                    && instance.native_socket.is_none()
                    && !instance.socket_path.exists()
                    && original.metadata()?.nlink() == 0,
                "exact retirement not closed"
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;
        drop(listener);
        if result.is_ok() {
            fs::remove_dir(&instance.work_dir)?;
        }
        result
    }

    #[test]
    #[ignore = "requires explicit protected root AENV_HOME_PATH; deliberately retains replacement debt"]
    fn native_api_socket_foreign_replacement_is_not_unlinked() -> Result<()> {
        let mut instance = fixture()?;
        let original = UnixListener::bind(&instance.socket_path)?;
        let socket = instance.native_socket.as_mut().unwrap();
        socket.dispatched = true;
        socket.capture(
            &instance.socket_path,
            Instant::now() + Duration::from_secs(3),
        )?;
        fs::rename(
            &instance.socket_path,
            instance.work_dir.join("original.socket"),
        )?;
        let foreign = UnixListener::bind(&instance.socket_path)?;
        let foreign_pin = fs::symlink_metadata(&instance.socket_path)?;
        let refused = socket
            .retire(
                &instance.socket_path,
                Instant::now() + Duration::from_secs(3),
            )
            .is_err();
        let unchanged = same_socket(&foreign_pin, &fs::symlink_metadata(&instance.socket_path)?);
        drop(original);
        drop(foreign);
        // Instance Drop retains original socket FD and parent anchors. Both
        // names remain as explicit fixture debt; no restoration/adoption.
        drop(instance);
        anyhow::ensure!(
            refused && unchanged,
            "replacement retirement was not refused"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires explicit protected root AENV_HOME_PATH; deliberately retains partial capture debt"]
    fn native_api_socket_partial_capture_and_uncaptured_calling_remain_debt() -> Result<()> {
        let mut instance = fixture()?;
        let path = instance.socket_path.clone();
        let socket = instance.native_socket.as_mut().unwrap();
        socket.dispatched = true;
        let absent_refused = socket
            .retire(&path, Instant::now() + Duration::from_secs(3))
            .is_err();
        // A real non-socket FD is installed before type validation fails. It
        // cannot become socket authority or authorize deletion afterwards.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let pin = file.metadata()?;
        let capture_refused = socket
            .capture(&path, Instant::now() + Duration::from_secs(3))
            .is_err();
        let retained = socket.leaf.is_some() && socket.pin.is_none();
        let retirement_refused = socket
            .retire(&path, Instant::now() + Duration::from_secs(3))
            .is_err();
        let unchanged = same_socket(&pin, &fs::symlink_metadata(&path)?);
        drop(file);
        drop(instance);
        anyhow::ensure!(
            absent_refused && capture_refused && retained && retirement_refused && unchanged,
            "partial capture lost original debt"
        );
        Ok(())
    }
}
