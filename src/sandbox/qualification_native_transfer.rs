//! Opt-in Linux SDK -> captured production broker -> production guest Engine.
//! Unix transport and real filesystem proof, never VM/VSOCK or boot proof.
use super::{
    native_download::NativeDownloadSpool,
    native_process::{NativeClient, NativeFraming, NativeUploadObservation},
    Executor,
};
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex as AsyncMutex,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema: u64,
    unit: String,
    namespace: PathBuf,
    workspace: PathBuf,
    endpoint: PathBuf,
    endpoint_sha256: String,
    broker: PathBuf,
    broker_sha256: String,
    sdk: PathBuf,
    sdk_sha256: String,
    identity: PathBuf,
    identity_sha256: String,
    chunks: u64,
    #[serde(default)]
    case: Option<QualificationCase>,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum QualificationCase {
    Metadata,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    node_id: String,
    owner_id: String,
    generation: u64,
    guest_nonce: String,
    kernel_sha256: String,
    rootfs_sha256: String,
    agent_sha256: String,
    auth_token: String,
}
type Identity = (u64, u64, u64, u32, u32, u32, i64, i64, i64, i64);
fn identity(file: &File) -> Result<Identity> {
    let m = file.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}
fn safe(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path.components().count() <= 33
        && path
            .components()
            .all(|p| matches!(p, Component::RootDir | Component::Normal(_)))
}
struct Anchor {
    file: File,
    path: PathBuf,
    id: (u64, u64),
}
struct Capture {
    file: File,
    path: PathBuf,
    original: Identity,
    anchors: Vec<Anchor>,
}
impl std::ops::Deref for Capture {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}
impl Capture {
    fn check(&self) -> Result<()> {
        for anchor in &self.anchors {
            let held = anchor.file.metadata()?;
            let named = std::fs::symlink_metadata(&anchor.path)?;
            ensure!(
                held.is_dir()
                    && named.is_dir()
                    && (held.dev(), held.ino()) == anchor.id
                    && (named.dev(), named.ino()) == anchor.id
                    && held.uid() == 0
                    && held.gid() == 0
                    && held.mode() & 0o022 == 0,
                "qualification ancestor changed"
            );
        }
        let named = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            identity(&self.file)? == self.original
                && (
                    named.dev(),
                    named.ino(),
                    named.len(),
                    named.mode(),
                    named.uid(),
                    named.gid(),
                    named.mtime(),
                    named.mtime_nsec(),
                    named.ctime(),
                    named.ctime_nsec()
                ) == self.original
                && named.nlink() == 1
                && self.file.metadata()?.nlink() == 1,
            "qualification captured file changed"
        );
        Ok(())
    }
}
fn protected(
    path: &Path,
    mode: u32,
    max: u64,
    expected: Option<&str>,
    expires: Instant,
) -> Result<Capture> {
    use nix::{
        fcntl::{open, openat, AtFlags, OFlag},
        sys::stat::{fstat, fstatat, Mode},
    };
    ensure!(safe(path), "qualification path refused");
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut parent = File::from(open("/", flags | OFlag::O_DIRECTORY, Mode::empty())?);
    let mut anchors = Vec::new();
    let mut ancestor_path = PathBuf::from("/");
    let parts: Vec<_> = path
        .components()
        .filter_map(|p| {
            if let Component::Normal(n) = p {
                Some(n)
            } else {
                None
            }
        })
        .collect();
    for name in &parts[..parts
        .len()
        .checked_sub(1)
        .context("qualification path refused")?]
    {
        let next = File::from(openat(
            &parent,
            *name,
            flags | OFlag::O_DIRECTORY,
            Mode::empty(),
        )?);
        let held = fstat(&next)?;
        let named = fstatat(&parent, *name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
        ensure!(
            held.st_uid == 0
                && held.st_gid == 0
                && held.st_mode & 0o022 == 0
                && (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
            "qualification ancestor refused"
        );
        ancestor_path.push(name);
        anchors.push(Anchor {
            file: next.try_clone()?,
            path: ancestor_path.clone(),
            id: (held.st_dev, held.st_ino),
        });
        parent = next;
    }
    let mut file = File::from(openat(
        &parent,
        *parts.last().context("qualification file refused")?,
        flags,
        Mode::empty(),
    )?);
    let m = file.metadata()?;
    let before = identity(&file)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == mode
            && m.len() <= max,
        "qualification file refused"
    );
    if let Some(expected) = expected {
        ensure!(
            expected.len() == 64
                && expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "qualification pin refused"
        );
        let mut hash = Sha256::new();
        let mut bytes = [0; 32768];
        loop {
            ensure!(Instant::now() < expires, "qualification admission deadline");
            let n = file.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            hash.update(&bytes[..n]);
        }
        ensure!(
            hash.finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                == expected,
            "qualification executable pin refused"
        );
        file.seek(SeekFrom::Start(0))?;
    }
    let named = fstatat(
        &parent,
        *parts.last().context("qualification file refused")?,
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )?;
    ensure!(
        identity(&file)? == before
            && (named.st_dev, named.st_ino) == (m.dev(), m.ino())
            && named.st_uid == 0
            && named.st_gid == 0
            && named.st_nlink == 1,
        "qualification file changed"
    );
    let capture = Capture {
        file,
        path: path.into(),
        original: before,
        anchors,
    };
    capture.check()?;
    Ok(capture)
}
struct Workspace {
    file: File,
    anchors: Vec<Anchor>,
    path: PathBuf,
    id: (u64, u64),
}
impl Workspace {
    fn capture(path: &Path) -> Result<Self> {
        use nix::{
            fcntl::{open, openat, AtFlags, OFlag},
            sys::stat::{fstat, fstatat, Mode},
        };
        ensure!(safe(path), "qualification workspace refused");
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let mut parent = File::from(open("/", flags, Mode::empty())?);
        let mut anchors = Vec::new();
        let mut named_path = PathBuf::from("/");
        let parts = path
            .components()
            .filter_map(|v| {
                if let Component::Normal(n) = v {
                    Some(n)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for (index, name) in parts.iter().enumerate() {
            let next = File::from(openat(&parent, *name, flags, Mode::empty())?);
            let held = fstat(&next)?;
            let named = fstatat(&parent, *name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
            ensure!(
                (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
                "qualification workspace named identity"
            );
            if index + 1 == parts.len() {
                ensure!(
                    held.st_uid == 1000 && held.st_gid == 1000,
                    "qualification workspace owner"
                );
            } else {
                ensure!(
                    held.st_uid == 0 && held.st_gid == 0 && held.st_mode & 0o022 == 0,
                    "qualification workspace ancestor"
                );
                named_path.push(name);
                anchors.push(Anchor {
                    file: next.try_clone()?,
                    path: named_path.clone(),
                    id: (held.st_dev, held.st_ino),
                });
            }
            parent = next;
        }
        let m = parent.metadata()?;
        let workspace = Self {
            file: parent,
            anchors,
            path: path.into(),
            id: (m.dev(), m.ino()),
        };
        workspace.check()?;
        Ok(workspace)
    }
    fn check(&self) -> Result<()> {
        for anchor in &self.anchors {
            let held = anchor.file.metadata()?;
            let named = std::fs::symlink_metadata(&anchor.path)?;
            ensure!(
                held.is_dir()
                    && named.is_dir()
                    && (held.dev(), held.ino()) == anchor.id
                    && (named.dev(), named.ino()) == anchor.id
                    && held.uid() == 0
                    && held.gid() == 0
                    && held.mode() & 0o022 == 0,
                "qualification workspace ancestor changed"
            );
        }
        let held = self.file.metadata()?;
        let named = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            held.is_dir()
                && named.is_dir()
                && (held.dev(), held.ino()) == self.id
                && (named.dev(), named.ino()) == self.id
                && held.uid() == 1000
                && held.gid() == 1000,
            "qualification workspace changed"
        );
        Ok(())
    }
}
struct SourcePin {
    workspace: File,
    parent: File,
    nested: File,
    file: File,
    ids: [(u64, u64); 4],
}
impl SourcePin {
    fn capture(workspace: &Workspace, size: u64, sha: &str, expires: Instant) -> Result<Self> {
        use nix::{
            fcntl::{openat, OFlag},
            sys::stat::Mode,
        };
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        workspace.check()?;
        let workspace = workspace.file.try_clone()?;
        let parent = File::from(openat(
            &workspace,
            "sdk-transfer",
            flags | OFlag::O_DIRECTORY,
            Mode::empty(),
        )?);
        let nested = File::from(openat(
            &parent,
            "nested",
            flags | OFlag::O_DIRECTORY,
            Mode::empty(),
        )?);
        let file = File::from(openat(
            &nested,
            "data",
            (flags & !OFlag::O_RDONLY) | OFlag::O_RDWR | OFlag::O_NONBLOCK,
            Mode::empty(),
        )?);
        let ids = [&workspace, &parent, &nested, &file]
            .map(|f| f.metadata().map(|m| (m.dev(), m.ino())))
            .into_iter()
            .collect::<std::io::Result<Vec<_>>>()?;
        let pin = Self {
            workspace,
            parent,
            nested,
            file,
            ids: ids
                .try_into()
                .map_err(|_| anyhow::anyhow!("qualification source identity"))?,
        };
        pin.check()?;
        ensure!(
            pin.file.metadata()?.len() == size && hash_file(&pin.file, size, expires)? == sha,
            "qualification physical upload differs"
        );
        Ok(pin)
    }
    fn check(&self) -> Result<()> {
        use nix::{fcntl::AtFlags, sys::stat::fstatat};
        for (index, file) in [&self.workspace, &self.parent, &self.nested, &self.file]
            .iter()
            .enumerate()
        {
            let m = file.metadata()?;
            ensure!(
                (m.dev(), m.ino()) == self.ids[index] && m.uid() == 1000 && m.gid() == 1000,
                "qualification source held identity"
            );
            if index == 3 {
                ensure!(
                    m.is_file() && m.nlink() == 1 && m.mode() & 0o7777 == 0o600,
                    "qualification source mode"
                );
            } else {
                ensure!(
                    m.is_dir() && (index == 0 || m.mode() & 0o7777 == 0o700),
                    "qualification source directory"
                );
            }
        }
        for (index, (parent, name)) in [
            (&self.workspace, "sdk-transfer"),
            (&self.parent, "nested"),
            (&self.nested, "data"),
        ]
        .iter()
        .enumerate()
        {
            let named = fstatat(*parent, *name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
            ensure!(
                (named.st_dev, named.st_ino) == self.ids[index + 1],
                "qualification source named identity"
            );
        }
        Ok(())
    }
    fn cleanup(&self) -> Result<()> {
        use nix::unistd::{unlinkat, UnlinkatFlags};
        self.check()?;
        unlinkat(&self.nested, "data", UnlinkatFlags::NoRemoveDir)?;
        unlinkat(&self.parent, "nested", UnlinkatFlags::RemoveDir)?;
        unlinkat(&self.workspace, "sdk-transfer", UnlinkatFlags::RemoveDir)?;
        Ok(())
    }
}
fn hash_file(file: &File, size: u64, expires: Instant) -> Result<String> {
    let before = identity(file)?;
    ensure!(
        size <= 32 * 1024 * 1024 && file.metadata()?.len() == size,
        "qualification physical size"
    );
    let mut offset = 0;
    let mut bytes = [0; 16384];
    let mut hash = Sha256::new();
    while offset < size {
        ensure!(
            Instant::now() < expires,
            "qualification physical hash deadline"
        );
        ensure!(
            identity(file)? == before,
            "qualification physical version drift"
        );
        let limit = (size - offset).min(bytes.len() as u64) as usize;
        let n = file.read_at(&mut bytes[..limit], offset)?;
        ensure!(n > 0, "qualification physical EOF");
        hash.update(&bytes[..n]);
        offset += n as u64;
    }
    ensure!(
        file.read_at(&mut bytes[..1], size)? == 0 && identity(file)? == before,
        "qualification physical changed"
    );
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}
fn pattern(sequence: u64, chunks: u64) -> Vec<u8> {
    let mut bytes = (0..16384)
        .map(|offset| ((offset + sequence as usize * 17) % 256) as u8)
        .collect::<Vec<_>>();
    if chunks == 2048 {
        bytes[..4].copy_from_slice(&(sequence as u32).to_le_bytes());
    }
    bytes
}
struct SocketPin {
    directory: File,
    held: File,
    id: (u64, u64),
}
impl SocketPin {
    fn capture(directory: &File, expected: (u64, u64)) -> Result<Self> {
        use nix::{
            fcntl::{openat, AtFlags, OFlag},
            sys::stat::{fstatat, Mode, SFlag},
        };
        let held = File::from(openat(
            directory,
            "native-guest.vsock",
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let info = held.metadata()?;
        let named = fstatat(
            directory,
            "native-guest.vsock",
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            (info.dev(), info.ino()) == expected
                && (named.st_dev, named.st_ino) == expected
                && info.uid() == 0
                && info.gid() == 0
                && info.nlink() == 1
                && SFlag::from_bits_truncate(info.mode()) == SFlag::S_IFSOCK,
            "qualification socket capture refused"
        );
        Ok(Self {
            directory: directory.try_clone()?,
            held,
            id: expected,
        })
    }
    fn cleanup(&self) -> Result<()> {
        use nix::{
            errno::Errno,
            fcntl::AtFlags,
            sys::stat::fstatat,
            unistd::{unlinkat, UnlinkatFlags},
        };
        let held = self.held.metadata()?;
        ensure!(
            (held.dev(), held.ino()) == self.id,
            "qualification socket held changed"
        );
        match fstatat(
            &self.directory,
            "native-guest.vsock",
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(named) => {
                ensure!(
                    (named.st_dev, named.st_ino) == self.id
                        && named.st_uid == 0
                        && named.st_gid == 0,
                    "qualification foreign socket retained"
                );
                unlinkat(
                    &self.directory,
                    "native-guest.vsock",
                    UnlinkatFlags::NoRemoveDir,
                )?;
            }
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(e.into()),
        }
        match fstatat(
            &self.directory,
            "native-guest.vsock",
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(Errno::ENOENT) => Ok(()),
            _ => bail!("qualification socket absence not verified"),
        }
    }
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum DiagnosticPhase {
    Entry,
    Descriptor,
    Namespace,
    EndpointPin,
    SdkPin,
    BrokerPin,
    Credential,
    Binding,
    Workspace,
    Scope,
    ParentProcess,
    BootstrapMembership,
    Listener,
    Control,
    BrokerAccept,
    BrokerProcess,
    BrokerMembership,
    Connect,
    EngineCreate,
    RuntimeGuard,
    EngineStep,
    EngineClose,
    SocketCleanup,
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum DiagnosticCode {
    Platform,
    Identity,
    Exists,
    Io,
    Bounds,
    Populated,
    Unavailable,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnostic {
    kind: String,
    phase: DiagnosticPhase,
    code: DiagnosticCode,
}
fn report_diagnostic(raw: &[u8]) -> bool {
    if let Ok(message) = serde_json::from_slice::<Diagnostic>(raw) {
        if message.kind == "fixture_error" {
            eprintln!(
                "native SDK endpoint refusal phase={:?} code={:?}",
                message.phase, message.code
            );
            return true;
        }
    }
    false
}
fn report_exit(role: &str, status: std::process::ExitStatus) {
    use std::os::unix::process::ExitStatusExt;
    eprintln!(
        "native SDK child actual_wait role={role} exit_code={:?} signal={:?}",
        status.code(),
        status.signal()
    );
}
#[derive(Default)]
struct Owner {
    endpoint: Option<Child>,
    broker: Option<Child>,
    client: Option<Arc<NativeClient>>,
    spool: Option<Arc<NativeDownloadSpool>>,
    pins: Vec<Capture>,
    source: Option<SourcePin>,
    metadata_tree: Option<MetadataTree>,
    http_orchestrator: Option<Arc<crate::orchestrator::Orchestrator>>,
    http_sandbox: Option<crate::types::SandboxId>,
    metadata_stage: Option<&'static str>,
    http_reply_diagnostic: Option<(u16, &'static str, &'static str, Option<bool>)>,
    metadata_page_count: usize,
    metadata_entry_count: usize,
    workspace: PathBuf,
    workspace_pin: Option<Workspace>,
    source_may_exist: bool,
    endpoint_control: Option<ChildStdin>,
    endpoint_output: Option<BufReader<ChildStdout>>,
    endpoint_exit: Option<std::process::ExitStatus>,
    broker_exit: Option<std::process::ExitStatus>,
    socket_directory: Option<File>,
    socket: Option<SocketPin>,
    socket_may_exist: bool,
}
static OWNER: Mutex<Option<Arc<AsyncMutex<Owner>>>> = Mutex::new(None);
async fn reap(
    child: &mut Option<Child>,
    exit: &mut Option<std::process::ExitStatus>,
    role: &str,
    until: Instant,
) -> Result<()> {
    if let Some(held) = child.as_mut() {
        let _ = held.start_kill();
        let status = tokio::time::timeout_at(tokio::time::Instant::from_std(until), held.wait())
            .await
            .context("qualification child wait deadline")??;
        report_exit(role, status);
        *exit = Some(status);
        child.take();
    }
    Ok(())
}
async fn retire(owner: &mut Owner) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(10);
    let mut failure = None;
    if owner
        .metadata_tree
        .as_ref()
        .is_some_and(|t| !t.pending.is_empty())
    {
        if let Err(e) = metadata_pending_witnesses(owner, until).await {
            failure = Some(e);
        }
    }
    if let Some(orchestrator) = &owner.http_orchestrator {
        let result = async {
            if let Some(id) = owner.http_sandbox {
                orchestrator.delete_sandbox(id).await?;
            }
            orchestrator.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        if let Err(error) = tokio::time::timeout_at(tokio::time::Instant::from_std(until), result)
            .await
            .context("qualification HTTP orchestrator retirement deadline")
            .and_then(|r| r)
        {
            failure = Some(error);
        } else {
            owner.http_orchestrator.take();
            owner.http_sandbox.take();
        }
    }
    if let Some(endpoint) = owner.endpoint.as_mut() {
        let shutdown = async {
            let control = owner
                .endpoint_control
                .as_mut()
                .context("qualification endpoint stop control unavailable")?;
            control.write_all(b"{\"kind\":\"fixture_stop\"}\n").await?;
            control.flush().await?;
            let status = endpoint.wait().await?;
            report_exit("endpoint", status);
            owner.endpoint_exit = Some(status);
            ensure!(
                status.success(),
                "qualification Engine cleanup not authenticated by clean endpoint exit"
            );
            Ok::<_, anyhow::Error>(())
        };
        let stopped = tokio::time::timeout_at(tokio::time::Instant::from_std(until), shutdown)
            .await
            .context("qualification endpoint graceful wait deadline")
            .and_then(|r| r);
        if let Err(e) = stopped {
            failure = Some(e);
        } else {
            owner.endpoint.take();
        }
    }
    if let Err(e) = reap(&mut owner.broker, &mut owner.broker_exit, "broker", until).await {
        failure = Some(e);
    }
    if owner.broker.is_none() {
        if let Some(client) = &owner.client {
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(until),
                client.retire_downloads(),
            )
            .await
            .context("qualification spool cleanup deadline")
            .and_then(|r| r);
            if let Err(e) = result {
                failure.get_or_insert(e);
            }
        }
    }
    if let Err(e) = reap(
        &mut owner.endpoint,
        &mut owner.endpoint_exit,
        "endpoint",
        until,
    )
    .await
    {
        failure.get_or_insert(e);
    }
    if owner.endpoint.is_none() {
        if let Some(output) = owner.endpoint_output.as_mut() {
            if let Ok(raw) = line(output, until).await {
                let _ = report_diagnostic(&raw);
            }
        }
        owner.endpoint_output.take();
        let socket_cleanup = (|| -> Result<()> {
            for pin in &owner.pins {
                pin.check()?;
            }
            if let Some(socket) = &owner.socket {
                socket.cleanup()?;
            } else if owner.socket_may_exist {
                use nix::{errno::Errno, fcntl::AtFlags, sys::stat::fstatat};
                let directory = owner
                    .socket_directory
                    .as_ref()
                    .context("qualification socket namespace custody")?;
                ensure!(
                    matches!(
                        fstatat(
                            directory,
                            "native-guest.vsock",
                            AtFlags::AT_SYMLINK_NOFOLLOW
                        ),
                        Err(Errno::ENOENT)
                    ),
                    "qualification uncaptured socket cleanup debt"
                );
            }
            Ok(())
        })();
        if let Err(e) = socket_cleanup {
            failure.get_or_insert(e);
        } else {
            owner.socket.take();
            owner.socket_may_exist = false;
            owner.endpoint_control.take();
        }
    }
    if owner.broker.is_none() && owner.endpoint.is_none() {
        if let Some(source) = &owner.source {
            if let Err(e) = owner
                .workspace_pin
                .as_ref()
                .context("qualification workspace custody")
                .and_then(Workspace::check)
                .and_then(|_| source.cleanup())
            {
                failure.get_or_insert(e);
            } else {
                owner.source.take();
                owner.source_may_exist = false;
            }
        } else if owner.source_may_exist
            && owner
                .workspace
                .join("sdk-transfer")
                .symlink_metadata()
                .is_ok()
        {
            failure.get_or_insert(anyhow::anyhow!(
                "qualification partial source cleanup custody retained"
            ));
        }
    }
    if let Some(tree) = &owner.metadata_tree {
        if owner.endpoint.is_none()
            && owner.broker.is_none()
            && owner.endpoint_exit.is_some_and(|s| s.success())
        {
            if let Err(e) = tree.cleanup() {
                failure.get_or_insert(e);
            } else {
                owner.metadata_tree.take();
            }
        } else {
            failure.get_or_insert(anyhow::anyhow!("qualification metadata child cleanup debt"));
        }
    }
    if let Some(e) = failure {
        return Err(e);
    }
    owner.client.take();
    owner.spool.take();
    owner.pins.clear();
    owner.workspace_pin.take();
    owner.socket_directory.take();
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listening {
    kind: String,
    monotonic_ns: u64,
    socket_dev: u64,
    socket_ino: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    kind: String,
}
async fn line(reader: &mut BufReader<ChildStdout>, until: Instant) -> Result<Vec<u8>> {
    line_bounded(reader, until, 512).await
}
async fn line_bounded(
    reader: &mut BufReader<ChildStdout>,
    until: Instant,
    max: usize,
) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    tokio::time::timeout_at(tokio::time::Instant::from_std(until), async {
        loop {
            let available = reader.fill_buf().await?;
            ensure!(!available.is_empty(), "qualification child output EOF");
            let n = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            ensure!(line.len() + n <= max, "qualification child output bounds");
            line.extend_from_slice(&available[..n]);
            reader.consume(n);
            if line.last() == Some(&b'\n') {
                line.pop();
                return Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await
    .context("qualification child output deadline")??;
    Ok(line)
}
pub(super) fn fd_count() -> Result<usize> {
    Ok(std::fs::read_dir("/proc/self/fd")?.count())
}
async fn body(
    owner: &mut Owner,
    d: &Descriptor,
    credential: &Credential,
    expires: Instant,
    http: bool,
) -> Result<()> {
    for pin in &owner.pins {
        pin.check()?;
    }
    owner
        .workspace_pin
        .as_ref()
        .context("qualification workspace custody")?
        .check()?;
    let endpoint = owner.pins[1].as_raw_fd();
    let broker = owner.pins[2].as_raw_fd();
    let mut command = Command::new(format!("/proc/self/fd/{endpoint}"));
    command
        .arg("--qualify-sdk-endpoint")
        .arg(
            std::env::var_os("AENV_NATIVE_TRANSFER_DESCRIPTOR")
                .context("explicit descriptor required")?,
        )
        .arg(std::process::id().to_string())
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    owner.socket_may_exist = true;
    owner.endpoint = Some(command.spawn().context("qualification endpoint spawn")?);
    let endpoint_pid = owner
        .endpoint
        .as_ref()
        .and_then(Child::id)
        .context("qualification endpoint PID")?;
    owner.endpoint_control = Some(
        owner
            .endpoint
            .as_mut()
            .and_then(|c| c.stdin.take())
            .context("qualification endpoint control")?,
    );
    owner.endpoint_output = Some(BufReader::new(
        owner
            .endpoint
            .as_mut()
            .and_then(|c| c.stdout.take())
            .context("qualification endpoint metadata")?,
    ));
    let metadata_raw = line(
        owner
            .endpoint_output
            .as_mut()
            .context("qualification endpoint metadata custody")?,
        expires.min(Instant::now() + Duration::from_secs(15)),
    )
    .await
    .context("qualification phase endpoint_listening")?;
    ensure!(
        !report_diagnostic(&metadata_raw),
        "qualification endpoint_listening explicitly refused"
    );
    let listening: Listening =
        serde_json::from_slice(&metadata_raw).context("qualification endpoint_listening schema")?;
    ensure!(
        listening.kind == "fixture_listening",
        "qualification endpoint refused"
    );
    owner.socket = Some(SocketPin::capture(
        owner
            .socket_directory
            .as_ref()
            .context("qualification socket namespace")?,
        (listening.socket_dev, listening.socket_ino),
    )?);
    let remaining = expires
        .checked_duration_since(Instant::now())
        .context("qualification fixed deadline")?;
    let deadline_ns = listening
        .monotonic_ns
        .checked_add(u64::try_from(remaining.as_nanos())?)
        .context("qualification clock bounds")?;
    let control = owner
        .endpoint_control
        .as_mut()
        .context("qualification endpoint control custody")?;
    control
        .write_all(
            format!(
                "{}\n",
                serde_json::json!({"kind":"fixture_deadline","deadline_ns":deadline_ns})
            )
            .as_bytes(),
        )
        .await?;
    control.flush().await?;
    let socket = d.namespace.join("native-guest.vsock");
    let mut command = Command::new(format!("/proc/self/fd/{broker}"));
    command
        .arg("--broker")
        .arg("--boot-budget-ms")
        .arg("3000")
        .arg("--identity")
        .arg(&d.identity)
        .arg("--socket")
        .arg(&socket)
        .arg("--peer-pid")
        .arg(endpoint_pid.to_string())
        .arg("--peer-uid")
        .arg("0")
        .arg("--node-id")
        .arg(&credential.node_id)
        .arg("--owner-id")
        .arg(&credential.owner_id)
        .arg("--generation")
        .arg(credential.generation.to_string())
        .arg("--guest-nonce")
        .arg(&credential.guest_nonce)
        .arg("--kernel-sha256")
        .arg(&credential.kernel_sha256)
        .arg("--rootfs-sha256")
        .arg(&credential.rootfs_sha256)
        .arg("--agent-sha256")
        .arg(&credential.agent_sha256)
        .arg("--budget-ms")
        .arg(
            expires
                .checked_duration_since(Instant::now())
                .context("qualification fixed deadline")?
                .as_millis()
                .min(240000)
                .to_string(),
        )
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    owner.broker = Some(command.spawn().context("qualification broker spawn")?);
    let input = owner
        .broker
        .as_mut()
        .and_then(|c| c.stdin.take())
        .context("qualification broker stdin")?;
    let output = owner
        .broker
        .as_mut()
        .and_then(|c| c.stdout.take())
        .context("qualification broker stdout")?;
    let mut output = BufReader::new(output);
    let ready: Ready = serde_json::from_slice(
        &line(
            &mut output,
            expires.min(Instant::now() + Duration::from_secs(3)),
        )
        .await
        .context("qualification phase broker_authenticated_ready")?,
    )?;
    ensure!(
        ready.kind == "ready",
        "qualification authenticated READY refused"
    );
    let spool = NativeDownloadSpool::admit(&d.namespace)
        .map_err(|_| anyhow::anyhow!("qualification protected spool unavailable"))?;
    owner.spool = Some(spool.clone());
    let framing = NativeFraming::new(
        &credential.node_id,
        &credential.owner_id,
        credential.generation,
        &credential.guest_nonce,
    )?;
    let client = NativeClient::install_with_downloads(output, input, expires, framing, Some(spool));
    owner.client = Some(client.clone());
    let executor = Executor::native(client);
    if d.case == Some(QualificationCase::Metadata) {
        return if http {
            metadata_http_body(owner, &d.namespace, expires).await
        } else {
            metadata_body(owner, &executor, expires).await
        };
    }
    let mut whole = Sha256::new();
    for sequence in 0..d.chunks {
        ensure!(Instant::now() < expires, "qualification hash deadline");
        whole.update(pattern(sequence, d.chunks));
    }
    let sha = whole
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let size = d.chunks * 16384;
    owner.source_may_exist = true;
    let upload = executor.start_native_upload("sdk-transfer/nested/data", size, &sha, true)?;
    let upload_id = upload.identity().clone();
    ensure!(
        upload.wait_ready().await?.next_sequence == 0,
        "qualification upload initial prefix"
    );
    for sequence in 0..d.chunks {
        for pin in &owner.pins {
            pin.check()?;
        }
        ensure!(Instant::now() < expires, "qualification upload deadline");
        let receipt = upload.write_chunk(&pattern(sequence, d.chunks)).await?;
        ensure!(
            receipt.next_sequence == sequence + 1
                && receipt.received == (sequence + 1) * 16384
                && receipt.identity.operation_id == upload_id.operation_id
                && receipt.identity.session_id == upload_id.session_id,
            "qualification upload original prefix"
        );
    }
    for pin in &owner.pins {
        pin.check()?;
    }
    let receipt = upload.commit().await?;
    ensure!(
        receipt.size == size
            && receipt.sha256 == sha
            && receipt.identity.operation_id == upload_id.operation_id,
        "qualification upload final receipt"
    );
    owner.source = Some(SourcePin::capture(
        owner
            .workspace_pin
            .as_ref()
            .context("qualification workspace custody")?,
        size,
        &sha,
        expires,
    )?);
    let download = executor
        .start_native_download("sdk-transfer/nested/data", size)
        .await?;
    let download_id = download.identity().clone();
    let result = download.receive().await?;
    ensure!(
        result.size == size
            && result.sha256 == sha
            && result.identity.operation_id == download_id.operation_id,
        "qualification download final receipt"
    );
    let mut read = result.open_read()?;
    let mut buffer = [0; 16384];
    for sequence in 0..d.chunks {
        ensure!(Instant::now() < expires, "qualification read deadline");
        read.read_exact(&mut buffer)?;
        ensure!(
            buffer.as_slice() == pattern(sequence, d.chunks),
            "qualification published bytes differ"
        );
    }
    ensure!(
        read.read(&mut buffer[..1])? == 0,
        "qualification published EOF"
    );
    drop(read);
    let source = owner
        .source
        .as_ref()
        .context("qualification source custody")?;
    source.check()?;
    let mut original = [0];
    ensure!(
        source.file.read_at(&mut original, 0)? == 1,
        "qualification source read"
    );
    source.file.write_at(&[original[0] ^ 0xff], 0)?;
    source.file.sync_data()?;
    match upload.query().await? {
        NativeUploadObservation::Complete(old) => ensure!(
            old.sha256 == sha && old.identity.operation_id == upload_id.operation_id,
            "qualification original upload query"
        ),
        NativeUploadObservation::Progress(_) => {
            bail!("qualification upload query lost final receipt")
        }
    };
    let cached = download.query_result().await?;
    ensure!(
        cached.sha256 == sha && cached.identity.operation_id == download_id.operation_id,
        "qualification original download query"
    );
    let mut changed = [0];
    source.file.read_at(&mut changed, 0)?;
    ensure!(
        changed[0] == (original[0] ^ 0xff),
        "qualification query replayed a mutation"
    );
    let mut held = cached.open_read()?;
    held.read_exact(&mut changed)?;
    ensure!(changed == original, "qualification cached spool changed");
    drop(held);
    println!("native SDK real Unix files: chunks={} upload_original_query=true download_original_query=true physical_sha=true controlled_tamper_cached=true no_vm_claim=true",d.chunks);
    Ok(())
}
async fn run(http: bool) -> Result<()> {
    ensure!(
        nix::unistd::geteuid().as_raw() == 0 && nix::unistd::getegid().as_raw() == 0,
        "qualification requires Linux root"
    );
    let path = PathBuf::from(
        std::env::var_os("AENV_NATIVE_TRANSFER_DESCRIPTOR")
            .context("explicit protected transfer descriptor required")?,
    );
    let entered = Instant::now();
    let mut expires = entered + Duration::from_secs(240);
    let baseline = fd_count()?;
    let mut descriptor = protected(&path, 0o600, 16384, None, expires)?;
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut descriptor.file)
        .take(16385)
        .read_to_end(&mut raw)?;
    let d: Descriptor = serde_json::from_slice(&raw)?;
    ensure!(
        !http || d.case == Some(QualificationCase::Metadata),
        "qualification HTTP requires metadata case"
    );
    if d.case == Some(QualificationCase::Metadata) {
        expires = entered + Duration::from_secs(30);
    }
    ensure!(
        d.unit
            .strip_prefix("codex-guest-416-")
            .and_then(|v| v.strip_suffix(".service"))
            .is_some_and(|v| v.len() == 32
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && d.schema == 1
            && matches!(d.chunks, 33 | 2048)
            && safe(&d.namespace)
            && path.parent() == Some(d.namespace.as_path())
            && d.identity.parent() == Some(d.namespace.as_path()),
        "qualification descriptor refused"
    );
    let home = PathBuf::from(
        std::env::var_os("AENV_HOME_PATH").context("owned qualification home required")?,
    );
    ensure!(
        d.namespace == home,
        "qualification namespace must be actual owned home"
    );
    let namespace = std::fs::symlink_metadata(&d.namespace)?;
    ensure!(
        namespace.is_dir()
            && namespace.uid() == 0
            && namespace.gid() == 0
            && namespace.mode() & 0o7777 == 0o700,
        "qualification namespace refused"
    );
    let until = expires.min(Instant::now() + Duration::from_secs(15));
    let endpoint = protected(
        &d.endpoint,
        0o755,
        64 * 1024 * 1024,
        Some(&d.endpoint_sha256),
        until,
    )?;
    let broker = protected(
        &d.broker,
        0o755,
        64 * 1024 * 1024,
        Some(&d.broker_sha256),
        until,
    )?;
    let sdk = protected(&d.sdk, 0o755, 512 * 1024 * 1024, Some(&d.sdk_sha256), until)?;
    ensure!(
        identity(&File::open("/proc/self/exe")?)? == identity(&sdk)?,
        "qualification actual SDK executable differs"
    );
    let mut identity_file = protected(&d.identity, 0o600, 8192, Some(&d.identity_sha256), until)?;
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut identity_file.file)
        .take(8193)
        .read_to_end(&mut raw)?;
    let credential: Credential = serde_json::from_slice(&raw)?;
    ensure!(
        credential.agent_sha256 == d.endpoint_sha256 && credential.auth_token.len() == 64,
        "qualification identity binding refused"
    );
    ensure!(
        !d.workspace.join("sdk-transfer").try_exists()?
            && !d.workspace.join("sdk-metadata").try_exists()?
            && !d.namespace.join("native-guest.vsock").try_exists()?
            && !d.namespace.join("native-downloads").try_exists()?,
        "qualification fresh namespace required"
    );
    let socket_directory = descriptor
        .anchors
        .last()
        .context("qualification namespace anchor")?
        .file
        .try_clone()?;
    let owner = Arc::new(AsyncMutex::new(Owner {
        socket_directory: Some(socket_directory),
        workspace_pin: Some(Workspace::capture(&d.workspace)?),
        workspace: d.workspace.clone(),
        pins: vec![descriptor, endpoint, broker, sdk, identity_file],
        ..Owner::default()
    }));
    {
        let mut registry = OWNER.lock().expect("qualification custody");
        ensure!(registry.is_none(), "qualification previous owner retained");
        *registry = Some(owner.clone());
    }
    let mut held = owner.lock().await;
    let outcome = tokio::time::timeout_at(
        tokio::time::Instant::from_std(expires),
        body(&mut held, &d, &credential, expires, http),
    )
    .await
    .context("qualification fixed incarnation deadline")
    .and_then(|r| r);
    let metadata_diagnostic = (
        held.metadata_stage,
        held.metadata_page_count,
        held.metadata_entry_count,
    );
    let http_reply_diagnostic = held.http_reply_diagnostic;
    let cleanup = retire(&mut held).await;
    if outcome.is_err() && d.case == Some(QualificationCase::Metadata) {
        eprintln!(
            "native SDK metadata diagnostic: stage={} pages={} entries={} cleanup_ok={}",
            metadata_diagnostic.0.unwrap_or("before_metadata"),
            metadata_diagnostic.1,
            metadata_diagnostic.2,
            cleanup.is_ok()
        );
    }
    if outcome.is_err() && http {
        if let Some((status, kind, result_kind, complete)) = http_reply_diagnostic {
            eprintln!("native HTTP reply diagnostic: status={status} kind={kind} result_kind={result_kind} complete={complete:?}");
        }
    }
    drop(held);
    if cleanup.is_ok() {
        *OWNER.lock().expect("qualification custody") = None;
    } else {
        eprintln!("native SDK qualifier retained cleanup debt");
    }
    outcome?;
    cleanup?;
    drop(owner);
    let until = Instant::now() + Duration::from_secs(3);
    while fd_count()? != baseline {
        ensure!(Instant::now() < until, "qualification SDK descriptor drift");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    if d.case == Some(QualificationCase::Metadata) {
        if http {
            println!("native keyed HTTP real Unix metadata: entries=70 original_retry=true cached_pages=true auth_epoch_refusal=true nonboundary_refusal=true lifecycle_gate=true cleanup=true lifecycle_adapter=true no_durable_persistence_claim=true no_vm_claim=true");
        } else {
            println!("native SDK real Unix metadata: entries=70 cached_original_pages=true original_lost_mkdir_query=true partial_unknown=true cleanup=true no_vm_claim=true");
        }
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires explicit protected AENV_NATIVE_TRANSFER_DESCRIPTOR, owned delegated Linux unit and pinned actual guest binaries"]
async fn native_sdk_production_broker_engine_real_file_transfer() -> Result<()> {
    static JOB: AsyncMutex<Option<tokio::task::JoinHandle<Result<()>>>> =
        AsyncMutex::const_new(None);
    let mut job = JOB.lock().await;
    ensure!(job.is_none(), "qualification task already retained");
    *job = Some(tokio::spawn(run(false)));
    let result = job
        .as_mut()
        .expect("registered qualification task")
        .await
        .context("qualification retained task join")?;
    job.take();
    result
}

// One independent test-directory owner, registered before mkdir. Failed opens or
// foreign replacements retain this bounded debt instead of unlinking by name.
struct SocketDirectoryDebt {
    capture: Capture,
    parent: File,
    held: Option<File>,
    original: Option<(u64, u64)>,
    created: bool,
}
impl SocketDirectoryDebt {
    fn create(&mut self) -> Result<()> {
        use nix::{
            fcntl::{openat, AtFlags, OFlag},
            sys::stat::{fstatat, mkdirat, Mode},
        };
        self.capture.check()?;
        mkdirat(&self.parent, "sg", Mode::S_IRWXU)?;
        self.created = true;
        let created = fstatat(&self.parent, "sg", AtFlags::AT_SYMLINK_NOFOLLOW)?;
        self.original = Some((created.st_dev, created.st_ino));
        let held = File::from(openat(
            &self.parent,
            "sg",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = held.metadata()?;
        ensure!(
            (metadata.dev(), metadata.ino())
                == self
                    .original
                    .context("qualification directory creation identity")?
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o700,
            "qualification directory capture refused"
        );
        self.held = Some(held);
        Ok(())
    }
    fn cleanup(&self) -> Result<()> {
        use nix::{
            errno::Errno,
            fcntl::AtFlags,
            sys::stat::fstatat,
            unistd::{unlinkat, UnlinkatFlags},
        };
        if !self.created {
            return Ok(());
        }
        self.capture.check()?;
        let held = self
            .held
            .as_ref()
            .context("qualification uncaptured directory debt")?
            .metadata()?;
        let id = self
            .original
            .context("qualification uncaptured directory identity")?;
        let named = fstatat(&self.parent, "sg", AtFlags::AT_SYMLINK_NOFOLLOW)?;
        ensure!(
            held.is_dir()
                && (held.dev(), held.ino()) == id
                && (named.st_dev, named.st_ino) == id
                && held.uid() == 0
                && held.gid() == 0
                && held.mode() & 0o7777 == 0o700
                && named.st_uid == 0
                && named.st_gid == 0,
            "qualification foreign directory cleanup refused"
        );
        // rmdir only succeeds when the exact owned directory is empty.
        unlinkat(&self.parent, "sg", UnlinkatFlags::RemoveDir)?;
        ensure!(
            matches!(
                fstatat(&self.parent, "sg", AtFlags::AT_SYMLINK_NOFOLLOW),
                Err(Errno::ENOENT)
            ),
            "qualification directory absence unverified"
        );
        Ok(())
    }
}
#[tokio::test]
#[ignore = "requires explicit protected descriptor in the actual owned Linux root namespace"]
async fn native_sdk_socket_guard_refuses_replacement_without_unlinking_foreign() -> Result<()> {
    use std::os::unix::net::UnixListener;
    ensure!(
        nix::unistd::geteuid().as_raw() == 0,
        "qualification requires actual root"
    );
    let descriptor = PathBuf::from(
        std::env::var_os("AENV_NATIVE_TRANSFER_DESCRIPTOR")
            .context("explicit protected descriptor required")?,
    );
    let capture = protected(
        &descriptor,
        0o600,
        16384,
        None,
        Instant::now() + Duration::from_secs(3),
    )?;
    let home = PathBuf::from(std::env::var_os("AENV_HOME_PATH").context("owned home required")?);
    ensure!(
        descriptor.parent() == Some(home.as_path()),
        "qualification owned namespace mismatch"
    );
    capture.check()?;
    let metadata = std::fs::symlink_metadata(&home)?;
    ensure!(
        metadata.uid() == 0 && metadata.gid() == 0 && metadata.mode() & 0o7777 == 0o700,
        "qualification root namespace refused"
    );
    let socket = home.join("sg/native-guest.vsock");
    ensure!(
        socket.as_os_str().len() < 108,
        "qualification Unix socket path bounds"
    );
    let parent = capture
        .anchors
        .last()
        .context("qualification namespace anchor")?
        .file
        .try_clone()?;
    static DIRECTORY: Mutex<Option<SocketDirectoryDebt>> = Mutex::new(None);
    let mut registry = DIRECTORY.lock().expect("qualification directory debt");
    ensure!(
        registry.is_none(),
        "qualification prior directory debt retained"
    );
    *registry = Some(SocketDirectoryDebt {
        capture,
        parent,
        held: None,
        original: None,
        created: false,
    });
    let outcome = (|| -> Result<()> {
        let debt = registry.as_mut().expect("registered directory debt");
        debt.create()?;
        let held = debt
            .held
            .as_ref()
            .context("qualification directory custody")?;
        let original = UnixListener::bind(&socket)?;
        let m = std::fs::symlink_metadata(&socket)?;
        let original_pin = SocketPin::capture(held, (m.dev(), m.ino()))?;
        // Only the captured original name is removed to install our second owner.
        original_pin.cleanup()?;
        let replacement = UnixListener::bind(&socket)?;
        let m = std::fs::symlink_metadata(&socket)?;
        let replacement_pin = SocketPin::capture(held, (m.dev(), m.ino()))?;
        let refused = original_pin.cleanup().is_err();
        let still_foreign = std::fs::symlink_metadata(&socket)
            .is_ok_and(|named| (named.dev(), named.ino()) == replacement_pin.id);
        drop(original);
        drop(replacement);
        replacement_pin.cleanup()?;
        ensure!(
            refused && still_foreign,
            "qualification cleanup adopted replacement socket"
        );
        Ok(())
    })();
    let cleanup = registry
        .as_ref()
        .expect("retained directory owner")
        .cleanup();
    if cleanup.is_ok() {
        registry.take();
    }
    outcome?;
    cleanup?;
    Ok(())
}

#[test]
fn native_sdk_endpoint_diagnostic_refuses_unrecognized_or_extra_fields() {
    assert!(report_diagnostic(
        br#"{"kind":"fixture_error","phase":"bootstrap_membership","code":"identity"}"#
    ));
    assert!(!report_diagnostic(
        br#"{"kind":"fixture_error","phase":"credential_contents","code":"identity"}"#
    ));
    assert!(!report_diagnostic(
        br#"{"kind":"fixture_error","phase":"binding","code":"secret"}"#
    ));
    assert!(!report_diagnostic(br#"{"kind":"fixture_error","phase":"binding","code":"identity","auth_token":"redacted-fixture"}"#));
    assert!(!report_diagnostic(
        br#"{"kind":"ready","phase":"binding","code":"identity"}"#
    ));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataCreated {
    path: String,
    depth: usize,
    device: u64,
    inode: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataWitness {
    kind: String,
    session_id: String,
    operation_id: String,
    created: Vec<MetadataCreated>,
}
struct MetadataPin {
    path: String,
    name: String,
    parent: Arc<File>,
    file: Arc<File>,
    id: Option<(u64, u64)>,
    directory: bool,
}
impl MetadataPin {
    fn check(&self) -> Result<()> {
        use nix::{fcntl::AtFlags, sys::stat::fstatat};
        let id = self
            .id
            .context("qualification metadata uncaptured inode debt")?;
        let h = self.file.metadata()?;
        let n = fstatat(
            self.parent.as_ref(),
            self.name.as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            (h.dev(), h.ino()) == id
                && (n.st_dev, n.st_ino) == id
                && h.uid() == 1000
                && h.gid() == 1000
                && n.st_uid == 1000
                && n.st_gid == 1000
                && h.is_dir() == self.directory
                && if self.directory {
                    h.mode() & 0o7777 == 0o700 && n.st_mode & 0o177777 == 0o040700
                } else {
                    h.is_file()
                        && h.nlink() == 1
                        && n.st_nlink == 1
                        && h.mode() & 0o7777 == 0o600
                        && n.st_mode & 0o177777 == 0o100600
                },
            "qualification metadata captured inode changed"
        );
        Ok(())
    }
}
struct MetadataTree {
    workspace: Arc<File>,
    pins: Vec<MetadataPin>,
    pending: Vec<super::NativeIdentity>,
}
impl MetadataTree {
    fn new(workspace: &Workspace) -> Result<Self> {
        workspace.check()?;
        Ok(Self {
            workspace: Arc::new(workspace.file.try_clone()?),
            pins: Vec::new(),
            pending: Vec::new(),
        })
    }
    fn parent(&self, path: &str) -> Result<Arc<File>> {
        if path.is_empty() {
            return Ok(self.workspace.clone());
        }
        let p = self
            .pins
            .iter()
            .find(|p| p.path == path && p.directory)
            .context("qualification metadata parent custody")?;
        p.check()?;
        Ok(p.file.clone())
    }
    fn adopt(&mut self, witness: &MetadataWitness) -> Result<()> {
        use nix::{
            fcntl::{openat, AtFlags, OFlag},
            sys::stat::{fstatat, Mode},
        };
        ensure!(
            witness.created.len() <= 16,
            "qualification metadata witness bounds"
        );
        ensure!(
            self.pending
                .iter()
                .any(|id| id.session_id == witness.session_id
                    && id.operation_id == witness.operation_id),
            "qualification metadata witness unreserved original"
        );
        let workspace_dev = self.workspace.metadata()?.dev();
        let mut last = 0;
        for w in &witness.created {
            super::native_metadata::path(&w.path)?;
            ensure!(
                w.path == "sdk-metadata" || w.path.starts_with("sdk-metadata/"),
                "qualification metadata witness root"
            );
            ensure!(
                w.device == workspace_dev
                    && w.depth == w.path.split('/').count()
                    && w.depth >= last
                    && w.depth <= 16,
                "qualification metadata witness depth"
            );
            last = w.depth;
            if let Some(old) = self.pins.iter().find(|p| p.path == w.path) {
                ensure!(
                    old.id == Some((w.device, w.inode)) && old.directory,
                    "qualification metadata witness conflict"
                );
                old.check()?;
                continue;
            }
            let (parent, name) = w.path.rsplit_once('/').unwrap_or(("", w.path.as_str()));
            let parent = self.parent(parent)?;
            let named = fstatat(parent.as_ref(), name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
            ensure!(
                (named.st_dev, named.st_ino) == (w.device, w.inode)
                    && named.st_uid == 1000
                    && named.st_gid == 1000
                    && named.st_mode & 0o177777 == 0o040700,
                "qualification metadata witness identity"
            );
            let file = File::from(openat(
                parent.as_ref(),
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?);
            let pin = MetadataPin {
                path: w.path.clone(),
                name: name.into(),
                parent,
                file: Arc::new(file),
                id: Some((w.device, w.inode)),
                directory: true,
            };
            pin.check()?;
            self.pins.push(pin);
        }
        self.pending.retain(|id| {
            id.session_id != witness.session_id || id.operation_id != witness.operation_id
        });
        Ok(())
    }
    fn create(&mut self, name: &str, data: &[u8]) -> Result<()> {
        use nix::{
            fcntl::{openat, AtFlags, OFlag},
            sys::stat::{fchmod, fstatat, Mode},
            unistd::{fchown, Gid, Uid},
        };
        ensure!(
            self.pins.len() < 512,
            "qualification metadata fixture capacity"
        );
        let parent = self.parent("sdk-metadata/nested")?;
        let file = File::from(openat(
            parent.as_ref(),
            name,
            OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_RDWR
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )?);
        self.pins.push(MetadataPin {
            path: format!("sdk-metadata/nested/{name}"),
            name: name.into(),
            parent,
            file: Arc::new(file),
            id: None,
            directory: false,
        });
        let pin = self.pins.last_mut().unwrap();
        let held = pin.file.metadata()?;
        let id = (held.dev(), held.ino());
        let named = fstatat(pin.parent.as_ref(), name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
        ensure!(
            held.is_file()
                && held.nlink() == 1
                && held.uid() == 0
                && held.gid() == 0
                && (named.st_dev, named.st_ino) == id
                && named.st_uid == 0
                && named.st_gid == 0,
            "qualification metadata exclusive file identity"
        );
        pin.id = Some(id);
        fchmod(pin.file.as_ref(), Mode::from_bits_truncate(0o600))?;
        fchown(
            pin.file.as_ref(),
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )?;
        pin.check()?;
        pin.file.write_all_at(data, 0)?;
        pin.file.sync_all()?;
        pin.check()?;
        Ok(())
    }
    fn cleanup(&self) -> Result<()> {
        use nix::unistd::{unlinkat, UnlinkatFlags};
        ensure!(
            self.pending.is_empty(),
            "qualification metadata missing producer witness debt"
        );
        for pin in self.pins.iter().rev() {
            pin.check()?;
            unlinkat(
                pin.parent.as_ref(),
                pin.name.as_str(),
                if pin.directory {
                    UnlinkatFlags::RemoveDir
                } else {
                    UnlinkatFlags::NoRemoveDir
                },
            )?;
        }
        Ok(())
    }
}
async fn metadata_control(
    owner: &mut Owner,
    message: serde_json::Value,
    expires: Instant,
) -> Result<Vec<u8>> {
    let until = expires.min(Instant::now() + Duration::from_secs(3));
    let mut wire = serde_json::to_vec(&message)?;
    ensure!(wire.len() <= 1024, "qualification metadata control bounds");
    wire.push(b'\n');
    tokio::time::timeout_at(tokio::time::Instant::from_std(until), async {
        let control = owner
            .endpoint_control
            .as_mut()
            .context("qualification metadata endpoint control")?;
        control.write_all(&wire).await?;
        control.flush().await?;
        line_bounded(
            owner
                .endpoint_output
                .as_mut()
                .context("qualification metadata endpoint output")?,
            until,
            16384,
        )
        .await
    })
    .await
    .context("qualification metadata control deadline")?
}
async fn metadata_witness(
    owner: &mut Owner,
    id: &super::NativeIdentity,
    expires: Instant,
) -> Result<()> {
    let raw=metadata_control(owner,serde_json::json!({"kind":"fixture_metadata_witness","session_id":id.session_id,"operation_id":id.operation_id}),expires).await?;
    let witness: MetadataWitness = serde_json::from_slice(&raw)?;
    ensure!(
        witness.kind == "fixture_metadata_created"
            && witness.session_id == id.session_id
            && witness.operation_id == id.operation_id,
        "qualification metadata witness original identity"
    );
    owner
        .metadata_tree
        .as_mut()
        .context("qualification metadata tree")?
        .adopt(&witness)
}
async fn metadata_pending_witnesses(owner: &mut Owner, expires: Instant) -> Result<()> {
    let ids = owner
        .metadata_tree
        .as_ref()
        .context("qualification metadata tree")?
        .pending
        .clone();
    for id in ids {
        metadata_witness(owner, &id, expires).await?;
    }
    Ok(())
}
async fn metadata_mkdir(
    owner: &mut Owner,
    executor: &Executor,
    path: &str,
    expires: Instant,
) -> Result<super::NativeStatReceipt> {
    let h = executor.start_native_mkdir(path)?;
    owner
        .metadata_tree
        .as_mut()
        .unwrap()
        .pending
        .push(h.identity().clone());
    let observed = h.wait().await;
    let witness = metadata_witness(owner, h.identity(), expires).await;
    witness?;
    match observed? {
        super::NativeMetadataReceipt::MakeDirResult(r) => Ok(r),
        _ => bail!("qualification metadata mkdir kind"),
    }
}
fn metadata_entry_matches(pin: &MetadataPin, entry: &super::NativeFileEntry) -> Result<()> {
    pin.check()?;
    let m = pin.file.metadata()?;
    ensure!(
        entry.path == pin.path
            && entry.name == pin.name
            && entry.kind
                == if pin.directory {
                    super::NativeFileType::Directory
                } else {
                    super::NativeFileType::File
                }
            && entry.permissions
                == if pin.directory {
                    "rwx------"
                } else {
                    "rw-------"
                }
            && entry.mode == m.mode()
            && entry.size == m.len()
            && entry.owner == m.uid().to_string()
            && entry.group == m.gid().to_string()
            && entry.symlink_target.is_none()
            && entry.version.device == m.dev()
            && entry.version.inode == m.ino()
            && entry.version.size == m.len()
            && entry.version.mtime_seconds == m.mtime()
            && entry.version.mtime_nanos as i64 == m.mtime_nsec()
            && entry.version.ctime_seconds == m.ctime()
            && entry.version.ctime_nanos as i64 == m.ctime_nsec()
            && entry.modified_time.seconds == m.mtime()
            && entry.modified_time.nanos as i64 == m.mtime_nsec(),
        "qualification actual metadata differs"
    );
    Ok(())
}
// Qualification oracle hashes one guest-canonical entry at a time; never
// materializes a second whole-list Value or serialized array.
fn metadata_guest_digest(entries: &[super::NativeFileEntry]) -> Result<String> {
    struct Sink(Sha256);
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink(Sha256::new());
    sink.write_all(b"[")?;
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            sink.write_all(b",")?;
        }
        let mut value = serde_json::to_value(entry)?;
        value.sort_all_objects();
        serde_json::to_writer(&mut sink, &value)?;
    }
    sink.write_all(b"]")?;
    Ok(format!("{:x}", sink.0.finalize()))
}
async fn metadata_body(owner: &mut Owner, executor: &Executor, expires: Instant) -> Result<()> {
    use super::NativeMetadataReceipt;
    owner.metadata_stage = Some("tree_admission");
    owner.metadata_tree = Some(MetadataTree::new(
        owner
            .workspace_pin
            .as_ref()
            .context("qualification metadata workspace")?,
    )?);
    owner.metadata_stage = Some("missing_stat");
    let missing = executor.start_native_stat("sdk-metadata-missing")?;
    ensure!(
        matches!(missing.wait().await?,NativeMetadataReceipt::FileStatResult(r) if r.entry.is_none()),
        "qualification metadata missing stat"
    );
    owner.metadata_stage = Some("nested_mkdir");
    let dir = metadata_mkdir(owner, executor, "sdk-metadata/nested", expires).await?;
    let original = dir.entry.context("qualification mkdir entry")?;
    metadata_entry_matches(
        owner
            .metadata_tree
            .as_ref()
            .unwrap()
            .pins
            .iter()
            .find(|p| p.path == original.path)
            .unwrap(),
        &original,
    )?;
    owner.metadata_stage = Some("existing_mkdir");
    let again = metadata_mkdir(owner, executor, "sdk-metadata/nested", expires).await?;
    ensure!(
        again
            .entry
            .as_ref()
            .is_some_and(|e| e.version.device == original.version.device
                && e.version.inode == original.version.inode),
        "qualification existing mkdir changed inode"
    );
    owner.metadata_stage = Some("seed_70_entries");
    for i in 0..70 {
        owner
            .metadata_tree
            .as_mut()
            .unwrap()
            .create(&format!("file-{i:03}"), format!("entry-{i:03}").as_bytes())?;
    }
    owner.metadata_stage = Some("existing_stat");
    let stat = executor.start_native_stat("sdk-metadata/nested/file-000")?;
    match stat.wait().await? {
        NativeMetadataReceipt::FileStatResult(r) => metadata_entry_matches(
            owner
                .metadata_tree
                .as_ref()
                .unwrap()
                .pins
                .iter()
                .find(|p| p.path == r.path)
                .unwrap(),
            r.entry.as_ref().context("qualification stat entry")?,
        )?,
        _ => bail!("qualification stat kind"),
    }
    owner.metadata_stage = Some("list_begin");
    let list = executor.start_native_list("sdk-metadata/nested")?;
    let mut pages = Vec::new();
    let mut entries = Vec::new();
    let mut receipt = list.wait().await?;
    let summary = loop {
        match receipt {
            NativeMetadataReceipt::ListPage(page) => {
                ensure!(
                    page.cursor == entries.len() as u64
                        && !page.entries.is_empty()
                        && page.entries.len() <= 64,
                    "qualification list contiguous page"
                );
                for e in &page.entries {
                    metadata_entry_matches(
                        owner
                            .metadata_tree
                            .as_ref()
                            .unwrap()
                            .pins
                            .iter()
                            .find(|p| p.path == e.path)
                            .context("qualification list file custody")?,
                        e,
                    )?;
                }
                entries.extend(page.entries.clone());
                let next = page.next_cursor;
                pages.push(page);
                owner.metadata_page_count = pages.len();
                owner.metadata_entry_count = entries.len();
                owner.metadata_stage = Some("list_next");
                receipt = list.next(next).await?;
            }
            NativeMetadataReceipt::ListResult(s) => break s,
            _ => bail!("qualification list kind"),
        }
    };
    owner.metadata_stage = Some("list_full_digest");
    ensure!(
        entries.len() == 70
            && summary.count == 70
            && metadata_guest_digest(&entries)? == summary.snapshot_sha256,
        "qualification full list hash"
    );
    owner.metadata_stage = Some("controlled_source_mutation");
    {
        let tree = owner.metadata_tree.as_mut().unwrap();
        let pin = tree
            .pins
            .iter()
            .find(|p| p.path == "sdk-metadata/nested/file-000")
            .unwrap();
        pin.file.write_all_at(b"CHANGED!!", 0)?;
        pin.file.sync_all()?;
        pin.check()?;
        tree.create("added", b"new")?;
    }
    owner.metadata_stage = Some("cached_original_query");
    match list.query().await? {
        NativeMetadataReceipt::ListResult(old) => {
            ensure!(old == summary, "qualification list query recomputed")
        }
        _ => bail!("qualification list query kind"),
    }
    owner.metadata_stage = Some("cached_original_pages");
    for old in &pages {
        match list.next(old.cursor).await? {
            NativeMetadataReceipt::ListPage(page) => {
                ensure!(&page == old, "qualification list page recomputed")
            }
            _ => bail!("qualification list replay kind"),
        }
    }
    owner.metadata_stage = Some("changed_source_stat");
    let changed = executor.start_native_stat("sdk-metadata/nested/file-000")?;
    match changed.wait().await? {
        NativeMetadataReceipt::FileStatResult(r) => {
            let entry = r.entry.context("qualification changed stat entry")?;
            metadata_entry_matches(
                owner
                    .metadata_tree
                    .as_ref()
                    .unwrap()
                    .pins
                    .iter()
                    .find(|p| p.path == r.path)
                    .unwrap(),
                &entry,
            )?;
            ensure!(
                entry.version != entries[0].version,
                "qualification changed source version invisible"
            );
        }
        _ => bail!("qualification changed stat kind"),
    }
    owner.metadata_stage = Some("fault_arm");
    let armed: serde_json::Value = serde_json::from_slice(
        &metadata_control(
            owner,
            serde_json::json!({"kind":"fixture_metadata_fault","path":"sdk-metadata/lost"}),
            expires,
        )
        .await?,
    )?;
    ensure!(
        armed == serde_json::json!({"kind":"fixture_metadata_fault_armed"}),
        "qualification metadata fault registration"
    );
    owner.metadata_stage = Some("lost_mkdir_admission");
    let lost = executor.start_native_mkdir("sdk-metadata/lost")?;
    owner
        .metadata_tree
        .as_mut()
        .unwrap()
        .pending
        .push(lost.identity().clone());
    owner.metadata_stage = Some("lost_mkdir_observation");
    ensure!(
        lost.wait().await.is_err(),
        "qualification lost mkdir falsely successful"
    );
    owner.metadata_stage = Some("lost_mkdir_original_query");
    let recovered = lost.query().await?;
    owner.metadata_stage = Some("lost_mkdir_witness");
    metadata_witness(owner, lost.identity(), expires).await?;
    let recovered = match recovered {
        NativeMetadataReceipt::MakeDirResult(r) => r,
        _ => bail!("qualification lost mkdir original query kind"),
    };
    let entry = recovered
        .entry
        .context("qualification lost mkdir receipt")?;
    metadata_entry_matches(
        owner
            .metadata_tree
            .as_ref()
            .unwrap()
            .pins
            .iter()
            .find(|p| p.path == entry.path)
            .unwrap(),
        &entry,
    )?;
    // Bring actual inventory to511 without creating new operation identities.
    owner.metadata_stage = Some("fill_inventory");
    while owner.metadata_tree.as_ref().unwrap().pins.len() < 511 {
        let n = owner.metadata_tree.as_ref().unwrap().pins.len();
        owner
            .metadata_tree
            .as_mut()
            .unwrap()
            .create(&format!("padding-{n:03}"), b"")?;
    }
    owner.metadata_stage = Some("partial_mkdir_admission");
    let partial = executor.start_native_mkdir("sdk-metadata/partial/second")?;
    owner
        .metadata_tree
        .as_mut()
        .unwrap()
        .pending
        .push(partial.identity().clone());
    owner.metadata_stage = Some("partial_mkdir_observation");
    ensure!(
        partial.wait().await.is_err(),
        "qualification partial mkdir falsely final"
    );
    owner.metadata_stage = Some("partial_original_query");
    ensure!(
        partial.query().await.is_err(),
        "qualification partial mkdir query falsely final"
    );
    owner.metadata_stage = Some("partial_witness");
    metadata_witness(owner, partial.identity(), expires).await?;
    let tree = owner.metadata_tree.as_ref().unwrap();
    ensure!(
        tree.pins.iter().any(|p| p.path == "sdk-metadata/partial")
            && !tree
                .pins
                .iter()
                .any(|p| p.path == "sdk-metadata/partial/second"),
        "qualification partial mkdir witness"
    );
    let parent = tree.parent("sdk-metadata/partial")?;
    ensure!(
        matches!(
            nix::sys::stat::fstatat(&parent, "second", nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW),
            Err(nix::errno::Errno::ENOENT)
        ),
        "qualification second partial name exists"
    );
    ensure!(
        expires
            .checked_duration_since(Instant::now())
            .is_some_and(|remaining| remaining > Duration::from_secs(4)),
        "qualification blocked owner observation budget"
    );
    owner.metadata_stage = Some("unknown_serial_slot");
    let blocked = executor.start_native_stat("sdk-metadata/nested/added")?;
    ensure!(
        blocked.wait().await.is_err(),
        "qualification UNKNOWN released serial slot"
    );
    ensure!(
        Instant::now() < expires && owner.client.as_ref().is_some_and(|c| c.is_ready()),
        "qualification UNKNOWN observation lost actual live broker"
    );

    Ok(())
}

#[test]
fn native_metadata_fixture_parent_clones_share_one_actual_directory_descriptor() -> Result<()> {
    let directory = Arc::new(File::open(".")?);
    let before = directory.metadata()?;
    let tree = MetadataTree {
        workspace: directory.clone(),
        pins: Vec::new(),
        pending: Vec::new(),
    };
    let parents = (0..512)
        .map(|_| tree.parent(""))
        .collect::<Result<Vec<_>>>()?;
    for parent in &parents {
        ensure!(
            Arc::ptr_eq(parent, &directory) && parent.as_raw_fd() == directory.as_raw_fd(),
            "qualification parent duplicated actual descriptor"
        );
        let held = parent.metadata()?;
        ensure!(
            (held.dev(), held.ino()) == (before.dev(), before.ino()) && held.is_dir(),
            "qualification shared parent inode changed"
        );
    }
    drop(directory);
    drop(tree);
    ensure!(
        parents
            .last()
            .context("retained parent")?
            .metadata()?
            .is_dir(),
        "qualification parent custody lost before children"
    );
    drop(parents);
    Ok(())
}

// Lifecycle adapter only: the business actor below is the captured production
// broker/Engine client. This adapter is not Firecracker or durable persistence.
struct HttpOwnedFactory {
    client: Arc<NativeClient>,
    built: Mutex<bool>,
    stopped: Arc<Mutex<bool>>,
}
struct HttpOwnedBackend {
    client: Arc<NativeClient>,
    stopped: Arc<Mutex<bool>>,
}
impl super::SandboxBackendFactory for HttpOwnedFactory {
    fn build(
        &self,
        _: super::FreshSandboxBuildSpec,
        _: super::SandboxLaunchConfig,
    ) -> Result<Box<dyn super::SandboxBackend>> {
        let mut built = self.built.lock().expect("qualification backend build");
        ensure!(
            !*built && self.client.is_ready(),
            "qualification requires original authenticated client"
        );
        *built = true;
        Ok(Box::new(HttpOwnedBackend {
            client: self.client.clone(),
            stopped: self.stopped.clone(),
        }))
    }
    fn build_from_snapshot(
        &self,
        _: &crate::snapshot::RunnableSnapshot,
        _: super::SandboxLaunchConfig,
    ) -> Result<Box<dyn super::SandboxBackend>> {
        bail!("qualification restore unsupported")
    }
    fn decode_paused_state(
        &self,
        _: PathBuf,
        _: serde_json::Value,
    ) -> Result<Arc<dyn super::PausedSandboxState>> {
        bail!("qualification paused state unsupported")
    }
    fn build_from_paused_state(
        &self,
        _: crate::types::SandboxId,
        _: &dyn super::PausedSandboxState,
        _: Option<super::EnvdAccessToken>,
    ) -> Result<Box<dyn super::SandboxBackend>> {
        bail!("qualification resume unsupported")
    }
}
#[async_trait::async_trait]
impl super::SandboxBackend for HttpOwnedBackend {
    async fn start(&mut self) -> Result<()> {
        self.wait_for_ready().await
    }
    async fn start_nowait(&mut self) -> Result<()> {
        self.wait_for_ready().await
    }
    async fn wait_for_ready(&self) -> Result<()> {
        ensure!(
            self.client.is_ready() && !*self.stopped.lock().expect("qualification lifecycle"),
            "qualification client not authenticated/available"
        );
        Ok(())
    }
    async fn pause(
        &mut self,
        _: Option<&Path>,
    ) -> super::SandboxCaptureResult<Arc<dyn super::PausedSandboxState>> {
        Err(super::SandboxCaptureError::recoverable(anyhow::anyhow!(
            "qualification pause unsupported"
        )))
    }
    async fn resume(&mut self) -> Result<()> {
        bail!("qualification resume unsupported")
    }
    async fn snapshot(&mut self) -> super::SandboxCaptureResult<super::CapturedSandboxSnapshot> {
        Err(super::SandboxCaptureError::recoverable(anyhow::anyhow!(
            "qualification snapshot unsupported"
        )))
    }
    async fn snapshot_volumes(&mut self) -> super::SandboxCaptureResult<()> {
        Err(super::SandboxCaptureError::recoverable(anyhow::anyhow!(
            "qualification volume snapshot unsupported"
        )))
    }
    async fn capture_to_dir(
        &mut self,
        _: &Path,
    ) -> super::SandboxCaptureResult<(
        super::SandboxSnapshotManifest,
        Option<Box<dyn std::any::Any + Send>>,
    )> {
        Err(super::SandboxCaptureError::recoverable(anyhow::anyhow!(
            "qualification capture unsupported"
        )))
    }
    async fn freeze_and_snapshot_volumes(&mut self) -> super::SandboxCaptureResult<()> {
        Err(super::SandboxCaptureError::recoverable(anyhow::anyhow!(
            "qualification volume freeze unsupported"
        )))
    }
    async fn thaw_volumes(&mut self) -> Result<()> {
        bail!("qualification volume thaw unsupported")
    }
    async fn fork(
        &mut self,
        _: &[super::SandboxForkSpec],
    ) -> super::SandboxCaptureResult<Vec<super::SandboxForkResult>> {
        Err(super::SandboxCaptureError::recoverable(anyhow::anyhow!(
            "qualification fork unsupported"
        )))
    }
    async fn stop(&mut self) -> Result<()> {
        self.client.close_caller_admission();
        self.client.close();
        *self.stopped.lock().expect("qualification lifecycle") = true;
        Ok(())
    }
    fn host_interaction_ip(&self) -> Option<std::net::Ipv4Addr> {
        None
    }
    fn native_control(&self) -> Option<super::NativeControl> {
        Some(super::NativeControl::new(self.client.clone()))
    }
    fn native_control_ready(&self) -> bool {
        self.client.is_ready()
    }
    fn runtime_info(&self) -> super::SandboxRuntimeInfo {
        super::SandboxRuntimeInfo::default()
    }
    fn startup_artifacts(&self) -> super::RuntimeArtifactSet {
        super::RuntimeArtifactSet::empty()
    }
    async fn update_network_policy(
        &mut self,
        _: Option<super::SandboxNetworkPolicy>,
    ) -> Result<()> {
        bail!("qualification network changes unsupported")
    }
    fn update_custom_extension_params(&mut self, _: Option<super::CustomExtensionParams>) {}
}
pub(super) const HTTP_KEY: &str =
    "e2b_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub(super) async fn qualified_http(
    app: &axum::Router,
    id: crate::types::SandboxId,
    body: Option<serde_json::Value>,
    keys: usize,
) -> Result<(axum::http::StatusCode, serde_json::Value)> {
    qualified_http_with_key(app, id, body, keys, HTTP_KEY).await
}
async fn qualified_http_with_key(
    app: &axum::Router,
    id: crate::types::SandboxId,
    body: Option<serde_json::Value>,
    keys: usize,
    api_key: &str,
) -> Result<(axum::http::StatusCode, serde_json::Value)> {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let mut request = Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(format!("/sandboxes/{id}/native/control"))
        .header("content-type", "application/json")
        .header("host", format!("8000-{id}.native.example.invalid"))
        .body(Body::from(body.map_or(String::new(), |v| v.to_string())))?;
    for _ in 0..keys {
        request.headers_mut().append("x-api-key", api_key.parse()?);
    }
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok((status, value))
}
fn http_diagnostic_kind(value: &serde_json::Value) -> &'static str {
    match value.as_str() {
        Some("accepted") => "accepted",
        Some("pending") => "pending",
        Some("status") => "status",
        Some("list_page") => "list_page",
        Some("list_result") => "list_result",
        Some("file_stat_result") => "file_stat_result",
        Some("make_dir_result") => "make_dir_result",
        Some("error") => "error",
        None => "missing_kind",
        _ => "other_kind",
    }
}
fn http_identity_equal(a: &super::NativeIdentity, b: &super::NativeIdentity) -> bool {
    a.session_id == b.session_id && a.operation_id == b.operation_id
}
fn http_identity(value: &serde_json::Value) -> Result<super::NativeIdentity> {
    Ok(super::NativeIdentity {
        session_id: value["session_id"]
            .as_str()
            .context("qualification HTTP session")?
            .into(),
        operation_id: value["operation_id"]
            .as_str()
            .context("qualification HTTP operation")?
            .into(),
    })
}
async fn metadata_http_body(owner: &mut Owner, namespace: &Path, expires: Instant) -> Result<()> {
    use crate::orchestrator::{
        CreateSandboxRequest, FileBackedSandboxPersister, InMemoryMetadataStore, Orchestrator,
        SandboxLaunchSource, SandboxTimeoutAction,
    };
    use serde_json::json;
    owner.metadata_stage = Some("http_create_publish");
    let client = owner
        .client
        .as_ref()
        .context("qualification HTTP original client")?
        .clone();
    let stopped = Arc::new(Mutex::new(false));
    let factory =
        super::FirecrackerSandboxFactory::with_qualification_delegate(Arc::new(HttpOwnedFactory {
            client: client.clone(),
            built: Mutex::new(false),
            stopped: stopped.clone(),
        }));
    let persister = FileBackedSandboxPersister::with_qualification_delegate();
    let orchestrator =
        Orchestrator::new_native_api_fixture(InMemoryMetadataStore::new(), factory, persister)
            .await?;
    owner.http_orchestrator = Some(orchestrator.clone());
    let created = orchestrator
        .create_sandbox(CreateSandboxRequest {
            extra_drives: Vec::new(),
            extra_drives_in_snapshot: false,
            volume_mounts: Default::default(),
            source: SandboxLaunchSource::Image {
                image_ref: "qualification-owned-native-client".into(),
                overlaybd_config_path: namespace.join("qualification-no-image-artifacts"),
                context: Default::default(),
                resources: Some(crate::types::SandboxResources {
                    cpu_count: 1,
                    memory_mib: 512,
                    disk_size_mib: 0,
                }),
                extra_drives: Vec::new(),
                extra_boot_args: None,
                image_configs: Box::new(crate::types::ImageConfigs::new()),
            },
            timeout: Some(Duration::from_secs(30)),
            timeout_action: SandboxTimeoutAction::Delete,
            auto_resume: false,
            user_metadata: None,
            env_vars: None,
            network_policy: super::SandboxNetworkPolicy::default(),
            secure: false,
            custom_extension_params: None,
        })
        .await?;
    let id = created.id;
    owner.http_sandbox = Some(id);
    ensure!(
        created.state == crate::orchestrator::SandboxState::Running,
        "qualification HTTP actual launch state"
    );
    let volume_catalog_owner = tempfile::tempdir()?;
    let snapshot_manager = Arc::new(crate::snapshot::mock::mock_snapshot_manager());
    let volume_manager = Arc::new(
        crate::volume::VolumeManager::open_with_repository(
            volume_catalog_owner.path().join("catalog.json"),
            snapshot_manager.repository(),
        )
        .await?,
    );
    let api = Arc::new(crate::api::ApiImpl::new(
        orchestrator.clone(),
        snapshot_manager,
        Arc::new(crate::template::TemplateBuilder::new()),
        Arc::new(crate::image::ImageResolver::new(
            &crate::cfg::AppConfig::default(),
        )),
        volume_manager,
        None,
        vec!["native.example.invalid".into()],
        crate::api_key::ApiKey::new(HTTP_KEY)?,
    ));
    let app = crate::api::server::new(api);
    let (status, capability) = qualified_http(&app, id, None, 1).await?;
    ensure!(
        status.is_success() && capability["epoch"] == client.incarnation(),
        "qualification HTTP original authenticated epoch"
    );
    let epoch = client.incarnation();
    let request = |key: &str, phase: serde_json::Value| json!({"epoch":epoch,"operation_id":key,"request":phase});
    owner.metadata_tree = Some(MetadataTree::new(
        owner
            .workspace_pin
            .as_ref()
            .context("qualification HTTP workspace")?,
    )?);
    owner.metadata_stage = Some("http_auth_epoch_refusal");
    let mkdir = request(
        "guard",
        json!({"kind":"mkdir","path":"sdk-metadata/refused"}),
    );
    for keys in [0, 2] {
        ensure!(
            !qualified_http(&app, id, Some(mkdir.clone()), keys)
                .await?
                .0
                .is_success(),
            "qualification HTTP auth bypass"
        );
    }
    let mut foreign = mkdir.clone();
    foreign["epoch"] = json!(uuid::Uuid::new_v4().to_string());
    ensure!(
        !qualified_http(&app, id, Some(foreign), 1)
            .await?
            .0
            .is_success(),
        "qualification HTTP foreign epoch"
    );
    let mut numeric = mkdir.clone();
    numeric["epoch"] = json!(1);
    ensure!(
        !qualified_http(&app, id, Some(numeric), 1)
            .await?
            .0
            .is_success(),
        "qualification HTTP numeric epoch"
    );
    let foreign_key = "e2b_1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    ensure!(
        !qualified_http_with_key(&app, id, Some(mkdir.clone()), 1, foreign_key)
            .await?
            .0
            .is_success(),
        "qualification HTTP foreign caller key"
    );
    ensure!(
        !qualified_http(
            &app,
            id,
            Some(request("unowned-caller-operation", json!({"kind":"query"}))),
            1
        )
        .await?
        .0
        .is_success(),
        "qualification HTTP foreign caller operation"
    );
    ensure!(
        matches!(
            nix::sys::stat::fstatat(
                &owner.metadata_tree.as_ref().unwrap().workspace,
                "sdk-metadata",
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW
            ),
            Err(nix::errno::Errno::ENOENT)
        ),
        "qualification refused HTTP mutated filesystem"
    );
    owner.metadata_stage = Some("http_mkdir_original");
    let begin = request(
        "mkdir",
        json!({"kind":"mkdir","path":"sdk-metadata/nested"}),
    );
    let (status, accepted) = qualified_http(&app, id, Some(begin.clone()), 1).await?;
    ensure!(
        status.is_success() && accepted["kind"] == "accepted",
        "qualification HTTP mkdir admission"
    );
    let original = http_identity(&accepted)?;
    owner
        .metadata_tree
        .as_mut()
        .unwrap()
        .pending
        .push(original.clone());
    let (_, retry) = qualified_http(&app, id, Some(begin), 1).await?;
    ensure!(
        http_identity_equal(&http_identity(&retry)?, &original),
        "qualification HTTP retry original changed"
    );
    let (status, receipt) =
        qualified_http(&app, id, Some(request("mkdir", json!({"kind":"query"}))), 1).await?;
    ensure!(
        status.is_success() && receipt["result"]["kind"] == "make_dir_result",
        "qualification HTTP mkdir receipt"
    );
    metadata_witness(owner, &original, expires).await?;
    for i in 0..70 {
        owner
            .metadata_tree
            .as_mut()
            .unwrap()
            .create(&format!("file-{i:03}"), format!("entry-{i:03}").as_bytes())?;
    }
    owner.metadata_stage = Some("http_stat_original");
    let (status, stat) = qualified_http(
        &app,
        id,
        Some(request(
            "stat",
            json!({"kind":"stat","path":"sdk-metadata/nested/file-000"}),
        )),
        1,
    )
    .await?;
    ensure!(
        status.is_success() && stat["kind"] == "accepted",
        "qualification HTTP stat admission"
    );
    let (status, stat) =
        qualified_http(&app, id, Some(request("stat", json!({"kind":"query"}))), 1).await?;
    ensure!(
        status.is_success() && stat["result"]["kind"] == "file_stat_result",
        "qualification HTTP stat receipt"
    );
    let entry: super::NativeFileEntry = serde_json::from_value(stat["result"]["entry"].clone())?;
    metadata_entry_matches(
        owner
            .metadata_tree
            .as_ref()
            .unwrap()
            .pins
            .iter()
            .find(|p| p.path == entry.path)
            .context("qualification HTTP stat custody")?,
        &entry,
    )?;
    owner.metadata_stage = Some("http_list_original");
    let begin = request("list", json!({"kind":"list","path":"sdk-metadata/nested"}));
    let (status, list) = qualified_http(&app, id, Some(begin.clone()), 1).await?;
    ensure!(status.is_success(), "qualification HTTP list admission");
    let list_id = http_identity(&list)?;
    let (_, retry) = qualified_http(&app, id, Some(begin), 1).await?;
    ensure!(
        http_identity_equal(&http_identity(&retry)?, &list_id),
        "qualification HTTP list repeated begin"
    );
    let (status, summary) =
        qualified_http(&app, id, Some(request("list", json!({"kind":"query"}))), 1).await?;
    owner.http_reply_diagnostic = Some((
        status.as_u16(),
        http_diagnostic_kind(&summary["kind"]),
        http_diagnostic_kind(&summary["result"]["kind"]),
        summary["result"]["complete"].as_bool(),
    ));
    ensure!(
        status.is_success()
            && summary["result"]["complete"] == false
            && http_identity_equal(&http_identity(&summary["result"])?, &list_id),
        "qualification HTTP initial list receipt identity/custody"
    );
    let mut entries = Vec::new();
    let mut pages = Vec::new();
    let mut cursor = 0;
    let mut initial = summary["result"].clone();
    for key in ["kind", "complete", "session_id", "operation_id"] {
        initial
            .as_object_mut()
            .context("qualification initial receipt object")?
            .remove(key);
    }
    let (snapshot_sha, snapshot_version) = match summary["result"]["kind"].as_str() {
        Some("list_page") => {
            let page: super::NativeListPage = serde_json::from_value(initial)?;
            ensure!(
                page.path == "sdk-metadata/nested"
                    && page.cursor == 0
                    && page.count == 70
                    && !page.entries.is_empty()
                    && page.entries.len() <= 64
                    && page.next_cursor == page.entries.len() as u64,
                "qualification HTTP initial contiguous page"
            );
            for entry in &page.entries {
                metadata_entry_matches(
                    owner
                        .metadata_tree
                        .as_ref()
                        .unwrap()
                        .pins
                        .iter()
                        .find(|p| p.path == entry.path)
                        .context("qualification initial page custody")?,
                    entry,
                )?;
            }
            let snapshot = (page.snapshot_sha256.clone(), page.version.clone());
            cursor = page.next_cursor;
            entries.extend(page.entries.clone());
            pages.push(page);
            owner.metadata_page_count = pages.len();
            owner.metadata_entry_count = entries.len();
            snapshot
        }
        Some("list_result") => {
            let result: super::NativeListSummary = serde_json::from_value(initial)?;
            ensure!(
                result.path == "sdk-metadata/nested"
                    && result.count == 70
                    && result.snapshot_sha256.len() == 64
                    && result
                        .snapshot_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "qualification HTTP actual early summary"
            );
            (result.snapshot_sha256, result.version)
        }
        _ => bail!("qualification HTTP initial list kind"),
    };
    while cursor < 70 {
        owner.metadata_stage = Some("http_list_next");
        let (status, response) = qualified_http(
            &app,
            id,
            Some(request("list", json!({"kind":"list_next","cursor":cursor}))),
            1,
        )
        .await?;
        let mut value = response["result"].clone();
        ensure!(
            value["kind"] == "list_page" && http_identity_equal(&http_identity(&value)?, &list_id),
            "qualification HTTP page kind/original identity"
        );
        for key in ["kind", "complete", "session_id", "operation_id"] {
            value
                .as_object_mut()
                .context("qualification HTTP page object")?
                .remove(key);
        }
        let page: super::NativeListPage = serde_json::from_value(value)?;
        ensure!(
            status.is_success()
                && page.cursor == cursor
                && page.next_cursor > cursor
                && page.count == 70
                && page.next_cursor == cursor + page.entries.len() as u64
                && !page.entries.is_empty()
                && page.entries.len() <= 64
                && page.snapshot_sha256 == snapshot_sha
                && page.version == snapshot_version,
            "qualification HTTP contiguous page"
        );
        for entry in &page.entries {
            metadata_entry_matches(
                owner
                    .metadata_tree
                    .as_ref()
                    .unwrap()
                    .pins
                    .iter()
                    .find(|p| p.path == entry.path)
                    .context("qualification HTTP list custody")?,
                entry,
            )?;
        }
        cursor = page.next_cursor;
        entries.extend(page.entries.clone());
        pages.push(page);
        owner.metadata_page_count = pages.len();
        owner.metadata_entry_count = entries.len();
    }
    let (status, final_result) = qualified_http(
        &app,
        id,
        Some(request("list", json!({"kind":"list_next","cursor":70}))),
        1,
    )
    .await?;
    ensure!(
        status.is_success()
            && final_result["result"]["kind"] == "list_result"
            && final_result["result"]["complete"] == true
            && final_result["result"]["snapshot_sha256"] == metadata_guest_digest(&entries)?
            && final_result["result"]["snapshot_sha256"] == snapshot_sha
            && final_result["result"]["count"] == 70
            && entries.len() == 70
            && http_identity_equal(&http_identity(&final_result["result"])?, &list_id),
        "qualification HTTP full digest final"
    );
    owner.metadata_stage = Some("http_boundary_refusal_cache");
    let invalid = (1..70)
        .find(|c| !pages.iter().any(|p| p.cursor == *c))
        .context("qualification nonboundary")?;
    ensure!(
        !qualified_http(
            &app,
            id,
            Some(request(
                "list",
                json!({"kind":"list_next","cursor":invalid})
            )),
            1
        )
        .await?
        .0
        .is_success(),
        "qualification HTTP nonboundary admitted"
    );
    let pin = owner
        .metadata_tree
        .as_ref()
        .unwrap()
        .pins
        .iter()
        .find(|p| p.path == "sdk-metadata/nested/file-000")
        .unwrap();
    pin.file.write_all_at(b"CHANGED!!", 0)?;
    pin.file.sync_all()?;
    pin.check()?;
    for old in &pages {
        let (status, cached) = qualified_http(
            &app,
            id,
            Some(request(
                "list",
                json!({"kind":"list_page","cursor":old.cursor}),
            )),
            1,
        )
        .await?;
        let mut value = cached["result"].clone();
        for key in ["kind", "complete", "session_id", "operation_id"] {
            value
                .as_object_mut()
                .context("qualification cached page")?
                .remove(key);
        }
        let page: super::NativeListPage = serde_json::from_value(value)?;
        ensure!(
            status.is_success() && page == *old,
            "qualification HTTP changed cached page"
        );
    }
    owner.metadata_stage = Some("http_lifecycle_close");
    orchestrator.delete_sandbox(id).await?;
    ensure!(
        *stopped.lock().expect("qualification lifecycle") && !client.is_ready(),
        "qualification adapter stop did not close exact client"
    );
    ensure!(
        !qualified_http(
            &app,
            id,
            Some(request(
                "after-stop",
                json!({"kind":"mkdir","path":"sdk-metadata/after-stop"})
            )),
            1
        )
        .await?
        .0
        .is_success(),
        "qualification HTTP stop admission"
    );
    let parent = owner
        .metadata_tree
        .as_ref()
        .unwrap()
        .parent("sdk-metadata")?;
    ensure!(
        matches!(
            nix::sys::stat::fstatat(
                &parent,
                "after-stop",
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW
            ),
            Err(nix::errno::Errno::ENOENT)
        ),
        "qualification after-stop physical effect"
    );
    drop(app);
    orchestrator.shutdown().await?;
    owner.http_orchestrator.take();
    owner.http_sandbox.take();
    Ok(())
}
#[tokio::test]
#[ignore = "requires explicit protected metadata descriptor, production broker/Engine, owned Linux unit; lifecycle adapter is not VM proof"]
async fn native_sdk_keyed_http_production_broker_engine_metadata() -> Result<()> {
    static JOB: AsyncMutex<Option<tokio::task::JoinHandle<Result<()>>>> =
        AsyncMutex::const_new(None);
    let mut job = JOB.lock().await;
    ensure!(job.is_none(), "qualification HTTP task already retained");
    *job = Some(tokio::spawn(run(true)));
    let result = job
        .as_mut()
        .expect("registered HTTP qualification task")
        .await
        .context("qualification retained HTTP task join")?;
    job.take();
    result
}
