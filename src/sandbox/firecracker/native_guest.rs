//! Explicit fresh-only native guest profile. The pinned native readiness binary
//! owns the single wire implementation; no shell, Python, retry or restore path.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeFeature {
    DirectoryV1,
}
fn profile_features<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<NativeFeature>, D::Error> {
    let features = Vec::<NativeFeature>::deserialize(d)?;
    if features.len() > 1 {
        return Err(serde::de::Error::custom("duplicate native feature"));
    }
    Ok(features)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGuestProfile {
    #[serde(default, deserialize_with = "profile_features")]
    pub features: Vec<NativeFeature>,
    pub rootfs_path: PathBuf,
    pub rootfs_sha256: String,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub kernel_path: PathBuf,
    pub kernel_sha256: String,
    pub agent_sha256: String,
    pub node_id: String,
    pub owner_id: String,
    pub generation: u64,
    pub guest_nonce: String,
    pub guest_cid: u32,
    pub vsock_filename: String,
    pub credential_path: PathBuf,
    pub credential_sha256: String,
    pub readiness_executable: PathBuf,
    pub readiness_sha256: String,
    pub vmm_executable: PathBuf,
    pub vmm_sha256: String,
    #[serde(skip)]
    source: Option<std::sync::Arc<ProfileSource>>,
}
impl fmt::Debug for NativeGuestProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeGuestProfile { fresh_only: true, .. }")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Profile,
    Identity,
    Deadline,
    Io,
    Probe,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native guest refused: {self:?}")
    }
}
impl std::error::Error for Error {}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}
fn safe_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
/// Retained descriptors for this exact admitted native launch, never cloned by path.
/// Runtime custody survives timeout/cancellation until actual probe reaping.
#[derive(Default)]
pub struct NativeProbeOwner {
    flight: tokio::sync::Mutex<Option<tokio::process::Child>>,
    client: std::sync::OnceLock<std::sync::Arc<crate::sandbox::native_process::NativeClient>>,
}
impl NativeProbeOwner {
    pub(crate) fn client(
        &self,
    ) -> Option<std::sync::Arc<crate::sandbox::native_process::NativeClient>> {
        self.client.get().filter(|v| v.is_ready()).cloned()
    }
    pub async fn retire(&self) -> Result<(), Error> {
        if let Some(client) = self.client.get() {
            client.close();
        }
        let mut held = self.flight.lock().await;
        if let Some(child) = held.as_mut() {
            let _ = child.start_kill();
            match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(_)) => {
                    held.take();
                }
                _ => return Err(Error::Deadline),
            }
        }
        if let Some(client) = self.client.get() {
            tokio::time::timeout(Duration::from_secs(2), client.retire_downloads())
                .await
                .map_err(|_| Error::Deadline)?
                .map_err(|_| Error::Io)?;
        }
        Ok(())
    }
}
pub struct NativeInputs {
    pub profile: std::sync::Arc<File>,
    // Original ancestor anchors and partial capture remain owned, never reopened.
    pub(super) anchors: Vec<(PathBuf, File)>,
    pub(super) pins: Vec<(PathBuf, std::fs::Metadata)>,
    pub(super) profile_ancestors: usize,
    pub rootfs: File,
    pub config: File,
    pub(super) source_drives: [File; 2],
    pub(super) sealed_sizes: [u64; 2],
    pub(super) sealed_pins: [std::fs::Metadata; 2],
    pub(super) sealed_hashes: [String; 2],
    pub(super) credential_sha256: String,
    pub kernel: File,
    pub probe: File,
    pub vmm: File,
    pub credential: File,
}
fn verify_small_content(file: &File, expected: &str, cap: u64) -> Result<(), Error> {
    use std::os::unix::fs::FileExt;
    let m = file.metadata().map_err(|_| Error::Io)?;
    if m.len() > cap {
        return Err(Error::Identity);
    }
    let mut bytes = [0u8; 16384];
    let length = usize::try_from(m.len()).map_err(|_| Error::Identity)?;
    file.read_exact_at(&mut bytes[..length], 0)
        .map_err(|_| Error::Io)?;
    if format!("{:x}", Sha256::digest(&bytes[..length])) != expected
        || identity(&m) != identity(&file.metadata().map_err(|_| Error::Io)?)
    {
        return Err(Error::Identity);
    }
    Ok(())
}
// Permanent aggregate backing tickets: partial capture never refunds or retries.
const SEALED_BACKING_CAP: u64 = 128 * 1024 * 1024;
static SEALED_BACKING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn drive_seals() -> nix::fcntl::SealFlag {
    use nix::fcntl::SealFlag as S;
    S::F_SEAL_WRITE | S::F_SEAL_GROW | S::F_SEAL_SHRINK | S::F_SEAL_SEAL
}
fn verify_sealed(file: &File, size: u64) -> Result<(), Error> {
    let m = file.metadata().map_err(|_| Error::Io)?;
    let seals =
        nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_GET_SEALS).map_err(|_| Error::Identity)?;
    if !m.is_file() || m.nlink() != 0 || m.len() != size || seals != drive_seals().bits() {
        return Err(Error::Identity);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn snapshot_drive(
    debt: &mut Vec<File>,
    source_index: usize,
    expected: &str,
    size: u64,
    until: Instant,
) -> Result<usize, Error> {
    use std::os::unix::fs::FileExt;
    remaining(until)?;
    if nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).map_err(|_| Error::Io)?
        != Some(4096)
    {
        return Err(Error::Identity);
    }
    let fd = nix::sys::memfd::memfd_create(
        c"aenv-native-drive",
        nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .map_err(|_| Error::Io)?;
    let target = debt.len();
    debt.push(File::from(fd)); // Actual FD custody before set_len/read/write/seal.
    debt[target].set_len(size).map_err(|_| Error::Io)?;
    let before = debt[source_index].metadata().map_err(|_| Error::Io)?;
    if before.len() != size {
        return Err(Error::Identity);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16384];
    let mut offset = 0;
    while offset < size {
        remaining(until)?;
        let length = usize::try_from((size - offset).min(buffer.len() as u64))
            .map_err(|_| Error::Identity)?;
        debt[source_index]
            .read_exact_at(&mut buffer[..length], offset)
            .map_err(|_| Error::Io)?;
        hash.update(&buffer[..length]);
        for (page, bytes) in buffer[..length].chunks(4096).enumerate() {
            if bytes.iter().any(|b| *b != 0) {
                SEALED_BACKING
                    .try_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |used| {
                            used.checked_add(4096)
                                .filter(|next| *next <= SEALED_BACKING_CAP)
                        },
                    )
                    .map_err(|_| Error::Identity)?;
                remaining(until)?;
                debt[target]
                    .write_all_at(bytes, offset + (page * 4096) as u64)
                    .map_err(|_| Error::Io)?;
            }
        }
        offset += length as u64;
        if identity(&before) != identity(&debt[source_index].metadata().map_err(|_| Error::Io)?) {
            return Err(Error::Identity);
        }
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err(Error::Identity);
    }
    remaining(until)?;
    nix::fcntl::fcntl(
        &debt[target],
        nix::fcntl::FcntlArg::F_ADD_SEALS(drive_seals()),
    )
    .map_err(|_| Error::Io)?;
    verify_sealed(&debt[target], size)?;
    // Verify the immutable destination bytes independently after sealing.
    let mut actual = Sha256::new();
    let mut offset = 0;
    while offset < size {
        remaining(until)?;
        let n = ((size - offset).min(buffer.len() as u64)) as usize;
        debt[target]
            .read_exact_at(&mut buffer[..n], offset)
            .map_err(|_| Error::Io)?;
        actual.update(&buffer[..n]);
        offset += n as u64;
    }
    if format!("{:x}", actual.finalize()) != expected
        || identity(&before) != identity(&debt[source_index].metadata().map_err(|_| Error::Io)?)
    {
        return Err(Error::Identity);
    }
    verify_sealed(&debt[target], size)?;
    remaining(until)?;
    Ok(target)
}
#[cfg(not(target_os = "linux"))]
fn snapshot_drive(
    _debt: &mut Vec<File>,
    _source_index: usize,
    _expected: &str,
    _size: u64,
    _until: Instant,
) -> Result<usize, Error> {
    Err(Error::Identity)
}
impl NativeGuestProfile {
    /// Closed root-owned mode600 descriptor, bounded before JSON allocation.
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !safe_path(path) {
            return Err(Error::Profile);
        }
        let mut file = protected(path, None, 16384, true, false)?;
        let before = file.metadata().map_err(|_| Error::Io)?;
        file.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
        let mut raw = Vec::new();
        (&mut file)
            .take(16385)
            .read_to_end(&mut raw)
            .map_err(|_| Error::Io)?;
        if raw.len() as u64 != before.len()
            || identity(&before) != identity(&file.metadata().map_err(|_| Error::Io)?)
            || identity(&before)
                != identity(&std::fs::symlink_metadata(path).map_err(|_| Error::Io)?)
        {
            return Err(Error::Identity);
        }
        let mut profile: Self = serde_json::from_slice(&raw).map_err(|_| Error::Profile)?;
        profile.validate()?;
        let policy = serde_json::to_vec(&profile).map_err(|_| Error::Profile)?;
        let anchors = capture_ancestors(path)?;
        let source = ProfileSource {
            sha256: format!("{:x}", Sha256::digest(&raw)),
            path: path.to_owned(),
            file: std::sync::Arc::new(file),
            original: before,
            policy,
            anchors,
        };
        source.verify()?;
        profile.source = Some(std::sync::Arc::new(source));
        Ok(profile)
    }
    pub(crate) fn verify_reserved_source(&self, path: &Path, sha: &str) -> Result<(), Error> {
        let source = self.source.as_ref().ok_or(Error::Identity)?;
        source.verify()?;
        if source.path != path || source.sha256 != sha {
            return Err(Error::Identity);
        }
        Ok(())
    }
    /// Expensive admission belongs in a bounded blocking owner before effects.
    /// Retain these actual descriptors until FC configuration and readiness finish.
    #[cfg(test)]
    pub(crate) fn admit_inputs(&self) -> Result<NativeInputs, Error> {
        let mut debt = Vec::new();
        self.capture_inputs(Instant::now() + Duration::from_secs(30), &mut debt)
    }
    fn capture_inputs(&self, until: Instant, debt: &mut Vec<File>) -> Result<NativeInputs, Error> {
        self.validate()?;
        let source = self.source.as_ref().ok_or(Error::Identity)?;
        source.verify()?;
        if serde_json::to_vec(self).map_err(|_| Error::Profile)? != source.policy {
            return Err(Error::Identity);
        }
        remaining(until)?;
        let roles = [
            (
                &self.rootfs_path,
                &self.rootfs_sha256,
                512 * 1024 * 1024,
                false,
                false,
            ),
            (
                &self.config_path,
                &self.config_sha256,
                4 * 1024 * 1024,
                false,
                false,
            ),
            (
                &self.kernel_path,
                &self.kernel_sha256,
                29862336,
                false,
                false,
            ),
            (
                &self.readiness_executable,
                &self.readiness_sha256,
                64 * 1024 * 1024,
                false,
                true,
            ),
            (
                &self.vmm_executable,
                &self.vmm_sha256,
                64 * 1024 * 1024,
                false,
                true,
            ),
            (
                &self.credential_path,
                &self.credential_sha256,
                8192,
                true,
                false,
            ),
        ];
        // Reserved capacity is fixed before any capture; each role has <=32 ancestors.
        debt.try_reserve(198).map_err(|_| Error::Io)?;
        let mut indices = [0usize; 6];
        let mut anchor_names = Vec::new();
        anchor_names.try_reserve(192).map_err(|_| Error::Io)?;
        let mut pins = Vec::new();
        pins.try_reserve(7).map_err(|_| Error::Io)?;
        pins.push((source.path.clone(), source.original.clone()));
        for (index, (path, digest, cap, private, executable)) in roles.iter().enumerate() {
            remaining(until)?;
            capture_ancestors_into(path, until, debt, &mut anchor_names)?;
            let file = open_protected(path, *cap, *private, *executable)?;
            indices[index] = debt.len();
            debt.push(file); // Install custody before hashing or any failure boundary.
            verify_digest(&mut debt[indices[index]], path, Some(digest), *cap, until)?;
            pins.push((
                (*path).clone(),
                debt[indices[index]].metadata().map_err(|_| Error::Io)?,
            ));
            if index < 3
                && debt[indices[index]]
                    .metadata()
                    .map_err(|_| Error::Io)?
                    .len()
                    != *cap
            {
                return Err(Error::Identity);
            }
        }
        source.verify()?;
        remaining(until)?;
        let sealed_root = snapshot_drive(
            debt,
            indices[0],
            &self.rootfs_sha256,
            512 * 1024 * 1024,
            until,
        )?;
        let sealed_config = snapshot_drive(
            debt,
            indices[1],
            &self.config_sha256,
            4 * 1024 * 1024,
            until,
        )?;
        source.verify()?;
        let sealed_pins = [
            debt[sealed_root].metadata().map_err(|_| Error::Io)?,
            debt[sealed_config].metadata().map_err(|_| Error::Io)?,
        ];
        let config_snapshot = debt.remove(sealed_config);
        let root_snapshot = debt.remove(sealed_root);
        // Remove role descriptors backwards; remaining descriptors are ancestor anchors.
        let credential = debt.remove(indices[5]);
        let vmm = debt.remove(indices[4]);
        let probe = debt.remove(indices[3]);
        let kernel = debt.remove(indices[2]);
        let config = debt.remove(indices[1]);
        let rootfs = debt.remove(indices[0]);
        let anchors = anchor_names.into_iter().zip(std::mem::take(debt)).collect();
        let inputs = NativeInputs {
            profile: source.file.clone(),
            anchors,
            pins,
            profile_ancestors: source.anchors.len(),
            sealed_pins,
            sealed_hashes: [self.rootfs_sha256.clone(), self.config_sha256.clone()],
            rootfs: root_snapshot,
            config: config_snapshot,
            source_drives: [rootfs, config],
            sealed_sizes: [512 * 1024 * 1024, 4 * 1024 * 1024],
            credential_sha256: self.credential_sha256.clone(),
            kernel,
            probe,
            vmm,
            credential,
        };
        Ok(inputs)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.features.len() > 1 {
            return Err(Error::Profile);
        }
        let namespace = self.config_path.parent().ok_or(Error::Profile)?;
        let raw = namespace.to_str().ok_or(Error::Profile)?;
        let nonce = raw
            .strip_prefix("/srv/codex-guest-416/")
            .ok_or(Error::Profile)?;
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.config_path != namespace.join("config.ext4")
            || self.rootfs_path != namespace.join("image/rootfs.ext4")
            || self.credential_path != namespace.join("native-image-identity.json")
            || self.readiness_executable != namespace.join("rust-guest-ready")
            || self.kernel_sha256
                != "3fe503e7b89a2b28da1d48c5973914f148a99f05e181fd8e904a73bf624a4686"
        {
            return Err(Error::Profile);
        }
        if self.guest_cid < 3
            || self.guest_cid == u32::MAX
            || !identifier(&self.node_id)
            || !identifier(&self.owner_id)
            || !(1..1 << 63).contains(&self.generation)
            || self.vsock_filename != "native-guest.vsock"
            || self.vsock_filename.len() > 32
            || self.vsock_filename == "."
            || self.vsock_filename == ".."
            || !self
                .vsock_filename
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || ![
                &self.rootfs_path,
                &self.config_path,
                &self.credential_path,
                &self.readiness_executable,
                &self.kernel_path,
                &self.vmm_executable,
            ]
            .into_iter()
            .all(|path| safe_path(path))
            || ![
                &self.rootfs_sha256,
                &self.config_sha256,
                &self.kernel_sha256,
                &self.agent_sha256,
                &self.guest_nonce,
                &self.credential_sha256,
                &self.readiness_sha256,
                &self.vmm_sha256,
            ]
            .into_iter()
            .all(|value| hash(value))
            || self.rootfs_path == self.config_path
            || self.credential_path == self.rootfs_path
            || self.credential_path == self.config_path
        {
            return Err(Error::Profile);
        }
        Ok(())
    }
    /// Consume this server-owned incarnation before any VMM launch effect.
    pub fn claim(&self) -> Result<(), Error> {
        use std::io::Write;
        self.validate()?;
        let namespace = self.config_path.parent().ok_or(Error::Profile)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(namespace.join("agentenv-attempted"))
            .map_err(|_| Error::Identity)?;
        file.write_all(b"native-agentenv/1\n")
            .map_err(|_| Error::Io)?;
        file.sync_all().map_err(|_| Error::Io)?;
        File::open(namespace)
            .map_err(|_| Error::Io)?
            .sync_all()
            .map_err(|_| Error::Io)?;
        Ok(())
    }
    pub fn vsock_path(&self, owned_work_dir: &Path) -> Result<PathBuf, Error> {
        self.validate()?;
        if !safe_path(owned_work_dir) {
            return Err(Error::Profile);
        }
        let path = owned_work_dir.join(&self.vsock_filename);
        if path.as_os_str().len() >= 108 {
            return Err(Error::Profile);
        }
        Ok(path)
    }
    /// Call only after this exact owned VMM has been configured and started.
    /// Probe exits0 only after CONNECT19721 and full authenticated READY matching
    /// every supplied fence. It produces no public output and never certifies
    /// physical absence, task completion, or snapshot compatibility.
    pub async fn wait_for_ready(
        &self,
        owned_work_dir: &Path,
        vmm_pid: u32,
        vmm_uid: u32,
        expires: Instant,
        owner: &NativeProbeOwner,
    ) -> Result<(), Error> {
        if vmm_pid == 0 {
            return Err(Error::Identity);
        }
        let path = self.vsock_path(owned_work_dir)?;
        let framing = crate::sandbox::native_process::NativeFraming::new(
            &self.node_id,
            &self.owner_id,
            self.generation,
            &self.guest_nonce,
        )
        .map_err(|_| Error::Profile)?;
        let until = (Instant::now() + Duration::from_secs(30)).min(expires);
        remaining(until)?;
        let probe = protected(
            &self.readiness_executable,
            Some(&self.readiness_sha256),
            64 * 1024 * 1024,
            false,
            true,
        )?;
        let _credential = protected(
            &self.credential_path,
            Some(&self.credential_sha256),
            8192,
            true,
            false,
        )?;
        remaining(until)?;
        let mut command =
            tokio::process::Command::new(format!("/proc/self/fd/{}", probe.as_raw_fd()));
        command
            .arg("--broker")
            .arg("--boot-budget-ms")
            .arg("30000")
            .arg("--identity")
            .arg(&self.credential_path)
            .arg("--socket")
            .arg(path)
            .arg("--peer-pid")
            .arg(vmm_pid.to_string())
            .arg("--peer-uid")
            .arg(vmm_uid.to_string())
            .arg("--node-id")
            .arg(&self.node_id)
            .arg("--owner-id")
            .arg(&self.owner_id)
            .arg("--generation")
            .arg(self.generation.to_string())
            .arg("--guest-nonce")
            .arg(&self.guest_nonce)
            .arg("--kernel-sha256")
            .arg(&self.kernel_sha256)
            .arg("--rootfs-sha256")
            .arg(&self.rootfs_sha256)
            .arg("--agent-sha256")
            .arg(&self.agent_sha256)
            .arg("--budget-ms")
            .arg(remaining(expires)?.as_millis().min(240000).to_string())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut held = owner.flight.lock().await;
        if held.is_some() {
            return if owner.client().is_some() {
                Ok(())
            } else {
                Err(Error::Probe)
            };
        }
        // Waiting for another owner must not permit effects after this deadline.
        remaining(until)?;
        *held = Some(command.spawn().map_err(|_| Error::Io)?);
        let child = held.as_mut().ok_or(Error::Probe)?;
        let input = child.stdin.take().ok_or(Error::Probe)?;
        let output = child.stdout.take().ok_or(Error::Probe)?;
        let mut reader = tokio::io::BufReader::new(output);
        let mut carry = Vec::new();
        let ready = tokio::time::timeout_at(
            tokio::time::Instant::from_std(until),
            crate::sandbox::native_process::read_line(&mut reader, &mut carry),
        )
        .await;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ready {
            kind: String,
        }
        let authenticated = matches!(ready, Ok(Ok(ref line)) if serde_json::from_slice::<Ready>(line).is_ok_and(|r| r.kind == "ready"));
        if authenticated && remaining(until).is_ok() {
            // Directory custody is optional and proves no disk allocation.
            // Unavailable downloads do not change authenticated Exec readiness.
            let download_spool = self.config_path.parent().and_then(|namespace| {
                crate::sandbox::native_download::NativeDownloadSpool::admit(namespace).ok()
            });
            let client =
                crate::sandbox::native_process::NativeClient::install_authenticated_profile(
                    reader,
                    input,
                    expires,
                    framing,
                    download_spool,
                    self.agent_sha256.clone(),
                    self.features.contains(&NativeFeature::DirectoryV1),
                );
            owner.client.set(client).map_err(|_| Error::Probe)?;
            return Ok(());
        }
        let _ = child.start_kill();
        if matches!(
            tokio::time::timeout(Duration::from_secs(2), child.wait()).await,
            Ok(Ok(_))
        ) {
            held.take();
        }
        Err(Error::Probe)
    }
}
fn remaining(until: Instant) -> Result<Duration, Error> {
    until
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(Error::Deadline)
}
fn identity(info: &std::fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        info.dev(),
        info.ino(),
        info.mode(),
        info.uid(),
        info.gid(),
        info.nlink(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    )
}
struct ProfileSource {
    sha256: String,
    path: PathBuf,
    file: std::sync::Arc<File>,
    original: std::fs::Metadata,
    policy: Vec<u8>,
    anchors: Vec<(PathBuf, File)>,
}
impl ProfileSource {
    fn verify(&self) -> Result<(), Error> {
        verify_small_content(&self.file, &self.sha256, 16384)?;
        if identity(&self.original) != identity(&self.file.metadata().map_err(|_| Error::Io)?)
            || identity(&self.original)
                != identity(&std::fs::symlink_metadata(&self.path).map_err(|_| Error::Identity)?)
        {
            return Err(Error::Identity);
        }
        for (path, held) in &self.anchors {
            verify_directory(path, held)?;
        }
        Ok(())
    }
}
fn directory_identity(info: &std::fs::Metadata) -> (u64, u64, u32, u32, u32) {
    (info.dev(), info.ino(), info.mode(), info.uid(), info.gid())
}
fn verify_directory(path: &Path, held: &File) -> Result<(), Error> {
    let named = std::fs::symlink_metadata(path).map_err(|_| Error::Identity)?;
    let info = held.metadata().map_err(|_| Error::Io)?;
    if !info.is_dir()
        || info.uid() != 0
        || info.gid() != 0
        || info.mode() & 0o022 != 0
        || directory_identity(&named) != directory_identity(&info)
    {
        return Err(Error::Identity);
    }
    Ok(())
}
fn capture_ancestors_into(
    path: &Path,
    until: Instant,
    debt: &mut Vec<File>,
    names: &mut Vec<PathBuf>,
) -> Result<(), Error> {
    if !safe_path(path) {
        return Err(Error::Identity);
    }
    let mut ancestor = PathBuf::from("/");
    let mut count = 0;
    for component in path.parent().ok_or(Error::Identity)?.components() {
        remaining(until)?;
        if let std::path::Component::Normal(part) = component {
            ancestor.push(part);
        }
        count += 1;
        if count > 32 {
            return Err(Error::Identity);
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY)
            .open(&ancestor)
            .map_err(|_| Error::Identity)?;
        debt.push(held); // Capture custody before any fstat/named verification.
        names.push(ancestor.clone());
        verify_directory(&ancestor, debt.last().ok_or(Error::Identity)?)?;
    }
    remaining(until)?;
    Ok(())
}
fn capture_ancestors(path: &Path) -> Result<Vec<(PathBuf, File)>, Error> {
    if !safe_path(path) {
        return Err(Error::Identity);
    }
    let mut anchors = Vec::new();
    let mut ancestor = PathBuf::from("/");
    for component in path.parent().ok_or(Error::Identity)?.components() {
        if let std::path::Component::Normal(part) = component {
            ancestor.push(part);
        }
        if anchors.len() >= 32 {
            return Err(Error::Identity);
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY)
            .open(&ancestor)
            .map_err(|_| Error::Identity)?;
        verify_directory(&ancestor, &held)?;
        anchors.push((ancestor.clone(), held));
    }
    Ok(anchors)
}
fn open_protected(path: &Path, limit: u64, private: bool, executable: bool) -> Result<File, Error> {
    let named = std::fs::symlink_metadata(path).map_err(|_| Error::Identity)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Io)?;
    let before = file.metadata().map_err(|_| Error::Io)?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > limit
        || identity(&named) != identity(&before)
        || (private && before.mode() & 0o7777 != 0o600)
        || (executable && before.mode() & 0o111 == 0)
    {
        return Err(Error::Identity);
    }
    Ok(file)
}
fn verify_digest(
    file: &mut File,
    path: &Path,
    expected: Option<&str>,
    limit: u64,
    until: Instant,
) -> Result<(), Error> {
    remaining(until)?;
    let before = file.metadata().map_err(|_| Error::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        remaining(until)?;
        let n = file.read(&mut buffer).map_err(|_| Error::Io)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or(Error::Identity)?;
        if count > limit || count > before.len() {
            return Err(Error::Identity);
        }
        digest.update(&buffer[..n]);
    }
    if count != before.len()
        || expected.is_some_and(|v| format!("{:x}", digest.finalize()) != v)
        || identity(&before) != identity(&file.metadata().map_err(|_| Error::Io)?)
        || identity(&before)
            != identity(&std::fs::symlink_metadata(path).map_err(|_| Error::Identity)?)
    {
        return Err(Error::Identity);
    }
    remaining(until)?;
    Ok(())
}
fn protected(
    path: &Path,
    expected: Option<&str>,
    limit: u64,
    private: bool,
    executable: bool,
) -> Result<File, Error> {
    let anchors = capture_ancestors(path)?;
    let mut file = open_protected(path, limit, private, executable)?;
    verify_digest(
        &mut file,
        path,
        expected,
        limit,
        Instant::now() + Duration::from_secs(30),
    )?;
    for (path, held) in anchors {
        verify_directory(&path, &held)?;
    }
    Ok(file)
}

#[cfg(test)]
mod feature_policy_red_tests {
    use super::*;
    fn legacy_profile() -> serde_json::Value {
        let root = "/srv/codex-guest-416/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        serde_json::json!({
            "rootfs_path":format!("{root}/image/rootfs.ext4"),"rootfs_sha256":"1".repeat(64),
            "config_path":format!("{root}/config.ext4"),"config_sha256":"2".repeat(64),
            "kernel_path":"/usr/local/lib/native/kernel","kernel_sha256":"3".repeat(64),
            "agent_sha256":"4".repeat(64),"node_id":"node","owner_id":"owner","generation":1,
            "guest_nonce":"5".repeat(64),"guest_cid":3,"vsock_filename":"native-guest.vsock",
            "credential_path":format!("{root}/native-image-identity.json"),"credential_sha256":"6".repeat(64),
            "readiness_executable":"/usr/local/lib/native/rust-guest-ready","readiness_sha256":"7".repeat(64),
            "vmm_executable":"/usr/local/lib/native/firecracker","vmm_sha256":"8".repeat(64)
        })
    }
    #[test]
    fn native_profile_directory_feature_is_closed_and_preserves_original_artifact_pins() {
        let legacy = legacy_profile();
        let mut declared = legacy.clone();
        declared["features"] = serde_json::json!(["directory-v1"]);
        let profile: NativeGuestProfile = serde_json::from_value(declared)
            .expect("known optional directory feature must decode without changing fences");
        let output = serde_json::to_value(profile).unwrap();
        assert_eq!(output["features"], serde_json::json!(["directory-v1"]));
        for key in [
            "agent_sha256",
            "kernel_sha256",
            "rootfs_sha256",
            "config_sha256",
            "node_id",
            "owner_id",
            "generation",
            "guest_nonce",
        ] {
            assert_eq!(output[key], legacy[key]);
        }
    }
    #[test]
    fn native_profile_absent_features_is_core_only_and_unknown_or_duplicate_refuses() {
        let legacy = legacy_profile();
        let profile: NativeGuestProfile = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(profile).unwrap()["features"],
            serde_json::json!([])
        );
        for features in [
            serde_json::json!(["unknown-v1"]),
            serde_json::json!(["directory-v1", "directory-v1"]),
            serde_json::json!("directory-v1"),
            serde_json::json!([1]),
            serde_json::json!(null),
            serde_json::json!({"directory-v1":true}),
        ] {
            let mut value = legacy.clone();
            value["features"] = features;
            assert!(serde_json::from_value::<NativeGuestProfile>(value).is_err());
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "native_artifact_tests.rs"]
mod artifact_tests;

#[cfg(test)]
#[derive(Default)]
struct ObservedCaptureWorker {
    flight: Option<tokio::task::JoinHandle<Result<std::sync::Arc<NativeInputs>, Error>>>,
    completed: bool,
}
/// One immutable imported bundle; capture clock is sealed at backend construction.
/// Retained truth survives expiry, but expiry never permits a new capture or start.
struct CaptureDebt {
    attempted: bool,
    descriptors: Vec<File>,
    completed: Option<std::sync::Arc<NativeInputs>>,
}
pub(crate) struct NativeArtifactDescriptor {
    profile: NativeGuestProfile,
    until: Instant,
    captured: std::sync::OnceLock<std::sync::Arc<NativeInputs>>,
    partial: std::sync::Mutex<CaptureDebt>,
    #[cfg(test)]
    observed_worker: tokio::sync::Mutex<ObservedCaptureWorker>,
}
impl fmt::Debug for NativeArtifactDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeArtifactDescriptor")
            .field("captured", &self.captured.get().is_some())
            .finish_non_exhaustive()
    }
}
impl NativeArtifactDescriptor {
    pub(crate) const FD_TICKET: usize = 233; // 7 roles plus <=32 ancestors per role.
    pub(crate) fn new(profile: NativeGuestProfile) -> Result<std::sync::Arc<Self>, Error> {
        Self::new_until(profile, Instant::now() + Duration::from_secs(30))
    }
    pub(crate) fn new_until(
        profile: NativeGuestProfile,
        expires: Instant,
    ) -> Result<std::sync::Arc<Self>, Error> {
        let until = expires.min(Instant::now() + Duration::from_secs(30));
        remaining(until)?;
        profile.validate()?;
        let source = profile.source.as_ref().ok_or(Error::Identity)?;
        source.verify()?;
        if serde_json::to_vec(&profile).map_err(|_| Error::Profile)? != source.policy {
            return Err(Error::Identity);
        }
        Ok(std::sync::Arc::new(Self {
            profile,
            until,
            captured: std::sync::OnceLock::new(),
            #[cfg(test)]
            observed_worker: tokio::sync::Mutex::new(ObservedCaptureWorker::default()),
            partial: std::sync::Mutex::new(CaptureDebt {
                attempted: false,
                descriptors: Vec::new(),
                completed: None,
            }),
        }))
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        match (&self.profile.source, &other.profile.source) {
            (Some(a), Some(b)) => {
                a.path == b.path
                    && identity(&a.original) == identity(&b.original)
                    && a.policy == b.policy
                    && a.sha256 == b.sha256
            }
            _ => false,
        }
    }
    pub(crate) fn same_namespace(&self, other: &Self) -> bool {
        self.profile.config_path == other.profile.config_path
    }
    pub(crate) fn capture(&self) -> Result<std::sync::Arc<NativeInputs>, Error> {
        let mut partial = self.partial.try_lock().map_err(|_| Error::Identity)?;
        if let Some(inputs) = self.captured.get() {
            self.profile
                .source
                .as_ref()
                .ok_or(Error::Identity)?
                .verify()?;
            inputs.verify()?;
            return Ok(inputs.clone());
        }
        if partial.attempted {
            return Err(Error::Identity);
        }
        partial.attempted = true; // A failed/abandoned original is a permanent capture tombstone.
        let inputs = std::sync::Arc::new(
            self.profile
                .capture_inputs(self.until, &mut partial.descriptors)?,
        );
        partial.completed = Some(inputs.clone()); // Final validation failure retains all actual role descriptors.
        if inputs.descriptor_count() > Self::FD_TICKET {
            return Err(Error::Identity);
        }
        inputs.verify()?;
        remaining(self.until)?;
        self.captured
            .set(inputs.clone())
            .map_err(|_| Error::Identity)?;
        partial.completed.take();
        Ok(inputs)
    }
    // Test-only ownership instrumentation of the actual capture worker, never an admission setter.
    #[cfg(test)]
    pub(crate) async fn observed_capture(
        self: std::sync::Arc<Self>,
    ) -> Result<std::sync::Arc<NativeInputs>, Error> {
        let mut worker = self.observed_worker.lock().await;
        if worker.completed {
            return self.capture();
        } // Existing capture verification/refusal only, no new role capture.
        if worker.flight.is_none() {
            let owner = self.clone();
            worker.flight = Some(tokio::task::spawn_blocking(move || owner.capture()));
        }
        let result = worker.flight.as_mut().ok_or(Error::Identity)?.await;
        worker.flight.take();
        worker.completed = true;
        result.map_err(|_| Error::Identity)?
    }
    #[cfg(test)]
    async fn join_observed_capture(&self) -> Result<(), Error> {
        let mut worker = self.observed_worker.lock().await;
        if let Some(flight) = worker.flight.as_mut() {
            let result = flight.await;
            worker.flight.take();
            worker.completed = true;
            // Drop the actual returned Arc/result before declaring worker custody retired.
            drop(result);
            return Ok(());
        }
        if worker.completed {
            Ok(())
        } else {
            Err(Error::Identity)
        }
    }
    pub(crate) fn is_captured(&self) -> bool {
        self.captured.get().is_some()
    }
    pub(crate) fn verify_captured(&self) -> Result<(), Error> {
        self.profile
            .source
            .as_ref()
            .ok_or(Error::Identity)?
            .verify()?;
        self.captured.get().ok_or(Error::Identity)?.verify()
    }
    pub(crate) fn admitted(&self) -> Result<std::sync::Arc<NativeInputs>, Error> {
        remaining(self.until)?;
        let source = self.profile.source.as_ref().ok_or(Error::Identity)?;
        source.verify()?;
        let inputs = self.captured.get().cloned().ok_or(Error::Identity)?;
        inputs.verify()?;
        remaining(self.until)?;
        Ok(inputs)
    }
}
impl NativeInputs {
    pub(crate) fn descriptor_count(&self) -> usize {
        9 + self.anchors.len() + self.profile_ancestors
    }
    pub(crate) fn verify(&self) -> Result<(), Error> {
        if identity(&self.sealed_pins[0])
            != identity(&self.rootfs.metadata().map_err(|_| Error::Io)?)
            || identity(&self.sealed_pins[1])
                != identity(&self.config.metadata().map_err(|_| Error::Io)?)
        {
            return Err(Error::Identity);
        }
        verify_sealed(&self.rootfs, self.sealed_sizes[0])?;
        verify_sealed(&self.config, self.sealed_sizes[1])?;
        verify_small_content(&self.credential, &self.credential_sha256, 8192)?;
        for (path, held) in &self.anchors {
            verify_directory(path, held)?;
        }
        let roles = [
            &*self.profile,
            &self.source_drives[0],
            &self.source_drives[1],
            &self.kernel,
            &self.probe,
            &self.vmm,
            &self.credential,
        ];
        for ((path, original), held) in self.pins.iter().zip(roles) {
            if identity(original) != identity(&held.metadata().map_err(|_| Error::Io)?)
                || identity(original)
                    != identity(&std::fs::symlink_metadata(path).map_err(|_| Error::Identity)?)
            {
                return Err(Error::Identity);
            }
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod sealed_drive_tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    #[test]
    fn sealed_snapshot_rejects_writes_and_survives_mutable_source_change() {
        let source = File::from(
            nix::sys::memfd::memfd_create(
                c"snapshot-source",
                nix::sys::memfd::MFdFlags::MFD_CLOEXEC,
            )
            .unwrap(),
        );
        let bytes = [7u8; 16384];
        source.write_all_at(&bytes, 0).unwrap();
        let mut debt = vec![source];
        let hash = format!("{:x}", Sha256::digest(bytes));
        let index = snapshot_drive(
            &mut debt,
            0,
            &hash,
            16384,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(debt[index].write_all_at(&[9], 0).is_err());
        assert!(debt[index].set_len(0).is_err());
        debt[0].write_all_at(&[9], 0).unwrap();
        verify_sealed(&debt[index], 16384).unwrap();
        let mut actual = [0u8; 16384];
        debt[index].read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, bytes);
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "native_sealed_fullsize_tests.rs"]
mod sealed_fullsize_tests;
