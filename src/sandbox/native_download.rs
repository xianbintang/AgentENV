//! Captured root-private download namespace. Directory admission alone is not
//! proof of disk backing, file retention, guest completion or VM absence.
use std::{
    fs::File,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DownloadError {
    Unavailable,
    Identity,
    Io,
    Capacity,
    Backing,
    Cleanup,
}
const MAX_DIRECTORY_OWNERS: usize = 32;
static DIRECTORY_OWNERS: AtomicUsize = AtomicUsize::new(0);
struct DirectorySlot;
impl DirectorySlot {
    fn reserve() -> Result<Self, DownloadError> {
        DIRECTORY_OWNERS
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < MAX_DIRECTORY_OWNERS).then_some(count + 1)
            })
            .map_err(|_| DownloadError::Unavailable)?;
        Ok(Self)
    }
}
impl Drop for DirectorySlot {
    fn drop(&mut self) {
        DIRECTORY_OWNERS.fetch_sub(1, Ordering::SeqCst);
    }
}
static DISK_QUOTA: LazyLock<Arc<Mutex<u64>>> = LazyLock::new(|| Arc::new(Mutex::new(0)));
/// Opaque namespace capability; only the admitted profile supplies this path.
pub(crate) struct NativeDownloadSpool {
    namespace: Option<File>,
    directory: Option<File>,
    _ancestors: Vec<File>,
    _quota: Arc<Mutex<u64>>,
    slot: Option<DirectorySlot>,
    path: std::path::PathBuf,
}
struct DirectoryDebt {
    _parent: File,
    _directory: Option<File>,
    _identity: Option<(u64, u64)>,
    _slot: DirectorySlot,
}
static DIRECTORY_DEBTS: Mutex<Vec<DirectoryDebt>> = Mutex::new(Vec::new());

impl NativeDownloadSpool {
    pub(crate) fn admit(namespace: &Path) -> Result<Arc<Self>, DownloadError> {
        #[cfg(target_os = "linux")]
        {
            Self::admit_linux(namespace)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = namespace;
            Err(DownloadError::Unavailable)
        }
    }
    #[cfg(target_os = "linux")]
    fn admit_linux(namespace: &Path) -> Result<Arc<Self>, DownloadError> {
        Self::admit_linux_inner(namespace, |_| {})
    }
    #[cfg(target_os = "linux")]
    fn admit_linux_inner(
        namespace: &Path,
        after_created: impl FnOnce(&File),
    ) -> Result<Arc<Self>, DownloadError> {
        use nix::{
            fcntl::AtFlags,
            fcntl::{open, openat, OFlag},
            sys::stat::{fstat, fstatat, mkdirat, Mode},
        };
        use std::{os::unix::fs::MetadataExt, path::Component};
        if nix::unistd::geteuid().as_raw() != 0 || nix::unistd::getegid().as_raw() != 0 {
            return Err(DownloadError::Unavailable);
        }
        if !namespace.is_absolute()
            || namespace.as_os_str().len() > 4096
            || namespace.components().count() > 33
            || namespace
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(DownloadError::Identity);
        }
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let root =
            File::from(open("/", flags, Mode::empty()).map_err(|_| DownloadError::Identity)?);
        let root_info = root.metadata().map_err(|_| DownloadError::Io)?;
        if root_info.uid() != 0 || root_info.gid() != 0 || root_info.mode() & 0o022 != 0 {
            return Err(DownloadError::Identity);
        }
        let mut ancestors = vec![root];
        for part in namespace.components() {
            let Component::Normal(name) = part else {
                continue;
            };
            let parent = ancestors.last().expect("root directory");
            let directory = File::from(
                openat(parent, name, flags, Mode::empty()).map_err(|_| DownloadError::Identity)?,
            );
            let held = fstat(&directory).map_err(|_| DownloadError::Io)?;
            let named = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| DownloadError::Identity)?;
            if held.st_dev != named.st_dev
                || held.st_ino != named.st_ino
                || held.st_uid != 0
                || held.st_gid != 0
                || held.st_mode & 0o022 != 0
            {
                return Err(DownloadError::Identity);
            }
            ancestors.push(directory);
        }
        let parent = ancestors.pop().ok_or(DownloadError::Identity)?;
        let info = parent.metadata().map_err(|_| DownloadError::Io)?;
        if info.uid() != 0 || info.gid() != 0 || info.mode() & 0o7777 != 0o700 {
            return Err(DownloadError::Identity);
        }
        let slot = DirectorySlot::reserve()?;
        if let Err(error) = mkdirat(&parent, "native-downloads", Mode::from_bits_truncate(0o700)) {
            if error != nix::errno::Errno::EEXIST {
                retain_or_remove_empty(parent, None, None, slot);
            }
            return Err(DownloadError::Identity);
        }
        let created = fstatat(&parent, "native-downloads", AtFlags::AT_SYMLINK_NOFOLLOW)
            .ok()
            .map(|stat| (stat.st_dev, stat.st_ino));
        after_created(&parent);
        let directory = match openat(&parent, "native-downloads", flags, Mode::empty()) {
            Ok(fd) => File::from(fd),
            Err(_) => {
                retain_or_remove_empty(parent, None, created, slot);
                return Err(DownloadError::Io);
            }
        };
        let held = directory.metadata().map_err(|_| DownloadError::Io);
        let named = fstatat(&parent, "native-downloads", AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| DownloadError::Identity);
        match (held, named) {
            (Ok(held), Ok(named))
                if created == Some((held.dev(), held.ino()))
                    && held.is_dir()
                    && held.uid() == 0
                    && held.gid() == 0
                    && held.mode() & 0o7777 == 0o700
                    && held.dev() == named.st_dev
                    && held.ino() == named.st_ino => {}
            _ => {
                retain_or_remove_empty(parent, Some(directory), created, slot);
                return Err(DownloadError::Identity);
            }
        }
        Ok(Arc::new(Self {
            namespace: Some(parent),
            directory: Some(directory),
            _ancestors: ancestors,
            _quota: DISK_QUOTA.clone(),
            slot: Some(slot),
            path: namespace.to_path_buf(),
        }))
    }
}
#[cfg(target_os = "linux")]
fn retain_or_remove_empty(
    parent: File,
    directory: Option<File>,
    identity: Option<(u64, u64)>,
    slot: DirectorySlot,
) {
    let named = nix::sys::stat::fstatat(
        &parent,
        "native-downloads",
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    );
    use std::os::unix::fs::MetadataExt;
    let held = directory.as_ref().and_then(|file| file.metadata().ok());
    let owned = matches!((held,named),(Some(info),Ok(stat)) if identity==Some((info.dev(),info.ino())) && identity==Some((stat.st_dev,stat.st_ino)) && info.is_dir() && info.uid()==0 && info.gid()==0 && info.mode()&0o7777==0o700 && stat.st_uid==0 && stat.st_gid==0 && stat.st_mode&0o177777==0o40700);
    if !owned
        || nix::unistd::unlinkat(
            &parent,
            "native-downloads",
            nix::unistd::UnlinkatFlags::RemoveDir,
        )
        .is_err()
    {
        DIRECTORY_DEBTS
            .lock()
            .expect("download directory custody")
            .push(DirectoryDebt {
                _parent: parent,
                _directory: directory,
                _identity: identity,
                _slot: slot,
            });
    }
}
impl Drop for NativeDownloadSpool {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(parent) = self.namespace.take() {
            use std::os::unix::fs::MetadataExt;
            let directory = self.directory.take();
            let identity = directory
                .as_ref()
                .and_then(|file| file.metadata().ok())
                .map(|info| (info.dev(), info.ino()));
            retain_or_remove_empty(
                parent,
                directory,
                identity,
                self.slot.take().expect("directory slot"),
            );
        }
    }
}

const DISK_LIMIT: u64 = 32 * 1024 * 1024;
const MAX_ALLOCATIONS: usize = 32;
static BACKING_DEBTS: LazyLock<Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
static ALLOCATIONS: LazyLock<Mutex<std::collections::HashMap<String, Arc<AllocationOwner>>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
type FileVersion = (u64, u64, u64, i64, i64, i64, i64);
#[cfg(target_os = "linux")]
fn file_version(file: &File) -> Result<FileVersion, DownloadError> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata().map_err(|_| DownloadError::Io)?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}
struct AllocationOwner {
    spool: Arc<NativeDownloadSpool>,
    name: String,
    requested: u64,
    charge: Mutex<u64>,
    file: Mutex<Option<File>>,
    identity: Mutex<Option<(u64, u64)>>,
    pending: tokio::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), DownloadError>>>>,
    worker_result: Mutex<Option<Result<(), DownloadError>>>,
    job_installed: std::sync::atomic::AtomicBool,
    backed: std::sync::atomic::AtomicU64,
    cleaned: std::sync::atomic::AtomicBool,
    cleanup_guard: tokio::sync::Mutex<()>,
    pending_cleanup: tokio::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), DownloadError>>>>,
    pending_io: tokio::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), DownloadError>>>>,
    sealed: std::sync::atomic::AtomicBool,
    closing: std::sync::atomic::AtomicBool,
    sealed_version: Mutex<Option<FileVersion>>,
    readers: Mutex<usize>,
}
/// Exact allocation custody. Drop does not unlink or refund an uncertain owner.
pub(crate) struct NativeSpoolFile {
    owner: Arc<AllocationOwner>,
}
impl NativeDownloadSpool {
    #[cfg(target_os = "linux")]
    fn healthy(&self) -> Result<(), DownloadError> {
        use std::os::unix::fs::MetadataExt;
        let names: Vec<_> = self
            .path
            .components()
            .filter_map(|part| {
                if let std::path::Component::Normal(name) = part {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        let namespace = self.namespace.as_ref().ok_or(DownloadError::Identity)?;
        if names.len() != self._ancestors.len() {
            return Err(DownloadError::Identity);
        }
        let root = self
            ._ancestors
            .first()
            .ok_or(DownloadError::Identity)?
            .metadata()
            .map_err(|_| DownloadError::Io)?;
        if !root.is_dir() || root.uid() != 0 || root.gid() != 0 || root.mode() & 0o022 != 0 {
            return Err(DownloadError::Identity);
        }
        for (index, name) in names.iter().enumerate() {
            let parent = &self._ancestors[index];
            let held = if index + 1 < self._ancestors.len() {
                &self._ancestors[index + 1]
            } else {
                namespace
            };
            let info = held.metadata().map_err(|_| DownloadError::Io)?;
            let named =
                nix::sys::stat::fstatat(parent, *name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|_| DownloadError::Identity)?;
            if !info.is_dir()
                || info.uid() != 0
                || info.gid() != 0
                || info.mode() & 0o022 != 0
                || (info.dev(), info.ino()) != (named.st_dev, named.st_ino)
            {
                return Err(DownloadError::Identity);
            }
        }
        let info = namespace.metadata().map_err(|_| DownloadError::Io)?;
        if info.mode() & 0o7777 != 0o700 {
            return Err(DownloadError::Identity);
        }
        let directory = self.directory.as_ref().ok_or(DownloadError::Identity)?;
        let info = directory.metadata().map_err(|_| DownloadError::Io)?;
        let named = nix::sys::stat::fstatat(
            namespace,
            "native-downloads",
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| DownloadError::Identity)?;
        if !info.is_dir()
            || info.uid() != 0
            || info.gid() != 0
            || info.mode() & 0o7777 != 0o700
            || (info.dev(), info.ino()) != (named.st_dev, named.st_ino)
        {
            return Err(DownloadError::Identity);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> u64 {
        *self._quota.lock().expect("download disk quota")
    }
    #[cfg(test)]
    pub(crate) async fn allocate(
        self: &Arc<Self>,
        bytes: u64,
    ) -> Result<NativeSpoolFile, DownloadError> {
        self.allocate_inner(bytes, || {}).await
    }
    pub(crate) async fn allocate_inner(
        self: &Arc<Self>,
        bytes: u64,
        before_backing: impl FnOnce() + Send + 'static,
    ) -> Result<NativeSpoolFile, DownloadError> {
        if !cfg!(target_os = "linux") {
            return Err(DownloadError::Unavailable);
        }
        if bytes > DISK_LIMIT {
            return Err(DownloadError::Capacity);
        }
        let owner = {
            let mut registry = ALLOCATIONS.lock().expect("download allocation custody");
            if registry.len() >= MAX_ALLOCATIONS {
                return Err(DownloadError::Capacity);
            }
            let name = format!("{}.part", uuid::Uuid::now_v7());
            let owner = Arc::new(AllocationOwner {
                spool: self.clone(),
                name: name.clone(),
                requested: bytes,
                charge: Mutex::new(0),
                file: Mutex::new(None),
                identity: Mutex::new(None),
                pending: tokio::sync::Mutex::new(None),
                worker_result: Mutex::new(None),
                job_installed: std::sync::atomic::AtomicBool::new(false),
                backed: std::sync::atomic::AtomicU64::new(0),
                cleaned: std::sync::atomic::AtomicBool::new(false),
                cleanup_guard: tokio::sync::Mutex::new(()),
                pending_cleanup: tokio::sync::Mutex::new(None),
                pending_io: tokio::sync::Mutex::new(None),
                sealed: std::sync::atomic::AtomicBool::new(false),
                closing: std::sync::atomic::AtomicBool::new(false),
                sealed_version: Mutex::new(None),
                readers: Mutex::new(0),
            });
            match registry.entry(name) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(owner.clone());
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(DownloadError::Capacity);
                }
            }
            owner
        };
        let work = owner.clone();
        let job = tokio::task::spawn_blocking(move || work.allocate_blocking(before_backing));
        // Install synchronously before the first await. Cancellation leaves the
        // exact job, captured file and reservation in the independent registry.
        *owner.pending.try_lock().expect("new allocation job") = Some(job);
        owner.job_installed.store(true, Ordering::Release);
        match owner.join_worker().await {
            Ok(()) => Ok(NativeSpoolFile { owner }),
            Err(error) => {
                if owner.cleanup().await.is_err() {
                    return Err(DownloadError::Cleanup);
                }
                Err(error)
            }
        }
    }
    /// Owner-stop boundary: cleanup ALL registered allocations, including live
    /// published handles. This is not an automatic abandoned-owner sweep.
    pub(crate) async fn cleanup_pending(self: &Arc<Self>) -> Result<(), DownloadError> {
        let owners: Vec<_> = ALLOCATIONS
            .lock()
            .expect("download allocation custody")
            .values()
            .filter(|owner| Arc::ptr_eq(&owner.spool, self))
            .cloned()
            .collect();
        for owner in owners {
            owner.cleanup().await?;
        }
        Ok(())
    }
}
impl AllocationOwner {
    #[cfg(target_os = "linux")]
    fn allocate_blocking(&self, before_backing: impl FnOnce()) -> Result<(), DownloadError> {
        use nix::{
            fcntl::{fallocate, openat, FallocateFlags, OFlag},
            sys::{
                stat::Mode,
                statvfs::{fstatvfs, FsFlags},
            },
        };
        use std::os::unix::fs::MetadataExt;
        self.spool.healthy()?;
        let directory = self
            .spool
            .directory
            .as_ref()
            .ok_or(DownloadError::Identity)?;
        let fs = fstatvfs(directory).map_err(|_| DownloadError::Io)?;
        let granule = fs.fragment_size();
        if fs.flags().contains(FsFlags::ST_RDONLY) || granule == 0 {
            return Err(DownloadError::Backing);
        }
        let rounded = self
            .requested
            .checked_add(granule - 1)
            .ok_or(DownloadError::Capacity)?
            / granule
            * granule;
        let available = fs
            .blocks_available()
            .checked_mul(granule)
            .ok_or(DownloadError::Backing)?;
        if rounded > DISK_LIMIT || rounded > available {
            return Err(DownloadError::Capacity);
        }
        {
            let mut quota = self.spool._quota.lock().expect("download disk quota");
            if !BACKING_DEBTS
                .lock()
                .expect("download backing debt")
                .is_empty()
            {
                return Err(DownloadError::Backing);
            }
            let total = quota.checked_add(rounded).ok_or(DownloadError::Capacity)?;
            if total > DISK_LIMIT {
                return Err(DownloadError::Capacity);
            }
            *quota = total;
            *self.charge.lock().expect("download reservation") = rounded;
        }
        self.spool.healthy()?;
        let file = File::from(
            openat(
                directory,
                self.name.as_str(),
                OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_RDWR
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|_| DownloadError::Io)?,
        );
        *self.file.lock().expect("download file custody") = Some(file);
        let held = self.file.lock().expect("download file custody");
        let file = held.as_ref().expect("installed file");
        let info = file.metadata().map_err(|_| DownloadError::Io)?;
        *self.identity.lock().expect("download file identity") = Some((info.dev(), info.ino()));
        self.validate_file(file)?;
        before_backing();
        BACKING_DEBTS
            .lock()
            .expect("download backing debt")
            .insert(self.name.clone());
        if self.requested != 0 {
            fallocate(
                file,
                FallocateFlags::empty(),
                0,
                i64::try_from(self.requested).map_err(|_| DownloadError::Capacity)?,
            )
            .map_err(|_| DownloadError::Backing)?;
        }
        self.spool.healthy()?;
        self.validate_file(file)?;
        let info = file.metadata().map_err(|_| DownloadError::Io)?;
        let backed = info
            .blocks()
            .checked_mul(512)
            .ok_or(DownloadError::Backing)?;
        if info.len() != self.requested || backed < self.requested {
            return Err(DownloadError::Backing);
        }
        self.account_backing(backed)
    }
    fn account_backing(&self, backed: u64) -> Result<(), DownloadError> {
        // Observed backing belongs to this exact owner even on failure. Debt
        // blocks new admissions until actual cleanup joins and releases it.
        self.backed.store(backed, Ordering::Release);
        let mut quota = self.spool._quota.lock().expect("download disk quota");
        let mut charge = self.charge.lock().expect("download reservation");
        if backed > *charge {
            *quota = quota
                .checked_add(backed - *charge)
                .ok_or(DownloadError::Backing)?;
            *charge = backed;
        }
        if *quota > DISK_LIMIT {
            BACKING_DEBTS
                .lock()
                .expect("download backing debt")
                .insert(self.name.clone());
            return Err(DownloadError::Backing);
        }
        BACKING_DEBTS
            .lock()
            .expect("download backing debt")
            .remove(&self.name);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    fn allocate_blocking(&self, _before_backing: impl FnOnce()) -> Result<(), DownloadError> {
        Err(DownloadError::Unavailable)
    }
    #[cfg(target_os = "linux")]
    fn validate_file(&self, file: &File) -> Result<(), DownloadError> {
        use std::os::unix::fs::MetadataExt;
        let info = file.metadata().map_err(|_| DownloadError::Io)?;
        let directory = self
            .spool
            .directory
            .as_ref()
            .ok_or(DownloadError::Identity)?;
        let named = nix::sys::stat::fstatat(
            directory,
            self.name.as_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| DownloadError::Identity)?;
        if !info.is_file()
            || info.uid() != 0
            || info.gid() != 0
            || info.mode() & 0o7777 != 0o600
            || info.nlink() != 1
            || *self.identity.lock().expect("download file identity")
                != Some((info.dev(), info.ino()))
            || (
                info.dev(),
                info.ino(),
                info.uid(),
                info.gid(),
                info.mode(),
                info.nlink(),
            ) != (
                named.st_dev,
                named.st_ino,
                named.st_uid,
                named.st_gid,
                named.st_mode,
                named.st_nlink,
            )
        {
            return Err(DownloadError::Identity);
        }
        Ok(())
    }
    async fn join_worker(&self) -> Result<(), DownloadError> {
        if !self.job_installed.load(Ordering::Acquire) {
            return Err(DownloadError::Unavailable);
        }
        let mut pending = self.pending.lock().await;
        if let Some(job) = pending.as_mut() {
            let result = job.await.unwrap_or(Err(DownloadError::Io));
            *self.worker_result.lock().expect("download worker result") = Some(result);
            pending.take();
        }
        self.worker_result
            .lock()
            .expect("download worker result")
            .as_ref()
            .copied()
            .ok_or(DownloadError::Unavailable)?
    }
    async fn cleanup(self: &Arc<Self>) -> Result<(), DownloadError> {
        self.closing.store(true, Ordering::Release);
        let _serial = self.cleanup_guard.lock().await;
        if self.cleaned.load(Ordering::Acquire) {
            return Ok(());
        }
        // A worker error is not physical cleanup, but actual join is required.
        let _result = self.join_worker().await;
        if self.pending.lock().await.is_some() || !self.job_installed.load(Ordering::Acquire) {
            return Err(DownloadError::Cleanup);
        }
        let mut io = self.pending_io.lock().await;
        if let Some(job) = io.as_mut() {
            let _ = job.await;
            io.take();
        }
        drop(io);
        let mut pending = self.pending_cleanup.lock().await;
        if pending.is_none() {
            let owned = self.clone();
            *pending = Some(tokio::task::spawn_blocking(move || {
                owned.cleanup_blocking()
            }));
        }
        let result = pending
            .as_mut()
            .expect("installed cleanup job")
            .await
            .unwrap_or(Err(DownloadError::Cleanup));
        pending.take();
        result?;
        let mut quota = self.spool._quota.lock().expect("download disk quota");
        let mut charge = self.charge.lock().expect("download reservation");
        *quota = quota.checked_sub(*charge).ok_or(DownloadError::Cleanup)?;
        *charge = 0;
        BACKING_DEBTS
            .lock()
            .expect("download backing debt")
            .remove(&self.name);
        self.cleaned.store(true, Ordering::Release);
        let mut registry = ALLOCATIONS.lock().expect("download allocation custody");
        if registry
            .get(&self.name)
            .is_some_and(|current| Arc::ptr_eq(current, self))
        {
            registry.remove(&self.name);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn cleanup_blocking(&self) -> Result<(), DownloadError> {
        self.spool.healthy().map_err(|_| DownloadError::Cleanup)?;
        let readers = self.readers.lock().expect("download reader custody");
        if *readers != 0 {
            return Err(DownloadError::Cleanup);
        }
        let mut held = self.file.lock().expect("download file custody");
        if let Some(file) = held.as_ref() {
            self.validate_file(file)
                .map_err(|_| DownloadError::Cleanup)?;
            nix::unistd::unlinkat(
                self.spool
                    .directory
                    .as_ref()
                    .ok_or(DownloadError::Cleanup)?,
                self.name.as_str(),
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            )
            .map_err(|_| DownloadError::Cleanup)?;
            held.take();
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    fn cleanup_blocking(&self) -> Result<(), DownloadError> {
        Err(DownloadError::Unavailable)
    }
}
/// Tracked read-only lease. It never exposes or clones the underlying FD.
pub struct NativeDownloadReader {
    file: Option<File>,
    owner: Arc<AllocationOwner>,
}
impl std::io::Read for NativeDownloadReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(self.file.as_mut().expect("live download reader"), bytes)
    }
}
impl std::io::Seek for NativeDownloadReader {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        std::io::Seek::seek(self.file.as_mut().expect("live download reader"), position)
    }
}
impl Drop for NativeDownloadReader {
    fn drop(&mut self) {
        // Close the actual FD before allowing cleanup to refund disk quota.
        drop(self.file.take());
        let mut readers = self.owner.readers.lock().expect("download reader custody");
        *readers -= 1;
    }
}
impl NativeSpoolFile {
    #[cfg(test)]
    pub(crate) fn backed_bytes(&self) -> u64 {
        if self.owner.cleaned.load(Ordering::Acquire) {
            0
        } else {
            self.owner.backed.load(Ordering::Acquire)
        }
    }
    pub(crate) async fn write_chunk(
        &self,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DownloadError> {
        if bytes.len() > 16384
            || offset
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > self.owner.requested)
        {
            return Err(DownloadError::Capacity);
        }
        let mut pending = self.owner.pending_io.lock().await;
        if pending.is_some() {
            return Err(DownloadError::Unavailable);
        }
        let owned = self.owner.clone();
        *pending = Some(tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::FileExt;
                owned.spool.healthy()?;
                if owned.cleaned.load(Ordering::Acquire)
                    || owned.closing.load(Ordering::Acquire)
                    || owned.sealed.load(Ordering::Acquire)
                {
                    return Err(DownloadError::Identity);
                }
                let held = owned.file.lock().expect("download file custody");
                let file = held.as_ref().ok_or(DownloadError::Identity)?;
                owned.validate_file(file)?;
                let mut written = 0;
                while written < bytes.len() {
                    let count = file
                        .write_at(&bytes[written..], offset + written as u64)
                        .map_err(|_| DownloadError::Io)?;
                    if count == 0 {
                        return Err(DownloadError::Io);
                    }
                    written += count;
                }
                owned.spool.healthy()?;
                owned.validate_file(file)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (owned, bytes, offset);
                Err(DownloadError::Unavailable)
            }
        }));
        let result = pending
            .as_mut()
            .expect("installed download write")
            .await
            .unwrap_or(Err(DownloadError::Io));
        pending.take();
        result
    }
    pub(crate) async fn seal(
        &self,
        size: u64,
        expected_sha: &str,
        expires: std::time::Instant,
    ) -> Result<(), DownloadError> {
        if expected_sha.len() != 64
            || !expected_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DownloadError::Identity);
        }
        let expected_sha = expected_sha.to_owned();
        if size > self.owner.requested || self.owner.closing.load(Ordering::Acquire) {
            return Err(DownloadError::Capacity);
        }
        let mut pending = self.owner.pending_io.lock().await;
        if pending.is_some() {
            return Err(DownloadError::Unavailable);
        }
        let owned = self.owner.clone();
        *pending = Some(tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "linux")]
            {
                use sha2::{Digest, Sha256};
                use std::os::unix::fs::FileExt;
                let check_deadline = || {
                    if std::time::Instant::now() >= expires {
                        Err(DownloadError::Unavailable)
                    } else {
                        Ok(())
                    }
                };
                check_deadline()?;
                if owned.closing.load(Ordering::Acquire) || owned.sealed.load(Ordering::Acquire) {
                    return Err(DownloadError::Identity);
                }
                owned.spool.healthy()?;
                let held = owned.file.lock().expect("download file custody");
                let file = held.as_ref().ok_or(DownloadError::Identity)?;
                owned.validate_file(file)?;
                file.set_len(size).map_err(|_| DownloadError::Io)?;
                file.sync_data().map_err(|_| DownloadError::Io)?;
                check_deadline()?;
                owned.spool.healthy()?;
                owned.validate_file(file)?;
                let version = file_version(file)?;
                if version.2 != size {
                    return Err(DownloadError::Identity);
                }
                let verify = || -> Result<(), DownloadError> {
                    check_deadline()?;
                    owned.spool.healthy()?;
                    owned.validate_file(file)?;
                    if file_version(file)? != version {
                        return Err(DownloadError::Identity);
                    }
                    Ok(())
                };
                let mut buffer = [0u8; 16384];
                let mut offset = 0u64;
                let mut hash = Sha256::new();
                while offset < size {
                    verify()?;
                    let wanted = (size - offset).min(buffer.len() as u64) as usize;
                    let count = match file.read_at(&mut buffer[..wanted], offset) {
                        Ok(count) => count,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err(DownloadError::Io),
                    };
                    if count == 0 {
                        return Err(DownloadError::Identity);
                    }
                    verify()?;
                    hash.update(&buffer[..count]);
                    offset += count as u64;
                }
                verify()?;
                if file
                    .read_at(&mut buffer[..1], size)
                    .map_err(|_| DownloadError::Io)?
                    != 0
                {
                    return Err(DownloadError::Identity);
                }
                verify()?;
                if format!("{:x}", hash.finalize()) != expected_sha {
                    return Err(DownloadError::Identity);
                }
                *owned
                    .sealed_version
                    .lock()
                    .expect("download sealed version") = Some(version);
                owned.sealed.store(true, Ordering::Release);
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (owned, size, expected_sha, expires);
                Err(DownloadError::Unavailable)
            }
        }));
        let result = pending
            .as_mut()
            .expect("installed download seal")
            .await
            .unwrap_or(Err(DownloadError::Io));
        pending.take();
        result
    }
    pub(crate) fn open_read(&self) -> Result<NativeDownloadReader, DownloadError> {
        #[cfg(target_os = "linux")]
        {
            let mut readers = self.owner.readers.lock().expect("download reader custody");
            if *readers >= 32
                || !self.owner.sealed.load(Ordering::Acquire)
                || self.owner.closing.load(Ordering::Acquire)
                || self.owner.cleaned.load(Ordering::Acquire)
            {
                return Err(DownloadError::Identity);
            }
            self.owner.spool.healthy()?;
            // A named FIFO must not block before post-open validation. The
            // nonblocking open also closes replacement races after this check.
            let directory = self
                .owner
                .spool
                .directory
                .as_ref()
                .ok_or(DownloadError::Identity)?;
            let named = nix::sys::stat::fstatat(
                directory,
                self.owner.name.as_str(),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| DownloadError::Identity)?;
            if named.st_mode & 0o177777 != 0o100600
                || named.st_uid != 0
                || named.st_gid != 0
                || named.st_nlink != 1
                || *self.owner.identity.lock().expect("download file identity")
                    != Some((named.st_dev, named.st_ino))
            {
                return Err(DownloadError::Identity);
            }

            let file = File::from(
                nix::fcntl::openat(
                    self.owner
                        .spool
                        .directory
                        .as_ref()
                        .ok_or(DownloadError::Identity)?,
                    self.owner.name.as_str(),
                    nix::fcntl::OFlag::O_RDONLY
                        | nix::fcntl::OFlag::O_NONBLOCK
                        | nix::fcntl::OFlag::O_NOFOLLOW
                        | nix::fcntl::OFlag::O_CLOEXEC,
                    nix::sys::stat::Mode::empty(),
                )
                .map_err(|_| DownloadError::Identity)?,
            );
            self.owner.validate_file(&file)?;
            if *self
                .owner
                .sealed_version
                .lock()
                .expect("download sealed version")
                != Some(file_version(&file)?)
            {
                return Err(DownloadError::Identity);
            }
            *readers += 1;
            Ok(NativeDownloadReader {
                file: Some(file),
                owner: self.owner.clone(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(DownloadError::Unavailable)
        }
    }
    pub(crate) async fn cleanup(&self) -> Result<(), DownloadError> {
        self.owner.cleanup().await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    static DISK_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    #[cfg(target_os = "linux")]
    pub(crate) struct RootFixture {
        pub(crate) path: std::path::PathBuf,
        identity: (u64, u64),
    }
    #[cfg(target_os = "linux")]
    impl RootFixture {
        pub(crate) fn new() -> Option<Self> {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            if nix::unistd::geteuid().as_raw() != 0 || nix::unistd::getegid().as_raw() != 0 {
                return None;
            }
            let home = std::env::var_os("AENV_HOME_PATH")
                .expect("root fixture requires actual private AENV_HOME_PATH");
            let parent = std::path::PathBuf::from(home);
            let info = std::fs::symlink_metadata(&parent).unwrap();
            assert!(info.is_dir());
            assert_eq!(info.uid(), 0);
            assert_eq!(info.gid(), 0);
            assert_eq!(info.mode() & 0o7777, 0o700);
            let path = parent.join(format!("native-download-test-{}", uuid::Uuid::now_v7()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            let info = std::fs::symlink_metadata(&path).unwrap();
            Some(Self {
                path,
                identity: (info.dev(), info.ino()),
            })
        }
    }
    #[cfg(target_os = "linux")]
    impl Drop for RootFixture {
        fn drop(&mut self) {
            use std::os::unix::fs::MetadataExt;
            let info = std::fs::symlink_metadata(&self.path).unwrap();
            assert_eq!((info.dev(), info.ino()), self.identity);
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }
    #[test]
    fn native_download_root_unavailable_on_nonlinux_or_nonroot() {
        if !cfg!(target_os = "linux")
            || nix::unistd::geteuid().as_raw() != 0
            || nix::unistd::getegid().as_raw() != 0
        {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_download_root_captures_actual_protected_namespace_refuses_adoption() {
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        assert!(NativeDownloadSpool::admit(&fixture.path).is_err());
        drop(spool);
        assert!(!fixture.path.join("native-downloads").exists());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_download_root_refuses_symlink_and_nonprivate_namespace() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let link = fixture.path.join("link");
        symlink(&fixture.path, &link).unwrap();
        assert!(NativeDownloadSpool::admit(&link).is_err());
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(NativeDownloadSpool::admit(&fixture.path).is_err());
        assert!(!fixture.path.join("native-downloads").exists());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_download_created_inode_refuses_replacement_adoption_and_cleanup() {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let named = fixture.path.join("native-downloads");
        let captured = fixture.path.join("captured-directory");
        let result = NativeDownloadSpool::admit_linux_inner(&fixture.path, |_| {
            std::fs::rename(&named, &captured).unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&named)
                .unwrap();
        });
        assert!(matches!(result, Err(DownloadError::Identity)));
        assert!(named.is_dir());
        assert!(captured.is_dir());
        assert_ne!(
            std::fs::metadata(&named).unwrap().ino(),
            std::fs::metadata(&captured).unwrap().ino()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_download_drop_never_unlinks_foreign_named_directory() {
        use std::os::unix::fs::DirBuilderExt;
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let named = fixture.path.join("native-downloads");
        let captured = fixture.path.join("captured-directory");
        std::fs::rename(&named, &captured).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&named)
            .unwrap();
        drop(spool);
        assert!(named.is_dir());
        assert!(captured.is_dir());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_disk_quota_backing_refuses_before_effects_and_retains_exact_owner() {
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let allocation = spool.allocate(32 * 1024 * 1024).await.unwrap();
        assert!(spool.allocate(1).await.is_err());
        assert!(allocation.backed_bytes() >= 32 * 1024 * 1024);
        allocation.cleanup().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_multiple_allocations_share_actual_32m_quota_and_cleanup() {
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let first = spool.allocate(1024 * 1024).await.unwrap();
        let second = spool.allocate(1024 * 1024).await.unwrap();
        let rest = spool.allocate(30 * 1024 * 1024).await.unwrap();
        assert_eq!(spool.reserved_bytes(), DISK_LIMIT);
        assert!(spool.allocate(1).await.is_err());
        assert_eq!(spool.reserved_bytes(), DISK_LIMIT);
        assert!(first.backed_bytes() >= 1024 * 1024);
        assert!(second.backed_bytes() >= 1024 * 1024);
        assert!(rest.backed_bytes() >= 30 * 1024 * 1024);
        first.cleanup().await.unwrap();
        second.cleanup().await.unwrap();
        rest.cleanup().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
        assert_eq!(
            std::fs::read_dir(fixture.path.join("native-downloads"))
                .unwrap()
                .count(),
            0
        );
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_injected_backing_overage_blocks_admission_until_exact_cleanup() {
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let allocation = spool.allocate(1024 * 1024).await.unwrap();
        // Inject accounting evidence only; this does not claim that this
        // filesystem physically overallocated the real one-MiB file.
        assert_eq!(
            allocation.owner.account_backing(DISK_LIMIT + 4096),
            Err(DownloadError::Backing)
        );
        assert_eq!(allocation.backed_bytes(), DISK_LIMIT + 4096);
        assert_eq!(spool.reserved_bytes(), DISK_LIMIT + 4096);
        assert!(matches!(
            spool.allocate(0).await,
            Err(DownloadError::Backing)
        ));
        assert_eq!(spool.reserved_bytes(), DISK_LIMIT + 4096);
        assert!(BACKING_DEBTS
            .lock()
            .unwrap()
            .contains(&allocation.owner.name));
        allocation.cleanup().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
        assert!(!BACKING_DEBTS
            .lock()
            .unwrap()
            .contains(&allocation.owner.name));
        let next = spool.allocate(1).await.unwrap();
        next.cleanup().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_sealed_read_capability_refuses_same_inode_postreceipt_mutation() {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::FileExt;
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let file = spool.allocate(1).await.unwrap();
        file.write_chunk(0, vec![1]).await.unwrap();
        let sha = format!("{:x}", Sha256::digest([1u8]));
        file.seal(
            1,
            &sha,
            std::time::Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        let mut byte = [0];
        std::io::Read::read_exact(&mut file.open_read().unwrap(), &mut byte).unwrap();
        assert_eq!(byte, [1]);
        let path = fixture.path.join("native-downloads").join(&file.owner.name);
        let changed = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        changed.write_at(&[2], 0).unwrap();
        changed.sync_data().unwrap();
        assert!(matches!(file.open_read(), Err(DownloadError::Identity)));
        file.cleanup().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_read_capability_refuses_named_fifo_without_blocking_or_adoption() {
        use sha2::{Digest, Sha256};
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let file = spool.allocate(0).await.unwrap();
        file.seal(
            0,
            &format!("{:x}", Sha256::digest([])),
            std::time::Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        let name = fixture.path.join("native-downloads").join(&file.owner.name);
        let captured = name.with_extension("captured");
        std::fs::rename(&name, &captured).unwrap();
        nix::unistd::mkfifo(&name, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        assert!(matches!(file.open_read(), Err(DownloadError::Identity)));
        use std::os::unix::fs::FileTypeExt;
        assert!(std::fs::symlink_metadata(&name)
            .unwrap()
            .file_type()
            .is_fifo());
        assert!(file.cleanup().await.is_err());
        std::fs::remove_file(&name).unwrap();
        std::fs::rename(&captured, &name).unwrap();
        file.cleanup().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_held_reader_prevents_unlink_and_quota_refund_until_actual_close() {
        use sha2::{Digest, Sha256};
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let file = spool.allocate(16384).await.unwrap();
        let bytes = vec![0x93; 16384];
        file.write_chunk(0, bytes.clone()).await.unwrap();
        file.seal(
            16384,
            &format!("{:x}", Sha256::digest(&bytes)),
            std::time::Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        let mut reader = file.open_read().unwrap();
        let charged = spool.reserved_bytes();
        assert!(charged >= 16384);
        assert_eq!(file.cleanup().await, Err(DownloadError::Cleanup));
        assert_eq!(spool.reserved_bytes(), charged);
        assert!(fixture
            .path
            .join("native-downloads")
            .join(&file.owner.name)
            .exists());
        let mut observed = vec![0; 16384];
        std::io::Read::read_exact(&mut reader, &mut observed).unwrap();
        assert_eq!(observed, bytes);
        drop(reader);
        file.cleanup().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
        assert!(!fixture
            .path
            .join("native-downloads")
            .join(&file.owner.name)
            .exists());
    }
    #[cfg(target_os = "linux")]
    struct BlockingGate {
        open: Mutex<bool>,
        changed: std::sync::Condvar,
    }
    #[cfg(target_os = "linux")]
    impl BlockingGate {
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
    struct ReleaseGate(Arc<BlockingGate>);
    #[cfg(target_os = "linux")]
    impl Drop for ReleaseGate {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_cancelled_allocation_keeps_worker_file_and_quota_until_join_cleanup() {
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let gate = Arc::new(BlockingGate {
            open: Mutex::new(false),
            changed: std::sync::Condvar::new(),
        });
        let release = ReleaseGate(gate.clone());
        let (entered, received) = tokio::sync::oneshot::channel();
        let owned = spool.clone();
        let blocked = gate.clone();
        let task = tokio::spawn(async move {
            owned
                .allocate_inner(DISK_LIMIT, move || {
                    let _ = entered.send(());
                    blocked.wait();
                })
                .await
        });
        received.await.unwrap();
        assert_eq!(spool.reserved_bytes(), DISK_LIMIT);
        task.abort();
        match task.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("allocation caller must be cancelled"),
        };
        assert!(spool.allocate(1).await.is_err());
        assert_eq!(
            std::fs::read_dir(fixture.path.join("native-downloads"))
                .unwrap()
                .count(),
            1
        );
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            spool.cleanup_pending()
        )
        .await
        .is_err());
        assert_eq!(spool.reserved_bytes(), DISK_LIMIT);
        drop(release);
        spool.cleanup_pending().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
        assert_eq!(
            std::fs::read_dir(fixture.path.join("native-downloads"))
                .unwrap()
                .count(),
            0
        );
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_download_replaced_file_retains_cleanup_debt_and_never_unlinks_foreign() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let _serial = DISK_TESTS.lock().await;
        let Some(fixture) = RootFixture::new() else {
            assert!(matches!(
                NativeDownloadSpool::admit(Path::new("/")),
                Err(DownloadError::Unavailable)
            ));
            return;
        };
        let spool = NativeDownloadSpool::admit(&fixture.path).unwrap();
        let path = fixture.path.join("native-downloads");
        let captured = path.join("captured-original");
        let recorded = Arc::new(Mutex::new(None));
        let copy = recorded.clone();
        let own_spool = spool.clone();
        let result = spool
            .allocate_inner(1024 * 1024, move || {
                let name = ALLOCATIONS
                    .lock()
                    .unwrap()
                    .values()
                    .find(|owner| Arc::ptr_eq(&owner.spool, &own_spool))
                    .unwrap()
                    .name
                    .clone();
                let named = path.join(&name);
                std::fs::rename(&named, &captured).unwrap();
                let foreign = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&named)
                    .unwrap();
                *copy.lock().unwrap() = Some((name, foreign.metadata().unwrap().ino()));
            })
            .await;
        assert!(matches!(result, Err(DownloadError::Cleanup)));
        assert!(spool.reserved_bytes() >= 1024 * 1024);
        let (name, inode) = recorded.lock().unwrap().clone().unwrap();
        let named = fixture.path.join("native-downloads").join(name);
        assert_eq!(std::fs::metadata(&named).unwrap().ino(), inode);
        assert!(spool.cleanup_pending().await.is_err());
        assert_eq!(std::fs::metadata(&named).unwrap().ino(), inode);
        std::fs::remove_file(&named).unwrap();
        std::fs::rename(
            fixture.path.join("native-downloads/captured-original"),
            &named,
        )
        .unwrap();
        spool.cleanup_pending().await.unwrap();
        assert_eq!(spool.reserved_bytes(), 0);
    }
}
