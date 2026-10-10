//! Explicit root-owned native-only deployment. Legacy admission is unchanged.
use crate::cfg::AppConfig;
use anyhow::{bail, ensure, Result};
use std::{
    fs::{File, OpenOptions},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
fn identity(m: &std::fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn anchors(path: &Path) -> Result<Vec<(PathBuf, File)>> {
    ensure!(
        path.is_absolute() && path.as_os_str().as_bytes().len() <= 4096,
        "native protected path invalid"
    );
    let mut result = Vec::new();
    let mut current = PathBuf::from("/");
    for c in path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("native parent missing"))?
        .components()
    {
        match c {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(n) => current.push(n),
            _ => bail!("native protected path invalid"),
        }
        ensure!(result.len() < 32, "native ancestor bound");
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY)
            .open(&current)?;
        let h = f.metadata()?;
        let n = std::fs::symlink_metadata(&current)?;
        ensure!(
            h.is_dir()
                && h.uid() == 0
                && h.gid() == 0
                && h.mode() & 0o022 == 0
                && (h.dev(), h.ino(), h.mode(), h.uid(), h.gid())
                    == (n.dev(), n.ino(), n.mode(), n.uid(), n.gid()),
            "native ancestor identity"
        );
        result.push((current.clone(), f));
    }
    Ok(result)
}
pub(crate) struct ConfigurationSource {
    path: PathBuf,
    file: File,
    original: std::fs::Metadata,
    anchors: Vec<(PathBuf, File)>,
}
impl ConfigurationSource {
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        let ancestors = anchors(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(path)?;
        let original = file.metadata()?;
        ensure!(
            original.is_file()
                && original.uid() == 0
                && original.gid() == 0
                && original.mode() & 0o7777 == 0o600
                && original.nlink() == 1
                && original.len() > 0
                && original.len() <= 65536,
            "native configuration must be protected root600"
        );
        let result = Self {
            path: path.into(),
            file,
            original,
            anchors: ancestors,
        };
        result.verify()?;
        Ok(result)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(
            identity(&self.original) == identity(&self.file.metadata()?)
                && identity(&self.original) == identity(&std::fs::symlink_metadata(&self.path)?),
            "native configuration changed"
        );
        for (p, f) in &self.anchors {
            let h = f.metadata()?;
            let n = std::fs::symlink_metadata(p)?;
            ensure!(
                (h.dev(), h.ino(), h.mode(), h.uid(), h.gid())
                    == (n.dev(), n.ino(), n.mode(), n.uid(), n.gid()),
                "native configuration ancestor changed"
            );
        }
        Ok(())
    }
}
fn private_directory(path: &Path) -> Result<()> {
    let _anchors = anchors(&path.join(".anchor"))?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY)
        .open(path)?;
    let h = f.metadata()?;
    let n = std::fs::symlink_metadata(path)?;
    ensure!(
        h.is_dir()
            && h.uid() == 0
            && h.gid() == 0
            && h.mode() & 0o7777 == 0o700
            && (h.dev(), h.ino(), h.mode(), h.uid(), h.gid())
                == (n.dev(), n.ino(), n.mode(), n.uid(), n.gid()),
        "native private directory identity"
    );
    Ok(())
}
fn disjoint_private_trees(trees: &[&Path], assets: &[&Path]) -> Result<()> {
    for (i, tree) in trees.iter().enumerate() {
        ensure!(tree.is_absolute(), "native mutable path invalid");
        for other in &trees[..i] {
            ensure!(
                !tree.starts_with(other) && !other.starts_with(tree),
                "native mutable trees overlap"
            );
        }
        for asset in assets {
            ensure!(
                !asset.starts_with(tree),
                "native profile asset in mutable tree"
            );
        }
    }
    Ok(())
}
pub fn validate_policy(c: &AppConfig) -> Result<()> {
    ensure!(c.is_native_root(), "native-root mode required");
    ensure!(
        c.firecracker.native_guest_profile.is_some(),
        "native-root protected profile required"
    );
    ensure!(
        nix::unistd::geteuid().as_raw() == 0
            && nix::unistd::getegid().as_raw() == 0
            && cfg!(target_os = "linux"),
        "native-root requires Linux UID/GID0"
    );
    ensure!(
        c.virtualization_mode == crate::virtualization::VirtualizationMode::Kvm,
        "native-root requires KVM"
    );
    ensure!(
        !c.p2p.enabled
            && !c.snapshot.p2p_enabled
            && !c.observability.enabled
            && c.custom_extension.url.is_none()
            && c.sandbox_proxy.domains.is_empty(),
        "native-root legacy extensions/proxy/P2P refused"
    );
    ensure!(
        !c.pool.network.enabled
            && !c.pool.block.enabled
            && !c.pool.firecracker.enabled
            && c.pool.low_watermark == 0
            && c.pool.high_watermark == 0,
        "native-root legacy pools refused"
    );
    ensure!(
        !c.memory_snapshot.track_dirty_pages && c.firecracker.url.is_none(),
        "native-root snapshot/shared VMM refused"
    );
    let profile = crate::sandbox::NativeGuestProfile::load(
        c.firecracker
            .native_guest_profile
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("native-root protected profile required"))?,
    )?;
    ensure!(
        c.resolved_firecracker_binary_path() == profile.vmm_executable,
        "native-root VMM profile mismatch"
    );
    ensure!(
        c.firecracker.work_dir.as_deref() == Some(c.home_path.join("work").as_path()),
        "native-root work must be separate private home/work"
    );
    ensure!(
        c.backend
            .posix_fs
            .as_ref()
            .is_some_and(|p| p.snapshot_store == c.home_path.join("snapshot-store"))
            && c.backend.oss.is_none()
            && c.snapshot.local_cache_path == c.home_path.join("snapshot-local-cache"),
        "native-root snapshot paths must stay private; snapshots unsupported"
    );
    ensure!(
        c.orchestrator.persisted_sandbox_store_path == c.home_path.join("state/sandboxes.json"),
        "native-root state path must stay private"
    );
    let state = c.home_path.join("state");
    let logs = c.home_path.join("logs");
    let store = c.home_path.join("snapshot-store");
    let cache = c.home_path.join("snapshot-local-cache");
    ensure!(
        c.firecracker.serial_dir.as_deref() == Some(logs.as_path()),
        "native-root logs must stay private"
    );
    let trees = [
        c.runtime_path.as_path(),
        c.firecracker.work_dir.as_ref().unwrap().as_path(),
        state.as_path(),
        logs.as_path(),
        store.as_path(),
        cache.as_path(),
    ];
    let profile_path = c.firecracker.native_guest_profile.as_ref().unwrap();
    disjoint_private_trees(
        &trees,
        &[
            profile_path.as_path(),
            profile.rootfs_path.as_path(),
            profile.config_path.as_path(),
            profile.kernel_path.as_path(),
            profile.credential_path.as_path(),
            profile.readiness_executable.as_path(),
            profile.vmm_executable.as_path(),
        ],
    )?;
    // The encompassing home is also mutable: no profile input may live anywhere below it.
    disjoint_private_trees(
        &[c.home_path.as_path()],
        &[
            profile_path.as_path(),
            profile.rootfs_path.as_path(),
            profile.config_path.as_path(),
            profile.kernel_path.as_path(),
            profile.credential_path.as_path(),
            profile.readiness_executable.as_path(),
            profile.vmm_executable.as_path(),
        ],
    )?;
    private_directory(&c.home_path)?;
    for tree in trees {
        private_directory(tree)?;
    }
    ensure!(
        matches!(std::fs::symlink_metadata(&c.orchestrator.persisted_sandbox_store_path),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "native-root requires fresh state; resume/recovery unsupported"
    );
    ensure!(
        c.runtime_path != c.home_path
            && !profile.credential_path.starts_with(&c.home_path)
            && c.home_path != std::path::Path::new("/var/lib/aenv")
            && c.runtime_path != std::path::Path::new("/run/aenv"),
        "native-root runtime/profile namespace overlap"
    );
    Ok(())
}
/// Refuse legacy resolving/build/snapshot/network requests before API handlers.
pub fn route_allowed(method: &str, path: &str) -> bool {
    if matches!(path, "/health" | "/metrics") {
        return method == "GET";
    }
    if path == "/sandboxes/native/create" {
        return matches!(method, "GET" | "POST");
    }
    if path == "/sandboxes" {
        return method == "GET";
    }
    let Some(rest) = path.strip_prefix("/sandboxes/") else {
        return false;
    };
    let (raw, suffix) = rest.split_once('/').unwrap_or((rest, ""));
    let Ok(id) = uuid::Uuid::parse_str(raw) else {
        return false;
    };
    if id.to_string() != raw {
        return false;
    }
    if suffix == "native/control" {
        matches!(method, "GET" | "POST")
    } else {
        suffix.is_empty() && matches!(method, "GET" | "DELETE")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use confique::Config;
    #[test]
    fn native_routes_refuse_legacy_effects_before_handlers() {
        let id = "00000000-0000-4000-8000-000000000001";
        assert!(route_allowed(
            "POST",
            &format!("/sandboxes/{id}/native/control")
        ));
        assert!(route_allowed("DELETE", &format!("/sandboxes/{id}")));
        for (m, p) in [
            ("POST", "/sandboxes"),
            ("POST", "/templates"),
            ("POST", "/snapshots"),
            (
                "POST",
                "/sandboxes/00000000-0000-4000-8000-000000000001/resume",
            ),
            ("GET", "/proxy/foo"),
        ] {
            assert!(!route_allowed(m, p));
        }
    }
    #[test]
    fn native_mode_missing_profile_refuses_before_environment_effects() {
        let c = AppConfig {
            deployment_mode: "native-root".into(),
            ..AppConfig::default()
        };
        assert!(validate_policy(&c)
            .unwrap_err()
            .to_string()
            .contains("protected profile required"));
    }
    #[test]
    fn native_mutable_trees_refuse_overlaps_and_all_embedded_assets() {
        let trees = [Path::new("/private/work"), Path::new("/private/state")];
        assert!(disjoint_private_trees(&trees, &[Path::new("/inputs/profile")]).is_ok());
        for asset in [
            "/private/work/rootfs",
            "/private/state/kernel",
            "/private/work/probe",
            "/private/state/config",
            "/private/work/identity",
            "/private/state/profile",
            "/private/work/vmm",
        ] {
            assert!(disjoint_private_trees(&trees, &[Path::new(asset)]).is_err());
        }
        assert!(disjoint_private_trees(
            &[
                Path::new("/private/work"),
                Path::new("/private/work/nested")
            ],
            &[]
        )
        .is_err());
        assert!(disjoint_private_trees(
            &[Path::new("/private/work"), Path::new("/private/work")],
            &[]
        )
        .is_err());
    }
    #[test]
    fn native_private_directory_refuses_symlink_and_foreign_tree() {
        // These are real filesystem negative inputs; no root-ownership fiction.
        let root = std::env::temp_dir().join(format!("native-policy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let named = root.join("link");
        std::os::unix::fs::symlink(&root, &named).unwrap();
        let symlink_refused = private_directory(&named).is_err();
        let unprotected_refused = private_directory(&root).is_err();
        std::fs::remove_file(named).unwrap();
        std::fs::remove_dir(root).unwrap();
        assert!(symlink_refused);
        assert!(unprotected_refused);
    }
    #[test]
    fn default_config_is_legacy() {
        let c = AppConfig::builder().load().unwrap();
        assert!(!c.is_native_root());
    }
}
