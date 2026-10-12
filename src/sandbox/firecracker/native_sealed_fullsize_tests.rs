//! Read-only fullsize drive qualification; no native launch or SCM transfer.
use super::*;
const PROFILE_SHA: &str = "8c80e5da4f298fcee14a1767c02389677c05d1d44d920896c6b5bcab1b51d1ec";
const ROOT_SHA: &str = "2fbabfb115bba85487c6fa2c4d7b9957b4d4486bf75bc64031880b02266f5273";
const CONFIG_SHA: &str = "267d4fd558051f9bb0d58ce8aeb288eb8c9e2df2d7035eae242be7a4d6eb27ea";
const NAMESPACE: &str = "/srv/codex-guest-416/87ddf5ea4dda415eb46d2964bc5efde2";
struct Owner {
    profile: Option<NativeGuestProfile>,
    debt: Vec<File>,
    names: Vec<PathBuf>,
    // Two role ranges map actual ancestor descriptors to original names.
    anchors: Vec<(usize, usize, usize)>,
    sources: Vec<(usize, PathBuf, std::fs::Metadata)>,
    targets: Vec<(usize, u64, std::fs::Metadata)>,
}
static OWNER: std::sync::Mutex<Option<Owner>> = std::sync::Mutex::new(None);
#[test]
#[ignore = "fresh isolated Linux process; exact protected87dd full512MiB+4MiB snapshot_drive, source readonly, no VM/SCM"]
fn actual_fullsize_snapshot_drive_uses_original_sources_and_deadline() -> Result<(), Error> {
    let started = Instant::now();
    // Separate import-only qualification: production descriptor's cap is also30s.
    // This fixed clock is never an IPC/Worker authority or a per-file renewal.
    let until = started + Duration::from_secs(30);
    let mut slot = OWNER.lock().map_err(|_| Error::Identity)?;
    if slot.is_some() || SEALED_BACKING.load(std::sync::atomic::Ordering::SeqCst) != 0 {
        return Err(Error::Identity);
    }
    *slot = Some(Owner {
        profile: None,
        debt: Vec::with_capacity(68),
        names: Vec::with_capacity(64),
        anchors: Vec::with_capacity(2),
        sources: Vec::with_capacity(2),
        targets: Vec::with_capacity(2),
    });
    let owner = slot.as_mut().ok_or(Error::Identity)?;
    let path = PathBuf::from(std::env::var_os("AGENTENV_NATIVE_PROFILE").ok_or(Error::Profile)?);
    if path.parent() != Some(Path::new(NAMESPACE)) {
        return Err(Error::Identity);
    }
    // Production loader is the closed DTO and protected original profile capture.
    remaining(until)?;
    owner.profile = Some(NativeGuestProfile::load(&path)?);
    let profile = owner.profile.as_ref().ok_or(Error::Identity)?;
    profile.verify_reserved_source(&path, PROFILE_SHA)?;
    if profile.rootfs_sha256 != ROOT_SHA
        || profile.config_sha256 != CONFIG_SHA
        || profile.rootfs_path != Path::new(NAMESPACE).join("image/rootfs.ext4")
        || profile.config_path != Path::new(NAMESPACE).join("config.ext4")
    {
        return Err(Error::Identity);
    }
    remaining(until)?;
    let roles = [
        (&profile.rootfs_path, ROOT_SHA, 512 * 1024 * 1024u64),
        (&profile.config_path, CONFIG_SHA, 4 * 1024 * 1024u64),
    ];
    for (path, hash, size) in roles {
        remaining(until)?;
        let anchor_start = owner.debt.len();
        let name_start = owner.names.len();
        capture_ancestors_into(path, until, &mut owner.debt, &mut owner.names)?;
        owner
            .anchors
            .push((anchor_start, owner.debt.len(), name_start));
        let source_index = owner.debt.len();
        owner.debt.push(open_protected(path, size, true, false)?);
        // Actual original FD installed before stat/hash or any later failure.
        let original = owner.debt[source_index].metadata().map_err(|_| Error::Io)?;
        owner.sources.push((source_index, path.clone(), original));
        verify_digest(&mut owner.debt[source_index], path, Some(hash), size, until)?;
        if owner.sources.last().ok_or(Error::Identity)?.2.len() != size {
            return Err(Error::Identity);
        }
    }
    for (role, (hash, size)) in [
        (ROOT_SHA, 512 * 1024 * 1024u64),
        (CONFIG_SHA, 4 * 1024 * 1024u64),
    ]
    .into_iter()
    .enumerate()
    {
        let source_index = owner.sources[role].0;
        let target = snapshot_drive(&mut owner.debt, source_index, hash, size, until)?;
        // Production snapshot_drive has independently hashed the actual sealed destination.
        let pin = owner.debt[target].metadata().map_err(|_| Error::Io)?;
        owner.targets.push((target, size, pin));
    }
    for (start, end, name_start) in &owner.anchors {
        for index in *start..*end {
            remaining(until)?;
            verify_directory(
                &owner.names[*name_start + index - *start],
                &owner.debt[index],
            )?;
        }
    }
    for (index, path, original) in &owner.sources {
        remaining(until)?;
        if identity(original) != identity(&owner.debt[*index].metadata().map_err(|_| Error::Io)?)
            || identity(original)
                != identity(&std::fs::symlink_metadata(path).map_err(|_| Error::Identity)?)
        {
            return Err(Error::Identity);
        }
    }
    let mut physical_backing = 0u64;
    for (target, size, original) in &owner.targets {
        remaining(until)?;
        verify_sealed(&owner.debt[*target], *size)?;
        let actual = owner.debt[*target].metadata().map_err(|_| Error::Io)?;
        if identity(&actual) != identity(original) {
            return Err(Error::Identity);
        }
        physical_backing = physical_backing
            .checked_add(actual.blocks().checked_mul(512).ok_or(Error::Identity)?)
            .ok_or(Error::Identity)?;
    }
    profile.verify_reserved_source(&path, PROFILE_SHA)?;
    let charged = SEALED_BACKING.load(std::sync::atomic::Ordering::SeqCst);
    if charged == 0 || charged > SEALED_BACKING_CAP || physical_backing > charged {
        return Err(Error::Identity);
    }
    remaining(until)?;
    eprintln!("SDK fullsize snapshot: logical_bytes=541065216 charged_bytes={charged} actual_backing_bytes={physical_backing} elapsed_ms={} source_readonly=true four_seals=true production_postseal_sha_verified=true original_owner_retained=true vm_claimed=false scm_claimed=false whole_rss_proved=false",started.elapsed().as_millis());
    // No source deletion or quota refund: fixed original owner/debt survives until process exit.
    Ok(())
}
