//! First actual-FS provenance RED; no image admission, claim, VM or GC effect.
use super::*;

fn matching_profile_descriptors(pin: &std::fs::Metadata) -> Result<usize, Error> {
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|_| Error::Io)?;
    let mut count = 0;
    let mut visited = 0usize;
    for entry in entries {
        visited = visited.checked_add(1).ok_or(Error::Identity)?;
        if visited > 4096 {
            return Err(Error::Identity);
        }
        let entry = entry.map_err(|_| Error::Io)?;
        // Kernel descriptor links are intentionally followed, never artifact names.
        let metadata = std::fs::metadata(entry.path()).map_err(|_| Error::Io)?;
        if metadata.is_file() && metadata.dev() == pin.dev() && metadata.ino() == pin.ino() {
            count += 1;
        }
    }
    Ok(count)
}

#[test]
#[ignore = "requires explicitly pinned protected native profile; readonly provenance boundary"]
fn native_artifact_loaded_profile_retains_original_seventh_role_until_drop() -> Result<(), Error> {
    let path = std::env::var_os("AGENTENV_NATIVE_ARTIFACT_PROFILE")
        .map(PathBuf::from)
        .ok_or(Error::Profile)?;
    let digest =
        std::env::var("AGENTENV_NATIVE_ARTIFACT_PROFILE_SHA256").map_err(|_| Error::Profile)?;
    if !hash(&digest) {
        return Err(Error::Profile);
    }
    // Actual protected FD/full SHA control, not a fabricated pin or recording ref.
    let control = protected(&path, Some(&digest), 16384, true, false)?;
    let original = control.metadata().map_err(|_| Error::Io)?;
    let baseline = matching_profile_descriptors(&original)?;
    let profile = NativeGuestProfile::load(&path)?;
    let retained = matching_profile_descriptors(&original)?;
    let required = baseline.checked_add(1).ok_or(Error::Identity)?;
    drop(profile);
    let after_drop = matching_profile_descriptors(&original)?;
    let source_unchanged = identity(&original)
        == identity(&control.metadata().map_err(|_| Error::Io)?)
        && identity(&original)
            == identity(&std::fs::symlink_metadata(&path).map_err(|_| Error::Io)?);
    drop(control);
    assert!(
        source_unchanged && after_drop == baseline,
        "native_profile_source_unchanged={source_unchanged} descriptors_after_drop={after_drop} baseline={baseline}"
    );
    assert_eq!(
        retained, required,
        "actual_missing_profile_custody: descriptor role7 must survive the actual protected profile loader"
    );
    Ok(())
}

fn actual_readonly_profile() -> Result<NativeGuestProfile, Error> {
    let path = std::env::var_os("AGENTENV_NATIVE_ARTIFACT_PROFILE")
        .map(PathBuf::from)
        .ok_or(Error::Profile)?;
    let digest =
        std::env::var("AGENTENV_NATIVE_ARTIFACT_PROFILE_SHA256").map_err(|_| Error::Profile)?;
    if !hash(&digest) {
        return Err(Error::Profile);
    }
    let control = protected(&path, Some(&digest), 16384, true, false)?;
    let original = control.metadata().map_err(|_| Error::Io)?;
    let profile = NativeGuestProfile::load(&path)?;
    if identity(&original) != identity(&profile.source.as_ref().ok_or(Error::Identity)?.original) {
        return Err(Error::Identity);
    }
    drop(control);
    Ok(profile)
}

#[test]
#[ignore = "requires pinned protected profile; readonly actual provenance"]
fn native_artifact_mutable_policy_and_deserialized_authority_refuse_before_capture(
) -> Result<(), Error> {
    let profile = actual_readonly_profile()?;
    let mut changed = profile.clone();
    changed.owner_id.push('x');
    let drift = matches!(NativeArtifactDescriptor::new(changed), Err(Error::Identity));
    let raw = serde_json::to_vec(&profile).map_err(|_| Error::Profile)?;
    let unbound: NativeGuestProfile = serde_json::from_slice(&raw).map_err(|_| Error::Profile)?;
    let unbound_refused = matches!(NativeArtifactDescriptor::new(unbound), Err(Error::Identity));
    let source_ok = profile
        .source
        .as_ref()
        .ok_or(Error::Identity)?
        .verify()
        .is_ok();
    drop(profile);
    assert!(
        drift && unbound_refused && source_ok,
        "mutable_policy_refused={drift} unbound_refused={unbound_refused} original_source_unchanged={source_ok}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires pinned protected profile; expires before any role admission/claim"]
async fn native_artifact_expired_store_reservation_keeps_original_debt_and_refuses_foreign_owner(
) -> anyhow::Result<()> {
    use crate::image::cache::{native_artifact_store::NativeArtifactStore, RuntimeImageOwner};
    let mut descriptor = NativeArtifactDescriptor::new(actual_readonly_profile()?)?;
    std::sync::Arc::get_mut(&mut descriptor)
        .ok_or(Error::Identity)?
        .until = Instant::now();
    let original_until = descriptor.until;
    let store = NativeArtifactStore::default();
    let sandbox_id = crate::types::SandboxId::new();
    let owner = RuntimeImageOwner::StartingSandbox(sandbox_id);
    let first = store.pin(owner.clone(), vec![descriptor.clone()]).await;
    let first_debt = store.custody();
    let duplicate = store.pin(owner.clone(), vec![descriptor.clone()]).await;
    let duplicate_debt = store.custody();
    let fresh = NativeArtifactDescriptor::new(descriptor.profile.clone())?;
    let no_reseal = store.pin(owner.clone(), vec![fresh.clone()]).await.is_err()
        && !fresh.is_captured()
        && store.custody() == first_debt;
    drop(fresh);
    let debt_owner = RuntimeImageOwner::NativeFailedLaunchDebt {
        debt: crate::types::SandboxId::new(),
        original: sandbox_id,
    };
    let retained_failed = store
        .pin(debt_owner.clone(), vec![descriptor.clone()])
        .await;
    let failed_debt = store.custody();
    store.release(&debt_owner);
    let no_failed_refund = store.custody() == first_debt;
    store.release(&owner);
    let released = store.custody();
    let foreign = store
        .pin(
            RuntimeImageOwner::StartingSandbox(crate::types::SandboxId::new()),
            vec![descriptor.clone()],
        )
        .await;
    let final_debt = store.custody();
    let no_input_capture = descriptor
        .partial
        .lock()
        .map_err(|_| Error::Identity)?
        .descriptors
        .is_empty()
        && !descriptor.is_captured();
    let no_renewal = descriptor.until == original_until;
    let before_effect = descriptor.admitted().is_err();
    drop(store);
    drop(descriptor);
    let exact_expiry =
        first.as_ref().err().and_then(|e| e.downcast_ref::<Error>()) == Some(&Error::Deadline);
    assert!(
        exact_expiry
            && duplicate.is_err()
            && foreign.is_err()
            && no_input_capture
            && no_renewal
            && before_effect
            && retained_failed.is_ok()
            && no_failed_refund
            && no_reseal,
        "expired_refused={} duplicate_refused={} foreign_refused={} no_capture={no_input_capture} fixed_clock={no_renewal} no_admitted_start={before_effect}",
        first.is_err(),
        duplicate.is_err(),
        foreign.is_err()
    );
    assert_eq!(
        first_debt, duplicate_debt,
        "duplicate must preserve original debt/tickets"
    );
    assert_eq!(
        released, final_debt,
        "foreign retry must not mutate released original tombstone"
    );
    assert_eq!(first_debt.0, 1);
    assert_eq!(first_debt.3, NativeArtifactDescriptor::FD_TICKET);
    assert_eq!(released.0, 1);
    assert_eq!(released.1, 0);
    assert_eq!(released.3, first_debt.3);
    assert_eq!(failed_debt.0, 1);
    assert_eq!(failed_debt.1, 2);
    assert_eq!(failed_debt.3, first_debt.3);
    Ok(())
}

#[test]
#[ignore = "requires pinned protected profile; typed failed-union original Arc boundary"]
fn native_artifact_failed_union_preserves_both_original_handles_and_overlaybd_lane(
) -> Result<(), Error> {
    let profile = actual_readonly_profile()?;
    let first = NativeArtifactDescriptor::new(profile.clone())?;
    let second = NativeArtifactDescriptor::new(profile)?;
    let a = crate::sandbox::RuntimeArtifactSet::from_overlaybd_image_configs(vec![PathBuf::from(
        "/protected/a",
    )])
    .with_native(first.clone());
    let b = crate::sandbox::RuntimeArtifactSet::from_overlaybd_image_configs(vec![PathBuf::from(
        "/protected/b",
    )])
    .with_native(second.clone());
    let union = a.union(b);
    let nonempty = !union.is_empty();
    let (paths, native) = union.split();
    let original_handles = native.len() == 2
        && std::sync::Arc::ptr_eq(&native[0], &first)
        && std::sync::Arc::ptr_eq(&native[1], &second);
    drop(native);
    drop(first);
    drop(second);
    assert!(nonempty && original_handles);
    assert_eq!(
        paths,
        vec![PathBuf::from("/protected/a"), PathBuf::from("/protected/b")]
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires pinned protected profile; RecordingRefs never initializes launch authority"]
async fn native_artifact_recording_refs_cannot_initialize_admitted_launch_cell(
) -> anyhow::Result<()> {
    use crate::image::cache::{RuntimeImageOwner, RuntimeImageRefs};
    let descriptor = NativeArtifactDescriptor::new(actual_readonly_profile()?)?;
    let refs = crate::image::cache::test_support::RecordingRuntimeImageRefs::default();
    refs.pin(
        RuntimeImageOwner::StartingSandbox(crate::types::SandboxId::new()),
        crate::sandbox::RuntimeArtifactSet::empty().with_native(descriptor.clone()),
    )
    .await?;
    let no_capture = !descriptor.is_captured();
    let cannot_start = matches!(descriptor.admitted(), Err(Error::Identity));
    drop(refs);
    drop(descriptor);
    assert!(no_capture && cannot_start);
    Ok(())
}

#[tokio::test]
async fn native_artifact_real_store_refuses_wrong_artifact_family_without_reservation() {
    use crate::image::cache::{
        native_artifact_store::NativeArtifactStore, RuntimeImageOwner, RuntimeImageRefs,
    };
    let store = NativeArtifactStore::default();
    let result = RuntimeImageRefs::pin(
        &store,
        RuntimeImageOwner::StartingSandbox(crate::types::SandboxId::new()),
        crate::sandbox::RuntimeArtifactSet::from_overlaybd_image_configs(vec![PathBuf::from(
            "/not-a-native-artifact",
        )]),
    )
    .await;
    let custody = store.custody();
    drop(store);
    assert!(result.is_err());
    assert_eq!(custody, (0, 0, 0, 0, 0));
}

fn fresh_protected_profile() -> Result<NativeGuestProfile, Error> {
    let path = std::env::var_os("AGENTENV_NATIVE_ARTIFACT_FRESH_PROFILE")
        .map(PathBuf::from)
        .ok_or(Error::Profile)?;
    let digest = std::env::var("AGENTENV_NATIVE_ARTIFACT_FRESH_PROFILE_SHA256")
        .map_err(|_| Error::Profile)?;
    if !hash(&digest) {
        return Err(Error::Profile);
    }
    let control = protected(&path, Some(&digest), 16384, true, false)?;
    let original = control.metadata().map_err(|_| Error::Io)?;
    let profile = NativeGuestProfile::load(&path)?;
    if identity(&original) != identity(&profile.source.as_ref().ok_or(Error::Identity)?.original) {
        return Err(Error::Identity);
    }
    let marker = profile
        .config_path
        .parent()
        .ok_or(Error::Profile)?
        .join("agentenv-attempted");
    match std::fs::symlink_metadata(marker) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(Error::Identity),
    }
    drop(control);
    Ok(profile)
}
fn role_versions(profile: &NativeGuestProfile) -> Result<Vec<std::fs::Metadata>, Error> {
    let source = profile.source.as_ref().ok_or(Error::Identity)?;
    let paths = [
        &source.path,
        &profile.rootfs_path,
        &profile.config_path,
        &profile.kernel_path,
        &profile.readiness_executable,
        &profile.vmm_executable,
        &profile.credential_path,
    ];
    paths
        .into_iter()
        .map(|path| std::fs::symlink_metadata(path).map_err(|_| Error::Io))
        .collect()
}
fn role_counts(versions: &[std::fs::Metadata]) -> Result<Vec<usize>, Error> {
    versions.iter().map(matching_profile_descriptors).collect()
}

#[tokio::test]
#[ignore = "requires fresh valid seven-role protected profile; real static-import capture only, no VM or claim"]
async fn native_artifact_seven_roles_same_capture_survive_expiry_and_logical_retirement(
) -> anyhow::Result<()> {
    use crate::image::cache::{native_artifact_store::NativeArtifactStore, RuntimeImageOwner};
    let profile = fresh_protected_profile()?;
    let versions = role_versions(&profile)?;
    let baseline = role_counts(&versions)?;
    let descriptor = NativeArtifactDescriptor::new(profile)?;
    let until = descriptor.until;
    let store = NativeArtifactStore::default();
    let id = crate::types::SandboxId::new();
    let owner = RuntimeImageOwner::StartingSandbox(id);
    let observed: Result<(), anyhow::Error> = async {
        store.pin(owner.clone(), vec![descriptor.clone()]).await?;
        let inputs = descriptor.admitted()?;
        anyhow::ensure!(
            inputs.descriptor_count() <= NativeArtifactDescriptor::FD_TICKET,
            "bounded actual capture descriptors"
        );
        inputs.verify()?;
        anyhow::ensure!(
            std::sync::Arc::ptr_eq(
                &inputs.profile,
                &descriptor
                    .profile
                    .source
                    .as_ref()
                    .ok_or(Error::Identity)?
                    .file
            ),
            "original profile FD Arc required"
        );
        let counts = role_counts(&versions)?;
        anyhow::ensure!(
            counts.len() == 7
                && counts[0] == baseline[0]
                && counts
                    .iter()
                    .skip(1)
                    .zip(baseline.iter().skip(1))
                    .all(|(now, before)| *now == *before + 1),
            "actual seven role FD custody required"
        );
        let original = store.custody();
        store.pin(owner.clone(), vec![descriptor.clone()]).await?;
        anyhow::ensure!(
            std::sync::Arc::ptr_eq(&inputs, &descriptor.admitted()?) && store.custody() == original,
            "duplicate original capture/tickets"
        );
        // The actual initial deadline expires once; no synthetic capture authority or renewal.
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            until + Duration::from_millis(1),
        ))
        .await;
        store.pin(owner.clone(), vec![descriptor.clone()]).await?;
        anyhow::ensure!(
            matches!(descriptor.admitted(), Err(Error::Deadline)) && descriptor.until == until,
            "expired original cannot authorize claim/spawn"
        );
        let retained = descriptor.captured.get().ok_or(Error::Identity)?;
        anyhow::ensure!(
            std::sync::Arc::ptr_eq(&inputs, retained)
                && store.custody() == original
                && role_counts(&versions)? == counts,
            "expired capture truth/tickets retained"
        );
        store.promote(id, vec![descriptor.clone()])?;
        store.release(&owner);
        anyhow::ensure!(
            store.custody().1 == 0 && store.custody().2 == 1,
            "explicit running owner transition"
        );
        store.retire_running(id, vec![descriptor.clone()])?;
        store.check_retired_capture(id)?;
        anyhow::ensure!(
            store.custody().0 == original.0
                && store.custody().3 == original.3
                && store.custody().4 == original.4,
            "retirement never refunds original/tickets"
        );
        drop(inputs);
        Ok(())
    }
    .await;
    drop(store);
    drop(descriptor);
    let closed = role_counts(&versions)?;
    let mut expected = baseline;
    expected[0] = expected[0].checked_sub(1).ok_or(Error::Identity)?;
    assert_eq!(
        closed, expected,
        "all locally held seven-role FDs closed after dropping original owners"
    );
    observed
}

#[tokio::test]
#[ignore = "requires fresh valid seven-role protected profile; actual in-flight caller cancellation and retained FD custody"]
async fn native_artifact_cancelled_pin_keeps_original_fd_ticket_and_capture_worker(
) -> anyhow::Result<()> {
    use crate::image::cache::{native_artifact_store::NativeArtifactStore, RuntimeImageOwner};
    let profile = fresh_protected_profile()?;
    let versions = role_versions(&profile)?;
    let baseline = role_counts(&versions)?;
    let descriptor = NativeArtifactDescriptor::new(profile)?;
    let until = descriptor.until;
    let store = std::sync::Arc::new(NativeArtifactStore::default());
    let id = crate::types::SandboxId::new();
    let owner = RuntimeImageOwner::StartingSandbox(id);
    let task_store = store.clone();
    let task_descriptor = descriptor.clone();
    let task = tokio::spawn(async move { task_store.pin(owner, vec![task_descriptor]).await });
    let observed: Result<(), anyhow::Error> = async {
        loop {
            let root = matching_profile_descriptors(&versions[1])?;
            if root > baseline[1] && !descriptor.is_captured() && !task.is_finished() {
                break;
            }
            anyhow::ensure!(
                !task.is_finished() && Instant::now() < until,
                "actual in-flight root descriptor not observed"
            );
            tokio::task::yield_now().await;
        }
        Ok(())
    }
    .await;
    // Always cancel/join the caller, including an observation error; no detached caller.
    task.abort();
    let cancelled = task.await;
    let cancelled_caller = matches!(cancelled,Err(ref error) if error.is_cancelled());
    let cleanup_until = until + Duration::from_secs(3);
    let actual_join = tokio::time::timeout_at(
        tokio::time::Instant::from_std(cleanup_until),
        descriptor.join_observed_capture(),
    )
    .await;
    let settled = matches!(actual_join, Ok(Ok(()))) && Instant::now() < cleanup_until;
    // If a blocking capture has not settled, its actual owner remains reachable as debt.
    if !settled {
        struct CaptureDebtOwner {
            _store: std::sync::Arc<NativeArtifactStore>,
            _descriptor: std::sync::Arc<NativeArtifactDescriptor>,
        }
        static DEBT: std::sync::OnceLock<std::sync::Mutex<Vec<CaptureDebtOwner>>> =
            std::sync::OnceLock::new();
        DEBT.get_or_init(Default::default)
            .lock()
            .map_err(|_| Error::Identity)?
            .push(CaptureDebtOwner {
                _store: store,
                _descriptor: descriptor,
            });
        anyhow::bail!("capture worker unsettled; original FD/ticket debt retained");
    }
    let actual_retained = matching_profile_descriptors(&versions[1])? > baseline[1];
    let custody = store.custody();
    let retained_original =
        custody.0 == 1 && custody.1 == 1 && custody.3 == NativeArtifactDescriptor::FD_TICKET;
    let same_clock = descriptor.until == until;
    let worker_captured = descriptor.is_captured();
    drop(store);
    drop(descriptor);
    let closed = role_counts(&versions)?;
    let mut expected = baseline;
    expected[0] = expected[0].checked_sub(1).ok_or(Error::Identity)?;
    assert_eq!(
        closed, expected,
        "cancelled caller must not leave unobserved local capture FDs"
    );
    observed?;
    anyhow::ensure!(
        cancelled_caller && actual_retained && retained_original && same_clock && worker_captured,
        "cancelled caller original custody/clock required"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires separately pinned protected config-hash-mismatch inputs; actual partial capture only, no VM or claim"]
async fn native_artifact_config_hash_failure_retains_original_partial_capture_and_tickets(
) -> anyhow::Result<()> {
    use crate::image::cache::{native_artifact_store::NativeArtifactStore, RuntimeImageOwner};
    let path = std::env::var_os("AGENTENV_NATIVE_ARTIFACT_INVALID_PROFILE")
        .map(PathBuf::from)
        .ok_or(Error::Profile)?;
    let digest = std::env::var("AGENTENV_NATIVE_ARTIFACT_INVALID_PROFILE_SHA256")
        .map_err(|_| Error::Profile)?;
    anyhow::ensure!(hash(&digest), "invalid profile pin syntax");
    let control = protected(&path, Some(&digest), 16384, true, false)?;
    let profile = NativeGuestProfile::load(&path)?;
    anyhow::ensure!(
        identity(&control.metadata()?)
            == identity(&profile.source.as_ref().ok_or(Error::Identity)?.original),
        "original protected profile required"
    );
    let marker = profile
        .config_path
        .parent()
        .ok_or(Error::Profile)?
        .join("agentenv-attempted");
    anyhow::ensure!(
        matches!(std::fs::symlink_metadata(marker), Err(ref e) if e.kind()==std::io::ErrorKind::NotFound),
        "invalid fixture must remain unclaimed"
    );
    // Independent readonly setup before the one original descriptor clock.
    // Root capture must succeed; only config's declared digest intentionally differs.
    drop(protected(
        &profile.rootfs_path,
        Some(&profile.rootfs_sha256),
        512 * 1024 * 1024,
        false,
        false,
    )?);
    let mut config = protected(&profile.config_path, None, 4 * 1024 * 1024, false, false)?;
    anyhow::ensure!(
        config.metadata()?.len() == 4 * 1024 * 1024,
        "exact config fixture size"
    );
    let config_version = config.metadata()?;
    let mut config_hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let setup_until = Instant::now() + Duration::from_secs(30);
    loop {
        remaining(setup_until)?;
        let count = config.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        config_hash.update(&buffer[..count]);
    }
    anyhow::ensure!(
        format!("{:x}", config_hash.finalize()) != profile.config_sha256
            && identity(&config_version) == identity(&config.metadata()?)
            && identity(&config_version)
                == identity(&std::fs::symlink_metadata(&profile.config_path)?),
        "intentional config digest mismatch with stable original required"
    );
    drop(config);
    drop(control);
    let versions = role_versions(&profile)?;
    let baseline = role_counts(&versions)?;
    let descriptor = NativeArtifactDescriptor::new(profile)?;
    let until = descriptor.until;
    let store = std::sync::Arc::new(NativeArtifactStore::default());
    let id = crate::types::SandboxId::new();
    let owner = RuntimeImageOwner::StartingSandbox(id);
    let first = tokio::time::timeout_at(
        tokio::time::Instant::from_std(until),
        store.pin(owner.clone(), vec![descriptor.clone()]),
    )
    .await;
    // Join the actual same blocking capture, including timeout/error paths.
    let cleanup_until = until + Duration::from_secs(3);
    let joined = tokio::time::timeout_at(
        tokio::time::Instant::from_std(cleanup_until),
        descriptor.join_observed_capture(),
    )
    .await;
    if !matches!(joined, Ok(Ok(()))) || Instant::now() >= cleanup_until {
        struct OriginalDebt {
            _store: std::sync::Arc<NativeArtifactStore>,
            _descriptor: std::sync::Arc<NativeArtifactDescriptor>,
        }
        static DEBT: std::sync::OnceLock<std::sync::Mutex<Vec<OriginalDebt>>> =
            std::sync::OnceLock::new();
        DEBT.get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(OriginalDebt {
                _store: store,
                _descriptor: descriptor,
            });
        anyhow::bail!("config hash capture worker unsettled; original debt retained");
    }
    let observed: anyhow::Result<()> = async {
        anyhow::ensure!(
            matches!(first,Ok(Err(ref e)) if e.downcast_ref::<Error>()==Some(&Error::Identity)),
            "expected actual config digest refusal"
        );
        {
            let partial = descriptor.partial.lock().map_err(|_| Error::Identity)?;
            anyhow::ensure!(
                partial.attempted && partial.completed.is_none() && !descriptor.is_captured(),
                "actual failed partial capture required"
            );
            for expected in [&versions[1], &versions[2]] {
                anyhow::ensure!(
                    partial.descriptors.iter().any(|fd| fd
                        .metadata()
                        .is_ok_and(|m| identity(&m) == identity(expected))),
                    "original root/config held full version required"
                );
            }
        }
        let counts = role_counts(&versions)?;
        anyhow::ensure!(
            counts[0] == baseline[0]
                && counts[1] == baseline[1] + 1
                && counts[2] == baseline[2] + 1
                && counts[3..] == baseline[3..],
            "exact partial role FD custody required"
        );
        let original = store.custody();
        anyhow::ensure!(
            original.0 == 1
                && original.1 == 1
                && original.2 == 0
                && original.3 == NativeArtifactDescriptor::FD_TICKET
                && original.4 > 0,
            "original pre-effect record/ticket required"
        );
        anyhow::ensure!(
            store
                .pin(owner.clone(), vec![descriptor.clone()])
                .await
                .is_err()
                && store.custody() == original
                && role_counts(&versions)? == counts
                && descriptor.until == until,
            "same original failure cannot recapture or renew"
        );
        let resealed = NativeArtifactDescriptor::new(descriptor.profile.clone())?;
        anyhow::ensure!(
            store
                .pin(owner.clone(), vec![resealed.clone()])
                .await
                .is_err()
                && !resealed
                    .partial
                    .lock()
                    .map_err(|_| Error::Identity)?
                    .attempted,
            "same namespace replacement must refuse before capture"
        );
        drop(resealed);
        anyhow::ensure!(
            store
                .pin(
                    RuntimeImageOwner::StartingSandbox(crate::types::SandboxId::new()),
                    vec![descriptor.clone()]
                )
                .await
                .is_err()
                && store.custody() == original,
            "foreign owner cannot reuse original"
        );
        let debt = RuntimeImageOwner::NativeFailedLaunchDebt {
            debt: crate::types::SandboxId::new(),
            original: id,
        };
        store.pin(debt.clone(), vec![descriptor.clone()]).await?;
        store.release(&debt);
        store.release(&owner);
        let released = store.custody();
        anyhow::ensure!(
            released.0 == 1
                && released.1 == 0
                && released.2 == 0
                && released.3 == original.3
                && released.4 == original.4
                && role_counts(&versions)? == counts,
            "logical release cannot refund original partial FD/tickets"
        );
        Ok(())
    }
    .await;
    drop(store);
    drop(descriptor);
    let closed = role_counts(&versions)?;
    let mut expected = baseline;
    expected[0] = expected[0].checked_sub(1).ok_or(Error::Identity)?;
    anyhow::ensure!(
        closed == expected,
        "all settled local partial owners must close before result"
    );
    observed
}

// These two adapters exercise real capture and production Orchestrator owner
// transitions. Mock backend readiness/stop and recording persistence are logical
// failure controls: neither test starts a VM or proves durable deletion.
async fn native_artifact_lifecycle_failure(persistence_failure: bool) -> anyhow::Result<()> {
    use crate::image::cache::native_artifact_store::NativeArtifactStore;
    use crate::orchestrator::{
        CreateSandboxRequest, InMemoryMetadataStore, Orchestrator, RecordingCall,
        RecordingPersister, SandboxLaunchSource, SandboxState, SandboxTimeoutAction,
    };
    use crate::sandbox::mock::{MockAction, MockBackendFactory, MockBehavior, MockOperation};
    use crate::sandbox::{RuntimeArtifactSet, SandboxNetworkPolicy, SandboxRuntimeInfo};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    let path = std::env::var_os("AGENTENV_NATIVE_ARTIFACT_LIFECYCLE_PROFILE")
        .map(PathBuf::from)
        .ok_or(Error::Profile)?;
    let digest = std::env::var("AGENTENV_NATIVE_ARTIFACT_LIFECYCLE_PROFILE_SHA256")
        .map_err(|_| Error::Profile)?;
    anyhow::ensure!(hash(&digest), "lifecycle profile pin syntax");
    let control = protected(&path, Some(&digest), 16384, true, false)?;
    let profile = NativeGuestProfile::load(&path)?;
    anyhow::ensure!(
        identity(&control.metadata()?)
            == identity(&profile.source.as_ref().ok_or(Error::Identity)?.original),
        "same original protected lifecycle profile"
    );
    let marker = profile
        .config_path
        .parent()
        .ok_or(Error::Profile)?
        .join("agentenv-attempted");
    anyhow::ensure!(
        matches!(std::fs::symlink_metadata(&marker),Err(ref e) if e.kind()==std::io::ErrorKind::NotFound),
        "lifecycle input already claimed"
    );
    drop(control);
    let versions = role_versions(&profile)?;
    let baseline = role_counts(&versions)?;
    let descriptor = NativeArtifactDescriptor::new(profile)?;
    let until = descriptor.until;
    let artifacts = RuntimeArtifactSet::empty().with_native(descriptor.clone());
    let store = Arc::new(NativeArtifactStore::default());
    let behavior = Arc::new(MockBehavior::new());
    behavior.set_startup_artifacts(artifacts.clone());
    behavior.set_runtime_info(SandboxRuntimeInfo {
        runtime_artifacts: artifacts,
        ..Default::default()
    });
    let builds = Arc::new(AtomicUsize::new(0));
    let count = builds.clone();
    behavior.set_on_operation(
        MockOperation::Build,
        Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let starts = Arc::new(AtomicUsize::new(0));
    let count = starts.clone();
    let admitted_before_start = Arc::new(AtomicBool::new(false));
    let checked = admitted_before_start.clone();
    let hook_evidence = Arc::new(std::sync::Mutex::new(None));
    let evidence = hook_evidence.clone();
    let captured = descriptor.clone();
    let pinned = versions.clone();
    let before = baseline.clone();
    behavior.set_on_operation(
        MockOperation::StartNowait,
        Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            let admitted = captured.admitted();
            let admitted_ok = admitted.is_ok();
            let verified = admitted
                .as_ref()
                .is_ok_and(|inputs| inputs.verify().is_ok());
            let same_profile = admitted.as_ref().is_ok_and(|inputs| {
                captured
                    .profile
                    .source
                    .as_ref()
                    .is_some_and(|source| Arc::ptr_eq(&inputs.profile, &source.file))
            });
            let counts: Option<[usize; 7]> = role_counts(&pinned)
                .ok()
                .and_then(|value| value.try_into().ok());
            let fd_exact = counts.as_ref().is_some_and(|counts| {
                counts[0] == before[0]
                    && counts
                        .iter()
                        .skip(1)
                        .zip(before.iter().skip(1))
                        .all(|(now, prior)| *now == *prior + 1)
            });
            *evidence.lock().unwrap_or_else(|error| error.into_inner()) =
                Some((admitted_ok, verified, same_profile, fd_exact, counts));
            let real = admitted_ok && verified && same_profile && fd_exact;
            checked.store(real, Ordering::SeqCst);
        }),
    );
    let persister = RecordingPersister::default();
    let orchestrator = Orchestrator::new_native_qualification_fixture(
        InMemoryMetadataStore::new(),
        MockBackendFactory::with_behavior(behavior.clone()),
        persister.clone(),
        store.clone(),
    )
    .await?;
    let mut original_id = None;
    let mut stage = "create";
    let observed=tokio::time::timeout_at(tokio::time::Instant::from_std(until),async {
        let created=orchestrator.create_sandbox(CreateSandboxRequest {
            extra_drives: Vec::new(), extra_drives_in_snapshot: false, volume_mounts: Default::default(),
            source:SandboxLaunchSource::Snapshot(Box::new(crate::snapshot::RunnableSnapshot::mock())),
            timeout:None,timeout_action:SandboxTimeoutAction::Delete,auto_resume:false,
            user_metadata:None,env_vars:None,network_policy:SandboxNetworkPolicy::default(),secure:false,custom_extension_params:None,
        }).await?;
        original_id = Some(created.id);
        stage = "initial_running_capture";
        let running = created.state==SandboxState::Running;
        let hook_ok = admitted_before_start.load(Ordering::SeqCst);
        let build_count = builds.load(Ordering::SeqCst);
        let start_count = starts.load(Ordering::SeqCst);
        if !(running && hook_ok && build_count==1 && start_count==1) {
            let evidence = *hook_evidence.lock().unwrap_or_else(|error|error.into_inner());
            eprintln!("native_artifact_lifecycle_initial running={running} hook_ok={hook_ok} build_count={build_count} start_count={start_count} hook_evidence={evidence:?} baseline_role_counts={baseline:?}");
        }
        anyhow::ensure!(running && hook_ok && build_count==1 && start_count==1,
            "normal create must capture original seven roles before mock start");
        let original=store.custody();
        let inputs=descriptor.admitted()?;
        let counts=role_counts(&versions)?;
        anyhow::ensure!(original.0==1 && original.1==0 && original.2==1
            && original.3==NativeArtifactDescriptor::FD_TICKET,
            "normal lifecycle must promote original capture");
        if persistence_failure {
            stage = "failed_persistence_delete";
            persister.fail_next(RecordingCall::DeleteRecordAndArtifacts);
            // Current best-effort public policy is Ok despite retained persistence debt.
            orchestrator.delete_sandbox(created.id).await?;
            anyhow::ensure!(orchestrator.get_sandbox(&created.id).await?.is_none()
                && behavior.stop_calls()==1 && persister.calls().contains(&RecordingCall::DeleteRecordAndArtifacts)
                && store.custody()==original,"failed persistence deletion must retain Running protection despite public Ok");
            let absent_retry=orchestrator.delete_sandbox(created.id).await;
            anyhow::ensure!(matches!(absent_retry,Err(crate::orchestrator::OrchestratorError::SandboxNotFound(id)) if id==created.id)
                && store.custody()==original && behavior.stop_calls()==1,
                "missing metadata retry must refuse without retiring persisted debt");
        } else {
            stage = "failed_stop";
            behavior.push_action(MockOperation::Stop,MockAction::Fail{message:"logical native stop refusal".into()});
            let refused=orchestrator.delete_sandbox(created.id).await;
            anyhow::ensure!(matches!(refused,Err(crate::orchestrator::OrchestratorError::SandboxOperationFailed {
                operation:crate::orchestrator::SandboxOperation::Stop,..}))
                && orchestrator.get_sandbox(&created.id).await?.is_some_and(|m|m.state==SandboxState::Running)
                && store.custody()==original && behavior.stop_calls()==1,
                "failed stop must restore metadata and retain original Running owner");
            inputs.verify()?;
            anyhow::ensure!(Arc::ptr_eq(&inputs,&descriptor.admitted()?) && role_counts(&versions)?==counts,
                "failed stop original FD/capture unchanged");
            stage = "same_original_delete_retry";
            orchestrator.delete_sandbox(created.id).await?;
            store.check_retired_capture(created.id)?;
            let retired=store.custody();
            anyhow::ensure!(retired.0==original.0 && retired.1==0 && retired.2==0
                && retired.3==original.3 && retired.4==original.4 && behavior.stop_calls()==2,
                "same sandbox retry retires only logical owner");
        }
        stage = "final_original_capture";
        inputs.verify()?;
        anyhow::ensure!(Arc::ptr_eq(&inputs,descriptor.captured.get().ok_or(Error::Identity)?)
            && role_counts(&versions)?==counts && descriptor.until==until
            && builds.load(Ordering::SeqCst)==1 && starts.load(Ordering::SeqCst)==1,
            "no second capture/start or authority refund");
        anyhow::ensure!(matches!(std::fs::symlink_metadata(&marker),Err(ref e) if e.kind()==std::io::ErrorKind::NotFound),
            "logical fixture cannot claim profile");
        drop(inputs);
        Ok::<(),anyhow::Error>(())
    }).await;
    // Always settle actual capture and normal cleanup before reporting assertions.
    let cleanup_until = until + Duration::from_secs(3);
    let capture = tokio::time::timeout_at(
        tokio::time::Instant::from_std(cleanup_until),
        descriptor.join_observed_capture(),
    )
    .await;
    let observed_ok = matches!(&observed, Ok(Ok(())));
    // A failed observation must not leave Running metadata to unsupported pause.
    // Delete only the same actually created sandbox. Absent metadata is never
    // proof that a previous failed persistence deletion has been repaired.
    let retirement = if observed_ok {
        Ok(Ok(()))
    } else {
        tokio::time::timeout_at(tokio::time::Instant::from_std(cleanup_until), async {
            let Some(id) = original_id else {
                return Ok::<(), crate::orchestrator::OrchestratorError>(());
            };
            let Some(_) = orchestrator.get_sandbox(&id).await? else {
                return Ok(());
            };
            orchestrator.delete_sandbox(id).await?;
            Ok(())
        })
        .await
    };
    let shutdown = tokio::time::timeout_at(
        tokio::time::Instant::from_std(cleanup_until),
        orchestrator.shutdown(),
    )
    .await;
    let capture_ok = matches!(capture, Ok(Ok(())));
    let retirement_ok = matches!(retirement, Ok(Ok(())));
    let shutdown_ok = matches!(shutdown, Ok(Ok(())));
    if !observed_ok || !capture_ok || !retirement_ok || !shutdown_ok {
        eprintln!(
            "native_artifact_lifecycle_failure stage={stage} observed_ok={observed_ok} capture_join_ok={capture_ok} same_original_retirement_ok={retirement_ok} shutdown_ok={shutdown_ok}"
        );
    }
    if !capture_ok || !retirement_ok || !shutdown_ok || Instant::now() >= cleanup_until {
        struct LifecycleDebt {
            _orchestrator: Arc<dyn std::any::Any + Send + Sync>,
            _store: Arc<NativeArtifactStore>,
            _descriptor: Arc<NativeArtifactDescriptor>,
        }
        static DEBT: std::sync::OnceLock<std::sync::Mutex<Vec<LifecycleDebt>>> =
            std::sync::OnceLock::new();
        DEBT.get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(LifecycleDebt {
                _orchestrator: orchestrator,
                _store: store,
                _descriptor: descriptor,
            });
        observed??;
        anyhow::bail!("logical lifecycle cleanup unsettled; original debt retained");
    }
    drop(orchestrator);
    drop(behavior); // Hook owns the same descriptor; it must retire before FD assertion.
    drop(store);
    drop(descriptor);
    let closed = role_counts(&versions);
    let mut expected = baseline;
    expected[0] = expected[0].checked_sub(1).ok_or(Error::Identity)?;
    let closed_ok = closed.as_ref().is_ok_and(|actual| *actual == expected);
    if !closed_ok {
        eprintln!(
            "native_artifact_lifecycle_failure stage=local_fd_closure observed_ok={observed_ok} closed_ok={closed_ok}"
        );
    }
    observed??;
    anyhow::ensure!(
        closed? == expected,
        "all local lifecycle holders must close after settled cleanup"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires fresh pinned seven-role inputs; actual capture and logical Orchestrator stop failure, no VM"]
async fn native_artifact_orchestrator_failed_stop_retains_original_running_capture(
) -> anyhow::Result<()> {
    native_artifact_lifecycle_failure(false).await
}

#[tokio::test]
#[ignore = "requires fresh pinned seven-role inputs; actual capture with logical failed persistence deletion debt, no VM"]
async fn native_artifact_orchestrator_failed_persistence_delete_retains_original_running_capture(
) -> anyhow::Result<()> {
    native_artifact_lifecycle_failure(true).await
}
