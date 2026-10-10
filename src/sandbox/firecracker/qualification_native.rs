//! Opt-in acceptance through the production AgentENV backend, never a mock VM.
//! Requires a fresh protected profile namespace; its consumed marker is permanent.
use super::{
    native_guest::NativeGuestProfile, FirecrackerCommonConfig, FirecrackerRuntimePolicy,
    FirecrackerSandbox, FirecrackerSandboxConfig,
};
use crate::sandbox::{ProcessOpts, SandboxBackend, SandboxExecutor};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use tokio::time::{timeout, Duration};

/// On cleanup failure the actual backend owner remains available for retry.
/// Callers must retain this object; dropping it is not proof of VM absence.
struct QualificationFailure {
    stage: &'static str,
    cause: String,
    owner: Option<Box<FirecrackerSandbox>>,
    refs: Option<std::sync::Arc<crate::image::cache::native_artifact_store::NativeArtifactStore>>,
}
impl fmt::Debug for QualificationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeQualificationFailure")
            .field("stage", &self.stage)
            .field("cause", &self.cause)
            .field("cleanup_debt", &self.owner.is_some())
            .field("reference_debt", &self.refs.is_some())
            .finish()
    }
}
fn sanitized_cause(error: &anyhow::Error) -> String {
    for cause in error.chain() {
        if let Some(native) = cause.downcast_ref::<super::native_guest::Error>() {
            return format!("native {native:?}");
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return format!("io {:?}", io.kind());
        }
        if cause.is::<tokio::time::error::Elapsed>() {
            return "deadline".into();
        }
    }
    "refused".into()
}
async fn qualify(profile_path: &Path) -> std::result::Result<(), QualificationFailure> {
    let config = (|| -> Result<FirecrackerSandboxConfig> {
        let profile = NativeGuestProfile::load(profile_path)?;
        let namespace = profile.config_path.parent().context("native namespace")?;
        let metadata = std::fs::symlink_metadata(namespace)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            bail!("qualification requires a private root-owned namespace");
        }
        let mut common = FirecrackerCommonConfig::new(
            profile.vmm_executable.clone(),
            String::new(),
            FirecrackerRuntimePolicy {
                socket_timeout: Duration::from_secs(3),
                socket_poll_interval: Duration::from_millis(10),
                envd_timeout: Duration::from_secs(30),
                envd_poll_interval: Duration::from_millis(10),
            },
        );
        // Exclusive root-private logs. The controlled qualification runner must
        // enforce LimitFSIZE=8M; kernel/VMM writes have no interruptible Rust budget.
        let stdout = namespace.join("native-vmm.stdout");
        let stderr = namespace.join("native-vmm.stderr");
        for path in [&stdout, &stderr] {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        common.stdout_path = Some(stdout);
        common.stderr_path = Some(stderr);
        common.firecracker_work_base_dir = Some(namespace.to_owned());
        common.track_dirty_pages = false;
        common.default_workdir = Some("/workspace".into());
        common.default_user = Some("1000".into());
        let kernel_image = profile.kernel_path.clone();
        common.native_guest_profile = Some(profile);
        Ok(FirecrackerSandboxConfig {
            common,
            kernel_image,
            boot_args: None,
            vcpu_count: 1,
            mem_size_mib: 128,
        })
    })()
    .map_err(|error| QualificationFailure {
        cause: sanitized_cause(&error),
        stage: "protected profile/private logs",
        owner: None,
        refs: None,
    })?;
    let sandbox_id = crate::types::SandboxId::new();
    let mut owner = Box::new(FirecrackerSandbox::new_with_id(config, sandbox_id).map_err(
        |error| QualificationFailure {
            cause: sanitized_cause(&error),
            stage: "construct",
            owner: None,
            refs: None,
        },
    )?);
    let refs = std::sync::Arc::new(
        crate::image::cache::native_artifact_store::NativeArtifactStore::default(),
    );
    let protection = crate::image::cache::RuntimeImageRefs::pin(
        &*refs,
        crate::image::cache::RuntimeImageOwner::StartingSandbox(sandbox_id),
        owner.startup_artifacts(),
    )
    .await;
    let start = match protection {
        Ok(()) => timeout(Duration::from_secs(45), SandboxBackend::start(&mut *owner)).await,
        Err(error) => Ok(Err(error)),
    };
    let mut stage = "production start/READY";
    let check: Result<()> = async {
        start.context("start deadline")??;
        if !SandboxBackend::native_control_ready(&*owner) {
            bail!("native control is not authenticated");
        }
        stage = "native executor capability";
        let executor = SandboxExecutor::executor(&*owner)?;
        let opts = ProcessOpts::default().with_timeout(Duration::from_secs(10));
        stage = "printf dispatch";
        let mut command = executor
            .start_process("/bin/sh", &["-c", "printf native-qualification"], &opts)
            .await?;
        if command.pid().is_some() {
            bail!("native handle invented a guest PID");
        }
        let original = command
            .native_identity()
            .context("native identity missing")?
            .clone();
        stage = "printf terminal/output";
        let output = timeout(Duration::from_secs(15), command.wait()).await??;
        if output.exit_code != 0
            || output.stdout != "native-qualification"
            || !output.stderr.is_empty()
        {
            bail!("native command result mismatch");
        }
        stage = "printf original query";
        let query = command.query_native_status().await?;
        if !query.terminal
            || query.state != "succeeded"
            || !query.process_absent
            || query.stdout_bytes != Some(20)
            || query.stderr_bytes != Some(0)
            || query.identity.session_id != original.session_id
            || query.identity.operation_id != original.operation_id
        {
            bail!("original command query truth mismatch");
        }
        // Actual file transport is exclusively the authenticated native bridge.
        // Shell mutation below changes only this controlled fixture to prove that
        // an original query returns its retained result instead of reading again.
        let binary: Vec<u8> = (0..16384).map(|n| (n % 256) as u8).collect();
        let digest = format!("{:x}", Sha256::digest(&binary));
        let path = "native-file-qualification.bin";
        stage = "native binary file write dispatch";
        let written = executor.start_native_file_write(path, 0, &binary)?;
        let write_identity = written.identity().clone();
        stage = "native binary file write result";
        let result = timeout(Duration::from_secs(8), written.wait()).await??;
        if result.identity.session_id != write_identity.session_id
            || result.identity.operation_id != write_identity.operation_id
            || result.path != path
            || result.offset != 0
            || result.data != binary
            || result.sha256 != digest
        {
            bail!("native write chunk truth mismatch");
        }
        stage = "native binary file read dispatch";
        let read = executor.start_native_file_read(path, 0, 16384)?;
        let read_identity = read.identity().clone();
        stage = "native binary file read result";
        let result = timeout(Duration::from_secs(8), read.wait()).await??;
        if result.identity.session_id != read_identity.session_id
            || result.identity.operation_id != read_identity.operation_id
            || result.path != path
            || result.offset != 0
            || result.data != binary
            || result.sha256 != digest
        {
            bail!("native read chunk truth mismatch");
        }
        stage = "controlled file fixture mutation";
        let changed = timeout(
            Duration::from_secs(15),
            executor.run_command_with_opts(
                "/bin/sh",
                &["-c", "printf changed > native-file-qualification.bin"],
                &opts,
            ),
        )
        .await??;
        if changed.exit_code != 0 || !changed.stdout.is_empty() || !changed.stderr.is_empty() {
            bail!("controlled fixture mutation failed");
        }
        stage = "native original file write cached query";
        let cached = written.query_result().await?;
        if cached.identity.session_id != write_identity.session_id
            || cached.identity.operation_id != write_identity.operation_id
            || cached.path != path
            || cached.offset != 0
            || cached.data != binary
            || cached.sha256 != digest
        {
            bail!("original write query changed retained result");
        }
        stage = "native original file read cached query";
        let cached = read.query_result().await?;
        if cached.identity.session_id != read_identity.session_id
            || cached.identity.operation_id != read_identity.operation_id
            || cached.path != path
            || cached.offset != 0
            || cached.data != binary
            || cached.sha256 != digest
        {
            bail!("original read query changed retained result");
        }
        stage = "native new file read observes changed fixture";
        let changed_read = executor.start_native_file_read(path, 0, 16384)?;
        let changed_identity = changed_read.identity().clone();
        let changed = timeout(Duration::from_secs(8), changed_read.wait()).await??;
        if changed.identity.session_id != changed_identity.session_id
            || changed.identity.operation_id != changed_identity.operation_id
            || changed.path != path
            || changed.offset != 0
            || changed.data != b"changed"
            || changed.sha256 != format!("{:x}", Sha256::digest(b"changed"))
        {
            bail!("new file read did not witness changed fixture");
        }
        stage = "busy-loop dispatch";
        let mut running = executor
            .start_process("/bin/sh", &["-c", "while :; do :; done"], &opts)
            .await?;
        let original = running
            .native_identity()
            .context("native cancellation identity missing")?
            .clone();
        stage = "busy-loop original query";
        let before = running.query_native_status().await?;
        if before.identity.session_id != original.session_id
            || before.identity.operation_id != original.operation_id
            || !matches!(before.state.as_str(), "accepted" | "running")
        {
            bail!("original running query truth mismatch");
        }
        stage = "original cancellation dispatch";
        running.kill().await?;
        stage = "authenticated cancellation terminal";
        let cancelled = timeout(Duration::from_secs(8), async {
            loop {
                let status = running.query_native_status().await?;
                if status.terminal {
                    return Ok::<_, anyhow::Error>(status);
                }
                if !matches!(status.state.as_str(), "accepted" | "running") {
                    bail!("cancel state unknown");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        if !cancelled.terminal
            || cancelled.state != "cancelled"
            || !cancelled.process_absent
            || cancelled.identity.session_id != original.session_id
            || cancelled.identity.operation_id != original.operation_id
        {
            bail!("authenticated cancellation terminal absent");
        }
        Ok(())
    }
    .await;
    let stopped = timeout(Duration::from_secs(10), SandboxBackend::stop(&mut *owner)).await;
    if !matches!(stopped, Ok(Ok(()))) {
        let cause = match stopped {
            Err(_) => "deadline".into(),
            Ok(Err(error)) => sanitized_cause(&error),
            Ok(Ok(())) => unreachable!(),
        };
        return Err(QualificationFailure {
            cause,
            stage: "actual owner cleanup",
            owner: Some(owner),
            refs: Some(refs),
        });
    }
    crate::image::cache::RuntimeImageRefs::unpin_best_effort(
        &*refs,
        crate::image::cache::RuntimeImageOwner::StartingSandbox(sandbox_id),
    )
    .await;
    if let Err(error) = refs.check_retired_capture(sandbox_id) {
        return Err(QualificationFailure {
            stage: "actual retained import/reference retirement",
            cause: sanitized_cause(&error),
            owner: Some(owner),
            refs: Some(refs),
        });
    }
    check.map_err(|error| QualificationFailure {
        cause: sanitized_cause(&error),
        stage,
        owner: None,
        refs: None,
    })
}

#[tokio::test]
#[ignore = "requires explicit AGENTENV_NATIVE_PROFILE, root Linux/KVM, and a fresh protected native namespace"]
async fn native_agentenv_owned_vm_acceptance() -> Result<()> {
    let profile = std::env::var_os("AGENTENV_NATIVE_PROFILE")
        .context("AGENTENV_NATIVE_PROFILE must explicitly select a fresh protected descriptor")?;
    match qualify(Path::new(&profile)).await {
        Ok(()) => Ok(()),
        Err(failure) => {
            let message = format!("native acceptance refused: {failure:?}");
            // Keep failed-cleanup custody in this test process for diagnosis.
            // Process exit remains unresolved ownership, never cleanup proof.
            static DEBT: std::sync::OnceLock<std::sync::Mutex<Vec<QualificationFailure>>> =
                std::sync::OnceLock::new();
            DEBT.get_or_init(Default::default)
                .lock()
                .expect("qualification custody")
                .push(failure);
            bail!(message)
        }
    }
}

/// Isolates captured executable access after the exact production caps=[] scope.
/// No VM, image, shared template, or socket is created by these diagnostics.
#[tokio::test]
#[ignore = "explicit Linux captured-FD regression, run in the same root capability context as qualification"]
async fn captured_self_fd_scoped_launch() -> Result<()> {
    use std::os::fd::AsRawFd;
    if !nix::unistd::Uid::effective().is_root() {
        bail!("captured-FD diagnostic requires root");
    }
    let held = std::fs::File::open("/bin/true")?;
    let command = tokio::process::Command::new(format!("/proc/self/fd/{}", held.as_raw_fd()));
    let mut child = crate::privileges::spawn_tokio_command_scoped(command, &[], || Ok(())).await?;
    let status = timeout(Duration::from_secs(3), child.wait()).await??;
    if !status.success() {
        bail!("captured self FD execution failed");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Linux root capability diagnostic: the previous parent-proc FD route must be refused"]
async fn captured_parent_fd_scoped_launch_refused_after_regression() -> Result<()> {
    use std::os::fd::AsRawFd;
    if !nix::unistd::Uid::effective().is_root() {
        bail!("captured-FD diagnostic requires root");
    }
    let held = std::fs::File::open("/bin/true")?;
    let command = tokio::process::Command::new(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        held.as_raw_fd()
    ));
    match crate::privileges::spawn_tokio_command_scoped(command, &[], || Ok(())).await {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(_) => bail!("parent FD refusal was not PermissionDenied"),
        Ok(mut child) => {
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(3), child.wait()).await;
            bail!("parent FD unexpectedly executable in diagnostic capability context")
        }
    }
}

#[tokio::test]
#[ignore = "actual Linux FD relay smoke test requires explicit protected AGENTENV_NATIVE_PROFILE; no VM is booted"]
async fn captured_fd_relay_executes_same_owned_child_without_parent_proc_paths() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let profile = std::env::var_os("AGENTENV_NATIVE_PROFILE")
        .context("explicit protected native profile required")?;
    let profile = NativeGuestProfile::load(Path::new(&profile))?;
    let mut inputs = profile.admit_inputs()?;
    // The smoke child exits immediately; the production VMM pin remains intact.
    // Real protected image/kernel descriptors exercise the actual SCM_RIGHTS leg.
    inputs.vmm = std::fs::File::open("/bin/true")?;
    let mut raw = Vec::new();
    inputs
        .vmm
        .try_clone()?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > 64 * 1024 * 1024 {
        bail!("smoke executable bounds");
    }
    let digest = format!("{:x}", Sha256::digest(raw));
    let work = tempfile::Builder::new()
        .prefix("fd-")
        .tempdir_in(profile.config_path.parent().context("profile namespace")?)?;
    let mut owner = super::instance::FirecrackerInstance::new(work.path().to_owned());
    let result = owner.spawn_native(&inputs, &digest, None, None).await;
    let check: Result<()> = async {
        let mapping = result?;
        for path in [mapping.rootfs(), mapping.config(), mapping.kernel()] {
            if !path.to_string_lossy().starts_with("/proc/self/fd/") {
                bail!("relay returned parent-process path");
            }
        }
        let pid = owner.pid()?;
        // stop_native actually waits for this same retained process. A relay
        // receipt alone does not establish a booted or absent VM.
        if pid.as_raw() <= 0 {
            bail!("relay child identity absent");
        }
        owner.native_smoke_exit_success().await?;
        Ok(())
    }
    .await;
    if let Err(error) = owner.stop_native(Duration::from_secs(3)).await {
        // Preserve failed-cleanup ownership inside this controlled test process.
        static DEBT: std::sync::OnceLock<
            std::sync::Mutex<Vec<(super::instance::FirecrackerInstance, tempfile::TempDir)>>,
        > = std::sync::OnceLock::new();
        DEBT.get_or_init(Default::default)
            .lock()
            .expect("relay custody")
            .push((owner, work));
        return Err(error.context("relay child cleanup retained"));
    }
    check
}

// Uses the actual imported native store; recording persistence still proves no durable GC.
async fn qualify_default_factory_router() -> Result<()> {
    use crate::sandbox::qualification_native_transfer::{fd_count, qualified_http, HTTP_KEY};
    use crate::{
        cfg::ConfigManager,
        orchestrator::{
            CreateSandboxRequest, FileBackedSandboxPersister, InMemoryMetadataStore, Orchestrator,
            SandboxLaunchSource, SandboxTimeoutAction,
        },
        sandbox::{FirecrackerSandboxFactory, SandboxNetworkPolicy},
        types::{ImageConfigs, SandboxResources},
    };
    use serde_json::json;
    use std::{sync::Arc, time::Instant};
    let until = Instant::now() + Duration::from_secs(90);
    let baseline = fd_count()?;
    anyhow::ensure!(
        nix::unistd::Uid::effective().is_root(),
        "qualification requires Linux root"
    );
    let selected = std::path::PathBuf::from(
        std::env::var_os("AGENTENV_NATIVE_PROFILE")
            .context("explicit protected profile required")?,
    );
    let profile = NativeGuestProfile::load(&selected)?;
    let config = ConfigManager::global_config();
    anyhow::ensure!(
        config.firecracker.native_guest_profile.as_deref() == Some(selected.as_path())
            && config.resolved_firecracker_binary_path() == profile.vmm_executable
            && config.firecracker.work_dir.as_deref() == profile.config_path.parent(),
        "qualification runner must bind global native profile/VMM/private work root"
    );
    let namespace = profile
        .config_path
        .parent()
        .context("qualification native namespace")?;
    let before = std::fs::symlink_metadata(namespace)?;
    anyhow::ensure!(
        before.is_dir()
            && before.uid() == 0
            && before.gid() == 0
            && before.mode() & 0o7777 == 0o700,
        "qualification private root namespace"
    );
    anyhow::ensure!(
        !namespace.join("agentenv-attempted").try_exists()?,
        "qualification profile already claimed"
    );
    let refs = Arc::new(crate::image::cache::native_artifact_store::NativeArtifactStore::default());
    let orchestrator = Orchestrator::new_native_qualification_fixture(
        InMemoryMetadataStore::new(),
        FirecrackerSandboxFactory::new(),
        FileBackedSandboxPersister::with_qualification_delegate(),
        refs.clone(),
    )
    .await?;
    // Retain the actual orchestrator and all pinned inputs if retirement refuses.
    static DEBT: std::sync::OnceLock<std::sync::Mutex<Vec<Arc<Orchestrator>>>> =
        std::sync::OnceLock::new();
    let mut sandbox = None;
    let mut original_deleted = false;
    let mut stage = "default_factory_create_ready";
    let observed=tokio::time::timeout_at(tokio::time::Instant::from_std(until),async {
        let created=orchestrator.create_sandbox(CreateSandboxRequest {
            extra_drives: Vec::new(), extra_drives_in_snapshot: false, volume_mounts: Default::default(),
            source:SandboxLaunchSource::Image {image_ref:profile.rootfs_sha256.clone(),overlaybd_config_path:profile.rootfs_path.clone(),context:Box::new(crate::snapshot::CommandContext {workdir:"/workspace".into(),user:Some("1000".into()),..Default::default()}),resources:Some(SandboxResources{cpu_count:1,memory_mib:128,disk_size_mib:0}),extra_drives:Vec::new(),extra_boot_args:None,image_configs:Box::new(ImageConfigs::new())},
            timeout:Some(Duration::from_secs(60)),timeout_action:SandboxTimeoutAction::Delete,auto_resume:false,user_metadata:None,env_vars:None,network_policy:SandboxNetworkPolicy::default(),secure:false,custom_extension_params:None,
        }).await?;
        sandbox=Some(created.id);
        anyhow::ensure!(created.state==crate::orchestrator::SandboxState::Running,"qualification actual READY/Running required");
        stage="default_factory_authenticated_router";
        let volume_catalog_owner = tempfile::tempdir()?;
        let snapshot_manager = Arc::new(crate::snapshot::mock::mock_snapshot_manager());
        let volume_manager = Arc::new(crate::volume::VolumeManager::open_with_repository(
            volume_catalog_owner.path().join("catalog.json"), snapshot_manager.repository()
        ).await?);
        let api=Arc::new(crate::api::ApiImpl::new(orchestrator.clone(),snapshot_manager,Arc::new(crate::template::TemplateBuilder::new()),Arc::new(crate::image::ImageResolver::new(config)),volume_manager,None,vec!["native.example.invalid".into()],crate::api_key::ApiKey::new(HTTP_KEY)?));
        let app=crate::api::server::new(api);
        let(status,capability)=qualified_http(&app,created.id,None,1).await?;
        anyhow::ensure!(status.is_success()&&capability["epoch"].as_str().is_some(),"qualification actual factory capability required");
        let epoch=capability["epoch"].clone();
        let request=json!({"epoch":epoch,"operation_id":"factory-printf","request":{"kind":"exec","command":"/bin/sh","args":["-c","printf factory-router"],"env":{},"cwd":null,"timeout_ms":2000}});
        for keys in [0,2] {anyhow::ensure!(!qualified_http(&app,created.id,Some(request.clone()),keys).await?.0.is_success(),"qualification actual factory auth refusal");}
        let(status,accepted)=qualified_http(&app,created.id,Some(request.clone()),1).await?;
        anyhow::ensure!(status.is_success()&&accepted["kind"]=="accepted","qualification actual factory exec admission");
        let(_,retry)=qualified_http(&app,created.id,Some(request),1).await?;
        anyhow::ensure!(retry["session_id"]==accepted["session_id"]&&retry["operation_id"]==accepted["operation_id"],"qualification factory retry original");
        let query=json!({"epoch":epoch,"operation_id":"factory-printf","request":{"kind":"query"}});
        loop {
            let(status,result)=qualified_http(&app,created.id,Some(query.clone()),1).await?;
            anyhow::ensure!(status.is_success(),"qualification factory original query refused");
            if result["result"]["terminal"]==true {anyhow::ensure!(result["result"]["state"]=="succeeded"&&result["result"]["stdout_bytes"]==14&&result["result"]["process_absent"]==true,"qualification factory authenticated terminal");break;}
            anyhow::ensure!(Instant::now()<until,"qualification fixed factory budget");
            tokio::task::yield_now().await;
        }
        stage="default_factory_delete";
        orchestrator.delete_sandbox(created.id).await?;
        original_deleted = true;
        anyhow::ensure!(!qualified_http(&app,created.id,Some(query),1).await?.0.is_success(),"qualification factory stop admission");
        drop(app);
        Ok::<_,anyhow::Error>(())
    }).await.context("qualification fixed factory deadline").and_then(|r|r);
    let retirement = tokio::time::timeout(Duration::from_secs(15), async {
        if let Some(id) = sandbox.filter(|_| !original_deleted) {
            orchestrator.delete_sandbox(id).await?;
            original_deleted = true;
        }
        orchestrator.shutdown().await?;
        anyhow::ensure!(
            original_deleted,
            "qualification original deletion unconfirmed"
        );
        refs.check_retired_capture(
            sandbox.context("qualification original SandboxID unavailable")?,
        )?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("qualification factory retirement deadline")
    .and_then(|r| r);
    if retirement.is_err() {
        DEBT.get_or_init(Default::default)
            .lock()
            .expect("qualification factory custody")
            .push(orchestrator.clone());
    }
    let rejected_overlaybd = false;
    drop(profile);
    let descriptors_restored = if retirement.is_ok() {
        drop(orchestrator);
        drop(refs);
        let cleanup_until = Instant::now() + Duration::from_secs(3);
        loop {
            if fd_count()? == baseline {
                break true;
            }
            if Instant::now() >= cleanup_until {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    } else {
        false
    };
    if let Err(error) = &observed {
        eprintln!(
            "native default factory qualification refused: stage={stage} cause={} overlaybd_rejected={rejected_overlaybd} cleanup_ok={} fd_baseline_restored={descriptors_restored}",
            sanitized_cause(error),
            retirement.is_ok()
        );
    }
    observed?;
    retirement?;
    anyhow::ensure!(
        descriptors_restored,
        "qualification factory descriptor drift"
    );
    println!(
        "native default factory Router: authenticated_ready=true original_keyed_exec=true normal_delete=true owner_pinned_static_profile=true persistence_adapter=true no_durable_gc_claim=true"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires explicit fresh protected AGENTENV_NATIVE_PROFILE and AENV_CONFIG_PATH binding same native profile/VMM/work namespace, root Linux/KVM; consumes profile only at actual launch"]
async fn native_agentenv_default_factory_router_acceptance() -> Result<()> {
    static JOB: tokio::sync::Mutex<Option<tokio::task::JoinHandle<Result<()>>>> =
        tokio::sync::Mutex::const_new(None);
    let mut job = JOB.lock().await;
    anyhow::ensure!(job.is_none(), "qualification factory task already retained");
    *job = Some(tokio::spawn(qualify_default_factory_router()));
    let result = job
        .as_mut()
        .expect("retained factory task")
        .await
        .context("qualification factory retained join")?;
    job.take();
    result
}

#[tokio::test]
#[ignore = "read-only protected native admission matrix requires explicit AGENTENV_NATIVE_PROFILE; never claims or spawns the profile"]
async fn native_default_factory_refuses_unsupported_requests_before_effects() -> Result<()> {
    use crate::sandbox::{
        FirecrackerSandboxFactory, FreshSandboxBuildSpec, SandboxBackendFactory,
        SandboxLaunchConfig,
    };
    let selected = std::env::var_os("AGENTENV_NATIVE_PROFILE")
        .context("explicit protected profile required")?;
    let profile = NativeGuestProfile::load(Path::new(&selected))?;
    let namespace = profile.config_path.parent().context("profile namespace")?;
    let config = crate::cfg::ConfigManager::global_config();
    anyhow::ensure!(
        config.firecracker.native_guest_profile.as_deref() == Some(Path::new(&selected))
            && config.resolved_firecracker_binary_path() == profile.vmm_executable
            && config.firecracker.work_dir.as_deref() == Some(namespace),
        "qualification matrix requires actual global protected native profile"
    );
    anyhow::ensure!(
        !namespace.join("agentenv-attempted").try_exists()?,
        "matrix requires unclaimed profile"
    );
    let build = FreshSandboxBuildSpec {
        image_config_path: profile.rootfs_path.clone(),
        context: crate::snapshot::CommandContext {
            user: Some("1000".into()),
            workdir: "/workspace".into(),
            ..Default::default()
        },
        resources: crate::types::SandboxResources {
            cpu_count: 1,
            memory_mib: 128,
            disk_size_mib: 0,
        },
        extra_drives: Vec::new(),
        extra_boot_args: None,
    };
    let launch = SandboxLaunchConfig::new(
        crate::types::SandboxId::new(),
        profile.rootfs_sha256.clone(),
    );
    super::factory::validate_native_request(&profile, &build, &launch)?;
    let mut cases = Vec::new();
    let mut b = build.clone();
    b.image_config_path = namespace.join("foreign-root.ext4");
    cases.push((b, launch.clone()));
    let mut l = launch.clone();
    l.snapshot_id = "0".repeat(64);
    cases.push((build.clone(), l));
    let mut b = build.clone();
    b.resources.disk_size_mib = 1;
    cases.push((b, launch.clone()));
    let mut b = build.clone();
    b.resources.cpu_count = 2;
    cases.push((b, launch.clone()));
    for memory in [127, 513] {
        let mut b = build.clone();
        b.resources.memory_mib = memory;
        cases.push((b, launch.clone()));
    }
    let mut b = build.clone();
    b.extra_boot_args = Some("console=ttyS0".into());
    cases.push((b, launch.clone()));
    let mut b = build.clone();
    b.context.user = Some("root".into());
    cases.push((b, launch.clone()));
    let mut b = build.clone();
    b.context.workdir = "/".into();
    cases.push((b, launch.clone()));
    let mut b = build.clone();
    b.context.env_vars.insert("X".into(), "1".into());
    cases.push((b, launch.clone()));
    let mut b = build.clone();
    b.context.cmd = Some(vec!["/bin/sh".into()]);
    cases.push((b, launch.clone()));
    let mut b = build.clone();
    b.context.exposed_ports.push("80/tcp".into());
    cases.push((b, launch.clone()));
    let mut l = launch.clone();
    l.env_vars = Some(std::collections::HashMap::from([("X".into(), "1".into())]));
    cases.push((build.clone(), l));
    let mut l = launch.clone();
    l.network = Some(crate::sandbox::SandboxNetworkPolicy::new(
        false,
        crate::sandbox::BaseSandboxNetworkPolicy::Deny,
        Default::default(),
    ));
    cases.push((build.clone(), l));
    let mut l = launch.clone();
    l.extra_mmds
        .insert("caller".into(), serde_json::json!(true));
    cases.push((build.clone(), l));
    let mut l = launch.clone();
    l.custom_extension_params = Some(serde_json::Map::from_iter([(
        "caller".into(),
        serde_json::json!(true),
    )]));
    cases.push((build.clone(), l));
    let mut b = build.clone();
    b.extra_drives
        .push(crate::sandbox::ExtraDrive::try_new_overlaybd(
            "extra",
            namespace.join("extra.json"),
            false,
        )?);
    cases.push((b, launch.clone()));
    let mut l = launch.clone();
    l.envd_access_token = Some(
        crate::sandbox::SandboxAccessTokenGenerator::new(&"1".repeat(64))?
            .generate(launch.sandbox_id),
    );
    cases.push((build.clone(), l));
    for (index, (b, l)) in cases.into_iter().enumerate() {
        anyhow::ensure!(
            FirecrackerSandboxFactory::new().build(b, l).is_err(),
            "native request matrix case {index} admitted"
        );
        anyhow::ensure!(
            !namespace.join("agentenv-attempted").try_exists()?,
            "refused request consumed profile"
        );
    }
    let mut common = FirecrackerCommonConfig::new(
        profile.vmm_executable.clone(),
        String::new(),
        FirecrackerRuntimePolicy {
            socket_timeout: Duration::from_secs(3),
            socket_poll_interval: Duration::from_millis(10),
            envd_timeout: Duration::from_secs(30),
            envd_poll_interval: Duration::from_millis(10),
        },
    );
    common.native_guest_profile = Some(profile.clone());
    common.default_user = Some("1000".into());
    common.default_workdir = Some("/workspace".into());
    let base = FirecrackerSandboxConfig {
        common,
        kernel_image: profile.kernel_path.clone(),
        boot_args: None,
        vcpu_count: 1,
        mem_size_mib: 128,
    };
    base.validate()?;
    let mut configs = Vec::new();
    let mut c = base.clone();
    c.common.rootfs_image_config = Some(crate::sandbox::OverlaybdConfig {
        image_config_path: profile.rootfs_path.clone(),
        read_only: false,
        runtime_upper_mode: overlaybd::config::UpperMode::LogStructured,
    });
    configs.push(c);
    let mut c = base.clone();
    c.common.rootfs_virtual_size = Some(512 * 1024 * 1024);
    configs.push(c);
    let mut c = base.clone();
    c.common.default_user = Some("root".into());
    configs.push(c);
    let mut c = base.clone();
    c.common.default_workdir = Some("/".into());
    configs.push(c);
    let mut c = base.clone();
    c.common.mmds_metadata = Some(super::mmds::MmdsMetadata::new(
        launch.sandbox_id,
        profile.rootfs_sha256.clone(),
    ));
    configs.push(c);
    let mut c = base.clone();
    c.common.cpu_config_json = Some("{}".into());
    configs.push(c);
    let mut c = base.clone();
    c.boot_args = Some("console=ttyS0".into());
    configs.push(c);
    let mut c = base.clone();
    c.kernel_image = namespace.join("foreign-kernel");
    configs.push(c);
    for (index, c) in configs.into_iter().enumerate() {
        anyhow::ensure!(
            c.validate().is_err(),
            "native direct constructor matrix case {index} admitted"
        );
        anyhow::ensure!(
            !namespace.join("agentenv-attempted").try_exists()?,
            "direct constructor validation consumed profile"
        );
    }
    Ok(())
}
