//! Actual requester identity and reciprocal local issuer qualification, no VM.
use super::native_issuer::*;
use anyhow::{Context, Result, ensure};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;
async fn run() -> Result<()> {
    let entry_until = Instant::now() + Duration::from_secs(20);
    let path = PathBuf::from(
        std::env::var_os("AGENTENV_NATIVE_ISSUER_CASE_DIR")
            .context("protected issuer case directory required")?,
    );
    ensure!(
        debts().lock().unwrap().is_empty(),
        "requester publication debt retained"
    );
    let mut publication = Publication::new(&path)?;
    let orchestrator = crate::orchestrator::Orchestrator::new_native_api_fixture(
        crate::orchestrator::InMemoryMetadataStore::new(),
        super::FirecrackerSandboxFactory::new(),
        crate::orchestrator::DisabledSandboxPersister,
    )
    .await?;
    let mut phase = Phase::Setup;
    let observed=async {
        let identity=orchestrator.native_create_incarnation().to_string();
        let pid=std::process::id();ensure!(nix::unistd::geteuid().as_raw()==0,"root requester required");
        let start=tick(pid)?;let group=cgroup(pid)?;
        let (_held,_,digest)=exe(pid,entry_until.min(Instant::now()+Duration::from_secs(3)))?;
        ensure!(tick(pid)?==start && cgroup(pid)?==group,"requester capture changed");
        ancestors(&group.join("anchor"))?;
        let bytes=serde_json::to_vec(&serde_json::json!({"schema":1,"server_incarnation":identity,
            "peer_pid":pid,"peer_uid":0,"start_tick":start,"exe_sha256":digest,"cgroup_path":group}))?;
        publication.publish(&bytes)?;
        let endpoint_path=path.join("worker-endpoint.json");let request_path=path.join("issuer-request.json");
        while !endpoint_path.try_exists()? || !request_path.try_exists()? {
            publication.valid()?;ensure!(Instant::now()<entry_until,"issuer fixture input deadline");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let (endpoint_file,raw)=Held::load(&endpoint_path)?;
        let endpoint:Endpoint=serde_json::from_slice(&raw)?;
        let (request_file,raw)=Held::load(&request_path)?;
        let envelope:Envelope=serde_json::from_slice(&raw)?;
        ensure!(envelope.schema==1 && envelope.authority_epoch>0 && envelope.request.schema==1
            && envelope.request.kind=="grant" && envelope.request.server_incarnation==identity
            && envelope.request.context.target==endpoint.worker && envelope.request.context.protocol_major==2
            && (1..=3000).contains(&envelope.request.context.remaining_budget_ms),"issuer original request binding refused");
        endpoint_file.verify()?;request_file.verify()?;publication.valid()?;
        let until=entry_until.min(Instant::now()+Duration::from_secs(3));
        let mut authority=None;
        let first=exchange(&endpoint,&publication,&envelope.request,envelope.authority_epoch,until,&mut authority,&mut phase)?;
        let mut query=envelope.request.clone();query.kind="query".into();
        endpoint_file.verify()?;request_file.verify()?;publication.valid()?;
        let until=entry_until.min(Instant::now()+Duration::from_secs(3));
        let second=exchange(&endpoint,&publication,&query,envelope.authority_epoch,until,&mut authority,&mut phase)?;
        ensure!(first==second,"issuer original query receipt drift");
        endpoint_file.verify()?;request_file.verify()?;publication.valid()?;
        Ok::<_,anyhow::Error>(())
    }.await;
    let shutdown = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(entry_until),
        orchestrator.shutdown(),
    )
    .await
    {
        Ok(result) => result.map_err(anyhow::Error::from),
        Err(_) => Err(anyhow::anyhow!("requester orchestrator shutdown deadline")),
    };
    let cleanup = publication.retire();
    if observed.is_err() {
        eprintln!("native issuer requester failure: stage={}", phase.label());
    }
    observed?;
    shutdown?;
    cleanup?;
    println!(
        "native issuer genuine Orchestrator requester: unavailable=true original_query=true reciprocal_peer=true no_vm_claim=true"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires protected issuer case directory and actual coupled Worker endpoint"]
async fn native_issuer_genuine_orchestrator_requester_child() -> Result<()> {
    static JOB: AsyncMutex<Option<tokio::task::JoinHandle<Result<()>>>> =
        AsyncMutex::const_new(None);
    let mut job = JOB.lock().await;
    ensure!(job.is_none(), "requester task already retained");
    *job = Some(tokio::spawn(run()));
    let result = job
        .as_mut()
        .unwrap()
        .await
        .context("requester retained task join")?;
    job.take();
    result
}

#[test]
fn native_issuer_receipt_codec_refuses_duplicate_and_missing_original_fields() {
    let raw = r#"{"schema":1,"status":"unavailable","reason":"profile_allocation_unavailable","grant_id":null,"operation_id":"p0.original","reservation_id":"p0.reservation","worker":{"environment_id":"owned","environment_generation":1,"node_id":7,"node_generation":1,"incarnation":"worker"},"authority_epoch":1,"request_id":7,"partition_id":0,"slot_index":0,"slot_generation":1,"server_incarnation":"01900000-0000-7000-8000-000000000001","profile_allocation_id":"requested","request_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    assert!(serde_json::from_str::<Receipt>(raw).is_ok());
    for field in [
        r#""schema":1"#,
        r#""status":"unavailable""#,
        r#""grant_id":null"#,
        r#""operation_id":"p0.original""#,
        r#""reservation_id":"p0.reservation""#,
        r#""environment_id":"owned""#,
    ] {
        let duplicated = raw.replacen(field, &format!("{field},{field}"), 1);
        // The duplicate remains valid JSON for a last-wins Value parser.
        assert!(serde_json::from_str::<serde_json::Value>(&duplicated).is_ok());
        assert!(serde_json::from_str::<Receipt>(&duplicated).is_err());
    }
    assert!(serde_json::from_str::<Receipt>(&raw.replace("\"grant_id\":null,", "")).is_err());
    assert!(
        serde_json::from_str::<Receipt>(
            &raw.replace("\"grant_id\":null", "\"grant_id\":\"invented\"")
        )
        .is_err()
    );
    assert!(serde_json::from_str::<Receipt>(&raw.replacen("{", "{\"extra\":true,", 1)).is_err());
}

#[tokio::test]
#[ignore = "requires owned protected root workspace for actual inode version change"]
async fn native_issuer_original_executable_version_detects_owned_mode_roundtrip() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path =
        PathBuf::from(std::env::var_os("AENV_HOME_PATH").context("protected root workspace")?);
    let mut owner = Publication::new(&path)?;
    let observed = (|| -> Result<bool> {
        owner.publish(b"owned version fixture")?;
        let old = owner.file.as_ref().unwrap().metadata()?;
        owner
            .file
            .as_ref()
            .unwrap()
            .set_permissions(std::fs::Permissions::from_mode(0o400))?;
        let changed = owner.file.as_ref().unwrap().metadata()?;
        let changed_refused = !same(&old, &changed);
        owner
            .file
            .as_ref()
            .unwrap()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let restored = owner.file.as_ref().unwrap().metadata()?;
        let restored_refused = !same(&old, &restored);
        // The qualification changes its own captured FD only. Preserve exact
        // inode/name ownership while advancing its cleanup pin after that change.
        ensure!(
            same_anchor(&old, &restored)
                && same(
                    &restored,
                    &std::fs::symlink_metadata(path.join("requester-identity.json"))?
                ),
            "version fixture original changed"
        );
        owner.pin = Some(restored);
        Ok(changed_refused && restored_refused)
    })();
    let cleanup = owner.retire();
    let refused = observed?;
    cleanup?;
    ensure!(
        refused,
        "full numeric version accepted owned mode roundtrip"
    );
    Ok(())
}

// The parent is the existing production Worker issuer fixture. No serialized
// Grant is supplied to this child: reserve/query use the pinned reciprocal peer.
async fn run_reserved_promotion(expired: bool) -> Result<()> {
    use crate::{
        cfg::ConfigManager,
        orchestrator::{DisabledSandboxPersister, InMemoryMetadataStore, Orchestrator},
        sandbox::FirecrackerSandboxFactory,
    };
    use sha2::Digest;
    use std::{future::Future, sync::Arc};
    type Actual =
        Orchestrator<InMemoryMetadataStore, FirecrackerSandboxFactory, DisabledSandboxPersister>;
    static DEBT: std::sync::OnceLock<std::sync::Mutex<Option<Arc<Actual>>>> =
        std::sync::OnceLock::new();
    let until = Instant::now() + Duration::from_secs(90);
    let config = ConfigManager::global_config();
    ensure!(
        config.is_native_root() && config.native_issuer_requester.is_some(),
        "explicit native requester mode required"
    );
    let path = PathBuf::from(
        std::env::var_os("AGENTENV_NATIVE_ISSUER_CASE_DIR")
            .context("protected issuer case directory required")?,
    );
    let profile_path = PathBuf::from(
        std::env::var_os("AGENTENV_NATIVE_PROFILE")
            .context("fresh protected native profile required")?,
    );
    let profile = super::NativeGuestProfile::load(&profile_path)?;
    let marker = profile
        .config_path
        .parent()
        .context("native namespace")?
        .join("agentenv-attempted");
    ensure!(!marker.try_exists()?, "profile already claimed");
    let refs = Arc::new(crate::image::cache::native_artifact_store::NativeArtifactStore::default());
    let orchestrator = Actual::new_native_qualification_fixture(
        InMemoryMetadataStore::new(),
        FirecrackerSandboxFactory::new(),
        DisabledSandboxPersister,
        refs.clone(),
    )
    .await?;
    let mut original = None;
    let mut owner = None;
    let mut stage = "worker_request";
    let observed = async {
        let request_path = path.join("issuer-request.json");
        while !request_path.try_exists()? {
            ensure!(Instant::now() < until, "issuer original input deadline");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let (request_pin, raw) = Held::load(&request_path)?;
        let envelope: Envelope = serde_json::from_slice(&raw)?;
        ensure!(
            envelope.schema == 1
                && envelope.request.kind == "grant"
                && envelope.request.server_incarnation
                    == orchestrator.native_create_incarnation().to_string(),
            "actual requester original binding"
        );
        let canonical = br#"{"schema":1,"memory_mib":128}"#;
        ensure!(
            envelope.request.request_sha256 == format!("{:x}", sha2::Sha256::digest(canonical)),
            "actual original launch fingerprint"
        );
        let request = serde_json::to_vec(&envelope.request)?;
        stage = "authenticated_reserved_grant";
        let grant = orchestrator.native_reserve_original(&request, envelope.authority_epoch)?;
        request_pin.verify()?;
        ensure!(
            grant.profile_path() == profile_path,
            "actual selected profile receipt"
        );
        profile.verify_reserved_source(grant.profile_path(), grant.profile_sha256())?;
        ensure!(
            orchestrator.native_query_original(&envelope.request.context.operation_id)? == grant,
            "original receipt immutable"
        );
        let operation = &envelope.request.context.operation_id;
        original = orchestrator.qualification_native_original_sandbox_id(operation);
        let id = original.context("retained original SandboxUUID")?;
        ensure!(
            orchestrator
                .qualification_native_original_owner(operation)
                .is_none(),
            "backend existed before promotion"
        );
        if expired {
            stage = "original_expiry_before_claim";
            let deadline = orchestrator
                .qualification_native_original_expiry(operation)
                .context("actual retained Worker expiry")?;
            ensure!(deadline < until, "original expiry outside fixture deadline");
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            ensure!(
                orchestrator
                    .native_launch_original(operation, canonical)
                    .await
                    .is_err(),
                "expired original promoted"
            );
            ensure!(
                !marker.try_exists()?
                    && orchestrator
                        .qualification_native_original_owner(operation)
                        .is_none()
                    && orchestrator
                        .qualification_native_registered_owner(id)
                        .await
                        .is_none(),
                "expired original created an owner or claim"
            );
        } else {
            stage = "owner_before_first_await";
            let mut launch = Box::pin(orchestrator.native_launch_original(operation, canonical));
            // This single-thread Tokio child does not poll the shielded launch
            // task until this poll returns; no synthetic factory or artifact gate.
            std::future::poll_fn(|cx| ensure_poll_pending(launch.as_mut().poll(cx))).await?;
            owner = orchestrator.qualification_native_original_owner(operation);
            ensure!(owner.is_some(), "actual backend absent at first await");
            stage = "actual_factory_ready";
            let ready = tokio::time::timeout_at(tokio::time::Instant::from_std(until), launch)
                .await
                .context("original launch fixture deadline")??;
            ensure!(
                ready.id == id && ready.state == crate::orchestrator::SandboxState::Running,
                "actual original READY required"
            );
            let registered = orchestrator
                .qualification_native_registered_owner(id)
                .await
                .context("actual registry owner")?;
            ensure!(
                Arc::ptr_eq(owner.as_ref().unwrap(), &registered),
                "registry replaced original backend"
            );
            ensure!(
                orchestrator
                    .native_launch_original(operation, canonical)
                    .await
                    .is_err(),
                "original start replayed"
            );
            ensure!(
                Arc::ptr_eq(
                    owner.as_ref().unwrap(),
                    &orchestrator
                        .qualification_native_original_owner(operation)
                        .context("original owner lost")?
                ),
                "duplicate changed original owner"
            );
            ensure!(
                registered.lock().await.native_control_ready(),
                "actual authenticated native client required"
            );
            stage = "actual_same_owner_stop";
            orchestrator.delete_sandbox(id).await?;
            ensure!(
                !registered.lock().await.native_control_ready()
                    && orchestrator
                        .qualification_native_registered_owner(id)
                        .await
                        .is_none()
                    && orchestrator
                        .qualification_native_original_owner(operation)
                        .is_none(),
                "actual original backend retirement incomplete"
            );
            drop(registered);
            owner.take();
            refs.check_retired_capture(id)?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = async {
        if let Some(id) = original {
            if orchestrator
                .qualification_native_registered_owner(id)
                .await
                .is_some()
            {
                orchestrator.delete_sandbox(id).await?;
            }
        }
        owner.take();
        orchestrator.shutdown().await?;
        orchestrator.qualification_native_requester_retire_identity()?;
        Ok::<_, anyhow::Error>(())
    };
    let cleanup = tokio::time::timeout(Duration::from_secs(15), cleanup)
        .await
        .context("coupled owner retirement deadline")
        .and_then(|r| r);
    if observed.is_err() || cleanup.is_err() {
        let mut debt = DEBT
            .get_or_init(Default::default)
            .lock()
            .expect("coupled owner debt");
        ensure!(debt.is_none(), "bounded coupled owner debt occupied");
        *debt = Some(orchestrator.clone());
    }
    if observed.is_err() || cleanup.is_err() {
        eprintln!(
            "coupled native promotion: stage={stage} cleanup={}",
            cleanup.is_ok()
        );
    }
    observed?;
    cleanup?;
    println!(
        "coupled native promotion: expired_before_claim={expired} actual_owner_stop={} durable_original_retained=true journal_gc_claim=false fd_baseline_claim=false",
        !expired
    );
    Ok(())
}

fn ensure_poll_pending<T>(poll: std::task::Poll<T>) -> std::task::Poll<Result<()>> {
    match poll {
        std::task::Poll::Pending => std::task::Poll::Ready(Ok(())),
        std::task::Poll::Ready(_) => std::task::Poll::Ready(Err(anyhow::anyhow!(
            "launch completed before retained-owner checkpoint"
        ))),
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual coupled Worker issuer, explicit protected native-root configuration and fresh profile; consumes profile on success"]
async fn native_issuer_genuine_reserved_profile_owner_child() -> Result<()> {
    static JOB: AsyncMutex<Option<tokio::task::JoinHandle<Result<()>>>> =
        AsyncMutex::const_new(None);
    let mut job = JOB.lock().await;
    ensure!(job.is_none(), "coupled promotion task already retained");
    *job = Some(tokio::spawn(run_reserved_promotion(false)));
    let result = job
        .as_mut()
        .unwrap()
        .await
        .context("coupled promotion retained task join")?;
    job.take();
    result
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual coupled Worker issuer and independent fresh profile; verifies original expiry before any claim"]
async fn native_issuer_genuine_expired_profile_no_claim_child() -> Result<()> {
    static JOB: AsyncMutex<Option<tokio::task::JoinHandle<Result<()>>>> =
        AsyncMutex::const_new(None);
    let mut job = JOB.lock().await;
    ensure!(job.is_none(), "coupled promotion task already retained");
    *job = Some(tokio::spawn(run_reserved_promotion(true)));
    let result = job
        .as_mut()
        .unwrap()
        .await
        .context("coupled promotion retained task join")?;
    job.take();
    result
}

// Genuine production ingress only: neither a fake response nor a backend claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngressPurpose {
    ActivationOnly,
    FixedExecution,
    UnknownQuery,
    UnavailableStart,
}

// Pin bytes by FD/path version without reading credential or mutable drive content.
// Activation has no authority to dispatch and must preserve consumed profile state.
struct ActivationPin {
    path: PathBuf,
    held: Option<(std::fs::File, std::fs::Metadata)>,
}
impl ActivationPin {
    fn capture(path: PathBuf, optional: bool) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        ancestors(&path)?;
        let held = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
            .open(&path)
        {
            Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => None,
            result => {
                let file = result?;
                let pin = file.metadata()?;
                ensure!(
                    pin.is_file()
                        && pin.uid() == 0
                        && pin.gid() == 0
                        && pin.mode() & 0o022 == 0
                        && pin.nlink() == 1,
                    "protected activation source"
                );
                ensure!(
                    same(&pin, &std::fs::symlink_metadata(&path)?),
                    "activation source path drift"
                );
                Some((file, pin))
            }
        };
        Ok(Self { path, held })
    }
    fn verify(&self) -> Result<()> {
        ancestors(&self.path)?;
        if let Some((file, pin)) = &self.held {
            ensure!(
                same(pin, &file.metadata()?) && same(pin, &std::fs::symlink_metadata(&self.path)?),
                "activation source version drift"
            );
        } else {
            ensure!(
                matches!(std::fs::symlink_metadata(&self.path),Err(ref error) if error.kind()==std::io::ErrorKind::NotFound),
                "activation created claim"
            );
        }
        Ok(())
    }
}

async fn run_transport_child(purpose: IngressPurpose) -> Result<()> {
    let start = purpose == IngressPurpose::UnavailableStart;
    use crate::{
        cfg::ConfigManager,
        orchestrator::{DisabledSandboxPersister, InMemoryMetadataStore, Orchestrator},
        sandbox::FirecrackerSandboxFactory,
    };
    use std::sync::{Arc, OnceLock};
    type Actual =
        Orchestrator<InMemoryMetadataStore, FirecrackerSandboxFactory, DisabledSandboxPersister>;
    static DEBT: OnceLock<std::sync::Mutex<Option<Arc<Actual>>>> = OnceLock::new();
    let until = Instant::now()
        + Duration::from_secs(if purpose == IngressPurpose::FixedExecution {
            100
        } else {
            25
        });
    let config = ConfigManager::global_config();
    ensure!(
        config.is_native_root()
            && config.native_worker_ingress
            && config.native_worker_provision
            && config.native_issuer_requester.is_some(),
        "explicit actual provisioned ingress config required"
    );
    let path = PathBuf::from(
        std::env::var_os("AGENTENV_NATIVE_ISSUER_CASE_DIR").context("owned case required")?,
    );
    let profile = super::NativeGuestProfile::load(
        config
            .firecracker
            .native_guest_profile
            .as_ref()
            .context("protected profile required")?,
    )?;
    let marker = profile
        .config_path
        .parent()
        .context("profile namespace")?
        .join("agentenv-attempted");
    let activation_pins = if purpose == IngressPurpose::ActivationOnly {
        let mut pins = Vec::new();
        for asset in [
            config.firecracker.native_guest_profile.as_ref().unwrap(),
            &profile.rootfs_path,
            &profile.config_path,
            &profile.kernel_path,
            &profile.credential_path,
            &profile.readiness_executable,
            &profile.vmm_executable,
        ] {
            pins.push(ActivationPin::capture(asset.clone(), false)?);
        }
        pins.push(ActivationPin::capture(marker.clone(), true)?);
        pins.push(ActivationPin::capture(
            marker.parent().unwrap().join("native-worker-claim.json"),
            true,
        )?);
        pins
    } else {
        ensure!(
            matches!(std::fs::symlink_metadata(&marker),Err(ref e) if e.kind()==std::io::ErrorKind::NotFound),
            "unclaimed profile required"
        );
        Vec::new()
    };
    let orchestrator = Actual::new_native_qualification_fixture(
        InMemoryMetadataStore::new(),
        FirecrackerSandboxFactory::new(),
        DisabledSandboxPersister,
        Arc::new(crate::image::cache::native_artifact_store::NativeArtifactStore::default()),
    )
    .await?;
    let debt = DEBT.get_or_init(|| std::sync::Mutex::new(None));
    ensure!(debt.lock().unwrap().is_none(), "prior ingress child debt");
    *debt.lock().unwrap() = Some(orchestrator.clone());
    let observed=async {
        if purpose == IngressPurpose::ActivationOnly {
            let stop = path.join("transport-stop.json");
            let intents = path.join("s/sdk-create-intents");
            loop {
                ensure!(Instant::now()<until,"activation parent deadline");
                for pin in &activation_pins { pin.verify()?; }
                ensure!(!path.join("issuer-request.json").try_exists()?,"activation cannot dispatch original envelopes");
                ensure!(std::fs::read_dir(&intents)?.next().is_none(),"activation cannot create Calling/backend owners");
                if stop.try_exists()? { break; }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let (stop_pin,raw)=Held::load(&stop)?;
            #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Stop {schema:u32,stop:bool}
            let stop:Stop=serde_json::from_slice(&raw)?;
            ensure!(stop.schema==1&&stop.stop,"closed activation stop request");stop_pin.verify()?;
            return Ok(());
        }
        if purpose == IngressPurpose::FixedExecution {
            let stop = path.join("transport-stop.json");
            while !stop.try_exists()? { ensure!(Instant::now()<until,"fixed execution parent deadline"); tokio::time::sleep(Duration::from_millis(1)).await; }
            let (stop_pin,raw)=Held::load(&stop)?;
            #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Stop {schema:u32,stop:bool}
            let stopped:Stop=serde_json::from_slice(&raw)?;ensure!(stopped.schema==1&&stopped.stop,"closed fixed execution stop");stop_pin.verify()?;
            let (evidence_pin,raw)=Held::load(&path.join("fixed-execution-observed.json"))?;
            #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Observed {schema:u32,operation_id:String,sandbox_id:String}
            let evidence:Observed=serde_json::from_slice(&raw)?;
            ensure!(evidence.schema==1&&!evidence.operation_id.is_empty()&&evidence.operation_id.len()<=128,"closed fixed execution evidence");
            let id=orchestrator.qualification_native_original_sandbox_id(&evidence.operation_id).context("actual Worker Calling absent")?;
            ensure!(id.to_string()==evidence.sandbox_id,"actual Worker sandbox binding");
            ensure!(orchestrator.qualification_native_original_owner(&evidence.operation_id).is_none(),"narrow Stop has not retired actual backend owner");
            let claim=ActivationPin::capture(marker.clone(),false)?;claim.verify()?;
            ensure!(std::fs::read_dir(path.join("s/sdk-create-intents"))?.next().is_some(),"charged Calling evidence absent");
            evidence_pin.verify()?;
            return Ok(());
        }
        let request_path=path.join("issuer-request.json");
        while !request_path.try_exists()? {ensure!(Instant::now()<until,"original input deadline");tokio::time::sleep(Duration::from_millis(1)).await;}
        let (pin,raw)=Held::load(&request_path)?;
        let envelope:Envelope=serde_json::from_slice(&raw)?;
        ensure!(envelope.request.server_incarnation==orchestrator.native_create_incarnation().to_string(),"original SDK incarnation");
        let operation=&envelope.request.context.operation_id;
        let stop=path.join("transport-stop.json");
        while !stop.try_exists()? {pin.verify()?;ensure!(Instant::now()<until,"transport parent deadline");tokio::time::sleep(Duration::from_millis(1)).await;}
        let (stop_pin,raw)=Held::load(&stop)?;
        #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Stop {schema:u32,stop:bool}
        let stop:Stop=serde_json::from_slice(&raw)?;ensure!(stop.schema==1&&stop.stop,"closed stop request");stop_pin.verify()?;
        let id=orchestrator.qualification_native_original_sandbox_id(operation);
        ensure!(id.is_some()==start,"actual requester Calling presence mismatch");
        ensure!(orchestrator.qualification_native_original_owner(operation).is_none(),"unexpected backend owner");
        ensure!(matches!(std::fs::symlink_metadata(&marker),Err(ref e) if e.kind()==std::io::ErrorKind::NotFound),"unexpected VM claim");
        pin.verify()?;
        Ok::<_,anyhow::Error>(())
    }.await;
    let cleanup = tokio::time::timeout_at(
        tokio::time::Instant::from_std(until),
        orchestrator.shutdown(),
    )
    .await;
    observed?;
    cleanup??;
    for pin in &activation_pins {
        pin.verify()?;
    }
    if purpose == IngressPurpose::ActivationOnly {
        ensure!(
            std::fs::read_dir(path.join("s/sdk-create-intents"))?
                .next()
                .is_none(),
            "activation retained Calling/backend owner"
        );
        ensure!(
            !path.join("issuer-request.json").try_exists()?,
            "activation original envelope effect"
        );
    }
    let ingress_path = if matches!(
        purpose,
        IngressPurpose::ActivationOnly | IngressPurpose::FixedExecution
    ) {
        path.join("s")
    } else {
        path.clone()
    };
    ensure!(
        !ingress_path
            .join("native-worker-ingress.sock")
            .try_exists()?
            && !ingress_path
                .join("native-worker-ingress.json")
                .try_exists()?,
        "actual ingress retirement incomplete"
    );
    // Keep original requester/case evidence intentionally. No journal GC,
    // requester namespace retirement, FD-baseline or quota refund claim.
    if purpose == IngressPurpose::FixedExecution {
        println!(
            "native fixed execution child: genuine_worker_calling=true backend_stopped=true claim_retained=true ingress_retired=true requester_evidence_retained=true"
        );
    } else {
        println!(
            "native transport child: purpose={:?} start={} no_new_vm_claim=true ingress_retired=true requester_evidence_retained=true",
            purpose, start
        );
    }
    Ok(())
}
#[tokio::test]
#[ignore = "actual protected native-root ingress, real Worker unavailable; no profile consumption"]
async fn native_sdk_transport_unknown_query_child() -> Result<()> {
    run_transport_child_shielded(IngressPurpose::UnknownQuery).await
}
#[tokio::test]
#[ignore = "actual protected native-root ingress and original unavailable Calling; no profile consumption"]
async fn native_sdk_transport_unavailable_start_child() -> Result<()> {
    run_transport_child_shielded(IngressPurpose::UnavailableStart).await
}
async fn run_transport_child_shielded(purpose: IngressPurpose) -> Result<()> {
    static JOB: AsyncMutex<Option<tokio::task::JoinHandle<Result<()>>>> =
        AsyncMutex::const_new(None);
    let mut job = JOB.lock().await;
    ensure!(job.is_none(), "original child retained");
    *job = Some(tokio::spawn(run_transport_child(purpose)));
    let result = job.as_mut().unwrap().await;
    job.take();
    result?
}

#[tokio::test]
#[ignore = "actual protected provisioned SDK ingress activation only; consumed profile permitted read-only; no dispatch or VM"]
async fn native_sdk_node_activation_only_child() -> Result<()> {
    run_transport_child_shielded(IngressPurpose::ActivationOnly).await
}

#[tokio::test]
#[ignore = "actual Worker fixed execution ingress; fresh protected profile and parent-owned bounded Stop required"]
async fn native_sdk_worker_fixed_execution_child() -> Result<()> {
    run_transport_child_shielded(IngressPurpose::FixedExecution).await
}
