//! Factory for creating FirecrackerSandbox instances.
//!
//! This module implements the [`FirecrackerSandboxFactory`] which creates instances of [`FirecrackerSandbox`] by
//! reading configuration from the global [`ConfigManager`]. It also handles
//! launches from committed snapshots and resumes from snapshot configs.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use serde_json::Value;

use super::config::FirecrackerSandboxConfig;
use super::sandbox::{FirecrackerPausedState, FirecrackerSandbox};
use crate::cfg::ConfigManager;
use crate::sandbox::backend::{PausedSandboxState, SandboxBackend, SandboxBackendFactory};
use crate::sandbox::{
    EnvdAccessToken, FreshSandboxBuildSpec, OverlaybdConfig, SandboxLaunchConfig, UblkConfig,
};
use crate::snapshot::RunnableSnapshot;
use crate::types::SandboxId;

pub struct FirecrackerSandboxFactory {
    cpu_config_arc: Option<Arc<RwLock<Option<String>>>>,
    #[cfg(test)]
    qualification_delegate: Option<Arc<dyn SandboxBackendFactory>>,
}

impl FirecrackerSandboxFactory {
    pub fn new() -> Self {
        Self {
            cpu_config_arc: None,
            #[cfg(test)]
            qualification_delegate: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_qualification_delegate(delegate: Arc<dyn SandboxBackendFactory>) -> Self {
        Self {
            cpu_config_arc: None,
            qualification_delegate: Some(delegate),
        }
    }

    pub fn with_cpu_config(arc: Arc<RwLock<Option<String>>>) -> Self {
        Self {
            cpu_config_arc: Some(arc),
            #[cfg(test)]
            qualification_delegate: None,
        }
    }
}

impl Default for FirecrackerSandboxFactory {
    fn default() -> Self {
        Self::new()
    }
}

fn filter_extra_boot_args(
    extra_boot_args: Option<&str>,
    allowed_prefixes: &[String],
) -> Option<String> {
    let extra_boot_args = extra_boot_args?.trim();
    if extra_boot_args.is_empty() {
        return None;
    }

    let filtered: Vec<&str> = extra_boot_args
        .split_whitespace()
        .filter(|arg| is_allowed_extra_boot_arg(arg, allowed_prefixes))
        .collect();

    (!filtered.is_empty()).then(|| filtered.join(" "))
}

fn is_allowed_extra_boot_arg(arg: &str, allowed_prefixes: &[String]) -> bool {
    let is_valid_char =
        |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '+' | '=');
    if arg.is_empty() || !arg.chars().all(is_valid_char) {
        return false;
    }

    allowed_prefixes
        .iter()
        .filter(|prefix| !prefix.is_empty())
        .any(|prefix| arg.starts_with(prefix))
}

pub(super) fn validate_native_request(
    profile: &super::native_guest::NativeGuestProfile,
    build: &FreshSandboxBuildSpec,
    launch: &SandboxLaunchConfig,
) -> Result<()> {
    anyhow::ensure!(
        build.image_config_path == profile.rootfs_path
            && launch.snapshot_id == profile.rootfs_sha256,
        "native source path/SHA must match the protected profile"
    );
    anyhow::ensure!(
        build.resources.cpu_count == 1
            && (128..=512).contains(&build.resources.memory_mib)
            && build.resources.disk_size_mib == 0
            && build.extra_drives.is_empty()
            && build.extra_boot_args.is_none(),
        "native resource/drive/boot request refused"
    );
    let context = &build.context;
    anyhow::ensure!(
        context.user.as_deref() == Some("1000")
            && context.workdir == "/workspace"
            && context.env_vars.is_empty()
            && context.exposed_ports.is_empty()
            && context.entrypoint.is_none()
            && context.cmd.is_none()
            && context.volumes.is_empty()
            && context.labels.is_empty(),
        "native source context must be canonical UID1000/workspace"
    );
    anyhow::ensure!(
        launch
            .env_vars
            .as_ref()
            .is_none_or(std::collections::HashMap::is_empty)
            && launch
                .network
                .as_ref()
                .is_none_or(|p| *p == crate::sandbox::SandboxNetworkPolicy::default())
            && launch.extra_mmds.is_empty()
            && launch.custom_extension_params.is_none()
            && launch.envd_access_token.is_none(),
        "native launch environment/network/MMDS/extension request refused"
    );
    Ok(())
}

impl SandboxBackendFactory for FirecrackerSandboxFactory {
    fn build_native_original(
        &self,
        promotion: &crate::sandbox::NativeProfilePromotion,
    ) -> Result<Box<dyn SandboxBackend>> {
        let app = ConfigManager::global_config();
        anyhow::ensure!(
            app.is_native_root()
                && app.firecracker.boot_args.is_none()
                && self
                    .cpu_config_arc
                    .as_ref()
                    .is_none_or(|arc| arc.read().expect("CPU config").is_none()),
            "native original factory policy refused"
        );
        let mut common = super::config::FirecrackerCommonConfig::from_app_config_selected_native(
            app,
            Some(promotion.profile.clone()),
        )?;
        common.default_workdir = Some("/workspace".into());
        common.default_user = Some("1000".into());
        let config = FirecrackerSandboxConfig {
            kernel_image: promotion.profile.kernel_path.clone(),
            common,
            boot_args: None,
            vcpu_count: 1,
            mem_size_mib: promotion.memory_mib,
        };
        config.validate()?;
        Ok(Box::new(FirecrackerSandbox::new_native_original(
            config,
            promotion.sandbox_id,
            promotion.expires,
        )?))
    }

    fn build(
        &self,
        build_spec: FreshSandboxBuildSpec,
        launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        #[cfg(test)]
        if let Some(delegate) = &self.qualification_delegate {
            return delegate.build(build_spec, launch_config);
        }
        let user_image_config = OverlaybdConfig {
            image_config_path: build_spec.image_config_path.clone(),
            read_only: false,
            runtime_upper_mode: overlaybd::config::UpperMode::LogStructured,
        };
        let mut config =
            FirecrackerSandboxConfig::from_global_config_with_user_image(user_image_config)?;
        if let Some(profile) = &config.common.native_guest_profile {
            validate_native_request(profile, &build_spec, &launch_config)?;
            anyhow::ensure!(
                self.cpu_config_arc
                    .as_ref()
                    .is_none_or(|arc| arc.read().expect("CPU config").is_none()),
                "native CPU customization is unsupported"
            );
            config.vcpu_count = build_spec.resources.cpu_count;
            config.mem_size_mib = build_spec.resources.memory_mib;
            // Native protocol/config binding owns identity; this guest does not
            // consume legacy MMDS. Caller extras were refused above, while the
            // normal orchestrator still retains SandboxId/source metadata.
            config.validate()?;
            return Ok(Box::new(FirecrackerSandbox::new_with_id(
                config,
                launch_config.sandbox_id,
            )?));
        }
        let (rootfs_image_config_path, rootfs_read_only, runtime_upper_mode) = {
            let rootfs_image_config = config
                .common
                .rootfs_image_config
                .as_ref()
                .context("fresh sandbox rootfs image config is missing")?;
            (
                rootfs_image_config.image_config_path.clone(),
                rootfs_image_config.read_only,
                rootfs_image_config.runtime_upper_mode,
            )
        };
        config.common.ublk_config = Some(UblkConfig::overlaybd_with_runtime_upper_mode(
            rootfs_image_config_path,
            rootfs_read_only,
            runtime_upper_mode,
        ));
        config.vcpu_count = build_spec.resources.cpu_count;
        config.mem_size_mib = build_spec.resources.memory_mib;
        config.common.rootfs_virtual_size = if build_spec.resources.disk_size_mib == 0 {
            None
        } else {
            Some(
                u64::from(build_spec.resources.disk_size_mib)
                    .checked_mul(1024 * 1024)
                    .context("requested rootfs size overflows bytes")?,
            )
        };
        config.common.extra_drives = build_spec.extra_drives;
        let allowed_extra_boot_args_prefixes = ConfigManager::global_config()
            .firecracker
            .allowed_extra_boot_args_prefixes
            .as_deref()
            .unwrap_or_default();
        if let Some(extra_boot_args) = filter_extra_boot_args(
            build_spec.extra_boot_args.as_deref(),
            allowed_extra_boot_args_prefixes,
        ) {
            config.boot_args = Some(match config.boot_args.take() {
                Some(existing) => format!("{existing} {extra_boot_args}"),
                None => extra_boot_args,
            });
        }
        config.common.cpu_config_json = self
            .cpu_config_arc
            .as_ref()
            .and_then(|arc| arc.read().unwrap().clone());
        config.common.env_vars = (!build_spec.context.env_vars.is_empty())
            .then_some(build_spec.context.env_vars.clone());
        config.common.default_workdir = Some(build_spec.context.workdir.clone());
        config.common.default_user = build_spec.context.user.clone();
        let config = config.apply_launch_config(&launch_config);
        let sandbox = FirecrackerSandbox::new_with_id(config, launch_config.sandbox_id)?;
        Ok(Box::new(sandbox))
    }

    fn build_from_snapshot(
        &self,
        snapshot: &RunnableSnapshot,
        launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        let sandbox = FirecrackerSandbox::from_snapshot(snapshot, &launch_config)?;
        Ok(Box::new(sandbox))
    }

    fn decode_paused_state(
        &self,
        artifact_root: PathBuf,
        state: Value,
    ) -> Result<Arc<dyn PausedSandboxState>> {
        Ok(Arc::new(FirecrackerPausedState::decode(
            artifact_root,
            state,
        )?))
    }

    fn build_from_paused_state(
        &self,
        sandbox_id: SandboxId,
        state: &dyn PausedSandboxState,
        envd_access_token: Option<EnvdAccessToken>,
    ) -> Result<Box<dyn SandboxBackend>> {
        let paused_state = state
            .downcast_ref::<FirecrackerPausedState>()
            .context("The provided PausedSandboxState is not a Firecracker paused state")?;
        let sandbox = FirecrackerSandbox::from_snapshot_config_with_override(
            paused_state.snapshot_config().clone(),
            sandbox_id,
            envd_access_token,
        )?;
        Ok(Box::new(sandbox))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::sandbox::{PausedSandboxState, RuntimeArtifactSet};

    #[derive(Debug)]
    struct WrongPausedState;

    impl PausedSandboxState for WrongPausedState {
        fn encode(&self) -> Result<Value> {
            Ok(Value::Null)
        }

        fn runtime_artifacts(&self) -> RuntimeArtifactSet {
            RuntimeArtifactSet::empty()
        }
    }

    #[test]
    fn filter_extra_boot_args_keeps_only_allowed_prefixes() {
        let prefixes = vec!["agentenv-custom.".to_string(), "agentenv.safe=".to_string()];

        assert_eq!(
            filter_extra_boot_args(
                Some("agentenv-custom.foo=bar debug agentenv.safe=1 root=/dev/vda"),
                &prefixes,
            ),
            Some("agentenv-custom.foo=bar agentenv.safe=1".to_string())
        );
    }

    #[test]
    fn filter_extra_boot_args_drops_when_no_prefix_matches() {
        let prefixes = vec!["agentenv-custom.".to_string()];

        assert_eq!(
            filter_extra_boot_args(Some("debug panic=1"), &prefixes),
            None
        );
        assert_eq!(
            filter_extra_boot_args(Some("agentenv-custom.foo=bar"), &[]),
            None
        );
    }

    #[test]
    fn filter_extra_boot_args_drops_invalid_chars() {
        let prefixes = vec!["agentenv-custom.".to_string()];

        assert_eq!(
            filter_extra_boot_args(
                Some(
                    "agentenv-custom.flag agentenv-custom.bad_char=a:b agentenv-custom.good=azAZ09_-./+= agentenv-custom.base64=YWJjZA==/+",
                ),
                &prefixes,
            ),
            Some(
                "agentenv-custom.flag agentenv-custom.good=azAZ09_-./+= agentenv-custom.base64=YWJjZA==/+"
                    .to_string()
            )
        );
    }

    #[test]
    fn build_from_paused_state_rejects_wrong_snapshot_type() {
        let factory = FirecrackerSandboxFactory::new();
        let state: Arc<dyn PausedSandboxState> = Arc::new(WrongPausedState);

        match factory.build_from_paused_state(SandboxId::new(), state.as_ref(), None) {
            Ok(_) => panic!("wrong snapshot type should fail"),
            Err(err) => assert!(err.to_string().contains("not a Firecracker paused state")),
        }
    }
}
