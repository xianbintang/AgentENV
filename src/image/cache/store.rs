//! Node-local image storage ports used outside the image cache module.

use futures::future::BoxFuture;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::service::{HoldNamespace, ImageCacheService};
use crate::cfg::{AppConfig, ConfigManager};
use crate::image::oci_image::ImageConversion;
use crate::image::ImageResolutionMetadata;
use crate::sandbox::RuntimeArtifactSet;
use crate::types::SandboxId;

pub(crate) enum CachedImageConfig {
    Missing,
    Found {
        image_config_path: PathBuf,
        metadata: Option<Box<ImageResolutionMetadata>>,
    },
}

#[derive(Debug)]
pub(crate) enum OverlaybdLayerLocation {
    LocalFile(PathBuf),
    CacheDir(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeImageOwner {
    StartingSandbox(SandboxId),
    PausedSandbox(SandboxId),
    NativeFailedLaunchDebt {
        debt: SandboxId,
        original: SandboxId,
    },
}

#[async_trait]
pub(crate) trait SourceImageStore: Send + Sync + std::fmt::Debug {
    fn open<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        manifest_digest: &'life1 str,
        repository_scope: Option<&'life2 str>,
    ) -> BoxFuture<'async_trait, Result<Box<dyn SourceImageEntry>>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait;
}

#[async_trait]
pub(crate) trait SourceImageEntry: Send {
    fn cached_config<'life0, 'async_trait>(
        &'life0 self,
    ) -> BoxFuture<'async_trait, Result<CachedImageConfig>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    fn begin_conversion<'life0, 'async_trait>(
        &'life0 self,
    ) -> BoxFuture<'async_trait, Result<Box<dyn ImageConversion>>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    fn publish_config<'life0, 'life1, 'async_trait>(
        &'life0 self,
        overlaybd_config: &'life1 Value,
        metadata: ImageResolutionMetadata,
        conversion: Box<dyn ImageConversion>,
    ) -> BoxFuture<'async_trait, Result<PathBuf>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    fn write_metadata<'life0, 'async_trait>(
        &'life0 self,
        metadata: ImageResolutionMetadata,
    ) -> BoxFuture<'async_trait, Result<PathBuf>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
}

pub(crate) trait OverlaybdLayerStore: Send + Sync + std::fmt::Debug {
    fn layer_location(&self, digest: &str, size: u64, has_remote: bool) -> OverlaybdLayerLocation;

    fn publishable_roots(&self) -> Vec<PathBuf>;
}

#[async_trait]
pub(crate) trait RuntimeImageRefs: Send + Sync + std::fmt::Debug {
    fn pin<'life0, 'async_trait>(
        &'life0 self,
        owner: RuntimeImageOwner,
        artifacts: RuntimeArtifactSet,
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    fn promote_native_running<'life0, 'async_trait>(
        &'life0 self,
        _id: SandboxId,
        artifacts: RuntimeArtifactSet,
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let (_, native) = artifacts.split();
            anyhow::ensure!(
                native.is_empty(),
                "runtime refs do not admit native custody"
            );
            Ok(())
        })
    }
    fn retire_native_running<'life0, 'async_trait>(
        &'life0 self,
        _id: SandboxId,
        artifacts: RuntimeArtifactSet,
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let (_, native) = artifacts.split();
            anyhow::ensure!(
                native.is_empty(),
                "runtime refs do not own native retirement"
            );
            Ok(())
        })
    }

    fn unpin_best_effort<'life0, 'async_trait>(
        &'life0 self,
        owner: RuntimeImageOwner,
    ) -> BoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    fn reconcile_paused<'life0, 'life1, 'async_trait>(
        &'life0 self,
        live_paused: &'life1 [SandboxId],
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    fn maintain_running<'life0, 'async_trait>(
        &'life0 self,
        running: Vec<(SandboxId, RuntimeArtifactSet)>,
    ) -> BoxFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
}

#[derive(Clone)]
pub(crate) struct LocalImageServices {
    pub(crate) source_images: Arc<dyn SourceImageStore>,
    pub(crate) overlaybd_layers: Arc<dyn OverlaybdLayerStore>,
    pub(crate) runtime_refs: Arc<dyn RuntimeImageRefs>,
}

#[derive(Debug)]
struct ImageCacheStore {
    cache: Arc<ImageCacheService>,
    gc_watermark: Option<(u64, u64)>,
    gc_min_age: Duration,
    native: Arc<super::native_artifact_store::NativeArtifactStore>,
}

struct ImageCacheSourceImageEntry {
    cache: Arc<ImageCacheService>,
    manifest_digest: String,
    repository_scope: Option<String>,
}

#[async_trait]
impl SourceImageStore for ImageCacheStore {
    async fn open(
        &self,
        manifest_digest: &str,
        repository_scope: Option<&str>,
    ) -> Result<Box<dyn SourceImageEntry>> {
        Ok(Box::new(ImageCacheSourceImageEntry {
            cache: Arc::clone(&self.cache),
            manifest_digest: manifest_digest.to_string(),
            repository_scope: repository_scope.map(|s| s.to_string()),
        }))
    }
}

#[async_trait]
impl SourceImageEntry for ImageCacheSourceImageEntry {
    async fn cached_config(&self) -> Result<CachedImageConfig> {
        self.cache
            .lookup_image_config(&self.manifest_digest, self.repository_scope.as_deref())
            .await
    }

    async fn begin_conversion(&self) -> Result<Box<dyn ImageConversion>> {
        self.cache
            .begin_image_conversion(&self.manifest_digest, self.repository_scope.as_deref())
            .await
    }

    async fn publish_config(
        &self,
        overlaybd_config: &Value,
        metadata: ImageResolutionMetadata,
        conversion: Box<dyn ImageConversion>,
    ) -> Result<PathBuf> {
        self.cache
            .publish_image_config(
                &self.manifest_digest,
                self.repository_scope.as_deref(),
                overlaybd_config,
                metadata,
                conversion,
            )
            .await
    }

    async fn write_metadata(&self, metadata: ImageResolutionMetadata) -> Result<PathBuf> {
        self.cache
            .write_image_metadata(
                &self.manifest_digest,
                self.repository_scope.as_deref(),
                metadata,
            )
            .await
    }
}

impl OverlaybdLayerStore for ImageCacheStore {
    fn layer_location(&self, digest: &str, size: u64, has_remote: bool) -> OverlaybdLayerLocation {
        self.cache
            .overlaybd_layer_location(digest, size, has_remote)
    }

    fn publishable_roots(&self) -> Vec<PathBuf> {
        self.cache.allowed_overlaybd_publish_roots()
    }
}

#[async_trait]
impl RuntimeImageRefs for ImageCacheStore {
    async fn pin(&self, owner: RuntimeImageOwner, artifacts: RuntimeArtifactSet) -> Result<()> {
        let (paths, native) = artifacts.split();
        self.native.pin(owner.clone(), native).await?;
        if paths.is_empty() {
            return Ok(());
        }
        let (namespace, id) = owner_namespace(owner);
        self.cache.protect(namespace, &id.to_string(), paths).await
    }

    async fn promote_native_running(
        &self,
        id: SandboxId,
        artifacts: RuntimeArtifactSet,
    ) -> Result<()> {
        let (_, native) = artifacts.split();
        self.native.promote(id, native)
    }

    async fn retire_native_running(
        &self,
        id: SandboxId,
        artifacts: RuntimeArtifactSet,
    ) -> Result<()> {
        let (_, native) = artifacts.split();
        self.native.retire_running(id, native)
    }

    async fn unpin_best_effort(&self, owner: RuntimeImageOwner) {
        self.native.release(&owner);
        let (namespace, id) = owner_namespace(owner);
        self.cache
            .release_protection_best_effort(namespace, &id.to_string())
            .await;
    }

    async fn reconcile_paused(&self, live_paused: &[SandboxId]) -> Result<()> {
        let ids: Vec<String> = live_paused.iter().map(|id| id.to_string()).collect();
        self.cache
            .reconcile_namespace(HoldNamespace::Paused, &ids)
            .await
    }

    async fn maintain_running(&self, running: Vec<(SandboxId, RuntimeArtifactSet)>) -> Result<()> {
        let mut overlaybd = Vec::new();
        for (id, artifacts) in running {
            let (paths, native) = artifacts.split();
            self.native.promote(id, native)?;
            if !paths.is_empty() {
                overlaybd.push((id.to_string(), paths));
            }
        }
        let running = overlaybd;
        let summary = self
            .cache
            .run_maintenance(running, self.gc_watermark, self.gc_min_age)
            .await?;
        info!(
            reclaimed = summary.collected,
            freed_bytes = summary.freed_bytes,
            retained = summary.retained,
            "image cache maintenance pass complete"
        );
        Ok(())
    }
}

fn owner_namespace(owner: RuntimeImageOwner) -> (HoldNamespace, SandboxId) {
    match owner {
        RuntimeImageOwner::StartingSandbox(id) => (HoldNamespace::Runtime, id),
        RuntimeImageOwner::PausedSandbox(id) => (HoldNamespace::Paused, id),
        RuntimeImageOwner::NativeFailedLaunchDebt { debt, .. } => (HoldNamespace::Runtime, debt),
    }
}

pub(crate) fn local_image_services_from_app_config(config: &AppConfig) -> LocalImageServices {
    let cache = ImageCacheService::shared_from_app_config(config);
    let gc = config.image.cache.gc_schedule();
    let capacity_bytes = config.image_cache_layout().capacity_bytes;
    services_from_store(Arc::new(ImageCacheStore {
        cache,
        gc_watermark: gc.watermark_bytes(capacity_bytes),
        gc_min_age: gc.min_age,
        native: super::native_artifact_store::NativeArtifactStore::shared(),
    }))
}

pub(crate) fn local_image_services_from_global_config() -> LocalImageServices {
    local_image_services_from_app_config(ConfigManager::global_config())
}

fn services_from_store(store: Arc<ImageCacheStore>) -> LocalImageServices {
    LocalImageServices {
        source_images: store.clone(),
        overlaybd_layers: store.clone(),
        runtime_refs: store,
    }
}

#[cfg(test)]
pub(crate) fn test_local_image_services_from_service(
    cache: Arc<ImageCacheService>,
    gc_watermark: Option<(u64, u64)>,
    gc_min_age: Duration,
) -> LocalImageServices {
    services_from_store(Arc::new(ImageCacheStore {
        cache,
        gc_watermark,
        gc_min_age,
        native: Arc::new(super::native_artifact_store::NativeArtifactStore::default()),
    }))
}
