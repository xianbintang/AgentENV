mod gc;
mod graph;
pub(crate) mod native_artifact_store;
mod service;
mod source_config;
mod store;

#[cfg(test)]
mod mock;

pub(crate) use service::ImageCacheService;

pub(crate) use store::{
    local_image_services_from_app_config, local_image_services_from_global_config,
    CachedImageConfig, OverlaybdLayerLocation, OverlaybdLayerStore, RuntimeImageOwner,
    RuntimeImageRefs, SourceImageStore,
};

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::mock::RecordingRuntimeImageRefs;
    pub(crate) use super::service::ImageCacheService;
    pub(crate) use super::store::test_local_image_services_from_service;

    pub(crate) fn owned_real_image_services() -> super::store::LocalImageServices {
        test_local_image_services_from_service(
            ImageCacheService::owned_test_service(),
            None,
            std::time::Duration::from_secs(0),
        )
    }
}
