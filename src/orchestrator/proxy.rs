use std::{collections::HashMap, net::Ipv4Addr, time::SystemTime};

use crate::orchestrator::SandboxState;
use crate::types::SandboxId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyTarget {
    pub ip: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyLookupResult {
    Ready(ProxyTarget),
    /// The sandbox uses authenticated native execution, with no HTTP endpoint.
    NativeControl,
    NotFound,
    Paused {
        auto_resume: bool,
    },
    Unavailable(SandboxState),
    RouteMissing,
}

#[derive(Clone, Debug)]
pub(crate) struct ProxyRoute {
    target: Option<ProxyTarget>,
    native_control: Option<crate::sandbox::NativeControl>,
    version: u64,
    updated_at: SystemTime,
}

#[derive(Debug, Default)]
pub(crate) struct ProxyRouteTable {
    routes: HashMap<SandboxId, ProxyRoute>,
}

impl ProxyTarget {
    pub fn new(host_interaction_ip: Ipv4Addr) -> Self {
        Self {
            ip: host_interaction_ip,
        }
    }
}

impl ProxyRoute {
    pub fn new(target: ProxyTarget, version: u64) -> Self {
        Self {
            target: Some(target),
            native_control: None,
            version,
            updated_at: SystemTime::now(),
        }
    }

    pub(crate) fn native_control(&self) -> Option<&crate::sandbox::NativeControl> {
        self.native_control.as_ref()
    }
    pub fn target(&self) -> Option<&ProxyTarget> {
        self.target.as_ref()
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn updated_at(&self) -> SystemTime {
        self.updated_at
    }
}

impl ProxyRouteTable {
    pub fn upsert(
        &mut self,
        sandbox_id: SandboxId,
        target: ProxyTarget,
        version: u64,
    ) -> ProxyRoute {
        let route = ProxyRoute::new(target, version);
        self.routes.insert(sandbox_id, route.clone());
        route
    }

    pub fn remove(&mut self, sandbox_id: &SandboxId) -> Option<ProxyRoute> {
        self.routes.remove(sandbox_id)
    }

    pub fn publish_native(&mut self, sandbox_id: SandboxId, version: u64) {
        self.routes.insert(
            sandbox_id,
            ProxyRoute {
                target: None,
                native_control: None,
                version,
                updated_at: SystemTime::now(),
            },
        );
    }

    pub(crate) fn publish_control(
        &mut self,
        sandbox_id: SandboxId,
        control: crate::sandbox::NativeControl,
        version: u64,
    ) {
        self.routes.insert(
            sandbox_id,
            ProxyRoute {
                target: None,
                native_control: Some(control),
                version,
                updated_at: SystemTime::now(),
            },
        );
    }
    #[cfg(test)]
    pub fn proxy_target(&self, sandbox_id: &SandboxId) -> Option<ProxyTarget> {
        self.routes
            .get(sandbox_id)
            .and_then(|route| route.target().cloned())
    }

    pub fn route(&self, sandbox_id: &SandboxId) -> Option<&ProxyRoute> {
        self.routes.get(sandbox_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_route_carries_no_http_target_and_is_removed_or_replaced() {
        let id = SandboxId::new();
        let mut table = ProxyRouteTable::default();
        table.publish_native(id, 1);
        assert!(table.route(&id).unwrap().target().is_none());
        assert!(table.proxy_target(&id).is_none());
        table.upsert(id, ProxyTarget::new(Ipv4Addr::LOCALHOST), 2);
        assert!(table.proxy_target(&id).is_some());
        table.publish_native(id, 3);
        assert!(table.remove(&id).unwrap().target().is_none());
        assert!(table.route(&id).is_none());
    }

    #[test]
    fn proxy_table_only_exposes_inserted_routes() {
        let sandbox_id = SandboxId::new();
        let target = ProxyTarget::new(Ipv4Addr::LOCALHOST);
        let mut table = ProxyRouteTable::default();

        table.upsert(sandbox_id, target.clone(), 1);
        assert_eq!(table.proxy_target(&sandbox_id), Some(target.clone()));

        table.upsert(sandbox_id, target.clone(), 2);
        assert_eq!(table.proxy_target(&sandbox_id), Some(target));
        assert_eq!(table.routes.get(&sandbox_id).unwrap().version(), 2);
    }

    #[test]
    fn proxy_table_remove_drops_route() {
        let sandbox_id = SandboxId::new();
        let mut table = ProxyRouteTable::default();

        table.upsert(sandbox_id, ProxyTarget::new(Ipv4Addr::LOCALHOST), 3);
        let _removed = table.remove(&sandbox_id).unwrap();

        assert!(!table.routes.contains_key(&sandbox_id));
        assert!(table.proxy_target(&sandbox_id).is_none());
    }
}
