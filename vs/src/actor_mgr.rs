//! Actor manager. Manages nodes too.
//!

use dashmap::DashMap;
use libeval::actor::Actor;
use libeval::attribute::key;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

use zpr::policy_types::{Scope, ServiceType};
use zpr::vsapi_types::{PublicKey, ServiceDescriptor};

use crate::assembly::Assembly;
use crate::config;
use crate::counters::Counters;
use crate::db;
use crate::db::ServiceEntry;
use crate::error::{ServiceError, StoreError};
use crate::logging::targets::ACTOR;

pub struct ActorMgr {
    actor_db: db::ActorRepo,
    node_db: db::NodeRepo,
    counters: Arc<Counters>,
    connection_table: Arc<DashMap<IpAddr, IpAddr>>, // adapter_zpr_addr -> docking_node_zpr_addr

    /// Maps AAA address → (docking_node, expiry). Registered on the request side when an
    /// unauthenticated adapter contacts an auth service. Looked up on the response side to
    /// find the correct docking node (which differs from job.requesting_node in multi-node
    /// setups). Evicted when the adapter authenticates or on lazy expiry at lookup time.
    aaa_table: DashMap<IpAddr, (IpAddr, SystemTime)>,
}

pub struct ServiceDetail {
    /// Name/id of the service
    pub service_name: String,

    /// ZPR address of the actor providing the service.
    pub zpr_addr: IpAddr,

    /// CN of the actor providing the service.
    pub actor_cn: String,

    /// Dock through which the actor is connected.
    pub connect_via: Option<IpAddr>,
}

impl ActorMgr {
    pub fn new(
        actor_repo: db::ActorRepo,
        node_repo: db::NodeRepo,
        counters: Arc<Counters>,
    ) -> Self {
        ActorMgr {
            actor_db: actor_repo,
            node_db: node_repo,
            counters,
            connection_table: Arc::new(DashMap::new()),
            aaa_table: DashMap::new(),
        }
    }

    /// When we start VS with state in the DB, we are primarily concerned about any nodes
    /// that were connected.
    ///
    /// For each node we find in here we check to make sure that the node auth has not
    /// expired.  Expired nodes are removed (along with any connected adapters).
    ///
    /// For non-expired nodes, we wipe their vss info.
    pub async fn refresh_state(&self) -> Result<(), ServiceError> {
        for node_addr in &self.node_db.list_node_addrs().await? {
            let node_actor = match self.actor_db.get_actor_by_zpr_addr(node_addr).await {
                Ok(actor) => actor,
                Err(StoreError::NotFound(_)) => {
                    debug!(target: ACTOR, "refresh_state: node at {} not found in actor DB, removing from node DB", node_addr);
                    self.remove_actor_by_zpr_addr(node_addr).await?;
                    continue;
                }
                Err(e) => return Err(ServiceError::from(e)),
            };

            if let Some(exp) = node_actor.get_authentication_expiration() {
                if exp < SystemTime::now() {
                    info!(target: ACTOR, "refresh_state: node at {node_addr} has expired auth, removing");
                    self.remove_actor_by_zpr_addr(node_addr).await?;
                    continue;
                }
            }

            if let Err(e) = self.node_db.clear_node_vss(node_addr).await {
                warn!(target: ACTOR, "refresh_state: failed to clear VSS info for node at {}: {}", node_addr, e);
            }

            match self.node_db.get_connected_adapters(node_addr).await {
                Ok(adapters) => {
                    for adapter_addr in adapters {
                        self.connection_table.insert(adapter_addr, *node_addr);
                    }
                }
                Err(StoreError::NotFound(_)) => {
                    // No connected adapters, that's fine.
                }
                Err(e) => {
                    warn!(target: ACTOR, "refresh_state: failed to get connected adapters for node at {}: {}", node_addr, e);
                }
            }
        }

        Ok(())
    }

    pub async fn add_node(&self, actor: &Actor, reconnect: bool) -> Result<(), ServiceError> {
        if !actor.is_node() {
            return Err(ServiceError::Internal(
                "attempt to add non-node actor as node".into(),
            ));
        }

        if !reconnect {
            self.node_db
                .remove_node(actor.get_zpr_addr().unwrap())
                .await?;
            self.counters
                .remove_node_info(actor.get_zpr_addr().unwrap());
            self.actor_db.add_actor(actor).await?;
        } else {
            // Is a reconnect...
            if let Err(e) = self.actor_db.update_actor(actor).await {
                // Update failed? Make the node try a fresh connect.
                if let Err(ee) = self
                    .node_db
                    .remove_node(actor.get_zpr_addr().unwrap())
                    .await
                {
                    warn!(target: ACTOR, "add_node: failed to remove node at {} after failed update during reconnect: {}", actor.get_zpr_addr().unwrap(), ee);
                }
                return Err(e.into());
            }
        }

        let node_obj = db::Node::new_from_node_actor(&actor)?;
        self.node_db.add_node(&node_obj).await?;
        self.node_db
            .update_last_seen_time(actor.get_zpr_addr().unwrap())
            .await?;
        Ok(())
    }

    // TODO: This probably updates too much ... all we really need is to update the attributes.
    // Only called from refresh_and_persist_actor, after an attribute refresh: from the
    // visa request path and from the attribute reconcile sweep in event_mgr.
    pub async fn update_actor(&self, actor: &Actor) -> Result<(), ServiceError> {
        self.actor_db.update_actor(actor).await?;
        Ok(())
    }

    /// Use [ActorMgr::remove_actor_by_zpr_addr] to remove actor records which apply to both nodes and adapters.
    /// Use this function here in addition to remove node state.
    ///
    /// Also updates our internal connection table.
    pub async fn remove_node(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        self.node_db.remove_node(node_addr).await?;

        // Remove any connections that point to this node.  Could be slow to iterate if
        // this is large, so this is run in spawn_blocking to avoid blocking the async runtime.
        tokio::task::spawn_blocking({
            let connection_table_ptr = self.connection_table.clone();
            let node_addr = *node_addr;
            move || {
                connection_table_ptr.retain(|_, v| v != &node_addr);
            }
        })
        .await
        .unwrap();

        self.counters.remove_node_info(node_addr);
        Ok(())
    }

    /// Update the last-seen time for given node.
    pub async fn update_node_last_seen(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        self.node_db.update_last_seen_time(node_addr).await?;
        Ok(())
    }

    pub async fn get_node_last_seen(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Option<SystemTime>, ServiceError> {
        Ok(self.node_db.get_last_seen_time(node_addr).await?)
    }

    /// Update vss socket for given node in the DB.
    pub async fn set_node_vss(
        &self,
        node_addr: &IpAddr,
        vss: &SocketAddr,
    ) -> Result<(), ServiceError> {
        self.node_db.set_node_vss(node_addr, vss).await?;
        Ok(())
    }

    pub async fn get_node_vss(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Option<SocketAddr>, ServiceError> {
        let vss = self.node_db.get_node_vss(node_addr).await?;
        Ok(vss)
    }

    /// Add an adapter that is connected to a node.
    /// Also updates our in-memory connection table.
    pub async fn add_adapter_via_node(
        &self,
        actor: &Actor,
        connected_to_node: &IpAddr,
    ) -> Result<(), ServiceError> {
        if actor.is_node() {
            return Err(ServiceError::Internal(
                "attempt to add node actor as adapter".into(),
            ));
        }

        let Some(adapter_addr) = actor.get_zpr_addr() else {
            return Err(ServiceError::Internal(format!(
                "attempt to add adapter actor without ZPR address: CN={:?}",
                actor.get_cn()
            )));
        };

        self.actor_db.add_actor(actor).await?;
        self.node_db
            .add_connected_adater(connected_to_node, adapter_addr)
            .await?;

        self.connection_table
            .insert(*adapter_addr, *connected_to_node);

        Ok(())
    }

    /// Hack: we use this to add the unauthenticated visa service adapter.
    /// We don't know what node it is attached to yet.
    ///
    /// See https://github.com/org-zpr/zpr-visaservice/issues/195
    pub async fn hack_add_adapter_no_node(&self, actor: &Actor) -> Result<(), ServiceError> {
        if actor.is_node() {
            return Err(ServiceError::Internal(
                "attempt to add node actor as adapter".into(),
            ));
        }
        self.actor_db.add_actor(actor).await?;
        Ok(())
    }

    /// Hack: this sets the docking node for the visa service adapter.
    /// TODO: Need a better way to do this. Perhaps talking to the local adapter directly? Perhaps our docking
    /// node can send a message over the vsapi (like a connection_request?).
    ///
    /// See https://github.com/org-zpr/zpr-visaservice/issues/195
    pub async fn hack_set_vs_docking_node(
        &self,
        node_zpr_addr: &IpAddr,
    ) -> Result<(), ServiceError> {
        let vs_zpr_addr = IpAddr::V6(config::VS_ZPR_ADDR);
        self.node_db
            .add_connected_adater(node_zpr_addr, &vs_zpr_addr)
            .await?;

        self.connection_table.insert(vs_zpr_addr, *node_zpr_addr);
        Ok(())
    }

    /// Returns Ok(None) if not found.
    pub async fn get_actor_by_zpr_addr(
        &self,
        zpra: &IpAddr,
    ) -> Result<Option<Actor>, ServiceError> {
        match self.actor_db.get_actor_by_zpr_addr(zpra).await {
            Ok(actor) => Ok(Some(actor)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Returns only the CN for the actor at the given ZPR address, without loading the full actor.
    pub async fn get_cn_by_zpr_addr(&self, zpra: &IpAddr) -> Result<String, ServiceError> {
        match self.actor_db.get_cn_by_zpr_addr(zpra).await {
            Ok(cn) => Ok(cn),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Returns actors public key or None if no key is stored for it.
    pub async fn get_a2a_dh_pubkey_by_zpr_addr(
        &self,
        zpra: &IpAddr,
    ) -> Result<Option<PublicKey>, ServiceError> {
        Ok(self.actor_db.get_a2a_dh_pubkey_by_zpr_addr(zpra).await?)
    }

    pub async fn get_actor_by_cn(&self, cn: &str) -> Result<Option<Actor>, ServiceError> {
        match self.actor_db.get_actor_by_cn(cn).await {
            Ok(actor) => Ok(Some(actor)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Remove actor state from the database. If removing a node, also call [ActorMgr::remove_node].
    pub async fn remove_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<(), ServiceError> {
        self.actor_db.rm_actor_by_zpr_addr(zpra).await?;
        self.connection_table.remove(zpra);
        Ok(())
    }

    /// Returns ZPR addresses of adapters (NOT nodes) connected to the given node.
    pub async fn get_adapters_connected_to_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<IpAddr>, ServiceError> {
        Ok(self
            .node_db
            .get_connected_adapters(node_addr)
            .await?
            .into_iter()
            .collect())
    }

    /// Get the node address that the actor is "docked" to.
    /// A "node" actor is considered to be docked to itself (returns the actors own address
    /// in this case).
    ///
    /// Returns NONE if we cannot determine a docking node ZPR address.
    pub fn get_docking_node_for_actor(&self, actor: &Actor) -> Option<IpAddr> {
        if actor.is_node() {
            actor.get_zpr_addr().copied()
        } else {
            if let Some(actor_addr) = actor.get_zpr_addr() {
                self.get_docking_node_for_adapter(actor_addr)
            } else {
                None
            }
        }
    }

    /// Docking node of an adapter identified by its ZPR address alone -- used where we
    /// have the address but no actor, e.g. the visa service's own adapter address.
    pub fn get_docking_node_for_adapter(&self, adapter_addr: &IpAddr) -> Option<IpAddr> {
        self.connection_table
            .get(adapter_addr)
            .map(|entry| *entry.value())
    }

    /// Register the docking node for an AAA actor. Called on the request side when an
    /// unauthenticated adapter (using an AAA address) contacts an auth service. Multiple
    /// requests for the same address overwrite the entry harmlessly — the docking node for
    /// a given AAA subnet cannot change.
    ///
    /// Not persisted. If we restart we loose in-flight AAA request tracking, but that
    /// should be ok since the actors can just retry authentication.
    pub fn register_aaa(&self, aaa_addr: IpAddr, docking_node: IpAddr, expiry: SystemTime) {
        self.aaa_table.insert(aaa_addr, (docking_node, expiry));
    }

    /// Look up the docking node for an AAA actor. Returns None if the entry is missing or
    /// expired (lazy eviction on lookup).
    ///
    /// TODO: Longer term we will need to clean up this AAA table. Ok for now until we
    /// figure out how AAA addresses will be used. There is talk of using this as some sort
    /// of "adapter identity" addresses.
    /// See issue: https://github.com/org-zpr/zpr-visaservice/issues/200
    pub fn get_docking_node_for_aaa(&self, aaa_addr: &IpAddr) -> Option<IpAddr> {
        let now = SystemTime::now();
        match self.aaa_table.get(aaa_addr) {
            Some(entry) if entry.value().1 > now => Some(entry.value().0),
            _ => {
                self.aaa_table
                    .remove_if(aaa_addr, |_, (_, expiry)| *expiry <= now); // rechecks the entry while holding write lock
                None
            }
        }
    }

    pub async fn get_adapter_cns_connected_to_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<String>, ServiceError> {
        let adapter_zpr_addrs = self.get_adapters_connected_to_node(node_addr).await?;

        Ok(futures::future::join_all(
            adapter_zpr_addrs
                .iter()
                .map(|addr| self.get_actor_by_zpr_addr(addr)),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .filter_map(|actor| actor.get_cn().map(|cn| cn.to_string()))
        .collect())
    }

    /// Get the list of connected authentication services.
    pub async fn get_auth_services_list(
        &self,
        asm: Arc<Assembly>,
    ) -> Result<Vec<ServiceDescriptor>, ServiceError> {
        let mut services = Vec::new();

        // From the DB we can get the (service_name, zpr_addr) for each connected service.
        let service_entries = self.actor_db.list_services().await?;

        // Then we need to consult policy to get the service details.
        let pol = asm.policy_mgr.get_current();

        let mut svc_map = HashMap::new();
        for svc in pol.list_services_by_kind(ServiceType::Authentication) {
            svc_map.insert(svc.id.clone(), svc);
        }

        if !svc_map.is_empty() {
            for s_ent in &service_entries {
                if let Some(svc) = svc_map.get(&s_ent.name) {
                    let sdesc = ServiceDescriptor {
                        // This path only lists policy `ServiceType::Authentication`
                        // services, which are on-net actor-authentication services;
                        // off-net OIDC providers are declared in policy, not connected.
                        stype: zpr::vsapi_types::ServiceT::ActorAuthentication,
                        service_id: svc.id.clone(),
                        service_uri: uri_for_service(
                            &svc.kind,
                            &s_ent.zpr_addr,
                            svc.endpoints.as_slice(),
                        )?,
                        zpr_addr: s_ent.zpr_addr.clone(),
                        oidc: None,
                    };
                    services.push(sdesc);
                }
            }
        }

        Ok(services)
    }

    pub async fn get_services_list(&self) -> Result<Vec<ServiceEntry>, ServiceError> {
        let services = self.actor_db.list_services().await?;
        Ok(services)
    }

    /// Get the list of connectioned actor CN values, optionally filtered by role.
    pub async fn list_actor_cns(
        &self,
        by_role: Option<db::Role>,
    ) -> Result<Vec<String>, ServiceError> {
        let cns = self.actor_db.list_actor_cns(by_role).await?;
        Ok(cns)
    }

    /// Get the service details for the named service.
    pub async fn get_service_detail(
        &self,
        service_name: &str,
    ) -> Result<Option<ServiceDetail>, ServiceError> {
        if let Some(addr) = self.actor_db.get_zpr_addr_for_service(service_name).await? {
            let attrs = self
                .actor_db
                .get_actor_attrs(&addr, &[key::CN, key::CONNECT_VIA])
                .await?;

            if attrs.is_empty() {
                warn!(target: ACTOR, "get_service_detail: service '{}': attributes not found", service_name);
                return Ok(None);
            }

            let mut val_cn = None;
            let mut val_connect_via = None;

            for attr in attrs {
                match attr.get_key() {
                    key::CN => {
                        val_cn = Some(attr.get_single_value().unwrap_or_default().to_owned());
                    }
                    key::CONNECT_VIA => {
                        val_connect_via = {
                            let via_str = attr.get_single_value().unwrap_or_default();
                            if via_str.is_empty() {
                                continue;
                            }
                            match via_str.parse::<IpAddr>() {
                                Ok(ip) => Some(ip),
                                Err(_) => {
                                    warn!(target: ACTOR, "get_service_detail: service '{}': invalid connect_via IP address '{}'", service_name, via_str);
                                    continue; // skip invalid
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            if val_cn.is_none() {
                warn!(target: ACTOR, "get_service_detail: service '{}': no CN attribute found", service_name);
                return Ok(None);
            }
            let detail = ServiceDetail {
                service_name: service_name.to_string(),
                zpr_addr: addr,
                actor_cn: val_cn.unwrap(),
                connect_via: val_connect_via,
            };
            return Ok(Some(detail));
        } else {
            debug!(target: ACTOR, "get_service_detail: service '{}' not found in DB", service_name);
            return Ok(None);
        }
    }

    pub async fn list_node_addrs(&self) -> Result<Vec<IpAddr>, ServiceError> {
        let addrs = self.node_db.list_node_addrs().await?;
        Ok(addrs)
    }

    pub async fn list_zpr_addrs(&self) -> Result<Vec<IpAddr>, ServiceError> {
        let addrs = self.actor_db.list_zpr_addrs().await?;
        Ok(addrs)
    }

    /// Return true if the actor exists and offers at least one authentication service.
    /// Note that this consults the **current** policy to determine if the service is an auth service.
    ///
    /// TODO: May be better to keep that cached with the actor.
    pub async fn has_auth_services(
        &self,
        asm: Arc<Assembly>,
        actor_zpr_addr: &IpAddr,
    ) -> Result<bool, ServiceError> {
        let services = match self.actor_db.list_services_for_actor(actor_zpr_addr).await {
            Ok(svcs) => svcs,
            Err(StoreError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(ServiceError::from(e)),
        };
        if services.is_empty() {
            return Ok(false);
        }
        let mut offered_map = HashSet::new();
        for s in services {
            offered_map.insert(s);
        }

        // Then we need to consult policy to get the service details.
        let pol = asm.policy_mgr.get_current();
        for svc in pol.list_services_by_kind(ServiceType::Authentication) {
            if offered_map.contains(&svc.id) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

// The auth service URI is of the form: <ZPR_AUTH_SCHEME>://<addr>:<port>/path
//
// Example: 'zpr-oauthrsa://[fd5a:5052:9090::88]:4000'
//
// The 'zpr-oauthrsa' scheme implies "https" and "/preauthorize" and "/authorize" endpoints.
//
// Currently "zpr-oauthrsa" is the only supported scheme and the service type of "auth"
// implies this scheme.
//
// TODO: Eventually we need to expand zplc and the compiler to have richer set of
// auth service types.
//
// TODO: The ph is passing the ASA info to the adapters as a socket-addr and the
// mechanics of zpr-oauthrsa are built in or something.  This all needs a clean up.
//
// Errors:
// - The only supported auth serice type requires a single scope, so you get an error
//   if there are none or more than one.
fn uri_for_service(
    skind: &ServiceType,
    addr: &IpAddr,
    endpoints: &[Scope],
) -> Result<String, ServiceError> {
    let scheme = match skind {
        ServiceType::Authentication => "zpr-oauthrsa",
        _ => {
            return Err(ServiceError::Internal(
                format!("unsupported service type for auth service URI: {skind:?}").into(),
            ));
        }
    };

    if endpoints.len() != 1 {
        return Err(ServiceError::Internal(
            format!(
                "auth service must have exactly one scope endpoint, not {}",
                endpoints.len()
            )
            .into(),
        ));
    }

    if let Some(portnum) = endpoints[0].port.as_ref() {
        let url = match addr {
            IpAddr::V4(a) => format!("{scheme}://{a}:{portnum}"),
            IpAddr::V6(a) => format!("{scheme}://[{a}]:{portnum}"),
        };
        Ok(url)
    } else {
        Err(ServiceError::Internal(
            "auth service scope must have a single port defined".into(),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::counters::Counters;
    use crate::db::{ActorRepo, FakeDb, NodeRepo};
    use crate::test_helpers::{
        make_actor_defexp, make_actor_with_services_defexp, make_adapter_actor_defexp,
        make_container_bytes, make_node_actor_defexp,
    };

    use bytes::Bytes;
    use libeval::attribute::ROLE_ADAPTER;
    use libeval::policy::Policy;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use zpr::policy::v1 as capnp_policy;
    use zpr::policy_types::{JoinPolicy, PFlags, Service};
    use zpr::write_to::WriteTo;

    fn make_mgr() -> ActorMgr {
        let db = Arc::new(FakeDb::new());
        let actor_repo = ActorRepo::new(db.clone());
        let node_repo = NodeRepo::new(db);
        ActorMgr::new(actor_repo, node_repo, Arc::new(Counters::default()))
    }

    /// Returns `(Policy, container_bytes)`
    fn make_policy_with_services(services: Vec<Service>) -> (Policy, Vec<u8>) {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");

            let mut jp_list = policy_bldr.reborrow().init_join_policies(1);
            let mut jp_bldr = jp_list.reborrow().get(0);
            let jp = JoinPolicy {
                conditions: Vec::new(),
                flags: PFlags::default(),
                provides: Some(services),
            };
            jp.write_to(&mut jp_bldr);
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();

        let container = make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        );

        (
            Policy::new_from_policy_bytes(Bytes::copy_from_slice(&bytes)).unwrap(),
            container,
        )
    }

    #[tokio::test]
    async fn test_add_node_and_set_vss() {
        let mgr = make_mgr();
        let actor = make_node_actor_defexp("fd5a:5052::1", "node-1", "[fd5a:5052::100]:1234");
        let node_addr: IpAddr = "fd5a:5052::1".parse().unwrap();

        mgr.add_node(&actor, false).await.unwrap();
        let loaded = mgr.get_actor_by_zpr_addr(&node_addr).await.unwrap();
        assert!(matches!(loaded, Some(a) if a.is_node()));

        let vss_addr: SocketAddr = "[fd5a:5052::200]:4000".parse().unwrap();
        mgr.set_node_vss(&node_addr, &vss_addr).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_node_rejects_non_node() {
        let mgr = make_mgr();
        let actor = make_adapter_actor_defexp("fd5a:5052::2", "adapter-1");

        let err = mgr.add_node(&actor, false).await.unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_actor_by_zpr_addr_none() {
        let mgr = make_mgr();
        let addr: IpAddr = "fd5a:5052::3".parse().unwrap();

        let result = mgr.get_actor_by_zpr_addr(&addr).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_add_adapter_via_node_tracks_connections() {
        let mgr = make_mgr();
        let node_actor = make_node_actor_defexp("fd5a:5052::4", "node-2", "[fd5a:5052::101]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::5", "adapter-2");
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::5".parse().unwrap();

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        let adapters = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert!(adapters.contains(&adapter_addr));

        let loaded = mgr.get_actor_by_zpr_addr(&adapter_addr).await.unwrap();
        assert!(matches!(loaded, Some(a) if !a.is_node()));
    }

    #[tokio::test]
    async fn test_remove_actor_by_zpr_addr() {
        let mgr = make_mgr();
        let node_actor = make_node_actor_defexp("fd5a:5052::6", "node-3", "[fd5a:5052::102]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::7", "adapter-3");
        let node_addr: IpAddr = "fd5a:5052::6".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::7".parse().unwrap();

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        mgr.remove_actor_by_zpr_addr(&adapter_addr).await.unwrap();
        let loaded = mgr.get_actor_by_zpr_addr(&adapter_addr).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_set_node_vss_missing_node() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::8".parse().unwrap();
        let vss_addr: SocketAddr = "[fd5a:5052::201]:4000".parse().unwrap();

        let err = mgr.set_node_vss(&node_addr, &vss_addr).await.unwrap_err();
        match err {
            ServiceError::Store(StoreError::NotFound(_)) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_uri_for_service_ipv6_auth() {
        let addr: IpAddr = "fd5a:5052::9".parse().unwrap();
        let endpoints = [Scope {
            protocol: 0,
            flag: None,
            port: Some(4000),
            port_range: None,
        }];

        let uri =
            uri_for_service(&ServiceType::Authentication, &addr, &endpoints, None).unwrap();
        assert_eq!(uri, "zpr-oauthrsa://[fd5a:5052::9]:4000");
    }

    /// The oidc arm: an `api = "oidc"` trusted service's URI is its issuer, straight
    /// from the policy `OidcConfig` (no endpoints, no on-net address involved).
    #[test]
    fn test_uri_for_service_oidc_returns_issuer() {
        let addr: IpAddr = IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
        let cfg = crate::test_helpers::make_test_oidc_config();

        let uri = uri_for_service(
            &ServiceType::Trusted("oidc".to_string()),
            &addr,
            &[],
            Some(&cfg),
        )
        .unwrap();
        assert_eq!(uri, "https://accounts.google.com");

        // An oidc service without its config is an internal error, not a panic.
        let err = uri_for_service(&ServiceType::Trusted("oidc".to_string()), &addr, &[], None)
            .unwrap_err();
        assert!(matches!(err, ServiceError::Internal(_)), "{err:?}");
    }

    #[test]
    fn test_uri_for_service_errors() {
        let addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let endpoints = [Scope {
            protocol: 0,
            flag: None,
            port: Some(4000),
            port_range: None,
        }];

        // Non-auth service types are not supported for auth service URIs.
        let err = uri_for_service(&ServiceType::Regular, &addr, &endpoints, None).unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }

        // Auth services must declare exactly one endpoint scope.
        let err = uri_for_service(&ServiceType::Authentication, &addr, &[], None).unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }

        let endpoints_missing_port = [Scope {
            protocol: 0,
            flag: None,
            port: None,
            port_range: None,
        }];
        // Auth service scope must include a concrete port number.
        let err = uri_for_service(
            &ServiceType::Authentication,
            &addr,
            &endpoints_missing_port,
            None,
        )
        .unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_auth_services_list_filters_and_formats() {
        let mgr = make_mgr();
        let actor = make_actor_with_services_defexp(
            ROLE_ADAPTER,
            "fd5a:5052::11",
            &["svc:auth", "svc:regular", "svc:unknown"],
            "adapter-auth",
        );
        mgr.hack_add_adapter_no_node(&actor).await.unwrap();

        let auth_service = Service {
            id: "svc:auth".to_string(),
            endpoints: vec![Scope {
                protocol: 0,
                flag: None,
                port: Some(4000),
                port_range: None,
            }],
            kind: ServiceType::Authentication,
        };
        let regular_service = Service {
            id: "svc:regular".to_string(),
            endpoints: vec![Scope {
                protocol: 0,
                flag: None,
                port: Some(8080),
                port_range: None,
            }],
            kind: ServiceType::Regular,
        };
        let (_policy, container_bytes) =
            make_policy_with_services(vec![auth_service, regular_service]);

        let asm = new_assembly_for_tests(None).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(container_bytes)
            .await
            .unwrap();
        let asm = Arc::new(asm);

        let mut services = mgr.get_auth_services_list(asm).await.unwrap();
        services.sort_by(|a, b| a.service_id.cmp(&b.service_id));

        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_id, "svc:auth");
        assert_eq!(
            services[0].service_uri,
            "zpr-oauthrsa://[fd5a:5052::11]:4000"
        );
        let addr: IpAddr = "fd5a:5052::11".parse().unwrap();
        assert_eq!(services[0].zpr_addr, addr);
    }

    #[tokio::test]
    async fn test_get_auth_services_list_returns_empty_without_policy_auth() {
        let mgr = make_mgr();
        let actor = make_actor_with_services_defexp(
            ROLE_ADAPTER,
            "fd5a:5052::12",
            &["svc:auth"],
            "adapter-regular",
        );
        mgr.hack_add_adapter_no_node(&actor).await.unwrap();

        let regular_service = Service {
            id: "svc:auth".to_string(),
            endpoints: vec![Scope {
                protocol: 0,
                flag: None,
                port: Some(8080),
                port_range: None,
            }],
            kind: ServiceType::Regular, // NOT an auth service
        };
        let (_policy, container_bytes) = make_policy_with_services(vec![regular_service]);

        let asm = new_assembly_for_tests(None).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(container_bytes)
            .await
            .unwrap();
        let asm = Arc::new(asm);

        let services = mgr.get_auth_services_list(asm).await.unwrap();
        assert!(services.is_empty());
    }

    /// A policy declaring an `api = "oidc"` trusted service yields an off-net IdP
    /// descriptor even though no actor provides the service: stype
    /// `OidcAuthentication`, `service_uri` = issuer, `zpr_addr` = `::`, and the
    /// `OidcClientConfig` carrying issuer/client_id/scopes.
    #[tokio::test]
    async fn test_auth_services_list_includes_oidc_descriptor() {
        let mgr = make_mgr();

        let oidc_cfg = crate::test_helpers::make_test_oidc_config();
        let container_bytes = crate::test_helpers::make_oidc_policy(
            "google",
            300,
            &["sub -> user.oidc-subject", "email -> user.email"],
            &["sub"],
            oidc_cfg.clone(),
        );

        let asm = new_assembly_for_tests(None).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(container_bytes)
            .await
            .unwrap();
        let asm = Arc::new(asm);

        let services = mgr.get_auth_services_list(asm).await.unwrap();
        assert_eq!(services.len(), 1);
        let sdesc = &services[0];
        assert_eq!(sdesc.stype, zpr::vsapi_types::ServiceT::OidcAuthentication);
        assert_eq!(sdesc.service_id, "google");
        assert_eq!(sdesc.service_uri, oidc_cfg.issuer);
        assert_eq!(
            sdesc.zpr_addr,
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            "off-net services carry the unspecified address"
        );
        let client = sdesc.oidc.as_ref().expect("oidc client config");
        assert_eq!(client.issuer, oidc_cfg.issuer);
        assert_eq!(client.client_id, oidc_cfg.client_id);
        assert_eq!(client.client_secret, oidc_cfg.client_secret);
        assert_eq!(client.scopes, oidc_cfg.scopes);
        assert_eq!(client.allow_offline_access, oidc_cfg.allow_offline_access);
    }

    #[tokio::test]
    async fn test_get_adapter_cns_connected_to_node_single_adapter() {
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn-1", "[fd5a:5052::120]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::21", "adapter-cn-1");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        let cns = mgr
            .get_adapter_cns_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert_eq!(cns.len(), 1);
        assert_eq!(cns[0], "adapter-cn-1");
    }

    #[tokio::test]
    async fn test_get_adapter_cns_connected_to_node_multiple_adapters() {
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn", "[fd5a:5052::120]:1234");
        let adapter1 = make_adapter_actor_defexp("fd5a:5052::21", "adapter-1");
        let adapter2 = make_adapter_actor_defexp("fd5a:5052::22", "adapter-2");
        let adapter3 = make_adapter_actor_defexp("fd5a:5052::23", "adapter-3");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter1, &node_addr)
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter2, &node_addr)
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter3, &node_addr)
            .await
            .unwrap();

        let mut cns = mgr
            .get_adapter_cns_connected_to_node(&node_addr)
            .await
            .unwrap();
        cns.sort();
        assert_eq!(cns.len(), 3);
        assert_eq!(cns, vec!["adapter-1", "adapter-2", "adapter-3"]);
    }

    #[tokio::test]
    async fn test_get_adapter_cns_connected_to_node_no_adapters() {
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn", "[fd5a:5052::120]:1234");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        mgr.add_node(&node_actor, false).await.unwrap();

        let cns = mgr
            .get_adapter_cns_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert!(cns.is_empty());
    }

    #[tokio::test]
    async fn test_get_adapter_cns_connected_to_node_only_returns_own_adapters() {
        // Two nodes, each with their own adapters — verify no cross-contamination.
        let mgr = make_mgr();
        let node_a = make_node_actor_defexp("fd5a:5052::20", "node-a", "[fd5a:5052::120]:1234");
        let node_b = make_node_actor_defexp("fd5a:5052::21", "node-b", "[fd5a:5052::120]:1234");
        let adapter_on_a = make_adapter_actor_defexp("fd5a:5052::22", "adapter-for-a");
        let adapter_on_b = make_adapter_actor_defexp("fd5a:5052::23", "adapter-for-b");

        let node_a_addr: IpAddr = "fd5a:5052::20".parse().unwrap();
        let node_b_addr: IpAddr = "fd5a:5052::21".parse().unwrap();

        mgr.add_node(&node_a, false).await.unwrap();
        mgr.add_node(&node_b, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter_on_a, &node_a_addr)
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_on_b, &node_b_addr)
            .await
            .unwrap();

        let cns_a = mgr
            .get_adapter_cns_connected_to_node(&node_a_addr)
            .await
            .unwrap();
        assert_eq!(cns_a.len(), 1);
        assert_eq!(cns_a[0], "adapter-for-a");

        let cns_b = mgr
            .get_adapter_cns_connected_to_node(&node_b_addr)
            .await
            .unwrap();
        assert_eq!(cns_b.len(), 1);
        assert_eq!(cns_b[0], "adapter-for-b");
    }

    #[tokio::test]
    async fn test_get_adapter_cns_connected_to_node_after_removal() {
        // Add two adapters, remove one, verify only the remaining CN is returned.
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn-rm", "[fd5a:5052::120]:1234");
        let adapter1 = make_adapter_actor_defexp("fd5a:5052::21", "keep-me");
        let adapter2 = make_adapter_actor_defexp("fd5a:5052::22", "remove-me");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();
        let remove_addr: IpAddr = "fd5a:5052::22".parse().unwrap();

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter1, &node_addr)
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter2, &node_addr)
            .await
            .unwrap();

        // Sanity: both present before removal.
        let mut cns = mgr
            .get_adapter_cns_connected_to_node(&node_addr)
            .await
            .unwrap();
        cns.sort();
        assert_eq!(cns.len(), 2);

        // Remove the actor record for adapter2.
        mgr.remove_actor_by_zpr_addr(&remove_addr).await.unwrap();

        // The node_db still has the ZPR address in its connected-adapters list,
        // but the actor lookup will return None — the function should gracefully
        // skip it via .flatten().
        let cns = mgr
            .get_adapter_cns_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert_eq!(cns.len(), 1);
        assert_eq!(cns[0], "keep-me");
    }

    #[tokio::test]
    async fn test_get_adapter_cns_connected_to_node_unknown_node() {
        // Querying a node address that was never added should return an empty vec
        // (or an error, depending on the NodeRepo implementation).
        let mgr = make_mgr();
        let unknown_addr: IpAddr = "fd5a:5052::99".parse().unwrap();

        let result = mgr.get_adapter_cns_connected_to_node(&unknown_addr).await;
        // With FakeDb this likely returns Ok(vec![]).
        // If the implementation errors on unknown nodes, adjust to unwrap_err().
        match result {
            Ok(cns) => assert!(cns.is_empty()),
            Err(_) => {} // Also acceptable — unknown node is not in DB.
        }
    }

    // --- connection table / get_docking_node_for_actor tests ---

    #[tokio::test]
    async fn test_get_docking_node_for_node_actor_returns_self() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::30".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::30", "node-self", "[fd5a:5052::130]:1234");

        mgr.add_node(&node_actor, false).await.unwrap();

        let docking = mgr.get_docking_node_for_actor(&node_actor);
        assert_eq!(docking, Some(node_addr));
    }

    #[tokio::test]
    async fn test_get_docking_node_for_adapter_with_connection_returns_node() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::31".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::31", "node-dock", "[fd5a:5052::131]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::32", "adapter-dock");

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        let docking = mgr.get_docking_node_for_actor(&adapter_actor);
        assert_eq!(docking, Some(node_addr));
    }

    #[tokio::test]
    async fn test_get_docking_node_for_adapter_not_in_connection_table_returns_none() {
        let mgr = make_mgr();
        // Adapter added to actor DB but NOT via a node (so no connection_table entry).
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::33", "adapter-orphan");
        mgr.hack_add_adapter_no_node(&adapter_actor).await.unwrap();

        let docking = mgr.get_docking_node_for_actor(&adapter_actor);
        assert_eq!(docking, None);
    }

    #[test]
    fn test_get_docking_node_for_actor_without_zpr_addr_returns_none() {
        let mgr = make_mgr();
        // Actor with no ZPR_ADDR attribute at all.
        let actor = make_actor_defexp(&[
            (
                libeval::attribute::key::ROLE,
                libeval::attribute::ROLE_ADAPTER,
            ),
            (libeval::attribute::key::CN, "no-addr-actor"),
        ]);

        let docking = mgr.get_docking_node_for_actor(&actor);
        assert_eq!(docking, None);
    }

    #[tokio::test]
    async fn test_remove_actor_clears_connection_table_entry() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::34".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::35".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::34", "node-rm-ct", "[fd5a:5052::134]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::35", "adapter-rm-ct");

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        // Confirm the entry is present before removal.
        assert_eq!(
            mgr.get_docking_node_for_actor(&adapter_actor),
            Some(node_addr)
        );

        mgr.remove_actor_by_zpr_addr(&adapter_addr).await.unwrap();

        // Entry must be gone from the connection table after removal.
        assert_eq!(mgr.get_docking_node_for_actor(&adapter_actor), None);
    }

    #[tokio::test]
    async fn test_remove_node_clears_adapters_from_connection_table() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::36".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::36", "node-rm-node", "[fd5a:5052::136]:1234");
        let adapter1 = make_adapter_actor_defexp("fd5a:5052::37", "adapter-rm-1");
        let adapter2 = make_adapter_actor_defexp("fd5a:5052::38", "adapter-rm-2");

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter1, &node_addr)
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter2, &node_addr)
            .await
            .unwrap();

        assert_eq!(mgr.get_docking_node_for_actor(&adapter1), Some(node_addr));
        assert_eq!(mgr.get_docking_node_for_actor(&adapter2), Some(node_addr));

        mgr.remove_node(&node_addr).await.unwrap();

        // Both adapter entries must be purged from the connection table.
        assert_eq!(mgr.get_docking_node_for_actor(&adapter1), None);
        assert_eq!(mgr.get_docking_node_for_actor(&adapter2), None);
    }

    #[tokio::test]
    async fn test_remove_node_does_not_affect_other_nodes_connections() {
        let mgr = make_mgr();
        let node_a_addr: IpAddr = "fd5a:5052::39".parse().unwrap();
        let node_b_addr: IpAddr = "fd5a:5052::40".parse().unwrap();
        let node_a = make_node_actor_defexp("fd5a:5052::39", "node-a-rm", "[fd5a:5052::139]:1234");
        let node_b = make_node_actor_defexp("fd5a:5052::40", "node-b-rm", "[fd5a:5052::140]:1234");
        let adapter_a = make_adapter_actor_defexp("fd5a:5052::41", "adapter-on-a");
        let adapter_b = make_adapter_actor_defexp("fd5a:5052::42", "adapter-on-b");

        mgr.add_node(&node_a, false).await.unwrap();
        mgr.add_node(&node_b, false).await.unwrap();
        mgr.add_adapter_via_node(&adapter_a, &node_a_addr)
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_b, &node_b_addr)
            .await
            .unwrap();

        mgr.remove_node(&node_a_addr).await.unwrap();

        // adapter_a's entry is gone, but adapter_b's entry (on node_b) must remain.
        assert_eq!(mgr.get_docking_node_for_actor(&adapter_a), None);
        assert_eq!(
            mgr.get_docking_node_for_actor(&adapter_b),
            Some(node_b_addr)
        );
    }

    #[tokio::test]
    async fn test_hack_set_vs_docking_node_updates_connection_table() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::43".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::43", "node-vs-hack", "[fd5a:5052::143]:1234");
        let vs_addr = IpAddr::V6(crate::config::VS_ZPR_ADDR);

        mgr.add_node(&node_actor, false).await.unwrap();
        mgr.hack_set_vs_docking_node(&node_addr).await.unwrap();

        // The VS adapter should now resolve to node_addr in the connection table.
        let vs_actor = make_actor_defexp(&[
            (
                libeval::attribute::key::ROLE,
                libeval::attribute::ROLE_ADAPTER,
            ),
            (libeval::attribute::key::CN, "visa-service"),
            (libeval::attribute::key::ZPR_ADDR, &vs_addr.to_string()),
        ]);
        let docking = mgr.get_docking_node_for_actor(&vs_actor);
        assert_eq!(docking, Some(node_addr));
    }

    #[tokio::test]
    async fn test_refresh_state_populates_connection_table() {
        // Set up state via one manager instance, then verify a fresh manager's
        // refresh_state repopulates the connection table from the DB.
        let db = Arc::new(crate::db::FakeDb::new());
        let actor_repo = crate::db::ActorRepo::new(db.clone());
        let node_repo = crate::db::NodeRepo::new(db.clone());
        let mgr1 = ActorMgr::new(actor_repo, node_repo, Arc::new(Counters::default()));

        let node_addr: IpAddr = "fd5a:5052::44".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::44", "node-refresh", "[fd5a:5052::144]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::45", "adapter-refresh");

        mgr1.add_node(&node_actor, false).await.unwrap();
        mgr1.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        // Create a fresh manager over the same DB (no in-memory connection_table).
        let actor_repo2 = crate::db::ActorRepo::new(db.clone());
        let node_repo2 = crate::db::NodeRepo::new(db.clone());
        let mgr2 = ActorMgr::new(actor_repo2, node_repo2, Arc::new(Counters::default()));

        // Before refresh the connection table is empty.
        assert_eq!(mgr2.get_docking_node_for_actor(&adapter_actor), None);

        mgr2.refresh_state().await.unwrap();

        // After refresh the adapter should resolve to its node.
        assert_eq!(
            mgr2.get_docking_node_for_actor(&adapter_actor),
            Some(node_addr)
        );
    }
}
