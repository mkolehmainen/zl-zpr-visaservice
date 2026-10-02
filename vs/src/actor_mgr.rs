//! Actor manager. Manages nodes too.
//!

use dashmap::DashMap;
use libeval::actor::Actor;
use libeval::attribute::key;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

use zpr::policy_types::ServiceType;
use zpr::vsapi_types::{OidcClientConfig, PublicKey, ServiceDescriptor};

use crate::assembly::Assembly;
use crate::config;
use crate::counters::Counters;
use crate::db;
use crate::db::ServiceEntry;
use crate::error::{ServiceError, StoreError};
use crate::logging::targets::ACTOR;
use crate::trusted_services::TS_API_OIDC;

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

/// A stale node identified by [ActorMgr::refresh_state], with the adapter
/// addresses that were docked through it. `refresh_state` runs before the
/// `Assembly` exists and deletes NOTHING (PR #46 review): the node's records —
/// and with them the connected-adapters set this was read from — are removed
/// by the caller's teardown ([main]'s `teardown_culled_nodes`) only after the
/// adapters' own teardown (zipline#138's `remove_departed_adapters` plus
/// `remove_visas_for_actors`) has run, so a crash anywhere before that leaves
/// the node discoverable and the next startup re-culls it (zipline#145).
pub struct CulledNode {
    /// The culled node's ZPR address.
    pub node_addr: IpAddr,
    /// ZPR addresses of the adapters that were docked through the node, read
    /// from the node's connected-adapters set (which is still in the DB: the
    /// teardown deletes it last).
    pub adapter_addrs: Vec<IpAddr>,
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
    /// For each node we find in here we check how long ago it was last seen. Nodes
    /// last seen more than [config::DEFAULT_AUTH_EXPIRATION] ago are culled: each is
    /// returned with the adapter addresses that were docked through it. **Nothing is
    /// deleted here** (PR #46 review): this runs before the `Assembly` exists, and
    /// `main` can still exit before the teardown runs (`VisaRepo::new`, API-key
    /// loading) — deleting the node record now would strand its docked adapters,
    /// since the connected-adapters set is the only place they are recorded. The
    /// caller (`main`, via `synchronize_state`) runs `teardown_culled_nodes` right
    /// after Assembly construction (zipline#145), which tears the adapters down and
    /// only then removes the node's records ([ActorMgr::finish_cull]); a crash
    /// anywhere in between leaves the node discoverable and this cull re-reports it
    /// on the next startup. Culling by last-seen age instead of
    /// authentication expiry (zipline#119): bootstrap authentication no longer
    /// expires, so an auth-expiry check would keep dead nodes forever; the 4 h
    /// window this preserves is the same one the old auth-expiry check gave a
    /// bootstrap node. A node with no recorded last-seen time is treated as stale
    /// and removed — its record predates last-seen tracking or never carried one.
    ///
    /// For nodes seen recently enough, we wipe their vss info.
    pub async fn refresh_state(&self) -> Result<Vec<CulledNode>, ServiceError> {
        let mut culled = Vec::new();
        for node_addr in &self.node_db.list_node_addrs().await? {
            match self.actor_db.get_actor_by_zpr_addr(node_addr).await {
                Ok(_actor) => {}
                Err(StoreError::NotFound(_)) => {
                    debug!(target: ACTOR, "refresh_state: node at {} not found in actor DB, removing from node DB", node_addr);
                    culled.push(self.cull_node(node_addr).await?);
                    continue;
                }
                Err(e) => return Err(ServiceError::from(e)),
            };

            let stale = match self.node_db.get_last_seen_time(node_addr).await? {
                Some(last_seen) => match SystemTime::now().duration_since(last_seen) {
                    Ok(age) => age > config::DEFAULT_AUTH_EXPIRATION,
                    // A last-seen in the future is clock skew, not staleness.
                    Err(_) => false,
                },
                None => true,
            };
            if stale {
                info!(target: ACTOR, "refresh_state: node at {node_addr} last seen too long ago, removing");
                culled.push(self.cull_node(node_addr).await?);
                continue;
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

        Ok(culled)
    }

    /// Read a stale node into its [CulledNode] — the node's ZPR address plus
    /// the adapters recorded in its connected-adapters set. **Deletes
    /// nothing** (PR #46 review): the node's records stay in the DB until
    /// [ActorMgr::finish_cull] runs from the post-Assembly teardown, so a
    /// crash before then leaves the node discoverable for the next startup.
    async fn cull_node(&self, node_addr: &IpAddr) -> Result<CulledNode, ServiceError> {
        let adapter_addrs = match self.node_db.get_connected_adapters(node_addr).await {
            Ok(adapters) => adapters.into_iter().collect(),
            Err(StoreError::NotFound(_)) => Vec::new(),
            Err(e) => return Err(ServiceError::from(e)),
        };
        Ok(CulledNode {
            node_addr: *node_addr,
            adapter_addrs,
        })
    }

    /// Complete a startup cull: remove the culled node's actor record and its
    /// node DB record (and with it the connected-adapters set). Called from
    /// `main`'s `teardown_culled_nodes` only AFTER the node's docked adapters
    /// have been torn down (PR #46 review) — the connected-adapters set is the
    /// only durable record of those adapters, so deleting it earlier would
    /// strand them if startup crashed before the teardown. Idempotent: both
    /// removals are key deletions, so re-running after a partial failure is
    /// safe.
    pub async fn finish_cull(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        self.remove_actor_by_zpr_addr(node_addr).await?;
        self.remove_node(node_addr).await?;
        Ok(())
    }

    pub async fn add_node(
        &self,
        actor: &Actor,
        reconnect: bool,
        policy_service_names: &HashSet<String>,
    ) -> Result<(), ServiceError> {
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
            // Replacing add: a node legitimately re-authenticates at its own
            // live record (RSA-proven against the policy bootstrap key for its
            // CN -- the occupied-address gate in authorize_connection already
            // enforced this), so an existing record here is the node's own and
            // is superseded, not evicted (PR #33 review, P2).
            self.actor_db
                .add_actor_replacing(actor, policy_service_names, &self.counters)
                .await?;
        } else {
            // Is a reconnect...
            if let Err(e) = self
                .actor_db
                .update_actor(actor, policy_service_names, &self.counters)
                .await
            {
                // Update failed? Make the node try a fresh connect. The node record is
                // deliberately left in place: the fresh connect's Reset teardown reads
                // the node's connected-adapters set to remove its docked adapters, and
                // the replacing add below then supersedes the record (zipline#138).
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
    pub async fn update_actor(
        &self,
        actor: &Actor,
        policy_service_names: &HashSet<String>,
    ) -> Result<(), ServiceError> {
        self.actor_db
            .update_actor(actor, policy_service_names, &self.counters)
            .await?;
        Ok(())
    }

    /// Rebuild the `host:<NAME>` hostname-claim index from persisted actor
    /// attributes against `policy_service_names` (zipline#53, PR #24 review).
    /// Called at startup (backfill for actors persisted before the index
    /// existed) and on policy install (a new policy service name evicts a
    /// matching held hostname).
    pub async fn reconcile_hostname_claims(
        &self,
        policy_service_names: &HashSet<String>,
    ) -> Result<(), ServiceError> {
        self.actor_db
            .reconcile_hostname_claims(policy_service_names, &self.counters)
            .await?;
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
        policy_service_names: &HashSet<String>,
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

        // The visa service's own adapter re-adds itself at its fixed address,
        // where its startup self-authorization (hack_add_adapter_no_node)
        // already wrote a record: that record is the VS's own, so it is
        // superseded rather than reported occupied (zipline#102). The
        // occupied-address gate in authorize_connection admits only the
        // authenticated VS at this address. Every other adapter keeps the
        // non-evicting add (PR #33 review, P2).
        let is_vs_self = actor.get_cn() == Some(config::VS_CN)
            && *adapter_addr == IpAddr::V6(config::VS_ZPR_ADDR);
        if is_vs_self {
            self.actor_db
                .add_actor_replacing(actor, policy_service_names, &self.counters)
                .await?;
        } else {
            self.actor_db
                .add_actor(actor, policy_service_names, &self.counters)
                .await?;
        }
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
    /// Replacing add: the VS re-authorizes itself at its own fixed address on
    /// every startup, and a record from the previous run may still be
    /// persisted — that record is the VS's own, superseded rather than
    /// evicted (the occupied-address gate in authorize_connection admits only
    /// the VS itself at this address; PR #33 review, P2).
    ///
    /// See https://github.com/org-zpr/zpr-visaservice/issues/195
    pub async fn hack_add_adapter_no_node(
        &self,
        actor: &Actor,
        policy_service_names: &HashSet<String>,
    ) -> Result<(), ServiceError> {
        if actor.is_node() {
            return Err(ServiceError::Internal(
                "attempt to add node actor as adapter".into(),
            ));
        }
        self.actor_db
            .add_actor_replacing(actor, policy_service_names, &self.counters)
            .await?;
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

    /// Returns actors public key or None if no key is stored for it.
    pub async fn get_a2a_dh_pubkey_by_zpr_addr(
        &self,
        zpra: &IpAddr,
    ) -> Result<Option<PublicKey>, ServiceError> {
        Ok(self.actor_db.get_a2a_dh_pubkey_by_zpr_addr(zpra).await?)
    }

    /// Remove actor state from the database. If removing a node, also call [ActorMgr::remove_node].
    ///
    /// An adapter is also dropped from its docking node's persisted connections set, so
    /// that set lists only adapters still docked there. A stale entry would let a later
    /// teardown of that node (a Reset or a disconnect cascade) remove whichever actor
    /// holds the address next, even one docked at another node (PR #45 review).
    pub async fn remove_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<(), ServiceError> {
        self.actor_db.rm_actor_by_zpr_addr(zpra).await?;
        if let Some((_, node_addr)) = self.connection_table.remove(zpra) {
            // The actor record is already gone, so report success either way; a
            // leftover entry is logged rather than failing the removal.
            if let Err(e) = self
                .node_db
                .remove_connected_adapter(&node_addr, zpra)
                .await
            {
                warn!(target: ACTOR, "failed to drop adapter {zpra} from connections of node {node_addr}: {e}");
            }
        }
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

    /// Get the list of authentication services to advertise to nodes: the
    /// policy-declared off-net OIDC identity providers. They never appear in the
    /// actor DB — they are not on the ZPR network — so the list comes from policy
    /// alone.
    pub async fn get_auth_services_list(
        &self,
        asm: Arc<Assembly>,
    ) -> Result<Vec<ServiceDescriptor>, ServiceError> {
        let mut services = Vec::new();
        let pol = asm.policy_mgr.get_current();

        for svc in pol.list_services_by_kind(ServiceType::Trusted(TS_API_OIDC.to_string())) {
            let Some(record) = pol.trusted_service_by_id(&svc.id) else {
                // trusted_service_definitions validated this at policy install.
                continue;
            };
            let Some(cfg) = &record.oidc else {
                continue; // same: rejected at install, fail soft here
            };
            services.push(ServiceDescriptor {
                stype: zpr::vsapi_types::ServiceT::OidcAuthentication,
                service_id: svc.id.clone(),
                // An off-net identity provider is addressed by its issuer URL.
                service_uri: cfg.issuer.clone(),
                // Off-net services carry the unspecified address.
                zpr_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                oidc: Some(OidcClientConfig {
                    issuer: cfg.issuer.clone(),
                    client_id: cfg.client_id.clone(),
                    client_secret: cfg.client_secret.clone(),
                    scopes: cfg.scopes.clone(),
                    allow_offline_access: cfg.allow_offline_access,
                }),
            });
        }

        Ok(services)
    }

    pub async fn get_services_list(&self) -> Result<Vec<ServiceEntry>, ServiceError> {
        let services = self.actor_db.list_services().await?;
        Ok(services)
    }

    /// List the connected actors, optionally filtered by role. Each entry is the
    /// actor's ZPR address (the key) plus its CN when it has one (a display label
    /// that may be absent).
    pub async fn list_actors(
        &self,
        by_role: Option<db::Role>,
    ) -> Result<Vec<(IpAddr, Option<String>)>, ServiceError> {
        let actors = self.actor_db.list_actors(by_role).await?;
        Ok(actors)
    }

    /// Given a hostname, the ZPR address of the actor holding it in the
    /// `host:<NAME>` claim index (zipline#53), if any. Query-side spelling
    /// matches claim-side exactly — no mangling of the caller's input.
    pub async fn get_zpr_addr_for_hostname(
        &self,
        hostname: &str,
    ) -> Result<Option<IpAddr>, ServiceError> {
        Ok(self.actor_db.get_zpr_addr_for_hostname(hostname).await?)
    }

    /// The actor's `hostname_conflicts` display field (zipline#54): claim
    /// values refused because another actor or a policy service held them.
    /// Missing or unparseable data is an empty list, never an error.
    pub async fn get_hostname_conflicts(
        &self,
        zpr_addr: &IpAddr,
    ) -> Result<Vec<String>, ServiceError> {
        Ok(self.actor_db.get_hostname_conflicts(zpr_addr).await?)
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

    /// Return true if the actor exists and offers at least one on-net authentication
    /// service (`ServiceType::Authentication` in the **current** policy). This is the
    /// gate that lets an unauthenticated adapter on an AAA address reach the actor
    /// (see `visareq_worker::try_aaa_actor`).
    ///
    /// No policy compiler currently emits `ServiceType::Authentication`: the on-net
    /// authentication service it described was retired, and OIDC identity providers
    /// are off-net. The check stays so the AAA path has a well-defined gate if an
    /// on-net authentication service returns; until then it answers `false` for any
    /// compiled policy.
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::counters::Counters;
    use crate::db::{ActorRepo, FakeDb, NodeRepo};
    use crate::test_helpers::{
        make_actor_defexp, make_adapter_actor_defexp, make_container_bytes, make_node_actor_defexp,
        make_oidc_only_adapter_defexp,
    };

    use bytes::Bytes;
    use libeval::policy::Policy;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
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

        mgr.add_node(&actor, false, &Default::default())
            .await
            .unwrap();
        let loaded = mgr.get_actor_by_zpr_addr(&node_addr).await.unwrap();
        assert!(matches!(loaded, Some(a) if a.is_node()));

        let vss_addr: SocketAddr = "[fd5a:5052::200]:4000".parse().unwrap();
        mgr.set_node_vss(&node_addr, &vss_addr).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_node_rejects_non_node() {
        let mgr = make_mgr();
        let actor = make_adapter_actor_defexp("fd5a:5052::2", "adapter-1");

        let err = mgr
            .add_node(&actor, false, &Default::default())
            .await
            .unwrap_err();
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

    /// zipline#102: the VS adapter's real connect re-adds the visa service at
    /// its own address, where its startup self-authorization already put a
    /// record. That record is the VS's own and must be superseded, not reported
    /// as an occupied address -- otherwise the VS can never finish connecting.
    #[tokio::test]
    async fn test_add_adapter_via_node_supersedes_vs_self_record() {
        let mgr = make_mgr();
        let vs_addr = IpAddr::V6(config::VS_ZPR_ADDR);
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let vs_actor = make_adapter_actor_defexp(&vs_addr.to_string(), config::VS_CN);

        mgr.hack_add_adapter_no_node(&vs_actor, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&vs_actor, &node_addr, &Default::default())
            .await
            .expect("the VS must be able to re-add itself at its own address");

        let adapters = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert!(adapters.contains(&vs_addr));
    }

    /// Any other adapter at an occupied address is still refused: the VS
    /// carve-out must not reopen the eviction PR #33 (P2) closed.
    #[tokio::test]
    async fn test_add_adapter_via_node_occupied_address_rejected() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let holder = make_adapter_actor_defexp("fd5a:5052:8888::5", "holder");
        let intruder = make_adapter_actor_defexp("fd5a:5052:8888::5", "intruder");

        mgr.add_adapter_via_node(&holder, &node_addr, &Default::default())
            .await
            .unwrap();
        let result = mgr
            .add_adapter_via_node(&intruder, &node_addr, &Default::default())
            .await;

        assert!(result.is_err(), "occupied address must be refused");
    }

    #[tokio::test]
    async fn test_add_adapter_via_node_tracks_connections() {
        let mgr = make_mgr();
        let node_actor = make_node_actor_defexp("fd5a:5052::4", "node-2", "[fd5a:5052::101]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::5", "adapter-2");
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::5".parse().unwrap();

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr, &Default::default())
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

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr, &Default::default())
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
    async fn test_get_adapters_connected_to_node_single_adapter() {
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn-1", "[fd5a:5052::120]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::21", "adapter-cn-1");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr, &Default::default())
            .await
            .unwrap();

        let addrs = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert_eq!(addrs, vec!["fd5a:5052::21".parse::<IpAddr>().unwrap()]);
    }

    /// F2 (zipline#29 / zipline#30, A1 gate): a CN-less adapter (OIDC-only connect)
    /// connected to a node must still be represented in the node's adapter list.
    /// Pre-A2, `get_adapter_cns_connected_to_node` ended in
    /// `.filter_map(|actor| actor.get_cn()...)`, so the adapter was silently
    /// dropped from `NodeRecordBrief.adapters` -- an omission path independent of
    /// F1's `list_actor_cns` drop. zipline#31 (A2) deletes that CN-mapping wrapper:
    /// the address list from `get_adapters_connected_to_node` is the surface, and
    /// it cannot drop a CN-less adapter.
    #[tokio::test]
    async fn test_get_adapters_includes_cn_less_adapter() {
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::60", "node-cn-f2", "[fd5a:5052::160]:1234");
        let cn_less_adapter = make_oidc_only_adapter_defexp("fd5a:5052::61");
        let normal_adapter = make_adapter_actor_defexp("fd5a:5052::62", "adapter-cn-f2");
        let node_addr: IpAddr = "fd5a:5052::60".parse().unwrap();

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&cn_less_adapter, &node_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&normal_adapter, &node_addr, &Default::default())
            .await
            .unwrap();

        // Both connected adapters must be represented by address; the CN-less one
        // must not be filter_map'd away.
        let mut addrs = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        addrs.sort();
        assert_eq!(
            addrs,
            vec![
                "fd5a:5052::61".parse::<IpAddr>().unwrap(),
                "fd5a:5052::62".parse::<IpAddr>().unwrap(),
            ],
            "CN-less adapter was dropped from the node's adapter list"
        );
    }

    #[tokio::test]
    async fn test_get_adapters_connected_to_node_multiple_adapters() {
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn", "[fd5a:5052::120]:1234");
        let adapter1 = make_adapter_actor_defexp("fd5a:5052::21", "adapter-1");
        let adapter2 = make_adapter_actor_defexp("fd5a:5052::22", "adapter-2");
        let adapter3 = make_adapter_actor_defexp("fd5a:5052::23", "adapter-3");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter1, &node_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter2, &node_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter3, &node_addr, &Default::default())
            .await
            .unwrap();

        let mut addrs = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        addrs.sort();
        assert_eq!(
            addrs,
            vec![
                "fd5a:5052::21".parse::<IpAddr>().unwrap(),
                "fd5a:5052::22".parse::<IpAddr>().unwrap(),
                "fd5a:5052::23".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn test_get_adapters_connected_to_node_no_adapters() {
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn", "[fd5a:5052::120]:1234");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();

        let addrs = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn test_get_adapters_connected_to_node_only_returns_own_adapters() {
        // Two nodes, each with their own adapters — verify no cross-contamination.
        let mgr = make_mgr();
        let node_a = make_node_actor_defexp("fd5a:5052::20", "node-a", "[fd5a:5052::120]:1234");
        let node_b = make_node_actor_defexp("fd5a:5052::21", "node-b", "[fd5a:5052::120]:1234");
        let adapter_on_a = make_adapter_actor_defexp("fd5a:5052::22", "adapter-for-a");
        let adapter_on_b = make_adapter_actor_defexp("fd5a:5052::23", "adapter-for-b");

        let node_a_addr: IpAddr = "fd5a:5052::20".parse().unwrap();
        let node_b_addr: IpAddr = "fd5a:5052::21".parse().unwrap();

        mgr.add_node(&node_a, false, &Default::default())
            .await
            .unwrap();
        mgr.add_node(&node_b, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_on_a, &node_a_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_on_b, &node_b_addr, &Default::default())
            .await
            .unwrap();

        let addrs_a = mgr
            .get_adapters_connected_to_node(&node_a_addr)
            .await
            .unwrap();
        assert_eq!(addrs_a, vec!["fd5a:5052::22".parse::<IpAddr>().unwrap()]);

        let addrs_b = mgr
            .get_adapters_connected_to_node(&node_b_addr)
            .await
            .unwrap();
        assert_eq!(addrs_b, vec!["fd5a:5052::23".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn test_get_adapters_connected_to_node_after_removal() {
        // Removing an adapter's actor record also drops it from its docking
        // node's persisted connections set (PR #45 review, Codex P1): a stale
        // entry there would let a later teardown of this node -- a Reset or a
        // disconnect cascade -- remove whatever actor holds the address next,
        // even one docked at a different node.
        let mgr = make_mgr();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::20", "node-cn-rm", "[fd5a:5052::120]:1234");
        let adapter1 = make_adapter_actor_defexp("fd5a:5052::21", "keep-me");
        let adapter2 = make_adapter_actor_defexp("fd5a:5052::22", "remove-me");
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();
        let remove_addr: IpAddr = "fd5a:5052::22".parse().unwrap();

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter1, &node_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter2, &node_addr, &Default::default())
            .await
            .unwrap();

        // Sanity: both present before removal.
        let mut addrs = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        addrs.sort();
        assert_eq!(addrs.len(), 2);

        // Remove the actor record for adapter2; it leaves the connections set too.
        mgr.remove_actor_by_zpr_addr(&remove_addr).await.unwrap();

        let addrs = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert_eq!(addrs, vec!["fd5a:5052::21".parse::<IpAddr>().unwrap()]);
        assert!(
            mgr.get_actor_by_zpr_addr(&remove_addr)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_get_adapters_connected_to_node_unknown_node() {
        // Querying a node address that was never added should return an empty vec
        // (or an error, depending on the NodeRepo implementation).
        let mgr = make_mgr();
        let unknown_addr: IpAddr = "fd5a:5052::99".parse().unwrap();

        let result = mgr.get_adapters_connected_to_node(&unknown_addr).await;
        // With FakeDb this likely returns Ok(vec![]).
        // If the implementation errors on unknown nodes, adjust to unwrap_err().
        match result {
            Ok(addrs) => assert!(addrs.is_empty()),
            Err(_) => {} // Also acceptable -- unknown node is not in DB.
        }
    }

    // --- connection table / get_docking_node_for_actor tests ---

    #[tokio::test]
    async fn test_get_docking_node_for_node_actor_returns_self() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::30".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::30", "node-self", "[fd5a:5052::130]:1234");

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();

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

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr, &Default::default())
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
        mgr.hack_add_adapter_no_node(&adapter_actor, &Default::default())
            .await
            .unwrap();

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

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr, &Default::default())
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

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter1, &node_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter2, &node_addr, &Default::default())
            .await
            .unwrap();

        assert_eq!(mgr.get_docking_node_for_actor(&adapter1), Some(node_addr));
        assert_eq!(mgr.get_docking_node_for_actor(&adapter2), Some(node_addr));

        mgr.remove_node(&node_addr).await.unwrap();

        // Both adapter entries must be purged from the connection table.
        assert_eq!(mgr.get_docking_node_for_actor(&adapter1), None);
        assert_eq!(mgr.get_docking_node_for_actor(&adapter2), None);
    }

    /// zipline#138: a reconnect whose actor update fails tells the node to do a
    /// fresh connect, whose Reset teardown finds the node's docked adapters in
    /// its connected-adapters set. So the failed reconnect must leave that set
    /// intact, or the Reset finds nothing and orphans the adapters.
    #[tokio::test]
    async fn test_failed_reconnect_keeps_connected_adapters() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::3a".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::3b".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::3a", "node-reconn", "[fd5a:5052::13a]:1234");
        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052::3b", "adapter-reconn"),
            &node_addr,
            &Default::default(),
        )
        .await
        .unwrap();

        // Losing the node's actor record makes the reconnect's update fail.
        mgr.actor_db.rm_actor_by_zpr_addr(&node_addr).await.unwrap();
        assert!(
            mgr.add_node(&node_actor, true, &Default::default())
                .await
                .is_err()
        );

        assert_eq!(
            mgr.get_adapters_connected_to_node(&node_addr)
                .await
                .unwrap(),
            vec![adapter_addr],
            "a failed reconnect must not erase the node's docked adapters"
        );
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

        mgr.add_node(&node_a, false, &Default::default())
            .await
            .unwrap();
        mgr.add_node(&node_b, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_a, &node_a_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_b, &node_b_addr, &Default::default())
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

        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
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

        mgr1.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr1.add_adapter_via_node(&adapter_actor, &node_addr, &Default::default())
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

    /// Backdate a node's recorded last-seen time by writing the raw
    /// `node:<ZADDR>:lastseen` key (same key `NodeRepo` uses; a ZADDR is the
    /// IPv6 address with colons replaced by dashes), so the culling tests do
    /// not need to sleep.
    async fn backdate_last_seen(
        db: &Arc<crate::db::FakeDb>,
        addr: &IpAddr,
        age: std::time::Duration,
    ) {
        use crate::db::DbConnection;
        let ts = chrono::Utc::now() - chrono::Duration::from_std(age).unwrap();
        db.set(
            &format!("node:{}:lastseen", addr.to_string().replace(':', "-")),
            &ts.to_rfc3339(),
        )
        .await
        .unwrap();
    }

    /// refresh_state culls a node by LAST-SEEN age (zipline#119): a node last
    /// seen longer than DEFAULT_AUTH_EXPIRATION ago is reported for culling at
    /// startup even though its (non-expiring) bootstrap authentication is
    /// still valid. The record removal itself happens in [ActorMgr::finish_cull],
    /// run from the post-Assembly teardown (PR #46 review).
    #[tokio::test]
    async fn test_refresh_state_culls_node_last_seen_too_long_ago() {
        let db = Arc::new(crate::db::FakeDb::new());
        let mgr = ActorMgr::new(
            crate::db::ActorRepo::new(db.clone()),
            crate::db::NodeRepo::new(db.clone()),
            Arc::new(Counters::default()),
        );

        let node_addr: IpAddr = "fd5a:5052::46".parse().unwrap();
        // Far-future authentication expiry: under the OLD auth-expiry rule
        // this node would never be culled.
        let mut node_actor =
            make_node_actor_defexp("fd5a:5052::46", "node-stale", "[fd5a:5052::146]:1234");
        node_actor
            .add_attribute(
                libeval::attribute::Attribute::builder(libeval::attribute::key::DEVICE_AUTHORITY)
                    .expires_in(crate::config::VS_AUTH_EXPIRATION)
                    .value(libeval::attribute::key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();

        // Last seen just over the window ago.
        backdate_last_seen(
            &db,
            &node_addr,
            crate::config::DEFAULT_AUTH_EXPIRATION + Duration::from_secs(60),
        )
        .await;

        let culled = mgr.refresh_state().await.unwrap();

        assert_eq!(
            culled.iter().map(|c| c.node_addr).collect::<Vec<_>>(),
            vec![node_addr],
            "a node last seen more than DEFAULT_AUTH_EXPIRATION ago must be culled \
             regardless of its authentication expiry"
        );
        // The record removal is finish_cull's job, run from the teardown.
        mgr.finish_cull(&node_addr).await.unwrap();
        assert!(
            mgr.get_actor_by_zpr_addr(&node_addr)
                .await
                .unwrap()
                .is_none(),
            "finish_cull must remove the culled node's actor record"
        );
    }

    /// refresh_state keeps a recently-seen node — even one whose recorded
    /// authentication has already EXPIRED, which the old auth-expiry rule
    /// would have removed. Last-seen age is the only startup culling input
    /// (zipline#119).
    #[tokio::test]
    async fn test_refresh_state_keeps_recently_seen_node() {
        let db = Arc::new(crate::db::FakeDb::new());
        let mgr = ActorMgr::new(
            crate::db::ActorRepo::new(db.clone()),
            crate::db::NodeRepo::new(db.clone()),
            Arc::new(Counters::default()),
        );

        let node_addr: IpAddr = "fd5a:5052::47".parse().unwrap();
        let mut node_actor =
            make_node_actor_defexp("fd5a:5052::47", "node-recent", "[fd5a:5052::147]:1234");
        node_actor
            .add_attribute(
                libeval::attribute::Attribute::builder(libeval::attribute::key::DEVICE_AUTHORITY)
                    .expires_in(Duration::ZERO)
                    .value(libeval::attribute::key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        // add_node records "now" as last seen; leave it in place.

        mgr.refresh_state().await.unwrap();

        assert!(
            mgr.get_actor_by_zpr_addr(&node_addr)
                .await
                .unwrap()
                .is_some(),
            "a recently-seen node must survive refresh_state even with expired auth"
        );
    }

    /// A node record with NO last-seen timestamp at all is treated as stale
    /// and removed (zipline#119): it predates last-seen tracking or never
    /// carried one, and non-expiring auth would otherwise keep it forever.
    #[tokio::test]
    async fn test_refresh_state_culls_node_without_last_seen() {
        let db = Arc::new(crate::db::FakeDb::new());
        let mgr = ActorMgr::new(
            crate::db::ActorRepo::new(db.clone()),
            crate::db::NodeRepo::new(db.clone()),
            Arc::new(Counters::default()),
        );

        let node_addr: IpAddr = "fd5a:5052::48".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::48", "node-nolastseen", "[fd5a:5052::148]:1234");
        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        // Delete the last-seen key add_node just wrote.
        {
            use crate::db::DbConnection;
            db.del(&format!(
                "node:{}:lastseen",
                node_addr.to_string().replace(':', "-")
            ))
            .await
            .unwrap();
        }

        let culled = mgr.refresh_state().await.unwrap();

        assert_eq!(
            culled.iter().map(|c| c.node_addr).collect::<Vec<_>>(),
            vec![node_addr],
            "a node with no recorded last-seen time must be treated as stale"
        );
    }

    /// zipline#145: completing a stale-node cull must remove its node DB
    /// record too, not only its actor record — a surviving record means
    /// `list_node_addrs` keeps returning the ghost on every restart, and its
    /// connected-adapters set survives with it. The removal is `finish_cull`'s
    /// (the post-Assembly teardown's), not `refresh_state`'s: `refresh_state`
    /// deletes nothing so the cull stays restart-recoverable (PR #46 review).
    #[tokio::test]
    async fn test_refresh_state_stale_node_cull_removes_node_record() {
        let db = Arc::new(crate::db::FakeDb::new());
        let mgr = ActorMgr::new(
            crate::db::ActorRepo::new(db.clone()),
            crate::db::NodeRepo::new(db.clone()),
            Arc::new(Counters::default()),
        );

        let node_addr: IpAddr = "fd5a:5052::49".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::49", "node-cull", "[fd5a:5052::149]:1234");
        let adapter_a = make_adapter_actor_defexp("fd5a:5052::4a", "cull-adapter-a");
        let adapter_b = make_adapter_actor_defexp("fd5a:5052::4b", "cull-adapter-b");
        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_a, &node_addr, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(&adapter_b, &node_addr, &Default::default())
            .await
            .unwrap();

        backdate_last_seen(
            &db,
            &node_addr,
            crate::config::DEFAULT_AUTH_EXPIRATION + Duration::from_secs(60),
        )
        .await;

        let culled = mgr.refresh_state().await.unwrap();
        assert_eq!(culled.len(), 1);
        mgr.finish_cull(&node_addr).await.unwrap();

        assert!(
            !mgr.list_node_addrs().await.unwrap().contains(&node_addr),
            "a culled node must leave no node DB record: list_node_addrs must not return it"
        );
    }

    /// zipline#145: `refresh_state` runs before the `Assembly` exists, so it
    /// cannot tear the adapters down itself — it must return each culled node
    /// with the adapter addresses that were docked through it, for main to
    /// tear down right after Assembly construction.
    #[tokio::test]
    async fn test_refresh_state_returns_stale_nodes_adapters() {
        let db = Arc::new(crate::db::FakeDb::new());
        let mgr = ActorMgr::new(
            crate::db::ActorRepo::new(db.clone()),
            crate::db::NodeRepo::new(db.clone()),
            Arc::new(Counters::default()),
        );

        let node_addr: IpAddr = "fd5a:5052::4c".parse().unwrap();
        let adapter_a_addr: IpAddr = "fd5a:5052::4d".parse().unwrap();
        let adapter_b_addr: IpAddr = "fd5a:5052::4e".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::4c", "node-ret", "[fd5a:5052::14c]:1234");
        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052::4d", "ret-adapter-a"),
            &node_addr,
            &Default::default(),
        )
        .await
        .unwrap();
        mgr.add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052::4e", "ret-adapter-b"),
            &node_addr,
            &Default::default(),
        )
        .await
        .unwrap();

        backdate_last_seen(
            &db,
            &node_addr,
            crate::config::DEFAULT_AUTH_EXPIRATION + Duration::from_secs(60),
        )
        .await;

        let culled = mgr.refresh_state().await.unwrap();

        assert_eq!(culled.len(), 1, "exactly one node must be culled");
        assert_eq!(culled[0].node_addr, node_addr);
        let mut adapters = culled[0].adapter_addrs.clone();
        adapters.sort();
        assert_eq!(
            adapters,
            vec![adapter_a_addr, adapter_b_addr],
            "the culled node's docked adapters must be reported for teardown"
        );
    }

    /// PR #46 review (P1): the startup cull must be restart-recoverable.
    /// `refresh_state` runs before the `Assembly` exists, and `main` can still
    /// exit between it and `teardown_culled_nodes` (`VisaRepo::new`, API-key
    /// loading). If the node's records were already deleted at that point, the
    /// only copy of its docked-adapter addresses is the in-memory `culled`
    /// vector, and the next startup can never find the orphaned adapters. So
    /// `refresh_state` must not delete anything: a second `refresh_state` over
    /// the same DB — a restart whose predecessor died before teardown — must
    /// report the same node with the same adapters.
    #[tokio::test]
    async fn test_refresh_state_cull_is_restart_recoverable() {
        let db = Arc::new(crate::db::FakeDb::new());
        let mgr = ActorMgr::new(
            crate::db::ActorRepo::new(db.clone()),
            crate::db::NodeRepo::new(db.clone()),
            Arc::new(Counters::default()),
        );

        let node_addr: IpAddr = "fd5a:5052::4f".parse().unwrap();
        let adapter_a_addr: IpAddr = "fd5a:5052::50".parse().unwrap();
        let adapter_b_addr: IpAddr = "fd5a:5052::51".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::4f", "node-recover", "[fd5a:5052::14f]:1234");
        mgr.add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        mgr.add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052::50", "recover-adapter-a"),
            &node_addr,
            &Default::default(),
        )
        .await
        .unwrap();
        mgr.add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052::51", "recover-adapter-b"),
            &node_addr,
            &Default::default(),
        )
        .await
        .unwrap();

        backdate_last_seen(
            &db,
            &node_addr,
            crate::config::DEFAULT_AUTH_EXPIRATION + Duration::from_secs(60),
        )
        .await;

        let culled1 = mgr.refresh_state().await.unwrap();
        assert_eq!(culled1.len(), 1);
        assert_eq!(culled1[0].node_addr, node_addr);

        // Crash before teardown_culled_nodes: nothing else runs. A restart is
        // a fresh manager over the same DB.
        let mgr2 = ActorMgr::new(
            crate::db::ActorRepo::new(db.clone()),
            crate::db::NodeRepo::new(db.clone()),
            Arc::new(Counters::default()),
        );
        let culled2 = mgr2.refresh_state().await.unwrap();

        assert_eq!(
            culled2.len(),
            1,
            "a culled node whose teardown never ran must be re-culled on the next startup"
        );
        assert_eq!(culled2[0].node_addr, node_addr);
        let mut adapters = culled2[0].adapter_addrs.clone();
        adapters.sort();
        assert_eq!(
            adapters,
            vec![adapter_a_addr, adapter_b_addr],
            "the re-culled node must still name its docked adapters — deleting the \
             connected-adapters set before teardown makes the orphans unfindable"
        );
    }
}
