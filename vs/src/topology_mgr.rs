//! Topology manager - maintains the graph of nodes and links, and provides pathfinding and route selection.
//! Note that this is topology as it exists. For toplogy as it is intended to be, you need to look at policy.
//!
//! The in-memory graph lives in [Router]. This manager owns a [LinkRepo] and is the
//! write-through point that persists the node-link adjacency to state so the graph can
//! be rebuilt on restart (see [TopologyMgr::restore_from_state]). Nodes themselves are
//! persisted by `ActorMgr`/`NodeRepo`; only the edges (links) are persisted here.
//!
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{debug, error, info, warn};

use crate::actor_mgr::ActorMgr;
use crate::db::LinkRepo;
use crate::error::{ServiceError, TopologyError};
use crate::logging::targets::TOPO;
use crate::policy_mgr::{LinkDescription, PolicyMgr};
use crate::router::Router;

use libeval::actor::Actor;
use libeval::attribute::{AttrMatch, Attribute};
use libeval::eval_route::{RouteHint, TopologyQueryApi};
use libeval::route::{LinkId, NodeId, Route};

pub struct TopologyMgr {
    router: Router,
    link_repo: LinkRepo,
}

/// Special error returned by [TopologyMgr::add_linked_node] that records
/// whether the failing call created the node. Callers (e.g.
/// `authorize_connect`) use this to decide whether to release the actor's
/// freshly allocated address: a pre-existing node's address is still live and
/// must not be released.
#[derive(Debug, thiserror::Error)]
pub enum AddLinkedNodeError {
    /// Failure while creating/persisting a brand-new node. The freshly allocated
    /// address is owned by this attempt and the caller should release it.
    #[error("new node failed: {0}")]
    NewNodeFailed(ServiceError),
    /// Failure while updating/repairing state for a node that already existed. The
    /// node and its address remain live; the caller must NOT release the address.
    #[error("existing node failed: {0}")]
    ExistingNodeFailed(ServiceError),
}

impl AddLinkedNodeError {
    /// Creates correct enum based on `preexisting` flag.
    pub fn new(preexisting: bool, e: ServiceError) -> Self {
        if preexisting {
            AddLinkedNodeError::ExistingNodeFailed(e)
        } else {
            AddLinkedNodeError::NewNodeFailed(e)
        }
    }
}

impl TopologyMgr {
    pub fn new(link_repo: LinkRepo) -> Self {
        Self {
            router: Router::new(),
            link_repo,
        }
    }

    /// Install a link into the in-memory router from a [LinkDescription], without
    /// persisting it. Used by both `add_linked_node` (which persists separately) and
    /// `restore_from_state` (which must not re-persist). The router error is returned
    /// unchanged so callers can decide how to treat [TopologyError::LinkExists].
    fn install_router_link(
        &self,
        a: &IpAddr,
        b: &IpAddr,
        link_desc: LinkDescription,
    ) -> Result<(), TopologyError> {
        self.router.add_link(
            a.clone(),
            b.clone(),
            link_desc.link_id.into(),
            link_desc.attrs,
            link_desc.cost,
        )
    }

    /// Persist an edge to state. Called only from public write-through mutation paths.
    async fn persist_edge(&self, a: &IpAddr, b: &IpAddr) -> Result<(), ServiceError> {
        self.link_repo.add_edge(a, b).await?;
        Ok(())
    }

    /// Roll back a node a call had just created. Used by the undo
    /// paths. Failures are logged rather than propagated so they do not mask the original
    /// error that triggered the rollback.
    async fn rollback_created_node(&self, actor_mgr: &ActorMgr, addr: &IpAddr) {
        // Removing the router node also drops its incident links.
        self.router.remove_node(addr);
        if let Err(re) = actor_mgr.remove_node(addr).await {
            warn!(target: TOPO, "rollback: failed to remove node {} state from actor_mgr: {}", addr, re);
        }
        if let Err(re) = actor_mgr.remove_actor_by_zpr_addr(addr).await {
            warn!(target: TOPO, "rollback: failed to remove actor record for {} from actor_mgr: {}", addr, re);
        }
    }

    /// Add a linked node to the graph.
    /// Also adds the node via the actor_manager if it is not already in the graph.
    ///
    /// On success the node-link edge is persisted to state. If persistence fails the
    /// partial in-memory/actor state created here is rolled back before returning the
    /// error, so we never report failure while leaving a router edge behind.
    pub async fn add_linked_node(
        &self,
        policy_mgr: &PolicyMgr,
        actor_mgr: &ActorMgr,
        actor: &Actor,
        connect_via: &IpAddr,
        new_node_addr: &IpAddr,
    ) -> Result<(), AddLinkedNodeError> {
        // I think we need to add the node.
        // But I'm not sure that the actor-mgr needs to know about links.
        // It does know about tethers.  So maybe is should?  But the router has the
        // actual graph. So maybe we add redis backing to the router???
        //
        // Is this node already in our graph over another link?
        //
        // QUESTION - how to tell if this node is just making a link or if it is reconnecting and we need to restore state?
        //
        // If a node is already connected to ZPR why does it need to authenticate again?
        // Well, it may not be allowed to make the link for one thing.
        //
        // Computed before describe_link so even an early policy failure is classified
        // (new vs pre-existing node) for the caller's address-release decision.
        let peer_node_addrs = self.router.get_peers(new_node_addr);
        let preexisting_node = self.router.has_node(new_node_addr);

        let link_desc = match policy_mgr.describe_link(connect_via, new_node_addr) {
            Ok(d) => d,
            Err(e) => return Err(AddLinkedNodeError::new(preexisting_node, e)),
        };
        // Kept for rollback: install_router_link consumes link_desc.
        let link_id_for_rollback = link_desc.link_id.clone();

        // If the new node has peers and one is the 'connect_via' .... uh, that's odd.  Error out?
        // If the new node has peers and none are the 'connect_via', then we already know about
        //    this node, but it is just forming a new link.
        // If the new node has no peers then it is not yet in our system.

        if !preexisting_node {
            // Brand new node. Add to router, add to actor_mgr.
            if let Err(e) = self.router.add_node(new_node_addr.clone()) {
                return Err(AddLinkedNodeError::NewNodeFailed(e.into()));
            }
            if let Err(e) = actor_mgr.add_node(actor, false).await {
                warn!(target: TOPO, "failed to add node to actor_mgr: {}", e);
                self.router.remove_node(new_node_addr);
                return Err(AddLinkedNodeError::NewNodeFailed(e.into()));
            };
        } else if peer_node_addrs.contains(connect_via) {
            // Already connected over this same link (e.g. a reconnect or re-auth).
            // Persist the edge before returning, to repair the case where the router
            // has the edge but Redis missed it.
            debug!(target: TOPO, "try_add_node but node at addr {} is already connected to us via {}: FINE!", new_node_addr, connect_via);
            if let Err(e) = self.persist_edge(connect_via, new_node_addr).await {
                warn!(target: TOPO, "failed to persist already-connected edge {} <-> {}: {}", connect_via, new_node_addr, e);
                // Pre-existing node: its address is still live, so this is not a
                // new-node failure.
                return Err(AddLinkedNodeError::ExistingNodeFailed(e));
            }
            return Ok(()); // Assume everything is just fine!
        }

        // Add the link to the router. LinkExists is tolerated (repair / re-auth): in
        // that case we did NOT add a link, so the rollback below must not remove it.
        let mut added_new_link = false;
        match self.install_router_link(connect_via, new_node_addr, link_desc) {
            Ok(()) => added_new_link = true,
            Err(TopologyError::LinkExists(_)) => {}
            Err(e) => {
                error!(target: TOPO, "failed to add link from {} to {}: {}", connect_via, new_node_addr, e);
                if !preexisting_node {
                    self.rollback_created_node(actor_mgr, new_node_addr).await;
                }
                return Err(AddLinkedNodeError::new(preexisting_node, e.into()));
            }
        }

        // Write-through: persist the edge. On failure, clean up the partial state we
        // created here, but return the ORIGINAL persistence error — the rollback calls
        // log their own failures.
        if let Err(e) = self.persist_edge(connect_via, new_node_addr).await {
            error!(target: TOPO, "failed to persist edge {} <-> {}: {}", connect_via, new_node_addr, e);
            if !preexisting_node {
                // We created the node; rolling it back also drops the incident link.
                self.rollback_created_node(actor_mgr, new_node_addr).await;
            } else if added_new_link {
                // Node pre-existed; remove only the link we just added.
                self.router.remove_link(&link_id_for_rollback.into());
            }
            return Err(AddLinkedNodeError::new(preexisting_node, e));
        }

        Ok(())
    }

    /// Rebuild the router graph from persisted state. Nodes come from `node_addrs`
    /// (the surviving node set after actor-state refresh); edges come from the
    /// [LinkRepo]. Edge attributes/cost are re-derived from the current policy.
    ///
    /// Stale-edge safety: an edge is only recreated when both endpoints survived the
    /// node-state refresh AND the current policy still describes that exact link.
    /// Otherwise the persisted edge is garbage-collected. Even if an address is reused,
    /// this never resurrects an edge the policy no longer describes.
    ///
    /// "Load state completely or fail": any error other than the precise
    /// link-not-found-in-policy case is propagated, so a transient policy/DB problem at
    /// startup fails the service rather than silently deleting valid persisted edges.
    pub async fn restore_from_state(
        &self,
        policy_mgr: &PolicyMgr,
        node_addrs: &[IpAddr],
    ) -> Result<(), ServiceError> {
        // In this code path there should be no cases for errors from add_node.
        for addr in node_addrs {
            self.router.add_node(addr.clone())?;
        }

        let known: HashSet<IpAddr> = node_addrs.iter().copied().collect();

        for (a, b) in self.link_repo.list_edges().await? {
            // GC edges whose endpoints are no longer known nodes.
            if !known.contains(&a) || !known.contains(&b) {
                info!(target: TOPO, "restore: GC stale edge {} <-> {} (endpoint no longer a known node)", a, b);
                if let Err(e) = self.link_repo.remove_edge(&a, &b).await {
                    warn!(target: TOPO, "restore: failed to GC stale edge {} <-> {}: {}", a, b, e);
                }
                continue;
            }

            // Edges are stored undirected, so try describing the link in either
            // direction before concluding the policy no longer describes it.
            match Self::describe_policy_link_either(policy_mgr, &a, &b) {
                Ok(link_desc) => match self.install_router_link(&a, &b, link_desc) {
                    Ok(()) | Err(TopologyError::LinkExists(_)) => {}
                    Err(e) => return Err(e.into()),
                },
                // Policy no longer describes this link in either direction: GC it.
                Err(ServiceError::Topology(TopologyError::LinkNotFound(_))) => {
                    info!(target: TOPO, "restore: GC stale edge {} <-> {} (policy no longer describes link)", a, b);
                    if let Err(e) = self.link_repo.remove_edge(&a, &b).await {
                        warn!(target: TOPO, "restore: failed to GC stale edge {} <-> {}: {}", a, b, e);
                    }
                }
                // Any other error (policy not loaded, resolver failure, etc.) must NOT
                // GC the edge: fail startup instead of silently deleting valid edges.
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Describe a link defined in policy in either direction. Edges are stored undirected, so a stored
    /// `(a, b)` may correspond to a policy peering recorded as `b -> a`. Returns
    /// `LinkNotFound` only when neither direction matches; any other error from the
    /// first lookup is returned as-is.
    fn describe_policy_link_either(
        policy_mgr: &PolicyMgr,
        a: &IpAddr,
        b: &IpAddr,
    ) -> Result<LinkDescription, ServiceError> {
        match policy_mgr.describe_link(a, b) {
            Err(ServiceError::Topology(TopologyError::LinkNotFound(_))) => {
                policy_mgr.describe_link(b, a)
            }
            other => other,
        }
    }

    /// Add a node to the router without disturbing links or persisted edges.
    /// This calls [Router::add_node].
    ///
    /// Retruns an error if the node already exists.
    #[allow(dead_code)]
    pub fn add_node(&self, addr: IpAddr) -> Result<(), TopologyError> {
        self.router.add_node(addr)
    }

    /// Add a node to the router without disturbing links or persisted edges.
    /// This calls [Router::add_node].
    ///
    /// Returns true if node was added. If node already exists, you get `false` back instead.
    pub fn add_node_if_not_exists(&self, addr: IpAddr) -> bool {
        match self.router.add_node(addr) {
            Ok(()) => true,
            Err(TopologyError::NodeExists(_)) => false,
            Err(e) => unreachable!("unexpected error adding node to router: {}", e),
        }
    }

    #[allow(dead_code)]
    pub fn add_link(
        &self,
        zpr_addr_a: IpAddr,
        zpr_addr_b: IpAddr,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), TopologyError> {
        self.router
            .add_link(zpr_addr_a, zpr_addr_b, id, attributes, cost)
    }

    /// Remove a node and all its incident links from the router, and best-effort
    /// delete the corresponding persisted edges.
    ///
    /// Persisted-edge removal is read-then-delete: incident peers are read *before*
    /// the router removal so we know which edges to delete. Failures are logged but do
    /// not abort the removal — this is a deliberate eventual-cleanup model: a stale
    /// persisted edge may survive a DB failure, but `restore_from_state` validates
    /// every persisted edge against the surviving node set and current policy before
    /// recreating anything, so stale edges never resurrect a real link.
    pub async fn remove_node(&self, addr: &IpAddr) {
        let peers = self.router.get_peers(addr);
        for peer in &peers {
            if let Err(e) = self.link_repo.remove_edge(addr, peer).await {
                warn!(target: TOPO, "failed to remove persisted edge {} <-> {} on node removal: {}", addr, peer, e);
            }
        }
        self.router.remove_node(addr)
    }

    /// Find optimal route between the nodes.
    /// Note that `a` and `b` must be node addresses.
    pub fn get_best_route(&self, a: &IpAddr, b: &IpAddr) -> Option<Route> {
        self.router.get_best_route(a, b)
    }

    /// Find all routes between the nodes.
    /// Note that `a` and `b` must be node addresses.
    pub fn get_routes(&self, a: &IpAddr, b: &IpAddr, hint: Option<&RouteHint>) -> Vec<Route> {
        self.router.get_routes(a, b, hint)
    }

    pub fn route_to_path(
        &self,
        route: &Route,
        starting: &NodeId,
    ) -> Result<Vec<NodeId>, TopologyError> {
        self.router.route_to_path(route, starting)
    }

    pub fn get_peers(&self, zpr_addr: &IpAddr) -> Vec<IpAddr> {
        self.router.get_peers(zpr_addr)
    }
}

impl TopologyQueryApi for TopologyMgr {
    /// TODO: We do not yet support policy on link attributes and [AttrMatch] is not yet defined. This alwayes returns false.
    fn link_has_attr(&self, _link_id: &LinkId, _attr: &AttrMatch) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use zpr::policy::v1 as policy_capnp;
    use zpr::policy_types::{NetAddr, Peering};
    use zpr::write_to::WriteTo;

    use crate::config;
    use crate::counters::Counters;
    use crate::db::{ActorRepo, DbConnection, FakeDb, LinkRepo, NodeRepo, PolicyRepo};
    use crate::test_helpers::{FakeResolver, make_container_bytes, make_node_actor_defexp};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a Policy containing a single peering between `node_a` and `node_b`.
    /// Substrate addresses use the node IPs with port 0 so the IP-only resolver works.
    fn policy_with_link(node_a: IpAddr, node_b: IpAddr, link_id: &str) -> Vec<u8> {
        let peering = Peering {
            link_id: link_id.to_string(),
            node_a,
            substrate_a: NetAddr::new_for_ip_or_host(&node_a.to_string(), 0),
            node_b,
            substrate_b: NetAddr::new_for_ip_or_host(&node_b.to_string(), 0),
            attributes: vec![],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
            policy.reborrow().set_created("1970-01-01T00:00:00Z");
            let mut topo = policy.reborrow().init_topology(1);
            peering.write_to(&mut topo.reborrow().get(0));
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        // Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap()
        bytes
    }

    /// Create a PolicyMgr over the given db preloaded with a single-link policy.
    async fn make_policy_mgr(db: Arc<FakeDb>, a: IpAddr, b: IpAddr, link_id: &str) -> PolicyMgr {
        let pol_bytes = policy_with_link(a, b, link_id);

        let repo = PolicyRepo::new(db);
        PolicyMgr::new_with_initial_policy(
            make_container_bytes(
                config::POLICY_MIN_COMPILER_MAJOR,
                config::POLICY_MIN_COMPILER_MINOR,
                config::POLICY_MIN_COMPILER_PATCH,
                &pol_bytes,
            ),
            repo,
            Arc::new(FakeResolver::ip_only()),
        )
        .await
        .unwrap()
    }

    /// Build an ActorMgr over the given db.
    fn make_actor_mgr(db: Arc<FakeDb>) -> ActorMgr {
        ActorMgr::new(
            ActorRepo::new(db.clone()),
            NodeRepo::new(db),
            Arc::new(Counters::default()),
        )
    }

    /// add_linked_node persists the node-link edge to state.
    #[tokio::test]
    async fn test_add_linked_node_persists_edge() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // connect_via node `a` must already exist in the router.
        topo.add_node(a).unwrap();
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");

        topo.add_linked_node(&policy_mgr, &actor_mgr, &actor_b, &a, &b)
            .await
            .unwrap();

        let edges = LinkRepo::new(db).list_edges().await.unwrap();
        assert_eq!(edges.len(), 1);
        let (ea, eb) = edges[0];
        assert!((ea == a && eb == b) || (ea == b && eb == a));
    }

    /// The already-connected (existing router link) path repairs a missing persisted edge.
    #[tokio::test]
    async fn test_add_linked_node_repairs_missing_persisted_edge() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // Pre-create both nodes and the router link directly, WITHOUT persisting an edge.
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();
        assert!(
            LinkRepo::new(db.clone())
                .list_edges()
                .await
                .unwrap()
                .is_empty()
        );

        // Re-adding the same link hits the already-connected path and repairs Redis.
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");
        topo.add_linked_node(&policy_mgr, &actor_mgr, &actor_b, &a, &b)
            .await
            .unwrap();

        let edges = LinkRepo::new(db).list_edges().await.unwrap();
        assert_eq!(edges.len(), 1);
    }

    /// A persistence failure compensates the partial router/actor state and returns Err.
    #[tokio::test]
    async fn test_add_linked_node_compensates_on_persist_failure() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.add_node(a).unwrap();
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");

        // Poison the edges key so sadd (and thus add_edge) fails with a type error.
        db.set("topology:edges", "junk").await.unwrap();

        let result = topo
            .add_linked_node(&policy_mgr, &actor_mgr, &actor_b, &a, &b)
            .await;
        // A brand-new node's failure must be reported as a new-node failure so the
        // caller releases the freshly allocated address.
        assert!(
            matches!(result, Err(AddLinkedNodeError::NewNodeFailed(_))),
            "new-node persist failure must be a NewNodeFailed error, got {:?}",
            result
        );

        // Compensation removed node `b` from the router (it can be re-added cleanly)...
        assert!(
            topo.add_node(b).is_ok(),
            "node b should have been removed from the router by compensation"
        );
        // ...and from the actor manager.
        assert!(
            actor_mgr.get_actor_by_zpr_addr(&b).await.unwrap().is_none(),
            "node b should have been removed from the actor manager by compensation"
        );
    }

    /// A persist failure while repairing a PRE-EXISTING node's edge is reported as an
    /// existing-node failure and leaves the live node in place.
    #[tokio::test]
    async fn test_add_linked_node_preexisting_failure_is_existing_node_error() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // Pre-create both nodes and the router link so `b` is already connected over `a`
        // (the already-connected edge-repair path).
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();

        // Poison the edges key so the repair persist fails.
        db.set("topology:edges", "junk").await.unwrap();

        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");
        let result = topo
            .add_linked_node(&policy_mgr, &actor_mgr, &actor_b, &a, &b)
            .await;

        assert!(
            matches!(result, Err(AddLinkedNodeError::ExistingNodeFailed(_))),
            "pre-existing node persist failure must be an ExistingNodeFailed error, got {:?}",
            result
        );
        // The live node must not have been removed by the failed call.
        assert!(
            topo.add_node(b).is_err(),
            "pre-existing node b must remain in the router after an existing-node failure"
        );
    }

    /// remove_node deletes the persisted incident edges.
    #[tokio::test]
    async fn test_remove_node_deletes_incident_edges() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.add_node(a).unwrap();
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");
        topo.add_linked_node(&policy_mgr, &actor_mgr, &actor_b, &a, &b)
            .await
            .unwrap();
        assert_eq!(
            LinkRepo::new(db.clone()).list_edges().await.unwrap().len(),
            1
        );

        topo.remove_node(&b).await;

        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "incident edge should be removed from state"
        );
    }

    /// restore_from_state rebuilds the router graph from persisted edges + policy.
    #[tokio::test]
    async fn test_restore_rebuilds_graph_from_edges() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;

        // Persist an edge directly, then restore into a fresh (empty) topology.
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.restore_from_state(&policy_mgr, &[a, b]).await.unwrap();

        // The link is back: a and b are peers and a route exists.
        assert_eq!(topo.get_peers(&a), vec![b]);
        assert!(topo.get_best_route(&a, &b).is_some());
    }

    /// add_node_if_not_exists preserves restored in-memory links and persisted edges on reconnect.
    #[tokio::test]
    async fn test_add_node_if_not_exists_preserves_restored_links_on_reconnect() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;

        // Persist an edge directly, then restore into a fresh topology to simulate restart.
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.restore_from_state(&policy_mgr, &[a, b]).await.unwrap();
        assert_eq!(topo.get_peers(&a), vec![b], "precondition: link restored");

        let added = topo.add_node_if_not_exists(b);

        assert!(!added, "node was already present from restore");
        assert_eq!(
            topo.get_peers(&a),
            vec![b],
            "restored in-memory link must survive reconnect"
        );
        assert_eq!(
            LinkRepo::new(db).list_edges().await.unwrap().len(),
            1,
            "persisted edge must survive reconnect"
        );
    }

    /// A persisted edge the current policy no longer describes is skipped and GC'd.
    #[tokio::test]
    async fn test_restore_gcs_stale_edge_not_in_policy() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let c = ip("fd5a:5052::3");
        // Policy only describes a<->b; the persisted edge a<->c is stale.
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &c).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.restore_from_state(&policy_mgr, &[a, c]).await.unwrap();

        assert!(
            topo.get_peers(&a).is_empty(),
            "stale edge must not be installed"
        );
        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "stale edge must be garbage-collected"
        );
    }

    /// A persisted edge whose endpoint is no longer a known node is GC'd on restore.
    #[tokio::test]
    async fn test_restore_gcs_edge_with_unknown_endpoint() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // Only `a` survived node-state refresh; `b` is gone.
        topo.restore_from_state(&policy_mgr, &[a]).await.unwrap();

        assert!(topo.get_peers(&a).is_empty());
        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "edge with a missing endpoint must be garbage-collected"
        );
    }

    /// Restoring from an empty surviving-node set intentionally GCs every persisted edge.
    /// With no known nodes, no persisted topology links or routes can remain valid.
    #[tokio::test]
    async fn test_restore_with_empty_node_set_gcs_all_edges() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.restore_from_state(&policy_mgr, &[]).await.unwrap();

        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "with no surviving nodes every edge is GC'd"
        );
    }
}
