//! Topology manager - maintains the graph of nodes and links, and provides pathfinding and route selection.
//! Note that this topology as it exists. For toplogy as it is intended to be you need to look at policy.
use std::net::IpAddr;
use tracing::{error, warn};

use crate::actor_mgr::ActorMgr;
use crate::error::{ServiceError, TopologyError};
use crate::logging::targets::TOPO;
use crate::policy_mgr::PolicyMgr;
use crate::router::Router;

use libeval::actor::Actor;
use libeval::attribute::{AttrMatch, Attribute};
use libeval::eval_route::{RouteHint, TopologyQueryApi};
use libeval::route::{LinkId, NodeId, Route};

pub struct TopologyMgr {
    router: Router,
}

impl TopologyMgr {
    pub fn new() -> Self {
        Self {
            router: Router::new(),
        }
    }

    /// Add a linked node to the graph.
    /// Also adds the node via the actor_manager if it is not already in the graph.
    ///
    /// TODO: not yet integrated with state!
    /// See https://github.com/org-zpr/zpr-visaservice/issues/209
    pub async fn add_linked_node(
        &self,
        policy_mgr: &PolicyMgr,
        actor_mgr: &ActorMgr,
        actor: &Actor,
        connect_via: &IpAddr,
        new_node_addr: &IpAddr,
    ) -> Result<(), ServiceError> {
        let link_desc = policy_mgr.describe_link(connect_via, new_node_addr)?;

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
        let peer_node_addrs = self.router.get_peers(new_node_addr);
        let preexisting_node = self.router.has_node(new_node_addr);

        // If the new node has peers and one is the 'connect_via' .... uh, that's odd.  Error out?
        // If the new node has peers and none are the 'connect_via', then we already know about
        //    this node, but it is just forming a new link.
        // If the new node has no peers then it is not yet in our system.

        if !preexisting_node {
            // Brand new node. Add to router, add to actor_mgr.
            self.router.add_node(new_node_addr.clone())?;
            if let Err(e) = actor_mgr.add_node(actor, false).await {
                warn!(target: TOPO, "failed to add node to actor_mgr: {}", e);
                self.router.remove_node(new_node_addr);
                return Err(e.into());
            };
        } else if peer_node_addrs.contains(connect_via) {
            // TODO: This might happen during a reconnect or a re-auth.
            warn!(target: TOPO, "try_add_node but node at addr {} is already connected to us via {}: FINE!", new_node_addr, connect_via);
            return Ok(()); // Assume everything is just fine!
        }

        if let Err(e) = self.router.add_link(
            connect_via.clone(),
            new_node_addr.clone(),
            link_desc.link_id.into(),
            link_desc.attrs,
            link_desc.cost,
        ) {
            if !matches!(e, TopologyError::LinkExists(_)) {
                error!(target: TOPO, "failed to add link from {} to {}: {}", connect_via, new_node_addr, e);
                if !preexisting_node {
                    self.router.remove_node(new_node_addr);
                    actor_mgr.remove_node(new_node_addr).await?;
                }
                return Err(e.into());
            }
        }

        Ok(())
    }

    pub fn add_node(&self, addr: IpAddr) -> Result<(), TopologyError> {
        self.router.add_node(addr)
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

    pub fn remove_node(&self, addr: &IpAddr) {
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
