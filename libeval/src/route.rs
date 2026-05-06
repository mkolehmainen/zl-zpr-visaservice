use serde::Serialize;
use std::net::IpAddr;

use crate::attribute::AttrMatch;

// Answers the question: "Is this route allowed?".
// Note these are extracted from policy duing first pass and attached to hits.
//
// TODO: Investigate why we really need Serialize on this. Is it for ZPT?
#[derive(Debug, Serialize)]
pub enum RoutePredicate {
    True,
    DirectOnly,
    RequireLinkedPath,
    AnyLinkHas(AttrMatch),
    NoLinkHas(AttrMatch),
    AllLinksHave(AttrMatch),
    And(Vec<RoutePredicate>),
    Or(Vec<RoutePredicate>),
}

/// A route is an ordered sequence of links between nodes.
#[derive(Debug, Serialize, Clone)]
pub struct Route {
    pub kind: RouteKind,
    pub links: Vec<LinkId>,
    /// Sum of the individual link costs.
    pub cost: u32,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub String);

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct LinkId(pub String);

#[derive(Debug, Serialize, Clone)]
pub enum RouteKind {
    /// Not even a route - adapaters are connected to the same node.
    DirectSameNode {
        node_id: NodeId,
    },
    Multihop,
}

impl From<IpAddr> for NodeId {
    fn from(addr: IpAddr) -> Self {
        NodeId(addr.to_string())
    }
}

impl From<&IpAddr> for NodeId {
    fn from(addr: &IpAddr) -> Self {
        NodeId(addr.to_string())
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId(s.to_string())
    }
}

impl From<&str> for LinkId {
    fn from(s: &str) -> Self {
        LinkId(s.to_string())
    }
}

impl Route {
    /// True if no links need to be traversed (hop count of zero).
    pub fn is_direct(&self) -> bool {
        matches!(self.kind, RouteKind::DirectSameNode { .. })
    }

    pub fn hop_count(&self) -> usize {
        self.links.len()
    }
}
