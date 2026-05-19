//! The policy manage is conceived as the one true place where the running visa service
//! can obtain the current policy.  Policy can be updated asynchronously by administrators.
//! A policy update can have many ripple effects on the running visa serivce: visas may no
//! longer be valid, connected actors may be forced to disconnect, services may be taken
//! down, node connections may change etc.
//!
//! The idea here is that clients of the policy will request it with [PolicyMgr::get_current]
//! use it as quickly as possible and then drop it.  In the case of a policy update there
//! should be few processes holding on to an old policy for long.
//!
//! The [libeval::policy::Policy] is designed to be easily cloned (as it is in an Arc) and
//! accessible by concurrent threads.

use arc_swap::ArcSwap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info};

use libeval::attribute::Attribute;
use libeval::policy::Policy;

use crate::db;
use crate::error::{ServiceError, StoreError, TopologyError};
use crate::logging::targets::MAIN;

// TODO: move to libeval::attribute::key
const LINK_COST_ATTR_KEY: &str = "link.zpr.cost";

/// The default and the minimum.
const DEFAULT_LINK_COST: u32 = 1;

#[allow(dead_code)]
pub struct PolicyMgr {
    inner: ArcSwap<Policy>,
    repo: db::PolicyRepo,
}

#[derive(Debug, Clone)]
pub struct LinkDescription {
    pub link_id: String,
    pub attrs: Vec<Attribute>,
    pub cost: u32,
}

impl PolicyMgr {
    /// Create a new policy manager, initializing it with the given initial policy.
    /// This will store the initial policy into the database if not already present.
    ///
    /// Note that policy is written to DB for backup purposes. It is kept in memory
    /// here for general access by rest of visa service.
    pub async fn new_with_initial_policy(
        mut policy: Policy,
        repo: db::PolicyRepo,
    ) -> Result<Self, StoreError> {
        debug!(target: MAIN, "initializing policy manager");
        policy.set_vinst(1);

        let _db_updated = repo.set_current_policy(&policy, false).await?;

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(PolicyMgr {
            inner: ArcSwap::from_pointee(policy),
            repo,
        })
    }

    /// Create a new policy manager, initializing it with the current policy in the database. If there is no
    /// policy in the database, this will return an error.
    pub async fn new_from_state(repo: db::PolicyRepo) -> Result<Self, StoreError> {
        debug!(target: MAIN, "initializing policy manager from state");
        let policy = repo.get_current_policy().await?;
        info!(target: MAIN, "loaded policy from state version:{}, created:{}", policy.get_version().unwrap_or(0),
            policy.get_created().unwrap_or("unknown").to_string());
        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(PolicyMgr {
            inner: ArcSwap::from_pointee(policy),
            repo,
        })
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    pub fn get_current(&self) -> Arc<Policy> {
        self.inner.load_full()
    }

    /// Update the current policy.  The new policy will be assigned a new version instance number (vinst)
    /// that is one greater than the current policy's vinst.
    ///
    /// TODO: There is a lot of housekeeping that needs to happen around a policy update. None of that
    /// is implemented here. Right now this is just to support unit tests.
    #[allow(dead_code)]
    pub fn update_policy(&self, new_policy: Policy) -> Result<(), StoreError> {
        let mut np = Arc::new(new_policy);
        self.inner.rcu(move |op| {
            Arc::get_mut(&mut np).unwrap().set_vinst(op.vinst() + 1);
            np.clone()
        });
        Ok(())
    }

    /// Consult policy to get a description of the link between `node_a` and `node_b`.
    /// Both arguments are ZPR addresses.
    ///
    /// ## Errors
    /// - `TopologyError::LinkNotFound` if there is no link between `node_a` and `node_b` in the policy.
    pub fn describe_link(
        &self,
        node_a: &IpAddr,
        node_b: &IpAddr,
    ) -> Result<LinkDescription, ServiceError> {
        let policy = self.get_current();
        if let Some(peers) = policy.get_peers_for_node(node_a) {
            for peer in peers {
                if &peer.remote_zpr_addr == node_b {
                    let attrs = get_attributes_for_link(&policy, &peer.link_id);
                    let cost = if !attrs.is_empty() {
                        get_link_cost(&attrs, DEFAULT_LINK_COST)
                    } else {
                        DEFAULT_LINK_COST
                    };
                    return Ok(LinkDescription {
                        link_id: peer.link_id.clone(),
                        attrs,
                        cost,
                    });
                }
            }
        }
        Err(TopologyError::LinkNotFound(format!("{node_a} <-> {node_b}")).into())
    }
}

/// Given policy and a link_id, return the libeval-style Attributes for that link.
/// If there are no attributes, return an empty vec.
fn get_attributes_for_link(policy: &Policy, link_id: &str) -> Vec<Attribute> {
    if let Some(attr_exps) = policy.get_link_attrs(link_id) {
        attr_exps
            .iter()
            .map(|ae| Attribute::builder(ae.key.clone()).values(ae.value.clone()))
            .collect()
    } else {
        Vec::new()
    }
}

/// Use the special 'zpr.link.cost' attribute to obtain a numeric cost.
/// Return `default_cost` if there is no cost attribute or if we cannot cooerce it into a number.
///
/// TODO: Better to do this in the compiler and then just have an integer cost value as part of the
/// bin2 representation.
fn get_link_cost(attrs: &[Attribute], default_cost: u32) -> u32 {
    for attr in attrs {
        if attr.get_key() == LINK_COST_ATTR_KEY {
            let value = attr
                .get_single_value()
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(default_cost as i32);
            return if value > 0 {
                value as u32
            } else {
                default_cost
            };
        }
    }
    // Default cost if not specified or if parsing fails.
    default_cost
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use std::sync::Arc;
    use zpr::policy::v1 as policy_capnp;
    use zpr::policy_types::{AttrExp, AttrOp, NetAddr, Peering};
    use zpr::write_to::WriteTo;

    use crate::db::{FakeDb, PolicyRepo};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a minimal valid Policy with no topology.
    fn policy_no_topology() -> Policy {
        policy_with_peerings(&[])
    }

    /// Build a Policy containing the given peerings by encoding a capnp message in memory.
    fn policy_with_peerings(peerings: &[Peering]) -> Policy {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
            policy.reborrow().set_created("1970-01-01T00:00:00Z");
            if !peerings.is_empty() {
                let mut topo = policy.reborrow().init_topology(peerings.len() as u32);
                for (i, p) in peerings.iter().enumerate() {
                    p.write_to(&mut topo.reborrow().get(i as u32));
                }
            }
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap()
    }

    /// Create a PolicyMgr backed by a FakeDb with the given policy loaded.
    async fn make_policy_mgr(policy: Policy) -> PolicyMgr {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        PolicyMgr::new_with_initial_policy(policy, repo)
            .await
            .unwrap()
    }

    /// Build a Peering between two ZPR addresses. describe_link(node_a, node_b) will find it.
    fn make_peering(node_a: IpAddr, node_b: IpAddr, link_id: &str, attrs: Vec<AttrExp>) -> Peering {
        Peering {
            link_id: link_id.to_string(),
            node_a,
            substrate_a: NetAddr::new_for_ip_or_host(&node_a.to_string(), 0),
            node_b,
            substrate_b: NetAddr::new_for_ip_or_host(&node_b.to_string(), 0),
            attributes: attrs,
        }
    }

    #[tokio::test]
    /// describe_link returns LinkNotFound when the policy has no topology.
    async fn test_describe_link_no_topology() {
        let mgr = make_policy_mgr(policy_no_topology()).await;
        let result = mgr.describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"));
        assert!(matches!(
            result,
            Err(ServiceError::Topology(TopologyError::LinkNotFound(_)))
        ));
    }

    #[tokio::test]
    /// describe_link returns LinkNotFound when node_a has no peers in the topology.
    async fn test_describe_link_node_a_not_in_topology() {
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        let mgr = make_policy_mgr(policy_with_peerings(&[peering])).await;
        let result = mgr.describe_link(&ip("fd5a:5052::99"), &ip("fd5a:5052::2"));
        assert!(matches!(
            result,
            Err(ServiceError::Topology(TopologyError::LinkNotFound(_)))
        ));
    }

    #[tokio::test]
    /// describe_link returns LinkNotFound when node_a is found but no peer's ZPR address
    /// matches node_b.
    async fn test_describe_link_node_b_not_matched() {
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        let mgr = make_policy_mgr(policy_with_peerings(&[peering])).await;
        let result = mgr.describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::99"));
        assert!(matches!(
            result,
            Err(ServiceError::Topology(TopologyError::LinkNotFound(_)))
        ));
    }

    #[tokio::test]
    /// describe_link returns the correct link_id when a matching peer is found via IP.
    async fn test_describe_link_found_by_ip() {
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-abc", vec![]);
        let mgr = make_policy_mgr(policy_with_peerings(&[peering])).await;
        let result = mgr
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.link_id, "link-abc");
    }

    #[tokio::test]
    /// describe_link returns DEFAULT_LINK_COST and an empty attrs vec when the link has no
    /// attributes.
    async fn test_describe_link_default_cost_no_attrs() {
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        let mgr = make_policy_mgr(policy_with_peerings(&[peering])).await;
        let result = mgr
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.cost, DEFAULT_LINK_COST);
        assert!(result.attrs.is_empty());
    }

    #[tokio::test]
    /// describe_link reads the numeric cost from the link.zpr.cost attribute.
    async fn test_describe_link_cost_from_attr() {
        let peering = make_peering(
            ip("fd5a:5052::1"),
            ip("fd5a:5052::2"),
            "link-1",
            vec![AttrExp {
                key: LINK_COST_ATTR_KEY.to_string(),
                op: AttrOp::Eq,
                value: vec!["5".to_string()],
            }],
        );
        let mgr = make_policy_mgr(policy_with_peerings(&[peering])).await;
        let result = mgr
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.cost, 5);
    }

    #[tokio::test]
    /// describe_link falls back to DEFAULT_LINK_COST when the cost attribute cannot be parsed.
    async fn test_describe_link_cost_unparseable_uses_default() {
        let peering = make_peering(
            ip("fd5a:5052::1"),
            ip("fd5a:5052::2"),
            "link-1",
            vec![AttrExp {
                key: LINK_COST_ATTR_KEY.to_string(),
                op: AttrOp::Eq,
                value: vec!["not-a-number".to_string()],
            }],
        );
        let mgr = make_policy_mgr(policy_with_peerings(&[peering])).await;
        let result = mgr
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.cost, DEFAULT_LINK_COST);
    }

    #[tokio::test]
    /// describe_link includes non-cost attributes in the returned LinkDescription.
    async fn test_describe_link_returns_non_cost_attrs() {
        let peering = make_peering(
            ip("fd5a:5052::1"),
            ip("fd5a:5052::2"),
            "link-1",
            vec![AttrExp {
                key: "link.class".to_string(),
                op: AttrOp::Eq,
                value: vec!["trusted".to_string()],
            }],
        );
        let mgr = make_policy_mgr(policy_with_peerings(&[peering])).await;
        let result = mgr
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.attrs.len(), 1);
        assert_eq!(result.attrs[0].get_key(), "link.class");
    }
}
