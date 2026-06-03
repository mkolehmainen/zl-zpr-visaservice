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
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info};

use libeval::attribute::Attribute;
use libeval::policy::{Peer, Policy};

use zpr::policy_types::{NetAddr, NetworkHost};
use zpr::vsapi_types::{Link, LinkRole, SockAddr};

use crate::db;
use crate::error::{ResolverError, ServiceError, TopologyError};
use crate::logging::targets::MAIN;

/// Abstracts DNS hostname resolution so it can be swapped out in tests.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolve `host` to a `SocketAddr` on the given `port`.
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ResolverError>;
}

// TODO: move to libeval::attribute::key
const LINK_COST_ATTR_KEY: &str = "link.zpr.cost";

/// The default and the minimum.
const DEFAULT_LINK_COST: u32 = 1;

/// Combined policy and resolved topology — swapped atomically as a unit.
struct PolicyState {
    policy: Arc<Policy>,
    links_by_node: HashMap<IpAddr, Vec<Link>>,
}

#[allow(dead_code)]
pub struct PolicyMgr {
    state: ArcSwap<PolicyState>,
    repo: db::PolicyRepo,
    /// Serializes concurrent policy updates; reads remain lock-free via ArcSwap.
    update_lock: tokio::sync::Mutex<()>,
    resolver: PolicyResolver,
}

#[derive(Debug, Clone)]
pub struct LinkDescription {
    pub link_id: String,
    pub attrs: Vec<Attribute>,
    pub cost: u32,
}

/// Production resolver that uses the OS/system resolver via `tokio::net::lookup_host`.
pub struct SystemResolver;

#[async_trait]
impl DnsResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ResolverError> {
        let mut addrs = tokio::net::lookup_host((host, port)).await?;
        addrs
            .next()
            .ok_or_else(|| ResolverError::NoAddresses(host.to_string()))
    }
}

impl PolicyMgr {
    /// Create a new policy manager, initializing it with the given initial policy.
    /// This will store the initial policy into the database if not already present.
    ///
    /// Note that policy is written to DB for backup purposes. It is kept in memory
    /// here for general access by rest of visa service.
    ///
    /// This also runs DNS lookups on all the peerings in the policy. Will throw a
    /// [ResolverError] if any of the peerings fail to resolve.  We may revisit this
    /// later if we decide to eventually pass DNS names down to nodes.
    pub async fn new_with_initial_policy(
        mut policy: Policy,
        repo: db::PolicyRepo,
        resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, ServiceError> {
        debug!(target: MAIN, "initializing policy manager");
        policy.set_vinst(1);

        let presolver = PolicyResolver::new(resolver);

        let links_by_node = presolver.resolve_topology(&policy).await?;
        let _db_updated = repo.set_current_policy(&policy, false).await?;

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(PolicyMgr {
            state: ArcSwap::from_pointee(PolicyState {
                policy: Arc::new(policy),
                links_by_node,
            }),
            repo,
            update_lock: tokio::sync::Mutex::new(()),
            resolver: presolver,
        })
    }

    /// Create a new policy manager, initializing it with the current policy in
    /// the database. If there is no policy in the database, this will return an
    /// error.  This will also run DNS on the policy so if there are any DNS
    /// issues with the peer hostnames (or if DNS is required and is not
    /// working) this will fail.
    ///
    /// If the policy contains hostnames and DNS is not working, this returns an
    /// error.
    pub async fn new_from_state(
        repo: db::PolicyRepo,
        resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, ServiceError> {
        debug!(target: MAIN, "initializing policy manager from state");
        let policy = repo.get_current_policy().await?;
        info!(target: MAIN, "loaded policy from state version:{}, created:{}", policy.get_version().unwrap_or(0),
            policy.get_created().unwrap_or("unknown").to_string());
        debug!(target: MAIN, "policy manager initialized successfully");

        let presolver = PolicyResolver::new(resolver);

        let links_by_node = presolver.resolve_topology(&policy).await?;
        Ok(PolicyMgr {
            state: ArcSwap::from_pointee(PolicyState {
                policy: Arc::new(policy),
                links_by_node,
            }),
            repo,
            update_lock: tokio::sync::Mutex::new(()),
            resolver: presolver,
        })
    }

    /// Update the current policy.  The new policy will be assigned a new version instance number (vinst)
    /// that is one greater than the current policy's vinst.
    ///
    /// TODO: There is a lot of housekeeping that needs to happen around a policy update. None of that
    /// is implemented here. Right now this is just to support unit tests.
    #[allow(dead_code)]
    pub async fn update_policy(&self, new_policy: Policy) -> Result<(), ServiceError> {
        let _guard = self.update_lock.lock().await;

        let mut new_policy = new_policy;
        new_policy.set_vinst(self.state.load().policy.vinst() + 1);

        let links_by_node = self.resolver.resolve_topology(&new_policy).await?;

        self.state.store(Arc::new(PolicyState {
            policy: Arc::new(new_policy),
            links_by_node,
        }));
        Ok(())
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    ///
    /// Currently there is no way to get a consistent view of policy AND the node resolution cache.
    /// If we find we need that we can add a snapshot mechanism.
    pub fn get_current(&self) -> Arc<Policy> {
        self.state.load().policy.clone()
    }

    /// When policy is updated, all the peer tables have their DNS names resolved and cached.
    /// Use this to get the links specified by policy for a node.
    ///
    /// Currently there is no way to get a consistent view of policy AND the node resolution cache.
    /// If we find we need that we can add a snapshot mechanism.
    ///
    pub fn resolved_links_for_node(&self, node: &IpAddr) -> Vec<Link> {
        self.state
            .load()
            .links_by_node
            .get(node)
            .cloned()
            .unwrap_or_default()
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

pub struct PolicyResolver {
    resolver: Arc<dyn DnsResolver>,
}

impl PolicyResolver {
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        PolicyResolver { resolver }
    }

    async fn resolve_topology(
        &self,
        policy: &Policy,
    ) -> Result<HashMap<IpAddr, Vec<Link>>, ResolverError> {
        let mut links_by_node: HashMap<IpAddr, Vec<Link>> = HashMap::new();
        for node_addr in policy.all_peered_nodes() {
            if let Some(peers) = policy.get_peers_for_node(node_addr) {
                let links = self.peers_to_links(peers).await?;
                links_by_node.insert(*node_addr, links);
            }
        }
        Ok(links_by_node)
    }

    /// Peers from policy may include hostnames. Here we run any hostnames through a
    /// DNS lookup and create concrete `Link` objects with IP addresses. Returns an error
    /// if any peer's address fails to resolve.
    async fn peers_to_links(&self, peers: &[Peer]) -> Result<Vec<Link>, ResolverError> {
        // Parallelize the DNS lookups then check for the first error.
        let futs = peers.iter().map(|peer| async move {
            (
                peer,
                resolve_netaddr(&peer.remote_substrate, self.resolver.as_ref()).await,
            )
        });

        futures::future::join_all(futs)
            .await
            .into_iter()
            .map(|(peer, result)| {
                result.map(|sock_addr| Link {
                    link_id: peer.link_id.clone(),
                    role: LinkRole::Active, // only "active" support at the moment.
                    peer: SockAddr {
                        addr: sock_addr.ip(),
                        port: sock_addr.port(),
                    },
                })
            })
            .collect()
    }
}

/// If the passed `NetAddr` contains a hostname, perform a DNS lookup to resolve it to an IP address.
/// Otherwise this quickly just returns a SocketAddr.
async fn resolve_netaddr(
    naddr: &NetAddr,
    resolver: &dyn DnsResolver,
) -> Result<SocketAddr, ResolverError> {
    match &naddr.host {
        NetworkHost::Ip(ip_addr) => Ok(SocketAddr::new(*ip_addr, naddr.port)),
        NetworkHost::Hostname(hostname) => resolver.resolve(hostname, naddr.port).await,
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
    use crate::test_helpers::FakeResolver;

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
        PolicyMgr::new_with_initial_policy(policy, repo, Arc::new(FakeResolver::ip_only()))
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

    fn ip_peer(link_id: &str, ip: IpAddr, port: u16) -> Peer {
        Peer {
            link_id: link_id.to_string(),
            remote_zpr_addr: "fd5a:5052::1".parse().unwrap(),
            remote_substrate: NetAddr {
                host: NetworkHost::Ip(ip),
                port,
            },
        }
    }

    /// Empty peer slice produces an empty link list.
    #[tokio::test]
    async fn test_peers_to_links_empty() {
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));
        let links = presolver.peers_to_links(&[]).await.unwrap();
        assert!(links.is_empty());
    }

    /// A single IP peer maps to a single Link with the correct fields.
    #[tokio::test]
    async fn test_peers_to_links_single_ip() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let peer = ip_peer("link-a", ip, 4000);
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let links = presolver.peers_to_links(&[peer]).await.unwrap();

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, "link-a");
        assert_eq!(links[0].role, LinkRole::Active);
        assert_eq!(links[0].peer.addr, ip);
        assert_eq!(links[0].peer.port, 4000);
    }

    /// Multiple IP peers produce one Link each, in the same order.
    #[tokio::test]
    async fn test_peers_to_links_multiple_ips() {
        let ip_a: IpAddr = "192.0.2.1".parse().unwrap();
        let ip_b: IpAddr = "192.0.2.2".parse().unwrap();
        let peers = [ip_peer("link-a", ip_a, 4000), ip_peer("link-b", ip_b, 5000)];
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let links = presolver.peers_to_links(&peers).await.unwrap();

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].link_id, "link-a");
        assert_eq!(links[0].peer.addr, ip_a);
        assert_eq!(links[1].link_id, "link-b");
        assert_eq!(links[1].peer.addr, ip_b);
    }

    /// A peer with an unresolvable hostname causes peers_to_links to return an error.
    /// FakeResolver has no entries, so any hostname lookup returns NoAddresses.
    #[tokio::test]
    async fn test_peers_to_links_bad_hostname_errors() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let good = ip_peer("link-good", ip, 4000);
        let bad = Peer {
            link_id: "link-bad".to_string(),
            remote_zpr_addr: "fd5a:5052::2".parse().unwrap(),
            remote_substrate: NetAddr {
                host: NetworkHost::Hostname("some.unresolvable.host".to_string()),
                port: 4000,
            },
        };
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let result = presolver.peers_to_links(&[good, bad]).await;

        assert!(result.is_err());
    }

    /// A hostname peer is resolved to the expected IP address via the FakeResolver.
    #[tokio::test]
    async fn test_peers_to_links_hostname_resolved() {
        let resolved_ip: IpAddr = "192.0.2.99".parse().unwrap();
        let peer = Peer {
            link_id: "link-h".to_string(),
            remote_zpr_addr: "fd5a:5052::10".parse().unwrap(),
            remote_substrate: NetAddr {
                host: NetworkHost::Hostname("peer.example.com".to_string()),
                port: 5000,
            },
        };
        let mut entries = HashMap::new();
        entries.insert(
            ("peer.example.com".to_string(), 5000),
            SocketAddr::new(resolved_ip, 5000),
        );
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::new(entries)));

        let links = presolver.peers_to_links(&[peer]).await.unwrap();

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, "link-h");
        assert_eq!(links[0].peer.addr, resolved_ip);
        assert_eq!(links[0].peer.port, 5000);
    }
}
