//! The policy manager is conceived as the one true place where the running visa service
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

use libeval::policy::{LinkDescription, Peer, Policy};

use zpr::policy_types::{NetAddr, NetworkHost, PolicyContainerBytes};
use zpr::vsapi_types::{Link, LinkRole, SockAddr};

use crate::config;
use crate::db;
use crate::error::{ResolverError, ServiceError, StoreError, TopologyError};
use crate::loaded_policy::LoadedPolicy;
use crate::logging::targets::MAIN;
use crate::trusted_services::{
    TrustedServiceDefinition, TrustedServiceInterface, TrustedServicesMgr, build_services,
    trusted_service_definitions,
};

/// Abstracts DNS hostname resolution so it can be swapped out in tests.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolve `host` to a `SocketAddr` on the given `port`.
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ResolverError>;
}

/// The identifier of the "current policy" shared over the admin API.
/// This will be reworked in the future where we may have multiple policies, not all
/// active, including policies for different domains.
pub const DEFAULT_POLICY_ID: u64 = 0;

/// Combined policy, source container, and resolved topology — swapped atomically
/// as a unit so the three can never drift apart.
struct PolicyState {
    policy: Arc<Policy>,
    container: PolicyContainerBytes,
    links_by_node: HashMap<IpAddr, Vec<Link>>,
    /// Attribute stores for the trusted services this policy declares. Republished to
    /// `ts_mgr` on every successful swap so the stores can never outlive their policy.
    trusted_services: Vec<Arc<dyn TrustedServiceInterface>>,
    /// The declarations `trusted_services` was built from. Carried alongside the stores so
    /// the next policy can be compared against them and reuse the stores when unchanged.
    ts_definitions: Vec<TrustedServiceDefinition>,
}

pub struct PolicyMgr {
    state: ArcSwap<PolicyState>,
    repo: db::PolicyRepo,
    /// Serializes concurrent policy updates; reads remain lock-free via ArcSwap.
    update_lock: tokio::sync::Mutex<()>,
    resolver: PolicyResolver,
    ts_mgr: Arc<TrustedServicesMgr>,
    /// Directory holding the `<service-id>.json` files for `api=file` trusted services.
    file_ts_dir: PathBuf,
}

/// A consistent, owned snapshot of policy, source container, and resolved topology,
/// all captured in a single atomic load. Cheap to clone (a refcount bump) and safe to
/// hold across awaits: it pins the holder to one coherent view until dropped, so policy
/// and links can never drift apart for the duration of a multi-step operation (e.g.
/// topology revalidation after a policy update).
#[derive(Clone)]
pub struct PolicySnapshot(Arc<PolicyState>);

impl PolicySnapshot {
    /// The policy captured by this snapshot.
    pub fn policy(&self) -> &Policy {
        &self.0.policy
    }

    /// A clone of the policy Arc captured by this snapshot.
    pub fn policy_arc(&self) -> Arc<Policy> {
        self.0.policy.clone()
    }

    /// The version instance number of the captured policy.
    pub fn vinst(&self) -> u64 {
        self.policy().vinst()
    }

    /// A clone of the source container bytes captured by this snapshot.
    pub fn container(&self) -> PolicyContainerBytes {
        self.0.container.clone()
    }

    /// The resolved links for `node` as captured by this snapshot.
    pub fn links_for_node(&self, node: &IpAddr) -> Vec<Link> {
        self.0.links_by_node.get(node).cloned().unwrap_or_default()
    }

    /// Dispatches to [Policy::describe_link] on the captured policy.
    ///
    /// ## Errors
    /// - `TopologyError::LinkNotFound` if there is no link between `node_a` and
    ///   `node_b` in the captured policy.
    pub fn describe_link(
        &self,
        node_a: &IpAddr,
        node_b: &IpAddr,
    ) -> Result<LinkDescription, ServiceError> {
        self.policy()
            .describe_link(node_a, node_b)
            .map_err(|_| TopologyError::LinkNotFound(format!("{node_a} <-> {node_b}")).into())
    }
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
        container_bytes: Vec<u8>,
        repo: db::PolicyRepo,
        resolver: Arc<dyn DnsResolver>,
        ts_mgr: Arc<TrustedServicesMgr>,
        file_ts_dir: PathBuf,
    ) -> Result<Self, ServiceError> {
        debug!(target: MAIN, "initializing policy manager");

        // Decode and assign the initial vinst while the policy Arc
        // is still uniquely held (before build_state clones it).
        let mut loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(container_bytes),
            &config::POLICY_MIN_VERSION,
        )?;
        // Derive the vinst from any persisted identifier so it is monotonic
        // across restarts. Same container (matching phash) is a plain restart:
        // reuse its vinst. A different container (or a fresh DB) is a new policy
        // install and gets the next vinst.
        let ident = repo.get_current_identifier().await?;
        let vinst = match &ident {
            Some(i) if i.phash == loaded.hash_container_bytes()? => i.vinst,
            Some(i) => i.vinst.checked_add(1).ok_or_else(|| {
                StoreError::InvalidData("persisted vinst is u64::MAX; cannot advance".into())
            })?,
            None => 1,
        };
        loaded.set_vinst(vinst);

        let resolver = PolicyResolver::new(resolver);

        // Resolve topology before persisting so a policy that cannot initialize is never
        // stored as the current policy. build_state borrows `loaded`, leaving it
        // available for the post-resolution persist below.
        let state = Self::build_state(&resolver, &loaded, &file_ts_dir, None).await?;
        repo.set_current_policy(&loaded, false).await?;

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(Self::from_state(state, repo, resolver, ts_mgr, file_ts_dir))
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
        ts_mgr: Arc<TrustedServicesMgr>,
        file_ts_dir: PathBuf,
    ) -> Result<Self, ServiceError> {
        debug!(target: MAIN, "initializing policy manager from state");
        let mut loaded = repo
            .get_current_loaded_policy(&config::POLICY_MIN_VERSION)
            .await?;
        // Restore the persisted vinst.
        let ident = repo.get_current_identifier().await?;
        loaded.set_vinst(ident.map_or(1, |i| i.vinst));
        {
            let policy = loaded.policy();
            info!(target: MAIN, "loaded policy from state version:{}, created:{}", policy.get_version().unwrap_or(0),
                policy.get_created().unwrap_or("unknown").to_string());
        }
        let resolver = PolicyResolver::new(resolver);
        // A trusted service the policy declares but that cannot be configured (e.g. its
        // attribute file is missing) fails startup; the error names the service and file.
        let state = Self::build_state(&resolver, &loaded, &file_ts_dir, None).await?;

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(Self::from_state(state, repo, resolver, ts_mgr, file_ts_dir))
    }

    /// This is the placeholder "update policy" function. It only replaces the current policy
    /// with a new current policy. Once the visa service is running this is how policy is
    /// updated.
    pub async fn update_policy_from_container_bytes(
        &self,
        policy_container_bytes: Vec<u8>,
    ) -> Result<u64, ServiceError> {
        let loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(policy_container_bytes),
            &config::POLICY_MIN_VERSION,
        )?;
        self.update_policy_internal(loaded).await
    }

    /// Build the atomically-swapped policy state after resolving all policy topology.
    ///
    /// Intentionally performs only validation/state construction: it does not write the
    /// DB or store into `self.state`. This keeps failed DNS/topology resolution from
    /// leaking partial policy state. Borrows `loaded` (cloning only the `Arc<Policy>`
    /// and the `Bytes`-backed container — both refcount bumps) so the caller can still
    /// persist it after resolution succeeds.
    ///
    /// `previous` is the currently live state, when there is one, and is used only to
    /// carry unchanged trusted-service stores forward.
    async fn build_state(
        resolver: &PolicyResolver,
        loaded: &LoadedPolicy,
        file_ts_dir: &Path,
        previous: Option<&PolicyState>,
    ) -> Result<PolicyState, ServiceError> {
        let policy = loaded.policy();
        let links_by_node = resolver.resolve_topology(&policy).await?;
        let ts_definitions = trusted_service_definitions(&policy)?;
        let trusted_services = match previous {
            // Identical declarations mean the live stores are still correct.
            // Reusing them keeps their revisions, otherwise a policy install
            // makes every actor revision-stale against every source. Cached
            // attribute data now only moves on a TTL reload or an admin flush.
            Some(prev) if prev.ts_definitions == ts_definitions => prev.trusted_services.clone(),
            _ => build_services(&ts_definitions, file_ts_dir)?,
        };
        Ok(PolicyState {
            policy,
            container: loaded.container().clone(),
            links_by_node,
            trusted_services,
            ts_definitions,
        })
    }

    /// Assemble a PolicyMgr from already-built state and constructor-owned parts.
    fn from_state(
        state: PolicyState,
        repo: db::PolicyRepo,
        resolver: PolicyResolver,
        ts_mgr: Arc<TrustedServicesMgr>,
        file_ts_dir: PathBuf,
    ) -> Self {
        ts_mgr.update_services(state.trusted_services.clone());
        PolicyMgr {
            state: ArcSwap::from_pointee(state),
            repo,
            update_lock: tokio::sync::Mutex::new(()),
            resolver,
            ts_mgr,
            file_ts_dir,
        }
    }

    /// Swap in `state` and republish its trusted service stores, so the manager's stores
    /// always come from the policy that is currently live.
    fn publish(&self, state: PolicyState) {
        self.ts_mgr.update_services(state.trusted_services.clone());
        self.state.store(Arc::new(state));
    }

    /// Update the current policy in state database and memory.  The new policy
    /// will be assigned a new version instance number (vinst) that is one
    /// greater than the current policy's vinst.
    ///
    /// TODO: There is a lot of housekeeping that needs to happen around a
    /// policy update. None of that is implemented here. Right now this is just
    /// to support unit tests.
    ///
    /// Returns the new `vinst` value.
    ///
    /// ### Errors
    /// - `ResolverError` if the new policy's topology contains hostnames that
    ///   fail to resolve.
    /// - `StoreError` if there is a problem writing to the database.
    ///
    async fn update_policy_internal(&self, mut loaded: LoadedPolicy) -> Result<u64, ServiceError> {
        let _guard = self.update_lock.lock().await;

        // Assign the new vinst while the policy Arc is still uniquely held.
        let vinst = self.state.load().policy.vinst() + 1;
        loaded.set_vinst(vinst);

        // Resolve topology before swapping in the new state so a failed update leaves
        // the current policy, container, and topology untouched. The new policy,
        // container, and links swap in together as one PolicyState. The live state is
        // passed in so trusted-service stores whose declaration did not change are
        // carried over rather than rebuilt with a fresh revision.
        let previous = self.state.load_full();
        let state =
            Self::build_state(&self.resolver, &loaded, &self.file_ts_dir, Some(&previous)).await?;
        self.repo.set_current_policy(&loaded, false).await?;

        self.publish(state);
        Ok(vinst)
    }

    /// A consistent snapshot of policy, container, and resolved links taken in
    /// one atomic load. Holding it does not block updates, but it pins the
    /// holder to an older view until dropped. Use this when a multi-step
    /// operation must see one coherent policy/links pair; otherwise the
    /// single-shot accessors below suffice.
    ///
    /// `ArcSwap::load_full` is just a refcount bump, and the resulting owned
    /// `Arc<PolicyState>` outlives the load `Guard` so the snapshot is safe to
    /// hold across awaits.
    pub fn get_current_snapshot(&self) -> PolicySnapshot {
        PolicySnapshot(self.state.load_full())
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    pub fn get_current(&self) -> Arc<Policy> {
        self.get_current_snapshot().policy_arc()
    }

    /// Get the source container bytes for the current policy (for the admin API).
    pub fn get_current_container(&self) -> PolicyContainerBytes {
        self.get_current_snapshot().container()
    }

    /// When policy is updated, all the peer tables have their DNS names resolved and cached.
    /// Use this to get the links specified by policy for a node.
    pub fn resolved_links_for_node(&self, node: &IpAddr) -> Vec<Link> {
        self.get_current_snapshot().links_for_node(node)
    }

    /// Consult policy to get a description of the link between `node_a` and `node_b`.
    /// Both arguments are ZPR addresses. A convenience single-shot wrapper over
    /// [PolicySnapshot::describe_link]; callers needing a consistent multi-step view
    /// should take a snapshot and call its method directly.
    ///
    /// Only used in unit tests.
    ///
    /// ## Errors
    /// - `TopologyError::LinkNotFound` if there is no link between `node_a` and `node_b` in the policy.
    #[allow(dead_code)]
    pub fn describe_link(
        &self,
        node_a: &IpAddr,
        node_b: &IpAddr,
    ) -> Result<LinkDescription, ServiceError> {
        self.get_current_snapshot().describe_link(node_a, node_b)
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_helpers::{make_peering, make_trusted_service_policy, policy_with_peerings};
    use std::sync::Arc;
    use zpr::policy_types::{NetAddr, Peering};

    use crate::db::{DbConnection, FakeDb, PolicyRepo};
    use crate::test_helpers::FakeResolver;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a minimal valid Policy with no topology.
    fn policy_no_topology() -> Vec<u8> {
        policy_with_peerings(&[])
    }

    /// Create a PolicyMgr backed by a FakeDb with the given policy loaded.
    async fn make_policy_mgr(container_bytes: Vec<u8>) -> PolicyMgr {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        PolicyMgr::new_with_initial_policy(
            container_bytes,
            repo,
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap()
    }

    /// A PolicyMgr over a FakeDb that publishes its trusted service stores into `ts_mgr`
    /// and looks for attribute files in `dir`.
    async fn make_policy_mgr_with_ts(
        container_bytes: Vec<u8>,
        ts_mgr: Arc<TrustedServicesMgr>,
        dir: &Path,
    ) -> PolicyMgr {
        PolicyMgr::new_with_initial_policy(
            container_bytes,
            PolicyRepo::new(Arc::new(FakeDb::new())),
            Arc::new(FakeResolver::ip_only()),
            ts_mgr,
            dir.to_path_buf(),
        )
        .await
        .unwrap()
    }

    /// A successful update publishes the policy's trusted service stores, and a later
    /// update whose attribute file is missing fails without disturbing the live state.
    #[tokio::test]
    async fn test_update_publishes_stores_and_preserves_state_on_failure() {
        let dir = std::env::temp_dir().join("vs-pm-ts");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"alice": {"color": ["red"]}}"#,
        )
        .unwrap();

        let ts_mgr = Arc::new(TrustedServicesMgr::new());
        let good = make_trusted_service_policy("attrfile", "file", Some(3600), &[]);
        let mgr = make_policy_mgr_with_ts(good, ts_mgr.clone(), &dir).await;

        // The declared store is live: looking it up by source id no longer reports it missing.
        let results = ts_mgr
            .get_attributes_from_source_for_actor("attrfile", "alice")
            .await;
        assert!(results[0].is_ok());

        // An update declaring a service with no attribute file fails...
        let bad = make_trusted_service_policy("nosuchfile", "file", Some(3600), &[]);
        assert!(mgr.update_policy_from_container_bytes(bad).await.is_err());

        // ...leaving the current policy and its published stores untouched.
        assert_eq!(mgr.get_current().vinst(), 1);
        let results = ts_mgr
            .get_attributes_from_source_for_actor("attrfile", "alice")
            .await;
        assert!(results[0].is_ok());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Installing a policy whose trusted-service declarations are unchanged keeps the live
    /// stores, so actors stay caught up. A changed declaration rebuilds the store and makes
    /// them stale again.
    #[tokio::test]
    async fn test_policy_update_preserves_revisions_when_ts_config_unchanged() {
        let dir = std::env::temp_dir().join("vs-pm-ts-rev");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"alice": {"color": ["red"]}}"#,
        )
        .unwrap();

        let ts_mgr = Arc::new(TrustedServicesMgr::new());
        let policy = make_trusted_service_policy("attrfile", "file", Some(3600), &[]);
        let mgr = make_policy_mgr_with_ts(policy.clone(), ts_mgr.clone(), &dir).await;

        // Catch "alice" up with the store's current revision.
        let stale = ts_mgr.stale_sources_for_actor("alice");
        assert_eq!(stale.len(), 1);
        ts_mgr.record_revision("alice", &stale[0].0, stale[0].1);
        assert!(ts_mgr.stale_sources_for_actor("alice").is_empty());

        // Same trusted-service declarations: the store (and its revision) is carried over.
        mgr.update_policy_from_container_bytes(policy)
            .await
            .unwrap();
        assert!(ts_mgr.stale_sources_for_actor("alice").is_empty());

        // A changed declaration rebuilds the store, so the actor is stale again.
        let changed = make_trusted_service_policy("attrfile", "file", Some(7200), &[]);
        mgr.update_policy_from_container_bytes(changed)
            .await
            .unwrap();
        assert_eq!(ts_mgr.stale_sources_for_actor("alice").len(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Build a Peering whose node_b substrate is an unresolvable hostname, so that
    /// resolving topology with a no-entry FakeResolver fails.
    fn make_peering_bad_host(node_a: IpAddr, node_b: IpAddr, link_id: &str) -> Peering {
        Peering {
            link_id: link_id.to_string(),
            node_a,
            substrate_a: NetAddr::new_for_ip_or_host(&node_a.to_string(), 0),
            node_b,
            substrate_b: NetAddr::new_for_ip_or_host("unresolvable.invalid", 5000),
            attributes: vec![],
        }
    }

    #[tokio::test]
    /// A resolver failure during initial policy load must not persist the policy to the DB.
    async fn test_initial_policy_resolver_failure_does_not_write_db() {
        let db = Arc::new(FakeDb::new());
        let peering = make_peering_bad_host(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1");

        let result = PolicyMgr::new_with_initial_policy(
            policy_with_peerings(&[peering]),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await;

        assert!(result.is_err());
        // The DB must remain empty: a policy that cannot resolve is never persisted.
        assert!(
            PolicyRepo::new(db)
                .get_current_loaded_policy(&config::POLICY_MIN_VERSION)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    /// A resolver failure during an update must leave the current policy, container,
    /// and topology unchanged (no swapped-in state).
    async fn test_update_resolver_failure_preserves_state() {
        // Start from a valid no-topology policy (vinst 1).
        let initial_container = policy_no_topology();
        let mgr = make_policy_mgr(initial_container.clone()).await;
        assert_eq!(mgr.get_current().vinst(), 1);

        // Attempt an update whose topology cannot be resolved.
        let peering = make_peering_bad_host(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1");
        let result = mgr
            .update_policy_from_container_bytes(policy_with_peerings(&[peering]))
            .await;

        assert!(result.is_err());
        // Current state untouched: vinst stays 1 and the container is still the initial one.
        assert_eq!(mgr.get_current().vinst(), 1);
        assert_eq!(
            mgr.get_current_container().as_bytes(),
            initial_container.as_slice()
        );
    }

    #[tokio::test]
    /// A successful update swaps the policy, topology, and container together.
    async fn test_update_swaps_policy_topology_and_container() {
        // Start from a no-topology policy (vinst 1).
        let mgr = make_policy_mgr(policy_no_topology()).await;
        assert_eq!(mgr.get_current().vinst(), 1);
        assert!(mgr.resolved_links_for_node(&ip("fd5a:5052::1")).is_empty());

        // Update to a policy with topology, all IP-addressed so it resolves.
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        let new_container = policy_with_peerings(&[peering]);
        let vinst = mgr
            .update_policy_from_container_bytes(new_container.clone())
            .await
            .unwrap();

        assert_eq!(vinst, 2);
        assert_eq!(mgr.get_current().vinst(), 2);
        // Topology swapped in: node now has a resolved link.
        assert!(!mgr.resolved_links_for_node(&ip("fd5a:5052::1")).is_empty());
        // Container swapped in and round-trips.
        assert_eq!(
            mgr.get_current_container().as_bytes(),
            new_container.as_slice()
        );
    }

    #[tokio::test]
    /// PolicyContainerBytes round-trips through as_bytes, and LoadedPolicy decodes
    /// a valid container while preserving the source bytes.
    async fn test_policy_artifact_construction() {
        let container_bytes = policy_no_topology();
        let pcb = PolicyContainerBytes::from(container_bytes.clone());
        assert_eq!(pcb.as_bytes(), container_bytes.as_slice());

        let mut loaded = LoadedPolicy::from_container(pcb, &config::POLICY_MIN_VERSION).unwrap();
        assert_eq!(loaded.container().as_bytes(), container_bytes.as_slice());

        // set_vinst mutates the decoded policy but not the container bytes.
        loaded.set_vinst(7);
        assert_eq!(loaded.policy().vinst(), 7);
        assert_eq!(loaded.container().as_bytes(), container_bytes.as_slice());
    }

    #[tokio::test]
    /// LoadedPolicy::from_container rejects bytes that are not a valid container.
    async fn test_loaded_policy_rejects_garbage() {
        let pcb = PolicyContainerBytes::from(b"not a capnp container".to_vec());
        let result = LoadedPolicy::from_container(pcb, &config::POLICY_MIN_VERSION);
        assert!(result.is_err());
    }

    /// A snapshot is an internally-consistent, stable, owned view: its policy vinst and
    /// resolved links agree at capture time, and a later update does not mutate a
    /// snapshot already held.
    #[tokio::test]
    async fn test_snapshot_is_consistent_and_stable_across_update() {
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        // Start from a policy with one IP-resolvable link (vinst 1).
        let mgr = make_policy_mgr(policy_with_peerings(&[make_peering(
            a,
            b,
            "link-ab",
            vec![],
        )]))
        .await;

        // The captured policy vinst and links agree at capture time.
        let snap = mgr.get_current_snapshot();
        assert_eq!(snap.vinst(), 1);
        assert!(
            !snap.links_for_node(&a).is_empty(),
            "snapshot must see the link its policy describes"
        );

        // Update to a fresh no-topology policy (vinst 2).
        let new_vinst = mgr
            .update_policy_from_container_bytes(policy_no_topology())
            .await
            .unwrap();
        assert_eq!(new_vinst, 2);

        // The already-held snapshot is unchanged: still vinst 1, still has the old link.
        assert_eq!(snap.vinst(), 1, "held snapshot must not see the new vinst");
        assert!(
            !snap.links_for_node(&a).is_empty(),
            "held snapshot must retain its captured links"
        );

        // A freshly taken snapshot reflects the update.
        let snap2 = mgr.get_current_snapshot();
        assert_eq!(snap2.vinst(), 2);
        assert!(snap2.links_for_node(&a).is_empty());
    }

    /// Build a `Peer` whose substrate is a plain IP address (no hostname), so
    /// `peers_to_links` resolves it without any DNS lookup.
    fn ip_peer(link_id: &str, ip: IpAddr, port: u16) -> Peer {
        let substrate = NetAddr {
            host: NetworkHost::Ip(ip),
            port,
        };
        Peer {
            link_id: link_id.to_string(),
            remote_zpr_addr: "fd5a:5052::1".parse().unwrap(),
            // ponytail: local end is irrelevant to peers_to_links, so reuse the remote one.
            local_substrate: substrate.clone(),
            remote_substrate: substrate,
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
            local_substrate: NetAddr {
                host: NetworkHost::Ip(ip),
                port: 4000,
            },
        };
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let result = presolver.peers_to_links(&[good, bad]).await;

        assert!(result.is_err());
    }

    /// After an update bumps vinst, a fresh PolicyMgr built from the same DB via
    /// new_from_state restores that vinst rather than the decoded default.
    #[tokio::test]
    async fn test_new_from_state_restores_vinst() {
        let db = Arc::new(FakeDb::new());
        let mgr = PolicyMgr::new_with_initial_policy(
            policy_no_topology(),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap();
        // Update to a distinct container so vinst advances to 2.
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        mgr.update_policy_from_container_bytes(policy_with_peerings(&[peering]))
            .await
            .unwrap();

        let restored = PolicyMgr::new_from_state(
            PolicyRepo::new(db),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap();
        assert_eq!(restored.get_current().vinst(), 2);
    }

    /// Rebooting with the same container reuses the persisted vinst (plain
    /// restart); a different container advances it (new install).
    #[tokio::test]
    async fn test_new_with_initial_policy_vinst_from_persisted_identifier() {
        let db = Arc::new(FakeDb::new());
        let container = policy_no_topology();
        // First boot: fresh DB → vinst 1.
        let mgr = PolicyMgr::new_with_initial_policy(
            container.clone(),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap();
        assert_eq!(mgr.get_current().vinst(), 1);

        // Reboot with the same container: same phash → vinst stays 1.
        let same = PolicyMgr::new_with_initial_policy(
            container,
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap();
        assert_eq!(same.get_current().vinst(), 1);

        // Reboot with a different container: new phash → vinst advances to 2.
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        let different = PolicyMgr::new_with_initial_policy(
            policy_with_peerings(&[peering]),
            PolicyRepo::new(db),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap();
        assert_eq!(different.get_current().vinst(), 2);
    }

    /// A corrupt DB (policy present, no persisted vinst field) fails startup
    /// rather than silently defaulting the vinst.
    #[tokio::test]
    async fn test_new_from_state_missing_vinst_errors() {
        let db = Arc::new(FakeDb::new());
        // Seed a current policy, then rewrite policy:current without a vinst
        // field to mimic a corrupt state (the container blob is left intact).
        PolicyMgr::new_with_initial_policy(
            policy_no_topology(),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap();
        let phash = db.hget("policy:current", "phash").await.unwrap().unwrap();
        db.del("policy:current").await.unwrap();
        db.hset("policy:current", "phash", &phash).await.unwrap();

        let res = PolicyMgr::new_from_state(
            PolicyRepo::new(db),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await;
        assert!(res.is_err());
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
            local_substrate: NetAddr {
                host: NetworkHost::Ip("192.0.2.1".parse().unwrap()),
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
