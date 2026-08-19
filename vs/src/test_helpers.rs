//! To make unit testing easier.

#![cfg(test)]

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use libeval::actor::Actor;
use libeval::attribute::{Attribute, AttributeSource, ROLE_ADAPTER, ROLE_NODE, key};
use libeval::eval_result::{Direction, Hit};
use libeval::policy::Policy;
use libeval::route::{LinkId, Route};

use zpr::policy::v1 as capnp_policy;
use zpr::policy_types::{
    AttrExp, JoinPolicy, NetAddr, PFlags, Peering, Service, ServiceType, TrustedService,
    parse_attribute_mapping,
};
use zpr::vsapi_types::{DockPepType, EndpointT, KeySet, PacketDesc, TcpUdpPep, Visa};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::assembly::tests::new_assembly_for_tests;
use crate::error::{ResolverError, ServiceError};
use crate::policy_mgr::DnsResolver;

const DEFAULT_EXPIRES: Duration = Duration::from_secs(3600);

/// Build an [Actor] with the provided attributes and a single expiration applied to all.
pub fn make_actor(attrs: &[(&str, &str)], expires: Duration) -> Actor {
    let mut actor = Actor::new();
    for (attr_key, attr_value) in attrs {
        actor
            .add_attribute(
                Attribute::builder(*attr_key)
                    .expires_in(expires)
                    .value(*attr_value),
            )
            .unwrap();
    }
    actor
}

/// Build an [Actor] with the provided attributes using the default expiration.
pub fn make_actor_defexp(attrs: &[(&str, &str)]) -> Actor {
    make_actor(attrs, DEFAULT_EXPIRES)
}

/// Build a node [Actor] with role, CN, ZPR addr and substrate addr.
/// Note: `substrate` must be a socket address string (e.g. `HOST:PORT` or `[IPv6]:PORT`).
pub fn make_node_actor(zpr_addr: &str, cn: &str, substrate: &str, expires: Duration) -> Actor {
    make_actor(
        &[
            (key::ROLE, ROLE_NODE),
            (key::CN, cn),
            (key::ZPR_ADDR, zpr_addr),
            (key::SUBSTRATE_ADDR, substrate),
        ],
        expires,
    )
}

/// Build a node [Actor] using the default expiration.
/// Note: `substrate` must be a socket address string (e.g. `HOST:PORT` or `[IPv6]:PORT`).
pub fn make_node_actor_defexp(zpr_addr: &str, cn: &str, substrate: &str) -> Actor {
    make_node_actor(zpr_addr, cn, substrate, DEFAULT_EXPIRES)
}

/// Build an adapter [Actor] with role, CN, and ZPR addr.
pub fn make_adapter_actor(zpr_addr: &str, cn: &str, expires: Duration) -> Actor {
    make_actor(
        &[
            (key::ROLE, ROLE_ADAPTER),
            (key::CN, cn),
            (key::ZPR_ADDR, zpr_addr),
        ],
        expires,
    )
}

/// Build an adapter [Actor] using the default expiration.
pub fn make_adapter_actor_defexp(zpr_addr: &str, cn: &str) -> Actor {
    make_adapter_actor(zpr_addr, cn, DEFAULT_EXPIRES)
}

/// Build an [Actor] with role/CN/ZPR addr plus services and an identity attribute.
pub fn make_actor_with_services(
    role: &str,
    zpr_addr: &str,
    services: &[&str],
    cn: &str,
    expires: Duration,
) -> Actor {
    let mut actor = make_actor(
        &[(key::ROLE, role), (key::CN, cn), (key::ZPR_ADDR, zpr_addr)],
        expires,
    );
    actor
        .add_attribute(
            Attribute::builder(key::SERVICES)
                .expires_in(expires)
                .values(services.iter().copied()),
        )
        .unwrap();
    actor
        .add_attribute(
            Attribute::builder("identity.foo")
                .expires_in(expires)
                .value("id-1"),
        )
        .unwrap();
    actor.add_identity_key(usize::MAX, "identity.foo").unwrap();
    actor
}

/// Build an [Actor] with services using the default expiration.
pub fn make_actor_with_services_defexp(
    role: &str,
    zpr_addr: &str,
    services: &[&str],
    cn: &str,
) -> Actor {
    make_actor_with_services(role, zpr_addr, services, cn, DEFAULT_EXPIRES)
}

/// A DNS resolver for tests. IP-only peerings short-circuit before calling this,
/// so an empty map suffices for tests that use only IP-addressed peers.
/// Populate the map to test hostname-resolution paths.
pub struct FakeResolver {
    entries: HashMap<(String, u16), SocketAddr>,
}

impl FakeResolver {
    pub fn new(entries: HashMap<(String, u16), SocketAddr>) -> Self {
        FakeResolver { entries }
    }

    /// A resolver with no hostname entries — suitable for tests that only use IP peers.
    pub fn ip_only() -> Self {
        FakeResolver::new(HashMap::new())
    }
}

#[async_trait]
impl DnsResolver for FakeResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ResolverError> {
        self.entries
            .get(&(host.to_string(), port))
            .copied()
            .ok_or_else(|| ResolverError::NoAddresses(host.to_string()))
    }
}

/// Build a [Visa] with the provided ID and expiry offset.
pub fn make_visa(visa_id: u64, expires_in: Duration) -> Visa {
    Visa::new(
        visa_id,
        0,
        SystemTime::now() + expires_in,
        "fd5a:5052::10".parse().unwrap(),
        "fd5a:5052::20".parse().unwrap(),
        DockPepType::TCP(TcpUdpPep::new(1234, 443, EndpointT::Server)),
        KeySet::new(b"ingress", b"egress"),
        None,
    )
}

/// Build a dummy TCP [PacketDesc] for tests that need a five-tuple but don't
/// care about its contents.
pub fn make_pdesc() -> PacketDesc {
    PacketDesc::new_tcp("fd5a:5052::10", "fd5a:5052::20", 1234, 443).unwrap()
}

/// Build a policy container declaring one trusted service: a join policy providing a
/// `ServiceType::Trusted(api)` service named `id`, plus (when `expiration_seconds` is
/// `Some`) the matching `TrustedService` record carrying `mappings`.
///
/// Build a [Policy] holding a single communication policy whose client and service
/// condition lists carry the given attribute keys (values/ops are left unset -- only the
/// keys matter to callers that look up condition keys). Pass empty slices for a com policy
/// with no conditions on that side.
pub fn make_policy_with_com_conditions(client_keys: &[&str], service_keys: &[&str]) -> Policy {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        let mut coms = policy_bldr.reborrow().init_com_policies(1);
        let mut com = coms.reborrow().get(0);
        let mut client = com.reborrow().init_client_conds(client_keys.len() as u32);
        for (i, k) in client_keys.iter().enumerate() {
            client.reborrow().get(i as u32).set_key(k);
        }
        let mut service = com.reborrow().init_service_conds(service_keys.len() as u32);
        for (i, k) in service_keys.iter().enumerate() {
            service.reborrow().get(i as u32).set_key(k);
        }
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap()
}

/// Pass `None` for `expiration_seconds` to get the "service declared but no record"
/// case. Each entry of `mappings` is a `"<service key> -> <attr spec>"` string.
pub fn make_trusted_service_policy(
    id: &str,
    api: &str,
    expiration_seconds: Option<u32>,
    mappings: &[&str],
) -> Vec<u8> {
    let service = Service {
        id: id.to_string(),
        endpoints: Vec::new(),
        kind: ServiceType::Trusted(api.to_string()),
    };
    let jp = JoinPolicy {
        conditions: Vec::new(),
        flags: PFlags::default(),
        provides: Some(vec![service]),
    };

    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        policy_bldr.set_created("2024-01-01T00:00:00Z");
        policy_bldr.set_version(1);
        policy_bldr.set_metadata("");
        jp.write_to(&mut policy_bldr.reborrow().init_join_policies(1).get(0));

        if let Some(secs) = expiration_seconds {
            let ts = TrustedService {
                service_id: id.to_string(),
                expiration_seconds: secs,
                returns_attrs: mappings
                    .iter()
                    .map(|m| parse_attribute_mapping(m).unwrap())
                    .collect(),
                identity_attrs: Vec::new(),
            };
            ts.write_to(&mut policy_bldr.reborrow().init_trusted_services(1).get(0));
        }
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// Build a `Peering` between two ZPR addresses, each reachable at its own address as
/// substrate so a `FakeResolver::ip_only()` resolves it. `describe_link(node_a, node_b)`
/// on the resulting policy finds this link.
pub fn make_peering(node_a: IpAddr, node_b: IpAddr, link_id: &str, attrs: Vec<AttrExp>) -> Peering {
    Peering {
        link_id: link_id.to_string(),
        node_a,
        substrate_a: NetAddr::new_for_ip_or_host(&node_a.to_string(), 0),
        node_b,
        substrate_b: NetAddr::new_for_ip_or_host(&node_b.to_string(), 0),
        attributes: attrs,
    }
}

/// Build the container bytes of a policy whose topology is the given peerings
/// (an empty slice gives a valid policy with no topology).
pub fn policy_with_peerings(peerings: &[Peering]) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy = msg.init_root::<capnp_policy::policy::Builder>();
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
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// Build the Cap'n Proto encoded bytes of a `PolicyContainer` with the given
/// compiler version and (arbitrary) policy payload, for use as test input.
pub fn make_container_bytes(maj: u32, min: u32, patch: u32, policy: &[u8]) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut container = msg.init_root::<capnp_policy::policy_container::Builder>();
        container.set_zplc_ver_major(maj);
        container.set_zplc_ver_minor(min);
        container.set_zplc_ver_patch(patch);
        container.set_policy(policy);
        container.set_signature(&[]);
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &msg).unwrap();
    buf
}

// ---- visa-sweep fixtures ----
// Shared by `visa_reconciler` (the sweep itself) and `event_mgr` (the handlers that
// drive it), so they live here rather than in either module's test block.

/// Build an assembly with two docked adapters (`::4000::a`/`::4000::b`) whose
/// nodes are in the topology. `with_link` controls whether a route exists.
/// The default (empty) policy denies everything (NoMatch), so with a route
/// present the eval still denies — either way the sweep sees a deny.
pub async fn build_sweep_asm(with_link: bool) -> (Arc<Assembly>, IpAddr) {
    let asm = new_assembly_for_tests(None).await;
    let node_a: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
    let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
    asm.actor_mgr
        .add_node(
            &make_node_actor_defexp("fd5a:5052:3000::1", "na", "10.0.0.1:1"),
            false,
        )
        .await
        .unwrap();
    asm.actor_mgr
        .add_node(
            &make_node_actor_defexp("fd5a:5052:3000::2", "nb", "10.0.0.2:2"),
            false,
        )
        .await
        .unwrap();
    asm.topo_mgr.add_node(node_a).unwrap();
    asm.topo_mgr.add_node(node_b).unwrap();
    if with_link {
        asm.topo_mgr
            .add_link(node_a, node_b, LinkId("l".into()), vec![], 1)
            .unwrap();
    }
    asm.actor_mgr
        .add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052:4000::a", "src"),
            &node_a,
        )
        .await
        .unwrap();
    asm.actor_mgr
        .add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052:4000::b", "dst"),
            &node_b,
        )
        .await
        .unwrap();
    (Arc::new(asm), node_a)
}

/// Create a single-node visa held (PendingInstall) by `req` for the given
/// five-tuple, seeded at `vinst`. Returns its id.
pub async fn create_sweep_visa(asm: &Arc<Assembly>, req: &IpAddr, vinst: u64) -> u64 {
    let pdesc = PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 1234, 80).unwrap();
    let hit = Hit::new_no_signal(0, Direction::Forward);
    let route = Route::new_direct((*req).into());
    let vwmd = asm
        .visa_mgr
        .create_visa(
            asm,
            req,
            &pdesc,
            &hit,
            &route,
            "",
            0,
            vinst,
            SystemTime::now() + DEFAULT_EXPIRES,
        )
        .await
        .unwrap();
    vwmd.visa.issuer_id
}

// ---- attribute-change sweep ----

pub const TS_SOURCE: &str = "hr";
pub const TS_KEY: &str = "user.dept";

/// A trusted service whose vended attributes, revision, and failure mode are all
/// settable, so a test can simulate "the external data changed" and "the service is
/// down".
pub struct MutableTrustedService {
    /// (key, value) pairs to vend; empty means the actor has no attributes here.
    pub attrs: std::sync::Mutex<Vec<(String, String)>>,
    pub fail: std::sync::atomic::AtomicBool,
    pub revision: std::sync::atomic::AtomicU64,
}

#[async_trait::async_trait]
impl crate::trusted_services::TrustedServiceInterface for MutableTrustedService {
    async fn get_attributes_for_actor(
        &self,
        _actor_ident: &str,
    ) -> Result<Vec<Attribute>, ServiceError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ServiceError::TrustedServiceInit("down".into()));
        }
        Ok(self
            .attrs
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                AttributeSource::new(TS_SOURCE)
                    .builder(k)
                    .expires_in(Duration::from_secs(600))
                    .value(v)
            })
            .collect())
    }

    async fn flush(&self) -> Result<(), ServiceError> {
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn current_revision(&self) -> u64 {
        self.revision.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn get_source_id(&self) -> &str {
        TS_SOURCE
    }
}

/// Register one [MutableTrustedService] vending `attrs` on the assembly, and return
/// it so the test can change its data or knock it over.
pub fn register_ts(asm: &Arc<Assembly>, attrs: &[(&str, &str)]) -> Arc<MutableTrustedService> {
    let svc = Arc::new(MutableTrustedService {
        attrs: std::sync::Mutex::new(
            attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ),
        fail: std::sync::atomic::AtomicBool::new(false),
        revision: std::sync::atomic::AtomicU64::new(1),
    });
    asm.ts_mgr.update_services(vec![svc.clone()]);
    svc
}

/// Give the stored actor at `zpr_addr` an attribute from [TS_SOURCE], standing in for
/// data the actor picked up from that source under the previous snapshot.
pub async fn seed_source_attr(asm: &Arc<Assembly>, zpr_addr: &str, ts_key: &str, value: &str) {
    let addr: IpAddr = zpr_addr.parse().unwrap();
    let mut actor = asm
        .actor_mgr
        .get_actor_by_zpr_addr(&addr)
        .await
        .unwrap()
        .unwrap();
    actor
        .add_attribute(
            AttributeSource::new(TS_SOURCE)
                .builder(ts_key)
                .expires_in(Duration::from_secs(600))
                .value(value),
        )
        .unwrap();
    asm.actor_mgr.update_actor(&actor).await.unwrap();
}

/// The stored actor's attribute values for `key`, if any.
pub async fn stored_attr(asm: &Arc<Assembly>, zpr_addr: &str, attr_key: &str) -> Option<String> {
    let addr: IpAddr = zpr_addr.parse().unwrap();
    let actor = asm
        .actor_mgr
        .get_actor_by_zpr_addr(&addr)
        .await
        .unwrap()
        .unwrap();
    actor
        .attrs_iter()
        .find(|a| a.get_key() == attr_key)
        .map(|a| a.get_value_as_string())
}
