//! To make unit testing easier.

#![cfg(test)]

use libeval::actor::Actor;
use libeval::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE, key};
use std::time::Duration;
use std::time::SystemTime;
use zpr::vsapi_types::{DockPepType, EndpointT, KeySet, TcpUdpPep, Visa};

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
