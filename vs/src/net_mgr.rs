//! Manage network type stuff like IP addresses and, maybe later, topology info.

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use libeval::actor::Role;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use crate::config;
use crate::error::ServiceError;

/// Minimum prefix length at which IPv4 `hosts()` includes the network address
/// (RFC 3021 point-to-point links and /32 host routes).
const IPV4_POINT_TO_POINT_PREFIX_LEN: u8 = 31;

/// Each node gets a /88 for AAA addresses.
const NODE_AAA_PREFIX_LEN: u8 = 88;

/// ZPRnet AAA network is a /64.
pub const AAA_NET: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0x0aaa, 0, 0, 0, 0), 64);

pub struct NetMgr {
    node_addrs: Arc<Mutex<dyn AddrAllocator + Send>>,
    adapter_addrs: Arc<Mutex<dyn AddrAllocator + Send>>,
}

trait AddrAllocator {
    fn allocate(&mut self) -> Option<IpAddr>;
    fn release(&mut self, addr: IpAddr) -> Result<(), ServiceError>;

    /// Explicitly take an address out of the pool, returning an error if it is already allocated or outside the pool.
    fn take(&mut self, addr: &IpAddr) -> Result<(), ServiceError>;
    fn contains(&self, addr: &IpAddr) -> bool;
}

struct Addr6Allocator {
    net: Ipv6Net,
    rng: SmallRng,
    used: HashSet<u64>,
}

struct Addr4Allocator {
    net: Ipv4Net,
    rng: SmallRng,
    used: HashSet<u32>,
}

/// Each AAA network is of the form:
///
///     fd5a:5052:0000:0aaa:NNNN:NNxx:xxxx:xxxx
///
/// Where NNNN:NN are based on a computed "node id".
/// And xx:xxxx:xxxx is up to the node to hand out.
///
/// For the ZPRnet the AAA network is a /64.
/// For each node the AAA network is a /88.
///
pub fn aaa_network_for_node(node_zpr_addr: &IpAddr) -> IpNet {
    let node_id = node_id_for_node(node_zpr_addr);
    let aaa_net_addr = AAA_NET.addr();

    let mut net_segments = [0u16; 8];
    net_segments[..8].copy_from_slice(&aaa_net_addr.segments());

    // Use bottom 24 bits of node ID.
    net_segments[4] = (node_id >> 8) as u16;
    net_segments[5] = (node_id << 8) as u16;

    let new_net_addr = IpAddr::V6(Ipv6Addr::from(net_segments));
    IpNet::new(new_net_addr, NODE_AAA_PREFIX_LEN).unwrap()
}

/// Three bytes of the AAA address must be unique to the ZPRnet and ideally stable for a
/// given node.  For now we simply pull the low 24 bits of the node's ZPRnet address.
///
/// TODO: Is it a good idea to tie this value to the node ZPR address? That means that if
/// the ZPR address changes the AAA address set changes for the node.  Probably not a huge
/// issue since AAA addresses are only used during authentication and are handed out
/// on demand (I think).
///
/// TODO: Come up with better scheme.
pub fn node_id_for_node(node_zpr_addr: &IpAddr) -> u32 {
    match node_zpr_addr {
        IpAddr::V4(addr) => u32::from_be_bytes(addr.octets()) & 0x00FFFFFF,
        IpAddr::V6(addr) => {
            u32::from_be_bytes(addr.octets()[12..16].try_into().unwrap()) & 0x00FFFFFF
        }
    }
}

impl NetMgr {
    /// Create a NetMgr backed by IPv6 address pools.
    pub fn new_v6() -> Result<Self, ServiceError> {
        let adapter_net = config::ADAPTER_BASE_V6NET;
        let node_net = config::NODE_BASE_V6NET;

        // Do we have state in the DB? If so grab next address info db.
        Ok(NetMgr {
            node_addrs: Arc::new(Mutex::new(Addr6Allocator::new(node_net))),
            adapter_addrs: Arc::new(Mutex::new(Addr6Allocator::new(adapter_net))),
        })
    }

    /// Create a NetMgr backed by IPv4 address pools.
    #[allow(dead_code)]
    pub fn new_v4() -> Result<Self, ServiceError> {
        let adapter_net = config::ADAPTER_BASE_V4NET;
        let node_net = config::NODE_BASE_V4NET;

        // Do we have state in the DB? If so grab next address info db.
        Ok(NetMgr {
            node_addrs: Arc::new(Mutex::new(Addr4Allocator::new(node_net))),
            adapter_addrs: Arc::new(Mutex::new(Addr4Allocator::new(adapter_net))),
        })
    }

    /// Return an unused, random address in our network space.
    pub fn get_next_zpr_addr(&self, role: &Role) -> Result<IpAddr, ServiceError> {
        let addr = match role {
            Role::Adapter => {
                self.adapter_addrs
                    .lock()
                    .unwrap()
                    .allocate()
                    .ok_or(ServiceError::Internal(
                        "failed to allocate adapter address".to_string(),
                    ))?
            }
            Role::Node => {
                self.node_addrs
                    .lock()
                    .unwrap()
                    .allocate()
                    .ok_or(ServiceError::Internal(
                        "failed to allocate node address".to_string(),
                    ))?
            }
            _ => panic!("get_next_zpr_addr called with unsupported role"),
        };

        // TODO: Update redis
        Ok(addr)
    }

    /// Release a previously allocated address, returns an error if the address
    /// was not allocated by this manager.
    pub fn release_zpr_addr(&self, addr: IpAddr) -> Result<(), ServiceError> {
        {
            let mut allocator = self.adapter_addrs.lock().unwrap();
            if allocator.contains(&addr) {
                return allocator.release(addr);
            }
        }
        {
            let mut allocator = self.node_addrs.lock().unwrap();
            if allocator.contains(&addr) {
                return allocator.release(addr);
            }
        }
        Err(ServiceError::Internal(format!(
            "attempted to release address {addr} not managed by any allocator"
        )))
    }

    /// Take an address out of the pool, returning an error if it is already allocated or outside the pool.
    pub fn take_zpr_addr(&self, addr: &IpAddr) -> Result<(), ServiceError> {
        {
            let mut allocator = self.adapter_addrs.lock().unwrap();
            if allocator.contains(addr) {
                return allocator.take(addr);
            }
        }
        {
            let mut allocator = self.node_addrs.lock().unwrap();
            if allocator.contains(addr) {
                return allocator.take(addr);
            }
        }
        Err(ServiceError::Internal(format!(
            "attempted to take address {addr} not managed by any allocator"
        )))
    }

    /// True if the address is within one of our managed networks.
    /// Note that address may or may not be currently allocated.
    pub fn is_managed_address(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(ip4) => {
                config::ADAPTER_BASE_V4NET.contains(ip4) || config::NODE_BASE_V4NET.contains(ip4)
            }
            IpAddr::V6(ip6) => {
                config::ADAPTER_BASE_V6NET.contains(ip6) || config::NODE_BASE_V6NET.contains(ip6)
            }
        }
    }
}

impl Addr6Allocator {
    /// Construct a new IPv6 allocator for a /64 subnet.
    fn new(net: Ipv6Net) -> Self {
        if net.prefix_len() != 64 {
            panic!("IPv6 AddrAllocator only supports /64 nets");
        }
        Addr6Allocator {
            net,
            rng: SmallRng::from_rng(&mut rand::rng()),
            used: HashSet::new(),
        }
    }
}

impl AddrAllocator for Addr6Allocator {
    fn contains(&self, addr: &IpAddr) -> bool {
        if let IpAddr::V6(v6addr) = addr {
            self.net.contains(v6addr)
        } else {
            false
        }
    }

    /// Allocate a random unused IPv6 address from the subnet.
    fn allocate(&mut self) -> Option<IpAddr> {
        for _ in 0..10_000 {
            let host: u64 = self.rng.next_u64();
            if self.used.insert(host) {
                // hosts() omits the network/broadcast slots, so a few offsets map
                // to None — keep drawing instead of bailing out of the loop.
                if let Some(ip) = self.net.hosts().nth(host as usize) {
                    return Some(IpAddr::V6(ip));
                }
            }
        }
        None
    }

    /// Release a previously allocated IPv6 address.
    fn release(&mut self, addr: IpAddr) -> Result<(), ServiceError> {
        if let IpAddr::V6(v6addr) = addr {
            if !self.net.contains(&v6addr) {
                return Err(ServiceError::Internal(format!(
                    "attempted to release IPv6 address {addr} outside allocator net: {}",
                    self.net
                )));
            }
            let n = u128::from(v6addr) - u128::from(self.net.network());
            if self.used.remove(&(n as u64)) {
                Ok(())
            } else {
                Err(ServiceError::Internal(format!(
                    "attempted to release unallocated IPv6 address: {addr}"
                )))
            }
        } else {
            Err(ServiceError::Internal(
                "attempted to release non-IPv6 address from IPv6 allocator".to_string(),
            ))
        }
    }

    fn take(&mut self, addr: &IpAddr) -> Result<(), ServiceError> {
        if let IpAddr::V6(v6addr) = addr {
            if !self.net.contains(v6addr) {
                return Err(ServiceError::Internal(format!(
                    "attempted to take IPv6 address {addr} outside allocator net: {}",
                    self.net
                )));
            }
            let n = u128::from(v6addr.clone()) - u128::from(self.net.network());
            if self.used.insert(n as u64) {
                Ok(())
            } else {
                Err(ServiceError::Internal(format!(
                    "attempted to take already allocated IPv6 address: {addr}"
                )))
            }
        } else {
            Err(ServiceError::Internal(
                "attempted to take non-IPv6 address from IPv6 allocator".to_string(),
            ))
        }
    }
}

impl Addr4Allocator {
    /// Construct a new IPv4 allocator for the given subnet.
    fn new(net: Ipv4Net) -> Self {
        Addr4Allocator {
            net,
            rng: SmallRng::from_rng(&mut rand::rng()),
            used: HashSet::new(),
        }
    }
}

impl AddrAllocator for Addr4Allocator {
    fn contains(&self, addr: &IpAddr) -> bool {
        if let IpAddr::V4(v4addr) = addr {
            self.net.contains(v4addr)
        } else {
            false
        }
    }

    /// Allocate a random unused IPv4 address from the subnet.
    fn allocate(&mut self) -> Option<IpAddr> {
        let host_bits = 32 - self.net.prefix_len();
        let mask = (1u32 << host_bits) - 1;

        for _ in 0..10_000 {
            let host: u32 = self.rng.next_u32() & mask;
            if self.used.insert(host) {
                // hosts() omits the network/broadcast slots, so the top offsets
                // in the masked range map to None — keep drawing instead of bailing.
                if let Some(ip) = self.net.hosts().nth(host as usize) {
                    return Some(IpAddr::V4(ip));
                }
            }
        }
        None
    }

    /// Release a previously allocated IPv4 address.
    fn release(&mut self, addr: IpAddr) -> Result<(), ServiceError> {
        if let IpAddr::V4(v4addr) = addr {
            if !self.net.contains(&v4addr) {
                return Err(ServiceError::Internal(format!(
                    "attempted to release IPv4 address {addr} outside allocator net: {}",
                    self.net
                )));
            }
            let n = u32::from(v4addr) - u32::from(self.net.network());
            let host_index = if self.net.prefix_len() < IPV4_POINT_TO_POINT_PREFIX_LEN {
                n.checked_sub(1).ok_or_else(|| {
                    ServiceError::Internal(format!(
                        "attempted to release IPv4 network address: {addr}"
                    ))
                })?
            } else {
                n
            };
            if self.used.remove(&host_index) {
                Ok(())
            } else {
                Err(ServiceError::Internal(format!(
                    "attempted to release unallocated IPv4 address: {addr}"
                )))
            }
        } else {
            Err(ServiceError::Internal(
                "attempted to release non-IPv4 address from IPv4 allocator".to_string(),
            ))
        }
    }

    fn take(&mut self, addr: &IpAddr) -> Result<(), ServiceError> {
        if let IpAddr::V4(v4addr) = addr {
            if !self.net.contains(v4addr) {
                return Err(ServiceError::Internal(format!(
                    "attempted to take IPv4 address {addr} outside allocator net: {}",
                    self.net
                )));
            }
            let n = u32::from(v4addr.clone()) - u32::from(self.net.network());
            let host_index = if self.net.prefix_len() < IPV4_POINT_TO_POINT_PREFIX_LEN {
                n.checked_sub(1).ok_or_else(|| {
                    ServiceError::Internal(format!(
                        "attempted to take IPv4 network address: {addr}"
                    ))
                })?
            } else {
                n
            };
            if self.used.insert(host_index) {
                Ok(())
            } else {
                Err(ServiceError::Internal(format!(
                    "attempted to take already allocated IPv4 address: {addr}"
                )))
            }
        } else {
            Err(ServiceError::Internal(
                "attempted to take non-IPv4 address from IPv4 allocator".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn v6_allocate_release_adapter_and_node() {
        let mgr = NetMgr::new_v6().expect("failed to build v6 NetMgr");
        let adapter_net = config::ADAPTER_BASE_V6NET;
        let node_net = config::NODE_BASE_V6NET;

        let adapter_addr = mgr
            .get_next_zpr_addr(&Role::Adapter)
            .expect("failed to allocate adapter v6 addr");
        let node_addr = mgr
            .get_next_zpr_addr(&Role::Node)
            .expect("failed to allocate node v6 addr");

        match adapter_addr {
            IpAddr::V6(addr) => assert!(adapter_net.contains(&addr)),
            _ => panic!("expected v6 adapter address"),
        }
        match node_addr {
            IpAddr::V6(addr) => assert!(node_net.contains(&addr)),
            _ => panic!("expected v6 node address"),
        }

        mgr.release_zpr_addr(adapter_addr)
            .expect("failed to release adapter v6 addr");
        mgr.release_zpr_addr(node_addr)
            .expect("failed to release node v6 addr");

        assert!(mgr.release_zpr_addr(adapter_addr).is_err());
        assert!(mgr.release_zpr_addr(node_addr).is_err());
    }

    #[tokio::test]
    async fn v4_allocate_release_adapter_and_node() {
        let mgr = NetMgr::new_v4().expect("failed to build v4 NetMgr");
        let adapter_net = config::ADAPTER_BASE_V4NET;
        let node_net = config::NODE_BASE_V4NET;

        let adapter_addr = mgr
            .get_next_zpr_addr(&Role::Adapter)
            .expect("failed to allocate adapter v4 addr");
        let node_addr = mgr
            .get_next_zpr_addr(&Role::Node)
            .expect("failed to allocate node v4 addr");

        match adapter_addr {
            IpAddr::V4(addr) => assert!(adapter_net.contains(&addr)),
            _ => panic!("expected v4 adapter address"),
        }
        match node_addr {
            IpAddr::V4(addr) => assert!(node_net.contains(&addr)),
            _ => panic!("expected v4 node address"),
        }

        mgr.release_zpr_addr(adapter_addr)
            .expect("failed to release adapter v4 addr");
        mgr.release_zpr_addr(node_addr)
            .expect("failed to release node v4 addr");

        assert!(mgr.release_zpr_addr(adapter_addr).is_err());
        assert!(mgr.release_zpr_addr(node_addr).is_err());
    }

    #[test]
    fn v4_allocate_release_on_slash31() {
        let net = Ipv4Net::from_str("10.0.0.0/31").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        let addr = alloc.allocate().expect("failed to allocate from /31");
        match addr {
            IpAddr::V4(v4) => assert!(net.contains(&v4)),
            _ => panic!("expected v4 address"),
        }
        alloc.release(addr).expect("failed to release /31 address");
        assert!(alloc.release(addr).is_err(), "double release should fail");
    }

    #[test]
    fn v4_allocate_release_all_slash31_hosts() {
        let net = Ipv4Net::from_str("10.0.0.0/31").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        // A /31 has exactly 2 usable hosts; allocate until we get both.
        let mut addrs = HashSet::new();
        for _ in 0..10_000 {
            if addrs.len() == 2 {
                break;
            }
            if let Some(addr) = alloc.allocate() {
                addrs.insert(addr);
            }
        }
        assert_eq!(addrs.len(), 2, "should allocate both /31 addresses");

        for addr in &addrs {
            alloc.release(*addr).expect("failed to release /31 address");
        }
    }

    #[test]
    fn v4_allocate_release_on_slash32() {
        let net = Ipv4Net::from_str("10.0.0.1/32").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        let addr = alloc.allocate().expect("failed to allocate from /32");
        assert_eq!(addr, IpAddr::from([10, 0, 0, 1]));
        alloc.release(addr).expect("failed to release /32 address");
        assert!(alloc.release(addr).is_err(), "double release should fail");
    }

    #[test]
    fn v4_allocate_release_on_slash30() {
        let net = Ipv4Net::from_str("10.0.0.0/30").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        // A /30 has 2 usable hosts (network and broadcast excluded).
        let mut addrs = HashSet::new();
        for _ in 0..10_000 {
            if addrs.len() == 2 {
                break;
            }
            if let Some(addr) = alloc.allocate() {
                addrs.insert(addr);
            }
        }
        assert_eq!(addrs.len(), 2, "should allocate both /30 host addresses");

        for addr in &addrs {
            alloc.release(*addr).expect("failed to release /30 address");
        }
    }

    #[test]
    fn v6_allocate_release_unallocated() {
        let mgr = NetMgr::new_v6().expect("failed to build v6 NetMgr");
        let adapter_net = config::ADAPTER_BASE_V6NET;

        let adapter_addr: IpAddr = "fd5a:5052:adda:1:7c51:12d4:f89e:8d90"
            .parse()
            .expect("failed to parse adapter v6 addr");

        match adapter_addr {
            IpAddr::V6(addr) => assert!(adapter_net.contains(&addr)),
            _ => panic!("expected v6 adapter address"),
        }

        // Should return an error since it is not allocated
        assert!(mgr.release_zpr_addr(adapter_addr).is_err());
    }

    #[test]
    fn v6_take_address_in_net() {
        let net = config::ADAPTER_BASE_V6NET;
        let mut alloc = Addr6Allocator::new(net);
        let addr: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();
        assert!(alloc.take(&addr).is_ok());
    }

    #[test]
    fn v6_take_duplicate_fails() {
        let net = config::ADAPTER_BASE_V6NET;
        let mut alloc = Addr6Allocator::new(net);
        let addr: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();
        alloc.take(&addr).expect("first take should succeed");
        assert!(alloc.take(&addr).is_err(), "second take should fail");
    }

    #[test]
    fn v6_take_after_allocate_fails() {
        let net = config::ADAPTER_BASE_V6NET;
        let mut alloc = Addr6Allocator::new(net);
        let addr = alloc.allocate().expect("allocation should succeed");
        assert!(
            alloc.take(&addr).is_err(),
            "take of already-allocated address should fail"
        );
    }

    #[test]
    fn v6_take_outside_net_fails() {
        let net = config::ADAPTER_BASE_V6NET;
        let mut alloc = Addr6Allocator::new(net);
        let outside: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(alloc.take(&outside).is_err());
    }

    #[test]
    fn v6_take_then_release() {
        let net = config::ADAPTER_BASE_V6NET;
        let mut alloc = Addr6Allocator::new(net);
        let addr: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();
        alloc.take(&addr).expect("take should succeed");
        alloc
            .release(addr)
            .expect("release after take should succeed");
    }

    #[test]
    fn v4_take_address_in_net() {
        let net = config::ADAPTER_BASE_V4NET;
        let mut alloc = Addr4Allocator::new(net);
        let addr: IpAddr = "10.128.0.1".parse().unwrap();
        assert!(alloc.take(&addr).is_ok());
    }

    #[test]
    fn v4_take_duplicate_fails() {
        let net = config::ADAPTER_BASE_V4NET;
        let mut alloc = Addr4Allocator::new(net);
        let addr: IpAddr = "10.128.0.1".parse().unwrap();
        alloc.take(&addr).expect("first take should succeed");
        assert!(alloc.take(&addr).is_err(), "second take should fail");
    }

    #[test]
    fn v4_take_after_allocate_fails() {
        let net = config::ADAPTER_BASE_V4NET;
        let mut alloc = Addr4Allocator::new(net);
        let addr = alloc.allocate().expect("allocation should succeed");
        assert!(
            alloc.take(&addr).is_err(),
            "take of already-allocated address should fail"
        );
    }

    #[test]
    fn v4_take_outside_net_fails() {
        let net = config::ADAPTER_BASE_V4NET;
        let mut alloc = Addr4Allocator::new(net);
        let outside: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(alloc.take(&outside).is_err());
    }

    #[test]
    fn v4_take_network_address_fails() {
        // For prefix_len < 31, take subtracts 1 from the offset; the network
        // address has offset 0, so checked_sub(1) returns None → error.
        let net = Ipv4Net::from_str("10.0.0.0/30").unwrap();
        let mut alloc = Addr4Allocator::new(net);
        let network_addr: IpAddr = "10.0.0.0".parse().unwrap();
        assert!(alloc.take(&network_addr).is_err());
    }

    #[test]
    fn v4_take_then_release() {
        let net = config::ADAPTER_BASE_V4NET;
        let mut alloc = Addr4Allocator::new(net);
        let addr: IpAddr = "10.128.0.1".parse().unwrap();
        alloc.take(&addr).expect("take should succeed");
        alloc
            .release(addr)
            .expect("release after take should succeed");
    }

    #[test]
    fn v4_take_on_slash31() {
        // For a /31 (prefix_len == IPV4_POINT_TO_POINT_PREFIX_LEN), the offset
        // is used directly without subtracting 1, so taking the network address works.
        let net = Ipv4Net::from_str("10.0.0.0/31").unwrap();
        let mut alloc = Addr4Allocator::new(net);
        let addr: IpAddr = "10.0.0.0".parse().unwrap();
        assert!(alloc.take(&addr).is_ok());
    }

    #[tokio::test]
    async fn v6_take_and_release_zpr_addr() {
        let mgr = NetMgr::new_v6().expect("failed to build v6 NetMgr");
        let adapter_addr: IpAddr = "fd5a:5052:adda:1::100".parse().unwrap();
        let node_addr: IpAddr = "fd5a:5052:90de:1::100".parse().unwrap();

        mgr.take_zpr_addr(&adapter_addr)
            .expect("take adapter addr should succeed");
        mgr.take_zpr_addr(&node_addr)
            .expect("take node addr should succeed");

        mgr.release_zpr_addr(adapter_addr)
            .expect("release adapter addr should succeed");
        mgr.release_zpr_addr(node_addr)
            .expect("release node addr should succeed");
    }

    #[test]
    fn v6_take_unmanaged_addr_fails() {
        let mgr = NetMgr::new_v6().expect("failed to build v6 NetMgr");
        let unmanaged: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(mgr.take_zpr_addr(&unmanaged).is_err());
    }

    #[test]
    fn v6_take_already_allocated_fails() {
        let mgr = NetMgr::new_v6().expect("failed to build v6 NetMgr");
        let addr = mgr
            .get_next_zpr_addr(&Role::Adapter)
            .expect("allocate should succeed");
        assert!(
            mgr.take_zpr_addr(&addr).is_err(),
            "take of already-allocated address should fail"
        );
    }

    #[tokio::test]
    async fn v4_take_and_release_zpr_addr() {
        let mgr = NetMgr::new_v4().expect("failed to build v4 NetMgr");
        let adapter_addr: IpAddr = "10.128.0.1".parse().unwrap();
        let node_addr: IpAddr = "10.192.0.1".parse().unwrap();

        mgr.take_zpr_addr(&adapter_addr)
            .expect("take adapter addr should succeed");
        mgr.take_zpr_addr(&node_addr)
            .expect("take node addr should succeed");

        mgr.release_zpr_addr(adapter_addr)
            .expect("release adapter addr should succeed");
        mgr.release_zpr_addr(node_addr)
            .expect("release node addr should succeed");
    }

    #[test]
    fn v4_take_unmanaged_addr_fails() {
        let mgr = NetMgr::new_v4().expect("failed to build v4 NetMgr");
        let unmanaged: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(mgr.take_zpr_addr(&unmanaged).is_err());
    }

    #[test]
    fn aaa_network_for_node_uses_low_24_bits_of_node_id() {
        let v4_node = IpAddr::from([10, 11, 12, 13]); // low 24 bits => 0x0b0c0d
        let v6_node = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 1, 0xaaaa, 0xbbbb, 0xcccc, 0x0c0d,
        )); // low 24 bits => 0xbbcc0c0d & 0x00ffffff => 0xcc0c0d

        let v4_net = aaa_network_for_node(&v4_node);
        let v6_net = aaa_network_for_node(&v6_node);

        assert_eq!(v4_net.prefix_len(), NODE_AAA_PREFIX_LEN);
        assert_eq!(v6_net.prefix_len(), NODE_AAA_PREFIX_LEN);
        assert_eq!(
            v4_net,
            IpNet::from_str("fd5a:5052:0:aaa:0b0c:0d00::/88").expect("parse expected v4 net"),
        );
        assert_eq!(
            v6_net,
            IpNet::from_str("fd5a:5052:0:aaa:cc0c:0d00::/88").expect("parse expected v6 net"),
        );
    }
}
