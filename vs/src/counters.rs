//! Counters: Track various interesting events in the visa service operations.
use dashmap::DashMap;
use enum_map::{Enum, EnumMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use strum_macros::IntoStaticStr;

#[derive(Default)]
pub struct Counters {
    pub counters: EnumMap<CounterType, Counter>,
    per_node_counters: DashMap<IpAddr, NodeInfo>,
}

pub struct Counter {
    value: AtomicU64,
}

#[derive(Default)]
pub struct NodeInfo {
    counters: EnumMap<CounterType, Counter>,
    last_visa_req: Option<std::time::SystemTime>,
}

impl Counters {
    /// Shorthand for `Counters::counters[<TYPE>].increment()`.
    pub fn incr(&self, c: CounterType) {
        self.counters[c].increment();
    }

    pub fn incr_node(&self, c: CounterType, node: &IpAddr) {
        self.per_node_counters.entry(*node).or_default().counters[c].increment();
    }

    pub fn remove_node_info(&self, node: &IpAddr) {
        self.per_node_counters.remove(node);
    }

    pub fn get_node_counter(&self, node: &IpAddr, c: CounterType) -> Option<u64> {
        match self.per_node_counters.get(node) {
            Some(node_info) => Some(node_info.value().counters[c].get_count()),
            None => None,
        }
    }

    pub fn update_request_time(&self, node: &IpAddr) {
        self.per_node_counters
            .entry(*node)
            .or_default()
            .last_visa_req = Some(std::time::SystemTime::now());
    }

    #[allow(dead_code)]
    // Returning None could mean either there is no matching node, OR the node has never had
    // a visa request
    pub fn get_last_request_time(&self, node: &IpAddr) -> Option<std::time::SystemTime> {
        match self.per_node_counters.get(node) {
            Some(node_info) => node_info.last_visa_req,
            None => None,
        }
    }
}

impl Counter {
    pub fn new() -> Self {
        Counter {
            value: AtomicU64::new(0),
        }
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Enum, Clone, Copy, Debug, Hash, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum CounterType {
    VisaRequests,
    VisaRequestsApproved,
    VisaRequestsDenied,
    VisaRequestQueueFull,
    VisaRequestTimeout,
    VisaRequestQueueError,
    VisaRequestFailed, // internal unspecified error of some sort

    VsApiVisaRequests,
    VsApiPings,

    VssErrors,

    NodeConnectionsSuccess,
    NodeConnectionsFailed,

    AuthorizeConnectSuccess,
    AuthorizeConnectFailed,

    /// A policy-declared link could not be installed during a VSAPI join. The node is
    /// connected but has no route over that link until an endpoint reconnects.
    LinkInstallFailed,
}

impl CounterType {
    pub fn name(&self) -> &'static str {
        self.into() // uses strum
    }
}

impl fmt::Display for CounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
