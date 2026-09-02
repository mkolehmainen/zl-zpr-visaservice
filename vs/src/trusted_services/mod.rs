//! Trusted-service abstractions and implementations.

use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

use libeval::attribute::Attribute;

use crate::error::ServiceError;

mod attribute_mapper;
mod factory;
mod file_attribute_store;
mod manager;

#[cfg(test)]
mod test_support;

pub use factory::{TrustedServiceDefinition, build_services, trusted_service_definitions};
pub use manager::TrustedServicesMgr;

/// A revision no snapshot will ever carry (the counter starts at 1). Recording it for
/// an actor keeps a source relevant-and-stale, forcing a retry on the next request.
pub const REVISION_NEVER: u64 = 0;

/// Process-wide source of snapshot revisions. Revisions and actor records both reset
/// on restart, while a missing actor record safely forces a refresh.
static REVISION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Hand out the next process-wide trusted-service snapshot revision.
fn next_revision() -> u64 {
    REVISION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Intersect the policy's lookup-identity keys (see `Policy::lookup_identity_keys`)
/// with a set of attributes -- authenticated claims at connect time, the actor's
/// attributes at refresh time -- producing the (key, value) pairs to send to trusted
/// services. Attributes that are not single-valued cannot name an identity and are
/// skipped.
pub(crate) fn lookup_identities<'a>(
    lookup_keys: &[&str],
    attrs: impl Iterator<Item = &'a Attribute>,
) -> Vec<(String, String)> {
    let mut identities = Vec::new();
    for attr in attrs {
        if lookup_keys.contains(&attr.get_key()) {
            if let Ok(value) = attr.get_single_value() {
                identities.push((attr.get_key().to_string(), value.to_string()));
            }
        }
    }
    identities
}

/// Interface for trusted services that can provide attributes for actors.
#[async_trait]
pub trait TrustedServiceInterface: Send + Sync {
    /// Return attributes for the actor identified by `identities`, or an empty vector
    /// when none of the identities are known.
    ///
    /// `identities` is the actor's lookup-identity set: one (attribute key, value) pair
    /// per identity the actor authenticated under (e.g. a device CN and a user subject),
    /// so the source can tell which kind of identity each value is. A source that
    /// matches more than one identity returns the UNION of their attributes; if two
    /// matched identities supply the same ZPR attribute key with differing values the
    /// source must return `Err` (fail closed) rather than pick a winner.
    async fn get_attributes_for_actor(
        &self,
        identities: &[(String, String)],
    ) -> Result<Vec<Attribute>, ServiceError>;

    /// Drop cached attribute data so the next lookup fetches fresh data.
    async fn flush(&self) -> Result<(), ServiceError>;

    /// Return the revision of the data the service currently serves.
    fn current_revision(&self) -> u64;

    /// Return the stable source identifier stamped on this service's attributes.
    fn get_source_id(&self) -> &str;
}
