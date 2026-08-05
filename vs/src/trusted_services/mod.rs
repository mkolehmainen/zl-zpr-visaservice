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

pub use factory::build_services_from_policy;
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

/// Interface for trusted services that can provide attributes for actors.
#[async_trait]
pub trait TrustedServiceInterface: Send + Sync {
    /// Return attributes for the actor, or an empty vector when the actor is unknown.
    async fn get_attributes_for_actor(
        &self,
        actor_ident: &str,
    ) -> Result<Vec<Attribute>, ServiceError>;

    /// Drop cached attribute data so the next lookup fetches fresh data.
    async fn flush(&self) -> Result<(), ServiceError>;

    /// Return the revision of the data the service currently serves.
    fn current_revision(&self) -> u64;

    /// Return the stable source identifier stamped on this service's attributes.
    fn get_source_id(&self) -> &str;
}
