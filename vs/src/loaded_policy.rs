//! Policy is kept together with its container. This does that.
//!
//! - [PolicyContainerBytes]: encoded Cap'n Proto `PolicyContainer` bytes.
//!   See https://github.com/org-zpr/zpr-common/blob/main/src/policy_types/policy_bundle.rs
//! - [LoadedPolicy]: a decoded [Policy] paired with the exact container bytes it
//!   was decoded from, so the two can never drift apart.
//!
//! These live in their own module (rather than in `policy_mgr`) so the DB layer
//! (`db::policy`) can use them in its public API without `db` having to depend on
//! the policy manager.

use std::sync::Arc;

use libeval::pio;
use libeval::policy::{Policy, PolicyError};
use openssl::hash::{Hasher, MessageDigest};
use zpr::policy_types::PolicyContainerBytes;

use crate::error::CryptoError;

/// A decoded [Policy] paired with the exact container bytes it came from.
///
/// Constructing a `LoadedPolicy` guarantees the policy and container agree *at
/// decode time*. The service-assigned `vinst` is mutated after decode (see
/// [LoadedPolicy::set_vinst]); that does not affect the container artifact, which
/// is what the admin API round-trips.
pub struct LoadedPolicy {
    policy: Arc<Policy>,
    container: PolicyContainerBytes,
}

impl LoadedPolicy {
    /// Decode a policy from encoded policy container bytes, retaining the source
    /// container for later round-tripping.
    pub fn from_container(
        container: PolicyContainerBytes,
        min_version: &pio::Version,
    ) -> Result<Self, PolicyError> {
        let policy = pio::load_policy_from_container(container.as_bytes(), min_version)?;
        Ok(Self {
            policy: Arc::new(policy),
            container,
        })
    }

    /// The decoded policy as a cheap-to-clone `Arc`.
    pub fn policy(&self) -> Arc<Policy> {
        self.policy.clone()
    }

    /// The source container bytes.
    pub fn container(&self) -> &PolicyContainerBytes {
        &self.container
    }

    /// Assign the service's version instance number to the decoded policy.
    ///
    /// `vinst` is service state, not part of the container artifact, so this
    /// mutates only the decoded policy and leaves the container bytes untouched.
    /// It mutates through the `Arc` and therefore must be called while the `Arc`
    /// is still uniquely held — i.e. right after [LoadedPolicy::from_container]
    /// and before the policy is cloned into shared state.
    pub fn set_vinst(&mut self, vinst: u64) {
        Arc::get_mut(&mut self.policy)
            .expect("set_vinst called after the policy Arc was shared")
            .set_vinst(vinst);
    }

    /// Compute the policy artifact hash: the SHA-256 of the container bytes as-is.
    /// We use this in the database to key policies.
    pub fn hash_container_bytes(&self) -> Result<String, CryptoError> {
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        hasher.update(self.container.as_bytes())?;
        let dig = hasher.finish()?;
        Ok(hex::encode(dig))
    }
}
