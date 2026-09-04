//! Trusted-service abstractions and implementations.

use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

use libeval::attribute::{Attribute, AttributeSource, key};

use crate::error::ServiceError;

mod attribute_mapper;
mod factory;
mod file_attribute_store;
mod manager;

pub(crate) use attribute_mapper::{AttrHint, AttributeMapper};

#[cfg(test)]
mod test_support;

pub use factory::{
    TS_API_OIDC, TrustedServiceDefinition, build_services, trusted_service_definitions,
};
pub use manager::TrustedServicesMgr;

/// A revision no snapshot will ever carry (the counter starts at 1). Recording it for
/// an actor keeps a source relevant-and-stale, forcing a retry on the next request.
pub const REVISION_NEVER: u64 = 0;

/// Process-wide source of snapshot revisions. Revisions and actor records both reset
/// on restart, while a missing actor record safely forces a refresh.
static REVISION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Hand out the next process-wide trusted-service snapshot revision.
pub(crate) fn next_revision() -> u64 {
    REVISION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Intersect the policy's lookup-identity keys (see `Policy::lookup_identity_keys`)
/// with a set of attributes -- authenticated claims at connect time, the actor's
/// attributes at refresh time -- producing the (key, value) pairs to send to trusted
/// services. Attributes that are not single-valued cannot name an identity and are
/// skipped.
///
/// `user.zpr.authority` is always included when the actor carries it, whether or
/// not policy names it: identities such as an OIDC `sub` are unique only within
/// the service that vouched for them, so sources need the authority pair to scope
/// per-issuer identities to the issuing service (see
/// `crate::oidc::OidcTrustedService::get_attributes_for_actor`).
pub(crate) fn lookup_identities<'a>(
    lookup_keys: &[&str],
    attrs: impl Iterator<Item = &'a Attribute>,
) -> Vec<(String, String)> {
    let mut identities = Vec::new();
    for attr in attrs {
        if lookup_keys.contains(&attr.get_key()) || attr.get_key() == key::USER_AUTHORITY {
            if let Ok(value) = attr.get_single_value() {
                identities.push((attr.get_key().to_string(), value.to_string()));
            }
        }
    }
    identities
}

/// Prefix of attribute keys in the user identity namespace.
const USER_NAMESPACE_PREFIX: &str = "user.";

/// Derive the bootstrap-era `user.zpr.authority` attribute from one trusted service's
/// results (#324 follow-up). A trusted service that vends `user.*` attributes for an
/// actor is the authority asserting that user identity, so the service's source id
/// becomes the authority value — the same shape as the RSA bootstrap path using
/// `zpr-bootstrap` as the `device.zpr.authority` value. The derived attribute expires
/// with the earliest-expiring vended user attribute, so the authority never outlives
/// the user record it vouches for, and is stamped with the service's source so the
/// refresh path prunes it together with that record.
///
/// Returns None when the service vended no `user.*` attributes (a device with no user
/// record in any trusted service must still not match a bare `allow users ...` rule —
/// the fail-closed property of #144 survives), and when the service explicitly vended
/// `user.zpr.authority` itself (it is asserting the authority directly; nothing to
/// derive).
pub(crate) fn derive_user_authority(source_id: &str, ts_attrs: &[Attribute]) -> Option<Attribute> {
    if ts_attrs.iter().any(|a| a.get_key() == key::USER_AUTHORITY) {
        return None;
    }
    let expires = ts_attrs
        .iter()
        .filter(|a| a.get_key().starts_with(USER_NAMESPACE_PREFIX))
        .map(|a| a.get_expires())
        .min()?;
    Some(
        AttributeSource::new(source_id)
            .builder(key::USER_AUTHORITY)
            .expires(expires)
            .value(source_id),
    )
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

#[cfg(test)]
mod derive_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    /// Build a source-stamped attribute expiring `secs` seconds from now.
    fn attr(source: &str, key: &str, value: &str, secs: u64) -> Attribute {
        AttributeSource::new(source)
            .builder(key)
            .expires(SystemTime::now() + Duration::from_secs(secs))
            .value(value)
    }

    /// A source vending `user.*` attributes yields a derived `user.zpr.authority`
    /// valued with the source id, stamped with that source, and expiring with the
    /// earliest-expiring vended user attribute.
    #[test]
    fn test_derive_user_authority_from_user_attrs() {
        let attrs = vec![
            attr("bas", "user.clearance", "classified", 600),
            attr("bas", "user.dept", "engineering", 300),
            attr("bas", "device.zpr.location", "hq", 60),
        ];
        let authority = derive_user_authority("bas", &attrs).expect("authority expected");
        assert_eq!(authority.get_key(), key::USER_AUTHORITY);
        assert_eq!(authority.get_value(), ["bas".to_string()]);
        assert_eq!(authority.get_source(), "bas");
        // Tracks the earliest user.* expiration (user.dept at ~300s), not the
        // device attribute's 60s and not user.clearance's 600s.
        assert_eq!(
            authority.get_expires(),
            attrs[1].get_expires(),
            "authority must expire with the earliest-expiring user attribute"
        );
    }

    /// A source vending only device attributes (or nothing) derives no user
    /// authority, preserving the fail-closed property of #144 for bare
    /// `allow users ...` rules.
    #[test]
    fn test_derive_user_authority_none_without_user_attrs() {
        let device_only = vec![attr("bas", "device.zpr.location", "hq", 600)];
        assert!(derive_user_authority("bas", &device_only).is_none());
        assert!(derive_user_authority("bas", &[]).is_none());
    }

    /// A source that vends `user.zpr.authority` itself asserts the authority
    /// directly; nothing is derived on top of it.
    #[test]
    fn test_derive_user_authority_defers_to_explicit() {
        let attrs = vec![
            attr("bas", key::USER_AUTHORITY, "custom-authority", 600),
            attr("bas", "user.dept", "engineering", 300),
        ];
        assert!(derive_user_authority("bas", &attrs).is_none());
    }

    /// `user.zpr.authority` is always part of the lookup-identity set when the
    /// actor carries it (PR #5 review): it scopes per-issuer identities like an
    /// OIDC `sub` to the service that vouched for them, so it must reach the
    /// stores even though policy never declares it as an identity attribute.
    #[test]
    fn test_lookup_identities_includes_user_authority() {
        let attrs = vec![
            attr("google", key::USER_AUTHORITY, "google", 600),
            attr("google", "user.oidc-subject", "s-123", 600),
            attr("bas", "user.dept", "engineering", 600),
        ];
        let identities = lookup_identities(&["user.oidc-subject"], attrs.iter());
        assert!(
            identities.contains(&(key::USER_AUTHORITY.to_string(), "google".to_string())),
            "the authority pair must be in the lookup set: {identities:?}"
        );
        assert!(identities.contains(&("user.oidc-subject".to_string(), "s-123".to_string())));
        // Non-identity attributes still never leak into the lookup set.
        assert!(!identities.iter().any(|(k, _)| k == "user.dept"));

        // And it is not duplicated when policy also names it a lookup key.
        let identities =
            lookup_identities(&["user.oidc-subject", key::USER_AUTHORITY], attrs.iter());
        assert_eq!(
            identities
                .iter()
                .filter(|(k, _)| k == key::USER_AUTHORITY)
                .count(),
            1
        );
    }
}
