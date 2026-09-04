//! The `api = "oidc"` trusted service (OIDC master plan C4).
//!
//! Unlike file/network trusted services an OIDC provider cannot be *queried*
//! for an arbitrary identity: the claims arrive with the validated `id_token`.
//! The connect path (C5) calls [`OidcTrustedService::admit`] after validation;
//! [`crate::trusted_services::TrustedServiceInterface::get_attributes_for_actor`]
//! then serves those cached claims, so the normal ts_mgr union/conflict/refresh
//! machinery applies unchanged.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::{KeySource, ValidatedToken, static_proxy};
    use crate::test_helpers::make_test_oidc_config;
    use crate::trusted_services::TrustedServiceInterface;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use zpr::policy_types::{TrustedService, parse_attribute_mapping};

    /// The `TrustedService` policy record an `api = "oidc"` declaration carries.
    fn make_record(mappings: &[&str]) -> TrustedService {
        TrustedService {
            service_id: "google".to_string(),
            expiration_seconds: 300,
            returns_attrs: mappings
                .iter()
                .map(|m| parse_attribute_mapping(m).unwrap())
                .collect(),
            identity_attrs: vec!["sub".to_string()],
            oidc: Some(make_test_oidc_config()),
        }
    }

    /// A store over the fixture OIDC config, seeded from policy (no network).
    fn make_store(mappings: &[&str]) -> OidcTrustedService {
        let record = make_record(mappings);
        let keys = Arc::new(
            KeySource::from_policy(record.oidc.as_ref().unwrap(), static_proxy(None)).unwrap(),
        );
        OidcTrustedService::new(&record, keys).unwrap()
    }

    /// A validated token for `sub`, carrying a verified email when given (an
    /// unverified email never reaches `raw_claims` — the C2 validator strips it).
    fn make_token(sub: &str, email: Option<&str>) -> ValidatedToken {
        let mut raw_claims = serde_json::Map::new();
        raw_claims.insert("sub".to_string(), json!(sub));
        raw_claims.insert("hd".to_string(), json!("example.com"));
        if let Some(email) = email {
            raw_claims.insert("email".to_string(), json!(email));
        }
        ValidatedToken {
            sub: sub.to_string(),
            email: email.map(str::to_string),
            hd: Some("example.com".to_string()),
            auth_time: SystemTime::now(),
            raw_claims,
        }
    }

    const MAPPINGS: &[&str] = &["sub -> user.oidc-subject", "email -> user.email"];

    /// admit -> lookup round-trips: the mapped claims come back for the
    /// `(mapped sub key, sub)` identity, stamped with the given expiry and the
    /// service's source id.
    #[tokio::test]
    async fn test_admit_then_lookup_by_sub() {
        let store = make_store(MAPPINGS);
        assert_eq!(store.get_source_id(), "google");
        let expires = SystemTime::now() + Duration::from_secs(300);

        let admitted = store
            .admit(&make_token("s-123", Some("jane@example.com")), expires)
            .unwrap();
        assert!(!admitted.is_empty());

        let attrs = store
            .get_attributes_for_actor(&[("user.oidc-subject".to_string(), "s-123".to_string())])
            .await
            .unwrap();
        let sub_attr = attrs
            .iter()
            .find(|a| a.get_key() == "user.oidc-subject")
            .expect("mapped sub attribute");
        assert_eq!(sub_attr.get_single_value().unwrap(), "s-123");
        assert_eq!(sub_attr.get_expires(), expires);
        assert_eq!(sub_attr.get_source(), "google");

        let email_attr = attrs
            .iter()
            .find(|a| a.get_key() == "user.email")
            .expect("mapped email attribute");
        assert_eq!(email_attr.get_single_value().unwrap(), "jane@example.com");
        assert_eq!(email_attr.get_expires(), expires);
    }

    /// A sub never admitted yields no attributes, and a matching value under a
    /// non-sub identity key never matches either.
    #[tokio::test]
    async fn test_lookup_unknown_sub_is_empty() {
        let store = make_store(MAPPINGS);
        let expires = SystemTime::now() + Duration::from_secs(300);
        store
            .admit(&make_token("s-123", Some("jane@example.com")), expires)
            .unwrap();

        let attrs = store
            .get_attributes_for_actor(&[("user.oidc-subject".to_string(), "s-999".to_string())])
            .await
            .unwrap();
        assert!(attrs.is_empty());

        // The admitted value under the wrong identity key is not an identity match.
        let attrs = store
            .get_attributes_for_actor(&[(
                "device.zpr.adapter.cn".to_string(),
                "s-123".to_string(),
            )])
            .await
            .unwrap();
        assert!(attrs.is_empty());
    }

    /// A token whose email was unverified (email == None, stripped from
    /// raw_claims by the validator) must never produce a `user.email` attribute.
    #[tokio::test]
    async fn test_email_not_mapped_when_unverified() {
        let store = make_store(MAPPINGS);
        let expires = SystemTime::now() + Duration::from_secs(300);

        let admitted = store.admit(&make_token("s-123", None), expires).unwrap();
        assert!(admitted.iter().all(|a| a.get_key() != "user.email"));

        let attrs = store
            .get_attributes_for_actor(&[("user.oidc-subject".to_string(), "s-123".to_string())])
            .await
            .unwrap();
        assert!(attrs.iter().all(|a| a.get_key() != "user.email"));
        // The sub itself still maps.
        assert!(attrs.iter().any(|a| a.get_key() == "user.oidc-subject"));
    }

    /// flush drops every admitted record: the next lookup finds nothing.
    #[tokio::test]
    async fn test_flush_clears_admitted() {
        let store = make_store(MAPPINGS);
        let expires = SystemTime::now() + Duration::from_secs(300);
        store
            .admit(&make_token("s-123", Some("jane@example.com")), expires)
            .unwrap();

        store.flush().await.unwrap();

        let attrs = store
            .get_attributes_for_actor(&[("user.oidc-subject".to_string(), "s-123".to_string())])
            .await
            .unwrap();
        assert!(attrs.is_empty());
    }

    /// Admitting a token advances the store revision, so the ts_mgr refresh
    /// machinery sees actors as stale against the new snapshot.
    #[tokio::test]
    async fn test_admit_bumps_revision() {
        let store = make_store(MAPPINGS);
        let before = store.current_revision();
        store
            .admit(
                &make_token("s-123", Some("jane@example.com")),
                SystemTime::now() + Duration::from_secs(300),
            )
            .unwrap();
        assert!(store.current_revision() > before);
    }
}
