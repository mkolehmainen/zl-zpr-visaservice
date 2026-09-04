//! Construction of trusted-service implementations from policy declarations.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libeval::policy::Policy;
use zpr::policy_types::{ServiceType, TrustedService};

use crate::error::ServiceError;

use super::TrustedServiceInterface;
use super::attribute_mapper::AttributeMapper;
use super::file_attribute_store::FileAttributeStore;

/// API name used by file-backed trusted services.
const TS_API_FILE: &str = "file";

/// One policy-declared trusted service, reduced to the inputs that determine its store
/// instance. Comparing these across policies tells us whether the live stores are still
/// correct, so an unchanged declaration can keep its store (and its revision).
#[derive(Debug, Clone, PartialEq)]
pub struct TrustedServiceDefinition {
    id: String,
    api: String,
    record: TrustedService,
}

/// Validate and extract the trusted services a policy declares.
pub fn trusted_service_definitions(
    policy: &Policy,
) -> Result<Vec<TrustedServiceDefinition>, ServiceError> {
    let mut definitions = Vec::new();

    for service in policy.list_services() {
        let ServiceType::Trusted(api) = &service.kind else {
            continue;
        };
        if api != TS_API_FILE {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': unsupported api '{api}'",
                service.id
            )));
        }
        if service.id.contains('/') || service.id.contains("..") {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': id is not a plain filename",
                service.id
            )));
        }
        let Some(trusted_service) = policy.trusted_service_by_id(&service.id) else {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': no trusted service record in policy",
                service.id
            )));
        };

        definitions.push(TrustedServiceDefinition {
            id: service.id.clone(),
            api: api.clone(),
            record: trusted_service.clone(),
        });
    }

    Ok(definitions)
}

/// Build one store per declaration, loading each initial attribute snapshot.
pub fn build_services(
    definitions: &[TrustedServiceDefinition],
    file_ts_dir: &Path,
) -> Result<Vec<Arc<dyn TrustedServiceInterface>>, ServiceError> {
    definitions
        .iter()
        .map(|definition| {
            let store = FileAttributeStore::new(
                definition.id.clone(),
                AttributeMapper {
                    mappings: definition.record.returns_attrs.clone(),
                },
                Duration::from_secs(definition.record.expiration_seconds as u64),
                &file_ts_dir.join(format!("{}.json", definition.id)),
            )?;
            Ok(Arc::new(store) as Arc<dyn TrustedServiceInterface>)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zpr::policy_types::PolicyContainerBytes;

    use crate::loaded_policy::LoadedPolicy;
    use crate::oidc::static_proxy;
    use crate::test_helpers::{make_oidc_policy, make_test_oidc_config, make_trusted_service_policy};

    /// Decode a test policy container into its policy representation.
    fn policy_from_container(container_bytes: Vec<u8>) -> Arc<Policy> {
        let loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(container_bytes),
            &crate::config::POLICY_MIN_VERSION,
        )
        .unwrap();
        loaded.policy()
    }

    /// Validate and build in one step, as `PolicyMgr` does for a brand-new policy.
    fn build_from_policy(
        policy: &Policy,
        dir: &std::path::Path,
    ) -> Result<Vec<Arc<dyn TrustedServiceInterface>>, ServiceError> {
        build_services(&trusted_service_definitions(policy)?, dir, &|_id| {
            static_proxy(None)
        })
    }

    /// A valid file declaration constructs a working mapped attribute store.
    #[tokio::test]
    async fn test_build_services_from_policy_happy_path() {
        let dir = std::env::temp_dir().join("vs-bsfp-ok");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        )
        .unwrap();

        let policy = policy_from_container(make_trusted_service_policy(
            "attrfile",
            "file",
            Some(3600),
            &["color -> user.color"],
        ));
        let stores = build_from_policy(&policy, &dir).unwrap();

        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].get_source_id(), "attrfile");
        let attrs = stores[0]
            .get_attributes_for_actor(&[("device.zpr.adapter.cn".to_string(), "alice".to_string())])
            .await
            .unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].get_key(), "user.color");
        assert!(attrs[0].value_has("red"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Invalid or unsupported declarations reject the policy atomically.
    #[test]
    fn test_build_services_from_policy_rejects_bad_declarations() {
        let dir = std::env::temp_dir().join("vs-bsfp-bad");
        std::fs::create_dir_all(&dir).unwrap();

        let cases = [
            ("attrfile", "file", Some(3600)),
            ("attrfile", "ldap", Some(3600)),
            ("attrfile", "file", None),
            ("attrfile", "file", Some(1)),
            ("../escape", "file", Some(3600)),
        ];
        for (id, api, seconds) in cases {
            let policy = policy_from_container(make_trusted_service_policy(id, api, seconds, &[]));
            assert!(
                build_from_policy(&policy, &dir).is_err(),
                "expected failure for id={id} api={api} seconds={seconds:?}"
            );
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An `api = "oidc"` declaration builds an OIDC trusted-service store (today the
    /// whole policy is rejected — the C4 acceptance case).
    #[test]
    fn test_oidc_definition_builds_oidc_store() {
        let dir = std::env::temp_dir().join("vs-bsfp-oidc-ok");
        std::fs::create_dir_all(&dir).unwrap();

        let policy = policy_from_container(make_oidc_policy(
            "google",
            300,
            &["sub -> user.oidc-subject", "email -> user.email"],
            &["sub"],
            make_test_oidc_config(),
        ));
        let stores = build_from_policy(&policy, &dir).unwrap();

        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].get_source_id(), "google");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two oidc declarations differing only in `OidcConfig.client_id` compare unequal,
    /// so a policy install rebuilds the store (the definition carries the full record,
    /// including its oidc config).
    #[test]
    fn test_oidc_definition_change_rebuilds_store() {
        let make_defs = |client_id: &str| {
            let mut cfg = make_test_oidc_config();
            cfg.client_id = client_id.to_string();
            let policy = policy_from_container(make_oidc_policy(
                "google",
                300,
                &["sub -> user.oidc-subject"],
                &["sub"],
                cfg,
            ));
            trusted_service_definitions(&policy).unwrap()
        };

        let defs_a = make_defs("client-a.apps.googleusercontent.com");
        let defs_a_again = make_defs("client-a.apps.googleusercontent.com");
        let defs_b = make_defs("client-b.apps.googleusercontent.com");

        assert_eq!(defs_a, defs_a_again, "identical declarations must compare equal");
        assert_ne!(
            defs_a, defs_b,
            "an oidc config change must break definition equality"
        );
    }

    /// `api = "oidc"` with no oidc record in the TrustedService is a policy error.
    #[test]
    fn test_oidc_definition_without_oidc_record_rejected() {
        let dir = std::env::temp_dir().join("vs-bsfp-oidc-norec");
        std::fs::create_dir_all(&dir).unwrap();

        // make_trusted_service_policy writes a TrustedService record with oidc: None.
        let policy = policy_from_container(make_trusted_service_policy(
            "google",
            "oidc",
            Some(300),
            &["sub -> user.oidc-subject"],
        ));
        let err = match build_from_policy(&policy, &dir) {
            Err(e) => e,
            Ok(_) => panic!("oidc service without an oidc record must be rejected"),
        };
        assert!(matches!(err, ServiceError::Param(_)), "{err:?}");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
