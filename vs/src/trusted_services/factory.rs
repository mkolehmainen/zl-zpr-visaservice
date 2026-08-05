//! Construction of trusted-service implementations from policy declarations.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libeval::policy::Policy;
use zpr::policy_types::ServiceType;

use crate::error::ServiceError;

use super::TrustedServiceInterface;
use super::attribute_mapper::AttributeMapper;
use super::file_attribute_store::FileAttributeStore;

/// API name used by file-backed trusted services.
const TS_API_FILE: &str = "file";

/// Build all trusted services declared by a policy.
pub fn build_services_from_policy(
    policy: &Policy,
    file_ts_dir: &Path,
) -> Result<Vec<Arc<dyn TrustedServiceInterface>>, ServiceError> {
    let mut stores: Vec<Arc<dyn TrustedServiceInterface>> = Vec::new();

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

        stores.push(Arc::new(FileAttributeStore::new(
            service.id.clone(),
            AttributeMapper {
                mappings: trusted_service.returns_attrs.clone(),
            },
            Duration::from_secs(trusted_service.expiration_seconds as u64),
            &file_ts_dir.join(format!("{}.json", service.id)),
        )?));
    }

    Ok(stores)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zpr::policy_types::PolicyContainerBytes;

    use crate::loaded_policy::LoadedPolicy;
    use crate::test_helpers::make_trusted_service_policy;

    /// Decode a test policy container into its policy representation.
    fn policy_from_container(container_bytes: Vec<u8>) -> Arc<Policy> {
        let loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(container_bytes),
            &crate::config::POLICY_MIN_VERSION,
        )
        .unwrap();
        loaded.policy()
    }

    /// A valid file declaration constructs a working mapped attribute store.
    #[tokio::test]
    async fn test_build_services_from_policy_happy_path() {
        let dir = std::env::temp_dir().join("vs-bsfp-ok");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"alice": {"color": ["red"]}}"#,
        )
        .unwrap();

        let policy = policy_from_container(make_trusted_service_policy(
            "attrfile",
            "file",
            Some(3600),
            &["color -> user.color"],
        ));
        let stores = build_services_from_policy(&policy, &dir).unwrap();

        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].get_source_id(), "attrfile");
        let attrs = stores[0].get_attributes_for_actor("alice").await.unwrap();
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
                build_services_from_policy(&policy, &dir).is_err(),
                "expected failure for id={id} api={api} seconds={seconds:?}"
            );
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
