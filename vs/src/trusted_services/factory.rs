//! Construction of trusted-service implementations from policy declarations.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libeval::policy::Policy;
use zpr::policy_types::{ServiceType, TrustedService};

use crate::error::ServiceError;
use crate::oidc::{KeySource, OidcTrustedService, ProxyResolver};

use super::TrustedServiceInterface;
use super::attribute_mapper::AttributeMapper;
use super::file_attribute_store::FileAttributeStore;

/// API name used by file-backed trusted services.
const TS_API_FILE: &str = "file";

/// API name used by OIDC identity-provider trusted services.
pub const TS_API_OIDC: &str = "oidc";

/// One policy-declared trusted service, reduced to the inputs that determine its store
/// instance. Comparing these across policies tells us whether the live stores are still
/// correct, so an unchanged declaration can keep its store (and its revision). The
/// embedded `record` carries the `oidc` config, so an OIDC config change (issuer,
/// client_id, keys, ...) breaks equality and rebuilds the store.
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
        if api != TS_API_FILE && api != TS_API_OIDC {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': unsupported api '{api}'",
                service.id
            )));
        }
        // File stores resolve `<id>.json` on disk, so the id must be a plain filename.
        if api == TS_API_FILE && (service.id.contains('/') || service.id.contains("..")) {
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
        if api == TS_API_OIDC && trusted_service.oidc.is_none() {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': api 'oidc' requires an oidc config in the policy record",
                service.id
            )));
        }

        definitions.push(TrustedServiceDefinition {
            id: service.id.clone(),
            api: api.clone(),
            record: trusted_service.clone(),
        });
    }

    Ok(definitions)
}

/// Build one store per declaration. File stores load their initial attribute
/// snapshot from `file_ts_dir`; OIDC stores build their JWKS key source from the
/// policy config, with `proxy_for(service_id)` supplying the CONNECT-proxy
/// resolver each refresh consults (see `crate::oidc::ProxyResolver`).
///
/// Returns the full `dyn` store list plus its typed OIDC subset (each OIDC
/// store appears in both), so `TrustedServicesMgr` can serve
/// `oidc_service_for_issuer` lookups for the connect path.
pub fn build_services(
    definitions: &[TrustedServiceDefinition],
    file_ts_dir: &Path,
    proxy_for: &dyn Fn(&str) -> ProxyResolver,
) -> Result<
    (
        Vec<Arc<dyn TrustedServiceInterface>>,
        Vec<Arc<OidcTrustedService>>,
    ),
    ServiceError,
> {
    let mut services: Vec<Arc<dyn TrustedServiceInterface>> = Vec::new();
    let mut oidc_services: Vec<Arc<OidcTrustedService>> = Vec::new();
    for definition in definitions {
        match definition.api.as_str() {
            TS_API_OIDC => {
                let Some(cfg) = &definition.record.oidc else {
                    // trusted_service_definitions already rejects this; fail
                    // closed anyway rather than panic on a hand-built definition.
                    return Err(ServiceError::Param(format!(
                        "trusted service '{}': api 'oidc' requires an oidc config",
                        definition.id
                    )));
                };
                let keys =
                    KeySource::from_policy(cfg, proxy_for(&definition.id)).map_err(|error| {
                        ServiceError::TrustedServiceInit(format!(
                            "TS '{}' failed to build JWKS key source: {error}",
                            definition.id
                        ))
                    })?;
                let store = Arc::new(OidcTrustedService::new(&definition.record, Arc::new(keys))?);
                oidc_services.push(store.clone());
                services.push(store);
            }
            _ => {
                let store = FileAttributeStore::new(
                    definition.id.clone(),
                    AttributeMapper {
                        mappings: definition.record.returns_attrs.clone(),
                    },
                    Duration::from_secs(definition.record.expiration_seconds as u64),
                    &file_ts_dir.join(format!("{}.json", definition.id)),
                )?;
                services.push(Arc::new(store));
            }
        }
    }
    Ok((services, oidc_services))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zpr::policy_types::PolicyContainerBytes;

    use crate::loaded_policy::LoadedPolicy;
    use crate::oidc::static_proxy;
    use crate::test_helpers::{
        make_oidc_policy, make_test_oidc_config, make_trusted_service_policy,
    };

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
    /// Yields only the `dyn` list; the typed OIDC subset is manager plumbing.
    fn build_from_policy(
        policy: &Policy,
        dir: &std::path::Path,
    ) -> Result<Vec<Arc<dyn TrustedServiceInterface>>, ServiceError> {
        build_services(&trusted_service_definitions(policy)?, dir, &|_id| {
            static_proxy(None)
        })
        .map(|(services, _oidc)| services)
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

        assert_eq!(
            defs_a, defs_a_again,
            "identical declarations must compare equal"
        );
        assert_ne!(
            defs_a, defs_b,
            "an oidc config change must break definition equality"
        );
    }

    /// Two oidc declarations for the SAME issuer are ambiguous (PR #5 review):
    /// which store validates a token would depend on unordered service
    /// iteration, so the policy is rejected with an error naming both services
    /// and the issuer — mirroring the compiler-side collision handling.
    #[test]
    fn test_duplicate_oidc_issuer_rejected() {
        use crate::test_helpers::{TrustedServiceSpec, make_trusted_services_policy};

        let spec = |id: &'static str| TrustedServiceSpec {
            id,
            api: "oidc",
            expiration_seconds: Some(300),
            mappings: &["sub -> user.oidc-subject"],
            identity: &["sub"],
            oidc: Some(make_test_oidc_config()), // same issuer both times
        };
        let policy = policy_from_container(make_trusted_services_policy(&[
            spec("idp-a"),
            spec("idp-b"),
        ]));

        let err = match trusted_service_definitions(&policy) {
            Err(e) => e,
            Ok(_) => panic!("duplicate oidc issuers must be rejected"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("idp-a") && msg.contains("idp-b"), "{msg}");
        assert!(msg.contains("https://accounts.google.com"), "{msg}");
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
