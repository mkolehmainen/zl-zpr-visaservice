//! The `api = "zpr-attr/1"` attribute-service store (zipline#72 / #78, V1).
//!
//! A *decorating* trusted service: it never authenticates anyone and is
//! queried by the identity attributes other services established, exactly
//! like a `file` store — except the answer comes from `POST {url}/query`
//! over pinned TLS with a per-declaration bearer token. Normative contract:
//! `docs/ATTRIBUTE_SERVICE.md` (the wire protocol, the five read-order
//! rules, and the fail-closed table).
//!
//! **Stateless**: the store holds no attribute cache. The actor's own
//! attribute expiry is the cache — `refresh_expired_attributes` re-queries a
//! source only when an attribute expired or the revision moved, so a
//! snapshot cache here would just be a second TTL to reason about.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use libeval::attribute::{Attribute, AttributeSource};
use tracing::{debug, info, warn};
use zpr::policy_types::{AttrQueryConfig, TrustedService};

use crate::error::ServiceError;
use crate::http_util::read_body_capped;
use crate::logging::targets::TS;

use super::attribute_mapper::{AttrHint, AttributeMapper};
use super::{TrustedServiceInterface, next_revision};

/// Shortest attribute lifetime a declaration may configure — the same floor
/// the file store enforces (docs/ATTRIBUTE_SERVICE.md, *Declaring an
/// attribute service in policy*).
const MIN_ATTRIBUTE_TTL: Duration = Duration::from_secs(60);

/// Whole-request timeout when the policy record carries none (the compiler
/// defaults to 5 and caps at 30; a hand-built record decoding to 0 gets the
/// same default rather than no timeout at all).
const DEFAULT_QUERY_TIMEOUT_SECS: u32 = 5;

/// An `api = "zpr-attr/1"` trusted service: one HTTPS client pinned by
/// policy, one bearer token read from `<ts_secrets_dir>/<id>.token`, no
/// attribute cache.
pub(super) struct AttrQueryStore {
    /// Trusted-service id; also the source stamped on every vended attribute.
    id: String,
    /// `returns_attributes` mapping from service-side names to ZPR keys.
    mapper: AttributeMapper,
    /// Default and maximum lifetime of returned attributes, from policy.
    expiration: Duration,
    /// `{url}/query`, precomputed from the policy base URL.
    query_url: String,
    /// `{url}/schema`, precomputed from the policy base URL.
    schema_url: String,
    /// The per-declaration bearer token. Never logged, never in errors.
    token: String,
    /// One client per store: no redirects, the policy timeout, and the
    /// policy CA pin (exclusive when set — built-in roots disabled).
    client: reqwest::Client,
    /// Snapshot revision from the process-wide counter, so the ts_mgr
    /// staleness machinery treats this store like any other.
    revision: AtomicU64,
}

/// One attribute entry of a `/query` response. Unknown JSON fields are
/// tolerated (forward compatibility); a missing `values` is a shape error.
#[derive(Debug, Deserialize)]
struct QueryAttrEntry {
    values: Vec<String>,
    expires_at: Option<String>,
}

/// The `/query` response body: an object keyed by service-side name.
#[derive(Debug, Deserialize)]
struct QueryResponse {
    attributes: BTreeMap<String, QueryAttrEntry>,
}

/// One SCIM 2.0 attribute definition from `/schema` (RFC 7643 §7). Only the
/// fields the correspondence check reads are decoded; every other SCIM
/// field (`required`, `caseExact`, `mutability`, ...) is ignored.
#[derive(Debug, Deserialize)]
struct SchemaAttrDef {
    name: String,
    #[serde(rename = "type", default = "default_scim_type")]
    scim_type: String,
    #[serde(rename = "multiValued", default)]
    multi_valued: bool,
}

/// SCIM's default attribute type.
fn default_scim_type() -> String {
    "string".to_string()
}

/// The `/schema` response envelope: our `identityKeys` plus SCIM definitions.
#[derive(Debug, Deserialize)]
struct SchemaResponse {
    #[serde(rename = "identityKeys", default)]
    identity_keys: Vec<String>,
    #[serde(default)]
    attributes: Vec<SchemaAttrDef>,
}

impl AttrQueryStore {
    /// Build the store from its policy record: read the bearer token from
    /// `<ts_secrets_dir>/<id>.token` (trimmed; missing or empty fails the
    /// install — a store that cannot authenticate cannot answer), and build
    /// the pinned HTTPS client. The record must carry an `attr_query` config.
    pub(super) fn new(
        record: &TrustedService,
        ts_secrets_dir: &Path,
    ) -> Result<Self, ServiceError> {
        let id = record.service_id.clone();
        let Some(cfg) = &record.attr_query else {
            return Err(ServiceError::Param(format!(
                "trusted service '{id}': api 'zpr-attr/1' requires an attr_query config \
                 in the policy record"
            )));
        };

        let expiration = Duration::from_secs(record.expiration_seconds as u64);
        if expiration <= MIN_ATTRIBUTE_TTL {
            return Err(ServiceError::Param(format!(
                "trusted service '{id}' ttl {expiration:?} must exceed minimum of \
                 {MIN_ATTRIBUTE_TTL:?}"
            )));
        }

        let token_path = ts_secrets_dir.join(format!("{id}.token"));
        let token = std::fs::read_to_string(&token_path)
            .map_err(|error| {
                ServiceError::TrustedServiceInit(format!(
                    "TS '{id}' failed to read bearer token file {token_path:?}: {error}"
                ))
            })?
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(ServiceError::TrustedServiceInit(format!(
                "TS '{id}' bearer token file {token_path:?} is empty"
            )));
        }

        let client = build_client(&id, cfg)?;
        let base = cfg.url.trim_end_matches('/');
        Ok(AttrQueryStore {
            query_url: format!("{base}/query"),
            schema_url: format!("{base}/schema"),
            id,
            mapper: AttributeMapper {
                mappings: record.returns_attrs.clone(),
            },
            expiration,
            token,
            client,
            revision: AtomicU64::new(next_revision()),
        })
    }

    /// The install-time schema check (docs/ATTRIBUTE_SERVICE.md, `GET
    /// {url}/schema`): advisory only. Warns per mapped name the schema does
    /// not list, per spelling/definition mismatch under the correspondence
    /// table, and when `identityKeys` shares nothing with the policy's
    /// lookup-identity keys. Any failure to fetch or parse logs one `info`
    /// line — **a schema disagreement never fails a policy install**:
    /// policy is authoritative and an attribute-service outage must not
    /// block a policy fix.
    pub(super) async fn check_schema(&self, lookup_identity_keys: &[&str]) {
        let schema = match self.fetch_schema().await {
            Ok(schema) => schema,
            Err(reason) => {
                info!(
                    target: TS,
                    "TS {}: schema check skipped ({reason}); policy is authoritative",
                    self.id
                );
                return;
            }
        };

        let defs: BTreeMap<&str, &SchemaAttrDef> = schema
            .attributes
            .iter()
            .map(|def| (def.name.as_str(), def))
            .collect();
        for mapping in &self.mapper.mappings {
            let name = mapping.service_attr_key.as_str();
            let Some(def) = defs.get(name) else {
                warn!(
                    target: TS,
                    "TS {}: mapped attribute '{name}' is not in the service schema",
                    self.id
                );
                continue;
            };
            // The correspondence table: what the policy spelling of this
            // mapping expects the SCIM definition to look like.
            let attr = &mapping.attr;
            let mismatch = if attr.is_tag() {
                // Tag: `type: boolean`, single-valued.
                def.scim_type != "boolean" || def.multi_valued
            } else if attr.is_multi_valued() {
                // Multi-valued: any type but boolean or complex, multiValued.
                def.scim_type == "boolean" || def.scim_type == "complex" || !def.multi_valued
            } else {
                // Single-valued: any type but boolean or complex, not multiValued.
                def.scim_type == "boolean" || def.scim_type == "complex" || def.multi_valued
            };
            if mismatch {
                warn!(
                    target: TS,
                    "TS {}: mapped attribute '{name}' disagrees with its schema definition \
                     (type '{}', multiValued {}) under the policy spelling",
                    self.id, def.scim_type, def.multi_valued
                );
            }
        }

        if !schema.identity_keys.is_empty()
            && !schema
                .identity_keys
                .iter()
                .any(|key| lookup_identity_keys.contains(&key.as_str()))
        {
            warn!(
                target: TS,
                "TS {}: schema identityKeys {:?} share nothing with the policy's \
                 lookup-identity keys {:?} — the service can never match an actor",
                self.id, schema.identity_keys, lookup_identity_keys
            );
        }
    }

    /// `GET {url}/schema` with the bearer token, capped and parsed. Errors
    /// come back as a reason string for the caller's single `info` line.
    async fn fetch_schema(&self) -> Result<SchemaResponse, String> {
        let mut resp = self
            .client
            .get(&self.schema_url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("schema fetch failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("schema endpoint returned status {status}"));
        }
        let body = read_body_capped(&mut resp, "schema response")
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice(&body).map_err(|_| "schema response does not parse".to_string())
    }
}

/// Build the store's `reqwest::Client`: never follow a redirect (a redirect
/// is a way to move a request to a host the pin does not cover), apply the
/// policy timeout, and when `ca_cert_pem` is set trust ONLY those roots.
/// reqwest 0.13 spells the exclusive pin `tls_certs_only(certs)` — the
/// 0.12-era `tls_built_in_root_certs(false)` + `add_root_certificate` pair
/// in the plan — so with a pin the built-in roots are disabled and a
/// certificate for the same hostname chaining to a public CA is rejected.
/// The pin is exclusive, never additive.
fn build_client(id: &str, cfg: &AttrQueryConfig) -> Result<reqwest::Client, ServiceError> {
    let timeout_seconds = if cfg.timeout_seconds == 0 {
        DEFAULT_QUERY_TIMEOUT_SECS
    } else {
        cfg.timeout_seconds
    };
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds as u64))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(pem) = cfg
        .ca_cert_pem
        .as_deref()
        .filter(|pem| !pem.trim().is_empty())
    {
        let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes()).map_err(|e| {
            ServiceError::TrustedServiceInit(format!(
                "TS '{id}' ca_cert_pem does not parse as PEM certificates: {e}"
            ))
        })?;
        if certs.is_empty() {
            return Err(ServiceError::TrustedServiceInit(format!(
                "TS '{id}' ca_cert_pem holds no CERTIFICATE block"
            )));
        }
        builder = builder.tls_certs_only(certs);
    }
    builder.build().map_err(|e| {
        ServiceError::TrustedServiceInit(format!("TS '{id}' failed to build HTTP client: {e}"))
    })
}

#[async_trait]
impl TrustedServiceInterface for AttrQueryStore {
    /// One `POST {url}/query` per lookup, mapped and validated under the
    /// spec's read-order rules (docs/ATTRIBUTE_SERVICE.md):
    ///
    /// 1. anything but a well-formed `200` — bad status (a `404` means the
    ///    URL is wrong, never "unknown actor"; a `409` is the service
    ///    refusing to pick between conflicting records), transport error,
    ///    timeout, oversized body, malformed body — is an `Err`, and the
    ///    caller makes the actor indeterminate;
    /// 2. returned names are mapped through `returns_attributes`; unmapped
    ///    names are dropped silently;
    /// 3. a single-valued mapping whose `values` holds more than one element
    ///    is an `Err` for the whole response;
    /// 4. a single- or multi-valued mapping with empty `values` is absent;
    ///    a tag's presence is the tag and its `values` are ignored;
    /// 5. expiry is `min(expires_at, now + expiration_seconds)` — policy
    ///    shortens, never extends; already-past means absent — and every
    ///    attribute is stamped with this store's id.
    ///
    /// An unknown actor is `{"attributes": {}}`: a successful, empty answer.
    /// Attribute values never reach logs above `debug`.
    async fn get_attributes_for_actor(
        &self,
        identities: &[(String, String)],
    ) -> Result<Vec<Attribute>, ServiceError> {
        // The request body from the spec: the lookup-identity set as ZPR key
        // names, plus the service-side names we will keep (a hint the
        // service may ignore; the mapping filters the response regardless).
        let identities_body: serde_json::Map<String, serde_json::Value> = identities
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect();
        let attributes_hint: Vec<&str> = self
            .mapper
            .mappings
            .iter()
            .map(|m| m.service_attr_key.as_str())
            .collect();
        let body = serde_json::json!({
            "identities": identities_body,
            "attributes": attributes_hint,
        });

        let mut resp = self
            .client
            .post(&self.query_url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                // reqwest errors name the URL, never the request body.
                ServiceError::Internal(format!("TS '{}' query failed: {e}", self.id))
            })?;
        let status = resp.status();
        if !status.is_success() {
            // Rule 1: every non-200 is a deny, logged by status for the
            // operator; a 404 is a wrong URL, never an unknown actor.
            return Err(ServiceError::Internal(format!(
                "TS '{}' query returned status {status}",
                self.id
            )));
        }
        let raw = read_body_capped(&mut resp, "attribute query response").await?;
        let parsed: QueryResponse = serde_json::from_slice(&raw).map_err(|_| {
            // Never echo the body: attribute values are personal data.
            ServiceError::Internal(format!(
                "TS '{}' query response does not parse to the zpr-attr/1 shape",
                self.id
            ))
        })?;

        let now = SystemTime::now();
        let policy_ceiling = now + self.expiration;
        let src = AttributeSource::new(self.id.clone());
        let mut mapped: BTreeMap<String, Attribute> = BTreeMap::new();
        for (name, entry) in &parsed.attributes {
            // Rule 2: unmapped names were never going to become attributes.
            let Some((zpr_key, hint)) = self.mapper.map_attribute(name) else {
                debug!(target: TS, "TS {}: dropping unmapped attribute '{name}'", self.id);
                continue;
            };

            // Rule 5: policy can shorten a lifetime but never extend one,
            // and a value already in the past makes the attribute absent.
            let expires = match entry.expires_at.as_deref() {
                None => policy_ceiling,
                Some(stamp) => {
                    let parsed_at = chrono::DateTime::parse_from_rfc3339(stamp).map_err(|_| {
                        ServiceError::Internal(format!(
                            "TS '{}' attribute '{name}' carries a malformed expires_at",
                            self.id
                        ))
                    })?;
                    SystemTime::from(parsed_at).min(policy_ceiling)
                }
            };
            if expires <= now {
                continue;
            }

            let builder = src.builder(zpr_key.clone()).expires(expires);
            let attr = match hint {
                AttrHint::SingleValued => {
                    if entry.values.len() > 1 {
                        // Rule 3: the service and the policy disagree about
                        // what this attribute IS; picking the first element
                        // would tie authorization to iteration order.
                        return Err(ServiceError::Internal(format!(
                            "TS '{}' returned {} values for single-valued attribute '{name}'",
                            self.id,
                            entry.values.len()
                        )));
                    }
                    // Rule 4: empty values on a non-tag means absent.
                    let Some(value) = entry.values.first() else {
                        continue;
                    };
                    builder.value(value.clone())
                }
                AttrHint::MultiValued => {
                    if entry.values.is_empty() {
                        continue; // rule 4
                    }
                    builder.values(entry.values.clone())
                }
                // A tag is valueless: the name's presence is the tag.
                AttrHint::Tag => builder.values(Vec::<String>::new()),
            };

            // Two service-side names mapping to the same ZPR key must agree,
            // the same fail-closed conflict rule every store implements.
            // Names only in the error — values never reach logs.
            if let Some(existing) = mapped.get(&zpr_key) {
                if existing.get_value() != attr.get_value() {
                    return Err(ServiceError::Internal(format!(
                        "TS '{}': two returned attributes disagree on '{zpr_key}'",
                        self.id
                    )));
                }
                continue;
            }
            mapped.insert(zpr_key, attr);
        }
        Ok(mapped.into_values().collect())
    }

    /// Bump the revision so every actor becomes stale for this source and is
    /// re-queried. There is no cache to drop — the store is stateless.
    async fn flush(&self) -> Result<(), ServiceError> {
        self.revision.store(next_revision(), Ordering::SeqCst);
        Ok(())
    }

    fn current_revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    fn get_source_id(&self) -> &str {
        &self.id
    }
}
