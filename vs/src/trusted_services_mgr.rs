//! Trusted Services Manager
//!
//! Placeholder for eventual comprehensive management of the trusted services.

use async_trait::async_trait;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::future::join_all;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;

use tracing::{debug, info};

use libeval::attribute::{Attribute, AttributeSource};
use libeval::policy::Policy;

use zpr::policy_types::{AttrMapping, ServiceType};

use crate::error::ServiceError;
use crate::logging::targets::TS;

/// The api name in `ServiceType::Trusted(<api>)` served by [`FileAttributeStore`].
const TS_API_FILE: &str = "file";

/// Shortest TTL we are willing to stamp on an emitted attribute. When a store's cached
/// data has less than this left, it refreshes early rather than hand a consumer something
/// that expires almost immediately.
const MIN_ATTRIBUTE_TTL: Duration = Duration::from_secs(60);

/// Process-wide source of snapshot revisions: every snapshot ever built in this
/// process gets a distinct value, across all services. Not durable.
/// The per-actor revision records are in-memory too, so both reset together on
/// restart and "missing record = stale" forces a safe refresh.
static REVISION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A revision no snapshot will ever carry (the counter starts at 1). Recording it for
/// an actor keeps a source relevant-and-stale, forcing a retry on the next request —
/// used when a revision-triggered refresh fails and the source's attributes were
/// stripped fail-closed.
pub const REVISION_NEVER: u64 = 0;

/// Hand out the next snapshot revision.
fn next_revision() -> u64 {
    REVISION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Interface for trusted services that can provide attributes for actors.
#[async_trait]
pub trait TrustedServiceInterface: Send + Sync {
    /// Must return attributes for the actor. If actor is unknown returns an empty vector.
    /// TODO: Maybe better to return None. Maybe in future we want to know if actor is not found?
    async fn get_attributes_for_actor(
        &self,
        actor_ident: &str,
    ) -> Result<Vec<Attribute>, ServiceError>;

    /// Drop any cached attribute data so the next lookup fetches fresh.
    ///
    /// A store that caches but forgets to override this would silently ignore
    /// flushes. Implementors holding no cache should return `Ok(())`.
    async fn flush(&self) -> Result<(), ServiceError>;

    /// Revision of the data the service currently serves; bumps whenever the data may
    /// have changed (flush or reload). Implementors without snapshots (e.g. test fakes)
    /// return a counter of their own flushes.
    fn current_revision(&self) -> u64;

    fn get_source_id(&self) -> &str;
}

/// Here we sketch out a manager for a bunch of interfaces to "trusted services" which
/// are able to return attributes for actors. These will usually require a network
/// request and so may be slow.
///
/// This manager needs to support a lot of concurrent reads and very infrequent updates of
/// the underlying set of services.
pub struct TrustedServicesMgr {
    services: ArcSwap<Vec<Arc<dyn TrustedServiceInterface>>>,

    /// Per actor (keyed by CN): the revision of each source the actor's
    /// attributes were last refreshed from. Memory-only; a missing entry reads
    /// as "stale", which seems safe (forces a refresh on the actor's next visa
    /// request).
    ///
    // TODO: for now entries are never evicted — bounded by distinct CNs seen since process
    // start. I think we are going to rework attributes soon. I'm not sure it makes sense to
    // keep then "on" the actors. I think we want to manage attribute data as its own thing
    // especially as we want to support multiple credentials for attribute sources.
    actor_revisions: DashMap<String, HashMap<String, u64>>,
}

impl TrustedServicesMgr {
    /// Create a new TrustedServicesMgr instance with no services.
    pub fn new() -> Self {
        TrustedServicesMgr {
            services: ArcSwap::new(Arc::new(Vec::new())),
            actor_revisions: DashMap::new(),
        }
    }

    /// Get the sources needing a revision-triggered refresh for `actor_ident`: every
    /// registered service that appears in `attr_sources` (the sources of the actor's
    /// attributes) or in the actor's revision record, whose current revision differs
    /// from the recorded one. A missing record counts as stale.
    ///
    /// Returns `(source id, current revision at check time)` pairs; pass the revision
    /// back to [`Self::record_revision`] after a successful refresh so a flush racing
    /// the fetch re-triggers rather than being missed.
    pub fn stale_sources_for_actor(
        &self,
        actor_ident: &str,
        attr_sources: &HashSet<String>,
    ) -> Vec<(String, u64)> {
        let services = self.services.load_full();
        let recorded = self.actor_revisions.get(actor_ident);
        services
            .iter()
            .filter_map(|svc| {
                let sid = svc.get_source_id();
                let rec = recorded.as_ref().and_then(|r| r.value().get(sid).copied());
                // A service the actor holds no attributes from and has no record for is
                // not relevant to this actor.
                if rec.is_none() && !attr_sources.contains(sid) {
                    return None;
                }
                let cur = svc.current_revision();
                (rec != Some(cur)).then(|| (sid.to_string(), cur))
            })
            .collect()
    }

    /// Record that `actor_ident`'s attributes from `source` are current as of
    /// `revision`. Call after a successful refresh (including one that returned zero
    /// attributes), or with [`REVISION_NEVER`] to pin the source stale for a retry.
    pub fn record_revision(&self, actor_ident: &str, source: &str, revision: u64) {
        self.actor_revisions
            .entry(actor_ident.to_string())
            .or_default()
            .insert(source.to_string(), revision);
    }

    /// Atomically replaces the whole service list.
    pub fn update_services(&self, services: Vec<Arc<dyn TrustedServiceInterface>>) {
        self.services.store(Arc::new(services));
    }

    /// Query all trusted services for attributes corresponding to the given actor.
    /// Returns a vector of results from each service.
    ///
    /// Many decisions are TODO here. This currently just supports our local file "service".
    pub async fn get_attributes_for_actor(
        &self,
        actor_ident: &str,
    ) -> Vec<Result<Vec<Attribute>, ServiceError>> {
        let snapshot = self.services.load_full(); // Arc<Vec<Arc<dyn ServiceInterface>>>

        let futures = snapshot.iter().map(|svc| {
            let svc = svc.clone(); // cheap Arc clone
            async move { svc.get_attributes_for_actor(actor_ident).await }
        });

        join_all(futures).await
    }

    /// Query all trusted services for attributes corresponding to the given actor.
    /// Returns a vector of results from each service.
    ///
    /// Many decisions are TODO here. This currently just supports our local file "service".
    pub async fn get_attributes_from_source_for_actor(
        &self,
        source_ident: &str,
        actor_ident: &str,
    ) -> Vec<Result<Vec<Attribute>, ServiceError>> {
        let snapshot = self.services.load_full(); // Arc<Vec<Arc<dyn ServiceInterface>>>

        // TODO: Find the service with the matching ident and call get_attributes_for_actor on it...
        if let Some(svc) = snapshot
            .iter()
            .find(|svc| svc.get_source_id() == source_ident)
        {
            let svc = svc.clone();
            return vec![svc.get_attributes_for_actor(actor_ident).await];
        }

        vec![Err(ServiceError::TrustedServiceNotFound(
            source_ident.to_string(),
        ))]
    }

    /// Ask every trusted service to drop its cached attribute data, so the next lookup
    /// fetches fresh. Returns one result per service.
    ///
    /// For api=file trusted services, this re-reads the file.
    #[allow(dead_code)]
    pub async fn flush_all(&self) -> Vec<Result<(), ServiceError>> {
        let snapshot = self.services.load_full();

        // TODO: I do not want a failure of one service to stop the rest of the flusing. I'd like to log the error.

        let futures = snapshot.iter().map(|svc| {
            let svc = svc.clone(); // cheap Arc clone
            async move { svc.flush().await }
        });

        join_all(futures).await
    }

    /// Flush one service. Error returned if the operation fails or service is not found.
    ///
    /// ### Errors
    /// - `ServiceError::TrustedServiceNotFound` if the service with the given `source_ident` does not exist.
    /// - Any error returned by the service's `flush` method.
    pub async fn flush_one(&self, source_ident: &str) -> Result<(), ServiceError> {
        let snapshot = self.services.load_full();

        if let Some(svc) = snapshot
            .iter()
            .find(|svc| svc.get_source_id() == source_ident)
        {
            let svc = svc.clone();
            return svc.flush().await;
        }

        Err(ServiceError::TrustedServiceNotFound(
            source_ident.to_string(),
        ))
    }
}

/// Build the trusted service stores (only works for local file at the moment)
/// declared by `policy`.
///
/// One store per `ServiceType::Trusted` service; for the `file` api the
/// attribute data is `<file_ts_dir>/<service-id>.json`. Any service that cannot
/// be built is an error, so a caller can run this before committing a policy
/// and reject the whole policy on failure.
///
pub fn build_services_from_policy(
    policy: &Policy,
    file_ts_dir: &Path,
) -> Result<Vec<Arc<dyn TrustedServiceInterface>>, ServiceError> {
    let mut stores: Vec<Arc<dyn TrustedServiceInterface>> = Vec::new();

    for svc in policy.list_services() {
        let ServiceType::Trusted(api) = &svc.kind else {
            continue;
        };
        if api != TS_API_FILE {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': unsupported api '{api}'",
                svc.id
            )));
        }
        // The id becomes a filename, so it must not be able to escape `file_ts_dir`.
        if svc.id.contains('/') || svc.id.contains("..") {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': id is not a plain filename",
                svc.id
            )));
        }
        let Some(ts) = policy.trusted_service_by_id(&svc.id) else {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': no trusted service record in policy",
                svc.id
            )));
        };

        // Covers the missing/unparseable file and the below-floor ttl (including an unset
        // expiration_seconds of 0).
        stores.push(Arc::new(FileAttributeStore::new(
            svc.id.clone(),
            AttributeMapper {
                mappings: ts.returns_attrs.clone(),
            },
            Duration::from_secs(ts.expiration_seconds as u64),
            &file_ts_dir.join(format!("{}.json", svc.id)),
        )?));
    }

    Ok(stores)
}

/// File based attributes encoded in JSON.
/// This is a placeholder until we have a real attribute service and protocol.
#[derive(Debug)]
pub struct FileAttributeStore {
    id: String,
    mapper: AttributeMapper,
    ttl: Duration,
    fp: PathBuf,
    snapshot: ArcSwap<Snapshot>,
    /// Serializes concurrent reloads; reads remain lock-free via ArcSwap.
    refresh_lock: tokio::sync::Mutex<()>,
}

/// Attribute data, the instant it goes stale, and its revision, swapped as a unit so
/// they can never drift apart.
#[derive(Debug)]
struct Snapshot {
    attributes: ActorAttributes,
    expires_at: Instant,
    revision: u64,
}

impl Snapshot {
    /// How much validity this snapshot has left; zero once it has expired.
    /// Saturating because `Instant - Instant` panics on underflow.
    fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

type ActorId = String;
type AttributeName = String;
type AttributeValue = String;

#[derive(Debug, Deserialize, Clone)]
struct ActorAttributes(BTreeMap<ActorId, BTreeMap<AttributeName, Vec<AttributeValue>>>);

// Blocking read of a small local JSON file, at most once per `ttl` and always
// under the refresh lock. Move to tokio::fs (or spawn_blocking, as actor_mgr.rs does) if
// the file ever gets big enough to stall the runtime.
fn load_actor_attributes_from_file(fp: &Path) -> Result<ActorAttributes, ServiceError> {
    let contents = fs::read_to_string(fp)?;
    let attributes = serde_json::from_str(&contents)?;
    Ok(attributes)
}

impl FileAttributeStore {
    /// Create new `FileAttributeStore` instance.
    ///
    /// `id` is written as the "source" of each attribute.
    ///
    /// `ttl` is used as the expiration time for the whole store -- it will be refreshed when the TTL runs out.
    ///  And attribiutes from the store will get an expiration time based on the time remaining until the TTL.
    ///
    /// `fp` must point to an existing file containing the actor attributes list in JSON format.
    ///
    /// ## Errors
    /// - `ServiceError::Param` if `ttl` is below [`MIN_ATTRIBUTE_TTL`]. A store that short
    ///   would sit permanently below the refresh floor and reload on every single request.
    pub fn new(
        id: String,
        mapper: AttributeMapper,
        ttl: Duration,
        fp: &Path,
    ) -> Result<Self, ServiceError> {
        if ttl < MIN_ATTRIBUTE_TTL {
            return Err(ServiceError::Param(format!(
                "trusted service '{id}' ttl {ttl:?} is below the minimum of {MIN_ATTRIBUTE_TTL:?}"
            )));
        }

        let attributes = match load_actor_attributes_from_file(fp) {
            Ok(attrs) => attrs,
            Err(e) => {
                return Err(ServiceError::TrustedServiceInit(format!(
                    "TS '{id}' failed to read attribute data file {fp:?}: {e}"
                )));
            }
        };

        let snapshot = Snapshot {
            attributes,
            expires_at: Instant::now() + ttl,
            revision: next_revision(),
        };
        let store = FileAttributeStore {
            id,
            mapper,
            ttl,
            fp: fp.into(),
            snapshot: ArcSwap::from_pointee(snapshot),
            refresh_lock: tokio::sync::Mutex::new(()),
        };
        Ok(store)
    }

    /// The live snapshot, re-reading the source file first if the current one is at or
    /// below the [`MIN_ATTRIBUTE_TTL`] floor.
    ///
    /// Only one caller does the reload; the rest wait on `refresh_lock` and re-check, so a
    /// burst of concurrent requests against an expired store costs one file read, not N.
    async fn live_snapshot(&self) -> Result<Arc<Snapshot>, ServiceError> {
        let snapshot = self.snapshot.load_full();
        if snapshot.remaining() >= MIN_ATTRIBUTE_TTL {
            return Ok(snapshot);
        }

        let _guard = self.refresh_lock.lock().await;

        // Re-check: another caller may have refreshed while we waited on the lock.
        let snapshot = self.snapshot.load_full();
        if snapshot.remaining() >= MIN_ATTRIBUTE_TTL {
            return Ok(snapshot);
        }

        info!(target: TS, "TS {} re-loading actor attributes", self.id);
        let fresh = Arc::new(Snapshot {
            attributes: load_actor_attributes_from_file(&self.fp)?,
            expires_at: Instant::now() + self.ttl,
            revision: next_revision(),
        });
        self.snapshot.store(fresh.clone());
        Ok(fresh)
    }
}

#[async_trait]
impl TrustedServiceInterface for FileAttributeStore {
    fn get_source_id(&self) -> &str {
        &self.id
    }

    /// Use the actor 'CN' to look up the corresponding attributes in the store.
    async fn get_attributes_for_actor(
        &self,
        actor_ident: &str,
    ) -> Result<Vec<Attribute>, ServiceError> {
        // Reloads from file if the cached data is at or below the TTL floor.
        let snapshot = self.live_snapshot().await?;

        let Some(attributes) = snapshot.attributes.0.get(actor_ident) else {
            // actor not found in the attribute store
            debug!(target: TS, "{}: actor '{actor_ident}' not found in the attribute store", self.id);
            return Ok(Vec::new());
        };

        // Add each attribute to the actor. Attribute lifetime is tied to the store's own
        // freshness, and `live_snapshot` guarantees at least MIN_ATTRIBUTE_TTL of it.
        let mut result = Vec::new();
        let src_builder = AttributeSource::new(self.id.clone());
        let remaining = snapshot.remaining();

        for (name, values) in attributes {
            if let Some((zpr_name, hint)) = self.mapper.map_attribute(name) {
                let bldr = src_builder.builder(zpr_name).expires_in(remaining);
                let attr = match hint {
                    AttrHint::SingleValued => {
                        bldr.value(values.first().cloned().unwrap_or_default())
                    }
                    AttrHint::MultiValued => bldr.values(values),
                    AttrHint::Tag(tag_value) => bldr.value(tag_value),
                };
                result.push(attr);
            }
        }
        Ok(result)
    }

    /// Re-read the attribute file and swap in a fresh snapshot (with a fresh
    /// revision). On failure the current snapshot and revision are left untouched and
    /// the error is returned — a bad file must not advance the revision.
    async fn flush(&self) -> Result<(), ServiceError> {
        info!(target: TS, "TS {} flushing cached actor attributes", self.id);
        let _guard = self.refresh_lock.lock().await;
        let attributes = load_actor_attributes_from_file(&self.fp)?;
        self.snapshot.store(Arc::new(Snapshot {
            attributes,
            expires_at: Instant::now() + self.ttl,
            revision: next_revision(),
        }));
        Ok(())
    }

    fn current_revision(&self) -> u64 {
        self.snapshot.load().revision
    }
}

#[derive(Debug)]
pub struct AttributeMapper {
    // Linear scan. A trusted service returns a handful of attributes; index it
    // by service_attr_key if that ever stops being true.
    pub mappings: Vec<AttrMapping>,
}

enum AttrHint {
    /// Attribute is declared as single valued.
    SingleValued,

    /// Attribute is declared as multi valued.
    MultiValued,

    /// Attribute is declared as a tag.
    Tag(String), // if a tag, this gets the value.
}

impl AttributeMapper {
    /// Map the trusted service name of an attribute into the zpr name of an attribute.
    /// If the `ts_key` presented is not in the mapping data, then None is returned.
    ///
    /// Tags are tricky since we need to parse the ZPR name and figure out the class
    /// that the attribute belongs on (user, device, service, link).  Then the evaluator
    /// uses a special key for tags: '<CLASS>.zpr.tag'.
    ///
    /// For example, a sample tag mapping is "lazy -> #user.lazy"
    /// In that case this returns ("user.zpr.tag", AttrHint::Tag("lazy"))
    ///
    fn map_attribute(&self, ts_key: &str) -> Option<(String, AttrHint)> {
        // `AttrMapping::attr` already carries the decoded RHS spec, so `zpl_key`/`zpl_value`
        // handle the tag class translation ("#user.lazy" -> "user.zpr.tag" + "user.lazy").
        let attr = &self
            .mappings
            .iter()
            .find(|m| m.service_attr_key == ts_key)?
            .attr;

        let hint = if attr.is_tag() {
            AttrHint::Tag(attr.zpl_value())
        } else if attr.is_multi_valued() {
            AttrHint::MultiValued
        } else {
            AttrHint::SingleValued
        };
        Some((attr.zpl_key(), hint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zpr::policy_types::{PolicyContainerBytes, parse_attribute_mapping};

    use crate::loaded_policy::LoadedPolicy;
    use crate::test_helpers::make_trusted_service_policy;

    /// A mapper covering all three RHS spec forms: single, multi, and tag.
    fn test_mapper() -> AttributeMapper {
        AttributeMapper {
            mappings: [
                "color -> user.color",
                "roles -> user.role{}",
                "lazy -> #user.lazy",
            ]
            .iter()
            .map(|m| parse_attribute_mapping(m).unwrap())
            .collect(),
        }
    }

    /// Each spec form must yield the right zpr key and hint, and an unmapped service key
    /// must be dropped rather than passed through.
    #[test]
    fn test_map_attribute_covers_every_spec_form() {
        let mapper = test_mapper();

        let (key, hint) = mapper.map_attribute("color").unwrap();
        assert_eq!(key, "user.color");
        assert!(matches!(hint, AttrHint::SingleValued));

        let (key, hint) = mapper.map_attribute("roles").unwrap();
        assert_eq!(key, "user.role");
        assert!(matches!(hint, AttrHint::MultiValued));

        // A tag maps onto the evaluator's per-class tag key, carrying the tag as the value.
        let (key, hint) = mapper.map_attribute("lazy").unwrap();
        assert_eq!(key, "user.zpr.tag");
        assert!(matches!(hint, AttrHint::Tag(t) if t == "user.lazy"));

        assert!(mapper.map_attribute("not_in_the_mapping").is_none());
    }

    /// Write `contents` to a uniquely named file in the system temp dir and return the path.
    /// Tests share a process, so a distinct `name` per test is enough to avoid collisions.
    fn write_fixture(name: &str, contents: &str) -> PathBuf {
        let fp = std::env::temp_dir().join(name);
        fs::write(&fp, contents).unwrap();
        fp
    }

    /// A ttl below the floor would leave the store permanently stale, reloading on every
    /// request. Construction must reject it rather than let that happen at runtime.
    #[test]
    fn test_new_rejects_ttl_below_floor() {
        let fp = write_fixture("vs-fas-short-ttl.json", "{}");
        let result = FileAttributeStore::new(
            "test".to_string(),
            test_mapper(),
            MIN_ATTRIBUTE_TTL - Duration::from_secs(1),
            &fp,
        );
        assert!(matches!(result, Err(ServiceError::Param(_))));

        // The same store with a ttl at the floor is accepted.
        assert!(
            FileAttributeStore::new("test".to_string(), test_mapper(), MIN_ATTRIBUTE_TTL, &fp)
                .is_ok()
        );
        fs::remove_file(&fp).unwrap();
    }

    /// The core of the interior-mutability rework: an unexpired store keeps serving its
    /// cached data even after the file changes underneath it, and `flush` makes the very
    /// next read pick up the new contents.
    #[tokio::test]
    async fn test_flush_forces_reload_on_next_read() {
        let fp = write_fixture("vs-fas-flush.json", r#"{"alice": {"color": ["red"]}}"#);
        let store = FileAttributeStore::new(
            "test".to_string(),
            test_mapper(),
            Duration::from_secs(3600),
            &fp,
        )
        .unwrap();

        let snapshot = store.live_snapshot().await.unwrap();
        assert!(snapshot.attributes.0.contains_key("alice"));

        // Change the file. The store is nowhere near its ttl, so it must not notice yet.
        fs::write(&fp, r#"{"bob": {"color": ["blue"]}}"#).unwrap();
        let snapshot = store.live_snapshot().await.unwrap();
        assert!(snapshot.attributes.0.contains_key("alice"));
        assert!(!snapshot.attributes.0.contains_key("bob"));

        // After a flush the next read reloads.
        store.flush().await.unwrap();
        let snapshot = store.live_snapshot().await.unwrap();
        assert!(snapshot.attributes.0.contains_key("bob"));
        assert!(!snapshot.attributes.0.contains_key("alice"));

        // A fresh reload resets the clock, so emitted attributes clear the floor again.
        assert!(snapshot.remaining() >= MIN_ATTRIBUTE_TTL);

        fs::remove_file(&fp).unwrap();
    }

    /// Decode a container built by `make_trusted_service_policy` into a `Policy`.
    fn policy_from_container(container_bytes: Vec<u8>) -> Arc<Policy> {
        let loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(container_bytes),
            &crate::config::POLICY_MIN_VERSION,
        )
        .unwrap();
        loaded.policy()
    }

    /// A well-formed `api=file` trusted service yields a working store: it is named after
    /// the service and serves the mapped attributes out of `<id>.json`.
    #[tokio::test]
    async fn test_build_services_from_policy_happy_path() {
        let dir = std::env::temp_dir().join("vs-bsfp-ok");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
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

        fs::remove_dir_all(&dir).unwrap();
    }

    /// Every way a declared trusted service can fail to configure must be an error, so the
    /// policy carrying it is rejected rather than silently losing the service.
    #[test]
    fn test_build_services_from_policy_rejects_bad_declarations() {
        // Empty dir: no `<id>.json` exists for any of these.
        let dir = std::env::temp_dir().join("vs-bsfp-bad");
        fs::create_dir_all(&dir).unwrap();

        let cases = [
            // (id, api, expiration_seconds) — the failure each one exercises.
            ("attrfile", "file", Some(3600)), // attribute file is missing
            ("attrfile", "ldap", Some(3600)), // unsupported api
            ("attrfile", "file", None),       // no TrustedService record in policy
            ("attrfile", "file", Some(1)),    // ttl below MIN_ATTRIBUTE_TTL
            ("../escape", "file", Some(3600)), // path traversal in the id
        ];
        for (id, api, secs) in cases {
            let policy = policy_from_container(make_trusted_service_policy(id, api, secs, &[]));
            assert!(
                build_services_from_policy(&policy, &dir).is_err(),
                "expected failure for id={id} api={api} secs={secs:?}"
            );
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    /// `flush_all` must reach every registered service.
    #[tokio::test]
    async fn test_manager_flush_all_reaches_every_service() {
        let fp = write_fixture("vs-fas-flush-all.json", r#"{"alice": {"color": ["red"]}}"#);
        let mgr = TrustedServicesMgr::new();
        let store = Arc::new(
            FileAttributeStore::new(
                "test".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp,
            )
            .unwrap(),
        );
        mgr.update_services(vec![store.clone()]);

        let rev_before = store.current_revision();

        let results = mgr.flush_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());

        // Eager flush: a fresh, fully-valid snapshot with a new revision was swapped in.
        assert!(store.current_revision() > rev_before);
        assert!(store.snapshot.load().remaining() >= MIN_ATTRIBUTE_TTL);

        fs::remove_file(&fp).unwrap();
    }

    /// A failed flush (unparseable file) must leave the current snapshot and revision
    /// untouched; a subsequent successful flush moves both forward.
    #[tokio::test]
    async fn test_flush_failure_keeps_snapshot_and_revision() {
        let fp = write_fixture("vs-fas-flush-fail.json", r#"{"alice": {"color": ["red"]}}"#);
        let store = FileAttributeStore::new(
            "test".to_string(),
            test_mapper(),
            Duration::from_secs(3600),
            &fp,
        )
        .unwrap();
        let rev = store.current_revision();

        // Corrupt the file: flush must fail and change nothing.
        fs::write(&fp, "not json").unwrap();
        assert!(store.flush().await.is_err());
        assert_eq!(store.current_revision(), rev);
        assert!(store.snapshot.load().attributes.0.contains_key("alice"));

        // Fix the file: flush succeeds, data and revision move forward.
        fs::write(&fp, r#"{"bob": {"color": ["blue"]}}"#).unwrap();
        store.flush().await.unwrap();
        assert!(store.current_revision() > rev);
        assert!(store.snapshot.load().attributes.0.contains_key("bob"));

        fs::remove_file(&fp).unwrap();
    }

    /// Revision staleness bookkeeping: an irrelevant source is skipped, a missing
    /// record reads as stale, recording the revision clears it, and a flush makes the
    /// actor stale again even when only the record marks the source relevant.
    #[tokio::test]
    async fn test_stale_sources_for_actor_tracks_revisions() {
        let fp = write_fixture("vs-fas-stale.json", r#"{"alice": {"color": ["red"]}}"#);
        let mgr = TrustedServicesMgr::new();
        let store = Arc::new(
            FileAttributeStore::new(
                "test".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp,
            )
            .unwrap(),
        );
        mgr.update_services(vec![store.clone()]);

        // No attributes from the source and no record: not relevant, not stale.
        assert!(
            mgr.stale_sources_for_actor("alice", &HashSet::new())
                .is_empty()
        );

        // Attributes from the source but no record: stale.
        let sources = HashSet::from(["test".to_string()]);
        let stale = mgr.stale_sources_for_actor("alice", &sources);
        assert_eq!(stale, vec![("test".to_string(), store.current_revision())]);

        // Recording the fetched revision clears the staleness.
        mgr.record_revision("alice", "test", stale[0].1);
        assert!(mgr.stale_sources_for_actor("alice", &sources).is_empty());

        // A flush bumps the revision: stale again, and the record alone is enough to
        // keep the source relevant (no attr_sources needed).
        store.flush().await.unwrap();
        assert_eq!(
            mgr.stale_sources_for_actor("alice", &HashSet::new()),
            vec![("test".to_string(), store.current_revision())]
        );

        fs::remove_file(&fp).unwrap();
    }
}
