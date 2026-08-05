//! Trusted Services Manager
//!
//! Placeholder for eventual comprehensive management of the trusted services.

use async_trait::async_trait;

use arc_swap::ArcSwap;
use futures::future::join_all;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;

use tracing::debug;

use libeval::attribute::{Attribute, AttributeSource};

use zpr::policy_types::AttrMapping;

use crate::error::ServiceError;
use crate::logging::targets::TS;

/// Shortest TTL we are willing to stamp on an emitted attribute. When a store's cached
/// data has less than this left, it refreshes early rather than hand a consumer something
/// that expires almost immediately.
const MIN_ATTRIBUTE_TTL: Duration = Duration::from_secs(60);

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
}

impl TrustedServicesMgr {
    /// Create a new TrustedServicesMgr instance with no services.
    pub fn new() -> Self {
        TrustedServicesMgr {
            services: ArcSwap::new(Arc::new(Vec::new())),
        }
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
    pub async fn flush_all(&self) -> Vec<Result<(), ServiceError>> {
        let snapshot = self.services.load_full();

        // TODO: I do not want a failure of one service to stop the rest of the flusing. I'd like to log the error.

        let futures = snapshot.iter().map(|svc| {
            let svc = svc.clone(); // cheap Arc clone
            async move { svc.flush().await }
        });

        join_all(futures).await
    }
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

/// Attribute data and the instant it goes stale, swapped as a unit so the two can
/// never drift apart.
#[derive(Debug)]
struct Snapshot {
    attributes: ActorAttributes,
    expires_at: Instant,
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

// ponytail: blocking read of a small local JSON file, at most once per `ttl` and always
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
        let snapshot = Snapshot {
            attributes: load_actor_attributes_from_file(fp)?,
            expires_at: Instant::now() + ttl,
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

        let fresh = Arc::new(Snapshot {
            attributes: load_actor_attributes_from_file(&self.fp)?,
            expires_at: Instant::now() + self.ttl,
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

    /// Expire the cached data in place so the next lookup re-reads the file. Reuses the
    /// normal staleness path rather than carrying a separate "force reload" flag.
    async fn flush(&self) -> Result<(), ServiceError> {
        self.snapshot.rcu(|cur| Snapshot {
            attributes: cur.attributes.clone(),
            expires_at: Instant::now(),
        });
        Ok(())
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
    use zpr::policy_types::parse_attribute_mapping;

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

        assert!(store.snapshot.load().remaining() >= MIN_ATTRIBUTE_TTL);

        let results = mgr.flush_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());

        // Flushed means expired: the cached data is now below the floor.
        assert!(store.snapshot.load().remaining() < MIN_ATTRIBUTE_TTL);

        fs::remove_file(&fp).unwrap();
    }
}
