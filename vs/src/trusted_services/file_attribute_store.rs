//! File-backed trusted-service attribute storage.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

use libeval::attribute::{Attribute, AttributeSource};

use crate::error::ServiceError;
use crate::logging::targets::TS;

use super::attribute_mapper::{AttrHint, AttributeMapper};
use super::{TrustedServiceInterface, next_revision};

/// Shortest TTL emitted on an attribute. A nearly stale snapshot refreshes early.
const MIN_ATTRIBUTE_TTL: Duration = Duration::from_secs(60);

/// File-based attributes encoded in JSON.
#[derive(Debug)]
pub(super) struct FileAttributeStore {
    id: String,
    mapper: AttributeMapper,
    ttl: Duration,
    fp: PathBuf,
    snapshot: ArcSwap<Snapshot>,
    /// Serializes concurrent reloads; reads remain lock-free via ArcSwap.
    refresh_lock: tokio::sync::Mutex<()>,
}

/// Attribute data, expiration, and revision swapped as one consistent unit.
#[derive(Debug)]
struct Snapshot {
    attributes: ActorAttributes,
    expires_at: Instant,
    revision: u64,
}

impl Snapshot {
    /// Return this snapshot's remaining validity, saturating at zero.
    fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

type ActorId = String;
type AttributeName = String;
type AttributeValue = String;

/// Actor attributes decoded from the file's JSON representation.
#[derive(Debug, Deserialize, Clone)]
struct ActorAttributes(BTreeMap<ActorId, BTreeMap<AttributeName, Vec<AttributeValue>>>);

/// Load and decode actor attributes from a local JSON file.
fn load_actor_attributes_from_file(fp: &Path) -> Result<ActorAttributes, ServiceError> {
    let contents = fs::read_to_string(fp)?;
    let attributes = serde_json::from_str(&contents)?;
    Ok(attributes)
}

impl FileAttributeStore {
    /// Create a file store and load its initial snapshot.
    pub(super) fn new(
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

        let attributes = load_actor_attributes_from_file(fp).map_err(|error| {
            ServiceError::TrustedServiceInit(format!(
                "TS '{id}' failed to read attribute data file {fp:?}: {error}"
            ))
        })?;

        let snapshot = Snapshot {
            attributes,
            expires_at: Instant::now() + ttl,
            revision: next_revision(),
        };
        Ok(Self {
            id,
            mapper,
            ttl,
            fp: fp.into(),
            snapshot: ArcSwap::from_pointee(snapshot),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Return a live snapshot, refreshing once when the cached data approaches expiry.
    async fn live_snapshot(&self) -> Result<Arc<Snapshot>, ServiceError> {
        let snapshot = self.snapshot.load_full();
        if snapshot.remaining() >= MIN_ATTRIBUTE_TTL {
            return Ok(snapshot);
        }

        let _guard = self.refresh_lock.lock().await;

        // Another caller may have refreshed while this caller waited.
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
    /// Look up an actor by CN and return its mapped attributes.
    async fn get_attributes_for_actor(
        &self,
        actor_ident: &str,
    ) -> Result<Vec<Attribute>, ServiceError> {
        let snapshot = self.live_snapshot().await?;

        let Some(attributes) = snapshot.attributes.0.get(actor_ident) else {
            debug!(target: TS, "{}: actor '{actor_ident}' not found in the attribute store", self.id);
            return Ok(Vec::new());
        };

        let mut result = Vec::new();
        let src_builder = AttributeSource::new(self.id.clone());
        let remaining = snapshot.remaining();

        for (name, values) in attributes {
            if let Some((zpr_name, hint)) = self.mapper.map_attribute(name) {
                let builder = src_builder.builder(zpr_name).expires_in(remaining);
                let attribute = match hint {
                    AttrHint::SingleValued => {
                        builder.value(values.first().cloned().unwrap_or_default())
                    }
                    AttrHint::MultiValued => builder.values(values),
                    AttrHint::Tag(tag_value) => builder.value(tag_value),
                };
                result.push(attribute);
            }
        }
        Ok(result)
    }

    /// Reload the file and atomically install a fresh snapshot.
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

    /// Return the revision of the current file snapshot.
    fn current_revision(&self) -> u64 {
        self.snapshot.load().revision
    }

    /// Return the configured trusted-service identifier.
    fn get_source_id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_services::test_support::{test_mapper, write_fixture};

    /// Construction rejects TTLs that would force a reload on every request.
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
        assert!(
            FileAttributeStore::new("test".to_string(), test_mapper(), MIN_ATTRIBUTE_TTL, &fp)
                .is_ok()
        );
        fs::remove_file(&fp).unwrap();
    }

    /// An unexpired store stays cached until an explicit flush installs new data.
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

        fs::write(&fp, r#"{"bob": {"color": ["blue"]}}"#).unwrap();
        let snapshot = store.live_snapshot().await.unwrap();
        assert!(snapshot.attributes.0.contains_key("alice"));
        assert!(!snapshot.attributes.0.contains_key("bob"));

        store.flush().await.unwrap();
        let snapshot = store.live_snapshot().await.unwrap();
        assert!(snapshot.attributes.0.contains_key("bob"));
        assert!(!snapshot.attributes.0.contains_key("alice"));
        assert!(snapshot.remaining() >= MIN_ATTRIBUTE_TTL);

        fs::remove_file(&fp).unwrap();
    }

    /// A failed flush preserves the current snapshot and revision.
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
        let revision = store.current_revision();

        fs::write(&fp, "not json").unwrap();
        assert!(store.flush().await.is_err());
        assert_eq!(store.current_revision(), revision);
        assert!(store.snapshot.load().attributes.0.contains_key("alice"));

        fs::write(&fp, r#"{"bob": {"color": ["blue"]}}"#).unwrap();
        store.flush().await.unwrap();
        assert!(store.current_revision() > revision);
        assert!(store.snapshot.load().attributes.0.contains_key("bob"));

        fs::remove_file(&fp).unwrap();
    }
}
