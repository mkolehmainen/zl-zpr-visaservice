//! Coordination and revision tracking across trusted services.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use libeval::attribute::Attribute;

use crate::error::ServiceError;

use super::TrustedServiceInterface;

/// Coordinates concurrent access to the configured trusted-service implementations.
pub struct TrustedServicesMgr {
    services: ArcSwap<Vec<Arc<dyn TrustedServiceInterface>>>,
    /// Per actor and source, the revision from which attributes were last refreshed.
    actor_revisions: DashMap<String, HashMap<String, u64>>,
}

impl TrustedServicesMgr {
    /// Create a manager with no configured services.
    pub fn new() -> Self {
        Self {
            services: ArcSwap::new(Arc::new(Vec::new())),
            actor_revisions: DashMap::new(),
        }
    }

    /// Return relevant sources whose current revision differs from the actor's record.
    pub fn stale_sources_for_actor(
        &self,
        actor_ident: &str,
        attr_sources: &HashSet<String>,
    ) -> Vec<(String, u64)> {
        let services = self.services.load_full();
        let recorded = self.actor_revisions.get(actor_ident);
        services
            .iter()
            .filter_map(|service| {
                let source_id = service.get_source_id();
                let recorded_revision = recorded
                    .as_ref()
                    .and_then(|revisions| revisions.value().get(source_id).copied());
                if recorded_revision.is_none() && !attr_sources.contains(source_id) {
                    return None;
                }
                let current_revision = service.current_revision();
                (recorded_revision != Some(current_revision))
                    .then(|| (source_id.to_string(), current_revision))
            })
            .collect()
    }

    /// Record the source revision used to refresh an actor's attributes.
    pub fn record_revision(&self, actor_ident: &str, source: &str, revision: u64) {
        self.actor_revisions
            .entry(actor_ident.to_string())
            .or_default()
            .insert(source.to_string(), revision);
    }

    /// Atomically replace the entire trusted-service list.
    pub fn update_services(&self, services: Vec<Arc<dyn TrustedServiceInterface>>) {
        self.services.store(Arc::new(services));
    }

    /// Query every trusted service concurrently for an actor's attributes.
    pub async fn get_attributes_for_actor(
        &self,
        actor_ident: &str,
    ) -> Vec<Result<Vec<Attribute>, ServiceError>> {
        let snapshot = self.services.load_full();
        let futures = snapshot.iter().map(|service| {
            let service = service.clone();
            async move { service.get_attributes_for_actor(actor_ident).await }
        });
        join_all(futures).await
    }

    /// Query one named trusted service for an actor's attributes.
    pub async fn get_attributes_from_source_for_actor(
        &self,
        source_ident: &str,
        actor_ident: &str,
    ) -> Vec<Result<Vec<Attribute>, ServiceError>> {
        let snapshot = self.services.load_full();
        if let Some(service) = snapshot
            .iter()
            .find(|service| service.get_source_id() == source_ident)
        {
            let service = service.clone();
            return vec![service.get_attributes_for_actor(actor_ident).await];
        }

        vec![Err(ServiceError::TrustedServiceNotFound(
            source_ident.to_string(),
        ))]
    }

    /// Flush every trusted service without stopping after an individual failure.
    #[allow(dead_code)]
    pub async fn flush_all(&self) -> Vec<Result<(), ServiceError>> {
        let snapshot = self.services.load_full();
        let futures = snapshot.iter().map(|service| {
            let service = service.clone();
            async move { service.flush().await }
        });
        join_all(futures).await
    }

    /// Flush one named trusted service.
    pub async fn flush_one(&self, source_ident: &str) -> Result<(), ServiceError> {
        let snapshot = self.services.load_full();
        if let Some(service) = snapshot
            .iter()
            .find(|service| service.get_source_id() == source_ident)
        {
            let service = service.clone();
            return service.flush().await;
        }

        Err(ServiceError::TrustedServiceNotFound(
            source_ident.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_services::file_attribute_store::FileAttributeStore;
    use crate::trusted_services::test_support::{test_mapper, write_fixture};
    use std::fs;
    use std::time::Duration;

    /// Flushing all services reaches each registered implementation.
    #[tokio::test]
    async fn test_manager_flush_all_reaches_every_service() {
        let fp = write_fixture("vs-fas-flush-all.json", r#"{"alice": {"color": ["red"]}}"#);
        let manager = TrustedServicesMgr::new();
        let store = Arc::new(
            FileAttributeStore::new(
                "test".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp,
            )
            .unwrap(),
        );
        manager.update_services(vec![store.clone()]);

        let revision_before = store.current_revision();
        let results = manager.flush_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
        assert!(store.current_revision() > revision_before);

        fs::remove_file(&fp).unwrap();
    }

    /// Actor revision records become stale whenever a relevant service advances.
    #[tokio::test]
    async fn test_stale_sources_for_actor_tracks_revisions() {
        let fp = write_fixture("vs-fas-stale.json", r#"{"alice": {"color": ["red"]}}"#);
        let manager = TrustedServicesMgr::new();
        let store = Arc::new(
            FileAttributeStore::new(
                "test".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp,
            )
            .unwrap(),
        );
        manager.update_services(vec![store.clone()]);

        assert!(
            manager
                .stale_sources_for_actor("alice", &HashSet::new())
                .is_empty()
        );

        let sources = HashSet::from(["test".to_string()]);
        let stale = manager.stale_sources_for_actor("alice", &sources);
        assert_eq!(stale, vec![("test".to_string(), store.current_revision())]);

        manager.record_revision("alice", "test", stale[0].1);
        assert!(
            manager
                .stale_sources_for_actor("alice", &sources)
                .is_empty()
        );

        store.flush().await.unwrap();
        assert_eq!(
            manager.stale_sources_for_actor("alice", &HashSet::new()),
            vec![("test".to_string(), store.current_revision())]
        );

        fs::remove_file(&fp).unwrap();
    }
}
