//! Redis/ValKey operations for the bootstrap-key denylist (zipline#136).
//!
//! An administrative revocation of a bootstrap authentication root
//! (`POST /admin/authrevoke/{cn}`) records the CN here. The connect and SS
//! renewal paths consult the denylist beside the policy key lookup, so a
//! re-connect presenting a revoked key is refused even while a stale policy
//! still carries the key.
//!
//! Unlike the admin actor disconnects, entries deliberately **persist across
//! policy installs** (operator decision on zipline#136, Q1): a compromised key
//! is not un-compromised by an install. An entry lives until explicitly
//! removed (`DELETE /admin/authrevoke/{id}`) or the list is cleared
//! (`POST /admin/authrevoke/clear`).
//!
//! Storage, in the same state DB as the rest of VS state so a VS restart does
//! not forget revocations:
//!
//! - `authrevoke:bootstrap` is a hash mapping the revoked CN to its numeric
//!   entry id (decimal string). The id is what the admin API lists and keys
//!   removal by.
//! - `authrevoke:bootstrap:next-id` is the id counter (INCR).

use std::sync::Arc;

use crate::db::DbConnection;
use crate::error::StoreError;

const KEY_DENYLIST: &str = "authrevoke:bootstrap";
const KEY_NEXT_ID: &str = "authrevoke:bootstrap:next-id";

pub struct BootstrapDenylist {
    db: Arc<dyn DbConnection>,
}

impl BootstrapDenylist {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        BootstrapDenylist { db }
    }

    /// Add `cn` to the denylist and return its entry id. Adding a CN that is
    /// already denylisted is idempotent: the existing entry (and id) is kept.
    ///
    /// Concurrency (PR #42 review, P2): the insert is an atomic set-if-absent
    /// ([DbConnection::hset_nx]), so two racing adds of the same absent CN
    /// cannot overwrite each other — one claims the field, the loser reads
    /// back the winner's stored id and returns that. A pre-allocated id that
    /// lost the claim is simply abandoned (the counter only ever moves
    /// forward, so ids stay unique; gaps are fine).
    pub async fn add(&self, cn: &str) -> Result<u64, StoreError> {
        if let Some(existing) = self.db.hget(KEY_DENYLIST, cn).await? {
            if let Ok(id) = existing.parse::<u64>() {
                return Ok(id);
            }
            // Unparseable id: this entry has no usable removal handle
            // (`remove()` is id-keyed), so re-mint it. hdel-then-claim keeps
            // the window where the CN is briefly absent, but revocation
            // enforcement re-reads the store (contains(), the sweep), and
            // this path only runs on an already-corrupt record.
            self.db.hdel(KEY_DENYLIST, cn).await?;
        }
        let id = self.db.incr(KEY_NEXT_ID, 1).await?;
        if self.db.hset_nx(KEY_DENYLIST, cn, &id.to_string()).await? {
            return Ok(id);
        }
        // Lost the claim to a concurrent add: return the id the store kept.
        match self.db.hget(KEY_DENYLIST, cn).await? {
            Some(stored) => stored.parse::<u64>().map_err(|_| {
                StoreError::InvalidData(format!("denylist entry for {cn} has a non-numeric id"))
            }),
            // Claim lost, then the entry vanished: a concurrent remove/clear.
            // One more claim attempt with our id; a second loss is contention
            // beyond anything the admin surface can generate.
            None => {
                if self.db.hset_nx(KEY_DENYLIST, cn, &id.to_string()).await? {
                    Ok(id)
                } else {
                    Err(StoreError::InvalidData(format!(
                        "denylist add for {cn} lost two consecutive claim races"
                    )))
                }
            }
        }
    }

    /// Whether `cn` is denylisted — the connect / SS-renewal check.
    pub async fn contains(&self, cn: &str) -> Result<bool, StoreError> {
        Ok(self.db.hget(KEY_DENYLIST, cn).await?.is_some())
    }

    /// All entries as `(id, cn)`, unordered. An entry whose id does not parse
    /// is dropped from the listing with an error log rather than wedging the
    /// caller on one bad record (it still blocks connects via [Self::contains],
    /// which never parses the id).
    pub async fn list(&self) -> Result<Vec<(u64, String)>, StoreError> {
        let map = self.db.hgetall(KEY_DENYLIST.to_string()).await?;
        let mut entries = Vec::with_capacity(map.len());
        for (cn, id_str) in map {
            match id_str.parse::<u64>() {
                Ok(id) => entries.push((id, cn)),
                Err(_) => {
                    tracing::error!("dropping unparseable denylist entry: cn={cn} id={id_str}");
                }
            }
        }
        Ok(entries)
    }

    /// The CN behind entry `id`, if any.
    pub async fn cn_by_id(&self, id: u64) -> Result<Option<String>, StoreError> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .find(|(eid, _)| *eid == id)
            .map(|(_, cn)| cn))
    }

    /// Remove entry `id`. Returns the removed CN, or `None` when no such
    /// entry exists.
    pub async fn remove(&self, id: u64) -> Result<Option<String>, StoreError> {
        let Some(cn) = self.cn_by_id(id).await? else {
            return Ok(None);
        };
        self.db.hdel(KEY_DENYLIST, &cn).await?;
        Ok(Some(cn))
    }

    /// Remove every entry.
    pub async fn clear(&self) -> Result<(), StoreError> {
        for (_, cn) in self.list().await? {
            self.db.hdel(KEY_DENYLIST, &cn).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FakeDb;

    /// Entries round-trip: what was added is listed back with a stable id,
    /// `contains` sees it, and removal by id prunes exactly one entry.
    #[tokio::test]
    async fn test_denylist_roundtrip_and_remove() {
        let db: Arc<dyn DbConnection> = Arc::new(FakeDb::new());
        let deny = BootstrapDenylist::new(db.clone());
        assert!(deny.list().await.unwrap().is_empty());
        assert!(!deny.contains("laptop-7.zpr").await.unwrap());

        let id1 = deny.add("laptop-7.zpr").await.unwrap();
        let id2 = deny.add("sensor-3.zpr").await.unwrap();
        assert_ne!(id1, id2, "entries get distinct ids");

        assert!(deny.contains("laptop-7.zpr").await.unwrap());
        assert!(deny.contains("sensor-3.zpr").await.unwrap());
        assert!(!deny.contains("innocent.zpr").await.unwrap());

        let mut got = deny.list().await.unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                (id1, "laptop-7.zpr".to_string()),
                (id2, "sensor-3.zpr".to_string())
            ]
        );
        assert_eq!(
            deny.cn_by_id(id1).await.unwrap().as_deref(),
            Some("laptop-7.zpr")
        );

        assert_eq!(
            deny.remove(id1).await.unwrap().as_deref(),
            Some("laptop-7.zpr")
        );
        assert!(!deny.contains("laptop-7.zpr").await.unwrap());
        assert_eq!(
            deny.list().await.unwrap(),
            vec![(id2, "sensor-3.zpr".to_string())]
        );

        // Removing an absent id is a no-op returning None.
        assert_eq!(deny.remove(9999).await.unwrap(), None);
        assert_eq!(deny.list().await.unwrap().len(), 1);
    }

    /// Adding a CN twice is idempotent: same id, one entry.
    #[tokio::test]
    async fn test_denylist_add_idempotent() {
        let deny = BootstrapDenylist::new(Arc::new(FakeDb::new()));
        let id1 = deny.add("laptop-7.zpr").await.unwrap();
        let id2 = deny.add("laptop-7.zpr").await.unwrap();
        assert_eq!(id1, id2, "re-adding the same CN keeps the entry id");
        assert_eq!(deny.list().await.unwrap().len(), 1);
    }

    /// PR #42 review (P2): idempotency must hold under CONCURRENT adds too.
    /// Two adds of the same absent CN can both pass the exists-check, allocate
    /// distinct ids, and overwrite each other — one caller is then handed an
    /// id that no entry carries, so its GET/DELETE 404s. Every concurrent add
    /// must return the id the store actually kept. Multi-threaded flavor: the
    /// race needs true parallelism to interleave FakeDb operations.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_denylist_concurrent_adds_agree_on_one_entry() {
        const TASKS: usize = 8;
        for round in 0..200 {
            let db: Arc<dyn DbConnection> = Arc::new(FakeDb::new());
            let barrier = Arc::new(tokio::sync::Barrier::new(TASKS));
            let mut handles = Vec::with_capacity(TASKS);
            for _ in 0..TASKS {
                let db = db.clone();
                let barrier = barrier.clone();
                handles.push(tokio::spawn(async move {
                    let deny = BootstrapDenylist::new(db);
                    barrier.wait().await;
                    deny.add("raced.zpr").await.unwrap()
                }));
            }
            let mut returned = Vec::with_capacity(TASKS);
            for handle in handles {
                returned.push(handle.await.unwrap());
            }

            let deny = BootstrapDenylist::new(db);
            let entries = deny.list().await.unwrap();
            assert_eq!(
                entries.len(),
                1,
                "round {round}: concurrent adds of one CN must leave one entry"
            );
            let stored = entries[0].0;
            for id in returned {
                assert_eq!(
                    id, stored,
                    "round {round}: an add returned id {id} but the store kept \
                     {stored} — that id 404s on GET/DELETE"
                );
            }
        }
    }

    /// Clear empties the list; contains goes false for every former entry.
    #[tokio::test]
    async fn test_denylist_clear() {
        let deny = BootstrapDenylist::new(Arc::new(FakeDb::new()));
        deny.add("a.zpr").await.unwrap();
        deny.add("b.zpr").await.unwrap();
        deny.clear().await.unwrap();
        assert!(deny.list().await.unwrap().is_empty());
        assert!(!deny.contains("a.zpr").await.unwrap());
        assert!(!deny.contains("b.zpr").await.unwrap());
    }

    /// Entries survive rehydration: a fresh repo over the same DB sees them —
    /// the write-through property that makes the denylist outlive a VS
    /// restart, like `ReauthRepo` (zipline#123).
    #[tokio::test]
    async fn test_denylist_survives_rehydration() {
        let db: Arc<dyn DbConnection> = Arc::new(FakeDb::new());
        let id = BootstrapDenylist::new(db.clone())
            .add("laptop-7.zpr")
            .await
            .unwrap();

        let fresh = BootstrapDenylist::new(db);
        assert!(fresh.contains("laptop-7.zpr").await.unwrap());
        assert_eq!(
            fresh.list().await.unwrap(),
            vec![(id, "laptop-7.zpr".to_string())]
        );
    }
}
