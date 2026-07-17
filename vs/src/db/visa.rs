//! Redis/ValKey operations related to visas.
//!
//! This updates:
//! - visa:next_visa_id a counter for the next visa ID to use (actually this is set to the last visa ID handed out).
//! - visa:<ID> a hash of metadata about each visa.
//! - visas:<ID>:blob the capnp encoded visa blob itself.
//! - nodevisa:<ZADDR>:<ID> a hash of state about each visa on each node.

use capnp;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, warn};

use ::zpr::vsapi::v1 as vsapi;
use libeval::eval_result::Direction;
use serde_with::{TimestampSeconds, serde_as};
use zpr::vsapi_types::{PacketDesc, Visa, VsapiFiveTuple};
use zpr::write_to::WriteTo;

use crate::db::{DbConnection, DbOp, ZAddr, gen_timestamp};
use crate::error::StoreError;
use crate::logging::targets::DB;

const KEY_VISA: &str = "visa";
const KEY_NEXT_VISA_ID: &str = "visa:next_visa_id";
const KEY_VISAS: &str = "visas";
const KEY_NODEVISA: &str = "nodevisa";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeVisaState {
    PendingInstall,
    Installed,
    PendingRevoke,
    Revoked,
}

/// Metadata around an issued visa.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisaMetadata {
    pub requesting_node: IpAddr,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub ctime: SystemTime,
    pub policy_version: u64, // from policy.get_version
    pub created_vinst: u64,  // service vinst active when the visa was issued
    pub checked_vinst: u64,  // latest vinst this visa has been evaluated against
    pub zpl: String,
    pub signal_msgs: Vec<String>, // note we do not keep the signal destination
    pub direction: Direction,
    pub path: Option<Vec<IpAddr>>, // ZPR addresses of nodes on the path only set if a link needs to be traversed.
    pub five_tuple: VsapiFiveTuple,
}

#[derive(Clone)]
pub struct VisaRepo {
    db: Arc<dyn DbConnection>,
}

impl VisaMetadata {
    /// Create a non-link-traversing metadata.
    ///
    /// `requesting_node` is the node that requested the visa.
    /// `pver` is the policy version that was in effect at the time of the visa request.
    /// `vinst` is the service policy-install generation active at issuance; it
    /// seeds both `created_vinst` and `checked_vinst`.
    /// `zpl` is the ZPL is a copy of the ZPL line that matched in policy.
    /// `direction` is the direction of the match as reported by the hit.
    pub fn new(
        requesting_node: IpAddr,
        pver: u64,
        vinst: u64,
        zpl: String,
        direction: Direction,
        path: Option<Vec<IpAddr>>,
        pdesc: &PacketDesc,
    ) -> Self {
        VisaMetadata {
            requesting_node,
            ctime: SystemTime::now(),
            policy_version: pver,
            created_vinst: vinst,
            checked_vinst: vinst,
            zpl,
            signal_msgs: Vec::new(),
            direction,
            path,
            five_tuple: pdesc.five_tuple.clone(),
        }
    }
}

impl VisaRepo {
    /// Set up and initialize the visa store.
    /// We set `initial_visa_id` only if the key is not already present.
    pub async fn new(db: Arc<dyn DbConnection>, initial_visa_id: u64) -> Result<Self, StoreError> {
        // TODO: More intialization is probably needed.

        // Only set the initial visa id if the key is not ready present.
        // We don't use the redis NX feature here since we are not concerned with any sort of concurrency
        // at startup time.
        if !db.exists(KEY_NEXT_VISA_ID).await? {
            db.set(KEY_NEXT_VISA_ID, &initial_visa_id.to_string())
                .await?;
        }

        Ok(VisaRepo { db })
    }

    pub async fn get_next_visa_id(&self) -> Result<u64, StoreError> {
        let next_id: u64 = self.db.incr(KEY_NEXT_VISA_ID, 1).await?;
        Ok(next_id)
    }

    /// Remove references to a visa from the state datbase. Caller must make sure
    /// that any revocation messages or whatever have already been sent.
    async fn clean_up(&self, visa_id: u64) -> Result<(), StoreError> {
        let blob_key = blob_key_for_visa(visa_id);
        let visa_id_key = visa_key_for_visa(visa_id);

        let ops = vec![DbOp::Del(blob_key.clone()), DbOp::Del(visa_id_key.clone())];
        self.db.atomic_pipeline(&ops).await?;

        // Remove any nodevisa references to this visa.
        let nodevisa_keys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:*:{visa_id}"))
            .await?;
        if !nodevisa_keys.is_empty() {
            let ops = nodevisa_keys
                .iter()
                .map(|k| DbOp::Del(k.clone()))
                .collect::<Vec<DbOp>>();
            self.db.atomic_pipeline(&ops).await?;
        }
        Ok(())
    }

    /// Force remove all the nodevisa:<ZADDR>:<ID> tables that refer to the
    /// passed `node_addr`.
    ///
    /// Does not remove visa:* entries or the flowid entries.
    ///
    /// TODO: A future version may remove the visa:ID entries so long as they
    /// are not referenced on another node.
    ///
    pub async fn clear_node_state(&self, node_addr: &IpAddr) -> Result<(), StoreError> {
        let zaddr = ZAddr::from(node_addr);
        let nodevisa_keys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:{zaddr}:*"))
            .await?;
        if !nodevisa_keys.is_empty() {
            let ops = nodevisa_keys
                .iter()
                .map(|k| DbOp::Del(k.clone()))
                .collect::<Vec<DbOp>>();
            self.db.atomic_pipeline(&ops).await?;
        }
        Ok(())
    }

    /// Store a new visa in the database, also sets the visa state with respect to the requesting node as
    /// `nstate`.
    ///
    /// If the `metadata` includes a `path` then visa is set PENDING on all nodes in the path.
    ///
    /// TODO: We may want to code path that does not include a requesting node.
    ///
    pub async fn store_visa(
        &self,
        visa: &Visa,
        metadata: VisaMetadata,
        nstate: NodeVisaState,
    ) -> Result<(), StoreError> {
        match self.try_store_visa(&metadata, visa, nstate).await {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!(target: DB, "failed to store visa: {}, attempting cleanup", visa.issuer_id);
                match self.clean_up(visa.issuer_id).await {
                    Ok(_) => (),
                    Err(cleanup_err) => {
                        error!(target: DB, "failed to store visa {} and clean up failed too: {}", visa.issuer_id, cleanup_err);
                    }
                }
                Err(e)
            }
        }
    }

    /// Attempt to store a visa.
    ///
    /// Will set the state w/ respect to the requesting_node to the passed `nstate`. Normally
    /// this should be [NodeVisaState::PendingInstall] but there are occasions where you may
    /// want to set it as [NodeVisaState::Installed].
    ///
    /// Nodes on the path (if any) are marked [NodeVisaState::PendingInstall].
    async fn try_store_visa(
        &self,
        metadata: &VisaMetadata,
        visa: &Visa,
        nstate: NodeVisaState,
    ) -> Result<(), StoreError> {
        // write capnpn version of visa into the store.

        let visa_id = visa.issuer_id;

        let expiration_seconds = seconds_until(visa.expires);
        if expiration_seconds == 0 {
            return Err(StoreError::InvalidData(
                "attempt to store already expired visa".into(),
            ));
        }

        // Store the whole visa in there in capnp format
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut visa_bldr = msg.init_root::<vsapi::visa::Builder>();
            visa.write_to(&mut visa_bldr);
            // Ends up dropping the visa_bldr and forgetting the mut borrow of msg.
        }
        let mut words: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut words, &msg)?;

        //
        // visa:<ID>:blob -> <capn proto bytes>
        //
        self.db
            .set_bin_ex(&blob_key_for_visa(visa_id), &words, expiration_seconds)
            .await?;

        let key_visa = visa_key_for_visa(visa_id);

        //
        // visa:<ID>
        //       |- JSON(VisaMetadata)
        //
        self.db
            .set(&key_visa, &serde_json::to_string(&metadata)?)
            .await?;
        self.db.expire(&key_visa, expiration_seconds as i64).await?;

        // Now update the state/time for the requesting node and any nodes on the path.
        //
        // nodevisa:<ZADDR>:<ID>
        //                   |- state -> string, JSON serialized NodeVisaState
        //                   |- utime -> string, timestamp
        //
        {
            let mut ops = Vec::new();

            let key_nodevisa = node_visa_key_for_visa(&metadata.requesting_node, visa_id);
            ops.push(DbOp::HSetMultiple {
                hash_key: key_nodevisa.clone(),
                field_values: vec![
                    ("state".to_string(), serde_json::to_string(&nstate)?),
                    ("utime".to_string(), gen_timestamp()),
                ],
            });
            ops.push(DbOp::Expire {
                key: key_nodevisa,
                seconds: expiration_seconds as i64,
            });

            if let Some(path) = &metadata.path {
                for node in path {
                    if node == &metadata.requesting_node {
                        continue;
                    }
                    let key_nodevisa = node_visa_key_for_visa(node, visa_id);
                    ops.push(DbOp::HSetMultiple {
                        hash_key: key_nodevisa.clone(),
                        field_values: vec![
                            (
                                "state".to_string(),
                                serde_json::to_string(&NodeVisaState::PendingInstall)?,
                            ),
                            ("utime".to_string(), gen_timestamp()),
                        ],
                    });
                    ops.push(DbOp::Expire {
                        key: key_nodevisa,
                        seconds: expiration_seconds as i64,
                    });
                }
            }

            self.db.atomic_pipeline(&ops).await?;
        }

        debug!(target: DB, "stored visa {visa_id} expires in {expiration_seconds} seconds");
        Ok(())
    }

    /// Update the nodevisa state information for the node and visa.
    pub async fn update_node_visa_state(
        &self,
        node_addr: &IpAddr,
        visa_id: u64,
        new_state: NodeVisaState,
    ) -> Result<(), StoreError> {
        let key_nodevisa = node_visa_key_for_visa(node_addr, visa_id);
        if !self.db.exists(&key_nodevisa).await? {
            return Err(StoreError::NotFound(format!(
                "node-visa record not found: {key_nodevisa}"
            )));
        }
        self.db
            .hset_multiple(
                &key_nodevisa,
                &[
                    ("state", &serde_json::to_string(&new_state)?),
                    ("last_update", &gen_timestamp()),
                ],
            )
            .await?;

        debug!(target: DB, "updated nodevisa state node={node_addr} visa={visa_id} -> {new_state:?}");
        Ok(())
    }

    /// Expired visas will have been removed from redis, so if we find any empty
    /// keys they are just skipped.
    pub async fn get_visas_for_node_by_state(
        &self,
        node_addr: &IpAddr,
        state: NodeVisaState,
    ) -> Result<Vec<Visa>, StoreError> {
        let zaddr = ZAddr::from(node_addr);
        let mut visas = Vec::new();

        let vkeys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:{zaddr}:*"))
            .await?;

        for key in &vkeys {
            let state_str: String = self.db.hget(&key, "state").await?.unwrap_or_default();
            let entry_state: NodeVisaState = serde_json::from_str(&state_str)?;
            if entry_state == state {
                // Extract visa ID from key
                let parts: Vec<&str> = key.rsplitn(2, ':').collect();
                if parts.len() != 2 {
                    warn!(target: DB, "malformed nodevisa key: {}", key);
                    continue;
                }
                let visa_id: u64 = parts[0].parse().map_err(|_| {
                    StoreError::InvalidData(format!("invalid visa ID in nodevisa key: {}", key))
                })?;

                // Load the visa blob
                let blob_key = blob_key_for_visa(visa_id);
                match self.db.get_bin(&blob_key).await {
                    Ok(visa_blob) => {
                        let visa = Visa::from_capnp_bytes(&visa_blob)?;
                        visas.push(visa);
                    }
                    Err(err) if err.kind() == redis::ErrorKind::UnexpectedReturnType => {
                        // Missing/expired visa blob. Skip it but keep other visas.
                        warn!(target: DB, "visa blob missing for key {}", blob_key);
                        continue;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }

        Ok(visas)
    }

    /// Get the visa IDs for a node filtered by state, without loading the visa blobs.
    pub async fn get_visa_ids_for_node_by_state(
        &self,
        node_addr: &IpAddr,
        state: NodeVisaState,
    ) -> Result<Vec<u64>, StoreError> {
        let zaddr = ZAddr::from(node_addr);
        let mut visa_ids = Vec::new();

        let vkeys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:{zaddr}:*"))
            .await?;

        for key in &vkeys {
            let state_str: String = self.db.hget(key, "state").await?.unwrap_or_default();
            let entry_state: NodeVisaState = serde_json::from_str(&state_str)?;
            if entry_state == state {
                let parts: Vec<&str> = key.rsplitn(2, ':').collect();
                if parts.len() != 2 {
                    warn!(target: DB, "malformed nodevisa key: {}", key);
                    continue;
                }
                let visa_id: u64 = parts[0].parse().map_err(|_| {
                    StoreError::InvalidData(format!("invalid visa ID in nodevisa key: {}", key))
                })?;
                visa_ids.push(visa_id);
            }
        }

        Ok(visa_ids)
    }

    /// Count the number of visas for a node that are in the given state.
    pub async fn get_count_visas_for_node_by_state(
        &self,
        node_addr: &IpAddr,
        state: NodeVisaState,
    ) -> Result<u32, StoreError> {
        let zaddr = ZAddr::from(node_addr);
        let mut count = 0;

        let vkeys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:{zaddr}:*"))
            .await?;

        for key in &vkeys {
            let state_str: String = self.db.hget(key, "state").await?.unwrap_or_default();
            let entry_state: NodeVisaState = serde_json::from_str(&state_str)?;
            if entry_state == state {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Get the visa by ID.
    ///
    /// ## Errors
    /// - [DBError::NotFound] if the visa does not exist.
    pub async fn get_visa_by_id(&self, visa_id: u64) -> Result<Visa, StoreError> {
        let blob_key = blob_key_for_visa(visa_id);
        if !self.db.exists(&blob_key).await? {
            return Err(StoreError::NotFound(format!(
                "visa blob not found for ID {}",
                visa_id
            )));
        }
        let visa_blob = self.db.get_bin(&blob_key).await?;
        let visa = Visa::from_capnp_bytes(&visa_blob)?;
        Ok(visa)
    }

    /// Get the metadata for the visa by ID.
    ///
    /// ## Errors
    /// - [StoreError::NotFound] if the visa metadata does not exist.
    pub async fn get_visa_metadata_by_id(&self, visa_id: u64) -> Result<VisaMetadata, StoreError> {
        let visa_key = visa_key_for_visa(visa_id);
        if !self.db.exists(&visa_key).await? {
            return Err(StoreError::NotFound(format!(
                "visa metadata not found for ID {}",
                visa_id
            )));
        }
        let metadata_str: String = self.db.get(&visa_key).await?.ok_or_else(|| {
            StoreError::NotFound(format!("visa metadata not found for ID {}", visa_id))
        })?;
        let metadata: VisaMetadata = serde_json::from_str(&metadata_str)?;
        Ok(metadata)
    }

    /// Copy all the visa IDs into a vec.
    pub async fn list_visa_ids(&self) -> Result<Vec<u64>, StoreError> {
        let visa_keys = self.db.scan_match_all(format!("{KEY_VISA}:[0-9]*")).await?;
        let mut visa_ids = Vec::new();
        for key in &visa_keys {
            let parts: Vec<&str> = key.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                warn!(target: DB, "malformed visa key: {}", key);
                continue;
            }
            let visa_id: u64 = match parts[0].parse() {
                Err(_) => {
                    // TODO: Should we just crash here?
                    warn!(target: DB, "invalid visa ID in visa key: {}, skipping entry", key);
                    continue;
                }
                Ok(id) => id,
            };
            visa_ids.push(visa_id);
        }
        Ok(visa_ids)
    }
}

// Get number of seconds until the given SystemTime or zero if in the past.
fn seconds_until(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn blob_key_for_visa(visa_id: u64) -> String {
    format!("{KEY_VISAS}:{visa_id}:blob")
}

fn visa_key_for_visa(visa_id: u64) -> String {
    format!("{KEY_VISA}:{visa_id}")
}

fn node_visa_key_for_visa(node_addr: &IpAddr, visa_id: u64) -> String {
    let zaddr = ZAddr::from(node_addr);
    format!("{KEY_NODEVISA}:{zaddr}:{visa_id}")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::DbConnection;
    use crate::db::db_fake::FakeDb;
    use crate::test_helpers::{make_pdesc, make_visa};

    #[tokio::test]
    async fn test_store_and_get_visas_by_state() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::1".parse().unwrap();
        let visa = make_visa(42, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        assert!(db.exists(&blob_key_for_visa(42)).await.unwrap());
        assert!(db.exists(&visa_key_for_visa(42)).await.unwrap());
        assert!(
            db.exists(&node_visa_key_for_visa(&node_addr, 42))
                .await
                .unwrap()
        );

        let pending = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].issuer_id, 42);

        repo.update_node_visa_state(&node_addr, 42, NodeVisaState::Installed)
            .await
            .unwrap();
        let pending = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert!(pending.is_empty());

        let installed = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::Installed)
            .await
            .unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].issuer_id, 42);
    }

    #[tokio::test]
    async fn test_update_node_visa_state_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::2".parse().unwrap();

        let err = repo
            .update_node_visa_state(&node_addr, 99, NodeVisaState::Installed)
            .await
            .unwrap_err();
        match err {
            StoreError::NotFound(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_clear_node_state_only_removes_nodevisa() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::3".parse().unwrap();
        let visa = make_visa(7, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();

        repo.clear_node_state(&node_addr).await.unwrap();

        assert!(
            !db.exists(&node_visa_key_for_visa(&node_addr, 7))
                .await
                .unwrap()
        );
        assert!(db.exists(&blob_key_for_visa(7)).await.unwrap());
        assert!(db.exists(&visa_key_for_visa(7)).await.unwrap());
    }

    #[tokio::test]
    async fn test_store_visa_rejects_expired() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let mut visa = make_visa(8, Duration::from_secs(1));
        visa.expires = SystemTime::now() - Duration::from_secs(1);

        let metadata = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        let err = repo
            .store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_update_node_visa_state_after_expiry() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::5".parse().unwrap();
        let visa = make_visa(9, Duration::from_secs(5));

        let metadata = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(6)).await;

        let err = repo
            .update_node_visa_state(&node_addr, 9, NodeVisaState::Installed)
            .await
            .unwrap_err();
        match err {
            StoreError::NotFound(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_visas_skips_missing_blobs() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::6".parse().unwrap();
        let visa_a = make_visa(10, Duration::from_secs(60));
        let visa_b = make_visa(11, Duration::from_secs(60));

        let metadata_a = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa_a, metadata_a, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        let metadata_b = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa_b, metadata_b, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        db.del(&blob_key_for_visa(10)).await.unwrap();

        let visas = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_eq!(visas.len(), 1);
        assert_eq!(visas[0].issuer_id, 11);
    }

    #[tokio::test]
    async fn test_list_visa_ids_after_store() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::7".parse().unwrap();

        let visa_a = make_visa(1, Duration::from_secs(60));
        let visa_b = make_visa(5, Duration::from_secs(60));
        let visa_c = make_visa(42, Duration::from_secs(60));

        repo.store_visa(
            &visa_a,
            VisaMetadata::new(
                node_addr,
                0,
                0,
                String::new(),
                Direction::Forward,
                None,
                &make_pdesc(),
            ),
            NodeVisaState::PendingInstall,
        )
        .await
        .unwrap();
        repo.store_visa(
            &visa_b,
            VisaMetadata::new(
                node_addr,
                0,
                0,
                String::new(),
                Direction::Forward,
                None,
                &make_pdesc(),
            ),
            NodeVisaState::PendingInstall,
        )
        .await
        .unwrap();
        repo.store_visa(
            &visa_c,
            VisaMetadata::new(
                node_addr,
                0,
                0,
                String::new(),
                Direction::Forward,
                None,
                &make_pdesc(),
            ),
            NodeVisaState::PendingInstall,
        )
        .await
        .unwrap();

        let mut ids = repo.list_visa_ids().await.unwrap();
        ids.sort_unstable();

        assert_eq!(ids, vec![1, 5, 42]);
    }

    #[tokio::test]
    async fn test_get_visa_by_id() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::8".parse().unwrap();
        let visa = make_visa(77, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let loaded = repo.get_visa_by_id(77).await.unwrap();
        assert_eq!(loaded.issuer_id, 77);
        assert_eq!(
            loaded.dock_pep.as_ref().unwrap().source_addr,
            visa.dock_pep.as_ref().unwrap().source_addr
        );
        assert_eq!(
            loaded.dock_pep.as_ref().unwrap().dest_addr,
            visa.dock_pep.as_ref().unwrap().dest_addr
        );
    }

    #[tokio::test]
    async fn test_get_visa_by_id_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();

        let err = repo.get_visa_by_id(1234).await.unwrap_err();
        match err {
            StoreError::NotFound(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_visa_metadata_by_id() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::9".parse().unwrap();
        let visa = make_visa(88, Duration::from_secs(60));

        let stored_metadata = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa, stored_metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let metadata = repo.get_visa_metadata_by_id(88).await.unwrap();
        assert_eq!(metadata.requesting_node, node_addr);
        assert!(metadata.ctime > SystemTime::UNIX_EPOCH);
    }

    #[tokio::test]
    async fn test_get_visa_metadata_by_id_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();

        let err = repo.get_visa_metadata_by_id(999).await.unwrap_err();
        match err {
            StoreError::NotFound(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    /// Verifies that a VisaMetadata with non-default values for all new fields
    /// survives a serialize → deserialize round-trip with all fields intact.
    #[test]
    fn test_visa_metadata_round_trip() {
        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let original = VisaMetadata {
            requesting_node: node_addr,
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            policy_version: 42,
            created_vinst: 7,
            checked_vinst: 9,
            zpl: "permit src any dst any".to_string(),
            signal_msgs: vec!["sig-a".to_string(), "sig-b".to_string()],
            direction: Direction::Reverse,
            path: None,
            five_tuple: make_pdesc().five_tuple,
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: VisaMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.requesting_node, original.requesting_node);
        assert_eq!(decoded.ctime, original.ctime);
        assert_eq!(decoded.policy_version, original.policy_version);
        assert_eq!(decoded.zpl, original.zpl);
        assert_eq!(decoded.signal_msgs, original.signal_msgs);
        assert_eq!(decoded.direction, original.direction);
        assert_eq!(decoded.created_vinst, original.created_vinst);
        assert_eq!(decoded.checked_vinst, original.checked_vinst);
    }

    /// Verifies that signal_msgs is preserved correctly when non-empty across
    /// a serialize → deserialize round-trip.
    #[test]
    fn test_visa_metadata_signal_msgs_preserved() {
        let node_addr: IpAddr = "fd5a:5052::12".parse().unwrap();
        let signals = vec![
            "msg-1".to_string(),
            "msg-2".to_string(),
            "msg-3".to_string(),
        ];
        let original = VisaMetadata {
            requesting_node: node_addr,
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001),
            policy_version: 1,
            created_vinst: 0,
            checked_vinst: 0,
            zpl: String::new(),
            signal_msgs: signals.clone(),
            direction: Direction::Forward,
            path: None,
            five_tuple: make_pdesc().five_tuple,
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: VisaMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.signal_msgs, signals);
    }

    /// Verifies that Direction::Forward and Direction::Reverse each survive a
    /// serialize → deserialize round-trip without being altered.
    #[test]
    fn test_visa_metadata_direction_round_trip_both_variants() {
        let node_addr: IpAddr = "fd5a:5052::13".parse().unwrap();

        for direction in [Direction::Forward, Direction::Reverse] {
            let original = VisaMetadata {
                requesting_node: node_addr,
                ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_002),
                policy_version: 0,
                created_vinst: 0,
                checked_vinst: 0,
                zpl: String::new(),
                signal_msgs: Vec::new(),
                direction,
                path: None,
                five_tuple: make_pdesc().five_tuple,
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: VisaMetadata = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.direction, direction);
        }
    }

    /// Stores a visa with a path and verifies that the requesting node gets the
    /// caller-supplied nstate while every other node in the path gets PendingInstall.
    #[tokio::test]
    async fn test_store_visa_with_path_sets_path_nodes_pending() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();

        let requesting: IpAddr = "fd5a:5052::30".parse().unwrap();
        let node_b: IpAddr = "fd5a:5052::31".parse().unwrap();
        let node_c: IpAddr = "fd5a:5052::32".parse().unwrap();
        let visa = make_visa(100, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            requesting,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![requesting, node_b, node_c]),
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();

        let state_str = db
            .hget(&node_visa_key_for_visa(&requesting, 100), "state")
            .await
            .unwrap()
            .unwrap();
        let state: NodeVisaState = serde_json::from_str(&state_str).unwrap();
        assert_eq!(state, NodeVisaState::Installed);

        for node in &[node_b, node_c] {
            assert!(db.exists(&node_visa_key_for_visa(node, 100)).await.unwrap());
            let state_str = db
                .hget(&node_visa_key_for_visa(node, 100), "state")
                .await
                .unwrap()
                .unwrap();
            let state: NodeVisaState = serde_json::from_str(&state_str).unwrap();
            assert_eq!(state, NodeVisaState::PendingInstall);
        }
    }

    /// When the requesting node also appears in the path list its state must not be
    /// overwritten with PendingInstall by the path-iteration loop.
    #[tokio::test]
    async fn test_store_visa_requesting_node_in_path_not_overwritten() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();

        let requesting: IpAddr = "fd5a:5052::40".parse().unwrap();
        let other: IpAddr = "fd5a:5052::41".parse().unwrap();
        let visa = make_visa(101, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            requesting,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![requesting, other]),
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();

        let state_str = db
            .hget(&node_visa_key_for_visa(&requesting, 101), "state")
            .await
            .unwrap()
            .unwrap();
        let state: NodeVisaState = serde_json::from_str(&state_str).unwrap();
        assert_eq!(
            state,
            NodeVisaState::Installed,
            "requesting node state should not be overwritten"
        );

        let state_str = db
            .hget(&node_visa_key_for_visa(&other, 101), "state")
            .await
            .unwrap()
            .unwrap();
        let state: NodeVisaState = serde_json::from_str(&state_str).unwrap();
        assert_eq!(state, NodeVisaState::PendingInstall);
    }

    /// Path nodes created by store_visa are discoverable through the standard
    /// get_visa_ids_for_node_by_state query.
    #[tokio::test]
    async fn test_store_visa_path_nodes_queryable_by_state() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();

        let requesting: IpAddr = "fd5a:5052::50".parse().unwrap();
        let path_node: IpAddr = "fd5a:5052::51".parse().unwrap();
        let visa = make_visa(102, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            requesting,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![requesting, path_node]),
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let ids = repo
            .get_visa_ids_for_node_by_state(&path_node, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_eq!(ids, vec![102]);

        let installed = repo
            .get_visa_ids_for_node_by_state(&path_node, NodeVisaState::Installed)
            .await
            .unwrap();
        assert!(installed.is_empty());
    }

    /// With no path, only the requesting node should receive a nodevisa entry.
    #[tokio::test]
    async fn test_store_visa_no_path_only_requesting_node_gets_nodevisa() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();

        let requesting: IpAddr = "fd5a:5052::60".parse().unwrap();
        let unrelated: IpAddr = "fd5a:5052::61".parse().unwrap();
        let visa = make_visa(103, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            requesting,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        assert!(
            db.exists(&node_visa_key_for_visa(&requesting, 103))
                .await
                .unwrap()
        );
        assert!(
            !db.exists(&node_visa_key_for_visa(&unrelated, 103))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_visa_ids_for_node_by_state_filters_correctly() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        let visa_a = make_visa(10, Duration::from_secs(60));
        let visa_b = make_visa(11, Duration::from_secs(60));

        let metadata_a = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa_a, metadata_a, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let metadata_b = VisaMetadata::new(
            node_addr,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        repo.store_visa(&visa_b, metadata_b, NodeVisaState::Installed)
            .await
            .unwrap();

        let pending_ids = repo
            .get_visa_ids_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        let pending_len = repo
            .get_count_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_eq!(pending_len, 1);
        assert_eq!(pending_ids.len(), 1);
        assert_eq!(pending_ids[0], 10);

        let installed_ids = repo
            .get_visa_ids_for_node_by_state(&node_addr, NodeVisaState::Installed)
            .await
            .unwrap();
        let installed_len = repo
            .get_count_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_eq!(installed_len, 1);
        assert_eq!(installed_ids.len(), 1);
        assert_eq!(installed_ids[0], 11);
    }
}
