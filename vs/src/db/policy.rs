//! Redis/ValKey operations related to policy.
//!
//! PHASH is a true content hash of the policy *container* artifact: the SHA-256
//! of the exact container bytes we received. It changes whenever the container
//! bytes change (recompiles, compiler metadata, signatures, or policy body).
//!
//! The container is the single source of truth; the inner decoded policy is
//! always re-derived from it. This updates:
//! - policies:<PHASH>:container maps to the raw Cap'n Proto `PolicyContainer` bytes.
//! - policy:current a hash which includes key 'phash' with the current policy PHASH.
//!

use libeval::pio;
use std::sync::Arc;
use tracing::debug;
use zpr::policy_types::PolicyContainerBytes;

use crate::db;
use crate::db::{DbConnection, DbOp};
use crate::error::StoreError;
use crate::loaded_policy::LoadedPolicy;
use crate::logging::targets::DB;

const KEY_POLICIES: &str = "policies";
const KEY_POLICY: &str = "policy";

/// The identifiers of the current policy as persisted in `policy:current`:
/// the container content hash and its monotonic version instance number.
pub struct PolicyIdentifier {
    pub phash: String,
    pub vinst: u64,
}

pub struct PolicyRepo {
    db: Arc<dyn DbConnection>,
}

impl PolicyRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        PolicyRepo { db }
    }

    /// Set the current policy information into the database. Unless
    /// `force_overwrite` is true, only updates the policy data in the database
    /// if the current policy is different (by its phash) from the one already
    /// stored.
    ///
    /// Only the container half of `loaded` is persisted; the decoded policy is
    /// always re-derived from it on load. Taking `&LoadedPolicy` makes it
    /// impossible to persist bytes that never decoded into a valid artifact.
    ///
    /// The vinst is always persisted, even when the container is unchanged:
    /// `update_policy_internal` bumps vinst while leaving identical container
    /// bytes, and that bump must reach the DB so vinst survives a restart.
    pub async fn set_current_policy(
        &self,
        loaded: &LoadedPolicy,
        force_overwrite: bool,
    ) -> Result<(), StoreError> {
        let container_bytes = loaded.container().as_bytes();
        let phash = loaded.hash_container_bytes()?;
        let vinst = loaded.policy().vinst().to_string();
        let maybe_curhash: Option<String> = self.db.hget("policy:current", "phash").await?;
        let curhash = maybe_curhash.unwrap_or_default();
        let container_key = format!("{KEY_POLICIES}:{phash}:container");
        let key_current = format!("{KEY_POLICY}:current");

        // Require the container blob to exist, so a half-written state (current
        // pointer present, container missing) still forces a rewrite.
        let exists: bool = (curhash == phash) && self.db.exists(&container_key).await?;
        if !exists || force_overwrite {
            debug!(target: DB, "updating current policy in DB to phash {phash}");

            //
            // policies:<PHASH>:container -> <capn proto container bytes>
            // policy:current
            //          |- phash -> the string <PHASH> value
            //          |- vinst -> the version instance number as a string
            //          |- ctime -> string
            //
            // All written in one atomic pipeline so the current pointer, its
            // container, and its vinst can never drift apart.
            //
            let ops = vec![
                DbOp::SetBin {
                    key: container_key,
                    value: container_bytes.to_vec(),
                },
                DbOp::HSet {
                    hash_key: key_current.clone(),
                    field: "phash".to_string(),
                    value: phash.clone(),
                },
                DbOp::HSet {
                    hash_key: key_current.clone(),
                    field: "vinst".to_string(),
                    value: vinst,
                },
                DbOp::HSet {
                    hash_key: key_current,
                    field: "ctime".to_string(),
                    value: db::gen_timestamp(),
                },
            ];
            self.db.atomic_pipeline(&ops).await?;
        } else {
            // Container unchanged, but vinst may have advanced (an update that
            // reuses identical container bytes). Persist the vinst on its own so
            // the bump is not lost on restart; atomicity with the container is
            // irrelevant here since the container is unchanged.
            debug!(target: DB, "set_current_policy container unchanged, updating vinst, hash={phash}");
            self.db.hset(&key_current, "vinst", &vinst).await?;
        }

        Ok(())
    }

    /// Read the current-policy identifier (phash + vinst) from
    /// `policy:current`.
    ///
    /// Returns `None` when no current policy is set (fresh DB). A present phash
    /// is always written alongside its vinst, so a phash with a missing or
    /// unparsable vinst is a corrupt state and an `InvalidData` error. Both
    /// fields are read together so startup never mixes a phash and vinst from
    /// separate writes.
    pub async fn get_current_identifier(&self) -> Result<Option<PolicyIdentifier>, StoreError> {
        let maybe_phash: Option<String> = self.db.hget("policy:current", "phash").await?;
        let Some(phash) = maybe_phash else {
            return Ok(None);
        };
        let vinst_str: String =
            self.db
                .hget("policy:current", "vinst")
                .await?
                .ok_or_else(|| {
                    StoreError::InvalidData(format!("current policy {phash} has no vinst field"))
                })?;
        let vinst = vinst_str
            .parse::<u64>()
            .map_err(|e| StoreError::InvalidData(format!("unparsable vinst {vinst_str:?}: {e}")))?;
        Ok(Some(PolicyIdentifier { phash, vinst }))
    }

    /// Load the current policy artifact and decode it into a [LoadedPolicy].
    ///
    /// Returns an error if there is no current policy set, or if the stored
    /// container bytes cannot be decoded into a valid policy.
    pub async fn get_current_loaded_policy(
        &self,
        min_version: &pio::Version,
    ) -> Result<LoadedPolicy, StoreError> {
        let maybe_curhash: Option<String> = self.db.hget("policy:current", "phash").await?;
        let curhash =
            maybe_curhash.ok_or_else(|| StoreError::NotFound("no current policy set".into()))?;
        let container_key = format!("{KEY_POLICIES}:{curhash}:container");
        let cbytes = self.db.get_bin(&container_key).await?;
        LoadedPolicy::from_container(PolicyContainerBytes::from(cbytes), min_version)
            .map_err(|e| StoreError::InvalidData(format!("failed to decode policy container: {e}")))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config;
    use crate::db::db_fake::FakeDb;
    use zpr::policy::v1 as policy_capnp;

    /// Build a [LoadedPolicy] by encoding a minimal policy, wrapping it in a
    /// container at the minimum supported compiler version, and decoding it.
    fn make_loaded(created: &str, version: u64, metadata: Option<&str>) -> LoadedPolicy {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<policy_capnp::policy::Builder>();
            policy_bldr.set_created(created);
            policy_bldr.set_version(version);
            policy_bldr.set_metadata(metadata.unwrap_or(""));
        }
        let mut inner = Vec::new();
        capnp::serialize::write_message(&mut inner, &msg).unwrap();
        let container = crate::test_helpers::make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &inner,
        );
        LoadedPolicy::from_container(
            PolicyContainerBytes::from(container),
            &config::POLICY_MIN_VERSION,
        )
        .unwrap()
    }

    #[tokio::test]
    /// An initial write stores the container blob and points policy:current at it.
    async fn test_set_current_policy_initial_write() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());
        let loaded = make_loaded("2024-01-01T00:00:00Z", 1, Some("meta"));

        repo.set_current_policy(&loaded, false).await.unwrap();

        let phash = db.hget("policy:current", "phash").await.unwrap().unwrap();
        let container_key = format!("{KEY_POLICIES}:{phash}:container");
        let stored = db.get_bin(&container_key).await.unwrap();
        assert_eq!(stored, loaded.container().as_bytes());
    }

    #[tokio::test]
    /// Re-writing the same artifact is a no-op for the write branch. Probed via a
    /// sentinel `ctime`: the write branch always rewrites `ctime`, so its survival
    /// proves the branch did not run.
    async fn test_set_current_policy_no_change() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());
        let loaded = make_loaded("2024-01-01T00:00:00Z", 2, Some("meta"));

        repo.set_current_policy(&loaded, false).await.unwrap();
        db.hset("policy:current", "ctime", "SENTINEL")
            .await
            .unwrap();
        repo.set_current_policy(&loaded, false).await.unwrap();

        let ctime = db.hget("policy:current", "ctime").await.unwrap().unwrap();
        assert_eq!(ctime, "SENTINEL", "write branch must not run for no change");
    }

    #[tokio::test]
    /// force_overwrite rewrites even when the artifact is unchanged. Probed via a
    /// sentinel `ctime` the write branch overwrites.
    async fn test_set_current_policy_force_overwrite() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());
        let loaded = make_loaded("2024-01-01T00:00:00Z", 3, Some("meta"));

        repo.set_current_policy(&loaded, false).await.unwrap();
        db.hset("policy:current", "ctime", "SENTINEL")
            .await
            .unwrap();
        repo.set_current_policy(&loaded, true).await.unwrap();

        let ctime = db.hget("policy:current", "ctime").await.unwrap().unwrap();
        assert_ne!(ctime, "SENTINEL", "force write branch must run");
    }

    #[tokio::test]
    /// A missing container blob forces a rewrite even though the current pointer
    /// still matches the phash.
    async fn test_set_current_policy_rewrites_when_container_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());
        let loaded = make_loaded("2024-01-01T00:00:00Z", 4, Some("meta"));

        repo.set_current_policy(&loaded, false).await.unwrap();

        let phash = db.hget("policy:current", "phash").await.unwrap().unwrap();
        let container_key = format!("{KEY_POLICIES}:{phash}:container");
        db.del(&container_key).await.unwrap();

        repo.set_current_policy(&loaded, false).await.unwrap();
        assert!(db.exists(&container_key).await.unwrap());
    }

    #[tokio::test]
    /// Changing only the container bytes changes the PHASH and stores a distinct
    /// artifact under a new key.
    async fn test_set_current_policy_distinct_phash_per_container() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());

        let loaded_a = make_loaded("2024-01-01T00:00:00Z", 1, Some("meta-a"));
        let loaded_b = make_loaded("2024-01-01T00:00:00Z", 1, Some("meta-b"));

        let phash_a = loaded_a.hash_container_bytes().unwrap();
        let phash_b = loaded_b.hash_container_bytes().unwrap();
        assert_ne!(phash_a, phash_b);

        repo.set_current_policy(&loaded_a, false).await.unwrap();
        repo.set_current_policy(&loaded_b, false).await.unwrap();

        // Both artifacts are stored under their own keys.
        assert!(
            db.exists(&format!("{KEY_POLICIES}:{phash_a}:container"))
                .await
                .unwrap()
        );
        assert!(
            db.exists(&format!("{KEY_POLICIES}:{phash_b}:container"))
                .await
                .unwrap()
        );
        // Current points at the most recent write.
        let cur = db.hget("policy:current", "phash").await.unwrap().unwrap();
        assert_eq!(cur, phash_b);
    }

    #[tokio::test]
    /// set_current_policy followed by get_current_loaded_policy round-trips
    /// through LoadedPolicy: same container bytes, same decoded policy version.
    async fn test_round_trip_through_loaded_policy() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        let loaded = make_loaded("2024-01-01T00:00:00Z", 7, Some("meta"));

        repo.set_current_policy(&loaded, false).await.unwrap();

        let got = repo
            .get_current_loaded_policy(&config::POLICY_MIN_VERSION)
            .await
            .unwrap();
        assert_eq!(got.container().as_bytes(), loaded.container().as_bytes());
        assert_eq!(got.policy().get_version(), Some(7));
    }

    #[tokio::test]
    /// get_current_loaded_policy errors when no current policy is set.
    async fn test_get_current_loaded_policy_not_found() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        let res = repo
            .get_current_loaded_policy(&config::POLICY_MIN_VERSION)
            .await;
        assert!(matches!(res, Err(StoreError::NotFound(_))));
    }

    #[tokio::test]
    /// The write branch persists the vinst; get_current_identifier round-trips
    /// both phash and vinst.
    async fn test_set_current_policy_persists_vinst() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        let mut loaded = make_loaded("2024-01-01T00:00:00Z", 1, Some("meta"));
        loaded.set_vinst(5);

        repo.set_current_policy(&loaded, false).await.unwrap();

        let ident = repo.get_current_identifier().await.unwrap().unwrap();
        assert_eq!(ident.phash, loaded.hash_container_bytes().unwrap());
        assert_eq!(ident.vinst, 5);
    }

    #[tokio::test]
    /// A vinst bump on identical container bytes still reaches the DB even though
    /// the container write branch is skipped.
    async fn test_set_current_policy_updates_vinst_when_container_unchanged() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        let mut loaded = make_loaded("2024-01-01T00:00:00Z", 1, Some("meta"));
        loaded.set_vinst(1);
        repo.set_current_policy(&loaded, false).await.unwrap();

        // Same container bytes, higher vinst: the no-change branch must still
        // persist the bumped vinst.
        loaded.set_vinst(2);
        repo.set_current_policy(&loaded, false).await.unwrap();

        let ident = repo.get_current_identifier().await.unwrap().unwrap();
        assert_eq!(ident.vinst, 2);
    }

    #[tokio::test]
    /// get_current_identifier returns None on a fresh DB.
    async fn test_get_current_identifier_none_on_fresh_db() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        assert!(repo.get_current_identifier().await.unwrap().is_none());
    }

    #[tokio::test]
    /// A phash with no vinst field is a corrupt state, not a valid default: it is
    /// an InvalidData error, since a phash is always written alongside its vinst.
    async fn test_get_current_identifier_errors_on_missing_vinst() {
        let db = Arc::new(FakeDb::new());
        db.hset("policy:current", "phash", "deadbeef")
            .await
            .unwrap();
        let repo = PolicyRepo::new(db);

        let res = repo.get_current_identifier().await;
        assert!(matches!(res, Err(StoreError::InvalidData(_))));
    }

    #[tokio::test]
    /// An unparsable vinst is an InvalidData error, not a silent default.
    async fn test_get_current_identifier_errors_on_garbage_vinst() {
        let db = Arc::new(FakeDb::new());
        db.hset("policy:current", "phash", "deadbeef")
            .await
            .unwrap();
        db.hset("policy:current", "vinst", "not-a-number")
            .await
            .unwrap();
        let repo = PolicyRepo::new(db);

        let res = repo.get_current_identifier().await;
        assert!(matches!(res, Err(StoreError::InvalidData(_))));
    }
}
