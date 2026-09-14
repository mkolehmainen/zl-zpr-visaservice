//! Redis/ValKey operations for actor state.
//!
//! Note that a ZADDR is a munged version of the ZPR address - colons replaced with dashes.
//! Note that the MUNGED_SERVICENAME is a db::KeyString - colons and '%' replaced with percent encoding.
//!
//! This updates:
//! - actor:<ZADDR>                - a hash for each connected actor
//! - actor:<ZADDR>:attrs          - a hash of attributes for each actor maps attribute keys to Attribug in JSON.
//! - actor:<ZADDR>:services       - a set of service names offered by the actor.
//! - service:<MUNGED_SERVICENAME> - a hash. Includes key 'zpr_addr' with the ZPR address (string) of the actor providing the service.
//! - nodes                        - set of IP addresses  of all connected nodes.
//! - adapters                     - set of IP addresses  of all connected adapters.

use libeval::actor::Actor;
use libeval::attribute::Attribute;
use libeval::attribute::key;
use libeval::pubkey::decode_public_key;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, error, warn};
use zpr::vsapi_types::PublicKey;

use crate::db::{DbConnection, DbOp, KeyString, ZAddr, gen_timestamp};
use crate::error::StoreError;
use crate::logging::targets::DB;

const KEY_ACTOR: &str = "actor";
const KEY_SERVICE: &str = "service";
const KEY_NODES: &str = "nodes";
const KEY_ADAPTERS: &str = "adapters";

pub enum Role {
    Node,
    Adapter,
}

pub struct ActorRepo {
    db: Arc<dyn DbConnection>,
}

/// Location of a service in the ZPRnet.
pub struct ServiceEntry {
    /// Name of service (sometimes called "id")
    pub name: String,
    pub zpr_addr: IpAddr,
}

impl ServiceEntry {
    pub fn new(name: String, zpr_addr: IpAddr) -> Self {
        ServiceEntry { name, zpr_addr }
    }
}

impl ActorRepo {
    pub fn new(db_handle: Arc<dyn DbConnection>) -> Self {
        ActorRepo { db: db_handle }
    }

    /// Undo all the redis additions performed by `add_actor`.
    async fn clean_up(&self, zpraddr: &IpAddr) -> Result<(), StoreError> {
        //let mut vk_conn = self.db.conn.clone();

        let zpraddr_str = zpraddr.to_string();

        let base_key = actor_key_for(&zpraddr);
        let attrs_key = attrs_key_for(&zpraddr);
        let services_key = actor_services_key_for(&zpraddr);

        // Sanity check- remove any existing records for this actor.
        // Including any stale service records.

        let ops = vec![
            DbOp::Del(base_key.clone()),
            DbOp::Del(attrs_key.clone()),
            DbOp::SRem {
                set_key: KEY_NODES.into(),
                member: zpraddr_str.clone(),
            },
            DbOp::SRem {
                set_key: KEY_ADAPTERS.into(),
                member: zpraddr_str.clone(),
            },
        ];
        self.db.atomic_pipeline(&ops).await?;

        if self.db.exists(&services_key).await? {
            let service_names: HashSet<String> = self.db.smembers(&services_key).await?;
            if !service_names.is_empty() {
                let mut ops = Vec::new();

                for name in &service_names {
                    // The stale names may actually be valid names on new actors. So we need to check the
                    // zaddr value before deleting.
                    let svc_key = service_key_for(&name);
                    let actor_addr_str: Option<String> = self.db.hget(&svc_key, "zpr_addr").await?;
                    if let Some(actor_addr) = actor_addr_str {
                        if actor_addr != zpraddr_str {
                            continue;
                        }
                        ops.push(DbOp::Del(service_key_for(&name)));
                    }
                }
                self.db.atomic_pipeline(&ops).await?;
            }
            self.db.del(&services_key).await?;
        }
        Ok(())
    }

    pub async fn add_actor(&self, actor: &Actor) -> Result<(), StoreError> {
        match self.try_add_actor(actor).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Attempt to clean up after ourselves...
                warn!(target: DB, "add_actor failed, attempting cleanup");
                if let Some(zpraddr) = actor.get_zpr_addr() {
                    match self.clean_up(zpraddr).await {
                        Ok(_) => (),
                        Err(cleanup_err) => {
                            error!(target: DB, "actor insert failed and so did clean up for addr={}: {}", zpraddr, cleanup_err);
                        }
                    }
                }
                Err(e)
            }
        }
    }

    /// Update existing actor data. The passed actor is authoritative: attributes it no
    /// longer carries are dropped from the store (an attribute refresh can remove
    /// attributes, and a stale copy left behind would resurface on the next load).
    pub async fn update_actor(&self, actor: &Actor) -> Result<(), StoreError> {
        let zpraddr = match actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                return Err(StoreError::MissingRequired(
                    "attempt to update actor with no ZPR address".into(),
                ));
            }
        };

        let zpraddr_str = zpraddr.to_string();
        let base_key = actor_key_for(&zpraddr);
        let attrs_key = attrs_key_for(&zpraddr);
        let services_key = actor_services_key_for(&zpraddr);

        if !self.db.exists(&base_key).await? {
            return Err(StoreError::NotFound(format!(
                "update called on non-existant actor: {zpraddr}"
            )));
        }

        let ts = gen_timestamp();

        // The actor is not allowed to change roles:
        if actor.is_node() {
            if !self.db.sismember(KEY_NODES, &zpraddr_str).await? {
                return Err(StoreError::InvalidData(format!(
                    "update fails since node actor not already in node role: {zpraddr}"
                )));
            }
        } else {
            if !self.db.sismember(KEY_ADAPTERS, &zpraddr_str).await? {
                return Err(StoreError::InvalidData(format!(
                    "update fails since adapter actor not already in adapter role: {zpraddr}"
                )));
            }
        }

        //
        // actor:<ZADDR>:attrs
        //                |- <key> -> JSON(<Attribute>)
        //
        // Write the attributes. We write out the attributes in JSON.
        // There may be a bunch of attributes so we take the time to set up a pipeline.
        // The hash is dropped first so removed attributes do not linger; the pipeline is
        // atomic, so no reader sees the actor without its attributes.
        let mut ops = vec![DbOp::Del(attrs_key.clone())];
        ops.extend(actor.attrs_iter().map(|attr| DbOp::HSet {
            hash_key: attrs_key.clone(),
            field: attr.get_key().to_string(),
            value: serde_json::to_string(attr).unwrap_or_default(),
        }));
        self.db.atomic_pipeline(&ops).await?;

        //
        // actor:<ZADDR>
        //         |- identity_keys -> JSON(<IdentityKeysVec>)
        //         |- ctime -> string
        //         |- utime -> string
        //

        // Get the identity keys as a vec, write as JSON array
        let identity_keys = actor
            .identity_keys_iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        self.db
            .hset(
                &base_key,
                "identity_keys",
                &serde_json::to_string(&identity_keys)?,
            )
            .await?;
        self.db.hset_nx(&base_key, "ctime", &ts).await?; // set create time only if not already there.
        self.db.hset(&base_key, "utime", &ts).await?; // always set update time

        //
        // service:<NAME>
        //           |- zpr_addr -> string
        //
        // actor:<ZADDR>:services -> SET[ <service_name> ]
        //

        // Remove existing services.
        let existing_services: HashSet<String> = self.db.smembers(&services_key).await?;
        for service_name in existing_services {
            let svc_key_str = service_key_for(&service_name);
            self.db.del(&svc_key_str).await?;
        }
        self.db.del(&services_key).await?;

        // Add services back based on what actor actually still has.
        for service_name in actor.services_iter() {
            debug!(target: DB, "adding service for actor: addr={zpraddr} service={service_name}");
            let svc_key_str = service_key_for(&service_name);
            self.db
                .hset(&svc_key_str, "zpr_addr", &zpraddr.to_string())
                .await?;
            self.db.sadd(&services_key, &service_name).await?;
        }

        debug!(target: DB, "update actor in DB: addr={zpraddr} cn={:?} node?={}", actor.get_cn(), actor.is_node());
        Ok(())
    }

    /// Get a list of all the connected services -- what they are called and where
    /// they are connected.
    pub async fn list_services(&self) -> Result<Vec<ServiceEntry>, StoreError> {
        let mut service_entries = Vec::new();

        let svc_keys = self.db.scan_match_all(format!("{KEY_SERVICE}:*")).await?;
        for svc_key in &svc_keys {
            let munged_svc_name = KeyString::from_raw(
                svc_key
                    .trim_start_matches(&format!("{KEY_SERVICE}:"))
                    .into(),
            );
            if let Some(addr_str) = self.db.hget(&svc_key, "zpr_addr").await? {
                let addr: IpAddr = addr_str.parse().map_err(|e| {
                    StoreError::InvalidData(format!(
                        "invalid zpr_addr in service entry {}: {}",
                        svc_key, e
                    ))
                })?;
                match String::try_from(munged_svc_name) {
                    Ok(svc_name) => service_entries.push(ServiceEntry::new(svc_name, addr)),
                    Err(_) => {
                        return Err(StoreError::InvalidData(format!(
                            "invalid service name encoding for key {svc_key}"
                        )));
                    }
                }
            } else {
                // possible corruption?
                warn!(target: DB, "zpr_addr field missing from service entry {}", svc_key);
            }
        }
        Ok(service_entries)
    }

    /// Given a service name, look up the ZPR address of the actor providing that service (if any).
    pub async fn get_zpr_addr_for_service(
        &self,
        service_name: &str,
    ) -> Result<Option<IpAddr>, StoreError> {
        let svc_key = service_key_for(service_name);
        if let Some(addr_str) = self.db.hget(&svc_key, "zpr_addr").await? {
            let addr: IpAddr = addr_str.parse().map_err(|e| {
                StoreError::InvalidData(format!(
                    "invalid zpr_addr in service entry {}: {}",
                    svc_key, e
                ))
            })?;
            Ok(Some(addr))
        } else {
            Ok(None)
        }
    }

    /// Load specific attributes by name from the actor datastructure. Only found attributes are returned.
    pub async fn get_actor_attrs(
        &self,
        zpr_addr: &IpAddr,
        attr_keys: &[&str],
    ) -> Result<Vec<Attribute>, StoreError> {
        let attrs_key = attrs_key_for(zpr_addr);
        let mut attrs = Vec::new();
        for key in attr_keys {
            if let Some(attr_json) = self.db.hget(&attrs_key, key).await? {
                let attr: Attribute = serde_json::from_str(&attr_json)?;
                attrs.push(attr);
            }
        }
        Ok(attrs)
    }

    /// Load and decode the actor's A2A DH public key. Returns Ok(None) when no key is stored.
    pub async fn get_a2a_dh_pubkey_by_zpr_addr(
        &self,
        zpra: &IpAddr,
    ) -> Result<Option<PublicKey>, StoreError> {
        let attrs = self.get_actor_attrs(zpra, &[key::A2A_DH_PUBKEY]).await?;
        let Some(attr) = attrs.first() else {
            return Ok(None);
        };
        let value = attr
            .get_single_value()
            .map_err(|e| StoreError::InvalidData(format!("actor {zpra}: {e}")))?;
        let pubkey = decode_public_key(value).map_err(|e| {
            StoreError::InvalidData(format!(
                "invalid {} for actor {zpra}: {e}",
                key::A2A_DH_PUBKEY
            ))
        })?;
        Ok(Some(pubkey))
    }

    /// Get a list of services offered by the actor.
    pub async fn list_services_for_actor(
        &self,
        zpr_addr: &IpAddr,
    ) -> Result<Vec<String>, StoreError> {
        let services_key = actor_services_key_for(&zpr_addr);
        let service_names: HashSet<String> = self.db.smembers(&services_key).await?;
        Ok(service_names.into_iter().collect())
    }

    /// Add an actor record which must only be called after initial authentication (there
    /// will likely be changes to an actor later from trusted services or re-authentication,
    /// but the updates should use a different function.)
    async fn try_add_actor(&self, actor: &Actor) -> Result<(), StoreError> {
        let zpraddr = match actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                return Err(StoreError::MissingRequired(
                    "attempt to add actor with no ZPR address".into(),
                ));
            }
        };

        self.clean_up(&zpraddr).await?;

        let zpraddr_str = zpraddr.to_string();
        let base_key = actor_key_for(&zpraddr);
        let attrs_key = attrs_key_for(&zpraddr);
        let services_key = actor_services_key_for(&zpraddr);

        let ts = gen_timestamp();

        //
        // actor:<ZADDR>:attrs
        //                |- <key> -> JSON(<Attribute>)
        //
        // Write the attributes. We write out the attributes in JSON.
        for attr in actor.attrs_iter() {
            self.db
                .hset(&attrs_key, attr.get_key(), &serde_json::to_string(&attr)?)
                .await?;
        }

        //
        // actor:<ZADDR>
        //         |- identity_keys -> JSON(<IdentityKeysVec>)
        //         |- ctime -> string
        //         |- utime -> string
        //

        // Get the identity keys as a vec, write as JSON array
        let identity_keys = actor
            .identity_keys_iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        self.db
            .hset(
                &base_key,
                "identity_keys",
                &serde_json::to_string(&identity_keys)?,
            )
            .await?;
        self.db.hset_nx(&base_key, "ctime", &ts).await?; // set create time only if not already there.
        self.db.hset(&base_key, "utime", &ts).await?; // always set update time

        //
        // service:<NAME>
        //           |- zpr_addr -> string
        //
        // actor:<ZADDR>:services -> SET[ <service_name> ]
        //

        // This means that each service can have just one entry here which we may want
        // to reasses later -- for example a service may be provided by multiple actors.
        for service_name in actor.services_iter() {
            debug!(target: DB, "adding service for actor: addr={zpraddr} service={service_name}");
            let svc_key_str = service_key_for(&service_name);
            self.db
                .hset(&svc_key_str, "zpr_addr", &zpraddr.to_string())
                .await?;
            self.db.sadd(&services_key, &service_name).await?;
        }

        //
        // One of:
        //    nodes    -> SET [ <zpr_address_string> ]
        //    adapters -> SET [ <zpr_address_string> ]
        //
        if actor.is_node() {
            self.db.sadd(KEY_NODES, &zpraddr_str).await?;
        } else {
            self.db.sadd(KEY_ADAPTERS, &zpraddr_str).await?;
        }

        debug!(target: DB, "added actor to DB: addr={zpraddr} cn={:?} node?={}", actor.get_cn(), actor.is_node());
        Ok(())
    }

    /// Remove actor from the state database, including all services.
    pub async fn rm_actor_by_zpr_addr(&self, zpra: &std::net::IpAddr) -> Result<(), StoreError> {
        self.clean_up(zpra).await?;
        debug!(target: DB, "removed actor from DB: addr={zpra}");
        Ok(())
    }

    /// Look up actor by ZPR address. Creates a new actor instance from the DB data if found.
    ///
    /// ## Errors
    /// - Returns `StoreError::NotFound` if no actor found for the given ZPR address.
    pub async fn get_actor_by_zpr_addr(
        &self,
        zpra: &std::net::IpAddr,
    ) -> Result<Actor, StoreError> {
        let base_key = actor_key_for(&zpra);
        let exists: bool = self.db.exists(&base_key).await?;
        if !exists {
            return Err(StoreError::NotFound(format!("actor not found: {}", zpra)));
        }

        let mut actor = Actor::new();

        // Load attributes from json.  The attributes are in 'actor:<ZADDR>:attrs' hash
        // each key is an attribute name, and the value is the JSON representation of the attribute.
        let attrs_map: std::collections::HashMap<String, String> =
            self.db.hgetall(format!("{base_key}:attrs")).await?;
        for (_key, attr_json) in attrs_map.iter() {
            let attr: Attribute = serde_json::from_str(attr_json)?;
            actor.add_attribute(attr)?;
        }

        // Then get the identity attribute key values.
        let identity_keys_json: String = self
            .db
            .hget(&base_key, "identity_keys")
            .await?
            .unwrap_or_default();
        let identity_keys: Vec<String> = serde_json::from_str(&identity_keys_json)?;
        for idkey in identity_keys.iter() {
            actor.add_identity_key(usize::MAX, idkey)?; // 0 means no expiration
        }
        Ok(actor)
    }

    /// List all connected actors, optionally filtered by role, keyed on the ZPR
    /// address. Each entry carries the actor's CN when it has one -- the CN is a
    /// display label that may be absent (e.g. an OIDC-only connect), never a key.
    ///
    /// Walks the "nodes" and "adapters" role sets.
    pub async fn list_actors(
        &self,
        by_role: Option<Role>,
    ) -> Result<Vec<(IpAddr, Option<String>)>, StoreError> {
        let mut actors = Vec::new();

        let set_keys = match by_role {
            Some(Role::Node) => vec![KEY_NODES.to_string()],
            Some(Role::Adapter) => vec![KEY_ADAPTERS.to_string()],
            None => vec![KEY_NODES.to_string(), KEY_ADAPTERS.to_string()],
        };

        for set_key in set_keys {
            let addr_strs: HashSet<String> = self.db.smembers(&set_key).await?;
            for addr_str in addr_strs {
                // The sets hold IP addresses as strings (not munged addresses)
                let addr: IpAddr = match addr_str.parse() {
                    Ok(addr) => addr,
                    Err(err) => {
                        warn!(target: DB, "invalid zpr address in set {}: {} ({})", set_key, addr_str, err);
                        continue;
                    }
                };
                let a_key = attrs_key_for(&addr);

                // Pull the CN attribute out of the actor hash (JSON Attribute) as a
                // display label; a missing CN is a normal state, not an anomaly.
                let cn = match self.db.hget(&a_key, key::CN).await? {
                    Some(cn_attr_json) => {
                        let cn_attr: Attribute = serde_json::from_str(&cn_attr_json)?;
                        match cn_attr.get_single_value() {
                            Ok(cn_val) => Some(cn_val.to_string()),
                            Err(_) => Some(cn_attr.get_value_as_string()),
                        }
                    }
                    None => None,
                };
                actors.push((addr, cn));
            }
        }
        Ok(actors)
    }
}

/// returns 'actor:<ZADDR>'
fn actor_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}")
}

/// returns 'actor:<ZADDR>:attrs'
fn attrs_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}:attrs")
}

/// returns 'service:<MUNGED_SERVICENAME>'
fn service_key_for(service_name: &str) -> String {
    let svc_name_clean = KeyString::from(service_name);
    format!("{KEY_SERVICE}:{}", svc_name_clean.as_str())
}

/// returns 'actor:<ZADDR>:services'
fn actor_services_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}:services")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::DbConnection;
    use crate::db::db_fake::FakeDb;
    use crate::test_helpers::{
        make_actor_defexp, make_actor_with_services_defexp, make_adapter_actor_defexp,
        make_oidc_only_adapter_defexp,
    };
    use libeval::attribute::{ROLE_ADAPTER, ROLE_NODE, key};

    #[tokio::test]
    async fn test_add_and_get_actor_roundtrip() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_with_services_defexp(
            ROLE_NODE,
            "fd5a:5052::1",
            &["svc:one", "svc%two"],
            "actor-1",
        );
        let zpr_addr: IpAddr = "fd5a:5052::1".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();
        let loaded = repo.get_actor_by_zpr_addr(&zpr_addr).await.unwrap();

        assert!(loaded.is_node());
        assert_eq!(loaded.get_cn(), Some("actor-1"));
        assert_eq!(loaded.get_zpr_addr(), Some(&zpr_addr));
        assert!(loaded.provides("svc:one"));
        assert!(loaded.provides("svc%two"));
        assert_eq!(loaded.get_identity(), Some(vec!["id-1".to_string()]));
    }

    #[tokio::test]
    async fn test_list_services_decodes_names() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_with_services_defexp(
            ROLE_ADAPTER,
            "fd5a:5052::2",
            &["svc:one", "svc%two"],
            "actor-1",
        );
        let zpr_addr: IpAddr = "fd5a:5052::2".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();
        let mut services = repo.list_services().await.unwrap();
        services.sort_by(|a, b| a.name.cmp(&b.name));

        let names: Vec<String> = services.iter().map(|s| s.name.clone()).collect();
        assert_eq!(names, vec!["svc%two".to_string(), "svc:one".to_string()]);
        for entry in services {
            assert_eq!(entry.zpr_addr, zpr_addr);
        }
    }

    #[tokio::test]
    async fn test_rm_actor_cleans_up_keys() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db.clone());
        let actor =
            make_actor_with_services_defexp(ROLE_NODE, "fd5a:5052::3", &["svc:one"], "actor-1");
        let zpr_addr: IpAddr = "fd5a:5052::3".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();
        repo.rm_actor_by_zpr_addr(&zpr_addr).await.unwrap();

        let base_key = actor_key_for(&zpr_addr);
        let attrs_key = attrs_key_for(&zpr_addr);
        let services_key = actor_services_key_for(&zpr_addr);
        let svc_key = service_key_for("svc:one");

        assert!(!db.exists(&base_key).await.unwrap());
        assert!(!db.exists(&attrs_key).await.unwrap());
        assert!(!db.exists(&services_key).await.unwrap());
        assert!(!db.exists(&svc_key).await.unwrap());

        let nodes = db.smembers(KEY_NODES).await.unwrap();
        assert!(!nodes.contains(&zpr_addr.to_string()));
    }

    #[tokio::test]
    async fn test_list_actors_with_role_filter() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let node_actor =
            make_actor_with_services_defexp(ROLE_NODE, "fd5a:5052::10", &["svc:one"], "node-cn");
        let adapter_actor = make_actor_with_services_defexp(
            ROLE_ADAPTER,
            "fd5a:5052::20",
            &["svc:two"],
            "adapter-cn",
        );

        repo.add_actor(&node_actor).await.unwrap();
        repo.add_actor(&adapter_actor).await.unwrap();

        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        let mut all_actors = repo.list_actors(None).await.unwrap();
        all_actors.sort();
        assert_eq!(
            all_actors,
            vec![
                (node_addr, Some("node-cn".to_string())),
                (adapter_addr, Some("adapter-cn".to_string())),
            ]
        );

        let node_actors = repo.list_actors(Some(Role::Node)).await.unwrap();
        assert_eq!(node_actors, vec![(node_addr, Some("node-cn".to_string()))]);

        let adapter_actors = repo.list_actors(Some(Role::Adapter)).await.unwrap();
        assert_eq!(
            adapter_actors,
            vec![(adapter_addr, Some("adapter-cn".to_string()))]
        );
    }

    #[tokio::test]
    async fn test_get_zpr_addr_for_service_returns_addr_and_none() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor =
            make_actor_with_services_defexp(ROLE_NODE, "fd5a:5052::30", &["svc:one"], "actor-1");
        let zpr_addr: IpAddr = "fd5a:5052::30".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();

        let found = repo.get_zpr_addr_for_service("svc:one").await.unwrap();
        assert_eq!(found, Some(zpr_addr));

        let missing = repo.get_zpr_addr_for_service("svc:missing").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_get_zpr_addr_for_service_invalid_addr() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db.clone());
        let svc_key = service_key_for("svc:bad");

        db.hset(&svc_key, "zpr_addr", "not-an-ip").await.unwrap();

        let err = repo.get_zpr_addr_for_service("svc:bad").await.unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_get_actor_attrs_returns_only_found() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_defexp(&[
            (key::ROLE, ROLE_ADAPTER),
            (key::CN, "actor-attrs"),
            (key::ZPR_ADDR, "fd5a:5052::40"),
        ]);
        let zpr_addr: IpAddr = "fd5a:5052::40".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();

        let attrs = repo
            .get_actor_attrs(&zpr_addr, &[key::CN, "missing.key", key::ROLE])
            .await
            .unwrap();

        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].get_key(), key::CN);
        assert_eq!(attrs[0].get_single_value().unwrap(), "actor-attrs");
        assert_eq!(attrs[1].get_key(), key::ROLE);
        assert_eq!(attrs[1].get_single_value().unwrap(), ROLE_ADAPTER);
    }

    /// An actor that never sent a key reads back as absent rather than as an error.
    #[tokio::test]
    async fn test_get_a2a_dh_pubkey_none_when_absent() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_for_pubkey_test("fd5a:5052::60", "no-key", None);
        let zpr_addr: IpAddr = "fd5a:5052::60".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();

        let pubkey = repo.get_a2a_dh_pubkey_by_zpr_addr(&zpr_addr).await.unwrap();
        assert!(pubkey.is_none());
    }

    /// A stored FMT:BASE64 value decodes back to the raw 32 key bytes.
    #[tokio::test]
    async fn test_get_a2a_dh_pubkey_decodes_stored_value() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_for_pubkey_test(
            "fd5a:5052::61",
            "keyed",
            Some("ZprKF01:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
        );
        let zpr_addr: IpAddr = "fd5a:5052::61".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();

        let pubkey = repo
            .get_a2a_dh_pubkey_by_zpr_addr(&zpr_addr)
            .await
            .unwrap()
            .expect("actor has a stored key");
        assert_eq!(pubkey.public_key, (0..32u8).collect::<Vec<u8>>());
    }

    #[tokio::test]
    async fn test_get_a2a_dh_pubkey_rejects_unknown_format() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_for_pubkey_test("fd5a:5052::62", "bad-key", Some("ZprKF99:AAEC"));
        let zpr_addr: IpAddr = "fd5a:5052::62".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();

        let err = repo
            .get_a2a_dh_pubkey_by_zpr_addr(&zpr_addr)
            .await
            .unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn make_actor_for_pubkey_test(zpr_addr: &str, cn: &str, pubkey_value: Option<&str>) -> Actor {
        let mut attrs = vec![
            (key::ROLE, ROLE_ADAPTER),
            (key::CN, cn),
            (key::ZPR_ADDR, zpr_addr),
        ];
        if let Some(value) = pubkey_value {
            attrs.push((key::A2A_DH_PUBKEY, value));
        }
        make_actor_defexp(&attrs)
    }

    #[tokio::test]
    async fn test_list_services_for_actor_only_returns_actor_services() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let node_actor = make_actor_with_services_defexp(
            ROLE_NODE,
            "fd5a:5052::30",
            &["svc:one", "svc%two"],
            "cn.1",
        );
        let adapter_actor =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::40", &["svc:three"], "cn.2");

        repo.add_actor(&node_actor).await.unwrap();
        repo.add_actor(&adapter_actor).await.unwrap();

        let node_addr: IpAddr = "fd5a:5052::30".parse().unwrap();
        let mut node_services = repo.list_services_for_actor(&node_addr).await.unwrap();
        node_services.sort();

        assert_eq!(
            node_services,
            vec!["svc%two".to_string(), "svc:one".to_string()]
        );

        let adapter_addr: IpAddr = "fd5a:5052::40".parse().unwrap();
        let mut adapter_services = repo.list_services_for_actor(&adapter_addr).await.unwrap();
        adapter_services.sort();

        assert_eq!(adapter_services, vec!["svc:three".to_string()]);
    }

    /// update_actor is authoritative: an attribute dropped from the actor is dropped from
    /// the store, so a later load does not resurrect it. (An attribute refresh can remove
    /// attributes -- e.g. a trusted service no longer vends one.)
    #[tokio::test]
    async fn test_update_actor_drops_removed_attributes() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let mut actor = make_actor_defexp(&[
            (key::ROLE, ROLE_NODE),
            (key::CN, "drop-node"),
            (key::ZPR_ADDR, "fd5a:5052::10"),
            ("user.dept", "sales"),
        ]);
        repo.add_actor(&actor).await.unwrap();

        actor.remove_attribute("user.dept");
        repo.update_actor(&actor).await.unwrap();

        let addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let loaded = repo.get_actor_by_zpr_addr(&addr).await.unwrap();
        assert!(loaded.attrs_iter().all(|a| a.get_key() != "user.dept"));
        // The rest of the actor survived the rewrite.
        assert_eq!(loaded.get_cn(), Some("drop-node"));
    }

    // ------------------------------------------------------------------
    // zipline#29 / zipline#30 (A1 gate): CN-keyed actor-surface defects.
    // A1 pinned these as #[ignore]d failing tests against the CN-keyed code;
    // zipline#31 (A2) re-keys the surface onto the ZPR address and turns them
    // green (F4's assertion is inverted -- it documented the defect).
    // ------------------------------------------------------------------

    /// F1 (zipline#29): a CN-less actor (real OIDC-only connect case) must still be
    /// represented in the actor listing. The pre-A2 `list_actor_cns` HGET'd the `cn`
    /// attribute, warned "missing CN attribute for actor at key = ..." and
    /// `continue`d, so the actor silently vanished from the admin listing even
    /// though it was in the DB and in its role set. Re-keyed onto `list_actors` by
    /// zipline#31 (A2): the actor appears as `(addr, None)`.
    #[tokio::test]
    async fn test_list_actors_includes_cn_less_actor() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let cn_less = make_oidc_only_adapter_defexp("fd5a:5052::71");
        let normal = make_adapter_actor_defexp("fd5a:5052::72", "adapter-with-cn");

        repo.add_actor(&cn_less).await.unwrap();
        repo.add_actor(&normal).await.unwrap();

        // Both connected actors must be represented -- the CN-less one must not be
        // skipped; it is listed by its address with no CN label.
        let mut actors = repo.list_actors(None).await.unwrap();
        actors.sort();
        assert_eq!(
            actors,
            vec![
                ("fd5a:5052::71".parse().unwrap(), None),
                (
                    "fd5a:5052::72".parse().unwrap(),
                    Some("adapter-with-cn".to_string())
                ),
            ],
            "CN-less actor must appear as (addr, None)"
        );
    }

    /// F3 (zipline#29): two actors at different addresses sharing one CN must remain
    /// distinct, and BOTH must stay resolvable. Pre-A2 the CN-keyed `cn_idx` was a
    /// single-slot `DashMap<String, IpAddr>` written with `insert`, so the second
    /// connect overwrote the first, and `clean_up` removed the CN entry
    /// unconditionally, so either actor's disconnect orphaned the survivor.
    ///
    /// Re-keyed by zipline#31 (A2): the ZPR address identifies the actor, so the
    /// two same-CN actors are two `list_actors` entries, each resolving through
    /// `get_actor_by_zpr_addr`, and whichever colliding actor disconnects, the
    /// OTHER remains fully resolvable. Scenario 1 removes the later writer,
    /// scenario 2 the earlier writer.
    #[tokio::test]
    async fn test_shared_cn_actors_remain_distinct() {
        let addr_a: IpAddr = "fd5a:5052::81".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::82".parse().unwrap();

        // --- Scenario 1: later writer (actor_b) disconnects; actor_a must survive.
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let actor_a = make_adapter_actor_defexp("fd5a:5052::81", "shared-cn");
        let actor_b = make_adapter_actor_defexp("fd5a:5052::82", "shared-cn");
        repo.add_actor(&actor_a).await.unwrap();
        repo.add_actor(&actor_b).await.unwrap();

        // Both actors are connected: two distinct entries carrying the shared CN,
        // each reachable by its own address.
        let mut actors = repo.list_actors(None).await.unwrap();
        actors.sort();
        assert_eq!(
            actors,
            vec![
                (addr_a, Some("shared-cn".to_string())),
                (addr_b, Some("shared-cn".to_string())),
            ],
            "expected two distinct entries for the shared CN"
        );
        for addr in [&addr_a, &addr_b] {
            let loaded = repo.get_actor_by_zpr_addr(addr).await.unwrap();
            assert_eq!(loaded.get_cn(), Some("shared-cn"));
            assert_eq!(loaded.get_zpr_addr(), Some(addr));
        }

        repo.rm_actor_by_zpr_addr(&addr_b).await.unwrap();
        let survivor = repo
            .get_actor_by_zpr_addr(&addr_a)
            .await
            .expect("actor_a must stay resolvable after the colliding actor_b disconnected");
        assert_eq!(*survivor.get_zpr_addr().unwrap(), addr_a);
        assert_eq!(
            repo.list_actors(None).await.unwrap(),
            vec![(addr_a, Some("shared-cn".to_string()))],
            "only the survivor may remain listed"
        );

        // --- Scenario 2: earlier writer (actor_a) disconnects; actor_b must survive.
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let actor_a = make_adapter_actor_defexp("fd5a:5052::81", "shared-cn");
        let actor_b = make_adapter_actor_defexp("fd5a:5052::82", "shared-cn");
        repo.add_actor(&actor_a).await.unwrap();
        repo.add_actor(&actor_b).await.unwrap();

        repo.rm_actor_by_zpr_addr(&addr_a).await.unwrap();
        let survivor = repo
            .get_actor_by_zpr_addr(&addr_b)
            .await
            .expect("actor_b must stay resolvable after the colliding actor_a disconnected");
        assert_eq!(*survivor.get_zpr_addr().unwrap(), addr_b);
        assert_eq!(
            repo.list_actors(None).await.unwrap(),
            vec![(addr_b, Some("shared-cn".to_string()))],
            "only the survivor may remain listed"
        );
    }

    /// F4 (zipline#29): a fresh `ActorRepo` over an already-populated
    /// `Arc<dyn DbConnection>` (what a VS restart against persisted state produces)
    /// must be able to fetch every actor it lists. Pre-A2 an in-process `cn_idx`
    /// was populated only by `add_actor` and never rebuilt from the backing store,
    /// so a fresh repo LISTED the actor but 404'd its CN lookup. zipline#31 (A2)
    /// deletes the index -- `ActorRepo` is stateless over the DB -- so this cannot
    /// regress by construction.
    ///
    /// (Inverts A1's `test_fresh_repo_forgets_cn_index_documents_defect`, which
    /// deliberately asserted the broken behaviour so it could not regress silently.)
    #[tokio::test]
    async fn test_fresh_repo_resolves_persisted_actor() {
        let db: Arc<FakeDb> = Arc::new(FakeDb::new());

        // Repo #1 populates the store.
        let repo1 = ActorRepo::new(db.clone());
        let actor = make_adapter_actor_defexp("fd5a:5052::91", "persisted-cn");
        repo1.add_actor(&actor).await.unwrap();

        // Repo #2 over the SAME backing store: an ActorRepo that never saw
        // add_actor for this actor -- the restart-against-persisted-state case.
        let repo2 = ActorRepo::new(db);

        // The actor is visible to the lister...
        let addr: IpAddr = "fd5a:5052::91".parse().unwrap();
        let actors = repo2.list_actors(None).await.unwrap();
        assert_eq!(actors, vec![(addr, Some("persisted-cn".to_string()))]);

        // ...and every listed actor is fetchable: no in-process index remains to
        // go stale.
        for (listed_addr, _cn) in &actors {
            let loaded = repo2
                .get_actor_by_zpr_addr(listed_addr)
                .await
                .expect("a fresh repo must fetch every actor it lists");
            assert_eq!(loaded.get_zpr_addr(), Some(listed_addr));
        }
    }
}
