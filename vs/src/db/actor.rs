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

use dashmap::DashMap;
use libeval::actor::Actor;
use libeval::attribute::Attribute;
use libeval::attribute::key;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, error, warn};

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

    cn_idx: DashMap<String, IpAddr>, // CN -> ZPR_ADDRESS
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
        ActorRepo {
            db: db_handle,
            cn_idx: DashMap::new(),
        }
    }

    /// Undo all the redis additions performed by `add_actor`.
    async fn clean_up(&self, zpraddr: &IpAddr, cn: Option<&str>) -> Result<(), StoreError> {
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

        if let Some(cn_val) = cn {
            self.cn_idx.remove(cn_val);
        }
        Ok(())
    }

    pub async fn add_actor(&self, actor: &Actor) -> Result<(), StoreError> {
        match self.try_add_actor(actor).await {
            Ok(_) => {
                self.add_to_cache(actor);
                Ok(())
            }
            Err(e) => {
                // Attempt to clean up after ourselves...
                warn!(target: DB, "add_actor failed, attempting cleanup");
                if let Some(zpraddr) = actor.get_zpr_addr() {
                    match self.clean_up(zpraddr, actor.get_cn()).await {
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

    /// List the ZPR addresses of all connected actors.
    pub async fn list_zpr_addrs(&self) -> Result<Vec<IpAddr>, StoreError> {
        let mut addrs = Vec::new();

        let node_addr_strs: HashSet<String> = self.db.smembers(KEY_NODES).await?;
        for addr_str in node_addr_strs {
            let addr: IpAddr = match addr_str.parse() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(target: DB, "invalid zpr address in set {}: {} ({})", KEY_NODES, addr_str, err);
                    continue;
                }
            };
            addrs.push(addr);
        }

        let adapter_addr_strs: HashSet<String> = self.db.smembers(KEY_ADAPTERS).await?;
        for addr_str in adapter_addr_strs {
            let addr: IpAddr = match addr_str.parse() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(target: DB, "invalid zpr address in set {}: {} ({})", KEY_ADAPTERS, addr_str, err);
                    continue;
                }
            };
            addrs.push(addr);
        }

        Ok(addrs)
    }

    /// Update existing actor data.
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
        let ops = actor
            .attrs_iter()
            .map(|attr| DbOp::HSet {
                hash_key: attrs_key.clone(),
                field: attr.get_key().to_string(),
                value: serde_json::to_string(attr).unwrap_or_default(),
            })
            .collect::<Vec<_>>();
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

    /// Update our in-memory cache when we add an actor.
    pub fn add_to_cache(&self, actor: &Actor) {
        if let Some(cn_val) = actor.get_cn() {
            if let Some(zpr_addr) = actor.get_zpr_addr() {
                self.cn_idx.insert(cn_val.to_string(), zpr_addr.clone());
            }
        }
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

        self.clean_up(&zpraddr, actor.get_cn()).await?;

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
        let opt_cn = match self.get_actor_attrs(zpra, &[key::CN]).await {
            Ok(attr_list) => {
                if attr_list.is_empty() {
                    None
                } else {
                    if let Ok(cn_val) = attr_list[0].get_single_value() {
                        Some(cn_val.to_string())
                    } else {
                        None
                    }
                }
            }
            Err(_) => None,
        };

        self.clean_up(zpra, opt_cn.as_deref()).await?;
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

    /// Returns only the CN for the actor at the given ZPR address, without loading the full actor.
    ///
    /// Returns `StoreError::NotFound` if no actor exists for the address or the actor has no CN attribute.
    pub async fn get_cn_by_zpr_addr(&self, zpra: &IpAddr) -> Result<String, StoreError> {
        let base_key = actor_key_for(zpra);
        let exists: bool = self.db.exists(&base_key).await?;
        if !exists {
            return Err(StoreError::NotFound(format!("actor not found: {}", zpra)));
        }
        let mut attrs = self.get_actor_attrs(zpra, &[key::CN]).await?;
        if attrs.is_empty() {
            return Err(StoreError::NotFound(format!("actor at {} has no CN", zpra)));
        }
        let cn_attr = attrs.remove(0);
        match cn_attr.get_single_value() {
            Ok(cn_val) => Ok(cn_val.to_string()),
            Err(_) => Ok(cn_attr.get_value_as_string()),
        }
    }

    /// Look up actor by CN attribute. Uses our cache.
    ///
    /// ## Errors
    // - Returns `StoreError::NotFound` if no actor found for the given CN.
    pub async fn get_actor_by_cn(&self, cn: &str) -> Result<Actor, StoreError> {
        let actor_addr = match self.cn_idx.get(cn) {
            Some(addr) => addr.clone(),
            None => {
                return Err(StoreError::NotFound(format!(
                    "actor not found for CN: {}",
                    cn
                )));
            }
        };
        self.get_actor_by_zpr_addr(&actor_addr).await
    }

    /// This uses our "nodes" and "adapters" sets to list the CN values of all connected actors.
    pub async fn list_actor_cns(&self, by_roles: Option<Role>) -> Result<Vec<String>, StoreError> {
        let mut cns = Vec::new();

        let set_keys = match by_roles {
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

                // Pull the CN attribute out of the actor hash (which is JSON Attribute)
                if let Some(cn_attr_json) = self.db.hget(&a_key, key::CN).await? {
                    let cn_attr: Attribute = serde_json::from_str(&cn_attr_json)?;
                    match cn_attr.get_single_value() {
                        Ok(cn_val) => cns.push(cn_val.to_string()),
                        Err(_) => cns.push(cn_attr.get_value_as_string()),
                    }
                } else {
                    warn!(target: DB, "missing CN attribute for actor at key = {a_key}");
                }
            }
        }
        Ok(cns)
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
    use crate::test_helpers::{make_actor_defexp, make_actor_with_services_defexp};
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
    async fn test_list_actor_cns_with_role_filter() {
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

        let mut all_cns = repo.list_actor_cns(None).await.unwrap();
        all_cns.sort();
        assert_eq!(
            all_cns,
            vec!["adapter-cn".to_string(), "node-cn".to_string()]
        );

        let node_cns = repo.list_actor_cns(Some(Role::Node)).await.unwrap();
        assert_eq!(node_cns, vec!["node-cn".to_string()]);

        let adapter_cns = repo.list_actor_cns(Some(Role::Adapter)).await.unwrap();
        assert_eq!(adapter_cns, vec!["adapter-cn".to_string()]);
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

    #[tokio::test]
    async fn test_get_actor_by_cn_not_found() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let err = repo.get_actor_by_cn("missing-cn").await.unwrap_err();
        match err {
            StoreError::NotFound(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_get_actor_by_cn_and_rm_clears_cache() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_with_services_defexp(
            ROLE_NODE,
            "fd5a:5052::50",
            &["svc:one"],
            "actor-cache",
        );
        let zpr_addr: IpAddr = "fd5a:5052::50".parse().unwrap();

        repo.add_actor(&actor).await.unwrap();
        let loaded = repo.get_actor_by_cn("actor-cache").await.unwrap();
        assert_eq!(loaded.get_zpr_addr(), Some(&zpr_addr));

        repo.rm_actor_by_zpr_addr(&zpr_addr).await.unwrap();
        let err = repo.get_actor_by_cn("actor-cache").await.unwrap_err();
        match err {
            StoreError::NotFound(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
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

    #[tokio::test]
    async fn test_get_cn_by_zpr_addr_returns_cn() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_defexp(&[
            (key::ROLE, ROLE_NODE),
            (key::CN, "my-node"),
            (key::ZPR_ADDR, "fd5a:5052::10"),
        ]);
        repo.add_actor(&actor).await.unwrap();

        let addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let cn = repo.get_cn_by_zpr_addr(&addr).await.unwrap();
        assert_eq!(cn, "my-node");
    }

    #[tokio::test]
    async fn test_get_cn_by_zpr_addr_not_found() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let err = repo.get_cn_by_zpr_addr(&addr).await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_get_cn_by_zpr_addr_matches_get_actor_get_cn() {
        //  Both get_cn_by_zpr_addr and get_actor_by_zpr_addr().get_cn() must return the same CN.
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor = make_actor_defexp(&[
            (key::ROLE, ROLE_NODE),
            (key::CN, "roundtrip-node"),
            (key::ZPR_ADDR, "fd5a:5052::10"),
        ]);
        repo.add_actor(&actor).await.unwrap();

        let addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let cn_direct = repo.get_cn_by_zpr_addr(&addr).await.unwrap();
        let loaded = repo.get_actor_by_zpr_addr(&addr).await.unwrap();
        let cn_via_actor = loaded.get_cn().unwrap();
        assert_eq!(cn_direct, cn_via_actor);
    }
}
