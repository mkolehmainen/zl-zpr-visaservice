//! Redis/ValKey operations for actor state.
//!
//! Note that a ZADDR is a munged version of the ZPR address - colons replaced with dashes.
//! Note that the MUNGED_SERVICENAME is a db::KeyString - colons and '%' replaced with percent encoding.
//!
//! This updates:
//! - actor:<ZADDR>                - a hash for each connected actor
//! - actor:<ZADDR>:attrs          - a hash of attributes for each actor maps attribute keys to Attribug in JSON.
//! - actor:<ZADDR>:services       - a set of service names offered by the actor.
//! - actor:<ZADDR>:hostnames      - a set of hostnames the actor has claimed (zipline#53).
//! - service:<MUNGED_SERVICENAME> - a hash. Includes key 'zpr_addr' with the ZPR address (string) of the actor providing the service.
//! - host:<MUNGED_HOSTNAME>       - a hash. Includes key 'zpr_addr' with the ZPR address (string) of the actor holding the hostname.
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

use crate::counters::Counters;
use crate::db::{DbConnection, DbOp, KeyString, ZAddr, gen_timestamp};
use crate::error::StoreError;
use crate::logging::targets::DB;

const KEY_ACTOR: &str = "actor";
const KEY_SERVICE: &str = "service";
const KEY_HOST: &str = "host";
const KEY_NODES: &str = "nodes";
const KEY_ADAPTERS: &str = "adapters";

/// The operator-namespace attribute whose values are claimed into the
/// `host:<NAME>` index (zipline#53). Deliberately NOT a `key::` constant in
/// `libeval/src/attribute.rs`: it is operator-namespace, not ZPR-owned, and
/// naming it there invites someone to add it to a reserved-namespace check.
const ATTR_DEVICE_HOSTNAME: &str = "device.hostname";

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
            self.release_owned_service_entries(&zpraddr_str, &service_names)
                .await?;
            self.db.del(&services_key).await?;
        }

        // host:<NAME> entries follow the actor record (zipline#53): release the
        // names this actor holds, owner-checked, when the record goes away.
        let hostnames_key = actor_hostnames_key_for(&zpraddr);
        if self.db.exists(&hostnames_key).await? {
            let host_names: HashSet<String> = self.db.smembers(&hostnames_key).await?;
            self.release_owned_host_entries(&zpraddr_str, &host_names)
                .await?;
            self.db.del(&hostnames_key).await?;
        }
        Ok(())
    }

    /// Release each `host:<name>` entry in `names` if and only if its `zpr_addr`
    /// still points at `zpraddr_str` — the owner check from zipline#31, restated
    /// for hostnames: a non-holder's departure must never destroy the holder's
    /// live entry. Unlike [Self::release_owned_service_entries] there is
    /// deliberately NO promotion of a surviving claimant: a hostname lost to
    /// first-claim-wins is only re-claimed by the loser's next normal attribute
    /// refresh (zipline#53 — no re-claim on release).
    async fn release_owned_host_entries(
        &self,
        zpraddr_str: &str,
        names: impl IntoIterator<Item = &String>,
    ) -> Result<(), StoreError> {
        for name in names {
            let host_key = host_key_for(name);
            let owner: Option<String> = self.db.hget(&host_key, "zpr_addr").await?;
            if owner.as_deref() == Some(zpraddr_str) {
                self.db.del(&host_key).await?;
            }
        }
        Ok(())
    }

    /// Release each `service:<name>` key in `names` if and only if its `zpr_addr`
    /// still points at `zpraddr_str`. Names re-claimed by another actor are left
    /// alone (the stale names may actually be valid names on new actors, so the
    /// owner is checked before touching the entry). Releasing an owned entry
    /// promotes another live claimant when one exists (zipline#51 review: with
    /// refreshes no longer clobbering their way to ownership, deleting the
    /// owner's entry outright would orphan the name until a survivor's next
    /// timed refresh) and deletes it only when nobody else claims the name.
    /// Shared by `clean_up` (actor departure) and `try_update_actor` (re-auth /
    /// attribute refresh) so the two release paths cannot drift apart again
    /// (zipline#51). Takes the names rather than re-reading the actor's set so
    /// the hostname index (H1) can reuse it for `host:<NAME>` entries.
    async fn release_owned_service_entries(
        &self,
        zpraddr_str: &str,
        names: impl IntoIterator<Item = &String>,
    ) -> Result<(), StoreError> {
        // The releasing actor must never be picked as its own successor; its
        // services set may still exist at this point on both call paths.
        let own_services_key = zpraddr_str
            .parse::<IpAddr>()
            .map(|addr| actor_services_key_for(&addr))
            .map_err(|e| {
                StoreError::InvalidData(format!("invalid ZPR address {zpraddr_str}: {e}"))
            })?;
        for name in names {
            let svc_key = service_key_for(name);
            let actor_addr_str: Option<String> = self.db.hget(&svc_key, "zpr_addr").await?;
            if let Some(actor_addr) = actor_addr_str {
                if actor_addr != zpraddr_str {
                    continue;
                }
                match self
                    .find_surviving_claimant(name, &own_services_key)
                    .await?
                {
                    Some(claimant_addr) => {
                        debug!(target: DB, "promoting surviving claimant for service: service={name} new_owner={claimant_addr}");
                        self.db.hset(&svc_key, "zpr_addr", &claimant_addr).await?;
                    }
                    None => {
                        self.db.del(&svc_key).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Find another live actor still claiming `service_name` in its private
    /// `actor:<ZADDR>:services` set, skipping `excluded_services_key` (the
    /// releasing actor's own set). An actor is live when its `actor:<ZADDR>`
    /// base record still exists. Candidates are sorted by address string so
    /// the promotion is deterministic. Returns the claimant's `zpr_addr`
    /// value for the `service:<name>` entry.
    async fn find_surviving_claimant(
        &self,
        service_name: &str,
        excluded_services_key: &str,
    ) -> Result<Option<String>, StoreError> {
        let keys = self
            .db
            .scan_match_all(format!("{KEY_ACTOR}:*:services"))
            .await?;
        let mut candidates = Vec::new();
        for key in keys {
            if key == excluded_services_key {
                continue;
            }
            let Some(zaddr_enc) = key
                .strip_prefix(&format!("{KEY_ACTOR}:"))
                .and_then(|s| s.strip_suffix(":services"))
            else {
                continue;
            };
            if !self.db.sismember(&key, service_name).await? {
                continue;
            }
            // Only a live actor is promotable: its base record must still exist
            // (a departing actor's base key is deleted before its services set).
            if !self.db.exists(&format!("{KEY_ACTOR}:{zaddr_enc}")).await? {
                continue;
            }
            let Ok(addr) = IpAddr::try_from(ZAddr::new_from_encoded(zaddr_enc)) else {
                warn!(target: DB, "unparseable ZPR address in services key, skipping claimant: {key}");
                continue;
            };
            candidates.push(addr.to_string());
        }
        candidates.sort();
        Ok(candidates.into_iter().next())
    }

    /// Add an actor and claim its `device.hostname` values (zipline#53).
    /// `policy_service_names` is the current policy's service-name set — a
    /// hostname claim colliding with one is rejected ("policy services win");
    /// passed as a parameter so this layer stays testable against `FakeDb`
    /// with no global state. Claim rejections are counted on `counters`.
    pub async fn add_actor(
        &self,
        actor: &Actor,
        policy_service_names: &HashSet<String>,
        counters: &Counters,
    ) -> Result<(), StoreError> {
        match self
            .try_add_actor(actor, policy_service_names, counters)
            .await
        {
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
    ///
    /// Re-claims the actor's `device.hostname` values into the `host:<NAME>`
    /// index (zipline#53) — idempotent for names it already holds; see
    /// [Self::add_actor] for the `policy_service_names` / `counters` contract.
    pub async fn update_actor(
        &self,
        actor: &Actor,
        policy_service_names: &HashSet<String>,
        counters: &Counters,
    ) -> Result<(), StoreError> {
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

        // Release entries the actor stopped advertising and still owns; entries
        // re-claimed by another actor are left alone (zipline#51 -- an
        // unconditional delete here destroyed the other actor's live entry on
        // re-auth/refresh). Only DROPPED names are released: releasing a name
        // the actor still advertises would promote a co-claimant away from a
        // perfectly live owner on every timed refresh. Owned entries the actor
        // keeps advertising are re-asserted by the loop below.
        let existing_services: HashSet<String> = self.db.smembers(&services_key).await?;
        let current_services: HashSet<String> = actor.services_iter().map(str::to_string).collect();
        let dropped_services: Vec<&String> = existing_services
            .iter()
            .filter(|name| !current_services.contains(*name))
            .collect();
        self.release_owned_service_entries(&zpraddr_str, dropped_services)
            .await?;
        self.db.del(&services_key).await?;

        // Add services back based on what actor actually still has. A refresh
        // must not steal a `service:<name>` entry another actor holds
        // (zipline#51): the last-add-wins claim happens at connect
        // (`try_add_actor`), not on every timed refresh. The name still goes
        // into this actor's set, so a later refresh re-claims the entry once
        // the current holder departs.
        for service_name in actor.services_iter() {
            debug!(target: DB, "adding service for actor: addr={zpraddr} service={service_name}");
            let svc_key_str = service_key_for(&service_name);
            let current_owner: Option<String> = self.db.hget(&svc_key_str, "zpr_addr").await?;
            match current_owner {
                Some(owner) if owner != zpraddr_str => {
                    debug!(target: DB, "service entry held by another actor, not overwriting: service={service_name} holder={owner}");
                }
                _ => {
                    self.db.hset(&svc_key_str, "zpr_addr", &zpraddr_str).await?;
                }
            }
            self.db.sadd(&services_key, &service_name).await?;
        }

        // Reconcile and claim `device.hostname` values (zipline#53).
        self.claim_hostnames_for_actor(actor, policy_service_names, counters)
            .await?;

        debug!(target: DB, "update actor in DB: addr={zpraddr} cn={:?} node?={}", actor.get_cn(), actor.is_node());
        Ok(())
    }

    /// Claim the actor's `device.hostname` values into the `host:<NAME>` index
    /// (zipline#53). Shared by both write paths (`try_add_actor` and
    /// `update_actor`) so claim semantics cannot drift apart. Per value:
    /// first claim wins (atomic via [DbConnection::hset_nx]), a re-claim of a
    /// name the actor already holds is idempotent, invalid values are rejected
    /// and logged (never transformed), and a value equal to a policy service
    /// name is rejected. Names the actor stopped claiming are released
    /// owner-checked. Rejections are counted and the losing names are rewritten
    /// into the actor's `hostname_conflicts` field (display data for #54,
    /// never an input to a decision).
    async fn claim_hostnames_for_actor(
        &self,
        actor: &Actor,
        policy_service_names: &HashSet<String>,
        counters: &Counters,
    ) -> Result<(), StoreError> {
        // TODO(zipline#53): implement the claim path.
        let _ = (actor, policy_service_names, counters);
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

    /// Given a hostname, look up the ZPR address of the actor holding it in the
    /// `host:<NAME>` index (zipline#53), if any.
    pub async fn get_zpr_addr_for_hostname(
        &self,
        hostname: &str,
    ) -> Result<Option<IpAddr>, StoreError> {
        let host_key = host_key_for(hostname);
        if let Some(addr_str) = self.db.hget(&host_key, "zpr_addr").await? {
            let addr: IpAddr = addr_str.parse().map_err(|e| {
                StoreError::InvalidData(format!(
                    "invalid zpr_addr in host entry {}: {}",
                    host_key, e
                ))
            })?;
            Ok(Some(addr))
        } else {
            Ok(None)
        }
    }

    /// Get the list of hostnames the actor currently holds in the `host:<NAME>`
    /// index (zipline#53).
    pub async fn list_hostnames_for_actor(
        &self,
        zpr_addr: &IpAddr,
    ) -> Result<Vec<String>, StoreError> {
        let hostnames_key = actor_hostnames_key_for(&zpr_addr);
        let names: HashSet<String> = self.db.smembers(&hostnames_key).await?;
        Ok(names.into_iter().collect())
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
    async fn try_add_actor(
        &self,
        actor: &Actor,
        policy_service_names: &HashSet<String>,
        counters: &Counters,
    ) -> Result<(), StoreError> {
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

        // Claim `device.hostname` values into the host:<NAME> index (zipline#53).
        self.claim_hostnames_for_actor(actor, policy_service_names, counters)
            .await?;

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
                // display label; a missing CN is a normal state, not an anomaly. A CN
                // that fails to load or decode degrades to no-CN rather than an error:
                // the ZPR address (the key) is what matters -- startup address
                // reservation walks this list, and one bad label must not discard
                // every other actor's address.
                let cn = match self.db.hget(&a_key, key::CN).await {
                    Ok(Some(cn_attr_json)) => {
                        match serde_json::from_str::<Attribute>(&cn_attr_json) {
                            Ok(cn_attr) => match cn_attr.get_single_value() {
                                Ok(cn_val) => Some(cn_val.to_string()),
                                Err(_) => Some(cn_attr.get_value_as_string()),
                            },
                            Err(err) => {
                                warn!(target: DB, "malformed CN attribute for actor {addr}, listing it without a CN: {err}");
                                None
                            }
                        }
                    }
                    Ok(None) => None,
                    Err(err) => {
                        warn!(target: DB, "could not load CN attribute for actor {addr}, listing it without a CN: {err}");
                        None
                    }
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

/// returns 'host:<MUNGED_HOSTNAME>'
///
/// `<NAME>` is percent-encoded through [KeyString] exactly like
/// [service_key_for] — a no-op for any name that passed validation, kept so
/// the key layer never depends on the validator (zipline#53).
fn host_key_for(hostname: &str) -> String {
    let host_name_clean = KeyString::from(hostname);
    format!("{KEY_HOST}:{}", host_name_clean.as_str())
}

/// returns 'actor:<ZADDR>:services'
fn actor_services_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}:services")
}

/// returns 'actor:<ZADDR>:hostnames'
fn actor_hostnames_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}:hostnames")
}

/// Validate one `device.hostname` value as a single lowercase DNS label
/// (zipline#53): `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, 1–63 bytes. Invalid values
/// are rejected by the claim path and logged — never transformed into valid
/// ones.
fn is_valid_hostname_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let inner = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    edge(bytes[0]) && edge(bytes[bytes.len() - 1]) && bytes.iter().all(|&b| inner(b))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::counters::CounterType;
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

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();
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

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();
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

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();
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

        repo.add_actor(&node_actor, &Default::default(), &Default::default())
            .await
            .unwrap();
        repo.add_actor(&adapter_actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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

    /// Startup address reservation walks `list_actors` (vs/src/main.rs
    /// `synchronize_state`), so one actor whose persisted CN attribute is
    /// malformed JSON must not error out the whole listing -- that would leave
    /// every other persisted ZPR address unreserved and re-assignable. The bad
    /// entry stays in the list with its address (the key) and no CN (a display
    /// label). Codex review on zipline#31.
    #[tokio::test]
    async fn test_list_actors_survives_malformed_cn_attribute() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db.clone());

        repo.add_actor(
            &make_adapter_actor_defexp("fd5a:5052::41", "good-cn"),
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();
        repo.add_actor(
            &make_adapter_actor_defexp("fd5a:5052::42", "bad-cn"),
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();

        // Corrupt one actor's persisted CN attribute JSON in place.
        let bad_addr: IpAddr = "fd5a:5052::42".parse().unwrap();
        db.hset(&attrs_key_for(&bad_addr), key::CN, "{not json")
            .await
            .unwrap();

        let mut actors = repo.list_actors(None).await.unwrap();
        actors.sort();

        let good_addr: IpAddr = "fd5a:5052::41".parse().unwrap();
        assert_eq!(
            actors,
            vec![(good_addr, Some("good-cn".to_string())), (bad_addr, None)]
        );
    }

    #[tokio::test]
    async fn test_get_zpr_addr_for_service_returns_addr_and_none() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);
        let actor =
            make_actor_with_services_defexp(ROLE_NODE, "fd5a:5052::30", &["svc:one"], "actor-1");
        let zpr_addr: IpAddr = "fd5a:5052::30".parse().unwrap();

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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

        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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

        repo.add_actor(&node_actor, &Default::default(), &Default::default())
            .await
            .unwrap();
        repo.add_actor(&adapter_actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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
        repo.add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

        actor.remove_attribute("user.dept");
        repo.update_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

        let addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let loaded = repo.get_actor_by_zpr_addr(&addr).await.unwrap();
        assert!(loaded.attrs_iter().all(|a| a.get_key() != "user.dept"));
        // The rest of the actor survived the rewrite.
        assert_eq!(loaded.get_cn(), Some("drop-node"));
    }

    /// zipline#51: two actors may advertise the same service name (the add path
    /// permits it -- the second provider's `hset` simply overwrites
    /// `service:<name>`, last add wins). A re-authentication or timed attribute
    /// refresh of the FIRST actor runs `update_actor`
    /// (actor_attributes.rs:73 -> actor_mgr.rs:156 -> update_actor), which must
    /// not destroy the SECOND actor's live `service:<name>` entry: the refresh
    /// releases only entries the refreshing actor still owns, same owner check
    /// `clean_up` has always done on the departure path.
    #[tokio::test]
    async fn test_update_actor_preserves_other_actors_service_entry() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let actor_a =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::a1", &["web"], "actor-a");
        let actor_b =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::b1", &["web"], "actor-b");

        repo.add_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();
        // B's add overwrites `service:web` -- B now owns the live entry.
        repo.add_actor(&actor_b, &Default::default(), &Default::default())
            .await
            .unwrap();

        // A's attribute refresh fires on a timer with A unchanged, still
        // advertising "web".
        repo.update_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();

        let addr_b: IpAddr = "fd5a:5052::b1".parse().unwrap();
        assert_eq!(
            repo.get_zpr_addr_for_service("web").await.unwrap(),
            Some(addr_b),
            "actor A's refresh must not clobber actor B's live service entry"
        );
    }

    /// The ordinary refresh: a single actor still advertising its service keeps
    /// its own live entry and its services set through `update_actor`.
    #[tokio::test]
    async fn test_update_actor_keeps_own_service_entry() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db.clone());

        let actor_a =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::a2", &["web"], "actor-a");
        repo.add_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();
        repo.update_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();

        let addr_a: IpAddr = "fd5a:5052::a2".parse().unwrap();
        assert_eq!(
            repo.get_zpr_addr_for_service("web").await.unwrap(),
            Some(addr_a)
        );
        let services: HashSet<String> =
            db.smembers(&actor_services_key_for(&addr_a)).await.unwrap();
        assert!(services.contains("web"));
    }

    /// A service the actor stopped advertising is released by the refresh: the
    /// `service:<name>` entry goes away and the name leaves the actor's set.
    #[tokio::test]
    async fn test_update_actor_releases_dropped_service() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db.clone());

        let actor_a =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::a3", &["web"], "actor-a");
        repo.add_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();

        // Same actor, no longer advertising "web".
        let addr_a: IpAddr = "fd5a:5052::a3".parse().unwrap();
        let mut refreshed = actor_a;
        refreshed.remove_attribute(key::SERVICES);
        repo.update_actor(&refreshed, &Default::default(), &Default::default())
            .await
            .unwrap();

        assert_eq!(repo.get_zpr_addr_for_service("web").await.unwrap(), None);
        let services: HashSet<String> =
            db.smembers(&actor_services_key_for(&addr_a)).await.unwrap();
        assert!(!services.contains("web"));
    }

    /// zipline#51 review (Codex P1 on PR #23): when the owner of a shared
    /// service departs, another live claimant must be promoted. A and B both
    /// advertise "web"; B owns the live entry (last add wins); B disconnects.
    /// `clean_up` deletes B's `service:web` key owner-checked, but with the
    /// refresh no longer clobbering its way to ownership, nothing re-installs
    /// A until A's next timed refresh -- the service resolves to `None` even
    /// though A is connected and advertising it. The departure path must
    /// promote a surviving claimant immediately.
    #[tokio::test]
    async fn test_clean_up_promotes_surviving_claimant() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let actor_a =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::a4", &["web"], "actor-a");
        let actor_b =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::b4", &["web"], "actor-b");

        repo.add_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();
        // B's add overwrites `service:web` -- B owns the live entry.
        repo.add_actor(&actor_b, &Default::default(), &Default::default())
            .await
            .unwrap();

        // B departs.
        let addr_b: IpAddr = "fd5a:5052::b4".parse().unwrap();
        repo.rm_actor_by_zpr_addr(&addr_b).await.unwrap();

        let addr_a: IpAddr = "fd5a:5052::a4".parse().unwrap();
        assert_eq!(
            repo.get_zpr_addr_for_service("web").await.unwrap(),
            Some(addr_a),
            "owner departure must promote the surviving claimant, not orphan the service"
        );
    }

    /// Same promotion on the refresh path: the OWNER stops advertising a
    /// service another live actor still claims. The refresh releases the
    /// owner's `service:<name>` entry and must hand it to the surviving
    /// claimant rather than leaving the name unresolvable until the
    /// claimant's own next refresh.
    #[tokio::test]
    async fn test_update_actor_drop_promotes_other_claimant() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db);

        let actor_b =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::b5", &["web"], "actor-b");
        let actor_a =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::a5", &["web"], "actor-a");

        repo.add_actor(&actor_b, &Default::default(), &Default::default())
            .await
            .unwrap();
        // A added last -- A owns the live entry, B still claims "web" in its set.
        repo.add_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();

        // A's refresh arrives no longer advertising "web".
        let mut refreshed = actor_a;
        refreshed.remove_attribute(key::SERVICES);
        repo.update_actor(&refreshed, &Default::default(), &Default::default())
            .await
            .unwrap();

        let addr_b: IpAddr = "fd5a:5052::b5".parse().unwrap();
        assert_eq!(
            repo.get_zpr_addr_for_service("web").await.unwrap(),
            Some(addr_b),
            "dropping an owned service must promote the surviving claimant"
        );
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

        repo.add_actor(&cn_less, &Default::default(), &Default::default())
            .await
            .unwrap();
        repo.add_actor(&normal, &Default::default(), &Default::default())
            .await
            .unwrap();

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
        repo.add_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();
        repo.add_actor(&actor_b, &Default::default(), &Default::default())
            .await
            .unwrap();

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
        repo.add_actor(&actor_a, &Default::default(), &Default::default())
            .await
            .unwrap();
        repo.add_actor(&actor_b, &Default::default(), &Default::default())
            .await
            .unwrap();

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
        repo1
            .add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();

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

    // ------------------------------------------------------------------
    // zipline#53: `device.hostname` -> `host:<NAME>` claim index.
    // ------------------------------------------------------------------

    /// Build an adapter actor at `zpr_addr` carrying a multi-valued
    /// `device.hostname` attribute with the given values.
    fn make_actor_with_hostnames(zpr_addr: &str, cn: &str, hostnames: &[&str]) -> Actor {
        let mut actor = make_adapter_actor_defexp(zpr_addr, cn);
        actor
            .add_attribute(Attribute::builder(ATTR_DEVICE_HOSTNAME).values(hostnames))
            .unwrap();
        actor
    }

    fn no_services() -> HashSet<String> {
        HashSet::new()
    }

    /// Contract 1 (zipline#53): every value of the multi-valued attribute is
    /// claimed — both names resolve to the actor's address, and
    /// `list_hostnames_for_actor` returns both.
    #[tokio::test]
    async fn test_hostname_multi_value_claim() {
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let counters = Counters::default();
        let actor =
            make_actor_with_hostnames("fd5a:5052::c1", "host-cn-1", &["somename", "m-7f3a2b"]);
        let addr: IpAddr = "fd5a:5052::c1".parse().unwrap();

        repo.add_actor(&actor, &no_services(), &counters)
            .await
            .unwrap();

        assert_eq!(
            repo.get_zpr_addr_for_hostname("somename").await.unwrap(),
            Some(addr)
        );
        assert_eq!(
            repo.get_zpr_addr_for_hostname("m-7f3a2b").await.unwrap(),
            Some(addr)
        );
        let mut names = repo.list_hostnames_for_actor(&addr).await.unwrap();
        names.sort();
        assert_eq!(names, vec!["m-7f3a2b".to_string(), "somename".to_string()]);
    }

    /// Contract 2 (zipline#53): first claim wins, PER VALUE. A second actor
    /// claiming `["somename", "other"]` loses `somename` to the first actor
    /// but still claims `other` — losing one value never costs the others.
    /// The rejection is counted and recorded in the loser's
    /// `hostname_conflicts` field (display data for #54).
    #[tokio::test]
    async fn test_hostname_first_claim_wins_per_value() {
        let db = Arc::new(FakeDb::new());
        let repo = ActorRepo::new(db.clone());
        let counters = Counters::default();
        let actor_1 = make_actor_with_hostnames("fd5a:5052::c2", "host-cn-1", &["somename"]);
        let actor_2 =
            make_actor_with_hostnames("fd5a:5052::c3", "host-cn-2", &["somename", "other"]);
        let addr_1: IpAddr = "fd5a:5052::c2".parse().unwrap();
        let addr_2: IpAddr = "fd5a:5052::c3".parse().unwrap();

        repo.add_actor(&actor_1, &no_services(), &counters)
            .await
            .unwrap();
        repo.add_actor(&actor_2, &no_services(), &counters)
            .await
            .unwrap();

        assert_eq!(
            repo.get_zpr_addr_for_hostname("somename").await.unwrap(),
            Some(addr_1),
            "first claim must win: somename stays with actor 1"
        );
        assert_eq!(
            repo.get_zpr_addr_for_hostname("other").await.unwrap(),
            Some(addr_2),
            "losing somename must not cost actor 2 its other claim"
        );
        assert_eq!(
            counters.counters[CounterType::HostnameClaimRejected].get_count(),
            1
        );
        // The losing name is recorded in actor 2's hostname_conflicts (JSON).
        let conflicts_json: Option<String> = db
            .hget(&actor_key_for(&addr_2), "hostname_conflicts")
            .await
            .unwrap();
        let conflicts: Vec<String> =
            serde_json::from_str(&conflicts_json.expect("hostname_conflicts field")).unwrap();
        assert_eq!(conflicts, vec!["somename".to_string()]);
    }

    /// Contract 3 (zipline#53): idempotence. `update_actor` on the holder must
    /// keep both claims — the claim test is "unset, or already mine", so
    /// re-auth and attribute refresh do not self-collide.
    #[tokio::test]
    async fn test_hostname_update_actor_idempotent() {
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let counters = Counters::default();
        let actor =
            make_actor_with_hostnames("fd5a:5052::c4", "host-cn-1", &["somename", "m-7f3a2b"]);
        let addr: IpAddr = "fd5a:5052::c4".parse().unwrap();

        repo.add_actor(&actor, &no_services(), &counters)
            .await
            .unwrap();
        repo.update_actor(&actor, &no_services(), &counters)
            .await
            .unwrap();

        assert_eq!(
            repo.get_zpr_addr_for_hostname("somename").await.unwrap(),
            Some(addr)
        );
        assert_eq!(
            repo.get_zpr_addr_for_hostname("m-7f3a2b").await.unwrap(),
            Some(addr)
        );
        assert_eq!(
            counters.counters[CounterType::HostnameClaimRejected].get_count(),
            0,
            "re-claiming a name the actor already holds is not a rejection"
        );
    }

    /// Contract 4 (zipline#53): release on disconnect. When the holder is
    /// removed, its names are freed — and the previous loser does NOT inherit
    /// them automatically (no re-claim on release; the loser re-claims on its
    /// next normal attribute refresh).
    #[tokio::test]
    async fn test_hostname_release_on_disconnect_no_auto_reclaim() {
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let counters = Counters::default();
        let holder = make_actor_with_hostnames("fd5a:5052::c5", "holder", &["somename"]);
        let loser = make_actor_with_hostnames("fd5a:5052::c6", "loser", &["somename"]);
        let holder_addr: IpAddr = "fd5a:5052::c5".parse().unwrap();

        repo.add_actor(&holder, &no_services(), &counters)
            .await
            .unwrap();
        repo.add_actor(&loser, &no_services(), &counters)
            .await
            .unwrap();

        repo.rm_actor_by_zpr_addr(&holder_addr).await.unwrap();

        assert_eq!(
            repo.get_zpr_addr_for_hostname("somename").await.unwrap(),
            None,
            "release must free the name; the loser does not inherit it automatically"
        );
    }

    /// Contract 5 (zipline#53, zipline#31 regression restated for hostnames):
    /// a NON-holder's disconnect must not destroy the holder's live `host:`
    /// entry — the release is owner-checked, reusing #51's pattern.
    #[tokio::test]
    async fn test_hostname_owner_checked_release() {
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let counters = Counters::default();
        let holder = make_actor_with_hostnames("fd5a:5052::c7", "holder", &["somename"]);
        let loser = make_actor_with_hostnames("fd5a:5052::c8", "loser", &["somename"]);
        let holder_addr: IpAddr = "fd5a:5052::c7".parse().unwrap();
        let loser_addr: IpAddr = "fd5a:5052::c8".parse().unwrap();

        repo.add_actor(&holder, &no_services(), &counters)
            .await
            .unwrap();
        repo.add_actor(&loser, &no_services(), &counters)
            .await
            .unwrap();

        // The non-holder departs.
        repo.rm_actor_by_zpr_addr(&loser_addr).await.unwrap();

        assert_eq!(
            repo.get_zpr_addr_for_hostname("somename").await.unwrap(),
            Some(holder_addr),
            "a non-holder's disconnect must not destroy the holder's entry"
        );
    }

    /// Contract 6 (zipline#53): validation. Invalid values are rejected and
    /// never transformed; valid siblings in the same attribute still claim.
    /// Grammar: `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, 1–63 bytes.
    #[tokio::test]
    async fn test_hostname_validation_rejects_invalid_keeps_valid_siblings() {
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let counters = Counters::default();
        let long_label = "x".repeat(64);
        let invalid = ["Some.Name", long_label.as_str(), "", "_x", "-x", "x-"];
        let mut values: Vec<&str> = invalid.to_vec();
        values.push("valid-name");
        let actor = make_actor_with_hostnames("fd5a:5052::c9", "host-cn-v", &values);
        let addr: IpAddr = "fd5a:5052::c9".parse().unwrap();

        repo.add_actor(&actor, &no_services(), &counters)
            .await
            .unwrap();

        // The valid sibling claimed.
        assert_eq!(
            repo.get_zpr_addr_for_hostname("valid-name").await.unwrap(),
            Some(addr)
        );
        // No invalid value claimed anything, under its own name or transformed.
        for name in invalid {
            if name.is_empty() {
                continue;
            }
            assert_eq!(
                repo.get_zpr_addr_for_hostname(name).await.unwrap(),
                None,
                "invalid value {name:?} must not be claimed"
            );
        }
        assert_eq!(
            repo.get_zpr_addr_for_hostname("some.name").await.unwrap(),
            None,
            "invalid values must never be transformed into valid ones"
        );
        let names = repo.list_hostnames_for_actor(&addr).await.unwrap();
        assert_eq!(names, vec!["valid-name".to_string()]);
    }

    /// Contract 7 (zipline#53): policy services win. A value equal to a policy
    /// service name is rejected and counted.
    #[tokio::test]
    async fn test_hostname_policy_service_name_wins() {
        let repo = ActorRepo::new(Arc::new(FakeDb::new()));
        let counters = Counters::default();
        let actor = make_actor_with_hostnames("fd5a:5052::ca", "host-cn-p", &["web", "ok-name"]);
        let addr: IpAddr = "fd5a:5052::ca".parse().unwrap();
        let policy_services: HashSet<String> = ["web".to_string()].into_iter().collect();

        repo.add_actor(&actor, &policy_services, &counters)
            .await
            .unwrap();

        assert_eq!(
            repo.get_zpr_addr_for_hostname("web").await.unwrap(),
            None,
            "a value equal to a policy service name must be rejected"
        );
        assert_eq!(
            repo.get_zpr_addr_for_hostname("ok-name").await.unwrap(),
            Some(addr)
        );
        assert_eq!(
            counters.counters[CounterType::HostnameClaimRejected].get_count(),
            1
        );
    }

    /// Contract 8 (zipline#53): the `hset_nx` claim primitive returns `true`
    /// only for the call that set the field. (Redis HSETNX returns the same;
    /// this pins the `FakeDb` mirror of that contract.)
    #[tokio::test]
    async fn test_hset_nx_returns_true_only_for_setting_call() {
        let db = FakeDb::new();
        assert!(
            db.hset_nx("host:x", "zpr_addr", "fd5a:5052::1")
                .await
                .unwrap(),
            "first hset_nx must report it set the field"
        );
        assert!(
            !db.hset_nx("host:x", "zpr_addr", "fd5a:5052::2")
                .await
                .unwrap(),
            "second hset_nx must report the field already existed"
        );
        assert_eq!(
            db.hget("host:x", "zpr_addr").await.unwrap(),
            Some("fd5a:5052::1".to_string()),
            "the losing call must not overwrite the value"
        );
    }

    /// The label validator itself, edge cases pinned.
    #[test]
    fn test_is_valid_hostname_label() {
        assert!(is_valid_hostname_label("a"));
        assert!(is_valid_hostname_label("m-7f3a2b"));
        assert!(is_valid_hostname_label("0name9"));
        assert!(is_valid_hostname_label(&"x".repeat(63)));
        assert!(!is_valid_hostname_label(""));
        assert!(!is_valid_hostname_label(&"x".repeat(64)));
        assert!(!is_valid_hostname_label("Some.Name"));
        assert!(!is_valid_hostname_label("UPPER"));
        assert!(!is_valid_hostname_label("_x"));
        assert!(!is_valid_hostname_label("-x"));
        assert!(!is_valid_hostname_label("x-"));
        assert!(!is_valid_hostname_label("a b"));
    }
}
