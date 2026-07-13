//! ConnectionControl is for handling new connections to the ZPRnet.
//! Nodes and adapters.  The two steps to a connection are authentication
//! and then authorization via policy.
//!
//! Nodes are authenticated using keys found in policy that are tied to
//! their CN.
//!
//! Adapters may be authenticated like nodes (using booststrap keys in policy),
//! or more commonly they will be authenticated by an authentication service
//! on th network.
//!
//! The authorization step runs through policy and attaches any special attributes
//! to the actor -- things like services offered.
//!
//! Finally, if everything goes well an address is assigned and the actor is
//! returned.

use chrono::Utc;
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use std::usize;
use tracing::{debug, error, info, warn};

use libeval::actor::{Actor, Role};
use libeval::attribute::{Attribute, key};
use libeval::eval::EvalContext;
use libeval::policy::Policy;

use zpr::vsapi::v1 as vsapi;
use zpr::vsapi_types::{AuthBlob, ChallengeAlg, Claim, ConnectRequest, SelfSignedBlob};

use crate::assembly::Assembly;
use crate::auth;
use crate::config;
use crate::error::ServiceError;
use crate::logging::targets::CC;

// TODO: move to libeval
const CLASS_ENDPOINT: &str = "endpoint";
const CLASS_USER: &str = "user";
const CLASS_SERVICE: &str = "service";

const ATTR_KEY_VS_IDENT: &str = "zpr.vs.bootstrap.ident";

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iss: String, // Issuer eg, 'vs.zpr/<IDENT>'
    sub: String, // Subject (user id), eg 'node/<CN>'
    exp: u64,    // Expiration time (as UNIX timestamp)
    iat: u64,    // Issued at time (as UNIX timestamp)
    jti: String, // JWT ID - unique identifier for the token, can be used for revocation
}

pub struct ConnectionControl {
    jwt_key: jwt::EncodingKey,
    authority: String,
}

impl ConnectionControl {
    pub fn new(vs_ident: String) -> Self {
        // massage ident into valid chars -> [a-zA-Z0-9.-_]
        let vs_ident: String = vs_ident
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let jwt_key = jwt::EncodingKey::from_secret(vs_ident.as_bytes());

        ConnectionControl {
            authority: format!("vs.zpr/{}", &vs_ident),
            jwt_key,
        }
    }

    /// VS uses this to create an "identity" token for bootstrap authenticated actors.
    ///
    /// `sub` should be 'node/<CN>' or 'adapter/<CN>'
    fn gen_jwt(&self, sub: String) -> Result<String, ServiceError> {
        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(
                config::DEFAULT_AUTH_EXPIRATION.as_secs() as i64,
            ))
            .expect("valid timestamp")
            .timestamp() as u64;
        let claims = JwtClaims {
            iss: self.authority.clone(),
            sub,
            exp: expiration,
            iat: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("time went backwards")
                .as_secs(),
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = jwt::encode(&jwt::Header::default(), &claims, &self.jwt_key).map_err(|e| {
            error!(target: CC, "failed to generate JWT: {}", e);
            ServiceError::Internal("JWT generation failed".into())
        })?;
        Ok(token)
    }

    /// Perform node specific authentication and run the connect request through policy.
    /// If successful you get an authenticated Actor back. This does not update our
    /// actor database.
    ///
    /// Currently a node must pass a request address and it must match policy.
    ///
    /// This does not update our actor database, or do anything with the nodes services.
    ///
    /// TODO: This needs more thought. This code path which is via the VSAPI 'authenticate' endpoint
    /// is only available to nodes, and this code assumes the node has bootstrap auth.  It is theoretically
    /// possible for a node to use external auth -- as long as it isn't the first node.
    ///
    /// This is a little odd mostly because this VSAPI authentication is the way that the
    /// first node establishes its identity (since before that there is no access to a vias service).
    ///
    /// However, it feels like once we have done that, future nodes should not have to actually
    /// authenticate with the VSAPI since they should have already authenticated just like an adapter
    /// does.
    ///
    /// See https://github.com/org-zpr/zpr-visaservice/issues/205
    ///
    pub async fn authenticate_node(
        &self,
        asm: Arc<Assembly>,
        challenge_presented: &[u8],
        timestamp: u64,
        cn: &str,
        challenge_response: &[u8],
        remote: SocketAddr,
        node_req_addr: IpAddr,
    ) -> Result<Actor, ServiceError> {
        // Massage this node authentication request into something that looks like a generic
        // adapter request.

        let mut authd_claims: Vec<Attribute> = Vec::new();
        authd_claims.push(Attribute::builder(key::SUBSTRATE_ADDR).value(remote.to_string()));

        let mut unauthd_claims: Vec<Attribute> = Vec::new();
        unauthd_claims.push(Attribute::builder(key::ZPR_ADDR).value(node_req_addr.to_string()));
        unauthd_claims.push(Attribute::builder(key::CN).value(cn.to_string()));

        let ss_blob = SelfSignedBlob {
            alg: ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: challenge_presented.to_vec(),
            cn: cn.to_string(),
            timestamp,
            signature: challenge_response.to_vec(),
        };

        // We are the authority since we are checking RSA locally.
        authd_claims.push(
            Attribute::builder(key::AUTHORITY)
                .expires(SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
                .value(&self.authority),
        );

        let node_actor = self
            .authenticate_zpr_entity_rsa(asm, &ss_blob, unauthd_claims, authd_claims, 0)
            .await?;

        // We only let nodes in here.
        if !node_actor.is_node() {
            info!(target: CC, "connection not approved for cn {}: not a node", cn);
            return Err(ServiceError::AuthenticationFailed("not authorized".into()));
        }

        Ok(node_actor)
    }

    /// Confirm adapter/node authentication and then get policy authorization, resulting in an Actor if
    /// everything checks out.
    ///
    /// This is used during a connection attempt to ZPR (as opposed to the VSAPI connection which right
    /// now is serviced by [ConnectionControl::authenticate_node]).
    ///
    pub async fn authenticate_adapter_or_node(
        &self,
        asm: Arc<Assembly>,
        req: ConnectRequest,
        connect_via: &IpAddr,
    ) -> Result<Actor, ServiceError> {
        if req.blobs.is_empty() || req.blobs.len() > 1 {
            return Err(ServiceError::Param("expected exactly one auth blob".into()));
        }

        check_required_claims(&req.claims, &[key::CN])?;

        let scrubbed_claims = scrub_adapter_claims(req.claims)?;

        let mut authd_claims = Vec::new();
        authd_claims.push(Attribute::builder(key::CONNECT_VIA).value(connect_via.to_string()));
        authd_claims
            .push(Attribute::builder(key::SUBSTRATE_ADDR).value(req.substrate_addr.to_string()));

        let actor = match &req.blobs[0] {
            AuthBlob::SS(ssb) => match ssb.alg {
                ChallengeAlg::RsaSha256Pkcs1v15 => {
                    // We are the authority since we are checking RSA locally.
                    authd_claims.push(
                        Attribute::builder(key::AUTHORITY)
                            .expires(SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
                            .value(&self.authority),
                    );

                    self.authenticate_zpr_entity_rsa(
                        asm,
                        ssb,
                        scrubbed_claims,
                        authd_claims,
                        req.dock_interface,
                    )
                    .await?
                }
            },
            AuthBlob::AC(_acb) => {
                return Err(ServiceError::Internal(
                    "external auth not yet supported".into(),
                ));
            }
        };

        Ok(actor)
    }

    pub async fn authenticate_visa_service(
        &self,
        asm: Arc<Assembly>,
        claims: Vec<Claim>,
    ) -> Result<Actor, ServiceError> {
        let mut authd_claims = Vec::new();

        authd_claims.push(Attribute::builder(key::AUTHORITY).value(&self.authority));

        for claim in claims {
            authd_claims.push(Attribute::builder(claim.key).value(claim.value));
        }

        let policy = asm.policy_mgr.get_current();

        // Ok checks out -- now run through policy.
        let vs_actor = self
            .authorize_connection(asm, &policy, &config::VS_CN, Vec::new(), authd_claims, 0)
            .await?;

        Ok(vs_actor)
    }

    /// Preform authentication of an adapter or a node, then run through policy.
    /// `unauthed_claims` - must include CN.
    async fn authenticate_zpr_entity_rsa(
        &self,
        asm: Arc<Assembly>,
        ssb: &SelfSignedBlob,
        unauthd_claims: Vec<Attribute>,
        authd_claims: Vec<Attribute>,
        dock_interface: u8,
    ) -> Result<Actor, ServiceError> {
        // a) is the auth correct (check policy for CN, check sig.)
        // b) is connection allowed by policy?
        //
        // Note that (b) is also needed for the AC type auth.

        {
            // Make sure there is a CN attribute.
            if !unauthd_claims.iter().any(|c| c.get_key() == key::CN) {
                warn!(target: CC, "adapter auth blob missing cn claim");
                return Err(ServiceError::AuthenticationFailed(
                    "cn claim is required".into(),
                ));
            }
            let claimed_cn = unauthd_claims
                .iter()
                .find(|c| c.get_key() == key::CN)
                .unwrap()
                .get_single_value()
                .unwrap(); // ok becuase checked earlier

            if claimed_cn != ssb.cn {
                warn!(target: CC, "cn mismatch: claim '{}' != blob '{}'", claimed_cn, ssb.cn);
                return Err(ServiceError::AuthenticationFailed(
                    "cn mismatch between claim and blob".into(),
                ));
            }
        }

        let policy = asm.policy_mgr.get_current();
        let pubkey = policy.get_bootstrap_key_by_cn(&ssb.cn).ok_or_else(|| {
            ServiceError::AuthenticationFailed(format!("no key found in policy for cn {}", ssb.cn))
        })?;

        if !auth::verify_ss_blob_signature(&ssb.cn, ssb, pubkey)? {
            info!(target: CC, "blob signature verification failed for cn {}", ssb.cn);
            return Err(ServiceError::AuthenticationFailed(
                "invalid signature".into(),
            ));
        }

        // Ok checks out -- now run through policy.
        let mut actor = self
            .authorize_connection(
                asm,
                &policy,
                &ssb.cn,
                unauthd_claims,
                authd_claims,
                dock_interface,
            )
            .await?;

        let actor_jwt = if actor.is_node() {
            self.gen_jwt(format!("node/{}", ssb.cn))?
        } else {
            self.gen_jwt(format!("adapter/{}", ssb.cn))?
        };
        let _ = actor.add_attribute(
            Attribute::builder(ATTR_KEY_VS_IDENT)
                .expires(SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
                .value(actor_jwt),
        );
        let _ = actor.add_identity_key(0, ATTR_KEY_VS_IDENT);

        Ok(actor)
    }

    /// Use policy to authorize the connection request. Works for adapters and nodes.
    /// If successful you get an authorized Actor back.
    ///
    /// Does not alter our actor databases.
    /// May take an IP address.
    ///
    /// Caller should set ROLE in unauthd_claims before calling.
    async fn authorize_connection(
        &self,
        asm: Arc<Assembly>,
        current_policy: &Arc<Policy>,
        endpoint_cn: &str,
        unauthd_claims: Vec<Attribute>,
        mut authd_claims: Vec<Attribute>,
        _dock_interface: u8,
    ) -> Result<Actor, ServiceError> {
        // TODO: Check with our revocation tables.
        info!(target: CC, "authorize_connection - TODO: check revocation table");
        // Actor may be denied by CN -- we can detect that before calling into policy.
        // In the future actor may be denied if the credential associated with the auth service is revoked.

        authd_claims.push(Attribute::builder(key::CN).value(endpoint_cn));
        authd_claims.push(
            Attribute::builder(key::CONFIG_ID)
                .value(format!("{}", current_policy.get_version().unwrap_or(0))),
        );

        // There may in the future be additional network I/O in the next step
        // for example if VS needs to talk to attribute service.

        let ectx = EvalContext::new(current_policy.clone());

        // TODO: Need to go in to eval and fix the approve_connection logic w/respect to the ROLE claim.
        // We won't know a priori if this is a node or adapter. Though sometimes we do know it's a node.
        // Anyway, best to let VS sort it out and do not do it in libeval.
        let mut authd_actor = match ectx.approve_connection(
            Some(&authd_claims),
            Some(&unauthd_claims),
            config::DEFAULT_AUTH_EXPIRATION,
        ) {
            Ok(actor) => actor,
            Err(e) => {
                info!(target: CC, "connection not approved for cn {}: {}", endpoint_cn, e);
                return Err(e.into());
            }
        };

        let actor_role = if authd_actor.is_node() {
            Role::Node
        } else {
            Role::Adapter
        };

        if let Some(addr) = authd_actor.get_zpr_addr() {
            info!(target: CC, "authorized connection of {actor_role:?} cn {} with ZPR addr {}", endpoint_cn, addr);
        } else {
            match asm.net_mgr.get_next_zpr_addr(&actor_role) {
                Ok(addr) => {
                    authd_actor.add_attribute(
                        Attribute::builder(key::ZPR_ADDR)
                            .expires(SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
                            .value(addr.to_string()),
                    )?;
                    info!(target: CC, "authorized adapter/{actor_role:?} cn {} assigned ZPR addr {}", endpoint_cn, addr);
                }
                Err(e) => {
                    error!(target: CC, "failed to assign ZPR addr to authorized adapter/{actor_role:?} cn {}: {}", endpoint_cn, e);
                    return Err(ServiceError::Internal("address assignment failed".into()));
                }
            }
        }

        Ok(authd_actor)
    }

    /// Disconnect logic. Cleans up actor database, visas, and our view of topology. Updates router.
    ///
    /// This is used only for policy disconnect calls over the VSAPI or for a policy instigated disconnect.
    /// In both cases, it is safe to remove all state for the disconnecting actor.
    ///
    /// ### Errors
    /// Most cleanup failures are logged and swallowed (the caller can't act on them). Only these
    /// propagate as `Err`:
    /// - Looking up the actor (`get_actor_by_zpr_addr`) hits a backing-store error other than
    ///   "not found" — i.e. the DB is unreachable/misbehaving.
    /// - Removing a node record (`remove_node`) may fail on a backing-store error.
    ///
    pub async fn disconnect(
        &self,
        asm: Arc<Assembly>,
        zpr_addr: IpAddr,
        reason: vsapi::DisconnectReason,
    ) -> Result<(), ServiceError> {
        info!(target: CC, "disconnect actor at {} for reason {:?}", zpr_addr, reason);

        let maybe_actor = asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await?;
        if maybe_actor.is_none() {
            warn!(target: CC, "disconnect for addr {zpr_addr} but no actor found in database");
        }

        match asm.actor_mgr.remove_actor_by_zpr_addr(&zpr_addr).await {
            Ok(()) => (),
            Err(e) => {
                // Caller can't do anything with this. So just log and continue.
                error!(target: CC, "failed to remove disconnected actor with addr {zpr_addr} from actor db: {e}");
            }
        };

        let mut removed_zpr_addrs = Vec::new();
        removed_zpr_addrs.push(zpr_addr);

        if let Some(actor) = maybe_actor {
            if actor.is_node() {
                asm.topo_mgr.remove_node(&zpr_addr).await;
                if let Some(vss_hndl) = asm.vss_mgr.get_handle(&zpr_addr) {
                    if let Err(e) = vss_hndl.stop().await {
                        error!(target: CC, "failed to stop VSS worker for disconnected node at addr {zpr_addr}: {e}");
                    }
                } else {
                    debug!(target: CC, "no VSS worker found for disconnected node at addr {zpr_addr}");
                }
                let connected_adapters = match asm
                    .actor_mgr
                    .get_adapters_connected_to_node(&zpr_addr)
                    .await
                {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        error!(target: CC, "failed to get connected adapters for disconnected node at addr {zpr_addr}: {e}");
                        Vec::new()
                    }
                };
                for adapter_addr in connected_adapters {
                    match asm.actor_mgr.remove_actor_by_zpr_addr(&adapter_addr).await {
                        Ok(()) => {
                            removed_zpr_addrs.push(adapter_addr);
                        }
                        Err(e) => {
                            // Caller can't do anything with this. So just log and continue.
                            error!(target: CC, "failed to remove disconnected adapter with addr {adapter_addr} from actor db: {e}");
                        }
                    };
                    if asm.net_mgr.is_managed_address(&adapter_addr) {
                        if let Err(s) = asm.net_mgr.release_zpr_addr(adapter_addr) {
                            error!(target: CC, "failed to release ZPR addr {adapter_addr} for orphaned adapter: {s}");
                        }
                    }
                }
                asm.actor_mgr.remove_node(&zpr_addr).await?;
                if let Err(e) = asm.visa_mgr.remove_visas_for_node(&zpr_addr).await {
                    error!(target: CC, "failed to remove visas for disconnected node at addr {zpr_addr}: {e}");
                }
            }
        }
        if let Err(e) = asm
            .visa_mgr
            .remove_visas_for_actors(&removed_zpr_addrs)
            .await
        {
            error!(target: CC, "failed to remove visas for disconnected actor at addr {zpr_addr}: {e}");
        }

        if asm.net_mgr.is_managed_address(&zpr_addr) {
            // De-allocating an address may error but it only indicates that the
            // address is not part of our pool.  We just log that if it occurs
            // and call the "disconnect" successful anyway.
            if let Err(e) = asm.net_mgr.release_zpr_addr(zpr_addr) {
                warn!(target: CC, "failed to release managed ZPR addr {zpr_addr} for actor disconnect: {e}");
            }
        }
        Ok(())
    }
}

/// Required claims must be present and non-empty.
fn check_required_claims(claims: &[Claim], required: &[&str]) -> Result<(), ServiceError> {
    let mut required_set = std::collections::HashSet::new();
    for rc in required {
        required_set.insert(*rc);
    }

    for claim in claims {
        if required_set.contains(claim.key.as_str()) {
            if claim.value.is_empty() {
                return Err(ServiceError::Param(format!(
                    "{} claim cannot be empty",
                    claim.key
                )));
            }
            required_set.remove(claim.key.as_str());
        }
    }

    if !required_set.is_empty() {
        let missing: Vec<&str> = required_set.into_iter().collect();
        return Err(ServiceError::Param(format!(
            "missing required claims: {:?}",
            missing
        )));
    }

    Ok(())
}

// Gatekeep claims. Claims are considered to be adapter _requests_ which may
// or may not be honored by policy.  But we set attributes from them and
// and some are for internal use only.
//
// Generally no claims that start with "zpr." are allowed except:
//   - zpr.addr -> which is interpreted as a request adapter ZPR address.
//
// Also cannot have <class>.zpr.* except:
//   - endpoint.zpr.adapter.cn -> which is the CN of the adapter as told to the node.
//
// Note classes are endpoint, user, service (as per ZPL and the compiler).
//
// Finally, the incoming VSAPI "Claims" are converted into libeval "Attributes" and returned.
fn scrub_adapter_claims(claims: Vec<Claim>) -> Result<Vec<Attribute>, ServiceError> {
    let mut scrubbed_claims = Vec::new();
    for claim in claims {
        if claim.key == key::ZPR_ADDR {
            // Allow zpr.addr
            scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
            continue;
        }

        if claim.key.starts_with("zpr.") {
            warn!(target: CC, "adapter claim key '{}' not allowed", claim.key);
            continue;
        }

        let parts: Vec<&str> = claim.key.split('.').collect();
        if parts.len() >= 2 && parts[1] == "zpr" {
            // Only permissible is endpoint.zpr.adapter.cn
            if claim.key == key::CN {
                // Allow endpoint.zpr.adapter.cn
                scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
                continue;
            }

            // We only check for the defined classes.
            if parts[0] == CLASS_ENDPOINT || parts[0] == CLASS_USER || parts[0] == CLASS_SERVICE {
                warn!(target: CC, "adapter claim key '{}' not allowed", claim.key);
                continue;
            }
        }

        // Note that we don't handle multi-value claims at this point.
        scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
    }
    Ok(scrubbed_claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_helpers::make_container_bytes;
    use libeval::pio;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use std::sync::Arc;
    use zpr::policy::v1;

    fn make_cc(ident: &str) -> ConnectionControl {
        ConnectionControl::new(ident.to_string())
    }

    fn decode_jwt(token: &str, secret: &str) -> Result<JwtClaims, jwt::errors::Error> {
        let key = jwt::DecodingKey::from_secret(secret.as_bytes());
        let validation = jwt::Validation::new(jwt::Algorithm::HS256);
        jwt::decode::<JwtClaims>(token, &key, &validation).map(|d| d.claims)
    }

    #[test]
    fn new_preserves_valid_ident_chars() {
        let cc = make_cc("valid-ident_1.2");
        assert_eq!(cc.authority, "vs.zpr/valid-ident_1.2");
    }

    #[test]
    fn new_sanitizes_special_chars() {
        let cc = make_cc("test@host:port/path");
        assert_eq!(cc.authority, "vs.zpr/test_host_port_path");
    }

    #[test]
    fn gen_jwt_node_has_correct_claims() {
        let cc = make_cc("test-vs");
        let token = cc.gen_jwt("node/my-node".to_string()).unwrap();
        let claims = decode_jwt(&token, "test-vs").expect("token must decode");

        assert_eq!(claims.sub, "node/my-node");
        assert_eq!(claims.iss, "vs.zpr/test-vs");
    }

    #[test]
    fn gen_jwt_jti_is_unique_per_call() {
        let cc = make_cc("test-vs");
        let t1 = decode_jwt(&cc.gen_jwt("node/cn".to_string()).unwrap(), "test-vs").unwrap();
        let t2 = decode_jwt(&cc.gen_jwt("node/cn".to_string()).unwrap(), "test-vs").unwrap();
        assert_ne!(t1.jti, t2.jti);
    }

    fn claim(key: &str, value: &str) -> Claim {
        Claim::new(key.to_string(), value.to_string())
    }

    fn keys(claims: &[Attribute]) -> Vec<String> {
        claims
            .iter()
            .map(|claim| claim.get_key().to_string())
            .collect()
    }

    #[test]
    fn scrub_adapter_claims_allows_addr_and_cn() {
        let claims = vec![
            claim(key::ZPR_ADDR, "fd5a:5052:90de::1"),
            claim(key::CN, "adapter.example"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::ZPR_ADDR, key::CN]);
    }

    #[test]
    fn scrub_adapter_claims_blocks_zpr_prefix_except_addr() {
        let claims = vec![
            claim("zpr.role", "adapter"),
            claim("zpr.services", "svc-a"),
            claim(key::ZPR_ADDR, "fd5a:5052:90de::2"),
            claim("endpoint.label", "edge"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::ZPR_ADDR, "endpoint.label"]);
    }

    #[test]
    fn scrub_adapter_claims_blocks_class_zpr_for_known_classes() {
        let claims = vec![
            claim("endpoint.zpr.adapter.token", "nope"),
            claim("user.zpr.name", "nope"),
            claim("service.zpr.name", "nope"),
            claim(key::CN, "allowed-cn"),
            claim("custom.zpr.value", "ok"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::CN, "custom.zpr.value"]);
    }

    // --- authenticate_node helpers ---

    fn gen_rsa_test_keypair() -> (PKey<Private>, Vec<u8>) {
        let rsa = Rsa::generate(2048).unwrap();
        let privkey = PKey::from_rsa(rsa).unwrap();
        let pubkey_der = privkey.public_key_to_der().unwrap();
        (privkey, pubkey_der)
    }

    fn sign_node_challenge(
        privkey: &PKey<Private>,
        timestamp: u64,
        cn: &str,
        challenge: &[u8],
    ) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha256(), privkey).unwrap();
        signer.update(&timestamp.to_be_bytes()).unwrap();
        signer.update(cn.as_bytes()).unwrap();
        signer.update(challenge).unwrap();
        signer.sign_to_vec().unwrap()
    }

    /// Returns container bytes for Capn Proto `PolicyContainer`
    fn make_policy_with_bootstrap_key(cn: &str, pubkey_der: &[u8]) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            let mut keys = policy_bldr.reborrow().init_keys(1);
            keys.reborrow().get(0).set_id(cn);
            keys.reborrow()
                .get(0)
                .set_key_type(v1::KeyMaterialT::RsaPub);
            keys.reborrow()
                .get(0)
                .init_key_allows(1)
                .set(0, v1::KeyAllowance::Bootstrap);
            keys.reborrow().get(0).set_key_data(pubkey_der);
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        let container = make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        );
        container
    }

    // --- authenticate_node tests ---

    #[tokio::test]
    async fn test_make_policy_with_bootstrap_key() {
        // Make sure our helper serializes Capn Proto properly.
        let cn = "test-node.zpr";
        let (_privkey, pubkey_der) = gen_rsa_test_keypair();
        let container_bytes = make_policy_with_bootstrap_key(cn, &pubkey_der);

        pio::load_policy_from_container(&container_bytes, &config::POLICY_MIN_VERSION)
            .expect("should load policy from container bytes");
    }

    #[tokio::test]
    async fn authenticate_node_unknown_cn() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let result = cc
            .authenticate_node(
                asm,
                b"challenge",
                12345678,
                "unknown.zpr",
                &[],
                "127.0.0.1:1234".parse().unwrap(),
                "fd5a:5052::1".parse().unwrap(),
            )
            .await;
        assert!(matches!(result, Err(ServiceError::AuthenticationFailed(_))));
    }

    #[tokio::test]
    async fn authenticate_node_invalid_signature() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (_, pubkey_der) = gen_rsa_test_keypair();
        match asm
            .policy_mgr
            .update_policy_from_container_bytes(make_policy_with_bootstrap_key(cn, &pubkey_der))
            .await
        {
            Ok(_vinst) => (),
            Err(e) => panic!("failed to update policy for test: {}", e),
        }

        let cc = make_cc("test-vs");
        let result = cc
            .authenticate_node(
                asm,
                b"challenge",
                12345678,
                cn,
                b"not-a-valid-rsa-sig",
                "127.0.0.1:1234".parse().unwrap(),
                "fd5a:5052::1".parse().unwrap(),
            )
            .await;
        assert!(matches!(result, Err(ServiceError::AuthenticationFailed(_))));
    }

    #[tokio::test]
    async fn authenticate_node_signature_wrong_content() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_bootstrap_key(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = 12345678u64;
        let bad_sig = sign_node_challenge(&privkey, timestamp + 1, cn, challenge);
        let result = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &bad_sig,
                "127.0.0.1:1234".parse().unwrap(),
                "fd5a:5052::1".parse().unwrap(),
            )
            .await;
        assert!(matches!(result, Err(ServiceError::AuthenticationFailed(_))));
    }

    fn make_policy_with_node_join_policy(cn: &str, pubkey_der: &[u8]) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            {
                let mut keys = policy_bldr.reborrow().init_keys(1);
                keys.reborrow().get(0).set_id(cn);
                keys.reborrow()
                    .get(0)
                    .set_key_type(v1::KeyMaterialT::RsaPub);
                keys.reborrow()
                    .get(0)
                    .init_key_allows(1)
                    .set(0, v1::KeyAllowance::Bootstrap);
                keys.reborrow().get(0).set_key_data(pubkey_der);
            }
            {
                // Empty match list → matches any connection; JoinFlag::Node marks this as a node.
                let mut jps = policy_bldr.reborrow().init_join_policies(1);
                jps.reborrow()
                    .get(0)
                    .init_flags(1)
                    .set(0, v1::JoinFlag::Node);
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    #[tokio::test]
    async fn authenticate_node_policy_denied() {
        // Test a valid node, but policy lacking a join policy for it.
        // So join is allowed but node role is denied.
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_bootstrap_key(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = 12345678u64;
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let result = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "127.0.0.1:1234".parse().unwrap(),
                "fd5a:5052::1".parse().unwrap(),
            )
            .await;
        assert!(
            matches!(result, Err(ServiceError::AuthenticationFailed(_))),
            "expected failure got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn authenticate_node_success() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = 12345678u64;
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "127.0.0.1:1234".parse().unwrap(),
                "fd5a:5052::1".parse().unwrap(),
            )
            .await
            .expect("authentication should succeed");

        assert!(actor.is_node());

        // zpr.vs.bootstrap.ident must be present and be a valid node JWT
        let jwt_str = actor
            .get_attribute(ATTR_KEY_VS_IDENT)
            .expect("bootstrap ident attribute must be present")
            .get_value()[0]
            .clone();
        let claims = decode_jwt(&jwt_str, "test-vs").expect("ident attribute must be a valid JWT");
        assert_eq!(claims.sub, format!("node/{}", cn));
        assert_eq!(claims.iss, "vs.zpr/test-vs");

        // get_identity() returns [jwt, cn, authority] in that order
        let identity = actor
            .get_identity()
            .expect("actor must have identity values");
        assert_eq!(identity[0], jwt_str);

        // Due to libeval not actually paying attention to what attributes are part of "identity",
        // it will add the CN claim.
        assert_eq!(identity[1], cn);
    }
}
