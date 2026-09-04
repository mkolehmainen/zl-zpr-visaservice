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
use std::time::{Duration, SystemTime};
use std::usize;
use tracing::{debug, error, info, warn};

use libeval::actor::{Actor, Role};
use libeval::attribute::{Attribute, AttributeSource, key};
use libeval::eval::EvalContext;
use libeval::policy::Policy;

use zpr::vsapi::v1 as vsapi;
use zpr::vsapi_types::{
    ApiResponseError, AuthBlob, ChallengeAlg, Claim, ConnectRequest, ErrorCode, OidcBlob,
    PublicKey, SelfSignedBlob,
};

use crate::assembly::Assembly;
use crate::auth;
use crate::config;
use crate::error::ServiceError;
use crate::logging::targets::CC;
use crate::oidc::{OidcError, validate_id_token};
use crate::trusted_services::{derive_user_authority, lookup_identities};

// TODO: move to libeval
const CLASS_DEVICE: &str = "device";
const CLASS_USER: &str = "user";
const CLASS_SERVICE: &str = "service";

const ATTR_KEY_VS_IDENT: &str = "zpr.vs.bootstrap.ident";

/// Identity namespace one auth blob authenticates. A connection may present at most
/// one blob per namespace (zipline#7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Device,
    User,
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Namespace::Device => write!(f, "device"),
            Namespace::User => write!(f, "user"),
        }
    }
}

/// What one successfully-validated auth blob contributes to the connection: the
/// claims it authenticated and the identity namespace it covers (zipline#7).
struct BlobOutcome {
    authd: Vec<Attribute>,
    namespace: Namespace,
}

/// The endpoint CN for logging/JWT purposes: the authenticated CN when a device blob
/// verified one, else the (unauthenticated) claimed CN, else empty.
fn authd_or_claimed_cn(authd_claims: &[Attribute], unauthd_claims: &[Attribute]) -> String {
    authd_claims
        .iter()
        .chain(unauthd_claims.iter())
        .find(|a| a.get_key() == key::CN)
        .and_then(|a| a.get_single_value().ok())
        .unwrap_or_default()
        .to_string()
}

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
    /// `lifetime` is how long the token is valid for.
    fn gen_jwt(&self, sub: String, lifetime: Duration) -> Result<String, ServiceError> {
        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(lifetime.as_secs() as i64))
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
    /// `reported_substrate` is the substrate address the node advertised in its connect
    /// params (the address peers dial). When policy topology also declares a substrate for
    /// this node the two must agree; when it declares none (e.g. a single-node deploy with
    /// no peerings) the reported value is used as-is. Either way the resolved value becomes
    /// the node's `key::SUBSTRATE_ADDR` claim -- there is no longer a TCP-peer-address
    /// fallback (see https://github.com/org-zpr/zpr-visaservice/issues/299).
    ///
    pub async fn authenticate_node(
        &self,
        asm: Arc<Assembly>,
        challenge_presented: &[u8],
        timestamp: u64,
        cn: &str,
        challenge_response: &[u8],
        node_req_addr: IpAddr,
        reported_substrate: SocketAddr,
        a2a_dh_pubkey: Option<&PublicKey>,
    ) -> Result<Actor, ServiceError> {
        // Massage this node authentication request into something that looks like a generic
        // adapter request.

        let mut authd_claims: Vec<Attribute> = Vec::new();

        // Policy topology may declare this node's substrate address; if so the node's
        // advertised value must match it. With no topology entry (single-node deploy,
        // no peerings) the advertised value is all we have, and it is trusted operator
        // config just like a policy-declared substrate.
        let substrate_addr = match substrate_addr_from_topology(&asm, &node_req_addr) {
            Some(sa) => {
                if sa != reported_substrate {
                    return Err(ServiceError::Param(format!(
                        "substrate address mismatch: policy declares {sa}, node reported {reported_substrate}"
                    )));
                }
                sa
            }
            None => reported_substrate,
        };
        authd_claims
            .push(Attribute::builder(key::SUBSTRATE_ADDR).value(substrate_addr.to_string()));
        match a2a_dh_pubkey.and_then(a2a_dh_pubkey_claim) {
            Some(attr) => authd_claims.push(attr),
            None => warn!(target: CC, "node {cn} sent no usable A2A DH public key"),
        }

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

        // Built-in RSA verification is the device authority (Contract 7).
        authd_claims.push(
            Attribute::builder(key::DEVICE_AUTHORITY)
                .expires_in(config::DEFAULT_AUTH_EXPIRATION)
                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
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
        if req.blobs.is_empty() {
            return Err(ServiceError::Param(
                "at least one auth blob is required".into(),
            ));
        }

        check_required_claims(&req.claims, &[key::CN])?;

        let scrubbed_claims = scrub_adapter_claims(req.claims)?;

        let mut authd_claims = Vec::new();
        authd_claims.push(Attribute::builder(key::CONNECT_VIA).value(connect_via.to_string()));
        authd_claims
            .push(Attribute::builder(key::SUBSTRATE_ADDR).value(req.substrate_addr.to_string()));
        match a2a_dh_pubkey_claim(&req.a2a_dh_public_key) {
            Some(attr) => authd_claims.push(attr),
            None => warn!(target: CC, "adapter via {connect_via} sent no usable A2A DH public key"),
        }

        // Validate every presented blob (spec: presented-and-invalid fails the whole
        // connection; absent is not a failure). Each arm authenticates one identity
        // namespace and yields its authenticated claims; the first error aborts, and
        // a repeated namespace is a protocol error.
        let mut seen_namespaces: Vec<Namespace> = Vec::new();
        for blob in &req.blobs {
            let outcome = match blob {
                AuthBlob::SS(ssb) => match ssb.alg {
                    ChallengeAlg::RsaSha256Pkcs1v15 => {
                        // Built-in RSA verification is the device authority (Contract 7).
                        let mut authd = vec![
                            Attribute::builder(key::DEVICE_AUTHORITY)
                                .expires_in(config::DEFAULT_AUTH_EXPIRATION)
                                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
                        ];
                        authd.extend(self.authenticate_ss_blob(&asm, ssb, &scrubbed_claims)?);
                        BlobOutcome {
                            authd,
                            namespace: Namespace::Device,
                        }
                    }
                },
                AuthBlob::AC(_acb) => {
                    return Err(ServiceError::Internal(
                        "external auth not yet supported".into(),
                    ));
                }
                // A user login: validate the id_token offline against the declared
                // provider and stamp the user authority (zipline#11, C5).
                AuthBlob::Oidc(oidc_blob) => self.authenticate_oidc_blob(&asm, oidc_blob).await?,
            };
            if seen_namespaces.contains(&outcome.namespace) {
                return Err(ServiceError::Param(format!(
                    "duplicate {} authentication",
                    outcome.namespace
                )));
            }
            seen_namespaces.push(outcome.namespace);
            authd_claims.extend(outcome.authd);
        }

        // Every presented blob validated -- now run through policy. A validated
        // user (OIDC) blob makes "no join policy matched" a refusal (policyDenied)
        // rather than the #227 device-only fallthrough.
        let user_login_presented = seen_namespaces.contains(&Namespace::User);
        let policy = asm.policy_mgr.get_current();
        let endpoint_cn = authd_or_claimed_cn(&authd_claims, &scrubbed_claims);
        let mut actor = self
            .authorize_connection(
                asm,
                &policy,
                &endpoint_cn,
                scrubbed_claims,
                authd_claims,
                req.dock_interface,
                user_login_presented,
            )
            .await?;

        let auth_expiration = if endpoint_cn == config::VS_CN {
            config::VS_AUTH_EXPIRATION
        } else {
            config::DEFAULT_AUTH_EXPIRATION
        };
        let actor_jwt = if actor.is_node() {
            self.gen_jwt(format!("node/{}", endpoint_cn), auth_expiration)?
        } else {
            self.gen_jwt(format!("adapter/{}", endpoint_cn), auth_expiration)?
        };
        let _ = actor.add_attribute(
            Attribute::builder(ATTR_KEY_VS_IDENT)
                .expires(SystemTime::now() + auth_expiration)
                .value(actor_jwt),
        );
        let _ = actor.add_identity_key(0, ATTR_KEY_VS_IDENT);

        // Our own adapter connects late: the node self-authorizes it during bootstrap and
        // sends the real request once it has VSAPI access.
        if actor.get_cn() == Some(config::VS_CN) {
            let vs_addr = IpAddr::V6(config::VS_ZPR_ADDR);
            if actor.get_zpr_addr() != Some(&vs_addr) {
                return Err(ServiceError::AuthenticationFailed(format!(
                    "visa service adapter claimed address {:?}, expected {vs_addr}",
                    actor.get_zpr_addr()
                )));
            }
            // The ordinary adapter path already stamped DEVICE_AUTHORITY with the default
            // (4 hour) expiration; re-add it with the VS expiration so the VS does not
            // expire itself.
            actor.add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(config::VS_AUTH_EXPIRATION)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )?;
        }

        Ok(actor)
    }

    pub async fn authenticate_visa_service(
        &self,
        asm: Arc<Assembly>,
        claims: Vec<Claim>,
    ) -> Result<Actor, ServiceError> {
        let mut authd_claims = Vec::new();

        // The VS authenticates itself by construction; that is the device authority.
        authd_claims.push(
            Attribute::builder(key::DEVICE_AUTHORITY)
                .expires_in(config::VS_AUTH_EXPIRATION)
                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
        );
        // The VS authorizes itself: its own CN is authenticated by construction, so it
        // is promoted here (authorize_connection no longer promotes the CN).
        authd_claims.push(Attribute::builder(key::CN).value(config::VS_CN));

        for claim in claims {
            authd_claims.push(Attribute::builder(claim.key).value(claim.value));
        }

        let policy = asm.policy_mgr.get_current();

        // Ok checks out -- now run through policy.
        let vs_actor = self
            .authorize_connection(
                asm,
                &policy,
                &config::VS_CN,
                Vec::new(),
                authd_claims,
                0,
                false,
            )
            .await?;

        // authorize_connection no longer stamps a blanket authority, so the
        // VS-expiration DEVICE_AUTHORITY pushed above survives as-is.

        Ok(vs_actor)
    }

    /// Verify one self-signed (RSA bootstrap) auth blob: the claimed CN must match
    /// the blob's CN, and the blob signature must verify against the policy's
    /// bootstrap key for that CN. On success returns the claims this blob
    /// authenticated -- the CN, promoted at the point where the authentication
    /// actually happened (authorize_connection never promotes it).
    fn authenticate_ss_blob(
        &self,
        asm: &Arc<Assembly>,
        ssb: &SelfSignedBlob,
        unauthd_claims: &[Attribute],
    ) -> Result<Vec<Attribute>, ServiceError> {
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

        // The RSA blob signature verified against the bootstrap key policy binds to
        // this CN, so the CN is authenticated.
        Ok(vec![Attribute::builder(key::CN).value(&ssb.cn)])
    }

    /// Verify one OIDC auth blob (zipline#11, C5): resolve the declared provider by
    /// the blob's issuer (a selector, not a trust input -- client_id and
    /// allowed_domains always come from policy), validate the `id_token` offline
    /// against the provider's cached JWKS, admit the mapped claims into the
    /// provider's store, and yield the user-namespace outcome.
    ///
    /// The outcome carries the namespaced user authority plus the mapped subject:
    /// the authority names the vouching service and the subject anchors the
    /// trusted-service lookup in [Self::authorize_connection] that serves the
    /// remaining mapped claims (C4). Token claims are never pushed directly.
    ///
    /// Failures are classified per the Contract 2 error table and returned as
    /// [ServiceError::ApiResponse] so the real code and retry hint reach the wire.
    /// Wire messages stay generic -- no claim values, no issuer echo, no
    /// validation internals -- so error responses cannot become a claim-probing
    /// oracle; the classified detail (claim names only, never values) goes to the
    /// log.
    async fn authenticate_oidc_blob(
        &self,
        asm: &Arc<Assembly>,
        blob: &OidcBlob,
    ) -> Result<BlobOutcome, ServiceError> {
        let Some(svc) = asm.ts_mgr.oidc_service_for_issuer(&blob.issuer) else {
            // The blob's issuer is attacker-supplied bytes: neither logged nor echoed.
            warn!(target: CC, "OIDC blob names an issuer with no declared trusted service");
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::ParamError,
                "no identity provider declared for issuer",
            )
            .into());
        };

        let now = SystemTime::now();
        let mut result = validate_id_token(
            &blob.id_token,
            &svc.keys().current(),
            &svc.params(),
            &blob.nonce,
            now,
        );
        if matches!(result, Err(OidcError::UnknownKid(_))) {
            // Providers rotate signing keys: refresh the JWKS once and retry once
            // (C3). A failed refresh keeps the stale keys serving; the retry then
            // fails the same way and is classified below.
            if let Err(e) = svc.keys().refresh().await {
                warn!(target: CC, "JWKS refresh after unknown kid failed for provider '{}': {e}", svc.id());
            }
            result = validate_id_token(
                &blob.id_token,
                &svc.keys().current(),
                &svc.params(),
                &blob.nonce,
                now,
            );
        }
        let token = match result {
            Ok(token) => token,
            Err(err) => {
                // The OidcError detail carries claim names, never values (C2), so
                // it is safe to log -- but not to send.
                info!(target: CC, "OIDC token rejected for provider '{}': {err}", svc.id());
                let api = match err {
                    OidcError::NoKeys => ApiResponseError::new(
                        ErrorCode::TemporarilyUnavailable,
                        "identity provider keys unavailable",
                        config::OIDC_NO_KEYS_RETRY_SECS,
                    ),
                    // UnknownKid after the one refresh+retry is a signature-class
                    // failure (Contract 2).
                    OidcError::Signature(_) | OidcError::UnknownKid(_) => {
                        ApiResponseError::new_code_msg(
                            ErrorCode::InvalidSignature,
                            "token validation failed",
                        )
                    }
                    OidcError::Rejected(_) => ApiResponseError::new_code_msg(
                        ErrorCode::AuthError,
                        "authentication rejected",
                    ),
                };
                return Err(api.into());
            }
        };

        // The credential lifetime anchors on the authentication moment
        // (`auth_time`, or `iat` when absent); the token's `exp` was reject-only
        // during validation and plays no part here (Contract 7).
        let expires = token.auth_time + svc.lifetime();
        let mapped = svc.admit(&token, expires)?;

        let src = AttributeSource::new(svc.id());
        let mut authd = vec![
            src.builder(key::USER_AUTHORITY)
                .expires(expires)
                .value(svc.id()),
        ];
        if let Some(sub_key) = svc.mapped_sub_key()
            && let Some(sub_attr) = mapped.into_iter().find(|a| a.get_key() == sub_key)
        {
            authd.push(sub_attr);
        }
        Ok(BlobOutcome {
            authd,
            namespace: Namespace::User,
        })
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

        let mut authd_claims = authd_claims;
        authd_claims.extend(self.authenticate_ss_blob(&asm, ssb, &unauthd_claims)?);

        // Ok checks out -- now run through policy.
        let policy = asm.policy_mgr.get_current();
        let mut actor = self
            .authorize_connection(
                asm,
                &policy,
                &ssb.cn,
                unauthd_claims,
                authd_claims,
                dock_interface,
                false,
            )
            .await?;

        // The visa service's own token gets the VS expiration. A 4 hour token would expire its
        // own authentication and it would start denying its own visas.
        let auth_expiration = if ssb.cn == config::VS_CN {
            config::VS_AUTH_EXPIRATION
        } else {
            config::DEFAULT_AUTH_EXPIRATION
        };
        let actor_jwt = if actor.is_node() {
            self.gen_jwt(format!("node/{}", ssb.cn), auth_expiration)?
        } else {
            self.gen_jwt(format!("adapter/{}", ssb.cn), auth_expiration)?
        };
        let _ = actor.add_attribute(
            Attribute::builder(ATTR_KEY_VS_IDENT)
                .expires(SystemTime::now() + auth_expiration)
                .value(actor_jwt),
        );
        let _ = actor.add_identity_key(0, ATTR_KEY_VS_IDENT);

        Ok(actor)
    }

    /// Use policy to authorize the connection request. Works for adapters and nodes.
    /// If successful you get an authorized Actor back.
    ///
    /// Is able to use the api=file Trusted service to fetch additional attributes.
    /// Eventually will query trusted services for additional actor attributes.
    ///
    /// Does not alter our actor databases.
    /// May take an IP address.
    ///
    /// Caller should set ROLE in unauthd_claims before calling.
    ///
    /// This does NOT add any authority attribute itself: the authentication path
    /// (blob arm) that verified the entity owns stamping the namespaced authority
    /// (e.g. [key::DEVICE_AUTHORITY] on the RSA bootstrap path). Whichever
    /// namespaced authorities are present are registered as identity attributes.
    ///
    /// `user_login_presented` says the connect carried a (validated) OIDC blob:
    /// such a connection is refused with `policyDenied` when no join policy
    /// matches, unlike the device-only case which may stay connected without one
    /// (#227) -- see [EvalContext::approve_connection_detailed].
    async fn authorize_connection(
        &self,
        asm: Arc<Assembly>,
        current_policy: &Arc<Policy>,
        endpoint_cn: &str,
        unauthd_claims: Vec<Attribute>,
        mut authd_claims: Vec<Attribute>,
        _dock_interface: u8,
        user_login_presented: bool,
    ) -> Result<Actor, ServiceError> {
        // TODO: Check with our revocation tables.
        info!(target: CC, "authorize_connection - TODO: check revocation table");
        // Actor may be denied by CN -- we can detect that before calling into policy.
        // In the future actor may be denied if the credential associated with the auth service is revoked.

        // NOTE: the CN is deliberately NOT promoted to an authenticated claim here.
        // Classification is the caller's job: a path that verified the CN (e.g. an RSA
        // blob signature) pushes it into `authd_claims` itself, and a path that only
        // received a claimed CN leaves it unauthenticated. `endpoint_cn` is log-only.
        authd_claims.push(
            Attribute::builder(key::CONFIG_ID)
                .value(format!("{}", current_policy.get_version().unwrap_or(0))),
        );

        // The trusted-service lookup is keyed on the actor's lookup-identity set: the
        // policy's lookup-identity keys intersected with the *authenticated* claims, as
        // (key, value) pairs so a source can tell a device CN from a user subject. Both
        // are in hand before approve_connection runs and before any ZPR address exists,
        // which matters because the attributes fetched here feed the join decision
        // itself. Nothing is recorded with the revision cache on this fetch (it is
        // keyed on the ZPR address, which does not exist yet); the first post-connect
        // refresh treats every source as stale and re-fetches once.
        let lookup_keys = current_policy.lookup_identity_keys();
        let identities = lookup_identities(&lookup_keys, authd_claims.iter());

        // A lookup failure is indeterminate, not "the actor has no such attribute", and
        // the two are indistinguishable once evaluation starts: a join policy can be
        // satisfied by a missing key. Refuse the connection rather than authorize
        // against a partial claim set. Note this means a trusted-service outage blocks
        // new connections.
        for (source_id, ts_results) in asm.ts_mgr.get_attributes_for_actor(&identities).await {
            match ts_results {
                Ok(ts_attrs) => {
                    // A source that vends `user.*` attributes is the authority asserting
                    // that user identity, so it installs `user.zpr.authority = <source id>`
                    // alongside them (#324 follow-up); see [derive_user_authority]. The
                    // identity-key registration below then picks it up unchanged.
                    if let Some(authority) = derive_user_authority(&source_id, &ts_attrs) {
                        authd_claims.push(authority);
                    }
                    for attr in ts_attrs {
                        authd_claims.push(attr);
                    }
                }
                Err(e) => {
                    error!(target: CC, "ts service attr lookup failed for actor {}: {}", endpoint_cn, e);
                    return Err(ServiceError::AttributesIndeterminate(format!(
                        "trusted service lookup failed for {endpoint_cn}: {e}"
                    )));
                }
            }
        }

        let ectx = EvalContext::new(current_policy.clone());

        // TODO: Need to go in to eval and fix the approve_connection logic w/respect to the ROLE claim.
        // We won't know a priori if this is a node or adapter. Though sometimes we do know it's a node.
        // Anyway, best to let VS sort it out and do not do it in libeval.
        let (mut authd_actor, matched_join_policy) =
            match ectx.approve_connection_detailed(Some(&authd_claims), Some(&unauthd_claims)) {
                Ok(approved) => approved,
                Err(e) => {
                    info!(target: CC, "connection not approved for cn {}: {}", endpoint_cn, e);
                    return Err(e.into());
                }
            };

        // A valid user login that policy does not admit is refused outright with
        // `policyDenied` (Contract 2): authentication succeeded, so this is not a
        // credential oracle, and unlike the device-only #227 case there is nothing
        // a join-policy-less user session may do. The message stays generic --
        // which policies exist is not the caller's to learn.
        if user_login_presented && !matched_join_policy {
            info!(target: CC, "user login for {endpoint_cn} matched no join policy");
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::PolicyDenied,
                "no join policy admits this connection",
            )
            .into());
        }

        // The blob arms own the authority: register whichever namespaced authority
        // attributes the authentication path stamped as identity attributes, rather
        // than adding a blanket one here (Contract 7).
        for authority_key in [key::DEVICE_AUTHORITY, key::USER_AUTHORITY] {
            if authd_actor.get_attribute(authority_key).is_some() {
                authd_actor.add_identity_key(usize::MAX, authority_key)?;
            }
        }

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
                    authd_actor
                        .add_attribute(Attribute::builder(key::ZPR_ADDR).value(addr.to_string()))?;
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
            Ok(()) => {
                // Purge recorded trusted-service revisions before the address returns to
                // the pool: addresses are recycled, and a later actor at this address
                // must not inherit them.
                asm.ts_mgr.forget_actor_revisions(&zpr_addr);
            }
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
                            // Same as the main actor above: purge before the cascaded
                            // adapter's address can be recycled.
                            asm.ts_mgr.forget_actor_revisions(&adapter_addr);
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

/// A node's own substrate address, taken from the resolved topology: for a peer `P` sharing
/// a link with `node_addr`, `P`'s resolved link points back at `node_addr`'s substrate. That
/// value is authoritative (it is what policy declares and what every peer dials) and is
/// already DNS-resolved, so it parses as a `SocketAddr`.
///
/// Returns `None` when policy declares no peering for the node, or none of its links appear
/// in the resolved topology -- both mean policy cannot tell us.
///
/// Does not support multi-homed nodes!
pub fn substrate_addr_from_topology(asm: &Assembly, node_addr: &IpAddr) -> Option<SocketAddr> {
    let psnap = asm.policy_mgr.get_current_snapshot();
    for peer in psnap.policy().get_peers_for_node(node_addr)? {
        if let Some((_, sock_addr)) = psnap
            .resolved_peers_for_node(&peer.remote_zpr_addr)
            .into_iter()
            .find(|(link_id, _)| *link_id == peer.link_id)
        {
            return Some(sock_addr);
        }
    }
    None
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
//   - device.zpr.adapter.cn -> which is the CN of the adapter as told to the node.
//
// Note classes are device, user, service (as per ZPL and the compiler).
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
            // Only permissible is device.zpr.adapter.cn
            if claim.key == key::CN {
                // Allow device.zpr.adapter.cn
                scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
                continue;
            }

            // We only check for the defined classes.
            if parts[0] == CLASS_DEVICE || parts[0] == CLASS_USER || parts[0] == CLASS_SERVICE {
                warn!(target: CC, "adapter claim key '{}' not allowed", claim.key);
                continue;
            }
        }

        // Note that we don't handle multi-value claims at this point.
        scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
    }
    Ok(scrubbed_claims)
}

/// The A2A DH public key as an attribute claim, or None if it is not a usable X25519 key.
fn a2a_dh_pubkey_claim(key: &PublicKey) -> Option<Attribute> {
    (key.public_key.len() == 32).then(|| {
        Attribute::builder(key::A2A_DH_PUBKEY).value(libeval::pubkey::encode_public_key(key))
    })
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

    /// A node's substrate address comes from its peer's view of their shared link, and is
    /// `None` when policy declares no peering for it.
    #[tokio::test]
    async fn test_substrate_addr_from_topology() {
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::db::PolicyRepo;
        use crate::policy_mgr::PolicyMgr;
        use crate::test_helpers::{FakeResolver, make_peering, policy_with_peerings};
        use crate::trusted_services::TrustedServicesMgr;
        use std::path::PathBuf;

        let a: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        let unpeered: IpAddr = "fd5a:5052:90de:1::9".parse().unwrap();

        let mut asm = new_assembly_for_tests(None).await;
        asm.policy_mgr = PolicyMgr::new_with_initial_policy(
            policy_with_peerings(&[make_peering(a, b, "link-ab", vec![])]),
            PolicyRepo::new(asm.state_db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
        )
        .await
        .unwrap();

        // make_peering uses each node's own address as its substrate, port 0.
        assert_eq!(
            substrate_addr_from_topology(&asm, &b),
            Some(SocketAddr::new(b, 0)),
            "node B's substrate is the address peer A dials it at"
        );
        assert_eq!(
            substrate_addr_from_topology(&asm, &unpeered),
            None,
            "a node with no peering has no policy-derived substrate"
        );
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
        let token = cc
            .gen_jwt("node/my-node".to_string(), config::DEFAULT_AUTH_EXPIRATION)
            .unwrap();
        let claims = decode_jwt(&token, "test-vs").expect("token must decode");

        assert_eq!(claims.sub, "node/my-node");
        assert_eq!(claims.iss, "vs.zpr/test-vs");
    }

    #[test]
    fn gen_jwt_jti_is_unique_per_call() {
        let cc = make_cc("test-vs");
        let exp = config::DEFAULT_AUTH_EXPIRATION;
        let t1 = decode_jwt(&cc.gen_jwt("node/cn".to_string(), exp).unwrap(), "test-vs").unwrap();
        let t2 = decode_jwt(&cc.gen_jwt("node/cn".to_string(), exp).unwrap(), "test-vs").unwrap();
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
            claim("device.label", "edge"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::ZPR_ADDR, "device.label"]);
    }

    #[test]
    fn scrub_adapter_claims_blocks_class_zpr_for_known_classes() {
        let claims = vec![
            claim("device.zpr.adapter.token", "nope"),
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

    /// A trusted service whose lookups always fail, standing in for an unreadable
    /// attribute file or an unreachable service.
    struct FailingTrustedService;

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for FailingTrustedService {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            Err(ServiceError::Internal("service is down".to_string()))
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            "failing"
        }
    }

    /// A trusted-service lookup failure must reject the connection rather than
    /// authorize against a partial claim set -- a join policy can be satisfied by a
    /// missing key, so falling through would let an outage approve an actor.
    #[tokio::test]
    async fn authorize_connection_rejects_on_trusted_service_failure() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");

        // Baseline: with no trusted services configured this same call succeeds, so the
        // rejection below is caused by the failure and not by the surrounding setup.
        cc.authenticate_visa_service(asm.clone(), Vec::new())
            .await
            .expect("should authorize with no trusted services");

        asm.ts_mgr
            .update_services(vec![Arc::new(FailingTrustedService)]);
        let result = cc.authenticate_visa_service(asm, Vec::new()).await;
        assert!(matches!(
            result,
            Err(ServiceError::AttributesIndeterminate(_))
        ));
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
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
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
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
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
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
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
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await;
        assert!(
            matches!(result, Err(ServiceError::AuthenticationFailed(_))),
            "expected failure got {:?}",
            result
        );
    }

    /// As [make_policy_with_node_join_policy], plus a topology peering so the policy
    /// declares a substrate address for the peered nodes.
    fn make_policy_with_node_join_and_peering(
        cn: &str,
        pubkey_der: &[u8],
        peering: &zpr::policy_types::Peering,
    ) -> Vec<u8> {
        use zpr::write_to::WriteTo;
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
                let mut jps = policy_bldr.reborrow().init_join_policies(1);
                jps.reborrow()
                    .get(0)
                    .init_flags(1)
                    .set(0, v1::JoinFlag::Node);
            }
            {
                let mut topo = policy_bldr.reborrow().init_topology(1);
                peering.write_to(&mut topo.reborrow().get(0));
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

    /// The RSA-verified (bootstrap) path installs the namespaced device authority
    /// `device.zpr.authority = "zpr-bootstrap"` as an identity attribute, and no
    /// legacy `zpr.authority` or `user.zpr.authority` attribute exists (Contract 7).
    #[tokio::test]
    async fn test_rsa_path_installs_device_authority_bootstrap() {
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
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await
            .expect("authentication should succeed");

        assert_eq!(
            actor
                .get_attribute(key::DEVICE_AUTHORITY)
                .expect("device authority must be present")
                .get_value(),
            &vec![key::AUTHORITY_METHOD_BOOTSTRAP.to_string()],
            "RSA path must stamp device.zpr.authority = zpr-bootstrap"
        );
        assert!(
            actor.get_attribute("zpr.authority").is_none(),
            "legacy un-namespaced zpr.authority must not exist"
        );
        assert!(
            actor.get_attribute(key::USER_AUTHORITY).is_none(),
            "device-only bootstrap must not assert a user authority"
        );
        assert!(
            actor
                .identity_keys_iter()
                .any(|k| k == key::DEVICE_AUTHORITY),
            "device.zpr.authority must be registered as an identity key"
        );
    }

    /// With no topology entry for the node, the reported substrate address is stored
    /// as the node's `key::SUBSTRATE_ADDR` claim (no TCP-peer fallback exists anymore).
    #[tokio::test]
    async fn authenticate_node_no_topology_stores_reported_substrate() {
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
        let reported: SocketAddr = "192.0.2.10:7000".parse().unwrap();

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "fd5a:5052::1".parse().unwrap(),
                reported,
                None,
            )
            .await
            .expect("authentication should succeed");

        let stored = actor
            .get_attribute(key::SUBSTRATE_ADDR)
            .expect("substrate addr claim must be present")
            .get_value()[0]
            .clone();
        assert_eq!(stored, reported.to_string());
    }

    /// When policy topology declares a substrate for the node and the node reports a
    /// different one, authentication fails with a param error.
    #[tokio::test]
    async fn authenticate_node_topology_mismatch_is_param_error() {
        use crate::test_helpers::make_peering;

        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let a: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        // make_peering declares each node's own address (port 0) as its substrate.
        let peering = make_peering(a, b, "link-ab", vec![]);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                cn,
                &pubkey_der,
                &peering,
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = 12345678u64;
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let reported: SocketAddr = "192.0.2.10:7000".parse().unwrap(); // != policy's [b]:0

        let result = cc
            .authenticate_node(asm, challenge, timestamp, cn, &sig, b, reported, None)
            .await;
        assert!(
            matches!(result, Err(ServiceError::Param(_))),
            "expected param error, got {:?}",
            result
        );
    }

    /// When policy topology declares a substrate and the node reports the same value,
    /// authentication succeeds and that value is stored.
    #[tokio::test]
    async fn authenticate_node_topology_match_succeeds() {
        use crate::test_helpers::make_peering;

        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let a: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        let peering = make_peering(a, b, "link-ab", vec![]);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                cn,
                &pubkey_der,
                &peering,
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = 12345678u64;
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let reported = SocketAddr::new(b, 0); // matches make_peering's declaration

        let actor = cc
            .authenticate_node(asm, challenge, timestamp, cn, &sig, b, reported, None)
            .await
            .expect("authentication should succeed");

        let stored = actor
            .get_attribute(key::SUBSTRATE_ADDR)
            .expect("substrate addr claim must be present")
            .get_value()[0]
            .clone();
        assert_eq!(stored, reported.to_string());
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
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
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

        // get_identity() returns [jwt, cn, device authority] in that order
        let identity = actor
            .get_identity()
            .expect("actor must have identity values");
        assert_eq!(identity[0], jwt_str);

        // The CN is an identity key in its own right (established by the builtin RSA
        // authentication; see libeval's approve_connection, #201), so it follows the JWT.
        assert_eq!(identity[1], cn);
    }

    /// A 32-byte X25519 key becomes a claim, any other length does not.
    #[test]
    fn test_a2a_dh_pubkey_claim_length_gate() {
        assert!(a2a_dh_pubkey_claim(&PublicKey::new(&[7u8; 32])).is_some());
        assert!(a2a_dh_pubkey_claim(&PublicKey::new(&[7u8; 31])).is_none());
    }

    // ---- lookup-identity derivation at connect time (#310) ----

    /// A trusted service that records the lookup-identity set of every call and vends
    /// a fixed attribute set for one specific identity value -- standing in for an
    /// attribute store holding a privileged device's attributes.
    struct CapturingTrustedService {
        /// Identity value that owns `vends`.
        known_value: String,
        /// (ZPR attribute key, value) pairs vended when `known_value` matches.
        vends: Vec<(String, String)>,
        calls: std::sync::Mutex<Vec<Vec<(String, String)>>>,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for CapturingTrustedService {
        async fn get_attributes_for_actor(
            &self,
            identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            self.calls.lock().unwrap().push(identities.to_vec());
            if identities.iter().any(|(_, v)| *v == self.known_value) {
                return Ok(self
                    .vends
                    .iter()
                    .map(|(k, v)| {
                        libeval::attribute::AttributeSource::new("capture")
                            .builder(k)
                            .expires_in(Duration::from_secs(600))
                            .value(v)
                    })
                    .collect());
            }
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            "capture"
        }
    }

    /// Register a capturing service on the assembly and return a handle for assertions.
    fn register_capturing_ts(
        asm: &Arc<Assembly>,
        known_value: &str,
        vends: &[(&str, &str)],
    ) -> Arc<CapturingTrustedService> {
        let svc = Arc::new(CapturingTrustedService {
            known_value: known_value.to_string(),
            vends: vends
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        asm.ts_mgr.update_services(vec![svc.clone()]);
        svc
    }

    /// Decode a test policy container into its policy representation.
    fn policy_from_container(container_bytes: Vec<u8>) -> Arc<Policy> {
        crate::loaded_policy::LoadedPolicy::from_container(
            zpr::policy_types::PolicyContainerBytes::from(container_bytes),
            &config::POLICY_MIN_VERSION,
        )
        .unwrap()
        .policy()
    }

    /// Regression test for the CN-claiming escalation (#310): a user-only actor whose
    /// claimed CN is UNAUTHENTICATED must not have that CN sent to trusted services as
    /// a lookup identity, and must not inherit the claimed device's attributes. The
    /// lookup set handed to the source is the security boundary, so it is what gets
    /// pinned.
    #[tokio::test]
    async fn user_only_actor_cannot_inherit_claimed_cn_attributes() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");

        // Policy declares `sub -> user.sub` as an identity attribute.
        let policy = policy_from_container(
            crate::test_helpers::make_trusted_service_policy_with_identity(
                "capture",
                "file",
                Some(3600),
                &["sub -> user.sub"],
                &["sub"],
            ),
        );
        // The store knows the privileged device's CN and vends its attributes.
        let svc = register_capturing_ts(&asm, "privileged.zpr.org", &[("user.privileged", "yes")]);

        // Authenticated: only the user identity. The claimed CN is unauthenticated.
        let authd = vec![
            Attribute::builder("user.sub")
                .expires_in(Duration::from_secs(600))
                .value("google-sub-12345"),
        ];
        let unauthd = vec![Attribute::builder(key::CN).value("privileged.zpr.org")];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &policy,
                "privileged.zpr.org",
                unauthd,
                authd,
                0,
                false,
            )
            .await
            .expect("user-only connection should authorize");

        // The lookup set contains exactly the authenticated user identity -- the
        // claimed CN never reaches the source.
        assert_eq!(
            *svc.calls.lock().unwrap(),
            vec![vec![(
                "user.sub".to_string(),
                "google-sub-12345".to_string()
            )]]
        );
        // And the actor carries none of the privileged device's attributes, nor an
        // authenticated CN.
        assert!(actor.get_attribute("user.privileged").is_none());
        assert!(actor.get_attribute(key::CN).is_none());
    }

    /// Existing device-only actors keep working: under the builtin CN identity the
    /// connect-time lookup set is exactly [(device.zpr.adapter.cn, <cn>)] -- CN
    /// survives the switch away from `identity_attr_keys()` (which excludes it).
    #[tokio::test]
    async fn device_only_actor_lookup_set_is_authenticated_cn() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");

        // No policy-declared identity attributes: the builtin CN is the only lookup key.
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "capture",
            "file",
            Some(3600),
            &["color -> user.color"],
        ));
        let svc = register_capturing_ts(&asm, "device-1.zpr.org", &[("user.color", "red")]);

        // As authenticate_zpr_entity_rsa would after signature verification.
        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &policy,
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
                false,
            )
            .await
            .expect("device connection should authorize");

        assert_eq!(
            *svc.calls.lock().unwrap(),
            vec![vec![(key::CN.to_string(), "device-1.zpr.org".to_string())]]
        );
        // The vended attribute reached the actor through the authenticated-claims path.
        assert!(actor.get_attribute("user.color").is_some());
    }

    /// A trusted service with a configurable source id that vends a fixed attribute
    /// set for every lookup. Minimal stand-in for the user-authority derivation tests,
    /// where the source id IS the asserted authority value.
    struct NamedTrustedService {
        source_id: String,
        /// (ZPR attribute key, value) pairs vended on every lookup.
        vends: Vec<(String, String)>,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for NamedTrustedService {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            Ok(self
                .vends
                .iter()
                .map(|(k, v)| {
                    libeval::attribute::AttributeSource::new(self.source_id.clone())
                        .builder(k)
                        .expires_in(Duration::from_secs(600))
                        .value(v)
                })
                .collect())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            &self.source_id
        }
    }

    /// Build a [NamedTrustedService] for registration with the test assembly.
    fn named_ts(source_id: &str, vends: &[(&str, &str)]) -> Arc<NamedTrustedService> {
        Arc::new(NamedTrustedService {
            source_id: source_id.to_string(),
            vends: vends
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
    }

    /// #324 follow-up (1): a trusted service vending `user.*` attributes installs
    /// `user.zpr.authority = <source id>` on the actor, and it is registered as an
    /// identity key -- the trusted service is the authority asserting the user
    /// identity, exactly as the RSA bootstrap path asserts the device identity.
    #[tokio::test]
    async fn ts_user_attrs_install_user_authority() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "bas",
            "file",
            Some(3600),
            &["dept -> user.dept"],
        ));
        asm.ts_mgr
            .update_services(vec![named_ts("bas", &[("user.dept", "engineering")])]);

        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];
        let actor = cc
            .authorize_connection(
                asm,
                &policy,
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
                false,
            )
            .await
            .expect("connection should authorize");

        let authority = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("user.zpr.authority should be installed");
        assert_eq!(authority.get_value(), ["bas".to_string()]);
        // Expires with the vended user attributes, so the authority never outlives
        // the user record it vouches for.
        assert_eq!(
            authority.get_expires(),
            actor.get_attribute("user.dept").unwrap().get_expires()
        );
        // And it is registered as an identity key, like any namespaced authority.
        assert!(
            actor.identity_keys_iter().any(|k| k == key::USER_AUTHORITY),
            "user.zpr.authority should be an identity key"
        );
    }

    /// #324 follow-up (2): a trusted service vending only device attributes (or
    /// nothing) installs no `user.zpr.authority` -- a device with no user record in
    /// any trusted service still does not match a bare `allow users ...` rule, so the
    /// fail-closed property of #144 survives.
    #[tokio::test]
    async fn ts_device_only_attrs_install_no_user_authority() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "bas",
            "file",
            Some(3600),
            &["location -> device.zpr.location"],
        ));
        asm.ts_mgr
            .update_services(vec![named_ts("bas", &[("device.zpr.location", "hq")])]);

        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];
        let actor = cc
            .authorize_connection(
                asm,
                &policy,
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
                false,
            )
            .await
            .expect("connection should authorize");

        assert!(actor.get_attribute("device.zpr.location").is_some());
        assert!(
            actor.get_attribute(key::USER_AUTHORITY).is_none(),
            "device-only trusted-service results must not install user.zpr.authority"
        );
    }

    /// #324 follow-up (3): with two sources of which only one vends user attributes,
    /// exactly that source's id becomes the (single) authority value.
    #[tokio::test]
    async fn ts_two_sources_one_user_authority_value() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "bas",
            "file",
            Some(3600),
            &["dept -> user.dept"],
        ));
        asm.ts_mgr.update_services(vec![
            named_ts("bas", &[("user.dept", "engineering")]),
            named_ts("inventory", &[("device.zpr.location", "hq")]),
        ]);

        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];
        let actor = cc
            .authorize_connection(
                asm,
                &policy,
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
                false,
            )
            .await
            .expect("connection should authorize");

        let authority = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("user.zpr.authority should be installed");
        assert_eq!(
            authority.get_value(),
            ["bas".to_string()],
            "exactly the user-vending source names the authority"
        );
    }

    /// Disconnect purges recorded trusted-service revisions for the actor AND for every
    /// cascaded adapter, before the addresses return to the pool -- so a recycled ZPR
    /// address cannot inherit the previous actor's revision records. This same
    /// `disconnect` is the path for API, policy-driven, and node-cascade disconnects,
    /// none of which may rely on an ActorLeaves event.
    #[tokio::test]
    async fn disconnect_purges_revisions_for_actor_and_cascaded_adapters() {
        use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp, register_ts};

        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        register_ts(&asm, &[("user.dept", "eng")]);

        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::11".parse().unwrap();
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        let adapter = make_adapter_actor_defexp("fd5a:5052::11", "adapter-1");
        asm.actor_mgr.add_node(&node, false).await.unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter, &node_addr)
            .await
            .unwrap();

        // Both actors are caught up with the source.
        for addr in [&node_addr, &adapter_addr] {
            let stale = asm.ts_mgr.stale_sources_for_actor(addr);
            assert_eq!(stale.len(), 1);
            asm.ts_mgr.record_revision(addr, &stale[0].0, stale[0].1);
            assert!(asm.ts_mgr.stale_sources_for_actor(addr).is_empty());
        }

        // Node disconnect cascades to the attached adapter.
        cc.disconnect(asm.clone(), node_addr, vsapi::DisconnectReason::Admin)
            .await
            .unwrap();

        // Every source is stale again for both addresses: the records are gone, so a
        // recycled address starts from scratch.
        assert_eq!(asm.ts_mgr.stale_sources_for_actor(&node_addr).len(), 1);
        assert_eq!(asm.ts_mgr.stale_sources_for_actor(&adapter_addr).len(), 1);
    }

    // ---- multi-blob authentication (zipline#7, C1) ----

    fn make_connect_request(blobs: Vec<AuthBlob>, cn: &str) -> ConnectRequest {
        ConnectRequest {
            blobs,
            claims: vec![claim(key::CN, cn)],
            substrate_addr: "127.0.0.1".parse().unwrap(),
            dock_interface: 0,
            a2a_dh_public_key: PublicKey::new(&[7u8; 32]),
        }
    }

    /// An SS blob whose signature verifies against the keypair's policy bootstrap key.
    fn make_valid_ss_blob(privkey: &PKey<Private>, cn: &str) -> AuthBlob {
        let challenge = b"multi-blob-challenge";
        let timestamp = 12345678u64;
        let signature = sign_node_challenge(privkey, timestamp, cn, challenge);
        AuthBlob::SS(SelfSignedBlob {
            alg: ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: challenge.to_vec(),
            cn: cn.to_string(),
            timestamp,
            signature,
        })
    }

    /// A syntactically-present OIDC blob naming an issuer no trusted service
    /// declares. Under C5 this is a real validation failure (paramError), which
    /// keeps this fixture useful for the fail-closed property below.
    fn oidc_stub_blob() -> AuthBlob {
        AuthBlob::Oidc(zpr::vsapi_types::OidcBlob {
            issuer: "https://issuer.example".to_string(),
            id_token: "stub-token".to_string(),
            nonce: "stub-nonce".to_string(),
        })
    }

    /// Zero auth blobs is a malformed request: authentication requires at least one.
    #[tokio::test]
    async fn test_zero_blobs_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let req = make_connect_request(Vec::new(), "test-node.zpr");
        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;
        match result {
            Err(ServiceError::Param(msg)) => {
                assert_eq!(msg, "at least one auth blob is required")
            }
            other => panic!("expected Param error, got {:?}", other),
        }
    }

    /// Presented-and-invalid fails closed: a connection carrying a VALID SS blob plus
    /// an OIDC blob naming an undeclared issuer fails as a whole -- the valid device
    /// authentication does not rescue it -- and no actor is persisted.
    #[tokio::test]
    async fn test_two_blobs_ss_and_oidc_stub_fails_whole_connection() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req =
            make_connect_request(vec![make_valid_ss_blob(&privkey, cn), oidc_stub_blob()], cn);

        let result = cc
            .authenticate_adapter_or_node(asm.clone(), req, &"fd5a:5052::1".parse().unwrap())
            .await;

        match result {
            Err(ServiceError::ApiResponse(api)) => {
                assert!(
                    matches!(api.code, zpr::vsapi_types::ErrorCode::ParamError),
                    "expected paramError for undeclared issuer, got {:?}",
                    api.code
                )
            }
            other => panic!("expected ApiResponse error, got {:?}", other),
        }
        // The failed connection must not leave an actor behind.
        assert!(
            asm.actor_mgr.get_actor_by_cn(cn).await.unwrap().is_none(),
            "no actor may be persisted for a failed multi-blob connection"
        );
    }

    /// Two blobs authenticating the same namespace are a protocol error, even when
    /// both are individually valid.
    #[tokio::test]
    async fn test_duplicate_device_blob_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                make_valid_ss_blob(&privkey, cn),
            ],
            cn,
        );

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        match result {
            Err(ServiceError::Param(msg)) => {
                assert_eq!(msg, "duplicate device authentication")
            }
            other => panic!("expected Param error, got {:?}", other),
        }
    }

    /// A connection with no device blob must not end up with an authenticated CN: the
    /// claimed CN stays unauthenticated through authorize_connection. Pins the
    /// no-CN-promotion behaviour the multi-blob loop relies on (zipline#7).
    #[tokio::test]
    async fn test_cn_not_authenticated_without_device_blob() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(
            crate::test_helpers::make_trusted_service_policy_with_identity(
                "idp",
                "file",
                Some(3600),
                &["oidc-subject -> user.oidc-subject"],
                &["oidc-subject"],
            ),
        );

        // Authenticated: user identity only (as the C5 OIDC arm will produce).
        let authd = vec![
            Attribute::builder(key::USER_AUTHORITY)
                .expires_in(Duration::from_secs(600))
                .value("idp"),
            Attribute::builder("user.oidc-subject")
                .expires_in(Duration::from_secs(600))
                .value("alice-sub"),
        ];
        let unauthd = vec![Attribute::builder(key::CN).value("some-device.zpr")];

        let actor = cc
            .authorize_connection(asm, &policy, "some-device.zpr", unauthd, authd, 0, false)
            .await
            .expect("user-only connection should authorize");

        // The claimed CN was never authenticated, so the actor carries no CN
        // attribute and the CN is not an identity key.
        assert!(actor.get_attribute(key::CN).is_none());
        assert!(!actor.identity_keys_iter().any(|k| k == key::CN));
    }

    /// Spec regression (OIDC.md failure rule): a user-only actor claiming a foreign
    /// device CN must not have that CN sent to trusted services as a lookup identity,
    /// and must not inherit the claimed device's attributes.
    #[tokio::test]
    async fn test_user_only_actor_claiming_foreign_cn_gets_no_cn_attributes() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(
            crate::test_helpers::make_trusted_service_policy_with_identity(
                "capture",
                "file",
                Some(3600),
                &["oidc-subject -> user.oidc-subject"],
                &["oidc-subject"],
            ),
        );
        // The store holds the privileged device's attributes, keyed by its CN value.
        let svc = register_capturing_ts(&asm, "server1.zpr", &[("device.role", "admin")]);

        // Authenticated: only the user subject. The foreign CN is a bare claim.
        let authd = vec![
            Attribute::builder("user.oidc-subject")
                .expires_in(Duration::from_secs(600))
                .value("alice-sub"),
        ];
        let unauthd = vec![Attribute::builder(key::CN).value("server1.zpr")];

        let actor = cc
            .authorize_connection(asm, &policy, "server1.zpr", unauthd, authd, 0, false)
            .await
            .expect("user-only connection should authorize");

        // The lookup identities sent to the source were only the user subject pair.
        assert_eq!(
            *svc.calls.lock().unwrap(),
            vec![vec![(
                "user.oidc-subject".to_string(),
                "alice-sub".to_string()
            )]]
        );
        // And none of the claimed device's attributes reached the actor.
        assert!(
            actor.get_attribute("device.role").is_none(),
            "actor must not inherit the claimed device's attributes"
        );
    }

    // ---- OIDC blob on the connect path (zipline#11, C5) ----

    use crate::oidc::mint::{TEST_KID, test_rsa_pem, token as mint_token};
    use crate::test_helpers::{make_oidc_connect_policy, make_test_oidc_config};
    use serde_json::json;
    use zpr::policy_types::OidcConfig;
    use zpr::vsapi_types::{ApiResponseError, ErrorCode, OidcBlob};

    /// Issuer/client of the fixture config ([make_test_oidc_config]).
    const OIDC_ISSUER: &str = "https://accounts.google.com";
    const OIDC_CLIENT_ID: &str = "test-client-id.apps.googleusercontent.com";
    /// The nonce the connect request binds its token to.
    const OIDC_NONCE: &str = "test-nonce-1";
    /// The subject minted into the test tokens.
    const OIDC_SUB: &str = "test-sub-12345";
    /// The claim -> ZPR attribute mappings the C5 test policies declare.
    const OIDC_MAPPINGS: &[&str] = &[
        "sub -> user.oidc-subject",
        "email -> user.email",
        "hd -> user.domain",
    ];
    /// `expiration_seconds` in the C5 test policies (12 h).
    const OIDC_LIFETIME_SECS: u32 = 43200;

    /// Unix seconds for "now" (the JWT library validates `exp` against real time).
    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A fully valid claim set for the fixture provider; tests override fields.
    fn oidc_base_claims() -> serde_json::Value {
        json!({
            "iss": OIDC_ISSUER,
            "aud": OIDC_CLIENT_ID,
            "sub": OIDC_SUB,
            "exp": unix_now() + 3600,
            "iat": unix_now(),
            "nonce": OIDC_NONCE,
            "hd": "example.com",
            "email": "jane@example.com",
            "email_verified": true,
        })
    }

    /// Sign `claims` with the fixture RSA key under the standard kid.
    fn mint_signed(claims: serde_json::Value) -> String {
        let signing_key = jwt::EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        mint_token(claims, TEST_KID, jwt::Algorithm::RS256, &signing_key)
    }

    /// An OIDC auth blob for the fixture issuer carrying `id_token`.
    fn oidc_blob(id_token: String) -> AuthBlob {
        AuthBlob::Oidc(OidcBlob {
            issuer: OIDC_ISSUER.to_string(),
            id_token,
            nonce: OIDC_NONCE.to_string(),
        })
    }

    /// Install the standard C5 OIDC policy (no bootstrap keys, join-any) on `asm`.
    async fn install_oidc_policy(asm: &Arc<Assembly>, oidc: OidcConfig) {
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                oidc,
                &[],
                &[],
            ))
            .await
            .expect("test policy should install");
    }

    /// Unwrap a connect failure into its wire-classified [ApiResponseError].
    fn expect_api_response(result: Result<Actor, ServiceError>) -> ApiResponseError {
        match result {
            Err(ServiceError::ApiResponse(api)) => api,
            other => panic!("expected ApiResponse error, got {:?}", other),
        }
    }

    /// A valid OIDC-only connect stamps `user.zpr.authority = ["google"]`, the mapped
    /// claims arrive through the trusted-service lookup, the identity keys are the
    /// mapped sub then the user authority (after the VS ident JWT), and nothing in the
    /// device namespace is asserted.
    #[tokio::test]
    async fn test_oidc_only_connect_yields_user_authority_and_claims() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("valid OIDC connect should authorize");

        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be stamped")
                .get_value(),
            &vec!["google".to_string()]
        );
        assert_eq!(
            actor
                .get_attribute("user.oidc-subject")
                .expect("mapped sub must be present")
                .get_single_value()
                .unwrap(),
            OIDC_SUB
        );
        assert_eq!(
            actor
                .get_attribute("user.email")
                .expect("mapped email must be present")
                .get_single_value()
                .unwrap(),
            "jane@example.com"
        );
        assert_eq!(
            actor
                .get_attribute("user.domain")
                .expect("mapped hd must be present")
                .get_single_value()
                .unwrap(),
            "example.com"
        );
        // lookup_identity_keys order (mapped sub) then the namespaced authority;
        // the VS ident JWT is prepended at order 0 by the connect path.
        let ikeys: Vec<&str> = actor.identity_keys_iter().map(|k| k.as_str()).collect();
        assert_eq!(
            ikeys,
            vec![ATTR_KEY_VS_IDENT, "user.oidc-subject", key::USER_AUTHORITY]
        );
        // No device identity was authenticated.
        assert!(actor.get_attribute(key::DEVICE_AUTHORITY).is_none());
        assert!(actor.get_attribute(key::CN).is_none());
        assert!(
            actor
                .attrs_iter()
                .all(|a| !a.get_key().starts_with("device.")),
            "no device.* attribute may be asserted by a user-only login"
        );
    }

    /// SS + OIDC in one connect: both namespaced authorities are stamped and both are
    /// registered as identity keys.
    #[tokio::test]
    async fn test_ss_plus_oidc_connect_yields_both_authorities() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                oidc_blob(mint_signed(oidc_base_claims())),
            ],
            cn,
        );

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("SS+OIDC connect should authorize");

        assert_eq!(
            actor
                .get_attribute(key::DEVICE_AUTHORITY)
                .expect("device authority must be stamped")
                .get_value(),
            &vec![key::AUTHORITY_METHOD_BOOTSTRAP.to_string()]
        );
        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be stamped")
                .get_value(),
            &vec!["google".to_string()]
        );
        assert!(
            actor
                .identity_keys_iter()
                .any(|k| k == key::DEVICE_AUTHORITY),
            "device authority must be an identity key"
        );
        assert!(
            actor.identity_keys_iter().any(|k| k == key::USER_AUTHORITY),
            "user authority must be an identity key"
        );
    }

    /// A nonce mismatch fails the whole connection with `invalidSignature`, even when a
    /// valid SS blob is also presented, and no actor is persisted (fail closed).
    #[tokio::test]
    async fn test_oidc_wrong_nonce_fails_whole_connection_invalid_signature() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let mut claims = oidc_base_claims();
        claims["nonce"] = json!("some-other-nonce");
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                oidc_blob(mint_signed(claims)),
            ],
            cn,
        );

        let result = cc
            .authenticate_adapter_or_node(asm.clone(), req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::InvalidSignature),
            "expected invalidSignature, got {:?}",
            api.code
        );
        assert!(
            asm.actor_mgr.get_actor_by_cn(cn).await.unwrap().is_none(),
            "no actor may be persisted for a failed multi-blob connection"
        );
    }

    /// A consumer account (no `hd` claim) against a domain-restricted provider is
    /// rejected with `authError`.
    #[tokio::test]
    async fn test_oidc_consumer_account_no_hd_rejected_auth_error() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let restricted = OidcConfig {
            allowed_domains: vec!["example.com".to_string()],
            ..make_test_oidc_config()
        };
        install_oidc_policy(&asm, restricted).await;
        let cc = make_cc("test-vs");
        let mut claims = oidc_base_claims();
        claims.as_object_mut().unwrap().remove("hd");
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "some.cn");

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::AuthError),
            "expected authError, got {:?}",
            api.code
        );
    }

    /// A blob naming an issuer with no declared trusted service is a `paramError`,
    /// and the error does not echo the attacker-supplied issuer string.
    #[tokio::test]
    async fn test_oidc_unknown_issuer_param_error() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let unknown_issuer = "https://idp.attacker.example";
        let req = make_connect_request(
            vec![AuthBlob::Oidc(OidcBlob {
                issuer: unknown_issuer.to_string(),
                id_token: mint_signed(oidc_base_claims()),
                nonce: OIDC_NONCE.to_string(),
            })],
            "some.cn",
        );

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "expected paramError, got {:?}",
            api.code
        );
        assert!(
            !api.message.contains(unknown_issuer),
            "error must not echo the blob's issuer: {}",
            api.message
        );
    }

    /// With no keys at all (empty seed, fetch never succeeded) the failure is
    /// `temporarilyUnavailable` with a non-zero retry hint.
    #[tokio::test]
    async fn test_oidc_no_keys_temporarily_unavailable() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        // Empty seed; a jwks_uri exists (so the key source is viable) but no fetch
        // has ever succeeded, so the current key set is empty.
        let keyless = OidcConfig {
            seed_jwks: String::new(),
            jwks_uri: "https://192.0.2.1/certs".to_string(),
            ..make_test_oidc_config()
        };
        install_oidc_policy(&asm, keyless).await;
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::TemporarilyUnavailable),
            "expected temporarilyUnavailable, got {:?}",
            api.code
        );
        assert_eq!(api.retry_in, config::OIDC_NO_KEYS_RETRY_SECS);
    }

    /// A fully valid login that no join policy admits is refused with `policyDenied`
    /// — unlike the device-only case (#227), which may stay connected without one.
    #[tokio::test]
    async fn test_valid_login_no_join_policy_is_policy_denied() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        // The only join policy requires a domain this login does not have.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[],
                &[("user.domain", "blocked.example")],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::PolicyDenied),
            "expected policyDenied, got {:?}",
            api.code
        );
    }

    /// `user.zpr.authority` expires at `auth_time + expiration_seconds`, anchored to
    /// the authentication moment — not at the token's `exp`, which is reject-only.
    #[tokio::test]
    async fn test_user_authority_expiry_is_auth_time_plus_lifetime() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        // Authenticated an hour ago; policy lifetime is 12 h, so the authority must
        // expire ~11 h from now regardless of the token's 1 h `exp`.
        let auth_time = unix_now() - 3600;
        let mut claims = oidc_base_claims();
        claims["auth_time"] = json!(auth_time);
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("valid OIDC connect should authorize");

        let expires = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("user authority must be stamped")
            .get_expires();
        let expected =
            SystemTime::UNIX_EPOCH + Duration::from_secs(auth_time + OIDC_LIFETIME_SECS as u64);
        let drift = expires
            .duration_since(expected)
            .unwrap_or_else(|e| e.duration());
        assert!(
            drift < Duration::from_secs(30),
            "authority expiry must be auth_time + lifetime (drift {}s)",
            drift.as_secs()
        );
    }
}
