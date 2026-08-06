//! HTTPS admin service implementation.
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use axum::{
    Extension,
    Json,
    Router,
    //routing::post,
    extract::{Json as EJson, Path as EPath, Query, Request, State},
    //extract::Form,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    //response::Response,
    routing::{delete, get, post},
};

use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tower_service::Service;

use zpr::policy_types::{PolicyBundle, Scope};
use zpr::vsapi_types::{DockPepType, KeyFormat, KeySet, Visa};

use libeval::attribute::{Attribute, ROLE_NODE, key};
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use serde::Deserialize;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::admin_apikeys::Permission;
use crate::apikey::ApiKey;
use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::db::Role;
use crate::error::ServiceError;
use crate::event_mgr::VsEvent;
use crate::logging::targets::ADMIN;
use crate::policy_mgr::DEFAULT_POLICY_ID;
use crate::visa_mgr::VisaMgr;

use zpr::vsapi_types::vsapi_ip_number as ip_proto;

use admin_api_types::{
    ActorDescriptor, ApiAttribute, ApiKeyFormat, ApiKeySet, CnEntry, ConnectionType, DenyRecord,
    ListEntry, NamedListEntry, NetworkDetails, NodeConnection, NodeRecordBrief, Revokes,
    ServiceDescriptor, Stats, VisaDescriptor,
};

// Must use tokio RwLock here becuase we need state to be Send.
type SharedState = Arc<tokio::sync::RwLock<AdminState>>;

#[allow(dead_code)]
struct AdminState {
    asm: Arc<Assembly>,
}

#[derive(Deserialize, Debug)]
struct RoleFilter {
    role: Option<ActorRole>,
}

/// Query args for `GET /admin/visas/denies`. `since` is epoch milliseconds.
#[derive(Deserialize, Debug)]
struct DenyFilter {
    since: Option<u64>,
    limit: Option<usize>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ActorRole {
    Node,
    Adapter,
}

struct ProtocolDetails {
    /// Human readable protocol name, e.g. "TCP", "UDP", "ICMP"
    protocol: String,
    source_port: Option<u16>,
    dest_port: Option<u16>,
}

/// Blocking start of the admin server.
/// TODO: Do I need a handle or something to stop this cleanly?
pub async fn start_admin_server(
    key_file: &Path,
    cert_file: &Path,
    listen: SocketAddr,
    asm: &Arc<Assembly>,
) {
    debug!(target: ADMIN, "admin service starting");
    let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
    serve(
        rustls_tls_acceptor(key_file, cert_file),
        listen,
        shared_state,
    )
    .await;
}

impl AdminState {
    pub fn new(asm: Arc<Assembly>) -> Self {
        AdminState { asm }
    }
}

fn rustls_tls_acceptor(key_file: &Path, cert_file: &Path) -> TlsAcceptor {
    let cert_pem = std::fs::read(cert_file).expect("failed to read admin cert file");
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .expect("failed to parse admin cert PEM");

    let key_pem = std::fs::read(key_file).expect("failed to read admin key file");
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("failed to parse admin key PEM")
        .expect("no private key found in admin key file");

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("failed to build rustls ServerConfig");

    TlsAcceptor::from(Arc::new(cfg))
}

/// Check the passed API key.
async fn validate_api_key(state: &SharedState, api_key: &str) -> Result<Permission, StatusCode> {
    let rstate = state.read().await;

    let apikey = ApiKey::parse(api_key).map_err(|_| StatusCode::UNAUTHORIZED)?;

    match rstate.asm.admin_api_keys.lookup_permission(&apikey) {
        Ok(Some(perm)) => Ok(perm),
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            error!(target: ADMIN, "error validating API key {}: {}", apikey.key_id_hex(), e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Check the API key and if all good inserts a Permission as a request extension.
async fn require_api_key(
    State(state): State<SharedState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|hv| hv.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // TODO: Add exponential backoff on unauthorizied requests.

    let perm = validate_api_key(&state, api_key).await?;
    req.extensions_mut().insert(perm);
    Ok(next.run(req).await)
}

fn admin_app(state: SharedState) -> Router {
    Router::new()
        .route("/admin/policies", get(get_policies))
        .route("/admin/policies/{capture}", get(get_policy))
        .route("/admin/policies/curr", get(get_curr_policy))
        .route("/admin/policies", post(install_policy))
        .route("/admin/visas", get(get_visas).with_state(state.clone()))
        .route("/admin/visas/denies", get(get_denies))
        .route("/admin/visas/{capture}", get(get_visa))
        .route("/admin/visas/{capture}", delete(revoke_visa))
        .route("/admin/actors", get(get_actors).with_state(state.clone()))
        .route("/admin/actors/{capture}", get(get_actor))
        .route("/admin/actors/{capture}/visas", get(get_related_visas))
        .route("/admin/actors/{capture}", delete(revoke_actor))
        .route("/admin/nodes/{capture}/visas", get(get_visas_on_node))
        .route("/admin/services", get(get_services))
        .route("/admin/services/{capture}", get(get_service))
        .route(
            "/admin/services/{capture}/cache",
            delete(flush_service_cache),
        )
        .route("/admin/authrevoke", get(get_revokes))
        .route("/admin/authrevoke/{capture}", get(get_revoke))
        .route("/admin/authrevoke/{capture}", post(add_revoke))
        .route("/admin/authrevoke/clear", post(clear_revokes))
        .route("/admin/authrevoke/{capture}", delete(remove_revoke))
        .route("/admin/network", get(get_network))
        .route("/admin/stats", get(get_stats))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .with_state(state.clone())
}

async fn serve(tls_acceptor: TlsAcceptor, listen: SocketAddr, state: SharedState) {
    let app = admin_app(state);
    let listener = TcpListener::bind(listen).await.unwrap_or_else(|e| {
        panic!("failed to bind admin https listener on {listen}: {e}");
    });
    info!(target: ADMIN, "admin https service listening on {listen} (TLS)");

    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();
        let (cnx, addr) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let stream = match tls_acceptor.accept(cnx).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!(target: ADMIN, "error during TLS handshake from {addr}, Error {e}");
                    return;
                }
            };

            let stream = TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |req: Request<Incoming>| {
                tower_service.clone().call(req)
            });

            let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
                .await;

            if let Err(e) = ret {
                warn!(target: ADMIN, "error serving admin connection from {addr}: {}", e);
            }
        });
    }
}

/// TODO: Placeholder - Only returns ID(0) which is for the current policy.
async fn get_policies(
    Extension(perm): Extension<Permission>,
) -> Result<Json<ListEntry>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/policies");
    let le = ListEntry {
        id: DEFAULT_POLICY_ID,
    };
    Ok(Json(le))
}

/// TODO: Handle multiple policies. Right now only accepts ID(0).
async fn get_policy(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(id): EPath<u64>,
) -> Result<Json<PolicyBundle>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/policies/{id}");
    get_policy_by_id(&state.read().await.asm, id).await
}

async fn get_curr_policy(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> Result<Json<PolicyBundle>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/policies/curr");
    get_policy_by_id(&state.read().await.asm, DEFAULT_POLICY_ID).await
}

/// Helper function used by [get_policy] and [get_curr_policy].
async fn get_policy_by_id(asm: &Assembly, id: u64) -> Result<Json<PolicyBundle>, StatusCode> {
    if id != DEFAULT_POLICY_ID {
        return Err(StatusCode::NOT_FOUND);
    }

    let bundle = {
        let pmgr = &asm.policy_mgr;
        let container = pmgr.get_current_container();
        match PolicyBundle::new_from_policy_container(0, container) {
            Ok(pb) => pb,
            Err(e) => {
                error!(target: ADMIN, "error creating policy bundle for policy {id}: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };
    Ok(Json(bundle))
}

async fn install_policy(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EJson(body): EJson<PolicyBundle>,
) -> Result<Json<ListEntry>, StatusCode> {
    if !perm.can_write() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "POST /admin/policies");

    let container_bytes = body.decode().map_err(|e| {
        error!(target: ADMIN, "error decoding policy bundle: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let rstate = state.read().await;
    match rstate
        .asm
        .policy_mgr
        .update_policy_from_container_bytes(container_bytes)
        .await
    {
        Ok(vinst) => {
            info!(target: ADMIN, "policy updated successfully, new vinst={vinst}");
            // fire event!
            let evt = VsEvent::PolicyUpdated(vinst);
            if let Err(e) = rstate.asm.event_mgr.record_event(evt).await {
                warn!(target: ADMIN, "failed to record policy updated event: {}", e);
            }
        }
        Err(e) => {
            error!(target: ADMIN, "failed to update policy: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    drop(rstate);

    // what do we use as the policy identifier?
    // In the future maybe it will be possible to add policies to system without activating them.
    // In delegating model we mave have several policies installed for different domains.
    // For now we punt on this and just use identifier 0.
    let le = ListEntry {
        id: DEFAULT_POLICY_ID,
    };
    Ok(Json(le))
}

/// Returns a list of visa IDs in ListEntry structs or empty list.
async fn get_visas(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> (StatusCode, Json<Vec<ListEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<ListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/visas");
    let rstate = state.read().await;

    // TODO: The API does not include details on how to do pagination.
    match rstate.asm.visa_mgr.list_all_visa_ids().await {
        Err(e) => {
            error!(target: ADMIN, "error listing visa IDs: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ListEntry>::new()),
            );
        }
        Ok(visa_ids) => {
            let le_list: Vec<ListEntry> = visa_ids.into_iter().map(|id| ListEntry { id }).collect();
            return (StatusCode::OK, Json(le_list));
        }
    }
}

/// Returns the recent-denies window, newest request first, optionally filtered
/// by `since` (epoch milliseconds, inclusive) and capped by `limit`.
async fn get_denies(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    Query(q): Query<DenyFilter>,
) -> (StatusCode, Json<Vec<DenyRecord>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<DenyRecord>::new()));
    }
    debug!(target: ADMIN, "GET /admin/visas/denies since={:?} limit={:?}", q.since, q.limit);
    let rstate = state.read().await;

    let records = rstate
        .asm
        .deny_log
        .recent(q.since, q.limit)
        .into_iter()
        .map(|e| DenyRecord {
            source_addr: e.source_addr,
            dest_addr: e.dest_addr,
            protocol: e.protocol,
            dest_port: e.dest_port,
            count: e.count,
            last_deny_ms: e.last_deny_ms,
            deny_code: e.deny_code,
        })
        .collect();

    (StatusCode::OK, Json(records))
}

async fn get_visa(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(id): EPath<u64>,
) -> Result<Json<VisaDescriptor>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/visas/{}", id);
    let rstate = state.read().await;

    match rstate.asm.visa_mgr.get_visa_with_metadata_by_id(id).await {
        Err(e) => {
            error!(target: ADMIN, "error getting visa {}: {}", id, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(opt_visa_and_md) => match opt_visa_and_md {
            None => Err(StatusCode::NOT_FOUND),
            Some(visa_and_md) => {
                let visa = &visa_and_md.visa;
                let metadata = &visa_and_md.metadata;
                let proto_deets = protocol_details_for_visa(visa);

                let vd = VisaDescriptor {
                    id: visa.issuer_id,
                    expires: visa.expires,
                    created: metadata.ctime,
                    requesting_node: metadata.requesting_node.to_string(),
                    policy_id: metadata.policy_version.to_string(),
                    zpl: metadata.zpl.to_string(),
                    direction: match metadata.direction {
                        libeval::eval_result::Direction::Forward => {
                            admin_api_types::VisaMatchDirection::Forward
                        }
                        libeval::eval_result::Direction::Reverse => {
                            admin_api_types::VisaMatchDirection::Reverse
                        }
                    },
                    source_addr: if let Some(ref dock_pep) = visa.dock_pep {
                        Some(dock_pep.source_addr.to_string())
                    } else {
                        None
                    },
                    dest_addr: if let Some(ref dock_pep) = visa.dock_pep {
                        Some(dock_pep.dest_addr.to_string())
                    } else {
                        None
                    },
                    source_port: proto_deets.source_port,
                    dest_port: proto_deets.dest_port,
                    proto: proto_deets.protocol,
                    signals: metadata.signal_msgs.clone(),
                    session_key: if let Some(ref dock_pep) = visa.dock_pep {
                        to_api_keyset(&dock_pep.session_key)
                    } else {
                        ApiKeySet::default()
                    },
                };
                return Ok(Json(vd));
            }
        },
    }
}

fn protocol_details_for_visa(visa: &Visa) -> ProtocolDetails {
    if visa.dock_pep.is_none() {
        return ProtocolDetails {
            protocol: "N/A".to_string(),
            source_port: None,
            dest_port: None,
        };
    }
    let (proto_name, source_port, dest_port) = match &visa.dock_pep.as_ref().unwrap().pep {
        DockPepType::ICMP(icmp_pep) => (
            "ICMP".to_string(),
            Some(icmp_pep.icmp_type as u16),
            Some(icmp_pep.icmp_code as u16),
        ),
        DockPepType::UDP(tu_pep) => (
            "UDP".to_string(),
            Some(tu_pep.source_port),
            Some(tu_pep.dest_port),
        ),
        DockPepType::TCP(tu_pep) => (
            "TCP".to_string(),
            Some(tu_pep.source_port),
            Some(tu_pep.dest_port),
        ),
    };

    ProtocolDetails {
        protocol: proto_name,
        source_port,
        dest_port,
    }
}

async fn revoke_visa(EPath(id): EPath<u64>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/visas/{}", id);
    let r = Revokes {
        id: id.to_string(),
        revoked: vec![0],
    };

    (StatusCode::OK, Json(r)).into_response()
}

/// Returns a list of connected CN values in CnEntry structs or empty list.
async fn get_actors(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    Query(q): Query<RoleFilter>,
) -> (StatusCode, Json<Vec<CnEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<CnEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/actors {:?}", q);
    let db_filter = match q.role {
        Some(ActorRole::Node) => Some(Role::Node),
        Some(ActorRole::Adapter) => Some(Role::Adapter),
        None => None,
    };

    let rstate = state.read().await;
    match rstate.asm.actor_mgr.list_actor_cns(db_filter).await {
        Err(e) => {
            error!(target: ADMIN, "error listing connected actors: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<CnEntry>::new()),
            )
        }
        Ok(cns) => {
            let cn_list: Vec<CnEntry> = cns.into_iter().map(|cn| CnEntry { cn }).collect();
            (StatusCode::OK, Json(cn_list))
        }
    }
}

async fn get_actor(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
    EPath(cn): EPath<String>,
) -> Result<Json<ActorDescriptor>, StatusCode> {
    debug!(target: ADMIN, "GET /admin/actor/{}", cn);
    let rstate = state.read().await;
    let asm = rstate.asm.clone();
    drop(rstate);

    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }

    match asm.actor_mgr.get_actor_by_cn(&cn).await {
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(opt_a) => match opt_a {
            None => Err(StatusCode::NOT_FOUND),
            Some(actor) => {
                let ident = match actor.get_identity() {
                    Some(id) => id.join("|"),
                    None => "".to_string(),
                };

                let is_node = match actor.get_attribute(key::ROLE) {
                    Some(role_attr) => {
                        if let Ok(role_val) = role_attr.get_single_value() {
                            role_val == ROLE_NODE
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                let zpr_addr_str = match actor.get_zpr_addr() {
                    Some(addr) => addr.to_string(),
                    None => "".to_string(),
                };

                let attrs = actor.attrs_iter().map(|a| to_api_attribute(a)).collect();

                let auth_exp = actor.get_authentication_expiration();

                let node_details = match is_node {
                    true => Some(build_node_record_brief(&asm, actor).await?),
                    false => None,
                };

                let descriptor = ActorDescriptor {
                    cn: cn.clone(),
                    ctime: SystemTime::UNIX_EPOCH, // TODO: Not tracked yet
                    ident,
                    node: is_node,
                    zpr_addr: zpr_addr_str,
                    attrs,
                    auth_exp,
                    node_details,
                };
                return Ok(Json(descriptor));
            }
        },
    }
}

async fn build_node_record_brief(
    asm: &Assembly,
    actor: libeval::actor::Actor,
) -> Result<NodeRecordBrief, StatusCode> {
    let counters = asm.counters.clone();
    let actor_mgr = asm.actor_mgr.clone();
    let visa_mgr = &asm.visa_mgr;
    let topo_mgr = &asm.topo_mgr;

    let zpr_addr = match actor.get_zpr_addr() {
        Some(addr) => addr,
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let pending_install = visa_mgr
        .get_num_pending_install_visas(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let last_contact = actor_mgr
        .get_node_last_seen(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let visa_requests = counters
        .get_node_counter(zpr_addr, CounterType::VisaRequests)
        .unwrap_or(0);
    let approved_vreqs = counters
        .get_node_counter(zpr_addr, CounterType::VisaRequestsApproved)
        .unwrap_or(0);
    let denied_vreqs = counters
        .get_node_counter(zpr_addr, CounterType::VisaRequestsDenied)
        .unwrap_or(0);
    let last_vreq = counters.get_last_request_time(zpr_addr);
    let adapters = actor_mgr
        .get_adapter_cns_connected_to_node(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut links: Vec<String> = Vec::new();
    for peer_addr in topo_mgr.get_peers(zpr_addr) {
        match actor_mgr.get_cn_by_zpr_addr(&peer_addr).await {
            Ok(cn) => links.push(cn),
            Err(e) => {
                warn!(target: ADMIN, "error {} getting CN for peer with addr {}", e, peer_addr);
                links.push(format!("cn_missing:{}", peer_addr))
            }
        }
    }
    let visas = visa_mgr
        .get_installed_visa_ids_for_node(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let visas_enqueued = visa_mgr
        .get_pending_visa_ids_for_node(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pending_revocation = visa_mgr
        .get_num_pending_revoked_visas(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (vss_port, in_sync) = match actor_mgr
        .get_node_vss(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(socket_addr) => (Some(socket_addr.port()), true),
        None => (None, false),
    };

    Ok(NodeRecordBrief {
        pending_install,
        last_contact,
        visa_requests,
        connect_requests: 0, // TODO blocked on tracking calls to authorize_connect
        in_sync,
        approved_vreqs,
        denied_vreqs,
        last_vreq,
        adapters,
        links,
        visas,
        visas_enqueued,
        pending_revocation,
        vss_port,
    })
}

async fn revoke_actor(EPath(cn): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/actors/{}", cn);
    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0, 1, 2],
    };

    (StatusCode::OK, Json(r)).into_response()
}

/// Resolve a CN to its ZPR address and a cloned (Arc-backed) visa manager, releasing the state
/// read-lock before returning so callers can do longer work without blocking writers. When
/// `require_node` is set, non-node actors are rejected with `BAD_REQUEST`. On any failure the
/// appropriate `StatusCode` is returned for the caller to surface.
async fn resolve_actor_addr(
    state: &SharedState,
    cn: &str,
    require_node: bool,
) -> Result<(IpAddr, VisaMgr), StatusCode> {
    let rstate = state.read().await;

    let actor = match rstate.asm.actor_mgr.get_actor_by_cn(cn).await {
        Err(e) => {
            error!(target: ADMIN, "error getting actor with cn {}: {}", cn, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Ok(Some(actor)) => actor,
    };

    if require_node && !actor.is_node() {
        warn!(target: ADMIN, "actor {} is not a node", cn);
        return Err(StatusCode::BAD_REQUEST);
    }

    let actor_addr = match actor.get_zpr_addr() {
        None => {
            warn!(target: ADMIN, "actor {} has no ZPR address", cn);
            return Err(StatusCode::NOT_FOUND);
        }
        Some(addr) => *addr,
    };

    Ok((actor_addr, rstate.asm.visa_mgr.clone()))
}

/// List of visa IDs
async fn get_related_visas(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(cn): EPath<String>,
) -> (StatusCode, Json<Vec<ListEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<ListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/actors/{}/visas", cn);

    let (actor_addr, visa_mgr) = match resolve_actor_addr(&state, &cn, false).await {
        Ok(pair) => pair,
        Err(code) => return (code, Json(Vec::<ListEntry>::new())),
    };

    match visa_mgr.get_visa_ids_for_actors(&[actor_addr]).await {
        Ok(ids) => (
            StatusCode::OK,
            Json(ids.into_iter().map(|id| ListEntry { id }).collect()),
        ),
        Err(e) => {
            error!(target: ADMIN, "get_visa_ids_for_actors failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ListEntry>::new()),
            )
        }
    }
}

/// List of visa IDs
async fn get_visas_on_node(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(cn): EPath<String>,
) -> (StatusCode, Json<Vec<ListEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<ListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/nodes/{}/visas", cn);

    let (actor_addr, visa_mgr) = match resolve_actor_addr(&state, &cn, true).await {
        Ok(pair) => pair,
        Err(code) => return (code, Json(Vec::<ListEntry>::new())),
    };

    let visa_ids = match visa_mgr.get_installed_visa_ids_for_node(&actor_addr).await {
        Ok(ids) => ids,
        Err(e) => {
            error!(target: ADMIN, "get_installed_visa_ids_for_node failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ListEntry>::new()),
            );
        }
    };
    let related_visas: Vec<ListEntry> = visa_ids.into_iter().map(|id| ListEntry { id }).collect();
    (StatusCode::OK, Json(related_visas))
}

async fn get_services(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> (StatusCode, Json<Vec<NamedListEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<NamedListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/services");
    let rstate = state.read().await;

    match rstate.asm.actor_mgr.get_services_list().await {
        Err(e) => {
            error!(target: ADMIN, "error listing services: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<NamedListEntry>::new()),
            )
        }
        Ok(services) => {
            let sle_list: Vec<NamedListEntry> = services
                .into_iter()
                .map(|se| NamedListEntry { id: se.name })
                .collect();
            (StatusCode::OK, Json(sle_list))
        }
    }
}

async fn get_service(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(svc_name): EPath<String>,
) -> Result<Json<ServiceDescriptor>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }

    debug!(target: ADMIN, "GET /admin/service name={}", svc_name);
    let rstate = state.read().await;

    match rstate.asm.actor_mgr.get_service_detail(&svc_name).await {
        Err(e) => {
            error!(target: ADMIN, "error getting service detail for service {}: {}", svc_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(opt_detail) => {
            if let Some(detail) = opt_detail {
                let connect_via = match detail.connect_via.as_ref() {
                    Some(cv_addr) => cv_addr.to_string(),
                    None => "".to_string(),
                };
                let cp = rstate.asm.policy_mgr.get_current();

                let (svc_kind, svc_endpoints) = if let Some(psvc) = cp.service_by_id(&svc_name) {
                    (
                        format!("{:?}", psvc.kind),
                        service_endpoints_to_string(&psvc.endpoints),
                    )
                } else {
                    ("".to_string(), "".to_string())
                };

                let sd = ServiceDescriptor {
                    service_name: detail.service_name,
                    zpr_addr: detail.zpr_addr.to_string(),
                    actor_cn: detail.actor_cn,
                    dock_zpr_addr: connect_via,
                    service_kind: svc_kind,
                    service_endpoints: svc_endpoints,
                };
                Ok(Json(sd))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }
    }
}

/// DELETE /admin/services/{id}/cache — reload a trusted service's attribute data and
/// reconcile against it: the actors behind live visas are refreshed and their visas
/// re-checked, so no visa keeps relying on the old data.
///
/// The reload is synchronous (its failure is reported to the caller); the reconciliation
/// runs on the event worker, so success returns `202 Accepted` and the outcome shows up
/// in the log rather than the response.
async fn flush_service_cache(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(svc_id): EPath<String>,
) -> StatusCode {
    if !perm.can_write() {
        return StatusCode::FORBIDDEN;
    }
    debug!(target: ADMIN, "DELETE /admin/services/{}/cache", svc_id);

    // Clone the Arcs and drop the read guard before awaiting the flush.
    let (ts_mgr, event_mgr) = {
        let rstate = state.read().await;
        (rstate.asm.ts_mgr.clone(), rstate.asm.event_mgr.clone())
    };

    match ts_mgr.flush_one(&svc_id).await {
        Ok(()) => {
            // The flush itself is done. If the event cannot be queued we lose only the
            // sweep of existing visas -- new visa decisions are still protected by the
            // per-actor revision check. The event carries no source id (the reconcile
            // is unscoped), so name the source here where it is known.
            info!(target: ADMIN, "flushed trusted service {}, queueing revalidation", svc_id);
            if let Err(e) = event_mgr.record_event(VsEvent::TrustedServiceChange).await {
                error!(target: ADMIN, "flushed trusted service {} but could not queue revalidation: {}", svc_id, e);
            }
            StatusCode::ACCEPTED
        }
        Err(ServiceError::TrustedServiceNotFound(_)) => StatusCode::NOT_FOUND,
        Err(e) => {
            error!(target: ADMIN, "error flushing trusted service {}: {}", svc_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn service_endpoints_to_string(endpoints: &[Scope]) -> String {
    let mut ep_strs: Vec<String> = Vec::new();
    for ep in endpoints {
        let port_str = if let Some(port) = ep.port {
            port.to_string()
        } else if let Some(port_range) = ep.port_range {
            format!("{}-{}", port_range.0, port_range.1)
        } else {
            "".to_string()
        };
        match ep.protocol {
            ip_proto::TCP => ep_strs.push(format!("TCP/{}", port_str)),
            ip_proto::UDP => ep_strs.push(format!("UDP/{}", port_str)),
            ip_proto::ICMP => ep_strs.push(format!("ICMP/{}", port_str)),
            ip_proto::IPV6_ICMP => ep_strs.push(format!("IPV6_ICMP/{}", port_str)),
            _ => ep_strs.push(format!("PROTO_{}/{}", ep.protocol, port_str)),
        }
    }
    ep_strs.join(",")
}

async fn get_revokes() -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/authrevoke - NOT IMPLEMENTED");
    (StatusCode::OK, Json(Vec::<ListEntry>::new())).into_response()
}

async fn get_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/authrevoke/{} - NOT IMPLEMENTED", id);
    (StatusCode::NOT_FOUND, Json(()).into_response())
}

async fn clear_revokes() -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/authrevoke/clear - NOT IMPLEMENTED");
    (StatusCode::NOT_IMPLEMENTED, Json(()).into_response())
}

async fn remove_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/authrevoke/{} - NOT IMPLEMENTED", id);
    (StatusCode::NOT_IMPLEMENTED, Json(()).into_response())
}

async fn add_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/authrevoke/{} - NOT IMPLEMENTED", id);
    (StatusCode::NOT_IMPLEMENTED, Json(()).into_response())
}

async fn get_network(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> Result<Json<NetworkDetails>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    info!(target: ADMIN, "GET /admin/network");
    let rstate = state.read().await;

    // Start with the desired topology setup, then we will mark which ones are up.

    // Only track link(a,b) once (ie, do not also store link(b,a)).
    let mut pairs = HashSet::new();

    let mut topo = Vec::new();
    let psnap = rstate.asm.policy_mgr.get_current_snapshot();

    for node_addr in psnap.policy().all_peered_nodes() {
        if let Some(peers) = psnap.policy().get_peers_for_node(node_addr) {
            for peer in peers {
                let pair_id = if node_addr < &peer.remote_zpr_addr {
                    (node_addr.clone(), peer.remote_zpr_addr.clone())
                } else {
                    (peer.remote_zpr_addr.clone(), node_addr.clone())
                };

                if pairs.contains(&pair_id) {
                    continue;
                }
                pairs.insert(pair_id);

                // Each peer has a link_id, remote_zpr_addr, and a remote_substrate NetAddr.
                // Ok so a desired link is node_addr to peer

                let mut bldr =
                    NodeConnection::builder(node_addr.clone(), peer.remote_zpr_addr.clone())
                        .link_id(peer.link_id.clone())
                        .node_b_substrate(format!(
                            "{}:{}",
                            peer.remote_substrate.host, peer.remote_substrate.port
                        ));

                if let Ok(link_desc) = psnap
                    .policy()
                    .describe_link(node_addr, &peer.remote_zpr_addr)
                {
                    let api_attrs = link_desc
                        .attrs
                        .iter()
                        .map(to_api_attribute)
                        .collect::<Vec<ApiAttribute>>();

                    bldr = bldr.link_attrs(api_attrs).link_cost(link_desc.cost);
                }
                topo.push(bldr.build());
            }
        }
    }

    // Now we have constructed the ideal topology, lets see what we've actually got
    // starting with our connected nodes.

    let node_addrs = match rstate.asm.actor_mgr.list_node_addrs().await {
        Ok(addrs) => addrs,
        Err(e) => {
            error!(target: ADMIN, "Error {} getting node list", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Everything in topo so far is policy-declared, so only those entries can go UP.
    // Links appended past this point were reported by a node but never declared.
    let declared = topo.len();

    for node_addr in node_addrs {
        for peer_addr in rstate.asm.topo_mgr.get_peers(&node_addr) {
            // Ok we have node_addr <-> peer_addr, so update the node connection to UP
            // Or if it does not exist, insert it as INVALID.
            let mut matched = false;
            for (i, nc) in topo.iter_mut().enumerate() {
                if nc.is_link_between(&node_addr, &peer_addr) {
                    if i < declared {
                        nc.set_status(ConnectionType::UP);
                    }
                    matched = true;
                }
            }
            if !matched {
                topo.push(
                    NodeConnection::builder(node_addr.clone(), peer_addr.clone())
                        .invalid()
                        .build(),
                );
            }
        }
    }

    Ok(Json(NetworkDetails { network: topo }))
}

async fn get_stats(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> Result<Json<Stats>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }

    debug!(target: ADMIN, "GET /admin/stats");

    let mut stat_map = HashMap::new();

    let rstate = state.read().await;

    stat_map.insert(
        "uptime".to_string(),
        rstate.asm.get_uptime().as_secs().to_string(),
    );
    for (key, ref value) in &rstate.asm.counters.counters {
        stat_map.insert(key.name().to_string(), value.get_count().to_string());
    }

    Ok(Json(Stats { stats: stat_map }))
}

fn to_api_attribute(attr: &Attribute) -> ApiAttribute {
    ApiAttribute {
        key: attr.get_key().to_string(),
        value: attr.get_value().to_vec(),
        expires_at: attr.get_expires(),
    }
}

fn to_api_keyset(ks: &KeySet) -> ApiKeySet {
    ApiKeySet {
        format: to_api_keyformat(&ks.format),
        ingress_key: ks.ingress_key.clone(),
        egress_key: ks.egress_key.clone(),
    }
}

fn to_api_keyformat(kf: &KeyFormat) -> ApiKeyFormat {
    match kf {
        KeyFormat::ZprKF01 => ApiKeyFormat::ZprKF01,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::apikey::ApiKey;
    use admin_api_types::VisaMatchDirection;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use libeval::eval_result::{Direction, Hit, Signal};
    use libeval::route::Route;
    use std::net::IpAddr;
    use tower::ServiceExt;
    use zpr::vsapi_types::{DenyCode, PacketDesc};

    use crate::admin_apikeys::{ApiKeyRecord, KeyStatus};
    use crate::assembly::tests::{new_assembly_for_tests, new_assembly_with_event_rx};
    use crate::test_helpers::{
        make_adapter_actor_defexp, make_node_actor_defexp, make_peering, policy_with_peerings,
    };
    use zpr::policy_types::AttrExp;

    /// Insert a readwrite test key into the assembly's key store and return the
    /// key string to use in the X-API-Key header.
    fn setup_test_api_rw_key(asm: &Arc<Assembly>) -> String {
        setup_test_api_key_with_perm(asm, Permission::ReadWrite)
    }

    fn setup_test_api_r_key(asm: &Arc<Assembly>) -> String {
        setup_test_api_key_with_perm(asm, Permission::Read)
    }

    /// Insert a test key with the given permission into the assembly's key store
    /// and return the key string to use in the X-API-Key header.
    fn setup_test_api_key_with_perm(asm: &Arc<Assembly>, permission: Permission) -> String {
        let secret_bytes: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let apikey = ApiKey::new(0xaabbccdd, secret_bytes);
        let record = ApiKeyRecord {
            owner: "test".to_string(),
            permission,
            status: KeyStatus::Active,
            created: "2026-01-01".to_string(),
            secret_hash: apikey.secret_hash().unwrap(),
            description: "test key".to_string(),
        };
        asm.admin_api_keys
            .insert_for_test(apikey.key_id_hex(), record);
        apikey.to_key_string()
    }

    /// Build a valid `PolicyBundle` carrying a minimal policy (no topology, so the
    /// FakeResolver in the test assembly resolves it cleanly) at the minimum
    /// supported compiler version, for use as `install_policy` request input.
    fn make_valid_policy_bundle() -> PolicyBundle {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<zpr::policy::v1::policy::Builder>();
            policy.set_created("2026-01-01T00:00:00Z");
            policy.set_version(1);
            policy.set_metadata("");
        }
        let mut inner = Vec::new();
        capnp::serialize::write_message(&mut inner, &msg).unwrap();
        let container = crate::test_helpers::make_container_bytes(
            crate::config::POLICY_MIN_COMPILER_MAJOR,
            crate::config::POLICY_MIN_COMPILER_MINOR,
            crate::config::POLICY_MIN_COMPILER_PATCH,
            &inner,
        );
        PolicyBundle::new_from_policy_container(0, container.into()).unwrap()
    }

    /// GET /admin/policies returns the single current policy id (0) with a read key.
    #[tokio::test]
    async fn test_get_policies_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let entry: ListEntry = serde_json::from_slice(&body).unwrap();
        assert_eq!(entry.id, DEFAULT_POLICY_ID);
    }

    /// GET /admin/policies/curr returns the current policy as a base64;zip PolicyBundle.
    #[tokio::test]
    async fn test_get_curr_policy_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/curr")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let bundle: PolicyBundle = serde_json::from_slice(&body).unwrap();
        assert_eq!(bundle.config_id, DEFAULT_POLICY_ID);
        assert!(bundle.format.starts_with("base64;zip;"));
        assert!(!bundle.container.is_empty());
    }

    /// GET /admin/policies/0 returns the current policy bundle (id 0 is the default).
    #[tokio::test]
    async fn test_get_policy_by_id_zero_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/0")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let bundle: PolicyBundle = serde_json::from_slice(&body).unwrap();
        assert!(bundle.format.starts_with("base64;zip;"));
    }

    /// GET /admin/policies/<non-zero> is rejected because only id 0 currently exists.
    #[tokio::test]
    async fn test_get_policy_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/1")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// POST /admin/policies installs a valid bundle and the new policy is then
    /// served by GET /admin/policies/curr.
    #[tokio::test]
    async fn test_install_policy_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));

        let bundle = make_valid_policy_bundle();
        let body = serde_json::to_vec(&bundle).unwrap();

        let app = admin_app(shared_state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let entry: ListEntry = serde_json::from_slice(&body).unwrap();
        assert_eq!(entry.id, DEFAULT_POLICY_ID);

        // The installed policy should now be the current one.
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/curr")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let curr: PolicyBundle = serde_json::from_slice(&body).unwrap();
        assert_eq!(curr.decode().unwrap(), bundle.decode().unwrap());
    }

    /// POST /admin/policies rejects a bundle whose container can't be decoded.
    #[tokio::test]
    async fn test_install_policy_bad_bundle() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));

        // Valid JSON shape, but an unsupported format makes decode() fail.
        let bad = PolicyBundle {
            config_id: 0,
            version: String::new(),
            format: "hex;zip;0.11.1".to_string(),
            container: String::new(),
        };
        let body = serde_json::to_vec(&bad).unwrap();

        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// POST /admin/policies is forbidden for a read-only key (no write permission).
    #[tokio::test]
    async fn test_install_policy_forbidden_without_write() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));

        let bundle = make_valid_policy_bundle();
        let body = serde_json::to_vec(&bundle).unwrap();

        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_visas_no_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert!(visas.is_empty());
    }

    #[tokio::test]
    async fn test_get_visas_one_visa() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        let route = Route::new_direct(node_addr.into());

        // Add a visa.
        let vwmd = asm
            .visa_mgr
            .create_visa(&asm, &node_addr, &pdesc, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        let created_id = vwmd.visa.issuer_id;
        assert!(created_id > 0);

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(visas.len(), 1);
        assert_eq!(visas[0].id, created_id);
    }

    /// Drives `GET /admin/visas/denies` with the given query string and returns
    /// the status plus the decoded body.
    async fn fetch_denies(
        asm: &Arc<Assembly>,
        api_key: &str,
        query: &str,
    ) -> (StatusCode, Vec<DenyRecord>) {
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/admin/visas/denies{query}"))
                    .header("X-API-Key", api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        // A non-OK response has no DenyRecord list body.
        let records = if status == StatusCode::OK {
            serde_json::from_slice(&body).unwrap()
        } else {
            Vec::new()
        };
        (status, records)
    }

    /// Records three denies at known times so the ordering and query-filter
    /// assertions below are deterministic.
    fn seed_denies(asm: &Arc<Assembly>) {
        for (i, dport) in [80u16, 443, 8080].into_iter().enumerate() {
            let ft = PacketDesc::new_tcp(
                "fd5a:5052:3000::1",
                "fd5a:5052:3000::2",
                12345,
                dport.into(),
            )
            .unwrap()
            .five_tuple;
            asm.deny_log
                .record_at_ms(&ft, &DenyCode::NoMatch, 1_000 + i as u64 * 1_000);
        }
    }

    #[tokio::test]
    async fn test_get_denies_empty() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let (status, denies) = fetch_denies(&asm, &api_key, "").await;
        assert_eq!(status, StatusCode::OK);
        assert!(denies.is_empty());
    }

    #[tokio::test]
    async fn test_get_denies_newest_first() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        seed_denies(&asm);

        let (status, denies) = fetch_denies(&asm, &api_key, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            denies.iter().map(|d| d.dest_port).collect::<Vec<_>>(),
            vec![8080, 443, 80]
        );

        let newest = &denies[0];
        assert_eq!(
            newest.source_addr,
            "fd5a:5052:3000::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            newest.dest_addr,
            "fd5a:5052:3000::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(newest.protocol, ip_proto::TCP);
        assert_eq!(newest.count, 1);
        assert_eq!(newest.last_deny_ms, 3_000);
        assert_eq!(newest.deny_code, "NoMatch");
    }

    #[tokio::test]
    async fn test_get_denies_since_and_limit() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        seed_denies(&asm);

        // `since` is inclusive, so the entry recorded exactly at 2000 is returned.
        let (status, denies) = fetch_denies(&asm, &api_key, "?since=2000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            denies.iter().map(|d| d.last_deny_ms).collect::<Vec<_>>(),
            vec![3_000, 2_000]
        );

        let (_, denies) = fetch_denies(&asm, &api_key, "?limit=1").await;
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].last_deny_ms, 3_000);

        let (_, denies) = fetch_denies(&asm, &api_key, "?since=1000&limit=2").await;
        assert_eq!(
            denies.iter().map(|d| d.last_deny_ms).collect::<Vec<_>>(),
            vec![3_000, 2_000]
        );
    }

    #[tokio::test]
    async fn test_get_denies_rejects_malformed_query() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        for query in ["?since=-1", "?since=abc", "?limit=-5", "?limit=1.5"] {
            let (status, _) = fetch_denies(&asm, &api_key, query).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "expected 400 for query {query}"
            );
        }
    }

    #[tokio::test]
    async fn test_get_visas_three_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        // Add three visas with distinct packet descriptors.
        let pdesc0 =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let pdesc1 =
            PacketDesc::new_tcp("fd5a:5052:3000::3", "fd5a:5052:3000::4", 12346, 443).unwrap();
        let pdesc2 =
            PacketDesc::new_tcp("fd5a:5052:3000::5", "fd5a:5052:3000::6", 12347, 22).unwrap();

        let route = Route::new_direct(node_addr.into());

        let v0 = asm
            .visa_mgr
            .create_visa(&asm, &node_addr, &pdesc0, &hit, &route, "", 0, 0)
            .await
            .unwrap();
        let v1 = asm
            .visa_mgr
            .create_visa(&asm, &node_addr, &pdesc1, &hit, &route, "", 0, 0)
            .await
            .unwrap();
        let v2 = asm
            .visa_mgr
            .create_visa(&asm, &node_addr, &pdesc2, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        let mut created_ids = vec![v0.visa.issuer_id, v1.visa.issuer_id, v2.visa.issuer_id];
        created_ids.sort_unstable();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(visas.len(), 3);

        let mut returned_ids: Vec<u64> = visas.into_iter().map(|v| v.id).collect();
        returned_ids.sort_unstable();
        assert_eq!(returned_ids, created_ids);
    }

    #[tokio::test]
    async fn test_get_actors_no_actors() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let actors: Vec<CnEntry> = serde_json::from_slice(&body).unwrap();
        assert!(actors.is_empty());
    }

    #[tokio::test]
    async fn test_get_actors_one_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let actor = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr.add_node(&actor, false).await.unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let actors: Vec<CnEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(actors.len(), 1);
        assert_eq!(actors[0].cn, "node-1");
    }

    #[tokio::test]
    async fn test_get_actors_multiple_actors() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let actor0 = make_node_actor_defexp("fd5a:5052::11", "node-1", "[fd5a:5052::101]:1234");
        let actor1 = make_node_actor_defexp("fd5a:5052::12", "node-2", "[fd5a:5052::102]:1234");
        let actor2 = make_node_actor_defexp("fd5a:5052::13", "node-3", "[fd5a:5052::103]:1234");

        asm.actor_mgr.add_node(&actor0, false).await.unwrap();
        asm.actor_mgr.add_node(&actor1, false).await.unwrap();
        asm.actor_mgr.add_node(&actor2, false).await.unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let mut actors: Vec<CnEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(actors.len(), 3);
        actors.sort_by(|a, b| a.cn.cmp(&b.cn));
        let actor_cns: Vec<String> = actors.into_iter().map(|a| a.cn).collect();
        assert_eq!(
            actor_cns,
            vec![
                "node-1".to_string(),
                "node-2".to_string(),
                "node-3".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_get_actors_role_filter() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node_actor = make_node_actor_defexp("fd5a:5052::20", "node-1", "[fd5a:5052::120]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::21", "adapter-1");

        asm.actor_mgr.add_node(&node_actor, false).await.unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter_actor, node_actor.get_zpr_addr().unwrap())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response_nodes = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=node")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response_nodes.status(), StatusCode::OK);

        let body_nodes = response_nodes
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let actors_nodes: Vec<CnEntry> = serde_json::from_slice(&body_nodes).unwrap();
        assert_eq!(actors_nodes.len(), 1);
        assert_eq!(actors_nodes[0].cn, "node-1");

        let response_adapters = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=adapter")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response_adapters.status(), StatusCode::OK);

        let body_adapters = response_adapters
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let actors_adapters: Vec<CnEntry> = serde_json::from_slice(&body_adapters).unwrap();
        assert_eq!(actors_adapters.len(), 1);
        assert_eq!(actors_adapters[0].cn, "adapter-1");
    }

    #[tokio::test]
    async fn test_get_visa_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas/9999")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_visa_fields_forward_no_signal() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let zpl_str = "permit tcp from groupA to groupB port 80";
        let policy_version: u64 = 42;
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = Route::new_direct(node_addr.into());

        let v = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc,
                &hit,
                &route,
                zpl_str,
                policy_version,
                0,
            )
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.visa.issuer_id))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let vd: VisaDescriptor = serde_json::from_slice(&body).unwrap();

        assert_eq!(vd.id, v.visa.issuer_id);
        assert_eq!(vd.policy_id, "42");
        assert_eq!(vd.zpl, zpl_str);
        assert_eq!(vd.direction, VisaMatchDirection::Forward);
        assert!(vd.signals.is_empty());

        // Verify JSON encodes direction as lowercase string.
        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(raw["direction"], "forward");
    }

    #[tokio::test]
    async fn test_get_visa_direction_reverse() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Reverse);
        let route = Route::new_direct(node_addr.into());

        let v = asm
            .visa_mgr
            .create_visa(&asm, &node_addr, &pdesc, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.visa.issuer_id))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let vd: VisaDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(vd.direction, VisaMatchDirection::Reverse);

        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(raw["direction"], "reverse");
    }

    #[tokio::test]
    async fn test_get_visa_with_signal() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let signal = Signal {
            message: "alert: suspicious traffic".to_string(),
            service: "svc1".to_string(),
        };
        let hit = Hit::new_with_signal(0, Direction::Forward, signal);
        let route = Route::new_direct(node_addr.into());

        let v = asm
            .visa_mgr
            .create_visa(&asm, &node_addr, &pdesc, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.visa.issuer_id))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let vd: VisaDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(vd.signals, vec!["alert: suspicious traffic".to_string()]);
    }

    #[tokio::test]
    async fn test_get_actors_invalid_role_filter() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=invalid")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    /// The test policy declares no topology, so there are no links to report.
    async fn test_get_network_empty() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let details = fetch_network(&asm).await;
        assert!(details.network.is_empty());
    }

    /// GET /admin/network and deserialize the response body.
    async fn fetch_network(asm: &Arc<Assembly>) -> NetworkDetails {
        let api_key = setup_test_api_r_key(asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let response = admin_app(shared_state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/network")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// Install a policy peering `a` and `b` over `link-ab`, with a link cost attribute.
    async fn install_ab_peering(asm: &Arc<Assembly>, a: IpAddr, b: IpAddr) {
        let attrs = vec![AttrExp {
            key: libeval::attribute::key::LINK_COST.to_string(),
            op: zpr::policy_types::AttrOp::Eq,
            value: vec!["7".to_string()],
        }];
        asm.policy_mgr
            .update_policy_from_container_bytes(policy_with_peerings(&[make_peering(
                a, b, "link-ab", attrs,
            )]))
            .await
            .unwrap();
    }

    #[tokio::test]
    /// A link the policy declares but that no connected node reports is DOWN, and it
    /// carries the link detail (id, substrate, cost, attrs) taken from policy.
    async fn test_get_network_declared_link_down() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::11".parse().unwrap();
        install_ab_peering(&asm, addr_a, addr_b).await;

        let details = fetch_network(&asm).await;

        assert_eq!(details.network.len(), 1);
        for nc in &details.network {
            assert!(nc.is_link_between(&addr_a, &addr_b));
            assert!(matches!(nc.ctype, ConnectionType::DOWN));
            assert_eq!(nc.link_id, "link-ab");
            assert_eq!(nc.link_cost, 7);
            assert_eq!(nc.node_b_substrate, format!("{}:0", nc.node_b_addr));
            assert_eq!(nc.link_attrs.len(), 1);
        }
    }

    #[tokio::test]
    /// A declared link that the connected nodes also report is UP.
    async fn test_get_network_declared_link_up() {
        use libeval::route::LinkId;

        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::11".parse().unwrap();
        install_ab_peering(&asm, addr_a, addr_b).await;

        let actor_a = make_node_actor_defexp("fd5a:5052::10", "node-a", "[fd5a:5052::100]:1234");
        let actor_b = make_node_actor_defexp("fd5a:5052::11", "node-b", "[fd5a:5052::101]:1234");
        asm.actor_mgr.add_node(&actor_a, false).await.unwrap();
        asm.actor_mgr.add_node(&actor_b, false).await.unwrap();
        asm.topo_mgr.add_node(addr_a).unwrap();
        asm.topo_mgr.add_node(addr_b).unwrap();
        asm.topo_mgr
            .add_link(addr_a, addr_b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();

        let details = fetch_network(&asm).await;

        assert_eq!(details.network.len(), 1);
        for nc in &details.network {
            assert!(nc.is_link_between(&addr_a, &addr_b));
            assert!(matches!(nc.ctype, ConnectionType::UP));
        }
    }

    #[tokio::test]
    /// A link the nodes report but that the policy does not declare is INVALID.
    async fn test_get_network_undeclared_link_invalid() {
        use libeval::route::LinkId;

        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::11".parse().unwrap();

        // Note: no policy peering installed, so this link is undeclared.
        let actor_a = make_node_actor_defexp("fd5a:5052::10", "node-a", "[fd5a:5052::100]:1234");
        let actor_b = make_node_actor_defexp("fd5a:5052::11", "node-b", "[fd5a:5052::101]:1234");
        asm.actor_mgr.add_node(&actor_a, false).await.unwrap();
        asm.actor_mgr.add_node(&actor_b, false).await.unwrap();
        asm.topo_mgr.add_node(addr_a).unwrap();
        asm.topo_mgr.add_node(addr_b).unwrap();
        asm.topo_mgr
            .add_link(addr_a, addr_b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();

        let details = fetch_network(&asm).await;

        assert_eq!(details.network.len(), 1);
        assert!(
            matches!(details.network[0].ctype, ConnectionType::INVALID),
            "got {:?}",
            details.network[0].ctype
        );
    }

    /// Build a Scope with the given protocol, single port, and port range.
    fn scope(protocol: u8, port: Option<u16>, port_range: Option<(u16, u16)>) -> Scope {
        Scope {
            protocol,
            flag: None,
            port,
            port_range,
        }
    }

    /// service_endpoints_to_string formats known protocols, port ranges, unknown
    /// protocols, and the empty list as expected.
    #[test]
    fn test_service_endpoints_to_string() {
        // Empty list -> empty string.
        assert_eq!(service_endpoints_to_string(&[]), "");

        // Single port with each known protocol.
        assert_eq!(
            service_endpoints_to_string(&[scope(ip_proto::TCP, Some(80), None)]),
            "TCP/80"
        );
        assert_eq!(
            service_endpoints_to_string(&[scope(ip_proto::UDP, Some(53), None)]),
            "UDP/53"
        );

        // Port range.
        assert_eq!(
            service_endpoints_to_string(&[scope(ip_proto::TCP, None, Some((8000, 8080)))]),
            "TCP/8000-8080"
        );

        // Unknown protocol falls back to PROTO_<n>.
        assert_eq!(
            service_endpoints_to_string(&[scope(200, Some(1), None)]),
            "PROTO_200/1"
        );

        // Multiple endpoints are comma-joined in order.
        assert_eq!(
            service_endpoints_to_string(&[
                scope(ip_proto::TCP, Some(80), None),
                scope(ip_proto::UDP, Some(53), None),
            ]),
            "TCP/80,UDP/53"
        );
    }

    /// GET /admin/nodes/{cn}/visas for a node with no installed visas returns OK
    /// with an empty list.
    #[tokio::test]
    async fn test_get_visas_on_node_empty_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::30", "node-1", "[fd5a:5052::130]:1234");
        asm.actor_mgr.add_node(&node, false).await.unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/nodes/node-1/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert!(visas.is_empty());
    }

    /// GET /admin/nodes/{cn}/visas for a non-node actor is rejected with BAD_REQUEST.
    #[tokio::test]
    async fn test_get_visas_on_node_non_node_bad_request() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::31", "node-1", "[fd5a:5052::131]:1234");
        let adapter = make_adapter_actor_defexp("fd5a:5052::32", "adapter-1");
        asm.actor_mgr.add_node(&node, false).await.unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter, node.get_zpr_addr().unwrap())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/nodes/adapter-1/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// GET /admin/nodes/{cn}/visas for an unknown CN returns NOT_FOUND.
    #[tokio::test]
    async fn test_get_visas_on_node_unknown_cn_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/nodes/does-not-exist/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// GET /admin/actors/{cn}/visas for an unknown CN returns NOT_FOUND (exercises
    /// the shared resolve_actor_addr helper with require_node = false).
    #[tokio::test]
    async fn test_get_related_visas_unknown_cn_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors/does-not-exist/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    const FLUSH_TS_ID: &str = "ts-file";

    /// Minimal trusted service that only records whether it was flushed.
    struct FlushCountingService {
        flushes: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for FlushCountingService {
        async fn get_attributes_for_actor(
            &self,
            _actor_ident: &str,
        ) -> Result<Vec<Attribute>, ServiceError> {
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        // Holds no snapshot; its flush count doubles as the revision.
        fn current_revision(&self) -> u64 {
            self.flushes.load(std::sync::atomic::Ordering::SeqCst) as u64
        }

        fn get_source_id(&self) -> &str {
            FLUSH_TS_ID
        }
    }

    /// Register one flush-counting trusted service on the assembly and return it for
    /// assertions.
    fn register_flush_counting_service(asm: &Arc<Assembly>) -> Arc<FlushCountingService> {
        let svc = Arc::new(FlushCountingService {
            flushes: std::sync::atomic::AtomicUsize::new(0),
        });
        asm.ts_mgr.update_services(vec![svc.clone()]);
        svc
    }

    /// DELETE /admin/services/{id}/cache flushes the named trusted service.
    #[tokio::test]
    async fn test_flush_service_cache_ok() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/services/{FLUSH_TS_ID}/cache"))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
        // The revalidation of existing visas is queued for the event worker.
        match event_rx.try_recv() {
            Ok(VsEvent::TrustedServiceChange) => {}
            other => panic!("expected TrustedServiceChange event, got {other:?}"),
        }
    }

    /// DELETE /admin/services/{id}/cache for an unregistered service returns NOT_FOUND.
    #[tokio::test]
    async fn test_flush_service_cache_unknown_not_found() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        register_flush_counting_service(&asm);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/services/does-not-exist/cache")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Nothing was invalidated, so nothing needs revalidating.
        assert!(event_rx.try_recv().is_err());
    }

    /// A read-only key may not flush a trusted service.
    #[tokio::test]
    async fn test_flush_service_cache_read_key_forbidden() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/services/{FLUSH_TS_ID}/cache"))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(event_rx.try_recv().is_err());
    }
}
