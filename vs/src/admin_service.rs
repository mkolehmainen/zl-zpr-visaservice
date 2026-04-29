//! HTTPS admin service implementation.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use libeval::attribute::{Attribute, ROLE_NODE, key};
use tracing::{debug, error, info, warn};

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

use zpr::vsapi_types::{DockPep, KeyFormat, KeySet, Visa};

use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use serde::Deserialize;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::admin_apikeys::Permission;
use crate::apikey::ApiKey;
use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::db::Role;
use crate::logging::targets::ADMIN;

use admin_api_types::{
    ActorDescriptor, ApiAttribute, ApiKeyFormat, ApiKeySet, AuthRevokeDescriptor, CnEntry,
    ListEntry, NamedListEntry, NodeRecordBrief, PolicyBundle, Revokes, ServiceDescriptor,
    VisaDescriptor,
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

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ActorRole {
    Node,
    Adapter,
}

struct ProtocolDetails {
    /// Human readable protocol name, e.g. "TCP", "UDP", "ICMP"
    protocol: String,
    source_port: u16,
    dest_port: u16,
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
        .route("/admin/visas/{capture}", get(get_visa))
        .route("/admin/visas/{capture}", delete(revoke_visa))
        .route("/admin/actors", get(get_actors).with_state(state.clone()))
        .route("/admin/actors/{capture}", get(get_actor))
        .route("/admin/actors/{capture}/visas", get(get_related_visas))
        .route("/admin/actors/{capture}", delete(revoke_actor))
        .route("/admin/services", get(get_services))
        .route("/admin/services/{capture}", get(get_service))
        .route("/admin/authrevoke", get(get_revokes))
        .route("/admin/authrevoke/{capture}", get(get_revoke))
        .route("/admin/authrevoke/{capture}", post(add_revoke))
        .route("/admin/authrevoke/clear", post(clear_revokes))
        .route("/admin/authrevoke/{capture}", delete(remove_revoke))
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

fn two_elem_list() -> impl IntoResponse {
    let le0 = ListEntry { id: 0 };
    let le1 = ListEntry { id: 1 };

    (StatusCode::OK, Json(vec![le0, le1])).into_response()
}

async fn get_policies() -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/policies");
    two_elem_list()
}

async fn get_policy(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/policies/{}", id);
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };

    (StatusCode::OK, Json(pb)).into_response()
}

async fn get_curr_policy() -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/policies/curr");
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };

    (StatusCode::OK, Json(pb)).into_response()
}

async fn install_policy(EJson(_body): EJson<PolicyBundle>) -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/policies");
    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}

/// Returns a list of visa IDs in ListEntry structs or empty list.
#[axum::debug_handler]
//async fn get_visas(State(state): State<SharedState>) -> impl IntoResponse {
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
                    source_addr: visa.source_addr.to_string(),
                    dest_addr: visa.dest_addr.to_string(),
                    source_port: proto_deets.source_port,
                    dest_port: proto_deets.dest_port,
                    proto: proto_deets.protocol,
                    signals: metadata.signal_msgs.clone(),
                    session_key: to_api_keyset(&visa.session_key),
                };
                return Ok(Json(vd));
            }
        },
    }
}

fn protocol_details_for_visa(visa: &Visa) -> ProtocolDetails {
    let (proto_name, source_port, dest_port) = match &visa.dock_pep {
        DockPep::ICMP(icmp_pep) => (
            "ICMP".to_string(),
            icmp_pep.icmp_type as u16,
            icmp_pep.icmp_code as u16,
        ),
        DockPep::UDP(tu_pep) => ("UDP".to_string(), tu_pep.source_port, tu_pep.dest_port),
        DockPep::TCP(tu_pep) => ("TCP".to_string(), tu_pep.source_port, tu_pep.dest_port),
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

    let zpr_addr = match actor.get_zpr_addr() {
        Some(addr) => addr,
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let pending_install = visa_mgr
        .get_num_pending_install_visas(zpr_addr)
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
    // TODO I don't think we have connected nodes yet, since we don't yet have multi-node
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
        last_contact: None, // TODO don't think we currently store last contact
        visa_requests,
        connect_requests: 0, // TODO blocked on tracking calls to authorize_connect
        in_sync,
        approved_vreqs,
        denied_vreqs,
        last_vreq,
        adapters,
        links: Vec::new(), // TODO blocked on multi-node support
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

async fn get_related_visas(EPath(cn): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/actors/{}/visas", cn);
    two_elem_list()
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
    EPath(cn): EPath<String>,
) -> Result<Json<ServiceDescriptor>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }

    debug!(target: ADMIN, "GET /admin/service CN={}", cn);
    let rstate = state.read().await;

    match rstate.asm.actor_mgr.get_service_detail(&cn).await {
        Err(e) => {
            error!(target: ADMIN, "error getting service detail for CN {}: {}", cn, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(opt_detail) => {
            if let Some(detail) = opt_detail {
                let connect_via = match detail.connect_via.as_ref() {
                    Some(cv_addr) => cv_addr.to_string(),
                    None => "".to_string(),
                };
                let sd = ServiceDescriptor {
                    service_name: detail.service_name,
                    zpr_addr: detail.zpr_addr.to_string(),
                    actor_cn: detail.actor_cn,
                    dock_zpr_addr: connect_via,
                };
                Ok(Json(sd))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }
    }
}

async fn get_revokes() -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/authrevoke");
    two_elem_list()
}

async fn get_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/authrevoke/{}", id);
    let ard: AuthRevokeDescriptor = AuthRevokeDescriptor {
        ty: "t".to_string(),
        cn: "c".to_string(),
    };

    (StatusCode::OK, Json(ard)).into_response()
}

async fn clear_revokes() -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/authrevoke/clear");
    two_elem_list()
}

async fn remove_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/authrevoke/{}", id);
    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}

async fn add_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/authrevoke/{}", id);

    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
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
    use std::net::IpAddr;
    use tower::ServiceExt;
    use zpr::vsapi_types::PacketDesc;

    use crate::admin_apikeys::{ApiKeyRecord, KeyStatus};
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp};

    /// Insert a readwrite test key into the assembly's key store and return the
    /// key string to use in the X-API-Key header.
    fn setup_test_api_key(asm: &Arc<Assembly>) -> String {
        let secret_bytes: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let apikey = ApiKey::new(0xaabbccdd, secret_bytes);
        let record = ApiKeyRecord {
            owner: "test".to_string(),
            permission: Permission::ReadWrite,
            status: KeyStatus::Active,
            created: "2026-01-01".to_string(),
            secret_hash: apikey.secret_hash().unwrap(),
            description: "test key".to_string(),
        };
        asm.admin_api_keys
            .insert_for_test(apikey.key_id_hex(), record);
        apikey.to_key_string()
    }

    #[tokio::test]
    async fn test_get_visas_no_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_key(&asm);
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
        let api_key = setup_test_api_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        // Add a visa.
        let v = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc, &hit, "", 0)
            .await
            .unwrap();

        let created_id = v.issuer_id;
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

    #[tokio::test]
    async fn test_get_visas_three_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        // Add three visas with distinct packet descriptors.
        let pdesc0 =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let pdesc1 =
            PacketDesc::new_tcp("fd5a:5052:3000::3", "fd5a:5052:3000::4", 12346, 443).unwrap();
        let pdesc2 =
            PacketDesc::new_tcp("fd5a:5052:3000::5", "fd5a:5052:3000::6", 12347, 22).unwrap();

        let v0 = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc0, &hit, "", 0)
            .await
            .unwrap();
        let v1 = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc1, &hit, "", 0)
            .await
            .unwrap();
        let v2 = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc2, &hit, "", 0)
            .await
            .unwrap();

        let mut created_ids = vec![v0.issuer_id, v1.issuer_id, v2.issuer_id];
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
        let api_key = setup_test_api_key(&asm);
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
        let api_key = setup_test_api_key(&asm);
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
        let api_key = setup_test_api_key(&asm);
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
        let api_key = setup_test_api_key(&asm);
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
        let api_key = setup_test_api_key(&asm);
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
        let api_key = setup_test_api_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let zpl_str = "permit tcp from groupA to groupB port 80";
        let policy_version: u64 = 42;
        let hit = Hit::new_no_signal(0, Direction::Forward);

        let v = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc, &hit, zpl_str, policy_version)
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.issuer_id))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let vd: VisaDescriptor = serde_json::from_slice(&body).unwrap();

        assert_eq!(vd.id, v.issuer_id);
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
        let api_key = setup_test_api_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Reverse);

        let v = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc, &hit, "", 0)
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.issuer_id))
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
        let api_key = setup_test_api_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let signal = Signal {
            message: "alert: suspicious traffic".to_string(),
            service: "svc1".to_string(),
        };
        let hit = Hit::new_with_signal(0, Direction::Forward, signal);

        let v = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc, &hit, "", 0)
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.issuer_id))
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
        let api_key = setup_test_api_key(&asm);
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
}
