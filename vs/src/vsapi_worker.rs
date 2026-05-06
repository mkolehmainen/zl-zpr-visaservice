use chrono::prelude::{DateTime, Utc};
use openssl::rand::rand_bytes;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::*;
use tracing::{debug, error, info, trace, warn};

use ::zpr::vsapi::v1 as vsapi;
use libeval::actor::Actor;
use libeval::attribute::{Attribute, key};
use zpr::vsapi_types::{
    ConnectRequest, Connection, PacketDesc, Param, ParamValue, SockAddr, VisaOp, pname,
};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::error::{ServiceError, TopologyError};
use crate::event_mgr::VsEvent;
use crate::logging::targets::API;
use crate::net_mgr;
use crate::visareq_worker::{VisaDecision, request_visa_wait_response};

// During node authentication we keep track in here of what state we have
// changed so that we can do an undo in case of an error in the sequence.
#[derive(Default)]
struct AuthenticateUndo {
    taken_zpr_addr: Option<IpAddr>,
    actor_mgr_add_node: Option<IpAddr>,
    added_node_to_router: Option<IpAddr>,
}

impl AuthenticateUndo {
    /// We checked out one of our ZPR addresses.
    fn took_zpr_addr(&mut self, addr: &IpAddr) {
        self.taken_zpr_addr = Some(addr.clone());
    }

    /// We added a node to state.
    fn added_node_to_actor_mgr(&mut self, addr: &IpAddr) {
        self.actor_mgr_add_node = Some(addr.clone());
    }

    /// We added a node to the router.
    fn added_node_to_router(&mut self, addr: &IpAddr) {
        self.added_node_to_router = Some(addr.clone());
    }

    async fn undo(self, asm: &Assembly) {
        if let Some(addr) = self.added_node_to_router {
            asm.router.remove_node(&addr);
        }
        if let Some(addr) = self.actor_mgr_add_node {
            let _ = asm.actor_mgr.remove_node(&addr).await;
            let _ = asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await;
        }
        if let Some(addr) = self.taken_zpr_addr {
            let _ = asm.net_mgr.release_zpr_addr(addr);
        }
    }
}

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listen: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(target: API, "VSAPI service listening on {} (capnp)", listen);
    let acceptor = tls_acceptor(listen)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;

    loop {
        // TODO: Figure out how to get tokio TLS in here.

        let (sock, addr) = listener.accept().await?;
        info!(target: API, "TCP connection from {}", addr);
        sock.set_nodelay(true)?;

        let tls = acceptor.accept(sock).await?;
        info!(target: API, "TLS connection");
        let (reader, writer) = tokio::io::split(tls);

        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        let vs_service: vsapi::visa_service::Client = capnp_rpc::new_client(VisaServiceImpl {
            asm: asm.clone(),
            remote: addr,
        });

        let rpc_system =
            capnp_rpc::RpcSystem::new(Box::new(network), Some(vs_service.clone().client));

        // TODO: spawn_local or spawn?
        tokio::task::spawn_local(async move {
            let err = rpc_system.await;
            err
        });
    }
}

pub async fn launch(asm: Arc<Assembly>, listen: SocketAddr) {
    match launch_capnp(asm.clone(), listen).await {
        Ok(()) => (),
        Err(e) => error!(target: API, "VSAPI capnp error: {}", e),
    };
}

// This function creates a certificate, and the clients will not require verification of the
// cert. In the future, we may actually want to share a cert between the VSAPI and VSS in VS/VSConn in Libnode2
fn tls_acceptor(listen: SocketAddr) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let self_signed_cert = rcgen::generate_simple_self_signed(vec![listen.to_string()])?;
    // Create self signed certificate that does not require client authentication
    let cert_der = self_signed_cert.cert.der();
    let key_der = self_signed_cert.signing_key.serialize_der();

    // Convert the cert into a format the
    let chain = vec![CertificateDer::from(cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;

    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

#[allow(dead_code)]
struct VisaServiceImpl {
    asm: Arc<Assembly>,
    remote: SocketAddr,
}

#[allow(dead_code)]
struct VSGateImpl {
    asm: Arc<Assembly>,
    remote: SocketAddr,
    remote_cn: String,
    req_zpr_addr: IpAddr,

    // This is set in `challenge` call and read in the `authenticate` call.
    // Safe to use here since the capn proto rpc is confined to a single thread.
    challenge_data: Cell<[u8; 32]>,

    // If node passes the "reconnect" flag.
    reconnect: bool,
}

#[allow(dead_code)]
struct VSHandleImpl {
    asm: Arc<Assembly>,
    node: Actor,
}

impl VSGateImpl {
    #[allow(dead_code)]
    fn new(
        asm: Arc<Assembly>,
        remote: SocketAddr,
        remote_cn: String,
        req_zpr_addr: IpAddr,
        reconnect: bool,
    ) -> Self {
        VSGateImpl {
            asm,
            remote,
            remote_cn,
            challenge_data: Cell::new([0u8; 32]),
            req_zpr_addr,
            reconnect,
        }
    }
}

impl VSHandleImpl {
    fn new(asm: Arc<Assembly>, node: Actor) -> Self {
        VSHandleImpl { asm, node }
    }

    /// Squash (but log) any errors.
    async fn update_last_seen_time(&self, node_addr: &IpAddr) {
        match self.asm.actor_mgr.update_node_last_seen(node_addr).await {
            Ok(_) => (),
            Err(e) => {
                warn!(target: API, "failed to update last-seen time for node at addr {}: {}", node_addr, e);
            }
        }
    }

    // Helper to process a visa request and either return an API error or a visa decision.
    async fn do_visa_request(
        &self,
        args: vsapi::v_s_handle::VisaRequestParams,
        timeout: Duration,
    ) -> Result<VisaDecision, (vsapi::ErrorCode, String)> {
        let Some(requestor_ip) = self.node.get_zpr_addr() else {
            warn!(target: API, "visa_request called by node {:?} with no ZPR address assigned", self.node.get_cn());
            return Err((
                vsapi::ErrorCode::InvalidOperation,
                "node has no ZPR address assigned".to_string(),
            ));
        };

        let vreq = match args.get() {
            Ok(a) => match a.get_req() {
                Ok(r) => r,
                Err(e) => {
                    error!(target: API, "error getting visa request: {}", e);
                    return Err((
                        vsapi::ErrorCode::Internal,
                        "internal error getting visa request".to_string(),
                    ));
                }
            },
            Err(e) => {
                error!(target: API, "error getting visa request args: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    "internal error getting visa request args".to_string(),
                ));
            }
        };

        let cp_pdesc = match vreq.get_packet() {
            Ok(p) => p,
            Err(e) => {
                error!(target: API, "error getting packet description: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    "internal error getting packet description".to_string(),
                ));
            }
        };

        let previous_id = {
            let pid = vreq.get_previous_id();
            if pid > 0 { Some(pid) } else { None }
        };
        if previous_id.is_some() {
            warn!(target: API, "visa_request: supplied previous_id is ignored (TODO)");
        }

        let pdesc: PacketDesc = match cp_pdesc.try_into() {
            Ok(pd) => pd,
            Err(e) => {
                error!(target: API, "error parsing packet description: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    format!("invalid packet description: {}", e),
                ));
            }
        };

        // Note that we assume that everything above this has taken no time.
        match request_visa_wait_response(&self.asm, requestor_ip, pdesc, timeout).await {
            Ok(vd) => Ok(vd),
            Err(e) => {
                error!(target: API, "error processing visa request: {}", e);
                Err((
                    vsapi::ErrorCode::Internal,
                    "visa request processing failed".to_string(),
                ))
            }
        }
    }
}

/// Helper to write an error into a capnp error builder with a retry of zero.
fn write_error(bldr: &mut vsapi::error::Builder, code: vsapi::ErrorCode, message: &str) {
    bldr.set_code(code);
    bldr.set_message(message);
    bldr.set_retry_in(0);
}

/// Convert a vsapi schema IpAddr into a rust ip address.
fn ipaddr_from_capnp(addr: vsapi::ip_addr::Reader) -> Result<std::net::IpAddr, capnp::Error> {
    match addr.which()? {
        vsapi::ip_addr::V4(ipv4) => {
            let octets = ipv4?;
            if octets.len() != 4 {
                return Err(capnp::Error::failed(
                    "invalid ipv4 address length".to_string(),
                ));
            }
            Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        vsapi::ip_addr::V6(ipv6) => {
            let octets = ipv6?;
            if octets.len() != 16 {
                return Err(capnp::Error::failed(
                    "invalid ipv6 address length".to_string(),
                ));
            }
            let mut octets_copy = [0u8; 16];
            octets_copy.copy_from_slice(&octets);
            Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets_copy)))
        }
    }
}

impl VisaServiceImpl {
    /// Helper for the connect routine -- returns the one connect param we require: zpr_addr.
    /// Older code used to pass in the AAA_PREFIX here but now we send that over the
    /// VSS.
    ///
    /// During this transition period we will error out if node passes use AAA_PREFIX.
    fn parse_my_connect_params(&self, params: &[Param]) -> Result<IpAddr, ServiceError> {
        let mut node_zpr_addr = None;

        for pp in params {
            match pp.name.as_str() {
                pname::ZPR_ADDR => match &pp.value {
                    ParamValue::IpParam(ipa) => node_zpr_addr = Some(ipa.clone()),
                    _ => {
                        return Err(ServiceError::Param(format!(
                            "param {} has invalid type",
                            pname::ZPR_ADDR
                        )));
                    }
                },

                pname::AAA_PREFIX => {
                    return Err(ServiceError::Param(format!(
                        "param {} must not be sent to VS",
                        pname::AAA_PREFIX
                    )));
                }

                name => info!(target: API, "ignored connect param {}", name),
            }
        }

        if node_zpr_addr.is_none() {
            return Err(ServiceError::Param("ZPR_ADDR param missing".into()));
        }
        Ok(node_zpr_addr.unwrap())
    }

    /// Helper to handle errors during connect call.
    /// Returns a Capn Proto OK, but an API level error.
    fn ok_with_connect_error(
        &self,
        mut results: vsapi::visa_service::ConnectResults,
        code: vsapi::ErrorCode,
        message: &str,
    ) -> Result<(), capnp::Error> {
        self.asm.counters.incr(CounterType::NodeConnectionsFailed);
        let res_builder = results.get().init_resp();
        let mut err_builder = res_builder.init_error();
        write_error(&mut err_builder, code, message);
        Ok(())
    }
}

impl vsapi::visa_service::Server for VisaServiceImpl {
    // Node connection request to the Visa Service.
    // Currently the node must pass its ZPR_ADDRESS and AAA_PREFIX as connect params.
    async fn connect(
        self: Rc<Self>,
        params: vsapi::visa_service::ConnectParams,
        mut results: vsapi::visa_service::ConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "connect call from {}", self.remote);

        let vs_connect_request = params.get()?.get_req()?;

        let req_cn = vs_connect_request.get_cn()?.to_string()?;
        let req_type = vs_connect_request.get_ctype()?;

        let parsed_params = match params_from_connect_request(&vs_connect_request, 4) {
            Ok(p) => p,
            Err(e) => {
                return self.ok_with_connect_error(
                    results,
                    vsapi::ErrorCode::ParamError,
                    &format!("failed to parse connect params: {}", e),
                );
            }
        };

        let node_zpr_addr = match self.parse_my_connect_params(&parsed_params) {
            Ok(addr) => addr,
            Err(e) => {
                return self.ok_with_connect_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    format!("{e}").as_str(),
                );
            }
        };

        info!(target: API, "node {} requests zpr addr {} (CONNECT_TYPE={:?})", req_cn, node_zpr_addr, req_type);

        match req_type {
            vsapi::VSConnT::Reset => {}
            vsapi::VSConnT::Reconnect => {
                // Node thinks it has state which means it may have connected adapters and a bunch of
                // visas already. If we don't know anything about this node we can deny this.

                let existing_actor = match self
                    .asm
                    .actor_mgr
                    .get_actor_by_zpr_addr(&node_zpr_addr)
                    .await
                {
                    Ok(Some(actor)) => actor,
                    Ok(None) => {
                        return self.ok_with_connect_error(
                            results,
                            vsapi::ErrorCode::OutOfSync,
                            "no state",
                        );
                    }
                    Err(e) => {
                        error!(target: API, "error checking existing state for reconnecting node {}: {}", node_zpr_addr, e);
                        return self.ok_with_connect_error(
                            results,
                            vsapi::ErrorCode::Internal,
                            "internal error during reconnect",
                        );
                    }
                };
                if !existing_actor.is_node() {
                    warn!(target: API, "reconnect attempt denied for {}: found {:?}", node_zpr_addr, existing_actor.get_cn());
                    return self.ok_with_connect_error(
                        results,
                        vsapi::ErrorCode::InvalidOperation,
                        "address in use",
                    );
                }
            }
        }

        let mut res_builder = results.get().init_resp();

        let vs_gate: vsapi::v_s_gate::Client = capnp_rpc::new_client(VSGateImpl::new(
            self.asm.clone(),
            self.remote,
            req_cn,
            node_zpr_addr,
            req_type == vsapi::VSConnT::Reconnect,
        ));

        res_builder.set_ok(vs_gate)?;

        Ok(())
    }
}

impl VSGateImpl {
    /// Helper to handle errors during authenticate call.
    /// Returns a Capn Proto OK, but an API level error.
    fn ok_with_authenticate_error(
        &self,
        mut results: vsapi::v_s_gate::AuthenticateResults,
        code: vsapi::ErrorCode,
        message: &str,
    ) -> Result<(), capnp::Error> {
        self.asm.counters.incr(CounterType::NodeConnectionsFailed);
        let res_builder = results.get().init_res();
        let mut err_builder = res_builder.init_error();
        write_error(&mut err_builder, code, message);
        Ok(())
    }
}

impl vsapi::v_s_gate::Server for VSGateImpl {
    async fn challenge(
        self: Rc<Self>,
        _params: vsapi::v_s_gate::ChallengeParams,
        mut results: vsapi::v_s_gate::ChallengeResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "challenge call from {} as {}", self.remote, self.remote_cn);
        let mut res_builder = results.get().init_challenge();
        res_builder.set_alg(vsapi::ChallengeAlg::RsaSha256Pkcs1v15);
        let mut challenge_data = [0u8; 32];
        rand_bytes(&mut challenge_data).unwrap();
        res_builder.set_bytes(&challenge_data);
        self.challenge_data.set(challenge_data);
        Ok(())
    }

    /// Authenticate VSAPI call is also the "authorize_connect" call for a node.
    async fn authenticate(
        self: Rc<Self>,
        params: vsapi::v_s_gate::AuthenticateParams,
        mut results: vsapi::v_s_gate::AuthenticateResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "authenticate from {} as {}", self.remote, self.remote_cn);
        let cresp = params.get()?.get_cresp()?; // has challenge (bytes), timestamp (uint64), bytes (bytes)

        let challenge_presented = cresp.get_challenge()?;

        // We must have sent challenge data ... meaning it cannot all be zeros.
        if challenge_presented.iter().all(|&b| b == 0) {
            warn!(target: API, "all zeros challenge presented from {}, authenticate fails", self.remote_cn);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                "invalid challenge",
            );
        }

        // Must match the challenge we sent.
        if challenge_presented != &self.challenge_data.get() {
            warn!(target: API, "invalid challenge from {}, authenticate fails", self.remote_cn);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                "challenge mismatch",
            );
        }

        // Challenge is one time use - so we set our memory of it to zeros.
        self.challenge_data.set([0u8; 32]);

        // Time must be within acceptable range.
        let unix_ts = cresp.get_timestamp();
        let now = SystemTime::now();
        let my_unix_ts = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        if my_unix_ts.abs_diff(unix_ts) > config::MAX_CLOCK_SKEW_SECS {
            warn!(target: API, "excess clock skew from {}, authenticate fails", self.remote_cn);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::Internal,
                "excess clock skew",
            );
        }

        let challenge_response = cresp.get_bytes()?;

        // Perform the authentication
        //
        let mut node_actor = match self
            .asm
            .cc
            .authenticate_node(
                self.asm.clone(),
                challenge_presented,
                unix_ts,
                &self.remote_cn,
                challenge_response,
                self.remote,
                self.req_zpr_addr,
            )
            .await
        {
            Ok(node_id) => node_id,
            Err(ServiceError::AuthenticationFailed(reason)) => {
                warn!(target: API, "authentication failed for {}: {}", self.remote_cn, reason);
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::AuthError,
                    format!("authentication failed: {reason}").as_str(),
                );
            }
            Err(e) => {
                error!(target: API, "internal error during authentication for {}: {}", self.remote_cn, e);
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    "internal error during authentication",
                );
            }
        };

        // At this point we may have taken an IP addr and assigned it to the actor.
        let mut undo = AuthenticateUndo::default();

        // Sanity check - every node has a CN and a ZPR address.
        // If this fails it means our authentication code is broken.
        let node_zpr_addr = match node_actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                error!(target: API, "auth subsystem failed to set a ZPR address on an authenticated node");
                undo.undo(&self.asm).await;
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    "assertion failed (ADDR)",
                );
            }
        };
        if self.asm.net_mgr.is_managed_address(&node_zpr_addr) {
            undo.took_zpr_addr(&node_zpr_addr);
        }

        let node_cn = match node_actor.get_cn() {
            Some(cn) => cn.to_owned(),
            None => {
                error!(target: API, "auth subsystem failed to set a CN on an authenticated node");
                undo.undo(&self.asm).await;
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    "assertion failed (CN)",
                );
            }
        };

        let node_aaa_net = net_mgr::aaa_network_for_node(&node_zpr_addr);

        info!(
            target: API,
            "successfully authenticated node {node_cn} from {:?} and assigned ip {node_zpr_addr} and AAA net {node_aaa_net}",
            self.remote,
        );

        // Ok, we have verified the credentials and checked with policy. Time to
        // update our state and return success.

        node_actor
            .add_attribute(Attribute::builder(key::AAA_NET).value(node_aaa_net.to_string()))
            .unwrap();

        // TODO: The policy may have changed since started the authentication. Once we add the node
        // it is part of the ZPRnet.  The add_node should check the visa vinst used to grant access
        // and we should make sure we do not allow add_node and update_policy to run concurrently.
        // If add_node runs first, then update policy can catch the issue.  If update_policy runs
        // first, then add_node will see the new version and should not allow the node to be added.

        // Note that the node may have services on it in addition to its node-ness.

        if !self.reconnect {
            if let Err(e) = self.asm.visa_mgr.clear_node_state(&node_zpr_addr).await {
                error!(target: API, "failed to clear node state for {:?}: {}", &node_cn, e);
                undo.undo(&self.asm).await;
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    "failed to clear node state",
                );
            }
            self.asm.router.remove_node(&node_zpr_addr);
        }

        // The add_node call will clean up after ifself if it fails.
        if let Err(e) = self
            .asm
            .actor_mgr
            .add_node(&node_actor, self.reconnect)
            .await
        {
            error!(target: API, "failed to add authenticated node {:?} to actor db: {}", &node_cn, e);
            undo.undo(&self.asm).await;
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::Internal,
                "state update failed",
            );
        }
        undo.added_node_to_actor_mgr(&node_zpr_addr);

        // TODO: This is a hack: the visa service "actor" needs to know what node it's adapter is docked to.
        //       Ideally we would query our adapter directly.
        {
            if let Ok(maybe_visa_service_actor) =
                self.asm.actor_mgr.get_actor_by_cn(config::VS_CN).await
            {
                if let Some(visa_service_actor) = maybe_visa_service_actor {
                    if self
                        .asm
                        .actor_mgr
                        .get_docking_node_for_actor(&visa_service_actor)
                        .is_none()
                    {
                        // VS does not yet have a docking address.  ASSUME this node is our dock.
                        // This does not update the 'connect_via' attribute on the vs actor. (TODO - rethink that)

                        if let Err(e) = self
                            .asm
                            .actor_mgr
                            .hack_set_vs_docking_node(&node_zpr_addr)
                            .await
                        {
                            error!(target: API, "failed to set VS docking node to {:?}: {}", &node_cn, e);
                            undo.undo(&self.asm).await;
                            return self.ok_with_authenticate_error(
                                results,
                                vsapi::ErrorCode::Internal,
                                "vs docking node update failed",
                            );
                        }
                        // No need to update the `undo` here since undoing the node-add will also remove the vs docking mapping.
                    }
                }
            }
        }

        // Add the node to the router.
        match self.asm.router.add_node(&node_zpr_addr) {
            Ok(()) => (),
            Err(TopologyError::NodeExists(_)) => {
                // Attempt to remove and re-add.
                warn!(target: API, "node {:?} already exists in router, attempting to remove and re-add", &node_cn);
                self.asm.router.remove_node(&node_zpr_addr);
                if let Err(e) = self.asm.router.add_node(&node_zpr_addr) {
                    // Failed to add the node to the router. We won't be able to route visas through this node.
                    // Best to just abort this connect.
                    error!(target: API, "router: failed to add node {} to router after removing existing: {}", node_zpr_addr, e);
                    undo.undo(&self.asm).await;
                    return self.ok_with_authenticate_error(
                        results,
                        vsapi::ErrorCode::Internal,
                        "router update failed",
                    );
                }
            }
            Err(e) => {
                unreachable!("unexpected error adding node to router: {}", e);
            }
        }

        undo.added_node_to_router(&node_zpr_addr);

        let evt = VsEvent::ActorJoins(node_zpr_addr);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            error!(target: API, "failed to record actor joins event for node {:?}: {}", &node_cn, e);
            undo.undo(&self.asm).await;
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::Internal,
                "event enqueue failed",
            );
        }
        self.asm.counters.incr(CounterType::NodeConnectionsSuccess);

        let vs_handle: vsapi::v_s_handle::Client =
            capnp_rpc::new_client(VSHandleImpl::new(self.asm.clone(), node_actor));
        let mut res_builder = results.get().init_res();
        res_builder.set_ok(vs_handle)?;

        Ok(())
    }
}

impl vsapi::v_s_handle::Server for VSHandleImpl {
    /// Node should call this after it has authenticated itself and it has installed its
    /// ZPR address into its tables.
    ///
    /// The VS must generate a visa for VISA->VSS communications and hand it back to
    /// the node with this call.  Any pending visas for the node are handed back with this.
    ///
    async fn register_vss(
        self: Rc<Self>,
        params: vsapi::v_s_handle::RegisterVssParams,
        mut res: vsapi::v_s_handle::RegisterVssResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "register_vss from {:?}", self.node.get_cn());
        let saddr_rdr = params.get()?.get_addr()?;

        let node_zpr_addr = self.node.get_zpr_addr().unwrap();
        self.update_last_seen_time(node_zpr_addr).await;

        let vss_sockaddr: SockAddr = match SockAddr::try_from(saddr_rdr) {
            Ok(addr) => addr,
            Err(e) => {
                error!(target: API, "failed to convert addr arg to SockAddr: {}", e);
                let res_builder = res.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::ParamError,
                    "invalid sockaddr",
                );
                return Ok(());
            }
        };

        // The socket addr address must match node address I think.
        if vss_sockaddr.addr != *node_zpr_addr {
            error!(target: API, "VSS socket address '{}' does not match node address '{}' for {:?}", vss_sockaddr.addr, node_zpr_addr, self.node.get_cn());
            let res_builder = res.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::ParamError,
                "VSS socket address does not match node address",
            );
            return Ok(());
        }

        let saddr: SocketAddr = vss_sockaddr.into();
        let amgr_asm = self.asm.clone();

        let initial_visas = match self
            .asm
            .visa_mgr
            .initial_visas_for_node(amgr_asm, node_zpr_addr, &saddr)
            .await
        {
            Ok(visas) => visas,
            Err(e) => {
                error!(target: API, "failed to initialize node VSS for {:?}: {}", self.node.get_cn(), e);
                let res_builder = res.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "failed to initialize node VSS",
                );
                return Ok(());
            }
        };

        let res_builder = res.get().init_res();
        let mut ok_builder = res_builder.initn_ok(initial_visas.len() as u32);

        for (i, visa) in initial_visas.iter().enumerate() {
            let mut vop_builder = ok_builder.reborrow().get(i as u32);

            let vop = VisaOp::Grant(visa.clone());
            vop.write_to(&mut vop_builder);
        }

        // Now assume that our reply will make it to the node and mark the visas as installed.
        //
        // The node must assume that if it gets an error trying to call register_vss that
        // there may be visas it is missing.  Since we don't have a way for the node to
        // ask for its "installed" visas, for now node should call register_vss again.
        //
        // TODO: Improve vsapi by adding a way for node to request its installed visas.
        // https://github.com/org-zpr/zpr-visaservice/issues/108

        for visa in &initial_visas {
            if let Err(e) = self
                .asm
                .visa_mgr
                .visa_installed(visa.issuer_id, node_zpr_addr)
                .await
            {
                warn!(target: API, "failed to mark visa {} as installed on {:?}: {}", visa.issuer_id, self.node.get_cn(), e);
            }
        }

        // Finally, update DB with node vss
        self.asm
            .actor_mgr
            .set_node_vss(&self.node.get_zpr_addr().unwrap(), &saddr)
            .await
            .unwrap_or_else(|e| {
                error!(target: API, "failed to set VSS for node {:?}: {}", self.node.get_cn(), e);
            });

        // As we return we kick off the vss worker for this node which will send config and list of services.
        // but will not work until visas are installed... So start it with small delay.
        if let Err(e) = self.asm.vss_mgr.start_vss_worker(
            self.asm.clone(),
            &self.node.get_zpr_addr().unwrap(),
            &saddr,
            config::VSS_START_DELAY,
        ) {
            warn!(target: API, "failed to start VSS worker for node {:?}: {}", self.node.get_cn(), e);
            // TODO: handle the duplicate error here - if worker already running we are ok, I think.
        }

        Ok(())
    }

    // When an adapter connects to a node, a node ends up making a call here to authorize
    // the connection.  If successful the VS returns a ZPR address for the adapter, and an
    // expiration time.
    //
    // The ConnectRequest arg is populated as follows:
    //       blobs: list of 1 (for now) 'AuthBlob'
    //       claims: may include 'zpr.addr' if a specific address is requested, must include 'zpr.adapter.cn' to match blob cn.
    //       substrateAddr: adapter substrate address
    //       dockinterface: 0
    //
    // There are just two ways that an adapter can authenticated and that is reflected in
    // the AuthBlob presented.
    //
    // (1) Adapter uses an RSA key that is shared with policy -- looked up by the adapter CN.
    //
    //     Note that the node has already verified that the CN in the blob matches the CN
    //     presented over the link by the adapter.
    //
    //     The AuthBlob is a ZPRSelfSignedBlob
    //       {
    //         alg: ChallengeAlg::RsaSha256Pkcs1v15
    //         challenge: <bytes> - The nodes challend to the adapter. Just opaque bytes to to the visa service.
    //         cn: adapter CN value
    //         timestamp: unix timestamp, seconds
    //         signature: RSA SHA256 PKCS1v15 signature using adapter private key over (ts + cn + challenge)
    //                    time is big-endian u64.
    //       }
    //
    //     To verify the blob, the visa service looks up the public key in policy by CN,
    //     and then verifies the signature.
    //
    //
    // (2) It can present a token from an authentication server.
    //
    //     The AuthBlob is a AuthCodeBlob
    //       {
    //         asaAddr: IpAddr of the auth service
    //         code: <string>
    //         pkce: <string>
    //         clientId: <string>
    //       }
    //
    //     All this is used in the oauth flow between visa service and the auth server to verify
    //     the adapter identity.
    //
    async fn authorize_connect(
        self: Rc<Self>,
        params: vsapi::v_s_handle::AuthorizeConnectParams,
        mut results: vsapi::v_s_handle::AuthorizeConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "authorize_connect from {:?}", self.node.get_cn());

        let cr_rdr = params.get()?.get_req()?;
        let creq = ConnectRequest::try_from(cr_rdr).map_err(|e| {
            capnp::Error::failed(format!("failed to parse ConnectionRequest: {}", e))
        })?;

        let connect_via = self.node.get_zpr_addr().unwrap();
        self.update_last_seen_time(connect_via).await;

        let actor = match self
            .asm
            .cc
            .authenticate_adapter(self.asm.clone(), creq, connect_via)
            .await
        {
            Ok(actor) => actor,
            Err(e) => {
                warn!(target: API, "adapter connection authorization failed for node {:?}: {}", connect_via, e);
                let mut err_builder = results.get().init_resp().init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::AuthError,
                    format!("adapter authorization failed: {}", e).as_str(),
                );
                return Ok(());
            }
        };

        let actor_addr = actor.get_zpr_addr().unwrap().clone(); // MUST have an addr by now.

        // Have an actor. Will have a ZPR address at this point.
        if let Err(e) = self
            .asm
            .actor_mgr
            .add_adapter_via_node(&actor, &connect_via)
            .await
        {
            error!(target: API, "failed to add authenticated adapter {:?} to actor db: {}", actor.get_cn(), e);

            if self.asm.net_mgr.is_managed_address(&actor_addr) {
                if let Err(e) = self.asm.net_mgr.release_zpr_addr(actor_addr) {
                    warn!(target: API, "failed to release adapter address {}: {}", actor_addr, e);
                }
            }

            let mut err_builder = results.get().init_resp().init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::Internal,
                "state update failed",
            );
            return Ok(());
        }

        let addr_attr = actor.get_attribute(key::ZPR_ADDR).unwrap();
        {
            let expires_utc: DateTime<Utc> = addr_attr.get_expires().into();
            info!(
                target: API,
                "successfully authorized adapter {:?} with address {} (expires {})",
                actor.get_cn(),
                actor_addr,
                expires_utc.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            );
        }
        let zpr_con = Connection::new(actor_addr, addr_attr.get_expires());
        let mut resp_builder = results.get().init_resp().init_ok();
        zpr_con.write_to(&mut resp_builder);

        let evt = VsEvent::ActorJoins(actor_addr);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            warn!(target: API, "failed to record actor joins event for adapter {:?}: {}", actor.get_cn(), e);
        }

        Ok(())
    }

    async fn reauthorize(
        self: Rc<Self>,
        _: vsapi::v_s_handle::ReauthorizeParams,
        _: vsapi::v_s_handle::ReauthorizeResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "reauthorize from {:?}", self.node.get_cn());
        Err(capnp::Error::unimplemented(
            "method v_s_handle::Server::reauthorize not implemented".to_string(),
        ))
    }

    async fn notify_disconnect(
        self: Rc<Self>,
        req: vsapi::v_s_handle::NotifyDisconnectParams,
        mut resp: vsapi::v_s_handle::NotifyDisconnectResults,
    ) -> Result<(), capnp::Error> {
        let dnotice = req.get()?.get_req()?;

        // If no ZPR address is specified that means that the node itself is disconnecting.
        let maybe_zpr_addr = if dnotice.has_zpr_addr() {
            let zpr_ipaddr = dnotice.get_zpr_addr()?;
            Some(ipaddr_from_capnp(zpr_ipaddr)?)
        } else {
            // populate with the actor ZPR addr.
            self.node.get_zpr_addr().cloned()
        };

        // I believe we need a ZPR address here otherwise this is just a NOP.
        if maybe_zpr_addr.is_none() {
            warn!(target: API, "notify_disconnect but no zpr address passed or derivable from actor {:?}", self.node.get_cn());
            let res_builder = resp.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::InvalidOperation,
                "disconnect requires zpr address",
            );
            return Ok(());
        }
        let zpr_addr = maybe_zpr_addr.unwrap();

        let reason = dnotice.get_reason_code()?;
        debug!(
            target: API,
            "disconnect call from node {:?} for {} with reason {:?}",
            self.node.get_cn(), zpr_addr, reason
        );

        // The disconnect call updates our state database.
        match self
            .asm
            .cc
            .disconnect(self.asm.clone(), zpr_addr, reason)
            .await
        {
            Ok(()) => (),
            Err(e) => {
                warn!(target: API, "error processing disconnect of {}: {}", zpr_addr, e);
                let res_builder = resp.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "internal error during disconnect",
                );
                return Ok(());
            }
        }
        let evt = VsEvent::ActorLeaves(zpr_addr, reason);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            warn!(target: API, "failed to record actor leaves event for {}: {}", zpr_addr, e);
        }
        let mut res_builder = resp.get().init_res();
        res_builder.set_ok(());
        Ok(())
    }

    async fn visa_request(
        self: Rc<Self>,
        args: vsapi::v_s_handle::VisaRequestParams,
        mut response: vsapi::v_s_handle::VisaRequestResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "visa_request from {:?}", self.node.get_cn());

        self.asm.counters.incr(CounterType::VsApiVisaRequests);

        // A node must have an address.
        let requestor_addr = self
            .node
            .get_zpr_addr()
            .expect("programming error - node must have an address");
        self.update_last_seen_time(requestor_addr).await;

        match self
            .do_visa_request(args, config::DEFAULT_VISA_REQ_TIMEOUT)
            .await
        {
            Ok(decision) => match decision {
                VisaDecision::Allow(visa, _route) => {
                    // TODO: Do something with the route
                    let res_builder = response.get().init_resp();
                    let mut visa_bldr = res_builder.init_allow();
                    visa.write_to(&mut visa_bldr);

                    // Set visa as installed in our state
                    if let Err(e) = self
                        .asm
                        .visa_mgr
                        .visa_installed(visa.issuer_id, requestor_addr)
                        .await
                    {
                        error!(target: API, "failed to update visa {} as installed on {}: {}", visa.issuer_id, requestor_addr, e);
                    }
                }
                VisaDecision::Deny(denial_reason) => {
                    let mut res_builder = response.get().init_resp();
                    res_builder.set_deny(denial_reason.into());
                }
            },

            Err((code, msg)) => {
                error!(target: API, "internal error ({code:?})processing visa_request: {msg}");
                let res_builder = response.get().init_resp();
                let mut err_builder = res_builder.init_error();
                write_error(&mut err_builder, code, &msg);
            }
        }
        return Ok(());
    }

    async fn ping(
        self: Rc<Self>,
        _req: vsapi::v_s_handle::PingParams,
        mut results: vsapi::v_s_handle::PingResults,
    ) -> Result<(), capnp::Error> {
        let node_cn = self.node.get_cn().unwrap_or("<unknown>");
        trace!(target: API, "ping from {node_cn}");
        if let Some(addr) = self.node.get_zpr_addr() {
            self.update_last_seen_time(addr).await;
        }
        self.asm.counters.incr(CounterType::VsApiPings);

        if let Some(node_addr) = self.node.get_zpr_addr() {
            if let Some(vssaddr) = self
                .asm
                .actor_mgr
                .get_node_vss(&node_addr)
                .await
                .unwrap_or(None)
            {
                match self.asm.vss_mgr.start_vss_worker_if_none(
                    self.asm.clone(),
                    &node_addr,
                    &vssaddr,
                    Duration::from_secs(0),
                ) {
                    Ok(true) => {
                        info!(
                            "found no VSS worker running for node {node_cn} @ {node_addr} - started one"
                        );
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(target: API, "failed to start VSS worker for node {node_cn}: {}", e);
                    }
                }
            }
        }

        let mut res_builder = results.get().init_res();
        res_builder.set_ok(());
        Ok(())
    }
}

/// Parse no more than `limit` params out of the connect request.
pub fn params_from_connect_request(
    vscr: &vsapi::v_s_connect_request::Reader,
    limit: usize,
) -> Result<Vec<Param>, ServiceError> {
    let mut results = Vec::new();
    let params = vscr.get_params()?;
    for param_rdr in params.iter() {
        let param: Param = param_rdr.try_into()?;
        results.push(param);
        if results.len() >= limit {
            break;
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use capnp::message::Builder;

    /// Helper function to create a v_s_connect_request message with the given params
    fn build_connect_request(
        build_fn: impl FnOnce(vsapi::v_s_connect_request::Builder),
    ) -> capnp::message::Reader<capnp::serialize::OwnedSegments> {
        let mut message = Builder::new_default();
        {
            let req = message.init_root::<vsapi::v_s_connect_request::Builder>();
            build_fn(req);
        }
        // Serialize and deserialize to get a Reader
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, &message).unwrap();
        let reader =
            capnp::serialize::read_message(&mut &buf[..], capnp::message::ReaderOptions::new())
                .unwrap();
        reader
    }

    #[test]
    fn test_from_connect_request_empty() {
        let message = build_connect_request(|req| {
            req.init_params(0);
        });

        let reader = message.get_root().unwrap();
        let result = params_from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_from_connect_request_single_string() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("test_name");
            param.set_ptype(vsapi::ParamT::String);
            param.set_value_text("test_value");
        });

        let reader = message.get_root().unwrap();
        let result = params_from_connect_request(&reader, 10).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "test_name");
        match &result[0].value {
            ParamValue::StrParam(s) => assert_eq!(s, "test_value"),
            _ => panic!("Expected String value"),
        }
    }

    #[test]
    fn test_from_connect_request_limit() {
        let message = build_connect_request(|req| {
            let mut params = req.init_params(5);
            for i in 0..5 {
                let mut param = params.reborrow().get(i);
                param.set_name(&format!("param{}", i));
                param.set_ptype(vsapi::ParamT::U64);
                param.set_value_u64(i as u64);
            }
        });

        let reader = message.get_root().unwrap();
        let result = params_from_connect_request(&reader, 3).unwrap();

        // Should only return 3 params due to limit
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].name, "param0");
        assert_eq!(result[1].name, "param1");
        assert_eq!(result[2].name, "param2");
    }

    mod authenticate_undo {
        use super::*;
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::test_helpers::make_node_actor_defexp;
        use libeval::actor::Role;
        use std::sync::Arc;

        #[tokio::test]
        async fn test_noop() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let undo = AuthenticateUndo::default();
            undo.undo(&asm).await; // must not panic
        }

        #[tokio::test]
        async fn test_releases_zpr_addr() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr = asm.net_mgr.get_next_zpr_addr(&Role::Node).unwrap();

            let mut undo = AuthenticateUndo::default();
            undo.took_zpr_addr(&addr);
            undo.undo(&asm).await;

            // Address was released back to the pool, so take_zpr_addr should succeed.
            assert!(
                asm.net_mgr.take_zpr_addr(&addr).is_ok(),
                "address should have been released by undo"
            );
        }

        #[tokio::test]
        async fn test_removes_node_from_router() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();

            asm.router.add_node(&addr).unwrap();

            let mut undo = AuthenticateUndo::default();
            undo.added_node_to_router(&addr);
            undo.undo(&asm).await;

            // Node was removed, so add_node must succeed again.
            assert!(
                asm.router.add_node(&addr).is_ok(),
                "node should have been removed from router by undo"
            );
        }

        #[tokio::test]
        async fn test_removes_node_from_actor_mgr() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
            let actor =
                make_node_actor_defexp("fd5a:5052:90de:1::2", "test-node", "[fd5a:5052::100]:1234");

            asm.actor_mgr.add_node(&actor, false).await.unwrap();

            let mut undo = AuthenticateUndo::default();
            undo.added_node_to_actor_mgr(&addr);
            undo.undo(&asm).await;

            let result = asm.actor_mgr.get_actor_by_zpr_addr(&addr).await.unwrap();
            assert!(
                result.is_none(),
                "node should have been removed from actor_mgr by undo"
            );
        }

        #[tokio::test]
        async fn test_all_three_undone() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr = asm.net_mgr.get_next_zpr_addr(&Role::Node).unwrap();
            let actor =
                make_node_actor_defexp(&addr.to_string(), "test-node-2", "[fd5a:5052::101]:1234");

            asm.actor_mgr.add_node(&actor, false).await.unwrap();
            asm.router.add_node(&addr).unwrap();

            let mut undo = AuthenticateUndo::default();
            undo.took_zpr_addr(&addr);
            undo.added_node_to_actor_mgr(&addr);
            undo.added_node_to_router(&addr);
            undo.undo(&asm).await;

            assert!(
                asm.router.add_node(&addr).is_ok(),
                "node should have been removed from router"
            );
            asm.router.remove_node(&addr);

            let actor_result = asm.actor_mgr.get_actor_by_zpr_addr(&addr).await.unwrap();
            assert!(
                actor_result.is_none(),
                "node should have been removed from actor_mgr"
            );

            assert!(
                asm.net_mgr.take_zpr_addr(&addr).is_ok(),
                "zpr address should have been released"
            );
        }
    }
}
