use dashmap::DashMap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use tokio_rustls::TlsConnector;
use tokio_util::compat::*;
use tracing::{debug, error, info, trace, warn};

use zpr::vsapi::v1;
use zpr::vsapi_types::{ApiResponseError, Param, ServiceDescriptor, Visa, pname};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::error::VssSyncError;
use crate::logging::targets::VSS;
use crate::net_mgr;

/// Minimum (and initial) timeout for a ping RPC call.
const PING_MIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Default timeout for a single Cap'n Proto RPC call.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

pub struct VssMgr {
    // Each node has an entry here, handle is a thread monitoring the nodes VSS.
    workers: DashMap<IpAddr, VssHandle>,

    // Only used to spin up VSS handlers.
    jobs_tx: mpsc::Sender<Job>,
}

#[derive(Clone)]
pub struct VssHandle {
    // For sending requests to a VSS handler thread (all the API calls)
    cmd_tx: mpsc::Sender<VssCmd>,
}

enum Job {
    // Params for starting a VssHandle thread.
    StartVssWorker {
        asm: Arc<Assembly>,
        node_addr: IpAddr,
        vss_addr: SocketAddr,
        delay: std::time::Duration,
        cmd_rx: mpsc::Receiver<VssCmd>,
    },
}

type VssPushResponse = Result<usize, VssSyncError>; // usize is number items pushed.
type VssRevokeAuthResponse = Result<usize, VssSyncError>; // usize is number of items revoked.
type VssSetServicesResponse = Result<(), VssSyncError>;
type VssConfigureResponse = Result<(), VssSyncError>;

// Each API call is expressed as a message using this enum.
#[allow(dead_code)]
enum VssCmd {
    Stop(),
    PushVisas(Vec<Visa>, oneshot::Sender<VssPushResponse>),
    RevokeVisasById(Vec<u64>, oneshot::Sender<VssPushResponse>),
    RevokeAuthsByZprAddr(Vec<IpAddr>, oneshot::Sender<VssRevokeAuthResponse>),
    SetServices(
        Vec<ServiceDescriptor>,
        oneshot::Sender<VssSetServicesResponse>,
    ), // (version, services-descriptor-list, channel)
    Configure(Vec<Param>, oneshot::Sender<VssConfigureResponse>),
}

/// The Vss Manager manages VSS connections for each node.
impl VssMgr {
    pub fn new() -> Self {
        let (jobs_tx, mut jobs_rx) = mpsc::channel(16);

        let rt = Builder::new_current_thread().enable_all().build().unwrap();

        std::thread::spawn(move || {
            let local = LocalSet::new();
            local.spawn_local(async move {
                while let Some(job) = jobs_rx.recv().await {
                    tokio::task::spawn_local(run_vss_job(job));
                }
            });
            rt.block_on(local);
        });

        VssMgr {
            workers: DashMap::new(),
            jobs_tx,
        }
    }

    /// Start a task to manage the VSS connection to a node.  Waits for `delay` before starting.
    /// Once this starts, the first thing it does is send the services list across.
    /// It them will periodically ping the vss API.
    ///
    /// Error is returned if a worker is already running for the node. If that happens caller
    /// should use [VssMgr::get_handle] to obtain the existing handle and then call [VssHandle::stop].
    /// Note that it takes time for handle to respond to stop and clear out state in this manager.
    pub fn start_vss_worker(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
        delay: std::time::Duration,
    ) -> Result<(), VssSyncError> {
        // Return error if we already have a worker for this node.
        if self.workers.contains_key(node_addr) {
            return Err(VssSyncError::DuplicateWorker(*vss_addr));
        }

        let (cmd_tx, cmd_rx) = mpsc::channel::<VssCmd>(16);

        let job = Job::StartVssWorker {
            asm,
            node_addr: node_addr.clone(),
            vss_addr: *vss_addr,
            delay,
            cmd_rx,
        };
        let send_result = self.jobs_tx.try_send(job);
        if let Err(e) = send_result {
            return Err(VssSyncError::QueueFull(format!(
                "failed to queue VSS worker start job for {}: {}",
                vss_addr, e
            )));
        }
        let worker = VssHandle { cmd_tx };
        self.workers.insert(node_addr.clone(), worker);
        Ok(())
    }

    /// Start a VSS worker only if none is already running for this node.
    /// Uses DashMap entry to make this thread safe.
    ///
    /// Returns `true` if a new worker was started, `false` if one was already running.
    pub fn start_vss_worker_if_none(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
        delay: std::time::Duration,
    ) -> Result<bool, VssSyncError> {
        // entry() holds the DashMap shard lock for the duration of the match, making the
        // check-and-insert atomic and preventing concurrent callers from both starting a worker.
        match self.workers.entry(*node_addr) {
            dashmap::Entry::Occupied(_) => Ok(false),
            dashmap::Entry::Vacant(slot) => {
                let (cmd_tx, cmd_rx) = mpsc::channel::<VssCmd>(16);
                let job = Job::StartVssWorker {
                    asm,
                    node_addr: *node_addr,
                    vss_addr: *vss_addr,
                    delay,
                    cmd_rx,
                };
                self.jobs_tx.try_send(job).map_err(|e| {
                    VssSyncError::QueueFull(format!(
                        "failed to queue VSS worker start job for {}: {}",
                        vss_addr, e
                    ))
                })?;
                slot.insert(VssHandle { cmd_tx });
                Ok(true)
            }
        }
    }

    /// Obtain a handle to the VSS worker for the given node. Using the handle you can
    /// send VSS API messages.
    pub fn get_handle(&self, naddr: &IpAddr) -> Option<VssHandle> {
        self.workers.get(naddr).map(|h| h.clone())
    }

    /// Housekeeping function to remove (presumably stale/not-running) worker.
    /// Called when the worker run loop exists.
    ///
    /// TODO: May need a way to alert the system when the VSS worker stops unexpectedly.
    fn clear_handle(&self, naddr: &IpAddr) {
        self.workers.remove(naddr);
    }
}

/// Each VSS thread has a handle to it stored in the [VssMgr] `workers` map.
impl VssHandle {
    async fn send_command(&self, cmd: VssCmd) -> Result<(), VssSyncError> {
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| VssSyncError::ConnClosed)
    }

    /// Stop the worker.
    pub async fn stop(&self) -> Result<(), VssSyncError> {
        let cmd = VssCmd::Stop();
        self.send_command(cmd).await
    }

    /// Send visas to the node.
    #[allow(dead_code)]
    pub async fn push_visas(&self, visas: Vec<Visa>) -> Result<usize, VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::PushVisas(visas, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Revoke visas installed on the node by their IDs.
    #[allow(dead_code)]
    pub async fn revoke_visas(&self, ids: Vec<u64>) -> Result<usize, VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::RevokeVisasById(ids, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Revoke authorizations present on the node for the given zpr addresses.
    #[allow(dead_code)]
    pub async fn revoke_auths(&self, addrs: Vec<IpAddr>) -> Result<usize, VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Tell the node about authentication services connected to the ZPRnet.
    #[allow(dead_code)]
    pub async fn set_services(&self, services: Vec<ServiceDescriptor>) -> Result<(), VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::SetServices(services, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }
}

// This rather convoluted pattern for starting a vss worker is here because the capn proto
// rpc system must run in a tokio local task.
//
// See https://docs.rs/tokio/latest/tokio/task/struct.LocalSet.html#use-inside-tokiospawn
//
// There is only ever one "job" implementation -- the job that starts a VSS worker.
//
// This is called in a new thread.
async fn run_vss_job(job: Job) {
    match job {
        Job::StartVssWorker {
            asm,
            node_addr,
            vss_addr,
            delay,
            cmd_rx,
        } => {
            debug!(target: VSS, "starting VSS worker for node {} at {}", node_addr, vss_addr);
            tokio::time::sleep(delay).await;
            vss_worker_loop(asm.clone(), vss_addr, cmd_rx).await;
            // When we exit the worker loop, we are done but the handle is still sitting in
            // the manager. So we clean it out here:
            asm.vss_mgr.clear_handle(&node_addr);
            info!(target: VSS, "VSS worker for node {} has exited", node_addr);
            // TODO: Do we need to track somewhere that we are no longer in communication with this node?
        }
    }
}

// Run-loop for a thread that manages a VSS connection to a node.
async fn vss_worker_loop(
    asm: Arc<Assembly>,
    node_addr: SocketAddr,
    mut cmd_rx: mpsc::Receiver<VssCmd>,
) {
    // Open connect to VSS.
    info!(target: VSS, "connecting to VSS at {}", node_addr);

    let sock = match tokio::net::TcpStream::connect(node_addr).await {
        Ok(sock) => sock,
        Err(e) => {
            error!(target: VSS, "failed to connect to VSS at {}: {}", node_addr, e);
            asm.counters.incr(CounterType::VssErrors);
            return; // TODO: How to signal manager?
        }
    };

    let connector = tls_connect();
    let tls = connector
        .connect(node_addr.ip().into(), sock)
        .await
        .unwrap();
    let (reader, writer) = tokio::io::split(tls);

    let network = capnp_rpc::twoparty::VatNetwork::new(
        tokio::io::BufReader::new(reader).compat(),
        tokio::io::BufWriter::new(writer).compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        capnp::message::ReaderOptions::new(),
    );

    let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);

    let vss_service: v1::visa_support_service::Client =
        rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);

    tokio::task::spawn_local(rpc_system);

    let req = vss_service.connect_request();

    let handle_result_rdr =
        match rpc_with_timeout("connect", DEFAULT_RPC_TIMEOUT, req.send().promise).await {
            Ok(req_resp) => req_resp,
            Err(e) => {
                error!(target: VSS, "VSS connect request failed: {}", e);
                asm.counters.incr(CounterType::VssErrors);
                return; // TODO: Signal manager?
            }
        };

    let handle_result_ok_or_error = handle_result_rdr.get().unwrap().get_resp().unwrap();

    let vss_handle: v1::v_s_s_handle::Client = match handle_result_ok_or_error.which().unwrap() {
        v1::result::Which::Ok(vss_handle_obj) => vss_handle_obj.unwrap(),
        v1::result::Which::Error(err_obj) => {
            let err_obj = err_obj.unwrap();
            error!(target: VSS, "VSS connect error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
            asm.counters.incr(CounterType::VssErrors);
            return; // TODO: Signal manager?
        }
    };

    info!(target: VSS, "now connected to VSS at {}", node_addr);

    do_vss_initialization(&asm, &node_addr.ip(), &vss_handle).await;

    let ping_timeout = tokio::time::sleep(config::VSS_PING_INTERVAL);
    tokio::pin!(ping_timeout);
    let mut ping_failures = 0;

    loop {
        tokio::select! {
            cmd_opt = cmd_rx.recv() => {
                match cmd_opt {
                    Some(cmd) => match cmd {
                        VssCmd::Stop() => {
                            info!(target: VSS, "stop called on VSS worker for {}", node_addr);
                            break;
                        }
                        VssCmd::PushVisas(_visas, resp_tx) => {
                            if let Err(e) = resp_tx.send(Err(VssSyncError::Internal("push-visas not implemented".to_string()))) {
                                error!(target: VSS, "failed to send response for push-visas command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::RevokeVisasById(_visa_id, resp_tx) => {
                            if let Err(e) = resp_tx.send(Err(VssSyncError::Internal("revoke-visas not implemented".to_string()))) {
                                error!(target: VSS, "failed to send response for revoke-visas command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::RevokeAuthsByZprAddr(_zpr_addr, resp_tx) => {
                            if let Err(e) = resp_tx.send(Err(VssSyncError::Internal("revoke-auths not implemented".to_string()))) {
                                error!(target: VSS, "failed to send response for revoke-auths command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::SetServices(services, resp_tx) => {
                            if let Err(e) = resp_tx.send(do_set_services(&vss_handle, services).await) {
                                error!(target: VSS, "failed to send response for set-services command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::Configure(params, resp_tx) => {
                            if let Err(e) = resp_tx.send(do_configure(&vss_handle, params).await) {
                                error!(target: VSS, "failed to send response for configure command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                    }
                    None => {
                        // Uh oh - channel closed.
                        warn!(target: VSS, "command channel closed for VSS worker for {}", node_addr);
                        break;
                    }
                }
            }

            () = &mut ping_timeout => {
                let ping_dur = PING_MIN_TIMEOUT + Duration::from_secs(ping_failures);
                match rpc_with_timeout("ping", ping_dur, vss_handle.ping_request().send().promise).await {
                    Ok(ping_response_rdr) => {
                        match ping_response_rdr.get().unwrap().get_res().unwrap().which().unwrap() {
                            v1::ok_or_error::Which::Ok(_) => {
                                trace!(target: VSS, "ping to VSS at {} succeeded", node_addr);
                                asm.actor_mgr.update_node_last_seen(&node_addr.ip()).await.ok(); // Ignore errors.
                                ping_failures = 0;
                            }
                            v1::ok_or_error::Which::Error(err_rdr) => {
                                let err_obj = err_rdr.unwrap();
                                error!(target: VSS, "VSS ping returns error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
                                asm.counters.incr(CounterType::VssErrors);
                                // TODO: What does this even mean? We got a reply but it is a coded error message? Should we just disconnect from node?
                                ping_failures += 1;
                            }
                        }
                    }
                    Err(VssSyncError::Timeout(_)) => {
                        warn!(target: VSS, "ping to VSS at {} timed out", node_addr);
                        asm.counters.incr(CounterType::VssErrors);
                        ping_failures += 1;
                    }
                    Err(_) => {
                        warn!(target: VSS, "ping to VSS at {} failed", node_addr);
                        asm.counters.incr(CounterType::VssErrors);
                        ping_failures += 1;
                    }
                }
                if ping_failures == 0 {
                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + config::VSS_PING_INTERVAL);
                } else if ping_failures < config::VSS_MAX_PING_FAILURES as u64 {
                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(1));
                } else {
                    error!(target: VSS, "too many VSS ping failures to {}, exiting VSS worker", node_addr);
                    return;
                }
            }
        }
    }
}

/// When the vss worker starts up the node expects a couple of calls immediately.
/// 1. to the configure endpoint to set the params (only AAA prefix for now).
/// 2. to the setServices endpoing to tell node about the available auth services.
async fn do_vss_initialization(
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    // The AAA net is stored in the actor properties, but it is statically tied to
    // the node ZPR address so we just recompute it here.
    let aaa_net = net_mgr::aaa_network_for_node(node_addr);
    let params = vec![Param::new_str(
        pname::AAA_PREFIX.into(),
        aaa_net.to_string(),
    )];
    debug!(target: VSS, "sending configure to VSS at {node_addr}");
    match do_configure(vss_handle, params).await {
        Ok(_) => {
            debug!(target: VSS, "{node_addr} configured successfully");
        }
        Err(e) => {
            warn!(target: VSS, "failed to configure VSS at {node_addr}: {e}");
            asm.counters.incr(CounterType::VssErrors);
        }
    }

    match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
        Ok(services) => {
            debug!(target: VSS, "sending initial auth services list to VSS at {}", node_addr);
            if let Err(e) = do_set_services(&vss_handle, services).await {
                error!(target: VSS, "failed to send initial auth services list to VSS at {}: {}", node_addr, e);
                asm.counters.incr(CounterType::VssErrors);
            } else {
                debug!(target: VSS, "initial auth services list sent to VSS at {}", node_addr);
            }
        }
        Err(e) => {
            warn!(target: VSS, "failed to get auth services list for VSS at {}: {}", node_addr, e);
        }
    }
}

#[derive(Debug)]
struct NoVerification;

// Implement the dangerous trait ServerCertVerifier NoVerification which will
// just always approve the connection
impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    }
}

// Create a dangerous connector - the verifier will always approve
// TODO decide if we want to use an actual certificate
fn tls_connect() -> TlsConnector {
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(cfg))
}

async fn do_set_services(
    vss_handle: &v1::v_s_s_handle::Client,
    services: Vec<ServiceDescriptor>,
) -> Result<(), VssSyncError> {
    let mut req = vss_handle.set_services_request();
    let req_builder = req.get();

    let mut svc_list_builder = req_builder.init_svcs(services.len() as u32);
    for (i, svc) in services.iter().enumerate() {
        let mut svc_builder = svc_list_builder.reborrow().get(i as u32);
        svc.write_to(&mut svc_builder);
    }

    let set_response_rdr =
        rpc_with_timeout("set-services", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let set_response_ok_or_err = set_response_rdr.get()?;

    match set_response_ok_or_err.get_res().unwrap().which().unwrap() {
        v1::ok_or_error::Which::Ok(_) => (),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            return Err(VssSyncError::from(api_err));
        }
    }

    Ok(())
}

async fn do_configure(
    vss_handle: &v1::v_s_s_handle::Client,
    params: Vec<Param>,
) -> Result<(), VssSyncError> {
    let mut req = vss_handle.configure_request();
    let req_builder = req.get();

    let mut params_builder = req_builder.init_params(params.len() as u32);
    for (i, param) in params.iter().enumerate() {
        let mut param_builder = params_builder.reborrow().get(i as u32);
        param.write_to(&mut param_builder);
    }

    let configure_response_rdr =
        rpc_with_timeout("configure", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let configure_response_ok_or_err = configure_response_rdr.get()?;

    match configure_response_ok_or_err
        .get_res()
        .unwrap()
        .which()
        .unwrap()
    {
        v1::ok_or_error::Which::Ok(_) => Ok(()),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            Err(VssSyncError::from(api_err))
        }
    }
}

/// Wrap a Cap'n Proto RPC future with a timeout, mapping errors.
async fn rpc_with_timeout<F, T>(
    name: &'static str,
    duration: Duration,
    fut: F,
) -> Result<T, VssSyncError>
where
    F: Future<Output = Result<T, capnp::Error>>,
{
    match tokio::time::timeout(duration, fut).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(capnp_err)) => Err(capnp_err.into()),
        Err(_elapsed) => Err(VssSyncError::Timeout(name.to_string())),
    }
}
