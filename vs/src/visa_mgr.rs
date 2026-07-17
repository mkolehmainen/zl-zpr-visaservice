//! Manage the creating, storage and retrieval of visas for the visa service.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, error, warn};

use crate::assembly::Assembly;
use crate::config;
use crate::db;
use crate::db::VisaMetadata;
use crate::error::{ServiceError, StoreError};
use crate::logging::targets::VISA;
use crate::packet::make_fivetuple_tcp;
use crate::visareq_worker::{VisaDecision, request_visa_wait_response};

use libeval::eval_result::{Direction, Hit};
use libeval::route::{NodeId, Route};
use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{
    CommFlag, DockPep, DockPepType, EndpointT, FwdPep, FwdPepStyle, IcmpPep, KeySet, PacketDesc,
    TcpUdpPep, Visa, VisaType, VsapiFiveTuple,
};

use tracing::info;

#[derive(Clone)]
pub struct VisaMgr {
    repo: db::VisaRepo,
}

pub struct VisaWithMetadata {
    pub visa: Visa,
    pub metadata: db::VisaMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VCtx {
    Ingress,
    Intermediary,
    Egress,
}

impl VisaWithMetadata {
    pub fn new(visa: Visa, metadata: db::VisaMetadata) -> Self {
        VisaWithMetadata { visa, metadata }
    }
}

impl VisaMgr {
    pub fn new(db: db::VisaRepo) -> Self {
        VisaMgr { repo: db }
    }

    /// To "actualize" a visa means to adjust it for the context in which it is deployed.
    /// The contexts are:
    /// - On an ingress node we send a full visa which may also have forwarding instuctions
    ///   when there are links that need to be traversed.
    /// - On an intermediary node we send a very truncated visa: just the ID and forwarding
    ///   instructions.
    /// - On an egress node we send a full visa, no forwarding info.
    ///
    pub async fn actualize_visa_for_target_node(
        &self,
        mut visa: Visa,
        target_node: &IpAddr,
    ) -> Result<Visa, ServiceError> {
        let md = self.repo.get_visa_metadata_by_id(visa.issuer_id).await?;

        let Some(path) = md.path.as_ref() else {
            return Ok(visa);
        };
        if path.len() < 2 {
            // should not happen but just in case, treat as no path.
            return Ok(visa);
        }

        // Metadata includes the requesting node addr.
        // If our `target_node` is first or last then we are in an ingress or egress context.
        // If target_node is requesting_node then this is ingress, else this is egress.

        let vctx =
            if (path.first().unwrap() == target_node) || (path.last().unwrap() == target_node) {
                if target_node == &md.requesting_node {
                    VCtx::Ingress
                } else {
                    VCtx::Egress
                }
            } else {
                VCtx::Intermediary
            };

        match vctx {
            VCtx::Ingress => {
                // We already know path is at least 2 so there is a forwarding instruction.
                // We are ingress so we are at one end of the path, so next hop is trivial.
                let next_hop = if path.first().unwrap() == target_node {
                    path[1]
                } else {
                    path[path.len() - 2]
                };
                let fwd_pep = FwdPep {
                    next_hop: next_hop,
                    style: FwdPepStyle::OneWay, // TODO: Not sure when to set this to symmetric.
                };
                visa.fwd_pep = Some(fwd_pep);
                return Ok(visa);
            }
            VCtx::Egress => {
                // Just return the full visa.
                return Ok(visa);
            }
            VCtx::Intermediary => {
                // We are an intermediate node, but are we going forward on the path or backwards?
                //
                // Given path [A, B, C, D] and and the fact that A requested the visa (and so is ingress) then,
                // Node D is egress.  Node B needs to forward to C, and C to D.

                // Build a forwardingOnly visa ...
                match next_hop_in_path(path, target_node, &md.requesting_node) {
                    Some(next_hop) => {
                        let fpep = FwdPep {
                            next_hop: *next_hop,
                            style: FwdPepStyle::OneWay, // TODO: Not sure when to set this to symmetric.
                        };
                        return Ok(to_forwarding_visa(visa, fpep));
                    }
                    None => {
                        error!(target: VISA, "error actualizing visa for ingress node {target_node} on path is {path:?}: no next_hop found");
                        return Err(ServiceError::Internal(format!("failed to actualize visa")));
                    }
                }
            }
        }
    }

    /// Used when a node has already connected to the VS via the VSAPI and has called
    /// `register_vss`.
    ///
    /// Creates visas for:
    /// - allow visa service to talk to node VSS.
    ///
    /// `node_addr` - The node, already connected and has just called `register_vss` over
    /// VSAPI.  The idea is that the VS is next going to open a connection back to the node's
    /// VSS so this can preempt the visa request.
    ///
    /// The visas returned here are any pending visas that should be installed on the
    /// node `node_addr` which has just called to initialize vss.  If there are intermediary
    /// nodes between the VS and `node_addr` those other visas are also created and set
    /// PENDING on the relevant nodes -- but are not returned here.
    ///
    pub async fn post_register_vss_visas_for_node(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
    ) -> Result<Vec<Visa>, ServiceError> {
        let mut visas = Vec::new();

        // Start with any visas that may already be pending.
        if let Ok(pendings) = self.get_pending_visas_for_node(node_addr).await {
            for v in pendings {
                let av = self.actualize_visa_for_target_node(v, node_addr).await?;
                visas.push(av);
            }
        }

        // The node may be reconnecting, in which case it may already have the core visas installed.
        let vs_node_ft = make_fivetuple_tcp(
            asm.config.get_vs_addr(),
            node_addr.clone(),
            0,
            vss_addr.port(),
        )?;
        let has_vs_to_node_visa = self
            .get_node_visa_by_five_tuple(node_addr, &vs_node_ft)
            .await?
            .is_some();

        if !has_vs_to_node_visa {
            let cres = self
                .create_vs_to_node_vss_visa(asm.clone(), node_addr, vss_addr.port())
                .await?;
            let cres = self.actualize_visa_for_target_node(cres, node_addr).await?;
            visas.push(cres);
        } else {
            debug!(
                target: VISA,
                "node {node_addr} already has VS->VSS visa installed, skipping creation"
            );
        }
        Ok(visas)
    }

    /// Use a linear search of all visas installed on the node to find a match.
    /// TODO: Need in-memory indexes for this.
    pub async fn get_node_visa_by_five_tuple(
        &self,
        node_addr: &IpAddr,
        ft: &VsapiFiveTuple,
    ) -> Result<Option<Visa>, ServiceError> {
        for visa in self
            .repo
            .get_visas_for_node_by_state(node_addr, db::NodeVisaState::Installed)
            .await?
        {
            if visa.dock_pep.is_none() {
                warn!(target: VISA, "found visa in store with no dock_pep ID={}", visa.issuer_id);
                continue; // not a full visa -- should not happen as only full visas are stored.
            }
            let dock_pep = visa.dock_pep.as_ref().unwrap();
            let vsource = &dock_pep.source_addr;
            let vdest = &dock_pep.dest_addr;
            if vsource == &ft.source_addr && vdest == &ft.dest_addr {
                // Is from VS -> NODE, check for VSS port match.
                match &dock_pep.pep {
                    DockPepType::TCP(tpep) => {
                        if tpep.dest_port == ft.dest_port && tpep.source_port == ft.source_port {
                            // Found it
                            return Ok(Some(visa));
                        } else {
                            continue; // not the right visa
                        }
                    }
                    _ => {
                        continue; // not the right visa
                    }
                }
            }
        }
        Ok(None)
    }

    /// Ask policy for a visa permitting this visa service to talk to the given node VSS addr.
    /// Creating the visa has side effect of storing it in state and as PENDING on the requesting node.
    ///
    /// TODO: Should also be set pending on any intermediary nodes.
    ///
    /// `node_addr` - node ZPR address hosting the VSS.
    ///
    /// Returns a visa for the docking node of `node_addr` (based on route of VS->node_addr).
    async fn create_vs_to_node_vss_visa(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_port: u16,
    ) -> Result<Visa, ServiceError> {
        // TODO: We may have this visa on hand already, if so return it and do not re-generate.

        let pkt_data =
            PacketDesc::new_tcp_with_addr(asm.config.get_vs_addr(), *node_addr, 0, vss_port)?;

        // TODO: This call to return a FULL visa plus Route info.
        // then we need to do some work.
        self.create_visa_for_packet(asm, pkt_data, node_addr).await
    }

    /// `requesting_node_addr` - The visa is created as if this node has requested it.
    ///
    /// The returned visa is a full visa (TODO: return route info).
    /// The visa needs to be crunched through PATH to determine what is sent to `requesting_node_addr` node.
    async fn create_visa_for_packet(
        &self,
        asm: Arc<Assembly>,
        pkt_data: PacketDesc,
        requesting_node_addr: &IpAddr,
    ) -> Result<Visa, ServiceError> {
        // This will end up calling into `create_visa` which means we get a route
        // and state will have been updated if any visas need to be sent to nodes.
        //
        // When it comes time to actually deliver a visa to a node
        // we can use the PATH to create correct visa contents. The visa stored in state
        // by ID is the FULL visa.
        //
        match request_visa_wait_response(
            &asm,
            requesting_node_addr,
            pkt_data,
            config::DEFAULT_VISA_REQ_TIMEOUT,
        )
        .await
        {
            Ok(VisaDecision::Allow(visa, _route)) => Ok(visa), // TODO: do something with the route
            Ok(VisaDecision::Deny(dcode)) => Err(ServiceError::VisaDenied(dcode.to_string())),
            Err(e) => Err(e),
        }
    }

    /// Placeholder implementation, called concurrently.
    /// Called after making use of libeval to check policy.
    /// Using a const expiration (4 hrs).
    /// No checking to see if visa already exists.
    /// Fake keys.
    ///
    /// Note that visa state with respect to the requesting node is set to PENDING_INSTALL.
    ///
    /// A path is created from the route using the direction inforation in the hit.
    ///
    /// This returns a FULL visa.
    pub async fn create_visa(
        &self,
        asm: &Assembly,
        requesting_node: &IpAddr,
        pdesc: &PacketDesc,
        hit: &Hit,
        route: &Route,
        source_zpl: impl Into<String>,
        policy_version: u64,
        vinst: u64,
    ) -> Result<VisaWithMetadata, ServiceError> {
        let expiration_time = std::time::SystemTime::now()
            .checked_add(config::DEFAULT_VISA_EXPIRATION)
            .ok_or_else(|| {
                ServiceError::Internal("failed to compute visa expiration time".to_string())
            })?;

        let (source_port, dest_port) = match pdesc.five_tuple.l4_protocol {
            ip_proto::TCP | ip_proto::UDP => {
                if pdesc.comm_flags == CommFlag::BiDirectional {
                    match hit.direction {
                        Direction::Forward => {
                            // client->server, allow any source port.
                            (0, pdesc.five_tuple.dest_port)
                        }
                        Direction::Reverse => {
                            // server->client, allow any dest port.
                            (pdesc.five_tuple.source_port, 0)
                        }
                    }
                } else {
                    // unidirectional, exact ports.
                    // TODO: What is ReRequest flag?
                    (pdesc.five_tuple.source_port, pdesc.five_tuple.dest_port)
                }
            }
            ip_proto::IPV6_ICMP => {
                // icmp type/code in ports
                (pdesc.five_tuple.source_port, pdesc.five_tuple.dest_port)
            }
            _ => {
                return Err(ServiceError::Internal(format!(
                    "unsupported protocol for visa: {}",
                    pdesc.five_tuple.l4_protocol
                )));
            }
        };

        let pep = match pdesc.five_tuple.l4_protocol {
            ip_proto::TCP => DockPepType::TCP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::UDP => DockPepType::UDP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::IPV6_ICMP => {
                DockPepType::ICMP(IcmpPep::new(source_port as u8, dest_port as u8))
            }

            _ => unreachable!(), // already handled above
        };

        let visa_id = self.repo.get_next_visa_id().await?;

        let path: Option<Vec<IpAddr>> = if matches!(route.kind, libeval::route::RouteKind::Multihop)
        {
            let starting_node = NodeId(*requesting_node);
            let mut node_id_path = asm.topo_mgr.route_to_path(route, &starting_node)?;
            // Normalize to canonical forward order (ingress→…→egress) so that
            // actualize_visa_for_target_node applies direction logic correctly.
            // A reverse hit starts traversal from the forward-egress node, so reversing
            // restores forward orientation.
            if hit.direction == Direction::Reverse {
                node_id_path.reverse();
            }
            Some(node_id_path.into_iter().map(|id| id.into()).collect())
        } else {
            None
        };

        let mut metadata = db::VisaMetadata::new(
            requesting_node.clone(),
            policy_version,
            vinst,
            source_zpl.into(),
            hit.direction,
            path,
            pdesc,
        );
        if let Some(sig) = hit.signal.as_ref() {
            metadata.signal_msgs.push(sig.message.clone());
        }

        let pep = DockPep {
            pep,
            source_addr: pdesc.five_tuple.source_addr.clone(),
            dest_addr: pdesc.five_tuple.dest_addr.clone(),
            session_key: KeySet::new("secret".as_bytes(), "secret".as_bytes()),
        };

        let visa = Visa {
            issuer_id: visa_id,
            config: 0,
            expires: expiration_time,
            visa_type: VisaType::Full,
            dock_pep: Some(pep),
            fwd_pep: None,
            cons: None,
        };

        // The store also updates the visa state along the path.
        self.repo
            .store_visa(&visa, metadata.clone(), db::NodeVisaState::PendingInstall)
            .await?;

        info!("created visa {visa_id}");
        Ok(VisaWithMetadata::new(visa, metadata))
    }

    pub async fn get_pending_visas_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<Visa>, ServiceError> {
        let visas = self
            .repo
            .get_visas_for_node_by_state(node_addr, db::NodeVisaState::PendingInstall)
            .await?;
        Ok(visas)
    }

    pub async fn get_pending_visa_ids_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<u64>, ServiceError> {
        let visa_ids = self
            .repo
            .get_visa_ids_for_node_by_state(node_addr, db::NodeVisaState::PendingInstall)
            .await?;
        Ok(visa_ids)
    }

    pub async fn get_installed_visa_ids_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<u64>, ServiceError> {
        let visa_ids = self
            .repo
            .get_visa_ids_for_node_by_state(node_addr, db::NodeVisaState::Installed)
            .await?;
        Ok(visa_ids)
    }

    pub async fn get_num_pending_install_visas(
        &self,
        node_addr: &IpAddr,
    ) -> Result<u32, ServiceError> {
        let pending_revokes = self
            .repo
            .get_count_visas_for_node_by_state(node_addr, db::NodeVisaState::PendingInstall)
            .await?;
        Ok(pending_revokes)
    }

    pub async fn get_num_pending_revoked_visas(
        &self,
        node_addr: &IpAddr,
    ) -> Result<u32, ServiceError> {
        let pending_revokes = self
            .repo
            .get_count_visas_for_node_by_state(node_addr, db::NodeVisaState::PendingRevoke)
            .await?;
        Ok(pending_revokes)
    }

    /// Register that visa `visa_id` has been installed on node at ZPR address `node_addr`.
    pub async fn visa_installed(
        &self,
        visa_id: u64,
        node_addr: &IpAddr,
    ) -> Result<(), ServiceError> {
        self.repo
            .update_node_visa_state(node_addr, visa_id, db::NodeVisaState::Installed)
            .await?;
        Ok(())
    }

    /// Designed to be used to setup database in clean state as we prepare for a
    /// fresh node joining.
    pub async fn clear_node_state(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        self.repo.clear_node_state(node_addr).await?;
        Ok(())
    }

    /// Remove all visas tied to the given node -- assumes that `node_addr` has departed.
    ///
    /// TODO: This probably needs a lock on the node address -- like we do not
    /// want the same node to be reconnecting while we are doing this clean up.
    ///
    /// TODO: Sometimes we want to keep track of visas installed on nodes so that
    /// nodes could restart and we can then just push them state.  TBD.
    ///
    /// For each visa that is marked installed or pending-install on the node,
    /// collect the ID.  Then wipe all the nodevisa records for the node.
    ///
    /// Now we have a bunch of visa IDs. For each ID, if the visa is installed
    /// or pending on some other node, update the state on that node to pending-revoke
    /// and then remove the visa:ID record.
    ///
    /// The housekeeping job will take care of updating the TODO lists and sending
    /// the revocation messages out to the other nodes.
    ///
    pub async fn remove_visas_for_node(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        info!(target: VISA, "TODO: remove visas for node {node_addr}");
        Ok(())
    }

    /// Remove all visas tied to the listed actors, assumes the actors have departed.
    pub async fn remove_visas_for_actors(
        &self,
        _actor_addrs: &[IpAddr],
    ) -> Result<(), ServiceError> {
        info!(target: VISA, "TODO: remove visas for actors now removed");
        Ok(())
    }

    /// Get all the visa IDs (non-expired).
    pub async fn list_all_visa_ids(&self) -> Result<Vec<u64>, ServiceError> {
        let visa_ids = self.repo.list_visa_ids().await?;
        Ok(visa_ids)
    }

    /// Shorthand and slightly more race-condition safe way of calling `get_visa_by_id` and `get_visa_metadata_by_id`.
    /// Returns None if either the visa or the metadata is not found.
    pub async fn get_visa_with_metadata_by_id(
        &self,
        visa_id: u64,
    ) -> Result<Option<VisaWithMetadata>, ServiceError> {
        match self.repo.get_visa_by_id(visa_id).await {
            Ok(visa) => match self.repo.get_visa_metadata_by_id(visa_id).await {
                Ok(md) => Ok(Some(VisaWithMetadata { visa, metadata: md })),
                Err(StoreError::NotFound(_)) => Ok(None),
                Err(e) => Err(ServiceError::from(e)),
            },
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Get just the visa (no metadata) using the visa ID.
    /// Returns None if not found.
    pub async fn get_visa_by_id(&self, visa_id: u64) -> Result<Option<Visa>, ServiceError> {
        match self.repo.get_visa_by_id(visa_id).await {
            Ok(visa) => Ok(Some(visa)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Get just the visa metadata using the visa ID.
    /// Returns None if not found.
    #[allow(dead_code)]
    pub async fn get_visa_metadata_by_id(
        &self,
        visa_id: u64,
    ) -> Result<Option<VisaMetadata>, ServiceError> {
        match self.repo.get_visa_metadata_by_id(visa_id).await {
            Ok(md) => Ok(Some(md)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }
}

fn ep_from_dir(dir: &Direction) -> EndpointT {
    match dir {
        // Matched forward direction: client to server.
        Direction::Forward => EndpointT::Client,

        // Matched reverse direction: server to client.
        Direction::Reverse => EndpointT::Server,
    }
}

fn to_forwarding_visa(mut visa: Visa, fwd_pep: FwdPep) -> Visa {
    visa.visa_type = VisaType::ForwardOnly;
    visa.dock_pep = None;
    visa.fwd_pep = Some(fwd_pep);
    visa
}

/// Returns the adjacent node after `target_node` in `path`, stepping forward or backward
/// according to the specified ingress node.
///
/// ### Panics
/// - if `ingress_node` is not either the first or last node in the path.
fn next_hop_in_path<'a>(
    path: &'a [IpAddr],
    target_node: &IpAddr,
    ingress_node: &IpAddr,
) -> Option<&'a IpAddr> {
    assert!(path.first()? == ingress_node || path.last()? == ingress_node);
    let pos = path.iter().position(|n| n == target_node)?;
    if path.first()? == ingress_node {
        path.get(pos + 1)
    } else {
        pos.checked_sub(1).and_then(|i| path.get(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{FakeDb, VisaRepo};
    use crate::packet::make_fivetuple_tcp;
    use crate::test_helpers::{make_pdesc, make_visa};
    use std::sync::Arc;
    use std::time::Duration;

    async fn make_mgr() -> VisaMgr {
        let db = Arc::new(FakeDb::new());
        VisaMgr::new(VisaRepo::new(db, 1).await.unwrap())
    }

    // The default visa from make_visa has source fd5a:5052::10, dest fd5a:5052::20,
    // TCP source_port=1234, dest_port=443.
    const NODE_ADDR: &str = "fd5a:5052::1";
    const SRC_ADDR: &str = "fd5a:5052::10";
    const DST_ADDR: &str = "fd5a:5052::20";

    #[test]
    fn test_next_hop_empty() {
        let path = vec![];
        let ingress = "fd5a:5052::1".parse().unwrap();
        let target = "fd5a:5052::2".parse().unwrap();
        assert_eq!(next_hop_in_path(&path, &target, &ingress), None);
    }

    #[test]
    fn test_next_hop_one_elem() {
        let n0 = "fd5a:5052::1".parse().unwrap();
        let n1 = "fd5a:5052::2".parse().unwrap();
        let path = vec![n0];
        assert_eq!(next_hop_in_path(&path, &n0, &n0), None);
        assert_eq!(next_hop_in_path(&path, &n1, &n0), None);
    }

    #[test]
    fn test_next_hop_two_elem() {
        let n0 = "fd5a:5052::1".parse().unwrap();
        let n1 = "fd5a:5052::2".parse().unwrap();
        let path = vec![n0, n1];
        assert_eq!(next_hop_in_path(&path, &n0, &n0), Some(&n1));
        assert_eq!(next_hop_in_path(&path, &n1, &n0), None);
        assert_eq!(next_hop_in_path(&path, &n1, &n1), Some(&n0));
        assert_eq!(next_hop_in_path(&path, &n0, &n1), None);
    }

    #[test]
    fn test_next_hop_three_elem() {
        let n0 = "fd5a:5052::1".parse().unwrap();
        let n1 = "fd5a:5052::2".parse().unwrap();
        let n2 = "fd5a:5052::3".parse().unwrap();
        let unknown = "fd5a:5052::4".parse().unwrap();
        let path = vec![n0, n1, n2];
        assert_eq!(next_hop_in_path(&path, &n0, &n0), Some(&n1));
        assert_eq!(next_hop_in_path(&path, &n1, &n0), Some(&n2));
        assert_eq!(next_hop_in_path(&path, &n2, &n0), None);

        assert_eq!(next_hop_in_path(&path, &n0, &n2), None);
        assert_eq!(next_hop_in_path(&path, &n1, &n2), Some(&n0));
        assert_eq!(next_hop_in_path(&path, &n2, &n2), Some(&n1));

        assert_eq!(next_hop_in_path(&path, &unknown, &n2), None);
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_found() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(1, std::time::Duration::from_secs(60));

        let metadata = db::VisaMetadata::new(
            node_addr.clone(),
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );

        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::Installed)
            .await
            .unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            443,
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().issuer_id, 1);
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_not_found_empty() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            443,
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_wrong_ports() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(2, std::time::Duration::from_secs(60));
        let metadata = db::VisaMetadata::new(
            node_addr.clone(),
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );

        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::Installed)
            .await
            .unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            8080, // wrong dest_port
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_pending_not_matched() {
        // Visas in PendingInstall state should not be returned.
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(3, std::time::Duration::from_secs(60));
        let metadata = db::VisaMetadata::new(
            node_addr.clone(),
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );

        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            443,
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    // --- actualize_visa_for_target_node tests ---

    // Path nodes used by actualize tests; distinct from the constants above.
    const PATH_NODE_A: &str = "fd5a:5052::a"; // ingress position
    const PATH_NODE_B: &str = "fd5a:5052::b"; // intermediary position
    const PATH_NODE_C: &str = "fd5a:5052::c"; // egress position

    /// Three-node path [A, B, C] used by the actualize tests.
    fn three_node_path() -> Vec<IpAddr> {
        vec![
            PATH_NODE_A.parse().unwrap(),
            PATH_NODE_B.parse().unwrap(),
            PATH_NODE_C.parse().unwrap(),
        ]
    }

    /// Store a visa in the repo with the given path; requesting_node is the first path node (or A if no path).
    async fn store_test_visa(mgr: &VisaMgr, id: u64, path: Option<Vec<IpAddr>>) -> Visa {
        let visa = make_visa(id, Duration::from_secs(60));
        let requesting_node: IpAddr = path
            .as_ref()
            .and_then(|p| p.first())
            .cloned()
            .unwrap_or_else(|| PATH_NODE_A.parse().unwrap());
        let metadata = db::VisaMetadata::new(
            requesting_node,
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            path,
            &make_pdesc(),
        );
        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();
        visa
    }

    async fn store_test_visa_with_reqesting_node(
        mgr: &VisaMgr,
        id: u64,
        path: Option<Vec<IpAddr>>,
        requesting_node: IpAddr,
    ) -> Visa {
        let visa = make_visa(id, Duration::from_secs(60));
        let metadata = db::VisaMetadata::new(
            requesting_node,
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            path,
            &make_pdesc(),
        );
        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();
        visa
    }

    /// No path in metadata → visa returned unchanged with no fwd_pep.
    #[tokio::test]
    async fn test_actualize_no_path_returns_unchanged() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = PATH_NODE_A.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, None).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_addr)
            .await
            .unwrap();
        assert_eq!(result.issuer_id, 1);
        assert!(result.fwd_pep.is_none());
    }

    /// Path with only one node → visa returned unchanged.
    #[tokio::test]
    async fn test_actualize_path_too_short_returns_unchanged() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = PATH_NODE_A.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(vec![node_addr.clone()])).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_addr)
            .await
            .unwrap();
        assert_eq!(result.issuer_id, 1);
        assert!(result.fwd_pep.is_none());
    }

    /// Ingress context (first node + Forward) → full visa with fwd_pep pointing to the second path node.
    #[tokio::test]
    async fn test_actualize_ingress_forward_sets_fwd_pep() {
        let mgr = make_mgr().await;
        let node_a: IpAddr = PATH_NODE_A.parse().unwrap();
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_a)
            .await
            .unwrap();
        let fwd_pep = result.fwd_pep.expect("expected fwd_pep on ingress visa");
        assert_eq!(fwd_pep.next_hop, node_b);
        assert!(result.dock_pep.is_some(), "ingress visa retains dock_pep");
    }

    /// Egress context (last node + Forward) → full visa returned unchanged (no fwd_pep added).
    #[tokio::test]
    async fn test_actualize_egress_forward_returns_full_visa() {
        let mgr = make_mgr().await;
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_c)
            .await
            .unwrap();
        assert!(result.fwd_pep.is_none());
        assert!(result.dock_pep.is_some(), "egress returns full visa");
    }

    /// Ingress context (last node + Reverse) → full visa with fwd_pep pointing to node before target.
    #[tokio::test]
    async fn test_actualize_ingress_reverse_sets_fwd_pep() {
        let mgr = make_mgr().await;
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let visa =
            store_test_visa_with_reqesting_node(&mgr, 1, Some(three_node_path()), node_c).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_c)
            .await
            .unwrap();
        let fwd_pep = result
            .fwd_pep
            .expect("expected fwd_pep on ingress-reverse visa");
        // Traversing in reverse from C, the next hop is B (the node immediately before C).
        assert_eq!(fwd_pep.next_hop, node_b);
        assert!(
            result.dock_pep.is_some(),
            "ingress-reverse visa retains dock_pep"
        );
    }

    /// Egress context (first node + Reverse) → full visa returned unchanged.
    #[tokio::test]
    async fn test_actualize_egress_reverse_returns_full_visa() {
        let mgr = make_mgr().await;
        let requesting_node: IpAddr = PATH_NODE_C.parse().unwrap();
        let node_a: IpAddr = PATH_NODE_A.parse().unwrap();
        let visa =
            store_test_visa_with_reqesting_node(&mgr, 1, Some(three_node_path()), requesting_node)
                .await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_a)
            .await
            .unwrap();
        assert!(result.fwd_pep.is_none());
        assert!(
            result.dock_pep.is_some(),
            "egress-reverse returns full visa"
        );
    }

    /// Demonstrates the next_hop bug: for intermediary node B on path [A, B, C] with Forward
    /// direction, the correct next hop is C (the node AFTER B in the path), not A (the first
    /// node != B, as returned by the buggy iter().find()).
    #[tokio::test]
    async fn test_actualize_next_hop_bug_intermediary_forward() {
        let mgr = make_mgr().await;
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_b)
            .await
            .unwrap();
        assert_eq!(result.visa_type, VisaType::ForwardOnly);
        let fwd_pep = result
            .fwd_pep
            .expect("expected fwd_pep on intermediary visa");
        assert_eq!(
            fwd_pep.next_hop, node_c,
            "next hop for B (Forward) must be C, not A"
        );
    }

    /// Intermediary context → ForwardOnly visa: dock_pep stripped, fwd_pep set to node after target.
    #[tokio::test]
    async fn test_actualize_intermediary_returns_forwarding_only_visa() {
        let mgr = make_mgr().await;
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_b)
            .await
            .unwrap();
        assert_eq!(result.visa_type, VisaType::ForwardOnly);
        assert!(
            result.dock_pep.is_none(),
            "ForwardOnly visa has no dock_pep"
        );
        let fwd_pep = result
            .fwd_pep
            .expect("expected fwd_pep on intermediary visa");
        assert_eq!(fwd_pep.next_hop, node_c);
    }

    // --- create_visa multihop integration tests ---
    // These verify that create_visa uses the explicit route parameter to populate
    // metadata.path, mark all path nodes pending, and enable actualize to set fwd_pep.

    use crate::assembly::tests::new_assembly_for_tests;
    use libeval::route::LinkId;

    // Three nodes forming a linear chain: SRC → MID → DST (no direct SRC–DST link).
    const MH_SRC: &str = "fd5a:5052::a1";
    const MH_MID: &str = "fd5a:5052::b1";
    const MH_DST: &str = "fd5a:5052::c1";

    /// Build an assembly with topology SRC→MID→DST and no direct SRC–DST link.
    async fn make_multihop_assembly() -> Assembly {
        let asm = new_assembly_for_tests(None).await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        asm.topo_mgr.add_node(src).unwrap();
        asm.topo_mgr.add_node(mid).unwrap();
        asm.topo_mgr.add_node(dst).unwrap();
        asm.topo_mgr
            .add_link(src, mid, LinkId("link-src-mid".into()), vec![], 1)
            .unwrap();
        asm.topo_mgr
            .add_link(mid, dst, LinkId("link-mid-dst".into()), vec![], 1)
            .unwrap();
        asm
    }

    /// create_visa with a multihop route records the full [src, mid, dst] path in metadata.
    #[tokio::test]
    async fn test_create_visa_multihop_path_stored_in_metadata() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();

        let src_adapter: IpAddr = "fd5a:5052:1234::a100".parse().unwrap();
        let dst_adapter: IpAddr = "fd5a:5052:1234::a200".parse().unwrap();

        let pdesc = PacketDesc::new_tcp_with_addr(src_adapter, dst_adapter, 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap(); // route between the nodes

        let visawmd = asm
            .visa_mgr
            .create_visa(&asm, &src, &pdesc, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        let metadata = asm
            .visa_mgr
            .repo
            .get_visa_metadata_by_id(visawmd.visa.issuer_id)
            .await
            .unwrap();
        assert_eq!(metadata.path, Some(vec![src, mid, dst]));
    }

    /// create_visa with a multihop route marks every path node (including the intermediary) pending.
    #[tokio::test]
    async fn test_create_visa_multihop_marks_all_path_nodes_pending() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        let src_adapter: IpAddr = "fd5a:5052:1234::a100".parse().unwrap();
        let dst_adapter: IpAddr = "fd5a:5052:1234::a200".parse().unwrap();
        let pdesc = PacketDesc::new_tcp_with_addr(src_adapter, dst_adapter, 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(&asm, &src, &pdesc, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        let visa_id = visawmd.visa.issuer_id;
        let pending_src = asm.visa_mgr.get_pending_visas_for_node(&src).await.unwrap();
        let pending_mid = asm.visa_mgr.get_pending_visas_for_node(&mid).await.unwrap();
        let pending_dst = asm.visa_mgr.get_pending_visas_for_node(&dst).await.unwrap();

        assert_eq!(
            pending_src.len(),
            1,
            "requesting node (src) must be pending"
        );
        assert_eq!(pending_mid.len(), 1, "intermediary (mid) must be pending");
        assert_eq!(pending_dst.len(), 1, "egress node (dst) must be pending");
        // All three pending entries refer to the same visa.
        assert!(pending_src.iter().any(|v| v.issuer_id == visa_id));
        assert!(pending_mid.iter().any(|v| v.issuer_id == visa_id));
        assert!(pending_dst.iter().any(|v| v.issuer_id == visa_id));
    }

    /// For a reverse multihop visa the requesting node is the reverse-direction ingress and
    /// must receive fwd_pep pointing to the next hop toward the forward source.
    ///
    /// The bug: create_visa always passes requesting_node as starting_node to route_to_path,
    /// so for a reverse hit where requesting_node == forward-egress (dst) the stored path is
    /// [dst, mid, src].  actualize_visa_for_target_node then sees path.first()==dst with
    /// Direction::Reverse → VCtx::Egress → no fwd_pep.  The fix is to reverse the stored
    /// path for reverse hits so it is always in canonical forward order [src, mid, dst].
    #[tokio::test]
    async fn test_create_visa_reverse_multihop_requesting_node_gets_fwd_pep() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        let src_adapter: IpAddr = "fd5a:5052:1234::a100".parse().unwrap();
        let dst_adapter: IpAddr = "fd5a:5052:1234::a200".parse().unwrap();

        // Reverse packet: dst is the sender, src is the destination.
        let pdesc = PacketDesc::new_tcp_with_addr(dst_adapter, src_adapter, 54321, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Reverse);
        let route = asm.topo_mgr.get_best_route(&dst, &src).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(&asm, &dst, &pdesc, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        // dst is the ingress for reverse traffic; it must get fwd_pep pointing to mid.
        let actualized = asm
            .visa_mgr
            .actualize_visa_for_target_node(visawmd.visa.clone(), &dst)
            .await
            .unwrap();

        let fwd_pep = actualized
            .fwd_pep
            .expect("reverse ingress node (dst) must have fwd_pep on a multihop visa");
        assert_eq!(
            fwd_pep.next_hop, mid,
            "reverse ingress fwd_pep must point to the intermediary"
        );
        assert!(
            actualized.dock_pep.is_some(),
            "reverse ingress node retains dock_pep"
        );
    }

    /// Actualizing a multihop visa for the ingress node sets fwd_pep to the next hop.
    #[tokio::test]
    async fn test_create_visa_multihop_actualize_ingress_sets_fwd_pep() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        let src_adapter: IpAddr = "fd5a:5052:1234::a100".parse().unwrap();
        let dst_adapter: IpAddr = "fd5a:5052:1234::a200".parse().unwrap();
        let pdesc = PacketDesc::new_tcp_with_addr(src_adapter, dst_adapter, 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(&asm, &src, &pdesc, &hit, &route, "", 0, 0)
            .await
            .unwrap();

        let actualized = asm
            .visa_mgr
            .actualize_visa_for_target_node(visawmd.visa.clone(), &src)
            .await
            .unwrap();

        let fwd_pep = actualized
            .fwd_pep
            .expect("ingress node must have a forwarding PEP on a multihop visa");
        assert_eq!(
            fwd_pep.next_hop, mid,
            "ingress fwd_pep must point to the intermediary"
        );
        assert!(
            actualized.dock_pep.is_some(),
            "ingress node retains the dock PEP"
        );
        // The egress node dst is not the target here, so this just confirms the visa
        // was created for the right endpoints.
        let _ = dst;
    }
}
