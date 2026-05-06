//! Manage the creating, storage and retrieval of visas for the visa service.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::debug;

use crate::assembly::Assembly;
use crate::config;
use crate::db;
use crate::error::{ServiceError, StoreError};
use crate::logging::targets::VISA;
use crate::packet::make_fivetuple_tcp;
use crate::visareq_worker::{VisaDecision, request_visa_wait_response};

use libeval::eval_result::{Direction, Hit};
use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{
    CommFlag, DockPep, EndpointT, IcmpPep, KeySet, PacketDesc, TcpUdpPep, Visa, VsapiFiveTuple,
};

use tracing::info;

pub struct VisaMgr {
    repo: db::VisaRepo,
}

pub struct VisaWithMetadata {
    pub visa: Visa,
    pub metadata: db::VisaMetadata,
}

impl VisaMgr {
    pub fn new(db: db::VisaRepo) -> Self {
        VisaMgr { repo: db }
    }

    pub async fn initial_visas_for_node(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
    ) -> Result<Vec<Visa>, ServiceError> {
        let mut visas = Vec::new();

        if let Ok(pendings) = self.get_pending_visas_for_node(node_addr).await {
            visas.extend(pendings); // ignore errors here
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
            if &visa.source_addr == &ft.source_addr && &visa.dest_addr == &ft.dest_addr {
                // Is from VS -> NODE, check for VSS port match.
                match &visa.dock_pep {
                    DockPep::TCP(tpep) => {
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
    pub async fn create_vs_to_node_vss_visa(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_port: u16,
    ) -> Result<Visa, ServiceError> {
        // TODO: We may have this visa on hand already, if so return it and do not re-generate.

        // TODO: PacketDesc should have new_xxx functions that take IpAddr (not just string)
        let pkt_data = PacketDesc::new_tcp(
            &asm.config.get_vs_addr().to_string(),
            &node_addr.to_string(),
            0,
            vss_port,
        )
        .unwrap();

        match request_visa_wait_response(
            &asm,
            node_addr,
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
    /// Note that visa state with respect tot he requesting node is set to PENDING_INSTALL.
    pub async fn create_visa(
        &self,
        requesting_node: &IpAddr,
        pdesc: &PacketDesc,
        hit: &Hit,
        source_zpl: impl Into<String>,
        policy_version: u64,
    ) -> Result<Visa, ServiceError> {
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
            ip_proto::TCP => DockPep::TCP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::UDP => DockPep::UDP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::IPV6_ICMP => DockPep::ICMP(IcmpPep::new(source_port as u8, dest_port as u8)),

            _ => unreachable!(), // already handled above
        };

        let visa_id = self.repo.get_next_visa_id().await?;

        let mut metadata = db::VisaMetadata::new(
            requesting_node.clone(),
            policy_version,
            source_zpl.into(),
            hit.direction,
        );
        if let Some(sig) = hit.signal.as_ref() {
            metadata.signal_msgs.push(sig.message.clone());
        }

        let visa = Visa {
            issuer_id: visa_id,
            config: 0,
            expires: expiration_time,
            source_addr: pdesc.five_tuple.source_addr.clone(),
            dest_addr: pdesc.five_tuple.dest_addr.clone(),
            dock_pep: pep,
            cons: None,
            session_key: KeySet::new("secret".as_bytes(), "secret".as_bytes()),
        };

        self.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await?;

        info!("created visa {visa_id}");
        Ok(visa)
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
}

fn ep_from_dir(dir: &Direction) -> EndpointT {
    match dir {
        // Matched forward direction: client to server.
        Direction::Forward => EndpointT::Client,

        // Matched reverse direction: server to client.
        Direction::Reverse => EndpointT::Server,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{FakeDb, VisaRepo};
    use crate::packet::make_fivetuple_tcp;
    use crate::test_helpers::make_visa;
    use std::sync::Arc;

    async fn make_mgr() -> VisaMgr {
        let db = Arc::new(FakeDb::new());
        VisaMgr::new(VisaRepo::new(db, 1).await.unwrap())
    }

    // The default visa from make_visa has source fd5a:5052::10, dest fd5a:5052::20,
    // TCP source_port=1234, dest_port=443.
    const NODE_ADDR: &str = "fd5a:5052::1";
    const SRC_ADDR: &str = "fd5a:5052::10";
    const DST_ADDR: &str = "fd5a:5052::20";

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_found() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(1, std::time::Duration::from_secs(60));

        let metadata =
            db::VisaMetadata::new(node_addr.clone(), 0, "zpl".to_string(), Direction::Forward);

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
        let metadata =
            db::VisaMetadata::new(node_addr.clone(), 0, "zpl".to_string(), Direction::Forward);

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
        let metadata =
            db::VisaMetadata::new(node_addr.clone(), 0, "zpl".to_string(), Direction::Forward);

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
}
