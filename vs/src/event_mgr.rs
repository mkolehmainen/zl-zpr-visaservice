//! Event Manager handles high-level events that have repurcussions around the
//! visa service system such as actor joins/leaves. Operations in here
//! are not able to report back success/failure to the "caller".

use futures::stream::{self, StreamExt};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use zpr::vsapi::v1::DisconnectReason;
use zpr::vsapi_types::ServiceDescriptor;

use crate::assembly::Assembly;
use crate::error::ServiceError;
use crate::logging::targets::EVENT;

pub enum VsEvent {
    /// Use _after_ actor has been authenticated and the datastore updated.
    ActorJoins(IpAddr),

    /// Use when we get a signal from remote that actor is disconnected/disconnecting.
    /// EventManager takes care of state updates.
    ActorLeaves(IpAddr, DisconnectReason),
}

pub struct EventMgr {
    event_queue: mpsc::Sender<VsEvent>,
}

impl EventMgr {
    pub fn new(event_queue: mpsc::Sender<VsEvent>) -> Self {
        EventMgr { event_queue }
    }

    pub async fn record_event(&self, event: VsEvent) -> Result<(), ServiceError> {
        if let Err(e) = self.event_queue.send(event).await {
            error!(target: EVENT, "failed to send to event-queue: {}", e);
            Err(ServiceError::QueueFull("event-queue".into()))
        } else {
            Ok(())
        }
    }
}

pub async fn launch(asm: Arc<Assembly>, mut event_rx: mpsc::Receiver<VsEvent>) {
    debug!(target: EVENT, "event manager worker started");
    while let Some(event) = event_rx.recv().await {
        match event {
            VsEvent::ActorJoins(actor) => {
                if let Err(e) = handle_actor_joins(&asm, actor).await {
                    error!(target: EVENT, "failed to handle actor join event: {}", e);
                }
            }
            VsEvent::ActorLeaves(actor, reason) => {
                if let Err(e) = handle_actor_leaves(&asm, actor, reason).await {
                    error!(target: EVENT, "failed to handle actor leave event: {}", e);
                }
            }
        }
    }
    info!(target: EVENT, "event manager shutting down");
}

// Maybe will call into topology routines from here eventually.
async fn handle_actor_joins(asm: &Arc<Assembly>, actor_addr: IpAddr) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor joined: {}", actor_addr);
    let has_auth_services = match asm
        .actor_mgr
        .has_auth_services(asm.clone(), &actor_addr)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            error!(target: EVENT, "actor_mgr.has_auth_services failed: {}", e);
            false
        }
    };

    if has_auth_services {
        //let service_list =
        match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
            Ok(svcs) => set_services_all_nodes(&asm, &svcs).await?,
            Err(e) => {
                error!(
                    target: EVENT,
                    "actor_mgr.get_auth_services_list failed: {}", e
                );
            }
        }
    }
    Ok(())
}

// TODO: Not sure I love this idea of having these wide ranging functions in the 'event_mgr'.
// Things could get quite messy.
//
// The goal is somewhere to centralize high level logic that imapacts all sorts of areas in the
// visa service.
async fn handle_actor_leaves(
    asm: &Arc<Assembly>,
    actor_addr: IpAddr,
    reason: DisconnectReason,
) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor left: {}", actor_addr);

    let prev_auth_services: HashSet<ServiceDescriptor> = HashSet::from_iter(
        asm.actor_mgr
            .get_auth_services_list(asm.clone())
            .await
            .unwrap_or_default(),
    );

    // The disconnect call updates our state database.
    // Could be we just lost a single adapter, or we lost a node and all adapters connected.
    // TODO: In future we may want to not wipe state so quickly? What if this is temporary (for node)?
    // TODO: What are the implications for VS if this next call errors out?
    asm.cc.disconnect(asm.clone(), actor_addr, reason).await?;

    if !prev_auth_services.is_empty() {
        let new_auth_services: HashSet<ServiceDescriptor> =
            HashSet::from_iter(asm.actor_mgr.get_auth_services_list(asm.clone()).await?); // will error out on DB error

        // If there is a difference between previous and new authorized services, we need to update nodes.
        if prev_auth_services != new_auth_services {
            set_services_all_nodes(&asm, &new_auth_services.iter().cloned().collect::<Vec<_>>())
                .await?;
        }
    }

    Ok(())
}

/// Helper to use the VSS on all connected nodes to update the auth services list.
async fn set_services_all_nodes(
    asm: &Arc<Assembly>,
    service_set: &[ServiceDescriptor],
) -> Result<(), ServiceError> {
    let node_list = asm.actor_mgr.list_node_addrs().await.unwrap_or_default();

    // Make RPC calls to the nodes in parallel.

    stream::iter(node_list)
        .for_each_concurrent(None, |naddr| {
            let asm = asm.clone();
            let service_list: Vec<ServiceDescriptor> = service_set.to_vec();
            async move {
                debug!(
                    target: EVENT,
                    "attempting to use VSS to set_services on node {naddr}"
                );
                if let Some(vss_h) = asm.vss_mgr.get_handle(&naddr) {
                    if let Err(e) = vss_h.set_services(service_list).await {
                        error!(
                            target: EVENT,
                            "failed to set_services on node {}: {}",
                            naddr,
                            e
                        );
                    }
                }
            }
        })
        .await;
    Ok(())
}
