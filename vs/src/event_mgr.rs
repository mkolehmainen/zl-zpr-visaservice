//! Event Manager handles high-level events that have repurcussions around the
//! visa service system such as actor joins/leaves. Operations in here
//! are not able to report back success/failure to the "caller".

use futures::stream::{self, StreamExt};
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

    /// The set of authorized services may have changed (an auth-service provider
    /// joined or left). Handler re-pushes the current auth-services list to all nodes.
    AuthServiceChange,

    /// Indicates that policy has been successfully updated. Pass the new `vinst`.
    PolicyUpdated(u64),
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
            VsEvent::AuthServiceChange => {
                if let Err(e) = handle_auth_service_change(&asm).await {
                    error!(target: EVENT, "failed to handle auth service change event: {}", e);
                }
            }
            VsEvent::PolicyUpdated(vinst) => {
                if let Err(e) = handle_policy_updated(&asm, vinst).await {
                    error!(target: EVENT, "failed to handle policy updated event: {}", e);
                }
            }
        }
    }
    info!(target: EVENT, "event manager shutting down");
}

/// TODO: Does not do anything yet.
async fn handle_actor_joins(_asm: &Arc<Assembly>, actor_addr: IpAddr) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor joined: {}", actor_addr);
    Ok(())
}

/// TODO: Does not do anything yet.
async fn handle_actor_leaves(
    _asm: &Arc<Assembly>,
    actor_addr: IpAddr,
    _reason: DisconnectReason,
) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor left: {}", actor_addr);
    Ok(())
}

// Re-push the current authorized-services list to all connected nodes. Triggered by
// `AuthServiceChange` when an auth-service provider has joined or left, so nodes always
// see the up-to-date list.
async fn handle_auth_service_change(asm: &Arc<Assembly>) -> Result<(), ServiceError> {
    let auth_services = asm.actor_mgr.get_auth_services_list(asm.clone()).await?;
    set_services_all_nodes(asm, &auth_services).await
}

/// Record an `AuthServiceChange` event, logging on failure. Call when the authorized
/// service set may have changed so the current list gets re-pushed to all nodes.
pub async fn record_auth_service_change(asm: &Arc<Assembly>) {
    if let Err(e) = asm.event_mgr.record_event(VsEvent::AuthServiceChange).await {
        error!(target: EVENT, "failed to record AuthServiceChange event: {}", e);
    }
}

/// If `addr` provides an auth service (per current policy and DB state), record an
/// `AuthServiceChange` event. Must be called while the actor is still present in the DB.
pub async fn record_auth_change_if_provider(asm: &Arc<Assembly>, addr: &IpAddr) {
    match asm.actor_mgr.has_auth_services(asm.clone(), addr).await {
        Ok(true) => record_auth_service_change(asm).await,
        Ok(false) => {}
        Err(e) => error!(target: EVENT, "has_auth_services check failed for {}: {}", addr, e),
    }
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

async fn handle_policy_updated(asm: &Arc<Assembly>, vinst: u64) -> Result<(), ServiceError> {
    /*

    https://github.com/org-zpr/zpr-visaservice/issues/219


    When we get here we have already updated policy.

    - are there any existing visas that need to be revoked.
       - do we have the 5-tuple or whatever so that we can check them? NO, this is a TODO.

    - check our existing topology.
       - Are all the nodes and links still valid?

    - request re-auth all nodes.

    - clear revocation list? May make more sense to keep it and make admin clear manually.

    - services -> ensure all services being offered are still allowed by policy.
       - What if an already connected adapter has a new service -> will need to re-connect?
       - We can do a basic check to see that all the services we have do exist in policy.
          - But that won't detect if a service has altered its provider.
          - TO BE SAFE: expire auth from all services - force re-auth of all existing services (after removing non-existing ones)

    - all connected adapters.  Are they still allowed?
       - Well we could expire all the auth, but that seems drastic.
       - Instead we will have already killed visas. Probably ok to let them be connected but unable to do anything.

     */

    // Grab one consistent policy snapshot and use it for the entire synchronize-to-policy
    // pass below, so revalidation and per-node link computation all read the same view.
    let psnap = asm.policy_mgr.get_current_snapshot();

    // PolicyUpdated(vinst) is a trigger, not a guarantee that this handler reconciles that
    // exact revision. If updates queue faster than we process them we reconcile against the
    // latest snapshot.
    let snapshot_vinst = psnap.vinst();
    if snapshot_vinst != vinst {
        info!(
            target: EVENT,
            "policy update event called with vinst={vinst}, using current snapshot vinst={snapshot_vinst}"
        );
    }

    info!(target: EVENT, "policy updated vinst={vinst}: TODO revalidate connected nodes");
    let connected_node_addrs = asm.actor_mgr.list_node_addrs().await?;

    // TODO: Check existing nodes against policy.
    // Until then  we just assume has not changed.
    // Once validated the `connected_node_addrs` will be in sync with policy. And we should have already removed the stale
    // nodes from the actor_mgr state, disconnected from VSS, etc.

    info!(target: EVENT, "policy updated vinst={vinst}: revalidating topology");
    let report = asm
        .topo_mgr
        .revalidate_against_policy(&psnap, &connected_node_addrs)
        .await?;
    info!(
        target: EVENT,
        "topology revalidated vinst={vinst}: removed={} updated={} repaired={} orphaned={}",
        report.links_removed,
        report.links_updated,
        report.links_repaired,
        report.orphaned_nodes.len()
    );

    // Queue up setTopology messages in parallel.
    let futs = connected_node_addrs.iter().filter_map(|naddr| {
        let links = psnap.links_for_node(naddr);
        asm.vss_mgr.get_handle(naddr).map(|vss_handle| async move {
            if let Err(e) = vss_handle.set_topology(links).await {
                error!(target: EVENT, "failed to set topology for node {}: {}", naddr, e);
            }
        })
    });
    futures::future::join_all(futs).await;

    Ok(())
}
