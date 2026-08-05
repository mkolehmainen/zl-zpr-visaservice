//! Event Manager handles high-level events that have repurcussions around the
//! visa service system such as actor joins/leaves. Operations in here
//! are not able to report back success/failure to the "caller".

use futures::future::join_all;
use futures::stream::{self, StreamExt};

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use zpr::vsapi::v1::DisconnectReason;
use zpr::vsapi_types::ServiceDescriptor;

use libeval::eval::EvalContext;

use crate::assembly::Assembly;
use crate::error::ServiceError;
use crate::logging::targets::EVENT;
use crate::policy_mgr::PolicySnapshot;
use crate::visa_mgr::VisaRecheck;
use crate::visareq_worker::refresh_and_persist_actor;

#[derive(Debug)]
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

    /// The attribute data behind a trusted service changed (an admin refreshed it).
    /// Pass the source id. Handler refreshes the actors behind live visas and
    /// re-checks those visas against the refreshed attributes.
    TrustedServiceChange(String),
}

/// Why a visa sweep is running. The two reasons need different handling because an
/// attribute change does not move the policy generation, so the `checked_vinst`
/// gates that make the policy sweep idempotent would make an attribute sweep a
/// complete no-op.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SweepReason {
    /// A new policy was installed.
    PolicyUpdate,
    /// A trusted service's attribute data changed.
    AttributeChange,
}

#[derive(Clone)]
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
            VsEvent::TrustedServiceChange(source_id) => {
                handle_trusted_service_change(&asm, &source_id).await;
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

    - TODO: request re-auth all nodes.

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

    // The new policy may invalidate some existing nodes. An error here will bail on the
    // update handling.
    let (connected_node_addrs, invalid_node_addrs) = revalidate_nodes(asm, &psnap).await?;

    // Disconnect the nodes that are no longer approved by the new policy.
    for naddr in &invalid_node_addrs {
        info!(target: EVENT, "connected node {naddr} is no longer approved by policy, disconnecting");
        // Note that the following disconnect call will also update the topology manager.
        if let Err(e) = asm
            .cc
            .disconnect(asm.clone(), *naddr, DisconnectReason::Admin)
            .await
        {
            error!(target: EVENT, "error processing disconnect of {naddr}: {e}");
            // In this case we do not send an actor-leaves event.
            // What is the state of our topology manager now?
            // Visa service is porbably hosed.
        }
        // TODO: If ActorLeaves event ever does anything we may need it here.
    }

    // Only do these steps if we managed to get a set of connected nodes. If
    // there actually are no nodes connected at the moment, then topology should
    // have been (or will soon be) updated via other code paths.  The purpose of
    // updating the topology when presented with a new policy is to verify that
    // existing links are still allowed, and send out peer messages.
    if !connected_node_addrs.is_empty() {
        info!(target: EVENT, "policy updated vinst={vinst}: revalidating topology ({} nodes)", connected_node_addrs.len());
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
        join_all(futs).await;

        // A policy update can change the authorized-service set (a provider was
        // disconnected above, or policy reclassified a service). Re-push the current
        // list so surviving nodes stay in sync.
        if let Err(e) = handle_auth_service_change(asm).await {
            error!(target: EVENT, "failed to refresh auth services after policy update: {e}");
        }
    }

    // Re-check existing visas against the new policy. Runs last so route checks
    // and the nodes' own link state already reflect the updated topology.
    revalidate_visas(asm, &psnap, SweepReason::PolicyUpdate).await;

    Ok(())
}

/// A trusted service's attribute data changed (an admin refreshed it). The new data may
/// invalidate visas that were issued under the old data, so reconcile in two phases:
/// refresh and persist the actors behind live visas, then re-check those visas.
///
/// Phase order matters: the sweep re-reads actors from the store, so their attributes
/// have to be reconciled and written back first.
///
/// Note this only reconciles actors that hold a live visa. Everyone else is handled
/// lazily on their next visa request by the revision check in `refresh_expired_attributes`.
async fn handle_trusted_service_change(asm: &Arc<Assembly>, source_id: &str) {
    // One snapshot for the whole pass, same as the policy handler.
    let psnap = asm.policy_mgr.get_current_snapshot();

    let (refreshed, unresolved, failed) = refresh_actors_for_live_visas(asm).await;
    info!(
        target: EVENT,
        "trusted service '{source_id}' changed: actors refreshed={refreshed} unresolved={unresolved} failed={failed}"
    );

    revalidate_visas(asm, &psnap, SweepReason::AttributeChange).await;
}

/// Refresh (and persist) the attributes of every distinct actor referenced by a live
/// visa. Only sources that are TTL-expired or revision-stale are actually fetched, so
/// an actor already current costs nothing.
///
/// A failure is logged and skipped rather than aborting the pass: that actor's recorded
/// revision stays mismatched, so its next visa request refreshes it again.
///
/// Returns `(refreshed, unresolved, failed)` counts for logging.
async fn refresh_actors_for_live_visas(asm: &Arc<Assembly>) -> (u32, u32, u32) {
    let mut zpr_addrs: HashSet<IpAddr> = HashSet::new();
    for (_, md) in asm.visa_mgr.list_visa_metadata().await {
        zpr_addrs.insert(md.five_tuple.source_addr);
        zpr_addrs.insert(md.five_tuple.dest_addr);
    }

    let (mut refreshed, mut unresolved, mut failed) = (0u32, 0u32, 0u32);
    // Sequential for now, join_all it if sweeps ever get slow.
    for zpr_addr in zpr_addrs {
        match asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await {
            Ok(Some(mut actor)) => match refresh_and_persist_actor(asm, &mut actor).await {
                Ok(true) => refreshed += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!(target: EVENT, "attribute reconcile: failed to refresh actor {zpr_addr}: {e}");
                    failed += 1;
                }
            },
            Ok(None) => unresolved += 1,
            Err(e) => {
                warn!(target: EVENT, "attribute reconcile: failed to load actor {zpr_addr}: {e}");
                failed += 1;
            }
        }
    }
    (refreshed, unresolved, failed)
}

/// When we get a new policy, some nodes may no longer be valid. This checks each
/// connected node against the policy and partitions them into `(valid, invalid)`
/// addresses. It has no side effects -- disconnecting the invalid nodes is left to
/// the caller.
///
/// Note that the best way to revalidate a node is to prompt it to
/// re-authenticate. (TODO).
///
/// ### Errors
/// - The only error you get from this will be an error from `list_node_addrs`.
async fn revalidate_nodes(
    asm: &Arc<Assembly>,
    psnap: &PolicySnapshot,
) -> Result<(Vec<IpAddr>, Vec<IpAddr>), ServiceError> {
    let connected_node_addrs = asm.actor_mgr.list_node_addrs().await?;

    // Check existing nodes against policy.
    let ectx = EvalContext::new(psnap.policy_arc());

    let keep_flags = join_all(
        connected_node_addrs
            .iter()
            .map(|naddr| node_still_valid(asm, &ectx, naddr)),
    )
    .await;

    // Partition into still-valid and no-longer-valid nodes.
    let (valid, invalid): (Vec<_>, Vec<_>) = connected_node_addrs
        .into_iter()
        .zip(keep_flags)
        .partition(|(_, keep)| *keep);

    let valid = valid.into_iter().map(|(naddr, _)| naddr).collect();
    let invalid = invalid.into_iter().map(|(naddr, _)| naddr).collect();

    Ok((valid, invalid))
}

/// Pure predicate helper for [revalidate_nodes].
/// Loads the node `Actor` from the `actor_mgr` and uses the `EvalContext` to check that
/// the actor is still permitted by policy. Note this does not check authentication -- just
/// attributes that were authenticated under the previous policy.
///
/// Returns `true` if the node looks valid (including on any query/eval error, where we
/// optimistically keep the node), and `false` only if policy affirmatively rejects it.
async fn node_still_valid(asm: &Arc<Assembly>, ectx: &EvalContext, naddr: &IpAddr) -> bool {
    match asm.actor_mgr.get_actor_by_zpr_addr(naddr).await {
        Ok(Some(node_actor)) => match ectx.approve_connected(&node_actor) {
            Ok(approved) => approved,
            Err(e) => {
                warn!(target: EVENT, "failed to evaluate connected node {naddr} against policy: {e}");
                true
            }
        },
        // No actor came back for this address, or the query failed. Optimistically keep it.
        Ok(None) => true,
        Err(_) => true,
    }
}

/// Sweep every live visa and re-evaluate it against the given policy snapshot.
/// Denied visas (and visas whose route moved) are marked `PendingRevoke` on all
/// their nodes so VSS housekeeping revokes them.
///
/// Visas whose actors can't be resolved are skipped (not revoked). A verdict is
/// only applied while `target_vinst` is still the live policy generation —
/// otherwise a newer policy sweep is coming and will decide.
///
/// [SweepReason::PolicyUpdate] skips any visa already checked at/after
/// `target_vinst`, bumps `checked_vinst` on allow (canceling any older queued
/// revoke), and denies through the vinst-gated verdict recorder.
///
/// [SweepReason::AttributeChange] cannot use those gates: the policy generation has
/// not moved, so every visa looks "current". It checks every visa, revokes through
/// the ungated [VisaMgr::mark_visa_revoked], and does nothing at all on allow —
/// a revoke queued by an earlier attribute sweep stays queued, and the node simply
/// re-requests to get a fresh decision.
async fn revalidate_visas(asm: &Arc<Assembly>, psnap: &PolicySnapshot, reason: SweepReason) {
    let target_vinst = psnap.vinst();
    let snapshot = asm.visa_mgr.list_visa_metadata().await;

    // Some numbers for logging purposes.
    let total = snapshot.len();
    let mut allowed = 0u32;
    let mut revoked = 0u32;
    let mut skipped_stale = 0u32;
    let mut skipped_unresolved = 0u32;
    let mut skipped_current = 0u32;

    for (visa_id, metadata) in snapshot {
        // Only a policy sweep can skip on generation: an attribute change leaves the
        // generation alone, so this would skip everything.
        if reason == SweepReason::PolicyUpdate && metadata.checked_vinst >= target_vinst {
            skipped_current += 1;
            continue;
        }
        match asm
            .visa_mgr
            .recheck_visa_allowed(asm, &metadata, psnap)
            .await
        {
            Ok(VisaRecheck::SkipUnresolvedActor) => {
                skipped_unresolved += 1;
                debug!(target: EVENT, "visa sweep: visa {visa_id} actor unresolved, skipping");
            }
            Ok(VisaRecheck::AllowSameRoute) => {
                // An attribute sweep records nothing on allow: it must not bump
                // checked_vinst (that would make a later policy sweep skip the visa)
                // and it deliberately leaves any queued revoke in place.
                if reason == SweepReason::AttributeChange {
                    allowed += 1;
                    continue;
                }
                // Allowed. Only apply while target_vinst is still the live policy;
                // otherwise an older sweep could cancel a newer revoke verdict.
                if asm.policy_mgr.get_current_snapshot().vinst() != target_vinst {
                    skipped_stale += 1;
                    continue;
                }
                match asm
                    .visa_mgr
                    .record_allow_verdict(visa_id, target_vinst)
                    .await
                {
                    Ok(_) => allowed += 1,
                    Err(e) => {
                        warn!(target: EVENT, "visa sweep: failed to record allow for visa {visa_id}: {e}")
                    }
                }
            }
            Ok(VisaRecheck::Revoke) => {
                // Denied, or allowed but rerouted. Only apply while target_vinst
                // is still the live policy; otherwise a newer sweep is coming and
                // will make the decision.
                if asm.policy_mgr.get_current_snapshot().vinst() != target_vinst {
                    skipped_stale += 1;
                    continue;
                }
                // The verdict recorder is vinst-gated, so an attribute sweep has to
                // revoke through the ungated path.
                let res = match reason {
                    SweepReason::PolicyUpdate => {
                        asm.visa_mgr
                            .record_deny_verdict(visa_id, target_vinst)
                            .await
                    }
                    SweepReason::AttributeChange => asm.visa_mgr.mark_visa_revoked(visa_id).await,
                };
                match res {
                    Ok(_) => revoked += 1,
                    Err(e) => {
                        warn!(target: EVENT, "visa sweep: failed to record deny for visa {visa_id}: {e}")
                    }
                }
            }
            Err(e) => {
                warn!(target: EVENT, "visa sweep: error re-checking visa {visa_id}: {e}");
            }
        }
    }

    // Note that this sweep just manipulates the desired state of the visas. The
    // actual revocations happen asynchronously in VSS housekeeping.
    info!(
        target: EVENT,
        "visa sweep reason={reason:?} vinst={target_vinst}: total={total} allowed={allowed} revoked={revoked} skipped_stale={skipped_stale} skipped_unresolved={skipped_unresolved} skipped_current={skipped_current}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::tests::{make_policy, new_assembly_for_tests};
    use crate::config;
    use crate::test_helpers::{
        make_adapter_actor_defexp, make_container_bytes, make_node_actor_defexp,
    };
    use libeval::attribute::{Attribute, AttributeSource, key};
    use libeval::eval_result::{Direction, Hit};
    use libeval::route::{LinkId, Route};
    use std::time::Duration;
    use zpr::policy::v1 as capnp_policy;
    use zpr::policy_types::{JoinPolicy, PFlags, Scope, Service, ServiceType};
    use zpr::vsapi_types::PacketDesc;
    use zpr::write_to::WriteTo;

    /// Build a policy container whose single join policy marks connections as
    /// nodes. `provides` is the set of services a node must offer to stay valid
    /// (`None` = no service requirement). Conditions are empty, so the policy
    /// matches any actor's claims.
    fn make_node_join_policy(provides: Option<Vec<Service>>) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            let mut jp_list = policy_bldr.reborrow().init_join_policies(1);
            let mut jp_bldr = jp_list.reborrow().get(0);
            let jp = JoinPolicy {
                conditions: Vec::new(),
                flags: PFlags::node(false),
                provides,
            };
            jp.write_to(&mut jp_bldr);
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    /// Build a single-endpoint regular [Service] with the given id, for use as a
    /// policy-required service.
    fn svc(id: &str) -> Service {
        Service {
            id: id.to_string(),
            endpoints: vec![Scope {
                protocol: 0,
                flag: None,
                port: Some(4000),
                port_range: None,
            }],
            kind: ServiceType::Regular,
        }
    }

    /// Sort a vec of addrs so results can be compared order-independently
    /// (`list_node_addrs` order is not guaranteed).
    fn sorted(mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
        addrs.sort();
        addrs
    }

    /// All connected nodes satisfy the policy: all are returned and none disconnected.
    #[tokio::test]
    async fn test_revalidate_nodes_all_valid() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        // Any node is valid: node flag set, no required services.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();

        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052::2".parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::1", "node-a", "[fd5a:5052::101]:1234"),
                false,
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::2", "node-b", "[fd5a:5052::102]:1234"),
                false,
            )
            .await
            .unwrap();

        let psnap = asm.policy_mgr.get_current_snapshot();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap).await.unwrap();

        assert_eq!(sorted(valid), sorted(vec![a, b]));
        assert!(invalid.is_empty());
    }

    /// No node satisfies the default (join-policy-free) policy: the returned set is
    /// empty and every node is disconnected/removed.
    #[tokio::test]
    async fn test_revalidate_nodes_all_invalid() {
        // The default test-assembly policy has no join policies, so no node matches.
        let asm = Arc::new(new_assembly_for_tests(None).await);

        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052::2".parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::1", "node-a", "[fd5a:5052::101]:1234"),
                false,
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::2", "node-b", "[fd5a:5052::102]:1234"),
                false,
            )
            .await
            .unwrap();

        let psnap = asm.policy_mgr.get_current_snapshot();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap).await.unwrap();

        assert!(valid.is_empty());
        assert_eq!(sorted(invalid), sorted(vec![a, b]));
    }

    /// Mixed set under one snapshot: policy allows service "svc-x". A node whose
    /// services are a subset of the policy survives; a node offering an unlisted
    /// service ("svc-y") is disconnected. Guards the keep-flag/retain index alignment.
    #[tokio::test]
    async fn test_revalidate_nodes_mixed() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(Some(vec![svc("svc-x")])))
            .await
            .unwrap();

        let good: IpAddr = "fd5a:5052::1".parse().unwrap();
        let bad: IpAddr = "fd5a:5052::2".parse().unwrap();
        // Node that provides the required service → stays valid.
        let mut good_actor =
            make_node_actor_defexp("fd5a:5052::1", "node-good", "[fd5a:5052::101]:1234");
        good_actor
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(Duration::from_secs(3600))
                    .value("svc-x"),
            )
            .unwrap();
        asm.actor_mgr.add_node(&good_actor, false).await.unwrap();
        // Node offering a service the policy does not allow → invalid → disconnected.
        let mut bad_actor =
            make_node_actor_defexp("fd5a:5052::2", "node-bad", "[fd5a:5052::102]:1234");
        bad_actor
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(Duration::from_secs(3600))
                    .value("svc-y"),
            )
            .unwrap();
        asm.actor_mgr.add_node(&bad_actor, false).await.unwrap();

        let psnap = asm.policy_mgr.get_current_snapshot();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap).await.unwrap();

        assert_eq!(valid, vec![good]);
        assert_eq!(invalid, vec![bad]);
    }

    /// No connected nodes at all: returns an empty set without error.
    #[tokio::test]
    async fn test_revalidate_nodes_empty() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let psnap = asm.policy_mgr.get_current_snapshot();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap).await.unwrap();
        assert!(valid.is_empty());
        assert!(invalid.is_empty());
    }

    /// Build an assembly with two docked adapters (`::4000::a`/`::4000::b`) whose
    /// nodes are in the topology. `with_link` controls whether a route exists.
    /// The default (empty) policy denies everything (NoMatch), so with a route
    /// present the eval still denies — either way the sweep sees a deny.
    async fn build_sweep_asm(with_link: bool) -> (Arc<Assembly>, IpAddr) {
        let asm = new_assembly_for_tests(None).await;
        let node_a: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052:3000::1", "na", "10.0.0.1:1"),
                false,
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052:3000::2", "nb", "10.0.0.2:2"),
                false,
            )
            .await
            .unwrap();
        asm.topo_mgr.add_node(node_a).unwrap();
        asm.topo_mgr.add_node(node_b).unwrap();
        if with_link {
            asm.topo_mgr
                .add_link(node_a, node_b, LinkId("l".into()), vec![], 1)
                .unwrap();
        }
        asm.actor_mgr
            .add_adapter_via_node(
                &make_adapter_actor_defexp("fd5a:5052:4000::a", "src"),
                &node_a,
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(
                &make_adapter_actor_defexp("fd5a:5052:4000::b", "dst"),
                &node_b,
            )
            .await
            .unwrap();
        (Arc::new(asm), node_a)
    }

    /// Create a single-node visa held (PendingInstall) by `req` for the given
    /// five-tuple, seeded at `vinst`. Returns its id.
    async fn create_sweep_visa(asm: &Arc<Assembly>, req: &IpAddr, vinst: u64) -> u64 {
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 1234, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = Route::new_direct((*req).into());
        let vwmd = asm
            .visa_mgr
            .create_visa(asm, req, &pdesc, &hit, &route, "", 0, vinst)
            .await
            .unwrap();
        vwmd.visa.issuer_id
    }

    /// A denied visa is marked PendingRevoke on its holder node (target policy
    /// still live). Uses the no-route assembly so eval falls out as a deny.
    #[tokio::test]
    async fn test_sweep_denied_visa_marked_pending_revoke() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let id = create_sweep_visa(&asm, &node_a, 0).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        assert!(
            psnap.vinst() > 0,
            "target must exceed the visa's checked_vinst"
        );
        revalidate_visas(&asm, &psnap, SweepReason::PolicyUpdate).await;

        let revoke_ids = asm
            .visa_mgr
            .get_pending_revoke_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(revoke_ids, vec![id]);
    }

    /// A visa already checked at/after target_vinst is skipped before re-eval:
    /// even on the deny (no-route) assembly it is NOT marked PendingRevoke.
    #[tokio::test]
    async fn test_sweep_skips_already_checked() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let target = asm.policy_mgr.get_current_snapshot().vinst();
        // checked_vinst == target, so the guard skips before recheck.
        let id = create_sweep_visa(&asm, &node_a, target).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::PolicyUpdate).await;

        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty(),
            "already-checked visa must not be re-evaluated/revoked"
        );
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(pending, vec![id]);
    }

    /// An unresolvable actor leaves the visa untouched (skipped, not revoked).
    #[tokio::test]
    async fn test_sweep_unresolved_actor_leaves_visa_untouched() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        // Five-tuple addrs (::4000::a/b) have no actors in the DB → unresolved.
        let id = create_sweep_visa(&asm, &node, 0).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::PolicyUpdate).await;

        // Still held as PendingInstall (untouched); nothing marked for revoke.
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&node)
            .await
            .unwrap();
        assert_eq!(pending, vec![id]);
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A deny whose target vinst is no longer the live policy generation is
    /// skipped (a newer sweep is coming): no revoke is marked.
    #[tokio::test]
    async fn test_sweep_denied_but_stale_target_skips() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let id = create_sweep_visa(&asm, &node_a, 0).await;

        // Snapshot the current (stale) generation, then bump the live policy so
        // get_current_snapshot().vinst() moves past the snapshot's vinst.
        let stale_psnap = asm.policy_mgr.get_current_snapshot();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy("2024-01-02T00:00:00Z", 2, Some("m")))
            .await
            .unwrap();
        assert!(asm.policy_mgr.get_current_snapshot().vinst() > stale_psnap.vinst());

        revalidate_visas(&asm, &stale_psnap, SweepReason::PolicyUpdate).await;

        // No revoke marked; the visa stays PendingInstall.
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty()
        );
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(pending, vec![id]);
    }

    // ---- attribute-change sweep ----

    const TS_SOURCE: &str = "hr";
    const TS_KEY: &str = "user.dept";

    /// A trusted service whose vended attributes, revision, and failure mode are all
    /// settable, so a test can simulate "the external data changed" and "the service is
    /// down".
    struct MutableTrustedService {
        /// (key, value) pairs to vend; empty means the actor has no attributes here.
        attrs: std::sync::Mutex<Vec<(String, String)>>,
        fail: std::sync::atomic::AtomicBool,
        revision: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for MutableTrustedService {
        async fn get_attributes_for_actor(
            &self,
            _actor_ident: &str,
        ) -> Result<Vec<Attribute>, ServiceError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ServiceError::TrustedServiceInit("down".into()));
            }
            Ok(self
                .attrs
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    AttributeSource::new(TS_SOURCE)
                        .builder(k)
                        .expires_in(Duration::from_secs(600))
                        .value(v)
                })
                .collect())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            self.revision
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn current_revision(&self) -> u64 {
            self.revision.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn get_source_id(&self) -> &str {
            TS_SOURCE
        }
    }

    /// Register one [MutableTrustedService] vending `attrs` on the assembly, and return
    /// it so the test can change its data or knock it over.
    fn register_ts(asm: &Arc<Assembly>, attrs: &[(&str, &str)]) -> Arc<MutableTrustedService> {
        let svc = Arc::new(MutableTrustedService {
            attrs: std::sync::Mutex::new(
                attrs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            fail: std::sync::atomic::AtomicBool::new(false),
            revision: std::sync::atomic::AtomicU64::new(1),
        });
        asm.ts_mgr.update_services(vec![svc.clone()]);
        svc
    }

    /// Give the stored actor at `zpr_addr` an attribute from [TS_SOURCE], so the source
    /// counts as relevant to that actor (a source the actor holds nothing from and has no
    /// revision record for is not refreshed).
    async fn seed_source_attr(asm: &Arc<Assembly>, zpr_addr: &str, ts_key: &str, value: &str) {
        let addr: IpAddr = zpr_addr.parse().unwrap();
        let mut actor = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        actor
            .add_attribute(
                AttributeSource::new(TS_SOURCE)
                    .builder(ts_key)
                    .expires_in(Duration::from_secs(600))
                    .value(value),
            )
            .unwrap();
        asm.actor_mgr.update_actor(&actor).await.unwrap();
    }

    /// The stored actor's attribute values for `key`, if any.
    async fn stored_attr(asm: &Arc<Assembly>, zpr_addr: &str, attr_key: &str) -> Option<String> {
        let addr: IpAddr = zpr_addr.parse().unwrap();
        let actor = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        actor
            .attrs_iter()
            .find(|a| a.get_key() == attr_key)
            .map(|a| a.get_value_as_string())
    }

    /// The core case: an attribute sweep re-checks (and revokes) a visa whose
    /// `checked_vinst` already equals the live generation -- exactly what the policy
    /// sweep skips, at both the sweep and the store layer.
    #[tokio::test]
    async fn test_attr_sweep_revokes_visa_at_current_vinst() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let target = asm.policy_mgr.get_current_snapshot().vinst();
        let id = create_sweep_visa(&asm, &node_a, target).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::AttributeChange).await;

        let revoke_ids = asm
            .visa_mgr
            .get_pending_revoke_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(revoke_ids, vec![id]);

        // The attribute sweep must not touch the policy generation it was checked at.
        let md = asm.visa_mgr.list_visa_metadata().await;
        assert_eq!(md.len(), 1);
        assert_eq!(md[0].1.checked_vinst, target);
    }

    /// An attribute sweep holding a snapshot older than the live policy applies nothing:
    /// a policy sweep is already coming and will decide.
    #[tokio::test]
    async fn test_attr_sweep_stale_target_skips() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let id = create_sweep_visa(&asm, &node_a, 0).await;

        let stale_psnap = asm.policy_mgr.get_current_snapshot();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy("2024-01-02T00:00:00Z", 2, Some("m")))
            .await
            .unwrap();

        revalidate_visas(&asm, &stale_psnap, SweepReason::AttributeChange).await;

        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            asm.visa_mgr
                .get_pending_visa_ids_for_node(&node_a)
                .await
                .unwrap(),
            vec![id]
        );
    }

    /// An unresolvable actor is skipped by the attribute sweep too, never revoked.
    #[tokio::test]
    async fn test_attr_sweep_unresolved_actor_leaves_visa_untouched() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let id = create_sweep_visa(&asm, &node, 0).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::AttributeChange).await;

        assert_eq!(
            asm.visa_mgr
                .get_pending_visa_ids_for_node(&node)
                .await
                .unwrap(),
            vec![id]
        );
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Phase A: handling the event refreshes the stored actors behind live visas from the
    /// changed service -- replacing a changed value and dropping an attribute the service
    /// no longer vends.
    #[tokio::test]
    async fn test_trusted_service_change_refreshes_stored_actors() {
        let (asm, node_a) = build_sweep_asm(false).await;
        create_sweep_visa(&asm, &node_a, 0).await;
        let svc = register_ts(&asm, &[(TS_KEY, "engineering")]);
        // What the actor holds from the old data: one value that changes, one that goes away.
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;
        seed_source_attr(&asm, "fd5a:5052:4000::a", "user.badge", "b-1").await;

        // The external data changed and the service was reloaded.
        *svc.attrs.lock().unwrap() = vec![(TS_KEY.to_string(), "engineering".to_string())];
        {
            use crate::trusted_services::TrustedServiceInterface;
            svc.flush().await.unwrap();
        }

        handle_trusted_service_change(&asm, TS_SOURCE).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("engineering".to_string()),
            "changed value must be refreshed in the store"
        );
        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", "user.badge").await,
            None,
            "attribute no longer vended must be pruned"
        );
    }

    /// Phase A fails closed: if the changed service cannot be reached, its attributes are
    /// stripped from the stored actor rather than left to satisfy a policy on their
    /// unexpired TTL.
    #[tokio::test]
    async fn test_trusted_service_change_strips_attrs_when_service_fails() {
        let (asm, node_a) = build_sweep_asm(false).await;
        create_sweep_visa(&asm, &node_a, 0).await;
        let svc = register_ts(&asm, &[(TS_KEY, "engineering")]);
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;

        svc.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        handle_trusted_service_change(&asm, TS_SOURCE).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            None,
            "unreachable service must not leave stale attributes in place"
        );
    }

    /// An actor with no live visa is left alone: it reconciles lazily on its next visa
    /// request instead.
    #[tokio::test]
    async fn test_trusted_service_change_ignores_actors_without_visas() {
        let (asm, _node_a) = build_sweep_asm(false).await;
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;

        // No visa created, so no actor is in scope for the refresh.
        handle_trusted_service_change(&asm, TS_SOURCE).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("sales".to_string())
        );
    }
}
