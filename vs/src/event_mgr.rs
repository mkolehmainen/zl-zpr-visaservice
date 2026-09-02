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

use crate::actor_attributes::refresh_actors;
use crate::assembly::Assembly;
use crate::error::ServiceError;
use crate::logging::targets::EVENT;
use crate::policy_mgr::PolicySnapshot;
use crate::visa_reconciler::{SweepReason, revalidate_visas};

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
    /// Handler reconciles *all* stale or TTL-expired trusted attributes on the actors
    /// behind live visas, then re-checks those visas. Deliberately not scoped to the
    /// source that changed: `stale_sources_for_actor` already narrows the fetch to
    /// sources whose revision actually moved, so a source id would buy nothing.
    TrustedServiceChange,
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
            VsEvent::TrustedServiceChange => {
                handle_trusted_service_change(&asm).await;
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
    When we get here we have already updated policy.

    - TODO: request re-auth all nodes.

    - clear revocation list? May make more sense to keep it and make admin clear manually.

    - services -> ensure all services being offered are still allowed by policy.
       - What if an already connected adapter has a new service -> will need to re-connect?
       - We can do a basic check to see that all the services we have do exist in policy.
          - But that won't detect if a service has altered its provider.
          - TO BE SAFE: expire auth from all services - force re-auth of all existing services (after removing non-existing ones)
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

    // Reconcile attributes before anything reads them. Both consumers below --
    // node revalidation and the visa sweep -- evaluate actors exactly as stored, so
    // a stale actor is judged on the previous store's data. Nothing between here and
    // the sweep mutates attributes, so this one pass covers both.
    //
    // Only actors that are actually stale cost a fetch: `PolicyMgr::build_state`
    // carries unchanged trusted-service stores (and their revisions) across a policy
    // install, so this is a no-op unless the policy changed a trusted-service.
    //
    // TODO: When a declaration does change, this refetches every source for every
    // actor in the set, sequentially -- an N x M synchronous fan-out on the event
    // handler's critical path. Once services are network-backed and actor/visa counts
    // are large this is going to be an issue.
    let connected_node_addrs = asm.actor_mgr.list_node_addrs().await?;
    let mut refresh_set = live_visa_actor_addrs(asm).await;
    refresh_set.extend(connected_node_addrs.iter().copied());
    let (refreshed, unresolved, failed) = refresh_actors(asm, refresh_set).await;
    info!(
        target: EVENT,
        "policy updated vinst={vinst}: actors refreshed={refreshed} unresolved={unresolved} failed={failed}"
    );

    // The new policy may invalidate some existing nodes.
    let (valid_node_addrs, invalid_node_addrs) =
        revalidate_nodes(asm, &psnap, connected_node_addrs).await;

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
    }

    // Only do these steps if we managed to get a set of connected nodes. If
    // there actually are no nodes connected at the moment, then topology should
    // have been (or will soon be) updated via other code paths.  The purpose of
    // updating the topology when presented with a new policy is to verify that
    // existing links are still allowed, and send out peer messages.
    if !valid_node_addrs.is_empty() {
        info!(target: EVENT, "policy updated vinst={vinst}: revalidating topology ({} nodes)", valid_node_addrs.len());
        let report = asm
            .topo_mgr
            .revalidate_against_policy(&psnap, &valid_node_addrs)
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
        let futs = valid_node_addrs.iter().filter_map(|naddr| {
            let peers = psnap.resolved_peers_for_node(naddr);
            // Same snapshot the peers came from: the worker builds the wire Links and
            // mints bootstrap visas off it.
            let policy = psnap.policy_arc();
            asm.vss_mgr.get_handle(naddr).map(|vss_handle| async move {
                if let Err(e) = vss_handle.set_topology(peers, policy).await {
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

/// A trusted service's attribute data changed (eg, an admin refreshed it). The
/// new data may invalidate visas that were issued under the old data, so
/// reconcile in two phases: refresh and persist the actors behind live visas,
/// then re-check those visas.
///
/// Phase order matters: the sweep re-reads actors from the store, so their
/// attributes have to be reconciled and written back first.
///
/// Note this only reconciles actors that hold a live visa. Everyone else is
/// handled lazily on their next visa request by the revision check in
/// `refresh_expired_attributes`.
async fn handle_trusted_service_change(asm: &Arc<Assembly>) {
    // One snapshot for the whole pass, same as the policy handler.
    let psnap = asm.policy_mgr.get_current_snapshot();

    let (refreshed, unresolved, failed) =
        refresh_actors(asm, live_visa_actor_addrs(asm).await).await;
    info!(
        target: EVENT,
        "trusted service changed: actors refreshed={refreshed} unresolved={unresolved} failed={failed}"
    );

    revalidate_visas(asm, &psnap, SweepReason::AttributeChange).await;
}

/// The distinct actor addresses referenced by a live visa (both ends of every visa's
/// five-tuple). The reconcile set for a sweep that only re-checks visas.
async fn live_visa_actor_addrs(asm: &Arc<Assembly>) -> HashSet<IpAddr> {
    let mut zpr_addrs: HashSet<IpAddr> = HashSet::new();
    for (_, md) in asm.visa_mgr.list_visa_metadata().await {
        zpr_addrs.insert(md.five_tuple.source_addr);
        zpr_addrs.insert(md.five_tuple.dest_addr);
    }
    zpr_addrs
}

/// When we get a new policy, some nodes may no longer be valid. This checks each of
/// `connected_node_addrs` against the policy and partitions them into `(valid, invalid)`
/// addresses. It has no side effects -- disconnecting the invalid nodes is left to
/// the caller.
///
/// The caller supplies the address list because it also needs it to reconcile those
/// nodes' attributes first; the evaluation below reads the actors as stored.
///
/// Note that the best way to revalidate a node is to prompt it to
/// re-authenticate. (TODO).
async fn revalidate_nodes(
    asm: &Arc<Assembly>,
    psnap: &PolicySnapshot,
    connected_node_addrs: Vec<IpAddr>,
) -> (Vec<IpAddr>, Vec<IpAddr>) {
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

    (valid, invalid)
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::tests::new_assembly_for_tests;
    use crate::config;
    use crate::test_helpers::{
        TS_KEY, build_sweep_asm, create_sweep_visa, make_container_bytes, make_node_actor_defexp,
        register_ts, seed_source_attr, stored_attr,
    };
    use libeval::attribute::{Attribute, key};
    use std::time::Duration;
    use zpr::policy::v1 as capnp_policy;
    use zpr::policy_types::{JoinPolicy, PFlags, Scope, Service, ServiceType};
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
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;

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
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;

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
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;

        assert_eq!(valid, vec![good]);
        assert_eq!(invalid, vec![bad]);
    }

    /// No connected nodes at all: returns an empty set without error.
    #[tokio::test]
    async fn test_revalidate_nodes_empty() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let psnap = asm.policy_mgr.get_current_snapshot();
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;
        assert!(valid.is_empty());
        assert!(invalid.is_empty());
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

        handle_trusted_service_change(&asm).await;

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
        handle_trusted_service_change(&asm).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            None,
            "unreachable service must not leave stale attributes in place"
        );
    }

    /// A policy update reconciles the actors behind live visas before it sweeps them.
    /// The actor here is revision-stale against the registered store (it has no recorded
    /// revision for it); the sweep re-reads actors from the store, and would otherwise
    /// judge them on the attributes seeded below.
    #[tokio::test]
    async fn test_policy_update_refreshes_stored_actors_before_sweep() {
        let (asm, node_a) = build_sweep_asm(false).await;
        // A policy the connected nodes still satisfy, so revalidation keeps them (and
        // their docked adapters) rather than disconnecting everything out from under us.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();
        create_sweep_visa(&asm, &node_a, 0).await;
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        // What the actor holds from the previous store's data.
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;

        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        handle_policy_updated(&asm, vinst).await.unwrap();

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("engineering".to_string()),
            "policy update must reconcile attributes before the visa sweep reads actors"
        );
    }

    /// A connected node is reconciled even though it holds no visa: `revalidate_nodes`
    /// judges it on its stored attributes, so those have to be current first. The
    /// live-visa refresh alone did not cover this (item 1 in ts-followups.md).
    #[tokio::test]
    async fn test_policy_update_refreshes_connected_nodes_without_visas() {
        let (asm, _node_a) = build_sweep_asm(false).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        // No visa anywhere, so the node is in scope only via the node-address list.
        seed_source_attr(&asm, "fd5a:5052:3000::1", TS_KEY, "sales").await;

        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        handle_policy_updated(&asm, vinst).await.unwrap();

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:3000::1", TS_KEY).await,
            Some("engineering".to_string()),
            "policy update must reconcile connected nodes before revalidating them"
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
        handle_trusted_service_change(&asm).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("sales".to_string())
        );
    }
}
