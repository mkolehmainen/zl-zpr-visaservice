//! Periodic authentication-expiry sweep: find connected adapter actors whose
//! authentication has expired, revoke their authentications on the docking
//! node's VSS, and drop them from the actor store — but only after the node
//! positively acks the revocation, so a VSS outage just defers the removal to
//! the next pass.
//!
//! Like `visa_reconciler::revalidate_visas`, the pass is a plain async fn the
//! spawned loop calls, so tests drive single passes directly — no timers in
//! tests. Node actors are out of scope (operator decision on zipline#44):
//! expired nodes are culled at startup by `actor_mgr::refresh_state`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::assembly::Assembly;
use crate::db;
use crate::event_mgr;
use crate::logging::targets::ACTOR;

/// What one sweep pass did, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SweepStats {
    /// Actors examined.
    pub checked: usize,
    /// Actors revoked on their docking node and removed from the store.
    pub revoked: usize,
    /// Expired actors left in place for the next pass (no VSS handle, or the
    /// revocation was not positively acked).
    pub deferred: usize,
}

/// One sweep pass over the connected adapters, in two phases. Phase 1 walks
/// the adapters and collects every one whose authentication expiration has
/// passed, grouped by docking node. Phase 2 sends **one batched**
/// `revokeAuthentication` per docking node (PR #20 review: N expired adapters
/// behind one unresponsive node cost the pass one RPC timeout, not N), and —
/// **only on a positive ack** — logs (with the gate: the credential that drove
/// the expiry) and removes the batch's actors from the store. A missing VSS
/// handle, an error, or a timeout leaves the batch untouched for the next pass.
pub(crate) async fn sweep_expired_auths(asm: &Arc<Assembly>) -> SweepStats {
    let mut stats = SweepStats::default();

    let entries = match asm.actor_mgr.list_actors(Some(db::Role::Adapter)).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(target: ACTOR, "auth sweep: failed to list actors: {e}");
            return stats;
        }
    };

    /// An adapter phase 1 found expired: its snapshot expiry and the gate
    /// (credential key) that drove it. The expiry snapshot is re-checked
    /// against the store after the revoke ack, so a concurrent renewal wins;
    /// the gate is for logging at removal time.
    struct Expired {
        addr: IpAddr,
        expiry: SystemTime,
        gate: String,
    }

    // Phase 1: collect expired adapters per docking node.
    let now = SystemTime::now();
    let mut by_node: BTreeMap<IpAddr, Vec<Expired>> = BTreeMap::new();
    for (addr, _cn) in entries {
        let actor = match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
            Ok(Some(actor)) => actor,
            Ok(None) => continue, // Removed between list and fetch.
            Err(e) => {
                warn!(target: ACTOR, "auth sweep: failed to load actor {addr}: {e}");
                continue;
            }
        };
        stats.checked += 1;

        // No expiration means no authentication to expire; in-window means fine.
        let Some((expiry, gate)) = actor.get_authentication_expiration_with_gate() else {
            continue;
        };
        if expiry > now {
            continue;
        }

        let Some(node_addr) = asm.actor_mgr.get_docking_node_for_actor(&actor) else {
            warn!(target: ACTOR, "auth sweep: no docking node for expired actor {addr}; deferring to next pass");
            stats.deferred += 1;
            continue;
        };
        by_node
            .entry(node_addr)
            .or_default()
            .push(Expired { addr, expiry, gate });
    }

    // Phase 2: one batched revoke per docking node; drop the batch's actors
    // only on a positive ack, so a VSS outage leaves them for the next pass
    // rather than half-removing them.
    for (node_addr, expired) in by_node {
        let Some(vss_handle) = asm.vss_mgr.get_handle(&node_addr) else {
            warn!(
                target: ACTOR,
                "auth sweep: no VSS handle for node {node_addr} ({} expired actor(s)); deferring to next pass",
                expired.len()
            );
            stats.deferred += expired.len();
            continue;
        };

        let addrs: Vec<IpAddr> = expired.iter().map(|e| e.addr).collect();
        match vss_handle.revoke_auths(addrs).await {
            Ok(_processed) => {
                for Expired { addr, expiry, gate } in expired {
                    // Serialize against a concurrent reauthorization (PR #20
                    // review): the expiry decision was made on a pre-RPC
                    // snapshot, and `reauthorize_actor` may have renewed the
                    // actor while the revoke ack was in flight. Re-load the
                    // stored actor and remove it only if its authentication
                    // expiration still matches the expired snapshot; a renewed
                    // actor stays, and its (revoked-then-renewed) node-side
                    // auth is re-established by its own reauth flow.
                    let stored_expiry = match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
                        Ok(Some(actor)) => actor
                            .get_authentication_expiration_with_gate()
                            .map(|(exp, _gate)| exp),
                        Ok(None) => continue, // Already removed concurrently.
                        Err(e) => {
                            warn!(target: ACTOR, "auth sweep: revoked {addr} but failed to re-load actor: {e}; deferring to next pass");
                            stats.deferred += 1;
                            continue;
                        }
                    };
                    if stored_expiry != Some(expiry) {
                        info!(
                            target: ACTOR,
                            "auth sweep: actor {addr} was reauthorized while the revoke was in flight (stored expiration changed); keeping actor"
                        );
                        continue;
                    }
                    info!(
                        target: ACTOR,
                        "authentication expired for actor {addr} (gate: {gate}); revoked on node {node_addr}, removing actor"
                    );
                    // Mirror the disconnect path (PR #20 review): detect
                    // whether this actor provides an authentication service
                    // *while it is still in the DB* — the check needs the
                    // actor's service list — and record `AuthServiceChange`
                    // after removal, so nodes re-pull the authorized-services
                    // list and stop advertising the revoked provider.
                    let was_auth_provider = matches!(
                        asm.actor_mgr.has_auth_services(asm.clone(), &addr).await,
                        Ok(true)
                    );
                    if let Err(e) = asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await {
                        warn!(target: ACTOR, "auth sweep: revoked {addr} but failed to remove actor: {e}");
                        continue;
                    }
                    if was_auth_provider {
                        event_mgr::record_auth_service_change(asm).await;
                    }
                    stats.revoked += 1;
                }
            }
            Err(e) => {
                warn!(
                    target: ACTOR,
                    "auth sweep: failed to revoke auths for {} actor(s) on node {node_addr}: {e}; deferring to next pass",
                    expired.len()
                );
                stats.deferred += expired.len();
            }
        }
    }

    if stats.revoked > 0 || stats.deferred > 0 {
        debug!(
            target: ACTOR,
            "auth sweep: checked {} actors, revoked {}, deferred {}",
            stats.checked, stats.revoked, stats.deferred
        );
    }
    stats
}

/// Run [sweep_expired_auths] every `period` in a background task, mirroring
/// `KeySource::spawn_refresher` (`oidc/jwks.rs`). A pass never fails as such —
/// per-actor trouble is logged and deferred inside the sweep — so the loop just
/// sleeps and sweeps. Callers pass [crate::config::MIN_VISA_LIFETIME]: fine-
/// grained enough that a revocation lands inside the shortest visa lifetime.
pub(crate) fn spawn_auth_expiry_sweeper(asm: Arc<Assembly>, period: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            sweep_expired_auths(&asm).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::Assembly;
    use crate::assembly::tests::{new_assembly_for_tests, new_assembly_with_event_rx};
    use crate::config;
    use crate::event_mgr::VsEvent;
    use crate::test_helpers::{make_actor_with_services, make_adapter_actor, make_container_bytes};
    use crate::vss::VssCmd;
    use libeval::attribute::{Attribute, ROLE_ADAPTER, key};
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use zpr::policy_types::{JoinPolicy, PFlags, Scope, Service, ServiceType};
    use zpr::write_to::WriteTo;

    const NODE: &str = "fd5a:5052:3000::1";
    const ADAPTER: &str = "fd5a:5052:4000::a";

    /// Policy container bytes declaring one Authentication service with the
    /// given id (same shape as the visareq_worker test helper).
    fn make_policy_with_auth_service(service_id: &str) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<zpr::policy::v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(2);
            policy_bldr.set_metadata("");

            let mut jp_list = policy_bldr.reborrow().init_join_policies(1);
            let mut jp_bldr = jp_list.reborrow().get(0);
            let jp = JoinPolicy {
                conditions: Vec::new(),
                flags: PFlags::default(),
                provides: Some(vec![Service {
                    id: service_id.to_string(),
                    endpoints: vec![Scope {
                        protocol: 0,
                        flag: None,
                        port: Some(4000),
                        port_range: None,
                    }],
                    kind: ServiceType::Authentication,
                }]),
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

    /// Add an adapter docked at `node` whose device authority expires in
    /// `auth_expires_in` (zero = already expired by sweep time).
    async fn add_adapter_with_auth(
        asm: &Arc<Assembly>,
        zpr_addr: &str,
        node: &IpAddr,
        auth_expires_in: Duration,
    ) {
        let mut actor = make_adapter_actor(zpr_addr, "sweep-test", Duration::from_secs(3600));
        actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(auth_expires_in)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&actor, node)
            .await
            .unwrap();
    }

    /// Install a fake VSS handle for `node` whose worker answers every
    /// `RevokeAuthsByZprAddr` per `ok`, recording the addr batches it saw.
    fn install_fake_vss(
        asm: &Arc<Assembly>,
        node: IpAddr,
        ok: bool,
    ) -> Arc<Mutex<Vec<Vec<IpAddr>>>> {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node, cmd_tx);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_task = seen.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                if let VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx) = cmd {
                    seen_task.lock().unwrap().push(addrs.clone());
                    let resp = if ok {
                        Ok(addrs.len())
                    } else {
                        Err(crate::error::VssSyncError::Timeout("test".to_string()))
                    };
                    let _ = resp_tx.send(resp);
                }
            }
        });
        seen
    }

    /// An adapter past its authentication expiry is revoked by one pass —
    /// the docking node's VSS sees the revoke — and is gone afterwards.
    #[tokio::test]
    async fn test_sweep_revokes_and_drops_expired_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 1, "one expired actor must be revoked");
        assert_eq!(stats.deferred, 0);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[vec![adapter]],
            "the docking node's VSS must see exactly the expired addr"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_none(),
            "the actor must be gone after a positive ack"
        );
    }

    /// An adapter still inside its authentication window is untouched: no
    /// revoke sent, actor still present.
    #[tokio::test]
    async fn test_sweep_leaves_in_window_actor_untouched() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::from_secs(3600)).await;
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 0);
        assert!(seen.lock().unwrap().is_empty(), "no revoke may be sent");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A VSS outage during a sweep leaves the actor for the next pass rather
    /// than half-removing it: no handle for the docking node, and a handle
    /// answering Err, both defer; a later pass with an acking handle removes it.
    #[tokio::test]
    async fn test_sweep_vss_outage_leaves_actor_for_next_pass() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;

        // Pass 1: no handle at all for the docking node.
        let stats = sweep_expired_auths(&asm).await;
        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 1, "missing handle must defer, not remove");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some(),
            "actor must survive a missing-handle pass"
        );

        // Pass 2: a handle that answers Err.
        let seen_err = install_fake_vss(&asm, node, false);
        let stats = sweep_expired_auths(&asm).await;
        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 1, "an Err ack must defer, not remove");
        assert_eq!(
            seen_err.lock().unwrap().len(),
            1,
            "the revoke was attempted"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some(),
            "actor must survive an Err pass"
        );

        // Pass 3: an acking handle finally removes it.
        let seen_ok = install_fake_vss(&asm, node, true);
        let stats = sweep_expired_auths(&asm).await;
        assert_eq!(stats.revoked, 1);
        assert_eq!(seen_ok.lock().unwrap().as_slice(), &[vec![adapter]]);
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An actor with no authentication expiration at all (no authority and no
    /// identity attributes) is skipped entirely.
    #[tokio::test]
    async fn test_sweep_skips_actor_without_expiration() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        // Plain adapter: role/CN/zpr-addr only — get_authentication_expiration() is None.
        let actor = make_adapter_actor(ADAPTER, "no-auth", Duration::ZERO);
        asm.actor_mgr
            .add_adapter_via_node(&actor, &node)
            .await
            .unwrap();
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 0);
        assert!(seen.lock().unwrap().is_empty());
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Two expired adapters docked at the same node are revoked with ONE
    /// batched `revokeAuthentication` RPC (PR #20 review): an unresponsive
    /// node costs the pass one RPC timeout, not one per expired adapter.
    #[tokio::test]
    async fn test_sweep_batches_expired_actors_per_node() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter_a: IpAddr = ADAPTER.parse().unwrap();
        let adapter_b: IpAddr = "fd5a:5052:4000::b".parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;
        add_adapter_with_auth(&asm, "fd5a:5052:4000::b", &node, Duration::ZERO).await;
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 2, "both expired actors must be revoked");
        assert_eq!(stats.deferred, 0);
        let batches = seen.lock().unwrap().clone();
        assert_eq!(
            batches.len(),
            1,
            "one docking node must see exactly one batched revoke, got {batches:?}"
        );
        let mut batch = batches[0].clone();
        batch.sort();
        let mut expected = vec![adapter_a, adapter_b];
        expected.sort();
        assert_eq!(batch, expected, "the batch must carry both expired addrs");
        for addr in [adapter_a, adapter_b] {
            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&addr)
                    .await
                    .unwrap()
                    .is_none(),
                "actor {addr} must be gone after the batched ack"
            );
        }
    }

    /// A renewal that lands while the sweep is awaiting the revoke ack wins
    /// (PR #20 review): the sweep re-checks the stored authentication
    /// expiration against its pre-RPC snapshot and must NOT remove an actor
    /// whose authentication was concurrently renewed by `reauthorize_actor`.
    #[tokio::test]
    async fn test_sweep_skips_actor_renewed_during_revoke() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;

        // Fake VSS that renews the actor's device authority *while the sweep
        // awaits the revoke ack*, then acks OK — the reauthorize race.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node, cmd_tx);
        let asm_task = asm.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                if let VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx) = cmd {
                    let renewed_addr: IpAddr = ADAPTER.parse().unwrap();
                    let mut actor = asm_task
                        .actor_mgr
                        .get_actor_by_zpr_addr(&renewed_addr)
                        .await
                        .unwrap()
                        .expect("actor must still exist during the revoke");
                    actor
                        .add_attribute(
                            Attribute::builder(key::DEVICE_AUTHORITY)
                                .expires_in(Duration::from_secs(3600))
                                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
                        )
                        .unwrap();
                    asm_task.actor_mgr.update_actor(&actor).await.unwrap();
                    let _ = resp_tx.send(Ok(addrs.len()));
                }
            }
        });

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(
            stats.revoked, 0,
            "a concurrently renewed actor must not be counted revoked"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some(),
            "the renewed actor must survive the sweep"
        );
    }

    /// Removing an expired actor that provides an authentication service must
    /// record `AuthServiceChange` (PR #20 review), mirroring the disconnect
    /// path: the provider check runs while the actor is still in the DB, the
    /// event after removal, so nodes re-pull the authorized-services list and
    /// stop advertising the revoked provider.
    #[tokio::test]
    async fn test_sweep_records_auth_service_change_for_expired_provider() {
        let (asm_inner, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm_inner);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();

        // Policy declares `svc:auth` as an Authentication service...
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_auth_service("svc:auth"))
            .await
            .unwrap();
        // ...and the expired adapter provides it (long-lived identity attr,
        // expired device authority drives the sweep).
        let mut actor = make_actor_with_services(
            ROLE_ADAPTER,
            ADAPTER,
            &["svc:auth"],
            "auth-provider",
            Duration::from_secs(3600),
        );
        actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(Duration::ZERO)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&actor, &node)
            .await
            .unwrap();
        let _seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 1, "the expired provider must be revoked");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_none()
        );
        let mut saw_auth_change = false;
        while let Ok(evt) = event_rx.try_recv() {
            if matches!(evt, VsEvent::AuthServiceChange) {
                saw_auth_change = true;
            }
        }
        assert!(
            saw_auth_change,
            "removing an auth-service provider must record AuthServiceChange"
        );
    }

    /// The spawned periodic task removes an expired actor without any direct
    /// call to the sweep: spawn with a millisecond period against the fake-VSS
    /// assembly and await removal with a bounded timeout (two-ish periods).
    #[tokio::test]
    async fn test_sweeper_task_removes_expired_actor_within_two_periods() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;
        let _seen = install_fake_vss(&asm, node, true);

        let handle = spawn_auth_expiry_sweeper(asm.clone(), Duration::from_millis(20));

        let removed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if asm
                    .actor_mgr
                    .get_actor_by_zpr_addr(&adapter)
                    .await
                    .unwrap()
                    .is_none()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        handle.abort();
        assert!(
            removed.is_ok(),
            "the periodic sweeper must remove the expired actor within the timeout"
        );
    }
}
