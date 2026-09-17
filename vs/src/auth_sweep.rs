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

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::assembly::Assembly;
use crate::db;
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

/// One sweep pass over the connected adapters. For each adapter whose
/// authentication expiration has passed: resolve its docking node, send a
/// `revokeAuthentication` for its ZPR address over that node's VSS, and —
/// **only on a positive ack** — log (with the gate: the credential that drove
/// the expiry) and remove the actor from the store. A missing VSS handle, an
/// error, or a timeout leaves the actor untouched for the next pass.
pub(crate) async fn sweep_expired_auths(asm: &Arc<Assembly>) -> SweepStats {
    let mut stats = SweepStats::default();

    let entries = match asm.actor_mgr.list_actors(Some(db::Role::Adapter)).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(target: ACTOR, "auth sweep: failed to list actors: {e}");
            return stats;
        }
    };

    let now = SystemTime::now();
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
        let Some(vss_handle) = asm.vss_mgr.get_handle(&node_addr) else {
            warn!(target: ACTOR, "auth sweep: no VSS handle for node {node_addr} (actor {addr}); deferring to next pass");
            stats.deferred += 1;
            continue;
        };

        // Revoke before drop; drop only on a positive ack, so a VSS outage
        // leaves the actor for the next pass rather than half-removing it.
        match vss_handle.revoke_auths(vec![addr]).await {
            Ok(_processed) => {
                info!(
                    target: ACTOR,
                    "authentication expired for actor {addr} (gate: {gate}); revoked on node {node_addr}, removing actor"
                );
                if let Err(e) = asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await {
                    warn!(target: ACTOR, "auth sweep: revoked {addr} but failed to remove actor: {e}");
                    continue;
                }
                stats.revoked += 1;
            }
            Err(e) => {
                warn!(target: ACTOR, "auth sweep: failed to revoke auths for {addr} on node {node_addr}: {e}; deferring to next pass");
                stats.deferred += 1;
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
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::make_adapter_actor;
    use crate::vss::VssCmd;
    use libeval::attribute::{Attribute, key};
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc;

    const NODE: &str = "fd5a:5052:3000::1";
    const ADAPTER: &str = "fd5a:5052:4000::a";

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
