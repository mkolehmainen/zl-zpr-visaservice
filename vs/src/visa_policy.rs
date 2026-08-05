//! Shared policy-evaluation core: given two resolved actors and a packet, decide
//! whether policy permits the flow and over which route.
//!
//! This is deliberately neutral ground. Both the visa-request path
//! (`visareq_worker`) and the visa sweep (`visa_reconciler`, via
//! `visa_mgr::recheck_visa_allowed`) run through here so a re-check applies
//! exactly the same rules as the original decision. Actor *resolution* is not
//! part of this -- that stays per-caller, since the request path fabricates AAA
//! actors and denies on missing ones while the sweep does neither.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use libeval::actor::Actor;
use libeval::eval::EvalContext;
use libeval::eval_result::{FinalDeny, FinalEvalResult, Hit, PartialEvalResult};
use libeval::policy::Policy;
use libeval::route::Route;

use tracing::{info, warn};
use zpr::vsapi_types::{DenyCode, PacketDesc};

use crate::assembly::Assembly;
use crate::error::ServiceError;
use crate::logging::targets::VREQ;

/// Outcome of running resolved actors and a packet through policy (docking-node
/// resolution, routing, and eval). Shared by the request path and the
/// policy-update visa sweep so both run identical policy logic.
pub(crate) enum PolicyOutcome {
    // default_route: None => route came from the hit (NeedsRoute-allow);
    // Some(best) => the AllowWithoutRoute case.
    Allow {
        hits: Vec<Hit>,
        default_route: Option<Route>,
    },
    Deny(DenyCode),
}

/// Resolve an actor's docking node: the connection-table entry, falling back to
/// the AAA table for fabricated anonymous actors. `None` means undocked.
fn resolve_docking_node(asm: &Assembly, actor: &Actor, zpr_addr: &IpAddr) -> Option<IpAddr> {
    asm.actor_mgr
        .get_docking_node_for_actor(actor)
        .or_else(|| asm.actor_mgr.get_docking_node_for_aaa(zpr_addr))
}

/// Shared policy-evaluation core: resolve both docking nodes, require a route,
/// then run the actors and packet through the policy (handling `NeedsRoute` route
/// evaluation). An undocked endpoint or no best route falls out as `Deny`.
pub(crate) async fn evaluate_against_policy(
    asm: &Assembly,
    src: &Actor,
    dst: &Actor,
    src_zpr: &IpAddr,
    dst_zpr: &IpAddr,
    pkt: &PacketDesc,
    policy: &Arc<Policy>,
) -> Result<PolicyOutcome, ServiceError> {
    // If auth is expired it's a no.
    if let Some(exp) = src.get_authentication_expiration() {
        if exp < SystemTime::now() {
            info!(target: VREQ, "eval denied: source actor authentication expired: {src:?}");
            return Ok(PolicyOutcome::Deny(DenyCode::SourceAuthError));
        }
    }
    if let Some(exp) = dst.get_authentication_expiration() {
        if exp < SystemTime::now() {
            info!(target: VREQ, "eval denied: dest actor authentication expired: {dst:?}");
            return Ok(PolicyOutcome::Deny(DenyCode::DestAuthError));
        }
    }

    // For AAA actors the docking node comes from the AAA table registered on the
    // request side rather than the connection table.
    let Some(node_addr_a) = resolve_docking_node(asm, src, src_zpr) else {
        warn!(target: VREQ, "eval denied: source actor {src:?} is not docked to any node");
        return Ok(PolicyOutcome::Deny(DenyCode::SourceNotFound));
    };
    let Some(node_addr_b) = resolve_docking_node(asm, dst, dst_zpr) else {
        warn!(target: VREQ, "eval denied: dest actor {dst:?} is not docked to any node");
        return Ok(PolicyOutcome::Deny(DenyCode::DestNotFound));
    };

    // When the evaluator does not care about the route, we use the "best" route.
    // And if there is no route at all then we don't bother evaluating.
    let Some(default_route) = asm.topo_mgr.get_best_route(&node_addr_a, &node_addr_b) else {
        info!(target: VREQ, "eval denied: no route between {node_addr_a:?} and {node_addr_b:?}");
        return Ok(PolicyOutcome::Deny(DenyCode::NoRoute));
    };

    let ctx = EvalContext::new(policy.clone());
    let decision = ctx.eval_request(src, dst, pkt)?;

    match decision {
        PartialEvalResult::Deny(FinalDeny::NoMatch(message)) => {
            info!(target: VREQ, "eval denied (no match): {message}");
            Ok(PolicyOutcome::Deny(DenyCode::NoMatch))
        }
        PartialEvalResult::AllowWithoutRoute(hits) => Ok(PolicyOutcome::Allow {
            hits,
            default_route: Some(default_route),
        }),
        PartialEvalResult::Deny(FinalDeny::Deny(_hits)) => {
            info!(target: VREQ, "eval denied by policy");
            Ok(PolicyOutcome::Deny(DenyCode::Denied))
        }
        PartialEvalResult::NeedsRoute(residual_evaluator) => {
            let hint = residual_evaluator.hint();
            let routes = asm.topo_mgr.get_routes(src_zpr, dst_zpr, hint);
            match residual_evaluator.eval_routes(&routes, &asm.topo_mgr)? {
                // TODO: Note that when we get a match using routes, the route is returned in the hit.
                FinalEvalResult::Allow(hits) => Ok(PolicyOutcome::Allow {
                    hits,
                    default_route: None,
                }),
                FinalEvalResult::Deny(_hits) => {
                    info!(target: VREQ, "eval denied by policy with routes");
                    Ok(PolicyOutcome::Deny(DenyCode::Denied))
                }
                FinalEvalResult::NoMatch(message) => {
                    info!(target: VREQ, "eval denied (no match using route): {message}");
                    Ok(PolicyOutcome::Deny(DenyCode::NoMatch))
                }
            }
        }
    }
}

/// Pick the route for an allow decision: the first hit's own route if it has
/// one, else the supplied default route. Shared by the request path
/// (`visa_from_allow`) and the sweep recheck so route selection stays identical.
pub(crate) fn route_for_allow(
    hits: &[Hit],
    default_route: Option<Route>,
) -> Result<Route, ServiceError> {
    match hits[0].route.as_ref() {
        Some(route) => Ok(route.clone()),
        None => default_route.ok_or_else(|| {
            ServiceError::Internal(
                "policy allowed visa but no route in hit and no default route".into(),
            )
        }),
    }
}
