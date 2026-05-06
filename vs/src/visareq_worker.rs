//! Visa request worker work on matching packets to policy in order to create visas.
//! The beating heart of the visa service.
//!
//! Each worker gets a single visa request and tries to run it through the policy.
//! There are several outcomes:
//! - One or both actors may be missing (disconnected)
//! - There may not be a route between the actors, so request fails.
//! - One or both actors may need to be refreshed from attribute services.
//! - One or both actors may have expired authentication.
//! - A visa may already exist and policy has not changed, in which case we can use existing visa.
//! - The visa may be denied by policy.
//! - The visa may be allowed, but not over any available route, so that is a deny.
//! - If at the end of all this a visa is permitted, then
//! - If policy has not been updated in the meanwhile, we issue a visa, else we fail it and hope caller tries again.
//!
//! Once a visa is issued we need to pick the path and figure out which nodes need to be informed.
//! There may be path constraints that make the visa invalid.
//!
//! Once we have a path, the visa is queued up for install on all the impacted nodes and
//! returned to the caller.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::StreamExt;
use futures::future::FutureExt;

use libeval::actor::Actor;
use libeval::attribute::{Attribute, ROLE_ADAPTER, key};
use libeval::eval::EvalContext;
use libeval::eval_result::{FinalDeny, FinalEvalResult, Hit, PartialEvalResult};
use libeval::policy::Policy;
use libeval::route::Route;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};
use zpr::vsapi_types::{DenyCode, PacketDesc, Visa};

use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::error::ServiceError;
use crate::logging::targets::VREQ;
use crate::{config, net_mgr};

pub enum VisaDecision {
    Allow(Visa, Route),
    Deny(DenyCode),
}

/// The result is either a [Visa], or a regular denial, or there was an unexpected failure
/// and you get a [ServiceError].
pub type VisaRequestResult = Result<VisaDecision, ServiceError>;

/// TODO: add a job ID for tracing/logging.
pub struct VisaRequestJob {
    pub requesting_node: IpAddr,
    pub packet_desc: PacketDesc,
    // A channel to send the result back to the requester.
    response_chan: oneshot::Sender<VisaRequestResult>,
}

// Visa requests come into the arena where they are processed by workers.
pub async fn launch_arena(
    asm: Arc<Assembly>,
    incoming: mpsc::Receiver<VisaRequestJob>,
    max_concurrent: usize,
) {
    let stream = ReceiverStream::new(incoming);

    // TODO: This looks slick but we may want to know when we are under pressure.
    stream
        .for_each_concurrent(max_concurrent, |job| {
            tokio::spawn(process_visa_request_job(asm.clone(), job)).map(|r| r.unwrap())
        })
        .await;
}

/// Helper function to submit a visa request job and wait for the decision.
/// All visa request jobs should run through this so that visa request related counters
/// are properly updated.
///
/// ### Errors
/// - [ServiceError::Timeout] if the request times out.
/// - [ServiceError::InternalError] if there is an internal error enqueuing the request or receiving the response.
pub async fn request_visa_wait_response(
    asm: &Assembly,
    requesting_node: &IpAddr,
    pkt_data: PacketDesc,
    timeout: Duration,
) -> Result<VisaDecision, ServiceError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let (job, response_rx) = VisaRequestJob::new(requesting_node.clone(), pkt_data);

    asm.counters.incr(CounterType::VisaRequests);
    asm.counters
        .incr_node(CounterType::VisaRequests, requesting_node);
    asm.counters.update_request_time(requesting_node);

    match tokio::time::timeout_at(deadline, asm.vreq_chan.reserve()).await {
        Ok(Ok(permit)) => {
            permit.send(job);
            Ok(())
        }

        Ok(Err(_closed)) => {
            asm.counters.incr(CounterType::VisaRequestQueueError);
            Err(ServiceError::Internal(
                "internal error enqueuing visa request".to_string(),
            ))
        }

        Err(_timedout) => {
            asm.counters.incr(CounterType::VisaRequestQueueFull);
            Err(ServiceError::Timeout(
                "timeout enqueuing visa request".into(),
            ))
        }
    }?;

    // Now wait for a response with the remaining timeout.
    match tokio::time::timeout_at(deadline, response_rx).await {
        // Increment the appropriate counters before returning.
        Ok(Ok(vr_result)) => match vr_result {
            Ok(VisaDecision::Allow(_, _)) => {
                asm.counters.incr(CounterType::VisaRequestsApproved);
                asm.counters
                    .incr_node(CounterType::VisaRequestsApproved, requesting_node);

                vr_result
            }
            Ok(VisaDecision::Deny(_)) => {
                asm.counters.incr(CounterType::VisaRequestsDenied);
                asm.counters
                    .incr_node(CounterType::VisaRequestsDenied, requesting_node);
                vr_result
            }
            Err(_) => {
                asm.counters.incr(CounterType::VisaRequestFailed);
                vr_result
            }
        },
        Ok(Err(e)) => {
            // Queue read error -- probably closed?
            asm.counters.incr(CounterType::VisaRequestQueueError);
            Err(ServiceError::Internal(format!(
                "queue error receiving visa request response: {}",
                e
            )))
        }
        Err(_timedout) => {
            asm.counters.incr(CounterType::VisaRequestTimeout);
            Err(ServiceError::Timeout(format!(
                "timeout waiting for visa request response after {:?}",
                timeout
            )))
        }
    }
}

impl VisaRequestJob {
    pub fn new(
        requesting_node: IpAddr,
        packet_desc: PacketDesc,
    ) -> (Self, oneshot::Receiver<VisaRequestResult>) {
        let (tx, rx) = oneshot::channel();
        (
            VisaRequestJob {
                requesting_node,
                packet_desc,
                response_chan: tx,
            },
            rx,
        )
    }

    /// Complete this job by sending a result to the requester.
    /// Logs a warning if the requester has dropped the receiver.
    pub fn complete(self, result: VisaRequestResult) {
        if let Err(_) = self.response_chan.send(result) {
            // Means the requester has dropped the receiver.
            warn!(target: VREQ,
                "failed to enqueue visa request result for {:?}",
                self.requesting_node
            );
        }
    }
}

/// Main processing function for processing a visa request.
///
/// This is just a rough sketch for now.
async fn process_visa_request_job(asm: Arc<Assembly>, job: VisaRequestJob) {
    // Run the job, send the result back over the job response channel.
    let vrr = process_visa_request(asm.clone(), &job).await;
    job.complete(vrr);
}

/// Run visa request.
async fn process_visa_request(asm: Arc<Assembly>, job: &VisaRequestJob) -> VisaRequestResult {
    let (source_actor, dest_actor) = get_actors(&asm, job).await?;
    let (source_actor, dest_actor) =
        match resolve_actors_or_deny(&asm, job, source_actor, dest_actor).await {
            Ok(actors) => actors,
            Err(decision) => return Ok(decision),
        };

    // Both actors must have addresses. Extract them here or return a fail.
    let Some(source_zpr_addr) = source_actor.get_zpr_addr() else {
        debug!(target: VREQ,
            "visa request from {:?} denied: source actor {:?} has no ZPR address",
            job.requesting_node, source_actor
        );
        return Ok(VisaDecision::Deny(DenyCode::SourceNotFound));
    };
    let Some(dest_zpr_addr) = dest_actor.get_zpr_addr() else {
        debug!(target: VREQ,
            "visa request from {:?} denied: dest actor {:?} has no ZPR address",
            job.requesting_node, dest_actor
        );
        return Ok(VisaDecision::Deny(DenyCode::DestNotFound));
    };

    // Find the docking nodes for each actor. For AAA actors (unauthenticated adapters
    // fabricated during anonymous auth), the docking node is looked up from the AAA table
    // registered on the request side, rather than from the connection table.
    let node_addr_a = match asm.actor_mgr.get_docking_node_for_actor(&source_actor) {
        Some(node_addr) => node_addr,
        None => match asm.actor_mgr.get_docking_node_for_aaa(source_zpr_addr) {
            Some(node_addr) => node_addr,
            None => {
                warn!(target: VREQ,
                    "visa request from {:?} denied: source actor {:?} is not docked to any node",
                    job.requesting_node, source_actor
                );
                return Ok(VisaDecision::Deny(DenyCode::SourceNotFound));
            }
        },
    };
    let node_addr_b = match asm.actor_mgr.get_docking_node_for_actor(&dest_actor) {
        Some(node_addr) => node_addr,
        None => match asm.actor_mgr.get_docking_node_for_aaa(dest_zpr_addr) {
            Some(node_addr) => node_addr,
            None => {
                warn!(target: VREQ,
                    "visa request from {:?} denied: dest actor {:?} is not docked to any node",
                    job.requesting_node, dest_actor
                );
                return Ok(VisaDecision::Deny(DenyCode::DestNotFound));
            }
        },
    };

    let Some(default_route) = asm.router.get_best_route(&node_addr_a, &node_addr_b) else {
        info!(target: VREQ,
            "visa request from {:?} denied: no route between {:?} and {:?}",
            job.requesting_node, node_addr_a, node_addr_b
        );
        return Ok(VisaDecision::Deny(DenyCode::NoReason)); // TODO: Update to the NoRoute code when available in vsapi
    };

    let policy = asm.policy_mgr.get_current();
    let ctx = EvalContext::new(policy.clone());
    let decision = match ctx.eval_request(&source_actor, &dest_actor, &job.packet_desc) {
        Ok(decision) => decision,
        Err(e) => {
            debug!(target: VREQ,
                "error evaluating visa request from {:?}: {}",
                job.requesting_node, e
            );
            return Err(e.into());
        }
    };

    // TODO: drop eval context?
    // Do I need eval context in the residual evaluator? I do unless we copied relevant policy out of it.

    match decision {
        PartialEvalResult::Deny(FinalDeny::NoMatch(message)) => {
            info!(target: VREQ,
                "visa request from {:?} denied (no match): {}",
                job.requesting_node, message
            );
            Ok(VisaDecision::Deny(DenyCode::NoMatch))
        }
        PartialEvalResult::AllowWithoutRoute(hits) => {
            visa_from_allow(&asm, job, &hits, &policy, default_route).await
        }
        PartialEvalResult::Deny(FinalDeny::Deny(_hits)) => {
            info!(target: VREQ,
                "visa request from {:?} denied by policy",
                job.requesting_node
            );
            Ok(VisaDecision::Deny(DenyCode::Denied))
        }
        PartialEvalResult::NeedsRoute(residual_evaluator) => {
            let hint = residual_evaluator.hint();
            let routes = asm.router.get_routes(source_zpr_addr, dest_zpr_addr, hint);

            match residual_evaluator.eval_routes(&routes, &asm.router) {
                // TODO: Note that when we get a match using routes, the route it returned in the hit.
                Ok(FinalEvalResult::Allow(hits)) => {
                    visa_from_allow(&asm, job, &hits, &policy, default_route).await
                }
                Ok(FinalEvalResult::Deny(_hits)) => {
                    info!(target: VREQ,
                        "visa request from {:?} denied by policy with routes",
                        job.requesting_node
                    );
                    Ok(VisaDecision::Deny(DenyCode::Denied))
                }
                Ok(FinalEvalResult::NoMatch(message)) => {
                    info!(target: VREQ,
                        "visa request from {:?} denied (no match using route): {}",
                        job.requesting_node, message
                    );
                    Ok(VisaDecision::Deny(DenyCode::NoMatch))
                }
                Err(e) => {
                    debug!(target: VREQ,
                        "error evaluating route for visa request from {:?}: {}",
                        job.requesting_node, e
                    );
                    return Err(e.into());
                }
            }
        }
    }
}

/// Fabricate an AAA actor for an anonymous endpoint at the given address.
fn fabricate_aaa_actor(anon_addr: &IpAddr, expiration: SystemTime) -> Actor {
    let mut anon_actor = Actor::new();
    let _ = anon_actor.add_attribute(
        Attribute::builder(key::ZPR_ADDR)
            .expires(expiration)
            .value(anon_addr.to_string()),
    );
    let _ = anon_actor.add_attribute(
        Attribute::builder(key::AUTHORITY)
            .expires(expiration)
            .value("vs_hack_anon_to_auth"),
    );
    let _ = anon_actor.add_attribute(
        Attribute::builder(key::ROLE)
            .expires(expiration)
            .value(ROLE_ADAPTER),
    );
    let _ = anon_actor.add_attribute(
        Attribute::builder(key::CN)
            .expires(expiration)
            .value(format!("hack.{}.zpr", anon_addr)),
    );
    let _ = anon_actor.add_identity_key(0, key::CN);
    anon_actor
}

/// Given that we have an ALLOW decision, pass the hist list in here and we will pick the first
/// hit and create a visa based on it.
async fn visa_from_allow(
    asm: &Assembly,
    job: &VisaRequestJob,
    hits: &[Hit],
    policy: &Policy,
    default_route: Route,
) -> Result<VisaDecision, ServiceError> {
    debug_assert!(!hits.is_empty(), "allow decision with no hits"); // should never happen.
    let policy_version = policy.get_version().unwrap_or(0);
    // TODO: For now we pick the first hit.
    let zpl = policy
        .get_cpol_source(hits[0].match_idx)
        .unwrap_or("")
        .to_string();

    let allowed_route: Route = match hits[0].route.as_ref() {
        Some(route) => route.clone(),
        None => default_route,
    };

    let visa = asm
        .visa_mgr
        .create_visa(
            &job.requesting_node,
            &job.packet_desc,
            &hits[0],
            zpl,
            policy_version,
        )
        .await?;

    Ok(VisaDecision::Allow(visa, allowed_route))
}

/// Resolves a pair of optional actors into concrete actors, handling the case where one is
/// missing because it is an unauthenticated actor reaching an auth service via an AAA address.
///
/// Returns `Ok((source, dest))` when both actors are resolved, or `Err(decision)` for an
/// early deny that should be returned directly to the caller.
async fn resolve_actors_or_deny(
    asm: &Arc<Assembly>,
    job: &VisaRequestJob,
    mut source_actor: Option<Actor>,
    mut dest_actor: Option<Actor>,
) -> Result<(Actor, Actor), VisaDecision> {
    if source_actor.is_none() && dest_actor.is_none() {
        return Err(VisaDecision::Deny(DenyCode::SourceNotFound));
    }

    if source_actor.is_none() || dest_actor.is_none() {
        // This might be an actor trying to talk to an authentication service.
        //
        // To check this we confirm that one actor is using an AAA network address
        // from its node, and the other is an installed authentication service.
        //

        let missing_source = source_actor.is_none();

        // "candidate" => the possible auth service, "anon_addr" => possible actor using AAA addr.
        let (candidate_addr, anon_addr) = if missing_source {
            (job.packet_desc.dest_addr(), job.packet_desc.source_addr())
        } else {
            (job.packet_desc.source_addr(), job.packet_desc.dest_addr())
        };

        let expiration = SystemTime::now() + config::DEFAULT_ANON_AUTH_EXPIRATION;

        if missing_source {
            // Request side: assume this is an unauthenticated adapter → auth service.
            // Validate that the source is in the requesting node's AAA subnet and that the
            // destination is a registered auth service, then record the docking node.
            let node_aaa_net = net_mgr::aaa_network_for_node(&job.requesting_node);
            if !node_aaa_net.contains(anon_addr) {
                debug!(target: VREQ,
                    "visa denied: unknown source {anon_addr} is not in the AAA network for node {:?}",
                    job.requesting_node
                );
                return Err(VisaDecision::Deny(DenyCode::SourceNotFound));
            }

            match asm
                .actor_mgr
                .has_auth_services(asm.clone(), candidate_addr)
                .await
            {
                Ok(true) => (),
                Ok(false) => {
                    warn!(target: VREQ, "visa denied: actor using AAA addr attempting to contact non-authentication service at {candidate_addr}");
                    return Err(VisaDecision::Deny(DenyCode::DestNotFound));
                }
                Err(e) => {
                    debug!(target: VREQ, "visa denied: error checking authentication services for actor at {candidate_addr}: {}", e);
                    return Err(VisaDecision::Deny(DenyCode::DestNotFound));
                }
            };

            // Record the docking node so the response side can resolve it correctly,
            // even when the response arrives via a different requesting node.
            asm.actor_mgr
                .register_aaa(*anon_addr, job.requesting_node, expiration);

            let anon_actor = fabricate_aaa_actor(anon_addr, expiration);
            debug!(target: VREQ, "fabricated AAA actor for anonymous request: {:?} -> {candidate_addr}", anon_actor);
            source_actor = Some(anon_actor);
        } else {
            // Response side: assume "auth service" → unauthenticated adapter.
            // On this side we don't bother checking to see if source is an auth-service.
            // The policy eval will flag that.
            //
            // The AAA address must already be in the table (registered on the request side).
            match asm.actor_mgr.get_docking_node_for_aaa(anon_addr) {
                Some(_) => {}
                None => {
                    warn!(target: VREQ,
                        "visa denied: AAA address {anon_addr} not found in AAA table (expired or never registered)"
                    );
                    return Err(VisaDecision::Deny(DenyCode::DestNotFound));
                }
            }

            let anon_actor = fabricate_aaa_actor(anon_addr, expiration);
            debug!(target: VREQ, "fabricated AAA actor for anonymous response: {candidate_addr} -> {:?}", anon_actor);
            dest_actor = Some(anon_actor);
        }
    }

    Ok((source_actor.unwrap(), dest_actor.unwrap()))
}

// Lookup source and destination actors in the DB based on ZPR address.
async fn get_actors(
    asm: &Arc<Assembly>,
    job: &VisaRequestJob,
) -> Result<(Option<Actor>, Option<Actor>), ServiceError> {
    // TODO: The source or destination could be from an unauthenticated adapter
    // using an AAA address to talk to an authentication service.

    // See prototype code in vsinst-core.go (around line 128). In there we create
    // a fake actor to use for granting the visa.  But we need to establish that
    // the AAA address is correct for the node the adapter is connected to.

    let source_actor = match asm
        .actor_mgr
        .get_actor_by_zpr_addr(&job.packet_desc.source_addr())
        .await
    {
        Ok(maybe_actor) => maybe_actor,
        Err(e) => {
            debug!(target: VREQ,
                "error retrieving source actor for visa request from {:?}: {e}",
                job.requesting_node
            );
            return Err(ServiceError::Internal(
                "error retrieving source actor".into(),
            ));
        }
    };

    let dest_actor = match asm
        .actor_mgr
        .get_actor_by_zpr_addr(&job.packet_desc.dest_addr())
        .await
    {
        Ok(maybe_actor) => maybe_actor,
        Err(e) => {
            debug!(target: VREQ,
                "error retrieving dest actor for visa request from {:?}: {e}",
                job.requesting_node
            );
            return Err(ServiceError::Internal("error retrieving dest actor".into()));
        }
    };
    Ok((source_actor, dest_actor))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::Assembly;
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::{make_actor_with_services_defexp, make_node_actor_defexp};
    use bytes::Bytes;
    use libeval::attribute::ROLE_ADAPTER;
    use libeval::eval_result::Direction;
    use libeval::policy::Policy;
    use libeval::route::{LinkId, RouteKind};
    use std::time::{Duration, SystemTime};
    use zpr::policy_types::{JoinPolicy, PFlags, Scope, Service, ServiceType};
    use zpr::write_to::WriteTo;

    /// Builds a Policy that declares one Authentication service with the given id.
    fn make_policy_with_auth_service(service_id: &str) -> Policy {
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
        Policy::new_from_policy_bytes(Bytes::copy_from_slice(&bytes)).unwrap()
    }

    // This test just runs a request through the pipeline. There is no real policy here
    // so it will fail.  But it should be a visa-deny not some other error.
    #[tokio::test]
    async fn request_visa_wait_response_denies_when_policy_has_no_match() {
        let (vreq_tx, vreq_rx) = mpsc::channel(8);
        let asm_inner = new_assembly_for_tests(Some(vreq_tx)).await;
        let src_zpr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let dst_zpr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        asm_inner.router.add_node(&src_zpr).unwrap();
        asm_inner.router.add_node(&dst_zpr).unwrap();
        asm_inner
            .router
            .add_link(&src_zpr, &dst_zpr, &LinkId("test-link".into()), &[], 1)
            .unwrap();
        let asm = Arc::new(asm_inner);

        let source_actor =
            make_node_actor_defexp("fd5a:5052:3000::1", "source-node", "10.0.0.1:10001");
        let dest_actor = make_node_actor_defexp("fd5a:5052:3000::2", "dest-node", "10.0.0.2:10002");
        asm.actor_mgr.add_node(&source_actor, false).await.unwrap();
        asm.actor_mgr.add_node(&dest_actor, false).await.unwrap();

        let arena = tokio::spawn(launch_arena(asm.clone(), vreq_rx, 1));

        let requestor_ip: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt_data =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let result =
            request_visa_wait_response(&asm, &requestor_ip, pkt_data, Duration::from_secs(1))
                .await
                .unwrap();

        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoMatch)));

        arena.abort();
    }

    // Verifies that visa_from_allow issues a visa and returns Allow when given a valid hit and route.
    #[tokio::test]
    async fn visa_from_allow_issues_visa_on_allow() {
        let asm = new_assembly_for_tests(None).await;
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt_data =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt_data);

        let hits = vec![Hit::new_no_signal(0, Direction::Forward)];
        let policy = Policy::new_empty();
        let route = Route {
            kind: RouteKind::Multihop,
            links: vec![],
            cost: 0,
        };

        let result = visa_from_allow(&asm, &job, &hits, &policy, route).await;
        assert!(matches!(result, Ok(VisaDecision::Allow(_, _))));
    }

    // When both actors are None the request cannot proceed: deny the source immediately.
    #[tokio::test]
    async fn resolve_actors_or_deny_both_missing_denies_source() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt = PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let result = resolve_actors_or_deny(&asm, &job, None, None).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::SourceNotFound))
        ));
    }

    // When both actors are known they pass through unchanged.
    #[tokio::test]
    async fn resolve_actors_or_deny_both_present_passes_through() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt = PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let src = make_node_actor_defexp("fd5a:5052:3000::1", "src", "10.0.0.1:1001");
        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");
        let src_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let dst_addr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();

        let (ra, rb) = resolve_actors_or_deny(&asm, &job, Some(src), Some(dst))
            .await
            .ok()
            .expect("expected Ok");
        assert_eq!(ra.get_zpr_addr(), Some(&src_addr));
        assert_eq!(rb.get_zpr_addr(), Some(&dst_addr));
    }

    // Missing source whose address is a plain ZPR address (not in the node's AAA subnet) is denied.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_source_not_in_aaa_network_denies_source() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        // source addr is a normal ZPR address, outside any node AAA subnet
        let pkt =
            PacketDesc::new_tcp("fd5a:5052:3000::99", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");
        let result = resolve_actors_or_deny(&asm, &job, None, Some(dst)).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::SourceNotFound))
        ));
    }

    // Missing source in the AAA subnet but the destination has no auth service registered:
    // deny because it would be a non-authenticated actor talking to a non-auth endpoint.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_source_in_aaa_net_dest_not_auth_service_denies() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        // AAA subnet for node ::ff is fd5a:5052:0:aaa:0:ff00::/88; pick an address inside it.
        let aaa_src = "fd5a:5052:0:aaa:0:ff00::1";
        let pkt = PacketDesc::new_tcp(aaa_src, "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        // No actor with auth services in the DB at the dest addr.
        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");
        let result = resolve_actors_or_deny(&asm, &job, None, Some(dst)).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::DestNotFound))
        ));
    }

    // Missing source in the AAA subnet, destination is a registered auth service:
    // fabricate an AAA actor for the anonymous source and register it in the AAA table.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_source_in_aaa_net_with_auth_service_fabricates_aaa_actor()
     {
        let asm_inner = new_assembly_for_tests(None).await;

        let dest_zpr = "fd5a:5052:3000::2";
        let auth_actor =
            make_actor_with_services_defexp(ROLE_ADAPTER, dest_zpr, &["svc:auth"], "auth-svc");
        asm_inner
            .actor_mgr
            .hack_add_adapter_no_node(&auth_actor)
            .await
            .unwrap();
        asm_inner
            .policy_mgr
            .update_policy(make_policy_with_auth_service("svc:auth"))
            .unwrap();

        let asm = Arc::new(asm_inner);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let aaa_src = "fd5a:5052:0:aaa:0:ff00::1";
        let pkt = PacketDesc::new_tcp(aaa_src, dest_zpr, 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let dst = make_node_actor_defexp(dest_zpr, "dst", "10.0.0.2:1002");
        let (aaa_src_actor, resolved_dst) = resolve_actors_or_deny(&asm, &job, None, Some(dst))
            .await
            .ok()
            .expect("expected Ok");

        let expected_aaa: IpAddr = aaa_src.parse().unwrap();
        let expected_dst: IpAddr = dest_zpr.parse().unwrap();
        assert_eq!(aaa_src_actor.get_zpr_addr(), Some(&expected_aaa));
        assert_eq!(resolved_dst.get_zpr_addr(), Some(&expected_dst));

        // Confirm the AAA table was populated by the request-side registration.
        assert_eq!(
            asm.actor_mgr.get_docking_node_for_aaa(&expected_aaa),
            Some(requesting_node),
            "aaa_table must record the requesting node as docking node"
        );
    }

    // Missing destination whose address is a plain ZPR address (not in the node's AAA subnet) is denied.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_dest_not_in_aaa_network_denies_dest() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        // dest addr is a normal ZPR address, outside any node AAA subnet
        let pkt =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::99", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let src = make_node_actor_defexp("fd5a:5052:3000::1", "src", "10.0.0.1:1001");
        let result = resolve_actors_or_deny(&asm, &job, Some(src), None).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::DestNotFound))
        ));
    }

    // Missing destination with the AAA address pre-registered in the table (simulating a prior
    // forward request): fabricate an AAA actor for the anonymous destination.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_dest_in_aaa_table_fabricates_aaa_actor() {
        let asm_inner = new_assembly_for_tests(None).await;

        let src_zpr = "fd5a:5052:3000::1";
        let auth_actor =
            make_actor_with_services_defexp(ROLE_ADAPTER, src_zpr, &["svc:auth"], "auth-svc");
        asm_inner
            .actor_mgr
            .hack_add_adapter_no_node(&auth_actor)
            .await
            .unwrap();
        asm_inner
            .policy_mgr
            .update_policy(make_policy_with_auth_service("svc:auth"))
            .unwrap();

        let asm = Arc::new(asm_inner);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let aaa_dst = "fd5a:5052:0:aaa:0:ff00::1";
        let aaa_dst_addr: IpAddr = aaa_dst.parse().unwrap();

        // Pre-register as the request side would have done.
        asm.actor_mgr.register_aaa(
            aaa_dst_addr,
            requesting_node,
            SystemTime::now() + Duration::from_secs(300),
        );

        let pkt = PacketDesc::new_tcp(src_zpr, aaa_dst, 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let src = make_node_actor_defexp(src_zpr, "src", "10.0.0.1:1001");
        let (resolved_src, aaa_dst_actor) = resolve_actors_or_deny(&asm, &job, Some(src), None)
            .await
            .ok()
            .expect("expected Ok");

        let expected_src: IpAddr = src_zpr.parse().unwrap();
        assert_eq!(resolved_src.get_zpr_addr(), Some(&expected_src));
        assert_eq!(aaa_dst_actor.get_zpr_addr(), Some(&aaa_dst_addr));
    }

    // --- AAA actor full pipeline tests ---

    // Shared setup for AAA pipeline tests:
    //   node A (fd5a:5052:3000::1) = requesting node and AAA actor docking node
    //   node B (fd5a:5052:3000::2) = auth service docking node
    //   auth adapter (fd5a:5052:3000::30) docked to node B, service "svc:auth"
    //   AAA subnet for node A: fd5a:5052:0:aaa:0:100::/88
    async fn build_aaa_test_asm(with_link: bool) -> Arc<Assembly> {
        let asm = new_assembly_for_tests(None).await;

        let node_a_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let node_b_addr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();

        let node_a = make_node_actor_defexp("fd5a:5052:3000::1", "node-a", "10.0.0.1:1001");
        let node_b = make_node_actor_defexp("fd5a:5052:3000::2", "node-b", "10.0.0.2:1002");
        asm.actor_mgr.add_node(&node_a, false).await.unwrap();
        asm.actor_mgr.add_node(&node_b, false).await.unwrap();
        asm.router.add_node(&node_a_addr).unwrap();
        asm.router.add_node(&node_b_addr).unwrap();

        if with_link {
            asm.router
                .add_link(
                    &node_a_addr,
                    &node_b_addr,
                    &LinkId("link-ab".into()),
                    &[],
                    1,
                )
                .unwrap();
        }

        let auth_adapter = make_actor_with_services_defexp(
            ROLE_ADAPTER,
            "fd5a:5052:3000::30",
            &["svc:auth"],
            "auth-svc",
        );
        asm.actor_mgr
            .add_adapter_via_node(&auth_adapter, &node_b_addr)
            .await
            .unwrap();

        asm.policy_mgr
            .update_policy(make_policy_with_auth_service("svc:auth"))
            .unwrap();

        Arc::new(asm)
    }

    // An AAA source actor passes the docking-node check and reaches policy evaluation.
    // Deny(NoMatch) confirms the actor was resolved and routing succeeded.
    #[tokio::test]
    async fn process_visa_request_aaa_source_reaches_policy_eval() {
        let asm = build_aaa_test_asm(true).await;
        let requesting_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        // node_id for ::1 = 0x000001; segments[5] = 0x0001<<8 = 0x0100 → subnet fd5a:5052:0:aaa:0:100::/88
        let pkt = PacketDesc::new_tcp(
            "fd5a:5052:0:aaa:0:100::1",
            "fd5a:5052:3000::30",
            12345,
            4000,
        )
        .unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoMatch)));
    }

    // An AAA source with no route between the docking node and the auth service docking node
    // is denied NoReason (not SourceNotFound), confirming the docking check passed.
    #[tokio::test]
    async fn process_visa_request_aaa_source_no_route_denied() {
        let asm = build_aaa_test_asm(false).await;
        let requesting_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let pkt = PacketDesc::new_tcp(
            "fd5a:5052:0:aaa:0:100::1",
            "fd5a:5052:3000::30",
            12345,
            4000,
        )
        .unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoReason)));
    }

    // An AAA destination actor with the AAA table pre-populated reaches policy evaluation.
    // Deny(NoMatch) confirms the actor was resolved and routing succeeded.
    #[tokio::test]
    async fn process_visa_request_aaa_dest_reaches_policy_eval() {
        let asm = build_aaa_test_asm(true).await;
        let node_a_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let aaa_addr: IpAddr = "fd5a:5052:0:aaa:0:100::1".parse().unwrap();

        // Pre-register as the request side would have done.
        asm.actor_mgr.register_aaa(
            aaa_addr,
            node_a_addr,
            SystemTime::now() + Duration::from_secs(300),
        );

        let requesting_node = node_a_addr;
        let pkt = PacketDesc::new_tcp(
            "fd5a:5052:3000::30",
            "fd5a:5052:0:aaa:0:100::1",
            4000,
            12345,
        )
        .unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoMatch)));
    }

    // Multi-node test: node A is the AAA docking node, node B hosts the auth service.
    // A forward request (requesting_node=A) registers the AAA address.
    // A return visa (requesting_node=B) must resolve the AAA dest to node A via the table.
    #[tokio::test]
    async fn process_visa_request_aaa_dest_multi_node_resolves_to_correct_docking_node() {
        let asm = build_aaa_test_asm(true).await;

        let node_a_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let node_b_addr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let aaa_addr: IpAddr = "fd5a:5052:0:aaa:0:100::1".parse().unwrap();

        // Step 1: forward request from node A registers the AAA address in the table.
        let fwd_pkt = PacketDesc::new_tcp(
            "fd5a:5052:0:aaa:0:100::1",
            "fd5a:5052:3000::30",
            12345,
            4000,
        )
        .unwrap();
        let (fwd_job, _rx) = VisaRequestJob::new(node_a_addr, fwd_pkt);
        let _ = process_visa_request(asm.clone(), &fwd_job).await.unwrap();

        // Confirm the AAA table now maps the address to node A.
        assert_eq!(
            asm.actor_mgr.get_docking_node_for_aaa(&aaa_addr),
            Some(node_a_addr),
            "aaa_table must map aaa_addr to node A after forward request"
        );

        // Step 2: return visa arrives via node B (the auth service's node).
        // Without the fix, requesting_node=B would cause the subnet check to fail.
        // With the fix, the table lookup finds node A as the correct docking node.
        let ret_pkt = PacketDesc::new_tcp(
            "fd5a:5052:3000::30",
            "fd5a:5052:0:aaa:0:100::1",
            4000,
            12345,
        )
        .unwrap();
        let (ret_job, _rx) = VisaRequestJob::new(node_b_addr, ret_pkt);
        let result = process_visa_request(asm, &ret_job).await.unwrap();

        // Deny(NoMatch) means routing resolved correctly; the request reached policy eval.
        // Deny(DestNotFound) would mean the table lookup failed (the old bug).
        assert!(
            matches!(result, VisaDecision::Deny(DenyCode::NoMatch)),
            "expected NoMatch (policy eval reached)"
        );
    }
}
