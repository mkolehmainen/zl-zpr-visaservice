//! The second phase policy evaluator which takes route constraints into consideration.

use zpr::vsapi_types::PacketDesc;

use crate::actor::Actor;
use crate::attribute::AttrMatch;
use crate::error::EvalError;
use crate::eval_result::{FinalEvalResult, Hit};
use crate::route::{LinkId, Route};

/// Simple interface into the ZPR network topology that the route residual evaluator uses
/// to evaluate routes.
pub trait TopologyQueryApi {
    fn link_has_attr(&self, link_id: &LinkId, attr: &AttrMatch) -> bool;
}

/// This evaluator is returned during policy evaluation if we get hits that depend on
/// route constraints.
///
/// Not implemented yet as we don't even have ZPL for expressing link constraints.
#[allow(dead_code)]
#[derive(Debug)]
pub struct RouteResidualEvaluator {
    src_actor: Actor, // cloned from phase 1 (TBD - actually we could just copy over the attrributes that matched policy...)
    dst_actor: Actor, // cloned from phase 1
    packet_desc: PacketDesc, // cloned from phase 1
    candidate_allow_hits: Vec<Hit>,
    candidate_deny_hits: Vec<Hit>,
    hint: Option<RouteHint>,
}

/// An optional route hint can be used by the Router to cull the set of possible routes.
/// The hint is conservative and may match more routes than are strictly possible by policy.
/// Not all policies will be able to provide a hint, and in that case all routes need
/// to be evaluated.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RouteHint {
    /// No links at all (direct connection between source and destination).
    pub direct_only: bool,

    /// Must have links (i.e. cannot be direct).
    pub require_linked_path: bool,

    /// Route is candidate if any link on the path matches
    pub any_link_has: Vec<AttrMatch>,

    /// Route is candidate if no link on the path matches
    pub no_link_has: Vec<AttrMatch>,

    /// Route is candidate if all links on the path match
    pub all_links_have: Vec<AttrMatch>,
}

impl RouteResidualEvaluator {
    /// An optional coarse hint that can be used to prune routes.
    pub fn hint(&self) -> Option<&RouteHint> {
        self.hint.as_ref()
    }

    /// Evaluate a single candidate route against policy.
    ///
    /// We have previously done an eval call on the EvalContext. So we know that the actors
    /// match.  But we may still need to hold on to the relevant actor attributes to make
    /// the evaluation.  The assumption is that everything we need in the residual is populated
    /// in it when it is created.
    ///
    /// Example:
    ///    allow admins to access services over secure links.
    ///    allow employees to access services. # implied: over any link.
    ///    never allow admins to access services over insecure links.
    ///
    /// When this is called with a route to "services" over "insecure" link.
    /// We need to know if the actor is an admin or just an employee.
    pub fn eval_route(
        &self,
        _route: &Route,
        _topology: &impl TopologyQueryApi,
    ) -> Result<FinalEvalResult, EvalError> {
        Err(EvalError::InternalError(
            "route evaluation not implemented".to_string(),
        ))

        // General approach idea:
        // - For each deny candidate hit evaluate its RoutePredicate against the route and re-check any actor condifitions
        //   using our cached actors.  If any deny fires this will be a deny (but I think we want to return ALL the denies that fire).
        // - For each allow candidate hit evaluate its RoutePredicate as above, collect any passing hits and return an allow.
        // - Else a deny with NO MATCH.
    }

    /// Evaluate multiple candidate routes against policy.
    ///
    /// This is a helper that just calls eval_route for each route and then combines the results.
    /// The final result is deny if any of the routes deny, and allow if any of the routes allow, else a deny with NO MATCH.
    ///
    /// I think we want the VS to use this function so that we can centralize the policy picking logic here.
    ///
    /// TODO: Consider maing `eval_route` private and only exposing this function.
    pub fn eval_routes(
        &self,
        _routes: &[Route],
        _topology: &impl TopologyQueryApi,
    ) -> Result<FinalEvalResult, EvalError> {
        Err(EvalError::InternalError(
            "route evaluation not implemented".to_string(),
        ))
    }
}
