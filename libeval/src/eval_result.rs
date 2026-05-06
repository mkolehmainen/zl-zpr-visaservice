use serde::{Deserialize, Serialize};
use std::fmt;

use crate::eval_route::RouteResidualEvaluator;
use crate::route::{Route, RoutePredicate};

/// The result of an initial evaluation of policy against a communicating pair of
/// actors and a description of the packet.  This may need further route-based
/// evaluation to determine if the communication is allowed or denied.
#[derive(Debug)]
pub enum PartialEvalResult {
    /// Denied no matter what route, can proceed without further eval.
    Deny(FinalDeny),

    /// Allowed no matter what route, can proceed without further eval.
    AllowWithoutRoute(Vec<Hit>),

    /// Needs further evaluation.
    NeedsRoute(RouteResidualEvaluator),
}

/// The FINAL result of evaluating policy against a communicating pair of actors
/// over a route.
///
/// Note that this does not select a winner when where are multiple
/// policy hits.  The hits are returned in policy order.
#[derive(Debug)]
pub enum FinalEvalResult {
    /// All matching allow permissions are returned.
    Allow(Vec<Hit>),

    /// Takes an explanatory string.
    NoMatch(String),

    /// All matching deny permissions are returned.
    Deny(Vec<Hit>),
}

/// A decision to deny based on policy.
/// Either no policy matched at all, or a deny policy matched.
/// Routes do not matter, this is a final decision.
#[derive(Debug)]
pub enum FinalDeny {
    /// No policy matched at all, provides an explanatory string.
    NoMatch(String),

    /// Policy matched but it was a deny.
    Deny(Vec<Hit>),
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct Signal {
    pub message: String,
    pub service: String,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Direction {
    Forward,
    Reverse,
}

/// A "hit" is a single matching permission or deny line in policy
/// that matches against the actors and packet description.
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct Hit {
    /// Index into the policies for the matching policy.
    /// Caller can use this to find the ZPL line and the conditions.
    pub match_idx: usize,

    /// If 'Forward' then this the Hit was on the "forward" client->service direction.
    pub direction: Direction,

    /// If there is a signal attached to this permission it is returned here.
    pub signal: Option<Signal>,

    /// If the hit includes a route constraint, it is returned here.
    /// Only used/valid in partial results (from pass 1).
    pub route_predicate: Option<RoutePredicate>,

    /// If this was evaluated over a route it is returned here.
    pub route: Option<Route>,
}

impl PartialEvalResult {
    pub fn deny_no_match(msg: String) -> Self {
        PartialEvalResult::Deny(FinalDeny::NoMatch(msg))
    }
    pub fn deny_hits(hits: Vec<Hit>) -> Self {
        PartialEvalResult::Deny(FinalDeny::Deny(hits))
    }
    pub fn allow_hits(hits: Vec<Hit>) -> Self {
        PartialEvalResult::AllowWithoutRoute(hits)
    }
}

impl Hit {
    /// Create Hit without a signal.
    pub fn new_no_signal(index: usize, direction: Direction) -> Self {
        Hit {
            match_idx: index,
            direction,
            signal: None,
            route_predicate: None,
            route: None,
        }
    }
    /// Create Hit with a signal.
    #[allow(dead_code)]
    pub fn new_with_signal(index: usize, direction: Direction, signal: Signal) -> Self {
        Hit {
            match_idx: index,
            direction,
            signal: Some(signal),
            route_predicate: None,
            route: None,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Forward => write!(f, "FWD"),
            Direction::Reverse => write!(f, "REV"),
        }
    }
}
