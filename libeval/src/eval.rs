use crate::actor::Actor;
use crate::attribute::{Attribute, NEVER_EXPIRES, ROLE_ADAPTER, ROLE_NODE, key};
use crate::error::EvalError;
use crate::eval_result::{Direction, FinalDeny, Hit, PartialEvalResult, Signal};
use crate::joinpolicy::JFlag;
use crate::logging::targets::EVAL;
use crate::policy::Policy;
use crate::visa::VisaProps;

use zpr::vsapi_types::PacketDesc;
use zpr::vsapi_types::vsapi_ip_number as ip_proto;

use enumset::EnumSet;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use tracing::{debug, warn};

use zpr::policy::v1 as policy_capnp;

// TODO: Not yet sure if this is useful. Maybe the context can build up
// some cache or something to make future eval calls faster?
pub struct EvalContext {
    policy: Arc<Policy>,
}

#[derive(Debug, PartialEq, Eq)]
enum ScopeMatchType {
    Forward,
    Reverse,
}

enum PAttrValue {
    Atom(String),
    Set(Vec<String>),
}

impl PAttrValue {
    fn is_empty(&self) -> bool {
        match self {
            PAttrValue::Atom(s) => s.is_empty(),
            PAttrValue::Set(vs) => vs.is_empty(),
        }
    }

    fn as_slice(&self) -> &[String] {
        match self {
            PAttrValue::Atom(s) => std::slice::from_ref(s),
            PAttrValue::Set(vs) => vs.as_slice(),
        }
    }
}

impl EvalContext {
    pub fn new(policy: Arc<Policy>) -> Self {
        EvalContext { policy }
    }

    /// Check if policy permits the described actor communication.
    ///
    /// Caller must ensure that the two actors passed here are the ones
    /// involved in the communication described by `request`.
    pub fn eval_request(
        &self,
        src_actor: &Actor,
        dst_actor: &Actor,
        request: &PacketDesc,
    ) -> Result<PartialEvalResult, EvalError> {
        if !matches!(
            request.protocol(),
            ip_proto::TCP | ip_proto::UDP | ip_proto::IPV6_ICMP
        ) {
            return Ok(PartialEvalResult::Deny(FinalDeny::NoMatch(
                "only TCP/UDP/ICMPv6 protocols supported".into(),
            )));
        }
        let rdr = match self.policy.get_policy_reader() {
            Some(r) => r,
            None => {
                return Ok(PartialEvalResult::deny_no_match(
                    "no policy available".into(),
                ));
            }
        };
        let policy = rdr.get_root::<policy_capnp::policy::Reader>()?;
        if !policy.has_com_policies() {
            return Ok(PartialEvalResult::deny_no_match(
                "no communication policies defined".into(),
            ));
        }

        // We will make two passes, once looking for denies, and then looking for allows (if needed).
        let deny_hits = self.match_policies(false, src_actor, dst_actor, request, &policy)?;
        if !deny_hits.is_empty() {
            return Ok(PartialEvalResult::deny_hits(deny_hits));
        }

        let allow_hits = self.match_policies(true, src_actor, dst_actor, request, &policy)?;
        // Different hits will have different constraints etc. We'll leave the picking of the
        // policy to apply to the caller.
        if !allow_hits.is_empty() {
            return Ok(PartialEvalResult::allow_hits(allow_hits));
        }
        Ok(PartialEvalResult::deny_no_match(
            "no matching policy".into(),
        ))
    }

    pub fn visa_info_for_hit(
        &self,
        hit: &Hit,
        request: &PacketDesc,
    ) -> Result<VisaProps, EvalError> {
        let rdr = match self.policy.get_policy_reader() {
            Some(r) => r,
            None => {
                return Err(EvalError::EmptyPolicy);
            }
        };
        let policy = rdr.get_root::<policy_capnp::policy::Reader>()?;

        let matched_pol = policy.get_com_policies().unwrap().get(hit.match_idx as u32);

        if !matched_pol.get_allow() {
            return Err(EvalError::InvalidRequest(
                "visa_info_for_hit called on a deny".into(),
            ));
        }

        let match_source_port;
        let match_dest_port;

        match request.protocol() {
            // For TCP/UDP if request was using a high numberd "client" port, grant the visa for
            // any client port.
            //
            // THIS IS NOT REQUIRED BY ZDP AND MAY NOT BE WHAT WE WANT.
            //
            //    This is an example of a "handler" related to the protocol.
            //    We should amend or remove if we don't want this behavior.
            //    Here only because this was in the prototype.
            //
            ip_proto::TCP | ip_proto::UDP => match hit.direction {
                Direction::Forward => {
                    if request.source_port() > 1023 {
                        match_source_port = 0;
                    } else {
                        match_source_port = request.source_port();
                    }
                    match_dest_port = request.dest_port();
                }
                Direction::Reverse => {
                    if request.dest_port() > 1023 {
                        match_dest_port = 0;
                    } else {
                        match_dest_port = request.dest_port();
                    }
                    match_source_port = request.source_port();
                }
            },
            ip_proto::IPV6_ICMP => {
                // For ICMPv6 the source port is the ICMP type.
                // The dest port is the ICMP code.
                // TODO: We do not yet encode ICMP codes into the binary policy format.
                match_source_port = request.source_port();
                match_dest_port = request.dest_port();
            }
            _ => {
                return Err(EvalError::UnsupportedProtocol(format!(
                    "unsupported protocol {}",
                    request.protocol()
                )));
            }
        }

        Ok(VisaProps {
            source_addr: request.source_addr().clone(),
            dest_addr: request.dest_addr().clone(),
            protocol: request.protocol(),
            source_port: match_source_port,
            dest_port: match_dest_port,
            constraints: None, // TODO
            comm_opts: None,   // TODO
            zpl: matched_pol.get_zpl().unwrap().to_string().unwrap(),
        })
    }

    /// Consult policy and determine if connection is allowed from the actor with
    /// the indicated authenticated and unauthenticated claims.
    ///
    /// On success returns an actor object that will include additional attributes set from
    /// policy (eg, ROLE).
    ///
    /// This does not set `zpr.addr` unless one is specified in policy (TODO).
    ///
    /// If the peer is requesting a specific ZPR address, then zpr.addr:<addr> should
    /// be included in the `unauthenticated_claims`. Connection request will fail if the
    /// policy specifies a different address for the actor.  Caller should scrub ZPR address
    /// from unauthenticated_claims before calling this function if they do not want it
    /// used in policy matching.
    pub fn approve_connection(
        &self,
        authenticated_claims: Option<&[Attribute]>,
        unauthenticated_claims: Option<&[Attribute]>,
    ) -> Result<Actor, EvalError> {
        if authenticated_claims.is_none() {
            return Err(EvalError::AttributeMissing(
                "no authenticated claims provided".into(),
            ));
        }
        let authenticated_claims = authenticated_claims.unwrap();

        let mut query_claims = Vec::new();
        query_claims.extend_from_slice(authenticated_claims);

        // Collect any requested zpr.addr from the unauth claims. These are used
        // for join-policy matching, but only committed to the final actor if a
        // join policy actually matches (and thereby validates them).
        let mut unauth_claims = Vec::new();
        if let Some(uc) = unauthenticated_claims {
            for ua_attr in uc {
                if ua_attr.get_key() == key::ZPR_ADDR {
                    unauth_claims.push(ua_attr.clone());
                }
            }
        }
        query_claims.extend_from_slice(&unauth_claims);

        // Query to see if the claims match any join policies.
        let matching_jps = self.policy.match_join_policies(&query_claims);
        // If nothing matched, the unauth claims are unvalidated and must be
        // scrubbed from the actor: otherwise a bootstrap-authenticated peer with
        // no matching join policy could claim an arbitrary or already-used ZPR
        // address and overwrite/disconnect that actor.
        let matched_join_policy = !matching_jps.is_empty();
        debug!(
            target: EVAL,
            "found {} matching join policies",
            matching_jps.len()
        );

        // Each policy may have flags and services.
        // TODO: Currently we have no way to set a static addr from policy.
        let mut flags: EnumSet<JFlag> = EnumSet::new();
        let mut services = HashSet::new();
        for jp in matching_jps {
            flags |= jp.flags;
            if let Some(svcs) = &jp.services {
                for s in svcs {
                    services.insert(s.clone());
                }
            }
        }

        let mut actor = Actor::new();

        // Always commit the authenticated claims. Commit the unauth claims only
        // if a join policy matched; otherwise scrub them.
        let final_claims: &[Attribute] = if matched_join_policy {
            &query_claims
        } else {
            if !unauth_claims.is_empty() {
                warn!(
                    target: EVAL,
                    "scrubbing {} unauthenticated claim(s) from actor: no matching join policy",
                    unauth_claims.len()
                );
            }
            authenticated_claims
        };

        for attr in final_claims {
            if let Err(e) = actor.add_attribute(attr.clone()) {
                warn!(target: EVAL, "dropping invalid claim attribute: {}", e);
            }
        }

        let role_attr = if flags.contains(JFlag::IsNode) {
            Attribute::builder(key::ROLE)
                .expires_in(NEVER_EXPIRES)
                .value(ROLE_NODE)
        } else {
            Attribute::builder(key::ROLE)
                .expires_in(NEVER_EXPIRES)
                .value(ROLE_ADAPTER)
        };
        actor.add_attribute(role_attr).unwrap();

        if !services.is_empty() {
            debug!(target: EVAL, "actor provides services: {:?}", services);
            let svc_attr = Attribute::builder(key::SERVICES)
                .expires_in(NEVER_EXPIRES)
                .values(services);
            actor.add_attribute(svc_attr).unwrap();
        }

        actor
            .add_attribute(
                Attribute::builder(key::VINST)
                    .expires_in(NEVER_EXPIRES)
                    .value(self.policy.get_vinst().to_string()),
            )
            .unwrap();

        // Policy tells us which attributes are tied to identity, and there is one identity
        // attribute libeval knows on its own: the adapter CN, established by the builtin RSA
        // authentication. Policy::lookup_identity_keys() carries that UNION (builtin CN
        // first, then the policy-declared keys in policy order, CN deduped), and is also
        // what the Visa Service intersects with claims when querying trusted services --
        // sharing the accessor keeps the two definitions from drifting.
        //
        // Everything is appended (usize::MAX) so CN stays first and the policy-declared keys keep
        // policy order. Callers layer their own keys around this set -- the Visa Service prepends
        // its JWT at order 0 and appends zpr.authority at the end -- so this must not reorder.
        //
        // Presence on the actor is a sufficient test: every attribute committed above is either an
        // authenticated claim or a zpr.addr validated by a matching join policy, so a peer cannot
        // self-assert an identity attribute into this set.
        for ikey in self.policy.lookup_identity_keys() {
            if actor.has_attribute_named(ikey) {
                // Only fails when the attribute is absent, which was just checked.
                actor.add_identity_key(usize::MAX, ikey).unwrap();
            }
        }

        // Last resort. An actor with no identity key at all reads as "never authenticated":
        // get_authentication_expiration returns None, and the Visa Service *skips* its
        // expiry check when it is None. So this set must never be left empty.
        if actor.identity_keys_iter().next().is_none() {
            if actor.has_attribute_named(key::ZPR_ADDR) {
                actor.add_identity_key(usize::MAX, key::ZPR_ADDR).unwrap();
            } else {
                let mut s = DefaultHasher::new();
                actor.hash(&mut s);
                let hash_str = format!("hash:{:x}", s.finish());
                actor
                    .add_attribute(Attribute::builder(key::ACTOR_HASH).value(hash_str))
                    .unwrap();
                actor.add_identity_key(usize::MAX, key::ACTOR_HASH).unwrap();
            }
        }

        Ok(actor)
    }

    /// Similar to [EvalContext::approve_connection] except this assumes that the passed actor
    /// is already connected and this just checks to see if the actor is compatible with the
    /// current policy.
    pub fn approve_connected(&self, connected_actor: &Actor) -> Result<bool, EvalError> {
        // All the AttrExpr's in the Join Policy must be present as Attributes on the actor and
        // have the same values.  It's ok for the actor to have more attributes than indicated in
        // a Join Policy.
        //
        // If join policy indicates (via flags) that the actor is a node, then the actor must return
        // true for `is_node()`. If there is no node flag then `is_node()` must return false.
        //
        // Any services offered by the actor must be allowed by policy.
        // The policy may have more services for the actor, but that must be picked up
        // by doing a re-auth. Identity keys are in the same bucket: a policy update does
        // not retroactively re-key a connected actor; new identity attributes are picked
        // up on re-auth via approve_connection.

        // Re-run join-policy matching against the actor's current attributes.
        let claims: Vec<Attribute> = connected_actor.attrs_iter().cloned().collect();
        let matching = self.policy.match_join_policies(&claims);
        if matching.is_empty() {
            // A node must be covered by a join policy; a non-node may remain
            // connected without one (see #227).
            return Ok(!connected_actor.is_node());
        }

        // Union the flags and services from all matching policies, mirroring
        // how `approve_connection` builds the actor.
        let mut flags: EnumSet<JFlag> = EnumSet::new();
        let mut services = HashSet::new();
        for jp in matching {
            flags |= jp.flags;
            if let Some(svcs) = &jp.services {
                services.extend(svcs.iter().cloned());
            }
        }

        // Node role must agree with policy in both directions.
        if flags.contains(JFlag::IsNode) != connected_actor.is_node() {
            return Ok(false);
        }

        // Every service offered by the actor must be allowed by policy. Policy
        // may allow more services than the actor offers; those are picked up on
        // re-auth, not here.
        if !connected_actor
            .services_iter()
            .all(|s| services.contains(s))
        {
            return Ok(false);
        }

        Ok(true)
    }

    fn match_policies(
        &self,
        allows: bool,
        src_actor: &Actor,
        dst_actor: &Actor,
        request: &PacketDesc,
        policy: &policy_capnp::policy::Reader,
    ) -> Result<Vec<Hit>, EvalError> {
        let mut hits = Vec::new();
        for (i, com_policy) in policy.get_com_policies().unwrap().iter().enumerate() {
            if allows != com_policy.get_allow() {
                continue;
            }
            if allows {
                debug!(target: EVAL, "trying to match allow policy #{i}");
            } else {
                debug!(target: EVAL, "trying to match deny policy #{i}");
            }
            let service_id = com_policy.get_service_id().unwrap().to_str().unwrap();
            let maybe_direction = match self.try_match_scope(request, &com_policy) {
                Some(ScopeMatchType::Forward) => {
                    // Source -> Dest match
                    // So requesting dest port matches a service.
                    // Proceed only if the destination provides a service.
                    if !dst_actor.is_provider() {
                        debug!(target: EVAL, "policy #{i} matches FWD but dest actor is not a provider");
                        continue;
                    }
                    // This policy only applies if the provider is providing the service referenced in the policy.
                    if !dst_actor.provides(service_id) {
                        debug!(
                            target: EVAL,
                            "policy #{i} matches FWD on ports but dest actor does not provide service {}",
                            service_id
                        );
                        continue;
                    }
                    debug!(target: EVAL, "policy #{i} matches FWD scope");
                    // This policy matches only if all conditions match.
                    if self.match_policy_conditions(src_actor, dst_actor, &com_policy, allows) {
                        Some(Direction::Forward)
                    } else {
                        None
                    }
                }
                Some(ScopeMatchType::Reverse) => {
                    // Dest -> Source match
                    // So requesting source port matches a service (is this a reply?)
                    // Proceed only if the source provides a service.
                    if !src_actor.is_provider() {
                        debug!(target: EVAL, "policy #{i} matches REV but src actor is not a provider");
                        continue;
                    }
                    // This policy only applies if the provider is providing the service referenced in the policy.
                    if !src_actor.provides(service_id) {
                        debug!(
                            target: EVAL,
                            "policy #{i} matches REV on ports but src actor does not provide service {}",
                            service_id
                        );
                        continue;
                    }
                    debug!(target: EVAL, "policy #{i} matches REV scope");
                    // This policy matches only if all conditions match.
                    if self.match_policy_conditions(dst_actor, src_actor, &com_policy, allows) {
                        Some(Direction::Reverse)
                    } else {
                        None
                    }
                }
                None => None,
            };
            if let Some(direction) = maybe_direction {
                if com_policy.has_signal() {
                    let signal_rdr = com_policy.get_signal().unwrap();
                    let signal = Signal {
                        message: signal_rdr.get_msg().unwrap().to_string().unwrap(),
                        service: signal_rdr.get_svc().unwrap().to_string().unwrap(),
                    };
                    debug!(target: EVAL, "policy #{i} hits {direction} with signal: {:?}", signal);
                    hits.push(Hit::new_with_signal(i, direction, signal));
                } else {
                    debug!(target: EVAL, "policy #{i} hits {direction} no signal");
                    hits.push(Hit::new_no_signal(i, direction));
                }
            }
        }
        debug!(target: EVAL, "matched {} policies", hits.len());
        Ok(hits)
    }

    /// Check that all conditions on the passed `com_policy` are satisfied by
    /// the `client_actor` and `service_actor`.  The policies "client
    /// conditions" are checked against the client_actor, and the "service
    /// conditions" are checked against the service_actor.
    ///
    /// To get an "allow/match", ALL conditions must be satisfied.
    fn match_policy_conditions(
        &self,
        client_actor: &Actor,
        server_actor: &Actor,
        com_policy: &policy_capnp::c_policy::Reader,
        for_allow: bool,
    ) -> bool {
        // All conditions must match for the policy to match. Expired attributes must
        // not help satisfy an allow policy; denies are matched against all attributes,
        // expired or not, so they stay fail-closed.
        if com_policy.has_client_conds() {
            for cond in com_policy.get_client_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, client_actor, for_allow) {
                    debug!(target: EVAL, "-- client condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        if com_policy.has_service_conds() {
            for cond in com_policy.get_service_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, server_actor, for_allow) {
                    debug!(target: EVAL, "-- service condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        true
    }

    /// Returns TRUE if the policy condition is satisfied by the actor. `for_allow`
    /// marks this as part of the allow pass, where expired attributes cannot match.
    fn match_condition_to_actor(
        &self,
        cond: &policy_capnp::attr_expr::Reader,
        actor: &Actor,
        for_allow: bool,
    ) -> bool {
        let value = if !cond.has_value() {
            None
        } else {
            let val_list = cond.get_value().unwrap();
            if val_list.len() == 0 {
                None
            } else if val_list.len() == 1 {
                Some(PAttrValue::Atom(
                    val_list.get(0).unwrap().to_str().unwrap().into(),
                ))
            } else {
                Some(PAttrValue::Set(
                    val_list
                        .iter()
                        .map(|v| v.unwrap().to_str().unwrap().into())
                        .collect(),
                ))
            }
        };
        let key = cond.get_key().unwrap().to_str().unwrap();

        // An expired attribute is indeterminate: we can neither confirm nor rule out
        // its value, so it can never satisfy an allow condition. Note this is not the
        // same as treating it as absent -- absent would make NE and EXCLUDES *pass*,
        // which would let expiry grant access. A key that was never set is unaffected.
        if for_allow && actor.get_attribute(key).is_some_and(|a| a.is_expired()) {
            debug!(target: EVAL, "-- condition key '{}' is expired, cannot match allow", key);
            return false;
        }

        match cond.get_op().unwrap() {
            policy_capnp::AttrOp::Eq => {
                match value {
                    None => {
                        // TODO: This is not valid and should be rejected at policy install.
                        warn!(target: EVAL, "INVALID ZPL: condition key '{}' has EQ op but no value", key);
                        return !for_allow;
                    }
                    Some(PAttrValue::Set(_)) => {
                        // EQ with a set is not supported for now, so this condition is
                        // indeterminate: it cannot satisfy an allow, and a deny keyed on
                        // it must still fire rather than silently disappear.
                        return !for_allow;
                    }
                    Some(PAttrValue::Atom(s)) => {
                        if !actor.has_attribute_value(key, s.as_str()) {
                            return false;
                        }
                    }
                }
            }
            policy_capnp::AttrOp::Ne => {
                match value {
                    None => {
                        // TODO: This is not valid and should be rejected at policy install.
                        warn!(target: EVAL, "INVALID ZPL: condition key '{}' has NE op but no value", key);
                        return !for_allow;
                    }
                    Some(PAttrValue::Set(_)) => {
                        // NE with a set is not supported for now, so this condition is
                        // indeterminate: it cannot satisfy an allow, and a deny keyed on
                        // it must still fire rather than silently disappear.
                        return !for_allow;
                    }
                    Some(PAttrValue::Atom(s)) => {
                        if actor.has_attribute_value(key, s.as_str()) {
                            return false;
                        }
                    }
                }
            }
            policy_capnp::AttrOp::Has => {
                let blank = match value {
                    None => true,
                    Some(ref v) => v.is_empty(),
                };
                if blank {
                    // This means we match if the actor has the attribute key present.
                    if !actor.has_attribute_named(key) {
                        return false;
                    }
                } else {
                    // HAS means the actor must have all the values set here.
                    if !actor.has_attribute_values(key, value.as_ref().unwrap().as_slice()) {
                        return false;
                    }
                }
            }
            policy_capnp::AttrOp::Excludes => {
                // Any values in here must not be present in the actor.
                // TODO: The compiler does not produce EXCLUDES or NE, so maybe we should remove them.
                let Some(ref values) = value else {
                    // Valueless EXCLUDES is indeterminate rather than a panic: it cannot
                    // satisfy an allow, and a deny keyed on it must still fire.
                    warn!(target: EVAL, "INVALID ZPL: condition key '{}' has EXCLUDES op but no value", key);
                    return !for_allow;
                };
                if actor.has_any_attribute_values(key, values.as_slice()) {
                    return false;
                }
            }
        };
        true
    }

    fn try_match_scope<'a>(
        &self,
        request: &PacketDesc,
        com_policy: &policy_capnp::c_policy::Reader<'a>,
    ) -> Option<ScopeMatchType> {
        // Each policy line describes access to a service.
        for scope in com_policy.get_scope().unwrap().iter() {
            if scope.get_protocol() != request.protocol() {
                continue;
            }
            let scope_match_type = match scope.which() {
                Ok(policy_capnp::scope::Port(pnum)) => {
                    if request.protocol() == ip_proto::IPV6_ICMP {
                        let allow_icmp_type = pnum.get_port_num();
                        if request.source_port() == allow_icmp_type {
                            Some(ScopeMatchType::Forward)
                        } else {
                            None
                        }
                    } else {
                        let allow_service_port_num = pnum.get_port_num();
                        if request.dest_port() == allow_service_port_num {
                            Some(ScopeMatchType::Forward)
                        } else if request.source_port() == allow_service_port_num {
                            Some(ScopeMatchType::Reverse)
                        } else {
                            None
                        }
                    }
                }
                Ok(policy_capnp::scope::PortRange(pr)) => {
                    if request.protocol() == ip_proto::IPV6_ICMP {
                        let icmp_type_request = pr.get_low();
                        let icmp_type_response = pr.get_high();

                        // Forward match if SRC->DST using the REQUEST type.
                        // Reverse match is SRC->DST using the RESPONSE type.
                        if request.source_port() == icmp_type_request {
                            Some(ScopeMatchType::Forward)
                        } else if request.source_port() == icmp_type_response {
                            Some(ScopeMatchType::Reverse)
                        } else {
                            None
                        }
                    } else {
                        let lowport = pr.get_low();
                        let highport = pr.get_high();
                        if request.dest_port() >= lowport && request.dest_port() <= highport {
                            Some(ScopeMatchType::Forward)
                        } else if request.source_port() >= lowport
                            && request.source_port() <= highport
                        {
                            Some(ScopeMatchType::Reverse)
                        } else {
                            None
                        }
                    }
                }
                Err(::capnp::NotInSchema(_)) => None,
            };
            if scope_match_type.is_none() {
                continue;
            }
            let scope_match_type = scope_match_type.unwrap();

            // If we are UDP and the UDP-one-way flag is set, then reverse match is not permitted.
            if request.protocol() == ip_proto::UDP && scope_match_type == ScopeMatchType::Reverse {
                match scope.get_flag() {
                    Ok(policy_capnp::ScopeFlag::UdpOneWay) => {
                        // Reverse not allowed, this is a one-way UDP service.
                        continue;
                    }
                    _ => (),
                }
            }

            // I don't think we need to check all the scopes once we get a match.
            return Some(scope_match_type);
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attribute::key;
    use bytes::{Buf, Bytes};
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime};
    use std::{path::Path, sync::Once};
    use tracing::Level;
    use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

    static TRACING_INIT: Once = Once::new();

    /// init logging
    fn setup() {
        TRACING_INIT.call_once(|| {
            tracing_subscriber::registry()
                .with(fmt::layer().with_thread_ids(true))
                .with(LevelFilter::from_level(Level::DEBUG))
                .init();
        });
    }

    /// Load a binary policy by name from the tests/zpl directory.
    fn load_policy(pname: &str) -> Policy {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let pname = Path::new(manifest_dir)
            .join("tests")
            .join("zpl")
            .join(pname);
        let encoded = std::fs::read(pname).unwrap();
        let encoded_container_bytes = Bytes::from(encoded);
        let container_reader = capnp::serialize::read_message(
            encoded_container_bytes.reader(),
            capnp::message::ReaderOptions::new(),
        )
        .unwrap();
        let container = container_reader
            .get_root::<policy_capnp::policy_container::Reader>()
            .unwrap();
        if !container.has_policy() {
            panic!("policy container missing 'policy' field");
        }
        let policy_bytes = container.get_policy().unwrap();
        Policy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes)).unwrap()
    }

    #[test]
    fn test_basic_eval() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users access content:red databases.
        let mut user = Actor::new();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 3);
                assert!(hits[0].direction == Direction::Forward);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }

        // Should deny access to green tagged users.
        let mut green_user = Actor::new();
        green_user
            .add_attr_from_parts("user.zpr.tag.green", "", Duration::from_secs(60))
            .unwrap();
        let decision = ctx.eval_request(&green_user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::Deny(hits)) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 2);
                assert!(hits[0].direction == Direction::Forward);
            }
            _ => panic!("expected deny decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_visa_info() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users access content:red databases.
        let mut user = Actor::new();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                let vinfo = ctx.visa_info_for_hit(&hits[0], &packet).unwrap();
                assert_eq!(
                    vinfo.zpl,
                    "(line 2) allow red users to access content:red services"
                );
                assert_eq!(vinfo.source_addr, packet.five_tuple.source_addr);
                assert_eq!(vinfo.dest_addr, packet.five_tuple.dest_addr);
                assert_eq!(vinfo.protocol, packet.protocol());
                assert_eq!(vinfo.source_port, 0); // high port becomes 0
                assert_eq!(vinfo.dest_port, 80);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    // Ran into an issue where libeval was not checking that the policy ID was applicable.
    // And this simple eval was failing.
    #[test]
    fn test_eval_with_never() {
        setup();
        let pol = load_policy("test-signal.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // User with bas_id and color:red should be able to access database service.
        let mut user = Actor::new();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();
        user.add_attr_from_parts("user.bas_id", "1000", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.bas_id", "1233", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 4);
                assert!(hits[0].direction == Direction::Forward);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_signal() {
        setup();
        let pol = load_policy("test-signal.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // Set user with color:green so it does not match color:red since in that
        // case we would match two policies.
        let mut user = Actor::new();
        user.add_attr_from_parts("user.color", "green", Duration::from_secs(60))
            .unwrap();
        user.add_attr_from_parts("user.bas_id", "1000", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.bas_id", "1233", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 4);
                assert!(hits[0].direction == Direction::Forward);
                assert!(hits[0].signal.is_some());
                let signal = hits[0].signal.as_ref().unwrap();
                assert_eq!(signal.message, "employee");
                assert_eq!(signal.service, "signalService");
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_ping_echo_request() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users ping pingdb
        let mut user = Actor::new();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "pingdb", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.bas_id", "1233", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_icmp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 0x80, 0).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                let vinfo = ctx.visa_info_for_hit(&hits[0], &packet).unwrap();
                assert_eq!(vinfo.zpl, "(line 5) allow red users to access pingdb");
                assert_eq!(vinfo.source_addr, packet.five_tuple.source_addr);
                assert_eq!(vinfo.dest_addr, packet.five_tuple.dest_addr);
                assert_eq!(vinfo.protocol, packet.protocol());
                assert_eq!(vinfo.source_port, 0x80);
                assert_eq!(vinfo.dest_port, 0x0);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_ping_echo_reply() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users ping pingdb
        let mut user = Actor::new();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "pingdb", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.bas_id", "1233", Duration::from_secs(60))
            .unwrap();

        // We picked up an echo reply packet.
        // According to policy this should match.
        let packet =
            PacketDesc::new_icmp("fd5a:5052:3000::2", "fd5a:5052:3000::1", 0x81, 0).unwrap();

        let decision = ctx.eval_request(&service, &user, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                let vinfo = ctx.visa_info_for_hit(&hits[0], &packet).unwrap();
                assert_eq!(vinfo.zpl, "(line 5) allow red users to access pingdb");
                assert_eq!(vinfo.source_addr, packet.five_tuple.source_addr);
                assert_eq!(vinfo.dest_addr, packet.five_tuple.dest_addr);
                assert_eq!(vinfo.protocol, packet.protocol());
                assert_eq!(vinfo.source_port, 0x81);
                assert_eq!(vinfo.dest_port, 0x0);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_ping_echo_reply_not_permitted() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users ping pingdb -- should not let randos send echo-reply to red users.
        let mut user = Actor::new();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "foo", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.bas_id", "1000", Duration::from_secs(60))
            .unwrap();

        // Echo reply to a red user
        let packet =
            PacketDesc::new_icmp("fd5a:5052:3000::2", "fd5a:5052:3000::1", 0x81, 0).unwrap();
        let decision = ctx.eval_request(&service, &user, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::NoMatch(s)) => {
                assert_eq!(s, "no matching policy");
            }
            _ => panic!("expected deny decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_node_can_connect() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut authenticated_claims = Vec::new();
        let mut unauthenticated_claims = Vec::new();

        authenticated_claims.push(Attribute::builder(key::CN).value("node.zpr.org"));

        unauthenticated_claims.push(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1"));

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        assert!(actor.is_node());

        // And address is set
        assert!(actor.get_zpr_addr().is_some());
        let ipaddr = actor.get_zpr_addr().unwrap().clone();
        assert_eq!(ipaddr, "fd5a:5052:90de::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_connect_allowed_even_with_no_allows() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut authenticated_claims = Vec::new();
        let mut unauthenticated_claims = Vec::new();

        authenticated_claims.push(Attribute::builder(key::CN).value("nobody.zpr.org"));

        unauthenticated_claims.push(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1"));

        match ctx.approve_connection(
            Some(authenticated_claims.as_slice()),
            Some(unauthenticated_claims.as_slice()),
        ) {
            Err(e) => panic!("expected connection approval to succeed, got {:?}", e),
            Ok(actor) => {
                assert!(!actor.is_node());
                assert!(actor.has_attribute_value(key::ROLE, ROLE_ADAPTER));
                // No join policy matched, so the requested (unauthenticated)
                // zpr.addr must have been scrubbed from the actor.
                assert!(actor.get_zpr_addr().is_none());
            }
        };
    }

    // Even when a join policy matches, only zpr.addr is taken from the
    // unauthenticated claims: a self-asserted identity-shaped claim (e.g.
    // `user.sub`) must never reach the actor, or the refresh path would send
    // it to trusted services as a lookup identity and leak another identity's
    // attributes to the claimant.
    #[test]
    fn test_join_match_does_not_commit_non_addr_unauth_claims() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // node.zpr.org matches a join policy in basic.bin2 (see
        // test_node_can_connect), so the zpr.addr claim IS validated and kept.
        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims = vec![
            Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1"),
            Attribute::builder("user.sub").value("someone-else"),
        ];

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        // The join policy matched: the requested address was committed...
        assert!(actor.is_node());
        assert!(actor.get_zpr_addr().is_some());
        // ...but the self-asserted user.sub claim was not.
        assert!(!actor.has_attribute_named("user.sub"));
    }

    // A node approved under the current policy should still pass re-check.
    #[test]
    fn test_approve_connected_node_still_valid() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1")];
        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();
        assert!(actor.is_node());

        assert!(ctx.approve_connected(&actor).unwrap());
    }

    // A non-node actor that matches no join policy may stay connected (#227).
    #[test]
    fn test_approve_connected_non_node_no_policy_ok() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("nobody.zpr.org")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();
        assert!(!actor.is_node());

        assert!(ctx.approve_connected(&actor).unwrap());
    }

    // A node whose attributes match no join policy must be rejected.
    #[test]
    fn test_approve_connected_node_not_in_policy() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut actor = Actor::new();
        actor
            .add_attr_from_parts(key::CN, "rando.zpr.org", Duration::from_secs(1000))
            .unwrap();
        actor
            .add_attr_from_parts(key::ROLE, ROLE_NODE, Duration::from_secs(1000))
            .unwrap();
        assert!(actor.is_node());

        assert!(!ctx.approve_connected(&actor).unwrap());
    }

    // Build the node actor from join policy 4 (node.zpr.org) with the given services.
    fn node_actor_with_services(services: &[&str]) -> Actor {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts(
                key::ZPR_ADDR,
                "fd5a:5052:90de::1",
                Duration::from_secs(1000),
            )
            .unwrap();
        actor
            .add_attr_from_parts(key::CN, "node.zpr.org", Duration::from_secs(1000))
            .unwrap();
        actor
            .add_attr_from_parts(key::ROLE, ROLE_NODE, Duration::from_secs(1000))
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(Duration::from_secs(1000))
                    .values(services.iter().copied()),
            )
            .unwrap();
        actor
    }

    // An actor offering only a subset of the services its policy allows is still
    // approved; the policy having extra services does not reject the connection.
    #[test]
    fn test_approve_connected_policy_has_extra_services_ok() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // Join policy 4 allows both "zpr/n0/vss" and "/zpr/n0"; offer just one.
        let actor = node_actor_with_services(&["zpr/n0/vss"]);
        assert!(ctx.approve_connected(&actor).unwrap());
    }

    // An actor offering a service its policy does not allow must be rejected.
    #[test]
    fn test_approve_connected_actor_service_not_in_policy() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // "not-allowed" is not among join policy 4's permitted services.
        let actor = node_actor_with_services(&["zpr/n0/vss", "not-allowed"]);
        assert!(!ctx.approve_connected(&actor).unwrap());
    }

    /// Build an attribute that is already expired.
    fn expired(key: &str, value: &str) -> Attribute {
        Attribute::builder(key)
            .expires(SystemTime::now() - Duration::from_secs(1))
            .value(value)
    }

    /// A user whose tag has expired cannot satisfy the allow policy that keys on it.
    #[test]
    fn test_expired_attr_cannot_match_allow() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut user = Actor::new();
        user.add_attribute(expired("user.zpr.tag.red", "")).unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::NoMatch(_)) => {}
            _ => panic!("expected NoMatch deny, not {:?}", decision),
        }
    }

    /// Expiry must never *grant* access: the deny pass ignores expiry, so an expired
    /// green tag still hits the deny policy rather than falling through to NoMatch.
    #[test]
    fn test_expired_attr_does_not_flip_deny() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut green_user = Actor::new();
        green_user
            .add_attribute(expired("user.zpr.tag.green", ""))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&green_user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::Deny(hits)) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 2);
            }
            _ => panic!("expected deny decision, not {:?}", decision),
        }
    }

    /// A key the actor never sets at all behaves exactly as before: the new guard is
    /// keyed on present-but-expired, not on absence.
    #[test]
    fn test_absent_attr_unaffected_by_expiry_guard() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // No user.zpr.tag at all -- neither the deny nor the allow policy can match.
        let user = Actor::new();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::NoMatch(_)) => {}
            _ => panic!("expected NoMatch deny, not {:?}", decision),
        }
    }

    /// A connected node whose join-policy key (CN) has expired matches no join policy
    /// and must be disconnected rather than silently re-approved. Role is a cached
    /// snapshot and NEVER_EXPIRES, so `is_node()` still reports true.
    #[test]
    fn test_approve_connected_expired_join_key_rejects_node() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut actor = node_actor_with_services(&["zpr/n0/vss"]);
        // Overwrite the CN join policy 4 keys on with an expired copy.
        actor
            .add_attribute(expired(key::CN, "node.zpr.org"))
            .unwrap();
        assert!(actor.is_node());

        assert!(!ctx.approve_connected(&actor).unwrap());
    }

    /// Build a standalone `AttrExpr` message so a single condition can be evaluated
    /// without compiling a whole policy.
    fn cond_message(
        key: &str,
        op: policy_capnp::AttrOp,
        values: &[&str],
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut expr = msg.init_root::<policy_capnp::attr_expr::Builder>();
            expr.set_key(key);
            expr.set_op(op);
            let mut vlist = expr.init_value(values.len() as u32);
            for (i, v) in values.iter().enumerate() {
                vlist.set(i as u32, *v);
            }
        }
        msg
    }

    /// An actor that authenticates with a CN gets exactly the CN as its identity key,
    /// even when it also carries a zpr.addr (guard test for the identity-key cascade).
    #[test]
    fn test_identity_keys_default_to_cn() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1")];
        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
        assert_eq!(actor.get_identity(), Some(vec!["node.zpr.org".to_string()]));
    }

    /// Without a CN, an actor carrying a zpr.addr uses that address as its identity key.
    #[test]
    fn test_identity_keys_fall_back_to_zpr_addr_without_cn() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::2")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::ZPR_ADDR]);
    }

    /// With neither CN nor zpr.addr, a synthesized zpr.actor_hash attribute becomes the
    /// identity key, so the identity-key set is never empty.
    #[test]
    fn test_identity_keys_fall_back_to_actor_hash() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder("user.color").value("red")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::ACTOR_HASH]);
        let hash_attr = actor.get_attribute(key::ACTOR_HASH).unwrap();
        assert!(hash_attr.get_value().first().unwrap().starts_with("hash:"));
    }

    /// Build a TrustedService test record from attribute-mapping strings and the
    /// service-side names of its identity attributes.
    fn ts(id: &str, mappings: &[&str], identity: &[&str]) -> zpr::policy_types::TrustedService {
        zpr::policy_types::TrustedService {
            service_id: id.to_string(),
            expiration_seconds: 3600,
            returns_attrs: mappings
                .iter()
                .map(|m| zpr::policy_types::parse_attribute_mapping(m).unwrap())
                .collect(),
            identity_attrs: identity.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Build an EvalContext over an in-memory policy carrying the given trusted services.
    fn ctx_with_trusted_services(records: &[zpr::policy_types::TrustedService]) -> EvalContext {
        let bytes = crate::policy::policy_bytes_with_trusted_services(records);
        EvalContext::new(Arc::new(Policy::new_from_policy_bytes(bytes).unwrap()))
    }

    /// A policy-declared identity attribute joins the builtin CN identity key: the two
    /// are a union, not a fallback. The core behavior of issue #201.
    #[test]
    fn test_policy_identity_attr_unions_with_cn() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts("bas", &["bas_id -> user.bas_id"], &["bas_id"])]);

        let authenticated_claims = vec![
            Attribute::builder(key::CN).value("a.zpr"),
            Attribute::builder("user.bas_id").value("1233"),
        ];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN, "user.bas_id"]);
        assert_eq!(
            actor.get_identity(),
            Some(vec!["a.zpr".to_string(), "1233".to_string()])
        );
    }

    /// An actor identified by a policy-declared attribute alone gets that key and no
    /// synthesized actor hash.
    #[test]
    fn test_policy_identity_attr_without_cn_is_not_hashed() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts("bas", &["bas_id -> user.bas_id"], &["bas_id"])]);

        let authenticated_claims = vec![Attribute::builder("user.bas_id").value("1233")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec!["user.bas_id"]);
        assert!(actor.get_attribute(key::ACTOR_HASH).is_none());
    }

    /// A declared identity attribute the actor does not carry changes nothing: the CN
    /// stays the sole identity key (the no-regression case every current caller hits).
    #[test]
    fn test_policy_identity_attr_absent_from_actor_leaves_cn() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts("bas", &["bas_id -> user.bas_id"], &["bas_id"])]);

        let authenticated_claims = vec![Attribute::builder(key::CN).value("a.zpr")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
    }

    /// Declaring an identity attribute must not suppress the last-resort hash for an
    /// actor that carries neither the CN nor the declared attribute.
    #[test]
    fn test_no_identity_attr_present_still_hashes() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts("bas", &["bas_id -> user.bas_id"], &["bas_id"])]);

        let authenticated_claims = vec![Attribute::builder("user.color").value("red")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::ACTOR_HASH]);
    }

    /// Policy-declared keys keep policy order after the CN; fails if the loop inserts
    /// at order 0 (which would reverse them).
    #[test]
    fn test_policy_identity_keys_follow_policy_order() {
        setup();
        let ctx =
            ctx_with_trusted_services(&[ts("bas", &["a -> user.a", "z -> user.z"], &["z", "a"])]);

        let authenticated_claims = vec![
            Attribute::builder(key::CN).value("a.zpr"),
            Attribute::builder("user.a").value("va"),
            Attribute::builder("user.z").value("vz"),
        ];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN, "user.z", "user.a"]);
    }

    /// A policy that names the CN itself as an identity attribute must not duplicate it:
    /// add_identity_key does not dedupe, so the union loop has to.
    #[test]
    fn test_policy_identity_cn_is_not_duplicated() {
        setup();
        let ctx =
            ctx_with_trusted_services(&[ts("bas", &["cn -> device.zpr.adapter.cn"], &["cn"])]);

        let authenticated_claims = vec![Attribute::builder(key::CN).value("a.zpr")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
    }

    /// A tag mapping declared as identity resolves to nothing: tags are valueless, so
    /// carrying the tag attribute never adds an identity key.
    #[test]
    fn test_policy_identity_tag_spec_is_not_an_identity_key() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts("bas", &["gov -> #user.government"], &["gov"])]);

        let authenticated_claims = vec![
            Attribute::builder(key::CN).value("a.zpr"),
            Attribute::builder("user.zpr.tag.government").value(""),
        ];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
    }

    /// Conditions libeval cannot evaluate -- valueless EQ/NE/EXCLUDES, and set-valued
    /// EQ/NE -- are indeterminate: they must never satisfy an allow, and must never let
    /// a deny silently stop matching. Valueless EXCLUDES also used to panic here.
    #[test]
    fn test_indeterminate_conditions_fail_safe() {
        setup();
        let ctx = EvalContext::new(Arc::new(load_policy("basic.bin2")));
        let actor = Actor::new();

        let cases: [(policy_capnp::AttrOp, &[&str]); 5] = [
            (policy_capnp::AttrOp::Eq, &[]),
            (policy_capnp::AttrOp::Ne, &[]),
            (policy_capnp::AttrOp::Excludes, &[]),
            (policy_capnp::AttrOp::Eq, &["a", "b"]),
            (policy_capnp::AttrOp::Ne, &["a", "b"]),
        ];
        for (op, values) in cases {
            let msg = cond_message("user.zpr.tag", op, values);
            let cond = msg
                .get_root_as_reader::<policy_capnp::attr_expr::Reader>()
                .unwrap();
            assert!(
                !ctx.match_condition_to_actor(&cond, &actor, true),
                "{op:?} with {values:?} must not satisfy an allow"
            );
            assert!(
                ctx.match_condition_to_actor(&cond, &actor, false),
                "{op:?} with {values:?} must keep a deny matching"
            );
        }
    }
}
