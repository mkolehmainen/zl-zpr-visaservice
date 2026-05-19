use crate::actor::Actor;
use crate::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE, key};
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
use std::time::{Duration, SystemTime};
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
        expiration: Duration,
    ) -> Result<Actor, EvalError> {
        if authenticated_claims.is_none() {
            return Err(EvalError::AttributeMissing(
                "no authenticated claims provided".into(),
            ));
        }
        let authenticated_claims = authenticated_claims.unwrap();

        let mut query_claims = Vec::new();
        query_claims.extend_from_slice(authenticated_claims);

        // If a zpr.addr is present in auth claims, we use that to match
        // policy too.
        if let Some(unauth_claims) = unauthenticated_claims {
            for ua_attr in unauth_claims {
                if ua_attr.get_key() == key::ZPR_ADDR {
                    query_claims.push(ua_attr.clone());
                }
            }
        }

        // Query to see if the authenticated claims match any join policies.
        let matching_jps = self.policy.match_join_policies(&query_claims);
        if matching_jps.is_empty() {
            return Err(EvalError::NoMatch);
        }
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

        for attr in &query_claims {
            if let Err(e) = actor.add_attribute(attr.clone()) {
                warn!(target: EVAL, "dropping invalid authenticated claim attribute: {}", e);
            }
        }

        let role_attr = if flags.contains(JFlag::IsNode) {
            Attribute::builder(key::ROLE)
                .expires_in(expiration)
                .value(ROLE_NODE)
        } else {
            Attribute::builder(key::ROLE)
                .expires_in(expiration)
                .value(ROLE_ADAPTER)
        };
        actor.add_attribute(role_attr).unwrap();

        if !services.is_empty() {
            debug!(target: EVAL, "actor provides services: {:?}", services);
            let svc_attr = Attribute::new(
                key::SERVICES.into(),
                &services.iter().cloned().collect::<Vec<String>>(),
                SystemTime::now() + expiration,
            );
            actor.add_attribute(svc_attr).unwrap();
        }

        actor
            .add_attribute(
                Attribute::builder(key::VINST)
                    .expires_in(expiration)
                    .value(self.policy.get_vinst().to_string()),
            )
            .unwrap();

        // Policy configuration also tells us what attributes are tied to identity.
        // TODO: use policy to figure out the identity attributes. (https://github.com/org-zpr/zpr-visaservice/issues/201)
        // For now this is just a hack: we try CN, address, and if those fail we use the hash.
        if actor.has_attribute_named(key::CN) {
            // use cn
            actor.add_identity_key(0, key::CN).unwrap();
        } else if actor.has_attribute_named(key::ZPR_ADDR) {
            // use addr
            actor.add_identity_key(0, key::ZPR_ADDR).unwrap();
        } else {
            // use hash
            let mut s = DefaultHasher::new();
            actor.hash(&mut s);
            let hash_str = format!("hash:{:x}", s.finish());
            actor
                .add_attribute(Attribute::builder(key::ACTOR_HASH).value(hash_str))
                .unwrap();
            actor.add_identity_key(0, key::ACTOR_HASH).unwrap();
        }

        Ok(actor)
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
                    if self.match_policy_conditions(src_actor, dst_actor, &com_policy) {
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
                    if self.match_policy_conditions(dst_actor, src_actor, &com_policy) {
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

    fn match_policy_conditions(
        &self,
        client_actor: &Actor,
        server_actor: &Actor,
        com_policy: &policy_capnp::c_policy::Reader,
    ) -> bool {
        // All conditions must match for the policy to match.
        if com_policy.has_client_conds() {
            for cond in com_policy.get_client_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, client_actor) {
                    debug!(target: EVAL, "-- client condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        if com_policy.has_service_conds() {
            for cond in com_policy.get_service_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, server_actor) {
                    debug!(target: EVAL, "-- service condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        true
    }

    /// Returns TRUE if the policy condition is satisfied by the actor.
    fn match_condition_to_actor(
        &self,
        cond: &policy_capnp::attr_expr::Reader,
        actor: &Actor,
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

        match cond.get_op().unwrap() {
            policy_capnp::AttrOp::Eq => {
                match value {
                    None => {
                        // Hmm... KEY, EQ, NONE ?? Is this valid?
                        if actor.has_attribute_named(key) {
                            return false;
                        }
                    }
                    Some(PAttrValue::Set(_)) => {
                        // EQ with a set is not supported for now.
                        return false;
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
                        // Hmm... KEY, NE, NONE ?? Is this valid?
                        if !actor.has_attribute_named(key) {
                            return false;
                        }
                    }
                    Some(PAttrValue::Set(_)) => {
                        // NE with a set is not supported for now.
                        return false;
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
                if actor.has_any_attribute_values(key, value.as_ref().unwrap().as_slice()) {
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
    use std::time::Duration;
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
        user.add_attr_from_parts("user.zpr.tag", "user.red", Duration::from_secs(60))
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
                assert_eq!(hits[0].match_idx, 4);
                assert!(hits[0].direction == Direction::Forward);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }

        // Should deny access to green tagged users.
        let mut green_user = Actor::new();
        green_user
            .add_attr_from_parts("user.zpr.tag", "user.green", Duration::from_secs(60))
            .unwrap();
        let decision = ctx.eval_request(&green_user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::Deny(hits)) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 3);
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
        user.add_attr_from_parts("user.zpr.tag", "user.red", Duration::from_secs(60))
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
        user.add_attr_from_parts("user.zpr.tag", "user.red", Duration::from_secs(60))
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
                assert_eq!(hits[0].match_idx, 1);
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
                assert_eq!(hits[0].match_idx, 1);
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
        user.add_attr_from_parts("user.zpr.tag", "user.red", Duration::from_secs(60))
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
        user.add_attr_from_parts("user.zpr.tag", "user.red", Duration::from_secs(60))
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
        user.add_attr_from_parts("user.zpr.tag", "user.red", Duration::from_secs(60))
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
                Duration::from_secs(1000),
            )
            .unwrap();

        assert!(actor.is_node());

        // And address is set
        assert!(actor.get_zpr_addr().is_some());
        let ipaddr = actor.get_zpr_addr().unwrap().clone();
        assert_eq!(ipaddr, "fd5a:5052:90de::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_connect_fail() {
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
            Duration::from_secs(1000),
        ) {
            Err(_) => {}
            Ok(actor) => panic!("expected connection approval to fail, got {:?}", actor),
        };
    }
}
