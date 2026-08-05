//! z-machine is the ZPT execution machine which executes ZPT "programs" line by
//! line.  Program lines either update state or sends API calls to the executor.

use rand::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{MachineError, PioError};
use crate::out::OutputFormatter;
use crate::pio;

use libeval::actor::Actor;
use libeval::attribute::Attribute;
use libeval::eval::EvalContext;
use libeval::eval_result::{FinalDeny, PartialEvalResult};
use zpr::vsapi_types::PacketDesc;
use zpr::vsapi_types::vsapi_ip_number as ip_proto;

const DEF_SOURCE_ADDR: &str = "fd5a:5052:3000::1";
const DEF_DEST_ADDR: &str = "fd5a:5052:3000::2";

/// IP Protocol is 8 bits.
type IpProtoT = u8;

#[derive(Debug, Clone)]
pub enum Instruction {
    Help(Option<String>), // String holds additional args present after "help"
    Load(PathBuf),
    Set {
        name: String,
        key: String,
        value: String, // may be comma separated list for multi-valued attributes
    },
    Eval {
        prot: IpProtoT,
        source_expr: ActorExpr,
        dest_expr: ActorExpr,
        extra: Option<InstrExtra>,
    },
    Connect {
        authd_claims: Option<Vec<Attribute>>,
        unauthd_claims: Option<Vec<Attribute>>,
    },
    Dumpdb,
}

#[derive(Debug, Clone)]
pub enum ActorExpr {
    ActorName(String),
    ActorNameAndPort(String, u16),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstrExtra {
    TcpFlags(u8),
    IcmpTypeCode(u8, u8),
}

#[derive(Default)]
pub struct State {
    ctx: Option<EvalContext>,
    policy_path: Option<PathBuf>,
    actor_db: HashMap<String, Actor>,
}

#[allow(dead_code)]
enum PortMissingBehavior {
    Error(String),    // if missing, error with a message
    HighPort,         // pick a random high (>1024) port
    DefaultPort(u16), // pick a specific default port
}

pub struct ZMachine {
    base_path: PathBuf,
    eval_counter: usize,
}

impl ZMachine {
    pub fn new(base_path: &Path) -> Self {
        ZMachine {
            base_path: base_path.to_path_buf(),
            eval_counter: 0,
        }
    }

    pub fn execute(
        &mut self,
        ins: &Instruction,
        state: &mut State,
        outfmt: &mut Box<dyn OutputFormatter>,
    ) -> Result<(), MachineError> {
        match ins {
            Instruction::Load(path) => {
                let path = if path.is_relative() {
                    self.base_path.join(path)
                } else {
                    path.to_path_buf()
                };
                state.load_policy(&path)?;
                Ok(())
            }
            Instruction::Set { name, key, value } => {
                state.set_actor_attribute(name, key, value)?;
                Ok(())
            }
            Instruction::Eval {
                prot,
                source_expr,
                dest_expr,
                extra,
            } => {
                self.eval_counter += 1;
                // Evaluate the protocol action from source to destination.
                // This may involve sending packets or simulating network actions.
                // Handle errors related to invalid expressions or unsupported protocols.
                if !state.has_policy() {
                    return Err(MachineError::ExecutionError(
                        "No policy loaded. Use 'load <path>' to load a policy.".to_string(),
                    ));
                }
                match *prot {
                    ip_proto::TCP => self.eval_tcp(state, source_expr, dest_expr, *extra, outfmt),
                    ip_proto::UDP => self.eval_udp(state, source_expr, dest_expr, outfmt),
                    ip_proto::IPV6_ICMP => {
                        self.eval_icmp(state, source_expr, dest_expr, *extra, outfmt)
                    }
                    _ => {
                        return Err(MachineError::ExecutionError(format!(
                            "Unsupported protocol: {}",
                            prot
                        )));
                    }
                }
            }
            Instruction::Connect {
                authd_claims,
                unauthd_claims,
            } => {
                self.eval_counter += 1;
                if !state.has_policy() {
                    return Err(MachineError::ExecutionError(
                        "No policy loaded. Use 'load <path>' to load a policy.".to_string(),
                    ));
                }
                self.eval_connect(state, authd_claims, unauthd_claims, outfmt)
            }
            Instruction::Dumpdb => {
                state.dump_db(outfmt);
                Ok(())
            }
            Instruction::Help(None) => {
                self.print_help();
                Ok(())
            }
            Instruction::Help(Some(topic)) => {
                match topic.to_lowercase().as_str() {
                    "tcp" => self.print_help_tcp(),
                    "icmp" => self.print_help_icmp(),
                    _ => {
                        outfmt.write_error(&format!("unknown help topic: '{topic}'"));
                    }
                }
                Ok(())
            }
        }
    }

    fn print_help(&self) {
        println!("Policy commands:");
        println!("  load <path>          - Load a ZPR policy from the specified file path.");
        println!();
        println!("Actor commands:");
        println!("  set <actor> <k>:<v>  - Set attribute <k> to value <v> for actor <actor>.");
        println!("  dumpdb               - Dump the current actor database.");
        println!();
        println!("Connection commands:");
        println!("  connect [--ac <k>:<v> ...] [--uc <k>:<v> ...] ...");
        println!("                      - Call approve_connection with given claims.");
        println!(
            "                        --ac for an authenticated claim, --uc for unauthenticated."
        );
        println!("Eval commands:");
        println!("  eval TCP <src_actor>.<src_port> > <dst_actor>.<dst_port> [flags]");
        println!("  eval UDP <src_actor> > <dst_actor>");
        println!("  eval ICMP6 <src_actor> > <dst_actor> <type>");
        println!();
        println!("Miscellaneous commands:");
        println!("  help                - Show this help message.");
        println!("  help tcp            - Help with tcp flag format.");
        println!("  help icmp           - Help with icmp type and code format.");
        println!("  exit, quit, q, ^C   - Exit the REPL.");
        println!();
    }

    fn print_help_tcp(&self) {
        println!("TCP flags:");
        println!("  [S] syn");
        println!("  [P] push");
        println!("  [R] reset");
        println!("  [F] fin");
        println!("  [.] ack");
        println!("  Ack '.' can be combined with the other flags, eg [S.] for a SYN-ACK.");
        println!();
    }

    fn print_help_icmp(&self) {
        println!("ICMP type and code:");
        println!("  You can specify ICMP type and code in one of three ways:");
        println!("    - <type>:<code>   both 8-bit decimal values");
        println!(
            "    - 0x<typecode>    16 bit hex encoded, big-endian value with type in high byte, code in low byte"
        );
        println!("    - <type-name>     eg, 'echo-request' (and code is set to zero)");
        println!();
        println!("  Common ICMPv6 types:");
        println!("    1   destination-unreachable");
        println!("    2   packet-too-big");
        println!("    3   time-exceeded");
        println!("    4   parameter-problem");
        println!("   128  echo-request");
        println!("   129  echo-reply");
        println!();
        println!("  If code is not specified, it defaults to zero.");
        println!();
    }

    fn eval_connect(
        &self,
        state: &State,
        authd_claims: &Option<Vec<Attribute>>,
        unauthd_claims: &Option<Vec<Attribute>>,
        outfmt: &mut Box<dyn OutputFormatter>,
    ) -> Result<(), MachineError> {
        // TODO: libeval should take same types for authd and unauthd claims!!

        let libeval_authd_claims = if let Some(ac_vec) = authd_claims {
            Some(ac_vec.as_slice())
        } else {
            None
        };
        let libeval_unauthed_claims = if let Some(uc_vec) = unauthd_claims {
            Some(uc_vec.as_slice())
        } else {
            None
        };

        if let Some(ctx) = state.get_ctx() {
            match ctx.approve_connection(libeval_authd_claims, libeval_unauthed_claims) {
                Ok(actor) => {
                    outfmt.write_connection_approved(&actor);
                }
                Err(e) => {
                    outfmt.write_connection_denied(&e);
                }
            }
        }
        Ok(())
    }

    fn eval_tcp(
        &self,
        state: &State,
        source_expr: &ActorExpr,
        dest_expr: &ActorExpr,
        _extra: Option<InstrExtra>,
        outfmt: &mut Box<dyn OutputFormatter>,
    ) -> Result<(), MachineError> {
        let (src_actor, src_port) =
            self.resolve_actor_and_port(state, source_expr, PortMissingBehavior::HighPort)?;
        let (dst_actor, dst_port) = self.resolve_actor_and_port(
            state,
            dest_expr,
            PortMissingBehavior::Error("destination port required for TCP".to_string()),
        )?;

        // TODO: Someting interesting with TCP flags?

        let pd = PacketDesc::new_tcp(DEF_SOURCE_ADDR, DEF_DEST_ADDR, src_port, dst_port);
        self.do_eval(state, src_actor, dst_actor, &pd?, outfmt)
    }

    fn eval_udp(
        &self,
        state: &State,
        source_expr: &ActorExpr,
        dest_expr: &ActorExpr,
        outfmt: &mut Box<dyn OutputFormatter>,
    ) -> Result<(), MachineError> {
        let (src_actor, src_port) =
            self.resolve_actor_and_port(state, source_expr, PortMissingBehavior::HighPort)?;
        let (dst_actor, dst_port) = self.resolve_actor_and_port(
            state,
            dest_expr,
            PortMissingBehavior::Error("destination port required for UDP".to_string()),
        )?;

        let pd = PacketDesc::new_udp(DEF_SOURCE_ADDR, DEF_DEST_ADDR, src_port, dst_port);
        self.do_eval(state, src_actor, dst_actor, &pd?, outfmt)
    }

    fn eval_icmp(
        &self,
        state: &mut State,
        source_expr: &ActorExpr,
        dest_expr: &ActorExpr,
        extra: Option<InstrExtra>,
        outfmt: &mut Box<dyn OutputFormatter>,
    ) -> Result<(), MachineError> {
        let (icmp_type, icmp_code) = match extra {
            Some(InstrExtra::IcmpTypeCode(t, c)) => (t, c),
            _ => {
                return Err(MachineError::ExecutionError(
                    "Invalid extra for ICMP; expected at least type".to_string(),
                ));
            }
        };
        let src_actor = self.resolve_actor_no_port(state, source_expr)?;
        let dst_actor = self.resolve_actor_no_port(state, dest_expr)?;
        let pd = PacketDesc::new_icmp(DEF_SOURCE_ADDR, DEF_DEST_ADDR, icmp_type, icmp_code);
        self.do_eval(state, src_actor, dst_actor, &pd?, outfmt)
    }

    fn do_eval(
        &self,
        state: &State,
        src_actor: &Actor,
        dst_actor: &Actor,
        pd: &PacketDesc,
        outfmt: &mut Box<dyn OutputFormatter>,
    ) -> Result<(), MachineError> {
        if let Some(ctx) = state.get_ctx() {
            match ctx.eval_request(src_actor, dst_actor, pd) {
                Ok(decision) => {
                    self.present_decision(state, &decision, pd, outfmt);
                }
                Err(e) => {
                    return Err(MachineError::ExecutionError(format!(
                        "policy evaluation error: {}",
                        e
                    )));
                }
            }
        } else {
            return Err(MachineError::ExecutionError(
                "No policy loaded. Use 'load <path>' to load a policy.".to_string(),
            ));
        }
        Ok(())
    }

    fn present_decision(
        &self,
        state: &State,
        decision: &PartialEvalResult,
        pd: &PacketDesc,
        outfmt: &mut Box<dyn OutputFormatter>,
    ) {
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                let mut vprops = Vec::new();
                for hit in hits {
                    let vprop_or_error =
                        state.get_ctx().as_ref().unwrap().visa_info_for_hit(hit, pd);
                    vprops.push(vprop_or_error);
                }
                outfmt.write_allow(self.eval_counter, hits, &vprops);
            }
            PartialEvalResult::Deny(FinalDeny::Deny(hits)) => {
                outfmt.write_deny(self.eval_counter, hits);
            }
            PartialEvalResult::Deny(FinalDeny::NoMatch(reason)) => {
                outfmt.write_no_match(self.eval_counter, reason);
            }
            PartialEvalResult::NeedsRoute(_) => {
                outfmt.write_error("PartialEvalResult::NeedsRoute not handled"); // TODO
            }
        }
    }

    /// For TCP/UDP.
    fn resolve_actor_and_port<'s>(
        &self,
        state: &'s State,
        expr: &ActorExpr,
        port_missing: PortMissingBehavior,
    ) -> Result<(&'s Actor, u16), MachineError> {
        let (actor, port) = match expr {
            ActorExpr::ActorName(name) => (
                state.get_actor(name).ok_or_else(|| {
                    MachineError::ExecutionError(format!("unknown actor: {name}"))
                })?,
                None,
            ),

            ActorExpr::ActorNameAndPort(name, pnum) => (
                state.get_actor(name).ok_or_else(|| {
                    MachineError::ExecutionError(format!("unknown actor: {name}"))
                })?,
                Some(*pnum),
            ),
        };

        if port.is_none() {
            match port_missing {
                PortMissingBehavior::Error(msg) => {
                    return Err(MachineError::ExecutionError(msg));
                }
                PortMissingBehavior::HighPort => {
                    let high_port = rand::rng().random_range(1025..=65535);
                    return Ok((actor, high_port));
                }
                PortMissingBehavior::DefaultPort(default_port) => {
                    return Ok((actor, default_port));
                }
            }
        }

        Ok((actor, port.unwrap()))
    }

    /// For ICMP
    fn resolve_actor_no_port<'s>(
        &self,
        state: &'s State,
        expr: &ActorExpr,
    ) -> Result<&'s Actor, MachineError> {
        match expr {
            ActorExpr::ActorName(name) => Ok(state
                .get_actor(name)
                .ok_or_else(|| MachineError::ExecutionError(format!("unknown actor: {name}")))?),

            ActorExpr::ActorNameAndPort(name, pnum) => Err(MachineError::ExecutionError(format!(
                "port not allowed here: {name}.{pnum}"
            )))?,
        }
    }
}

impl State {
    pub fn new() -> Self {
        State::default()
    }

    pub fn get_ctx(&self) -> Option<&EvalContext> {
        self.ctx.as_ref()
    }

    pub fn has_policy(&self) -> bool {
        self.ctx.is_some()
    }

    pub fn dump_db(&self, outfmt: &mut Box<dyn OutputFormatter>) {
        outfmt.write_actor_db(&self.actor_db);
    }

    pub fn load_policy(&mut self, path: &Path) -> Result<(), PioError> {
        let policy = Arc::new(pio::load_policy(path)?);
        self.ctx = Some(EvalContext::new(policy));
        self.policy_path = Some(path.to_path_buf());
        // todo: centralized way to report status, eg "loaded XYZ"
        Ok(())
    }

    pub fn set_actor_attribute(
        &mut self,
        actor_name: &str,
        key: &str,
        value: &str,
    ) -> Result<(), MachineError> {
        let actor = self
            .actor_db
            .entry(actor_name.to_string())
            .or_insert_with(|| Actor::new());

        // TODO: Attribute allows duplicate attribute keys -- it should not.

        // Humans enter multi value attributes as comma separated values.
        let values: Vec<String> = value.split(',').map(|s| s.trim().to_string()).collect();
        let attr = Attribute::builder(key)
            .expires_in(Duration::from_secs(3600))
            .values(values);
        actor.add_attribute(attr)?;
        Ok(())
    }

    pub fn get_actor(&self, name: &str) -> Option<&Actor> {
        self.actor_db.get(name)
    }
}
