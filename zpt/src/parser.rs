use libeval::attribute::Attribute;
use std::path::PathBuf;
use zpr::vsapi_types::vsapi_ip_number as ip_proto;

use crate::error::ParseError;
use crate::zmachine::{ActorExpr, InstrExtra, Instruction};

mod packet {
    #[allow(dead_code)]
    pub mod tcp {
        pub const FIN: u8 = 0x01;
        pub const SYN: u8 = 0x02;
        pub const RST: u8 = 0x04;
        pub const PSH: u8 = 0x08;
        pub const ACK: u8 = 0x10;
        pub const URG: u8 = 0x20;
    }
}

pub fn parse(input_line: &str) -> Result<Instruction, ParseError> {
    let mut parsing = Parsing::new(input_line);
    match parsing.pop_word()?.to_lowercase().as_str() {
        "help" => {
            if parsing.is_empty() {
                Ok(Instruction::Help(None))
            } else {
                Ok(Instruction::Help(Some(parsing.pop_eol()?)))
            }
        }

        "dumpdb" => Ok(Instruction::Dumpdb),
        "load" => {
            let path = parsing.pop_path()?;
            Ok(Instruction::Load(path))
        }
        "set" => {
            // TODO: Expiration
            let actor_name = parsing.pop_word()?;
            let attr_expr = parsing.pop_eol()?;
            let (key, val) = parse_key_value(attr_expr)?;
            Ok(Instruction::Set {
                name: actor_name,
                key,
                value: val,
            })
        }
        "eval" => {
            let prot_str = parsing.pop_word()?.to_lowercase();
            match prot_str.as_str() {
                "tcp" => Ok(parse_tcp_expr(parsing.pop_eol()?)?),
                "udp" => Ok(parse_udp_expr(parsing.pop_eol()?)?),
                "icmp6" => Ok(parse_icmp6_expr(parsing.pop_eol()?)?),
                _ => Err(ParseError::UnknownInstruction),
            }
        }
        "connect" => Ok(parse_connect_expr(parsing.pop_eol()?)?),
        _ => Err(ParseError::UnknownInstruction),
    }
}

fn parse_key_value(expr: String) -> Result<(String, String), ParseError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(ParseError::InvalidFormat(
            "empty attribute expression".to_string(),
        ));
    }
    if expr.starts_with('#') {
        // Tag. Encoded as a valueless per-tag key: `#user.red` -> `user.zpr.tag.red`.
        let tag = expr[1..].trim();
        let Some((domain, name)) = tag.split_once('.') else {
            return Err(ParseError::InvalidFormat(format!(
                "tag must be domain-qualified, e.g. #user.red: '{expr}'"
            )));
        };
        if domain.is_empty() || name.is_empty() {
            return Err(ParseError::InvalidFormat(
                "empty tag in attribute expression".to_string(),
            ));
        }
        Ok((format!("{domain}.zpr.tag.{name}"), String::new()))
    } else if let Some(colon_pos) = expr.find(':') {
        let key = expr[..colon_pos].trim();
        let value = expr[colon_pos + 1..].trim();
        if key.is_empty() {
            return Err(ParseError::InvalidFormat(
                "empty key in attribute expression".to_string(),
            ));
        }
        if value.starts_with('{') && value.ends_with('}') {
            // Multi-value
            let inner = &value[1..value.len() - 1];
            let values: Vec<String> = inner
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if values.is_empty() {
                return Err(ParseError::InvalidFormat(
                    "empty multi-value attribute expression".to_string(),
                ));
            }
            Ok((key.to_string(), values.join(", ")))
        } else {
            // Single value (can be empty)
            Ok((key.to_string(), value.to_string()))
        }
    } else {
        Err(ParseError::InvalidFormat(
            "attribute expression must contain ':' or start with '#'".to_string(),
        ))
    }
}

/// Split the value returned by [parse_key_value] into its attribute values.
/// Humans enter multi value attributes as a comma separated list; an empty
/// value (e.g. a tag) means no values, not one empty value.
pub fn split_values(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split(',').map(|s| s.trim().to_string()).collect()
    }
}

// format of a connect expression is:
//   `connect <claim_expr> [<claim_expr> ...]`
//
//   where <claim_expr> is:
//     `<claim_type> <key>:<value>`
//
//   and <claim_type> is one of:
//     `--ac` for an authentication claim
//     `--uc` for an unauthenticated claim
//
fn parse_connect_expr(expr: String) -> Result<Instruction, ParseError> {
    let mut authd_claims = Vec::new();
    let mut unauthd_claims = Vec::new();

    let mut toks_iter = expr.split_whitespace();
    while let Some(claim_type) = toks_iter.next() {
        let mut claim_kv = toks_iter
            .next()
            .ok_or_else(|| {
                ParseError::InvalidFormat(
                    "missing key:value for claim in connect expression".to_string(),
                )
            })?
            .to_string();
        // A multi-value claim like `colors:{red, blue}` may contain spaces, so
        // keep consuming tokens until the brace closes.
        while claim_kv.contains('{') && !claim_kv.contains('}') {
            let more = toks_iter.next().ok_or_else(|| {
                ParseError::InvalidFormat(
                    "unterminated '{' in multi-value claim in connect expression".to_string(),
                )
            })?;
            claim_kv.push(' ');
            claim_kv.push_str(more);
        }
        let (key, value) = parse_key_value(claim_kv)?;
        let values = split_values(&value);

        match claim_type {
            "--ac" => {
                authd_claims.push(Attribute::builder(key).values(values));
            }
            "--uc" => {
                unauthd_claims.push(Attribute::builder(key).values(values));
            }
            _ => {
                return Err(ParseError::InvalidFormat(format!(
                    "unknown claim type '{}' in connect expression",
                    claim_type
                )));
            }
        }
    }
    Ok(Instruction::Connect {
        authd_claims: if authd_claims.is_empty() {
            None
        } else {
            Some(authd_claims)
        },
        unauthd_claims: if unauthd_claims.is_empty() {
            None
        } else {
            Some(unauthd_claims)
        },
    })
}

// format is:
//   `tcp <src_actor_name>.<src_port> > <dst_actor_name>.<dst_port> <flags>`
//
// Where <flags> is in tcp-dump format, e.g.:
//    [] no flags (or flags is just not there)
//    [S] syn
//    [P] push
//    [R] reset
//    [F] fin
// Adding a '.' means ACK, so for example:
//    [S.] is syn-ack
//    [P.] is push-ack
//    [.] is ack without other flags
//
fn parse_tcp_expr(expr: String) -> Result<Instruction, ParseError> {
    let (source_expr, dest_expr, flags_part) = parse_tcp_udp_preamble(expr, "tcp")?;

    // Parse flags
    let mut flag_byte = 0u8;

    if let Some(flags_str) = flags_part {
        let flags_str = flags_str.trim();
        if !flags_str.starts_with('[') || !flags_str.ends_with(']') {
            return Err(ParseError::InvalidFormat(
                "flags must be enclosed in []".to_string(),
            ));
        }
        let flags_inner = &flags_str[1..flags_str.len() - 1];
        for ch in flags_inner.chars() {
            match ch {
                'F' => flag_byte |= packet::tcp::FIN,
                'S' => flag_byte |= packet::tcp::SYN,
                'R' => flag_byte |= packet::tcp::RST,
                'P' => flag_byte |= packet::tcp::PSH,
                '.' => flag_byte |= packet::tcp::ACK,
                _ => {
                    return Err(ParseError::InvalidFormat(format!(
                        "unknown TCP flag '{}'",
                        ch
                    )));
                }
            }
        }
    }
    let flags = if flag_byte > 0 {
        Some(InstrExtra::TcpFlags(flag_byte))
    } else {
        None
    };

    Ok(Instruction::Eval {
        prot: ip_proto::TCP,
        source_expr,
        dest_expr,
        extra: flags,
    })
}

// format is:
//   `udp <src_actor_name>.<src_port> > <dst_actor_name>.<dst_port>`
//
fn parse_udp_expr(expr: String) -> Result<Instruction, ParseError> {
    let (source_expr, dest_expr, more) = parse_tcp_udp_preamble(expr, "udp")?;
    if more.is_some() {
        return Err(ParseError::InvalidFormat(
            "unexpected additional input for UDP expression".to_string(),
        ));
    }
    Ok(Instruction::Eval {
        prot: ip_proto::UDP,
        source_expr,
        dest_expr,
        extra: None,
    })
}

// format is:
//   `icmp <src_actor_name> > <dst_actor_name> <type_expr>`
//
//  where <type_expr> is:
//    - <type>          8-bit value (code is 0)
//    - <type>:<code>   both 8-bit decimal values
//    - 0x<typecode>    16 bit hex encoded value with type in high byte, code in low byte
//    - <type-name>     eg, "echo-request"
//
fn parse_icmp6_expr(expr: String) -> Result<Instruction, ParseError> {
    let (source_expr, dest_expr, more) = parse_ip_preamble(expr, "icmp6")?;
    if more.is_none() {
        return Err(ParseError::InvalidFormat(
            "type or type code is required for ICMP6".to_string(),
        ));
    }

    let type_expr = more.unwrap();
    let type_expr = type_expr.trim();
    if type_expr.is_empty() {
        return Err(ParseError::InvalidFormat(
            "type or type code is required for ICMP6".to_string(),
        ));
    }

    let icmp_type: u8;
    let icmp_code: u8;

    if let Some(colon_pos) = type_expr.find(':') {
        // Two numbers: type and code
        let type_str = type_expr[..colon_pos].trim();
        let code_str = type_expr[colon_pos + 1..].trim();
        if type_str.is_empty() || code_str.is_empty() {
            return Err(ParseError::InvalidFormat(
                "invalid type and code expression for ICMP6".to_string(),
            ));
        }
        icmp_type = type_str.parse().map_err(|_| {
            ParseError::InvalidFormat(format!("invalid ICMP6 type number '{}'", type_str))
        })?;
        icmp_code = code_str.parse().map_err(|_| {
            ParseError::InvalidFormat(format!("invalid ICMP6 code number '{}'", code_str))
        })?;
    } else if let Some(hex_encoded) = type_expr.strip_prefix("0x") {
        // Hex encoded typecode
        icmp_type = u8::from_str_radix(&hex_encoded[..2], 16).map_err(|_| {
            ParseError::InvalidFormat(format!("invalid ICMP6 type '{}'", type_expr))
        })?;
        icmp_code = u8::from_str_radix(&hex_encoded[2..], 16).map_err(|_| {
            ParseError::InvalidFormat(format!("invalid ICMP6 code '{}'", type_expr))
        })?;
    } else {
        // Try to parse as name
        icmp_type = match type_expr.to_lowercase().as_str() {
            "destination-unreachable" => 1,
            "packet-too-big" => 2,
            "time-exceeded" => 3,
            "parameter-problem" => 4,
            "echo-request" => 128,
            "echo-reply" => 129,
            "router-solicitation" => 133,
            "router-advertisement" => 134,
            "neighbor-solicitation" => 135,
            "neighbor-advertisement" => 136,
            "redirect-message" => 137,
            _ => {
                return Err(ParseError::InvalidFormat(format!(
                    "unknown ICMP6 type name '{}'",
                    type_expr
                )));
            }
        };
        icmp_code = 0;
    }

    Ok(Instruction::Eval {
        prot: ip_proto::IPV6_ICMP,
        source_expr,
        dest_expr,
        extra: Some(InstrExtra::IcmpTypeCode(icmp_type, icmp_code)),
    })
}

/// Parse the general form of IP preamble:
///  <src_actor> > <dst_actor> [more]
///
/// Returns: (source_actor, dest_actor, more?)
fn parse_ip_preamble(
    expr: String,
    ctx: &str,
) -> Result<(ActorExpr, ActorExpr, Option<String>), ParseError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(ParseError::InvalidFormat(format!("empty {ctx} expression")));
    }
    let mut parts = expr.split_whitespace();
    let src_part = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat(format!("missing source in {ctx} expression")))?;
    let arrow = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat(format!("missing '>' in {ctx} expression")))?;
    if arrow != ">" {
        return Err(ParseError::InvalidFormat(format!(
            "expected '>' in {ctx} expression"
        )));
    }
    let dst_part = parts.next().ok_or_else(|| {
        ParseError::InvalidFormat(format!("missing destination in {ctx} expression"))
    })?;

    let more = if let Some(more_part) = parts.next() {
        Some(more_part.trim().to_string())
    } else {
        None
    };

    // Parse source
    let (src_actor, src_port) = parse_actor_port(src_part)?;
    let source_expr = match src_port {
        Some(_port) => {
            return Err(ParseError::InvalidFormat(format!(
                "unexpected port in source actor for {ctx} expression"
            )));
        }
        None => ActorExpr::ActorName(src_actor),
    };
    // Parse destination
    let (dst_actor, dst_port) = parse_actor_port(dst_part)?;
    let dest_expr = match dst_port {
        Some(_port) => {
            return Err(ParseError::InvalidFormat(format!(
                "unexpected port in destination actor for {ctx} expression"
            )));
        }
        None => ActorExpr::ActorName(dst_actor),
    };
    Ok((source_expr, dest_expr, more))
}

/// Parse the general form of TCP/UDP preamble:
///  <src_actor>[.<src_port>] > <dst_actor>[.<dst_port>] [more]
///
/// Returns: (source_actor, dest_actor, more?)
fn parse_tcp_udp_preamble(
    expr: String,
    ctx: &str,
) -> Result<(ActorExpr, ActorExpr, Option<String>), ParseError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(ParseError::InvalidFormat(format!("empty {ctx} expression")));
    }
    let mut parts = expr.split_whitespace();
    let src_part = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat(format!("missing source in {ctx} expression")))?;
    let arrow = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat(format!("missing '>' in {ctx} expression")))?;
    if arrow != ">" {
        return Err(ParseError::InvalidFormat(format!(
            "expected '>' in {ctx} expression"
        )));
    }
    let dst_part = parts.next().ok_or_else(|| {
        ParseError::InvalidFormat(format!("missing destination in {ctx} expression"))
    })?;

    let more = if let Some(more_part) = parts.next() {
        Some(more_part.trim().to_string())
    } else {
        None
    };

    // Parse source
    let (src_actor, src_port) = parse_actor_port(src_part)?;
    let source_expr = match src_port {
        Some(port) => ActorExpr::ActorNameAndPort(src_actor, port),
        None => ActorExpr::ActorName(src_actor),
    };
    // Parse destination
    let (dst_actor, dst_port) = parse_actor_port(dst_part)?;
    let dest_expr = match dst_port {
        Some(port) => ActorExpr::ActorNameAndPort(dst_actor, port),
        None => ActorExpr::ActorName(dst_actor),
    };
    Ok((source_expr, dest_expr, more))
}

// Actor name is required, port is optional.
fn parse_actor_port(actor_and_maybe_port: &str) -> Result<(String, Option<u16>), ParseError> {
    let (actor, port) = if let Some(dot_pos) = actor_and_maybe_port.rfind('.') {
        let actor = actor_and_maybe_port[..dot_pos].trim().to_string();
        let port_str = actor_and_maybe_port[dot_pos + 1..].trim();
        if port_str.is_empty() {
            return Err(ParseError::InvalidFormat(
                "empty port in actor.port expression".to_string(),
            ));
        }
        let port: u16 = port_str.parse().map_err(|_| {
            ParseError::InvalidFormat(format!("invalid port number '{}'", port_str))
        })?;
        (actor, Some(port))
    } else {
        // Just actor
        (actor_and_maybe_port.trim().to_string(), None)
    };

    if actor.is_empty() {
        return Err(ParseError::InvalidFormat(
            "empty actor name in actor.port expression".to_string(),
        ));
    }
    Ok((actor, port))
}

/// A sort of cursor style parser.
struct Parsing {
    input: String,
    cpos: usize, // input[cpos] is next position to start parsing.
}

impl Parsing {
    fn new<S: Into<String>>(input_line: S) -> Self {
        Parsing {
            input: input_line.into(),
            cpos: 0,
        }
    }

    // True if no more input to parse.
    fn is_empty(&self) -> bool {
        self.cpos >= self.input.len()
    }

    fn pop_word(&mut self) -> Result<String, ParseError> {
        let word = self.read_to(' ', true)?;
        Ok(word)
    }

    fn pop_eol(&mut self) -> Result<String, ParseError> {
        if self.cpos >= self.input.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let word = String::from(self.input[self.cpos..].trim());
        self.cpos = self.input.len();
        Ok(word)
    }

    fn pop_path(&mut self) -> Result<PathBuf, ParseError> {
        let word = self.pop_word()?;
        Ok(PathBuf::from(word))
    }

    fn read_to(&mut self, delim: char, or_eol: bool) -> Result<String, ParseError> {
        if self.cpos >= self.input.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let rest = &self.input[self.cpos..];
        if let Some(pos) = rest.find(delim) {
            let word = &rest[..pos];
            self.cpos += pos + 1; // +1 to skip the delimiter
            Ok(word.to_string())
        } else if or_eol {
            // No delimiter found: return rest.
            let word = rest;
            self.cpos = self.input.len();
            Ok(word.to_string())
        } else {
            Err(ParseError::UnexpectedEof)
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_parses_load() {
        let ins = parse("load /path/to/policy.zpr").unwrap();
        match ins {
            Instruction::Load(path) => {
                assert_eq!(path.to_string_lossy(), "/path/to/policy.zpr");
            }
            _ => panic!("expected Load instruction"),
        }
    }

    #[test]
    fn test_parses_simple_set() {
        let ins = parse("set alice color:red").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "color");
                assert_eq!(value, "red");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    #[test]
    fn test_parses_simple_empty() {
        let ins = parse("set alice color:").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "color");
                assert_eq!(value, "");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    #[test]
    fn test_parses_simple_set_tag() {
        let ins = parse("set alice #user.red").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "user.zpr.tag.red");
                assert_eq!(value, "");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    // A tag must be domain qualified (`#user.red`), since the encoded key is
    // `<domain>.zpr.tag.<name>`; a bare `#red` has no domain and is rejected.
    #[test]
    fn test_set_tag_requires_domain() {
        assert!(parse("set alice #red").is_err());
    }

    #[test]
    fn test_parses_simple_set_multi() {
        let ins = parse("set alice colors:{red, blue}").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "colors");
                assert_eq!(value, "red, blue");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    // A connect claim must encode tags and multi-values the same way `set` does:
    // a tag is a valueless per-tag key, a `{a, b}` claim is two values.
    #[test]
    fn test_parses_connect_claims() {
        let ins = parse("connect --ac #user.red --uc colors:{red, blue} --ac color:green").unwrap();
        match ins {
            Instruction::Connect {
                authd_claims,
                unauthd_claims,
            } => {
                let ac = authd_claims.expect("expected authenticated claims");
                assert_eq!(ac[0].get_key(), "user.zpr.tag.red");
                assert!(ac[0].get_value().is_empty());
                assert_eq!(ac[1].get_key(), "color");
                assert_eq!(ac[1].get_value(), &["green"]);

                let uc = unauthd_claims.expect("expected unauthenticated claims");
                assert_eq!(uc[0].get_key(), "colors");
                assert_eq!(uc[0].get_value(), &["red", "blue"]);
            }
            _ => panic!("expected Connect instruction"),
        }
    }

    #[test]
    fn test_parse_tcp_expr() {
        let ins = parse("eval tcp alice.1234 > bob.80 [S.]").unwrap();
        match ins {
            Instruction::Eval {
                prot,
                source_expr,
                dest_expr,
                extra,
            } => {
                assert_eq!(prot, ip_proto::TCP);
                match source_expr {
                    ActorExpr::ActorNameAndPort(name, port) => {
                        assert_eq!(name, "alice");
                        assert_eq!(port, 1234);
                    }
                    _ => panic!("expected ActorNameAndPort for source"),
                }
                match dest_expr {
                    ActorExpr::ActorNameAndPort(name, port) => {
                        assert_eq!(name, "bob");
                        assert_eq!(port, 80);
                    }
                    _ => panic!("expected ActorNameAndPort for dest"),
                }
                match extra {
                    Some(InstrExtra::TcpFlags(flags)) => {
                        assert_eq!(flags, packet::tcp::SYN | packet::tcp::ACK);
                    }
                    _ => panic!("expected TcpFlags extra"),
                }
            }
            _ => panic!("expected Eval instruction"),
        }
    }

    #[test]
    fn test_parse_tcp_expr_no_flags() {
        for input_line in [
            "eval tcp alice.1234 > bob.80",
            "eval tcp alice.1234 > bob.80 []",
            "eval tcp alice.1234 > bob.80    ",
        ] {
            let ins = parse(input_line).unwrap();
            match ins {
                Instruction::Eval {
                    prot,
                    source_expr,
                    dest_expr,
                    extra,
                } => {
                    assert_eq!(prot, ip_proto::TCP);
                    match source_expr {
                        ActorExpr::ActorNameAndPort(name, port) => {
                            assert_eq!(name, "alice");
                            assert_eq!(port, 1234);
                        }
                        _ => panic!("expected ActorNameAndPort for source"),
                    }
                    match dest_expr {
                        ActorExpr::ActorNameAndPort(name, port) => {
                            assert_eq!(name, "bob");
                            assert_eq!(port, 80);
                        }
                        _ => panic!("expected ActorNameAndPort for dest"),
                    }
                    match extra {
                        None => {}
                        _ => panic!("expected no extra"),
                    }
                }
                _ => panic!("expected Eval instruction"),
            }
        }
    }

    #[test]
    fn test_parse_udp_expr() {
        let ins = parse("eval udp alice.1234 > bob.80").unwrap();
        match ins {
            Instruction::Eval {
                prot,
                source_expr,
                dest_expr,
                extra,
            } => {
                assert_eq!(prot, ip_proto::UDP);
                match source_expr {
                    ActorExpr::ActorNameAndPort(name, port) => {
                        assert_eq!(name, "alice");
                        assert_eq!(port, 1234);
                    }
                    _ => panic!("expected ActorNameAndPort for source"),
                }
                match dest_expr {
                    ActorExpr::ActorNameAndPort(name, port) => {
                        assert_eq!(name, "bob");
                        assert_eq!(port, 80);
                    }
                    _ => panic!("expected ActorNameAndPort for dest"),
                }
                match extra {
                    None => (),
                    _ => panic!("expected no extra"),
                }
            }
            _ => panic!("expected Eval instruction"),
        }
    }

    #[test]
    fn test_parse_icmp6_expr() {
        for input_line in &[
            "eval icmp6 alice > bob echo-request",
            "eval icmp6 alice > bob 0x8000",
            "eval icmp6 alice > bob 128:0",
        ] {
            let ins = parse(input_line).expect("failed to parse {input_line}");
            match ins {
                Instruction::Eval {
                    prot,
                    source_expr,
                    dest_expr,
                    extra,
                } => {
                    assert_eq!(prot, ip_proto::IPV6_ICMP);
                    match source_expr {
                        ActorExpr::ActorName(name) => {
                            assert_eq!(name, "alice", "failed to parse {input_line}");
                        }
                        _ => panic!("expected ActorName for source"),
                    }
                    match dest_expr {
                        ActorExpr::ActorName(name) => {
                            assert_eq!(name, "bob", "failed to parse {input_line}");
                        }
                        _ => panic!("expected ActorName for dest"),
                    }
                    match extra {
                        Some(InstrExtra::IcmpTypeCode(icmp_type, icmp_code)) => {
                            assert_eq!(icmp_type, 128, "failed to parse {input_line}");
                            assert_eq!(icmp_code, 0, "failed to parse {input_line}");
                        }
                        _ => panic!("expected icmp extra"),
                    }
                }
                _ => panic!("expected Eval instruction"),
            }
        }
    }
}
