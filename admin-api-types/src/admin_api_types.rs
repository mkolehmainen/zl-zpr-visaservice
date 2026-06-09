use chrono::{DateTime, SecondsFormat, Utc};
use colored::{Color, Colorize};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::{TimestampSeconds, serde_as};
use std::fmt;
use std::time::SystemTime;

/// List entry is a list with a numeric ID.
#[derive(Serialize, Deserialize)]
pub struct ListEntry {
    pub id: u64,
}

impl fmt::Display for ListEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{} {}", "id".dimmed(), self.id,)
    }
}

/// NamedListEntry is a list with a string ID.
#[derive(Serialize, Deserialize)]
pub struct NamedListEntry {
    pub id: String,
}

impl fmt::Display for NamedListEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{} {}", "id".dimmed(), self.id)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VisaMatchDirection {
    Forward,
    Reverse,
}

impl fmt::Display for VisaMatchDirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VisaMatchDirection::Forward => write!(f, "forward"),
            VisaMatchDirection::Reverse => write!(f, "reverse"),
        }
    }
}

#[serde_as]
#[derive(Serialize, Debug, Deserialize, Eq)]
pub struct VisaDescriptor {
    /// Policy reported version number
    pub id: u64,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub expires: SystemTime,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub created: SystemTime,
    pub policy_id: String,
    pub zpl: String,
    pub direction: VisaMatchDirection,
    pub requesting_node: String,     // ZPR address
    pub source_addr: Option<String>, // ZPR address
    pub dest_addr: Option<String>,   // ZPR address
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub proto: String,
    pub signals: Vec<String>,
    pub session_key: ApiKeySet,
}

impl PartialEq for VisaDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Ord for VisaDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for VisaDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for VisaDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let now = Utc::now();
        let dt_exp: DateTime<Utc> = self.expires.into();
        let dt_created: DateTime<Utc> = self.created.into();

        let remain = dt_exp.signed_duration_since(now);

        write!(f, "{} {}  ", "id:".dimmed(), self.id)?;
        write!(
            f,
            "{} {}  ",
            "requesting node:".dimmed(),
            self.requesting_node.yellow()
        )?;
        write!(f, "{} {}  ", "policy id:".dimmed(), self.policy_id)?;
        write!(
            f,
            "{} [{}] {}  ",
            "zpl:".dimmed(),
            self.direction,
            self.zpl.yellow()
        )?;
        write!(
            f,
            "{}:{} {} {}:{}  ",
            self.source_addr.as_ref().unwrap_or(&"-".into()).yellow(),
            self.source_port.unwrap_or(0),
            "->".bold().green(),
            self.dest_addr.as_ref().unwrap_or(&"-".into()).yellow(),
            self.dest_port.unwrap_or(0),
        )?;
        write!(f, "{} {}  ", "proto:".dimmed(), self.proto)?;
        write!(
            f,
            "{} {}  ",
            "created:".dimmed(),
            dt_created.to_rfc3339_opts(SecondsFormat::Secs, true).cyan()
        )?;
        write!(
            f,
            "{} {} ({}:{:02}:{:02} remain)  ",
            "exp:".dimmed(),
            dt_exp.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
            remain.num_hours(),
            remain.num_minutes() % 60,
            remain.num_seconds() % 60,
        )?;
        if !self.signals.is_empty() {
            write!(f, "{} [{}]  ", "signals:".dimmed(), self.signals.join(", "))?;
        }
        write!(f, "{} {}\n", "session_key:".dimmed(), self.session_key,)?;

        Ok(())
    }
}

/// Intentionally match the zpr::vsapi_types KeySet and KeyFormat, but
/// reproduced here to prevent coupling of the API types from the internal types
/// Note these keys are encrypted.
#[serde_as]
#[derive(Default, Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ApiKeySet {
    pub format: ApiKeyFormat,
    /// session key encrypted for ingress node to read
    #[serde_as(as = "Base64")]
    pub ingress_key: Vec<u8>,
    /// session key encrypted for egress node to read
    #[serde_as(as = "Base64")]
    pub egress_key: Vec<u8>,
}

// Due to encryption, didn't want to leak too much information in the display,
// so only have the length of the keys
impl fmt::Display for ApiKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}  ", "format:".dimmed(), self.format)?;
        write!(
            f,
            "{} {}B  ",
            "ingress_key:".dimmed(),
            self.ingress_key.len()
        )?;
        write!(f, "{} {}B\n", "egress_key:".dimmed(), self.egress_key.len())
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ApiKeyFormat {
    #[default]
    ZprKF01,
}

impl fmt::Display for ApiKeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiKeyFormat::ZprKF01 => write!(f, "ZprKF01"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Revokes {
    pub id: String,
    pub revoked: Vec<u64>,
}

impl fmt::Display for Revokes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}  ", "id:".dimmed(), self.id)?;
        write!(f, "{} {:?}\n", "revoked:".dimmed(), self.revoked)
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Eq)]
pub struct ActorDescriptor {
    pub cn: String,
    #[serde(rename = "created")]
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub ctime: SystemTime,
    pub ident: String,
    pub node: bool,
    pub zpr_addr: String,
    pub attrs: Vec<ApiAttribute>,
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub auth_exp: Option<SystemTime>,
    pub node_details: Option<NodeRecordBrief>,
}

impl PartialEq for ActorDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.cn == other.cn
    }
}

impl Ord for ActorDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cn.cmp(&other.cn)
    }
}

impl PartialOrd for ActorDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ActorDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ts: DateTime<Utc> = self.ctime.into();
        let auth_exp = match self.auth_exp {
            Some(ae) => Some(DateTime::<Utc>::from(ae)),
            None => None,
        };
        write!(
            f,
            "{} ({} {}) @ {}  ",
            self.cn,
            "created:".dimmed(),
            ts.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
            self.zpr_addr.yellow()
        )?;
        write!(f, "{} {}  ", "identity:".dimmed(), self.ident)?;

        write!(f, " {} {}  ", "is node:".dimmed(), self.node)?;
        write!(f, " {} {:?}  ", "attributes:".dimmed(), self.attrs)?;
        write!(
            f,
            "{} {}  ",
            "auth exp:".dimmed(),
            match auth_exp {
                Some(ae) => ae.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
                None => "No auth".to_string().red(),
            }
        )?;
        write!(
            f,
            "{}\n",
            match &self.node_details {
                Some(nd) => format!("[{} {}]", "node details:".green(), nd,),
                None => "".normal().to_string(),
            },
        )
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[allow(dead_code)]
pub struct ApiAttribute {
    pub key: String,
    pub value: Vec<String>,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub expires_at: SystemTime,
}

#[derive(Serialize, Deserialize, Debug, Eq)]
pub struct ServiceDescriptor {
    pub service_name: String,
    pub actor_cn: String,
    pub zpr_addr: String,
    pub dock_zpr_addr: String,
}

impl PartialEq for ServiceDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.service_name == other.service_name
    }
}

impl Ord for ServiceDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.service_name.cmp(&other.service_name)
    }
}

impl PartialOrd for ServiceDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ServiceDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}  ", "name:".dimmed(), self.service_name)?;
        write!(f, "{} {}  ", "cn:".dimmed(), self.actor_cn)?;
        write!(f, "{} {}  ", "zpr_addr:".dimmed(), self.zpr_addr)?;
        write!(f, "{} {}\n", "dock_zpr_addr:".dimmed(), self.dock_zpr_addr)
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Eq)]
#[allow(dead_code)]
pub struct HostRecordBrief {
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub ctime: SystemTime,
    pub cn: String,
    pub zpr_addr: String,
    pub ident: String,
    pub node: bool,
}

impl PartialEq for HostRecordBrief {
    fn eq(&self, other: &Self) -> bool {
        self.cn == other.cn
    }
}

impl Ord for HostRecordBrief {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cn.cmp(&other.cn)
    }
}

impl PartialOrd for HostRecordBrief {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for HostRecordBrief {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ts: DateTime<Utc> = self.ctime.into();
        writeln!(
            f,
            "{} ({} {}) @ {} {}",
            self.cn,
            "created:".dimmed(),
            ts.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
            self.zpr_addr.yellow(),
            if self.node {
                "[node]".green()
            } else {
                "".normal()
            },
        )
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecordBrief {
    // Number of visas pending install on the node
    pub pending_install: u32,
    // Last time node was contacted by the visa service, 0 if there was no contact
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub last_contact: Option<SystemTime>,
    // Number of visa requests on the node
    pub visa_requests: u64,
    // Number of calls to authorize_connect by the node
    pub connect_requests: u64,
    // If the node is connected to the vss
    pub in_sync: bool,
    // Approved visa requests
    pub approved_vreqs: u64,
    // Denied visa requests
    pub denied_vreqs: u64,
    // Time of last visa request, None if there was no request
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub last_vreq: Option<SystemTime>,
    // CNs of all adapters connected to the node
    pub adapters: Vec<String>,
    // CNs of all other nodes connected to the node
    pub links: Vec<String>,
    // IDs of all visas installed on the node
    pub visas: Vec<u64>,
    // IDs of all pending visas on the node
    pub visas_enqueued: Vec<u64>,
    // Number of visas pending revocation on the node
    pub pending_revocation: u32,
    // Port of the VSS the node is connected to
    pub vss_port: Option<u16>,
}

impl fmt::Display for NodeRecordBrief {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let last_contact = match self.last_contact {
            Some(lc) => Some(DateTime::<Utc>::from(lc)),
            None => None,
        };
        let last_vreq = match self.last_vreq {
            Some(lr) => Some(DateTime::<Utc>::from(lr)),
            None => None,
        };
        write!(
            f,
            "{} {}  ",
            "pending installs:".dimmed(),
            self.pending_install
        )?;
        write!(
            f,
            "{} {}  ",
            "SYNC:".dimmed(),
            if self.in_sync {
                "YES".green()
            } else {
                "NO".red()
            }
        )?;
        write!(
            f,
            "{} {}  ",
            "last_contact:".dimmed(),
            match last_contact {
                Some(lc) => lc.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
                None => "never".to_string().red(),
            }
        )?;
        // [vreqs: VAL (vreqs_appr: VAL | vreqs_den: VAL ) (vinstalled: [VAL, VAL, VAL] | venqueued: [VAL, VAL])]'
        write!(f, "[{} {} ", "vreqs:".dimmed(), self.visa_requests)?;
        write!(
            f,
            "({} {} | {} {}) ",
            "vreqs_appr:".dimmed(),
            self.approved_vreqs,
            "vreqs_den:".dimmed(),
            self.denied_vreqs
        )?;
        write!(
            f,
            "({}{:?} | {} {:?})]  ",
            "vinstalled:".dimmed(),
            self.visas,
            "venqueued:".dimmed(),
            self.visas_enqueued
        )?;

        write!(
            f,
            "{} {}  ",
            "last_request:".dimmed(),
            match last_vreq {
                Some(lr) => lr.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
                None => "never".to_string().red(),
            }
        )?;
        // [creqs: VAL (adapters: [VAL, VAL, VAL] | nodes: [VAL, VAL])]
        write!(f, "[{} {} ", "creqs:".dimmed(), self.connect_requests)?;
        write!(
            f,
            "({} {:?} | {} {:?})]  ",
            "adapters:".dimmed(),
            self.adapters,
            "nodes:".dimmed(),
            self.links
        )?;

        write!(
            f,
            "{} {}  ",
            "pending revocations:".dimmed(),
            self.pending_revocation
        )?;
        write!(
            f,
            "{} {}\n",
            "vss_port:".dimmed(),
            match self.vss_port {
                Some(port) => port.to_string(),
                None => "no vss".to_string(),
            }
        )
    }
}

#[serde_as]
#[derive(Debug, Deserialize, Eq)]
#[allow(dead_code)]
pub struct ServiceRecord {
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub ctime: SystemTime,
    pub cn: String,
    pub zpr_addr: String,
    pub ident: String,
    pub node: bool,
    pub services: Vec<String>,
}

impl fmt::Display for ServiceRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for svc in &self.services {
            writeln!(
                f,
                "{:<36}  {}  @ {} {}\n",
                svc,
                self.cn.cyan(),
                self.zpr_addr.yellow(),
                if self.node {
                    "[node]".green()
                } else {
                    "".normal()
                },
            )?;
        }
        Ok(())
    }
}

impl PartialEq for ServiceRecord {
    fn eq(&self, other: &Self) -> bool {
        self.cn == other.cn
    }
}

impl Ord for ServiceRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cn.cmp(&other.cn)
    }
}

impl PartialOrd for ServiceRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthRevokeDescriptor {
    pub ty: String,
    pub cn: String,
}

impl fmt::Display for AuthRevokeDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}  ", "type:".dimmed(), self.ty)?;
        write!(f, "{} {}\n", "cn:".dimmed(), self.cn)
    }
}

// Not exactly an api type, but the version generated by the compiler has some parts
// to it separated by colons.  This splits them up and makes it possible to pretty
// print.
#[allow(dead_code)]
pub struct PolicyVersion {
    parts: Vec<String>,
}

#[allow(dead_code)]
impl PolicyVersion {
    pub fn new(version: &str) -> Self {
        PolicyVersion {
            parts: version.split(':').map(|s| s.to_string()).collect(),
        }
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let colors = [Color::Cyan, Color::Green, Color::Blue, Color::BrightBlue];
        for (i, part) in self.parts.iter().enumerate() {
            if i > 0 {
                write!(f, "{}", ":".bold())?;
            }
            write!(f, "{}", part.color(colors[i % 4]))?;
        }
        writeln!(f, "")?;
        Ok(())
    }
}

#[allow(dead_code)]
pub fn reason_for(sc: StatusCode) -> String {
    match sc.canonical_reason() {
        Some(reason) => reason.to_string(),
        None => "unknown".to_string(),
    }
}

/// Simple struct with a "cn" field.
#[derive(Serialize, Deserialize, Debug)]
pub struct CnEntry {
    pub cn: String,
}

impl fmt::Display for CnEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{} {}", "cn".dimmed(), self.cn)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkDetails {
    pub network: Vec<NodeConnections>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeConnections {
    pub node: String,
    pub connections: Vec<String>,
}

impl fmt::Display for NetworkDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.network.is_empty() {
            writeln!(f, "No network")?;
        }
        for node in &self.network {
            writeln!(
                f,
                "{} {}  {} {:?}",
                "actor:".dimmed(),
                node.node.yellow(),
                "connected to:".dimmed(),
                node.connections
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn api_keyset_serializes_keys_as_base64() {
        let ks = ApiKeySet {
            format: ApiKeyFormat::ZprKF01,
            ingress_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            egress_key: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };

        let json = serde_json::to_string(&ks).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Confirm they're strings, not arrays
        assert!(v["ingress_key"].is_string());
        assert!(v["egress_key"].is_string());

        // Confirm the actual base64 values
        assert_eq!(v["ingress_key"].as_str().unwrap(), "3q2+7w==");
        assert_eq!(v["egress_key"].as_str().unwrap(), "yv66vg==");
    }

    #[test]
    fn api_keyset_roundtrips_through_json() {
        let original = ApiKeySet {
            format: ApiKeyFormat::ZprKF01,
            ingress_key: vec![0x01, 0x02, 0x03],
            egress_key: vec![0xFF, 0xFE, 0xFD],
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiKeySet = serde_json::from_str(&json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn api_attribute_serializes_expires_at_as_seconds() {
        let attr = ApiAttribute {
            key: "test_key".to_string(),
            value: vec!["val1".to_string()],
            expires_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12345),
        };

        let json = serde_json::to_string(&attr).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Should be a bare integer (seconds since epoch), not an object or string
        assert_eq!(v["expires_at"].as_i64().unwrap(), 12345);
    }

    #[test]
    fn api_attribute_deserializes_expires_at_from_seconds() {
        let json = r#"{"key":"k","value":["v"],"expires_at":123}"#;
        let attr: ApiAttribute = serde_json::from_str(json).unwrap();

        let expected = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(123);
        assert_eq!(attr.expires_at, expected);
    }

    #[test]
    fn api_attribute_roundtrips_through_json() {
        let original = ApiAttribute {
            key: "roundtrip".to_string(),
            value: vec!["a".to_string(), "b".to_string()],
            expires_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890),
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiAttribute = serde_json::from_str(&json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn visa_descriptor_serializes_timestamps_as_integer_seconds() {
        let vd = VisaDescriptor {
            id: 42,
            expires: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9000),
            created: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000),
            policy_id: "pol".to_string(),
            zpl: "zpl".to_string(),
            direction: VisaMatchDirection::Forward,
            requesting_node: "fd5a::1".to_string(),
            source_addr: Some("fd5a::2".to_string()),
            dest_addr: Some("fd5a::3".to_string()),
            source_port: Some(80),
            dest_port: Some(443),
            proto: "TCP".to_string(),
            signals: vec![],
            session_key: ApiKeySet::default(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&vd).unwrap()).unwrap();
        assert_eq!(v["expires"].as_i64().unwrap(), 9000);
        assert_eq!(v["created"].as_i64().unwrap(), 1000);
    }

    #[test]
    fn visa_descriptor_deserializes_timestamps_from_integer_seconds() {
        let json = r#"{
            "id": 1, "expires": 9000, "created": 1000,
            "policy_id": "p", "zpl": "z", "direction": "forward",
            "requesting_node": "fd5a::1", "source_addr": "fd5a::2", "dest_addr": "fd5a::3",
            "source_port": 80, "dest_port": 443, "proto": "TCP", "signals": [],
            "session_key": {"format": "ZprKF01", "ingress_key": "AAEC", "egress_key": "AAEC"}
        }"#;
        let vd: VisaDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(
            vd.expires,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9000)
        );
        assert_eq!(
            vd.created,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000)
        );
    }

    #[test]
    fn actor_descriptor_serializes_timestamps_as_integer_seconds() {
        let ad = ActorDescriptor {
            cn: "test.cn".to_string(),
            ctime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(5000),
            ident: "ident".to_string(),
            node: false,
            zpr_addr: "fd5a::1".to_string(),
            attrs: vec![],
            auth_exp: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(7000)),
            node_details: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ad).unwrap()).unwrap();
        assert_eq!(v["created"].as_i64().unwrap(), 5000);
        assert_eq!(v["auth_exp"].as_i64().unwrap(), 7000);
    }

    #[test]
    fn actor_descriptor_none_auth_exp_serializes_as_null() {
        let ad = ActorDescriptor {
            cn: "test.cn".to_string(),
            ctime: SystemTime::UNIX_EPOCH,
            ident: "ident".to_string(),
            node: false,
            zpr_addr: "fd5a::1".to_string(),
            attrs: vec![],
            auth_exp: None,
            node_details: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ad).unwrap()).unwrap();
        assert!(v["auth_exp"].is_null());
    }

    fn make_node_record_brief(
        last_contact: Option<SystemTime>,
        last_vreq: Option<SystemTime>,
    ) -> NodeRecordBrief {
        NodeRecordBrief {
            pending_install: 0,
            last_contact,
            visa_requests: 0,
            connect_requests: 0,
            in_sync: false,
            approved_vreqs: 0,
            denied_vreqs: 0,
            last_vreq,
            adapters: vec![],
            links: vec![],
            visas: vec![],
            visas_enqueued: vec![],
            pending_revocation: 0,
            vss_port: None,
        }
    }

    #[test]
    fn node_record_brief_serializes_timestamps_as_integer_seconds() {
        let nb = make_node_record_brief(
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2000)),
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3000)),
        );
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&nb).unwrap()).unwrap();
        assert_eq!(v["last_contact"].as_i64().unwrap(), 2000);
        assert_eq!(v["last_vreq"].as_i64().unwrap(), 3000);
    }

    #[test]
    fn node_record_brief_none_timestamps_serialize_as_null() {
        let nb = make_node_record_brief(None, None);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&nb).unwrap()).unwrap();
        assert!(v["last_contact"].is_null());
        assert!(v["last_vreq"].is_null());
    }

    #[test]
    fn node_record_brief_roundtrips_through_json() {
        let original = make_node_record_brief(
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890)),
            None,
        );
        let json = serde_json::to_string(&original).unwrap();
        let decoded: NodeRecordBrief = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
