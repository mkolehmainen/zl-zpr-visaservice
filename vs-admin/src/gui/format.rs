//! Pure time/string summary helpers for the Details views and header.

use admin_api_types::{ApiKeySet, VisaDescriptor};
use chrono::{DateTime, SecondsFormat, Utc};
use std::time::SystemTime;
use thousands::Separable;

/// Format seconds as "01d 04h 09m 22s", hours rolling into days.
pub(super) fn fmt_uptime(secs: u64) -> String {
    format!(
        "{:02}d {:02}h {:02}m {:02}s",
        secs / 86400,
        secs % 86400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    )
}

/// "Xh Ym" for a minute count, hours comma-separated (durations can be huge).
pub(super) fn hm(total_mins: u64) -> String {
    format!(
        "{}h {:02}m",
        (total_mins / 60).separate_with_commas(),
        total_mins % 60
    )
}

/// Human-readable time remaining until `expires`, relative to `now`.
/// "EXPIRED" once past; otherwise "expires in Xh Ym" (or "expires in Xm"
/// under an hour). Rounds down.
pub(super) fn remaining_str(expires: SystemTime, now: SystemTime) -> String {
    match expires.duration_since(now) {
        Err(_) => "EXPIRED".to_string(),
        Ok(d) => {
            let mins = d.as_secs() / 60;
            if mins >= 60 {
                format!("expires in {}", hm(mins))
            } else {
                format!("expires in {mins}m")
            }
        }
    }
}

/// The flow line: `[src]:sport  --PROTO-->  [dst]:dport`. Missing addr → `-`,
/// missing port → `0` (matches the visas list row convention).
pub(super) fn flow_str(v: &VisaDescriptor) -> String {
    let src = v.source_addr.as_deref().unwrap_or("-");
    let dst = v.dest_addr.as_deref().unwrap_or("-");
    let sport = v.source_port.unwrap_or(0);
    let dport = v.dest_port.unwrap_or(0);
    let proto = v.proto.to_uppercase();
    format!("[{src}]:{sport}  --{proto}-->  [{dst}]:{dport}")
}

/// One-line session-key summary — never prints key material, only the key
/// format and the encrypted byte lengths.
pub(super) fn session_key_summary(k: &ApiKeySet) -> String {
    format!(
        "fmt={:?} ingress={}B egress={}B",
        k.format,
        k.ingress_key.len(),
        k.egress_key.len()
    )
}

/// A `SystemTime` as RFC3339 (secs, UTC), or `fallback` when absent.
pub(super) fn ts_or(t: Option<SystemTime>, fallback: &str) -> String {
    match t {
        Some(t) => {
            let dt: DateTime<Utc> = t.into();
            dt.to_rfc3339_opts(SecondsFormat::Secs, true)
        }
        None => fallback.to_string(),
    }
}

/// Header's right-hand auth text: "no auth" (None), "auth EXPIRED" (past),
/// or "auth in Xh Ym".
pub(super) fn auth_hdr(auth_exp: Option<SystemTime>, now: SystemTime) -> String {
    match auth_exp {
        None => "no auth".to_string(),
        Some(e) => match e.duration_since(now) {
            Err(_) => "auth EXPIRED".to_string(),
            Ok(d) => format!("auth in {}", hm(d.as_secs() / 60)),
        },
    }
}

/// Relative " (Xm ago)" / " (Xh Ym ago)" suffix for a past time; empty if the
/// time is in the future or absent.
pub(super) fn ago_suffix(t: SystemTime, now: SystemTime) -> String {
    match now.duration_since(t) {
        Ok(d) => {
            let mins = d.as_secs() / 60;
            if mins >= 60 {
                format!(" ({} ago)", hm(mins))
            } else {
                format!(" ({mins}m ago)")
            }
        }
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{auth_hdr, flow_str, fmt_uptime, remaining_str, session_key_summary, ts_or};
    use admin_api_types::{ApiKeySet, VisaDescriptor, VisaMatchDirection};
    use std::time::{Duration, UNIX_EPOCH};

    /// A minimal VisaDescriptor for helper tests.
    fn sample_visa() -> VisaDescriptor {
        VisaDescriptor {
            id: 1001,
            expires: UNIX_EPOCH + Duration::from_secs(3600),
            created: UNIX_EPOCH,
            policy_id: "v7".into(),
            zpl: "allow tcp alice -> web:443".into(),
            direction: VisaMatchDirection::Forward,
            requesting_node: "fd5a:5052::a1".into(),
            source_addr: Some("fd5a:5052::a1".into()),
            dest_addr: Some("fd5a:5052::b2".into()),
            source_port: Some(52344),
            dest_port: Some(443),
            proto: "tcp".into(),
            signals: vec![],
            session_key: ApiKeySet {
                format: Default::default(),
                ingress_key: vec![0u8; 48],
                egress_key: vec![0u8; 48],
            },
        }
    }

    /// remaining_str shows EXPIRED past, and hh/mm vs minutes-only.
    #[test]
    fn remaining_str_formats_and_expires() {
        let base = UNIX_EPOCH;
        // 1h02m ahead.
        let exp = base + Duration::from_secs(3720);
        assert_eq!(remaining_str(exp, base), "expires in 1h 02m");
        // 45m ahead → minutes only.
        let exp = base + Duration::from_secs(45 * 60);
        assert_eq!(remaining_str(exp, base), "expires in 45m");
        // already past.
        assert_eq!(
            remaining_str(base, base + Duration::from_secs(1)),
            "EXPIRED"
        );
    }

    /// flow_str renders full flows and uses -/0 for missing addr/port.
    #[test]
    fn flow_str_full_and_missing() {
        let v = sample_visa();
        assert_eq!(
            flow_str(&v),
            "[fd5a:5052::a1]:52344  --TCP-->  [fd5a:5052::b2]:443"
        );
        let mut v = sample_visa();
        v.source_addr = None;
        v.dest_port = None;
        assert_eq!(flow_str(&v), "[-]:52344  --TCP-->  [fd5a:5052::b2]:0");
    }

    /// session_key_summary reports format and byte lengths, never key bytes.
    #[test]
    fn session_key_summary_no_material() {
        let s = session_key_summary(&sample_visa().session_key);
        assert!(s.contains("fmt="));
        assert!(s.contains("ingress=48B"));
        assert!(s.contains("egress=48B"));
    }

    /// auth_hdr covers None, expired, and future cases.
    #[test]
    fn auth_hdr_none_expired_future() {
        let base = UNIX_EPOCH;
        assert_eq!(auth_hdr(None, base), "no auth");
        // 1s in the past → EXPIRED.
        assert_eq!(
            auth_hdr(Some(base), base + Duration::from_secs(1)),
            "auth EXPIRED"
        );
        // 1h02m ahead.
        let exp = base + Duration::from_secs(3720);
        assert_eq!(auth_hdr(Some(exp), base), "auth in 1h 02m");
    }

    /// ts_or renders RFC3339 when set, else the fallback word.
    #[test]
    fn ts_or_timestamp_or_fallback() {
        assert!(ts_or(Some(UNIX_EPOCH), "never").contains("1970-01-01"));
        assert_eq!(ts_or(None, "never"), "never");
    }

    /// fmt_uptime rolls seconds into d/h/m/s with zero-padding.
    #[test]
    fn fmt_uptime_rolls_units() {
        assert_eq!(fmt_uptime(100162), "01d 03h 49m 22s");
        assert_eq!(fmt_uptime(0), "00d 00h 00m 00s");
    }
}
