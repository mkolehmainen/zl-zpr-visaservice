//! A bounded, in-memory record of recent visa denials.
//!
//! Denies are collapsed on a 5-tuple key so a chatty source does not flush the
//! window; a repeat bumps a count and moves the entry to the newest end.
//! Not persisted: the log starts empty on every VS restart.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::SystemTime;

use zpr::vsapi_types::{DenyCode, VsapiFiveTuple};

use crate::config::DENY_LOG_SIZE;

/// One collapsed deny, keyed by (source_addr, dest_addr, protocol, dest_port, deny_code).
#[derive(Clone)]
pub struct DenyEntry {
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub protocol: u8,   // raw IP proto number
    pub dest_port: u16, // ICMP code for ICMP, per VsapiFiveTuple
    pub count: u64,
    pub last_deny_ms: u64,
    pub deny_code: String, // stable API spelling produced by deny_code_name
}

/// Bounded request-recency-ordered window of denies. Oldest at the front.
#[derive(Default)]
pub struct DenyLog {
    entries: Mutex<VecDeque<DenyEntry>>,
}

/// The stable wire spelling for a deny code.
pub fn deny_code_name(code: &DenyCode) -> &'static str {
    match code {
        DenyCode::NoReason => "NoReason",
        DenyCode::NoMatch => "NoMatch",
        DenyCode::Denied => "Denied",
        DenyCode::SourceNotFound => "SourceNotFound",
        DenyCode::DestNotFound => "DestNotFound",
        DenyCode::SourceAuthError => "SourceAuthError",
        DenyCode::DestAuthError => "DestAuthError",
        DenyCode::QuotaExceeded => "QuotaExceeded",
        DenyCode::NoRoute => "NoRoute",
    }
}

/// Epoch milliseconds, clamped rather than panicking: a pre-epoch clock reads
/// as 0 and an absurdly future one saturates at `u64::MAX`.
fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl DenyLog {
    /// Record a deny at the current wall-clock time.
    pub fn record(&self, ft: &VsapiFiveTuple, code: &DenyCode) {
        self.record_at_ms(ft, code, epoch_ms_now());
    }

    /// Record a deny at an explicit epoch-millisecond time.
    ///
    // Note: O(N) scan under one mutex, N=500; add a HashMap key index if
    // the deny rate makes this hot.
    pub(crate) fn record_at_ms(&self, ft: &VsapiFiveTuple, code: &DenyCode, now_ms: u64) {
        let name = deny_code_name(code);
        let mut entries = self.entries.lock().expect("deny log mutex poisoned");

        let hit = entries.iter().position(|e| {
            e.source_addr == ft.source_addr
                && e.dest_addr == ft.dest_addr
                && e.protocol == ft.l4_protocol
                && e.dest_port == ft.dest_port
                && e.deny_code == name
        });

        match hit {
            Some(idx) => {
                let mut entry = entries
                    .remove(idx)
                    .expect("position() returned a valid index");
                entry.count += 1;
                entry.last_deny_ms = now_ms;
                entries.push_back(entry);
            }
            None => {
                entries.push_back(DenyEntry {
                    source_addr: ft.source_addr,
                    dest_addr: ft.dest_addr,
                    protocol: ft.l4_protocol,
                    dest_port: ft.dest_port,
                    count: 1,
                    last_deny_ms: now_ms,
                    deny_code: name.to_string(),
                });
                while entries.len() > DENY_LOG_SIZE {
                    entries.pop_front();
                }
            }
        }
    }

    /// Snapshot of the window, newest request first, optionally filtered to
    /// `last_deny_ms >= since` and truncated to `limit` entries.
    pub fn recent(&self, since: Option<u64>, limit: Option<usize>) -> Vec<DenyEntry> {
        let entries = self.entries.lock().expect("deny log mutex poisoned");
        entries
            .iter()
            .rev()
            .filter(|e| since.is_none_or(|s| e.last_deny_ms >= s))
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zpr::packet_info::L3Type;
    use zpr::vsapi_types::vsapi_ip_number as ip_proto;

    /// Builds a five-tuple for tests; source port is deliberately varied to
    /// prove it is not part of the collapsing key.
    fn ft(src: &str, dst: &str, proto: u8, dest_port: u16) -> VsapiFiveTuple {
        VsapiFiveTuple::new(
            L3Type::Ipv6,
            src.parse().unwrap(),
            dst.parse().unwrap(),
            proto,
            u16::from(proto) + dest_port, // arbitrary, ignored by the key
            dest_port,
        )
    }

    /// Renders the log as (source, deny code, count) triples, newest first.
    fn snapshot(log: &DenyLog) -> Vec<(String, String, u64)> {
        log.recent(None, None)
            .into_iter()
            .map(|e| (e.source_addr.to_string(), e.deny_code, e.count))
            .collect()
    }

    /// The worked example from the spec: a repeat of the middle entry moves it
    /// to the newest end and bumps its count, leaving the others in place.
    #[test]
    fn repeat_moves_entry_to_newest_and_increments_count() {
        let log = DenyLog::default();
        let a = ft("fd5a:5052:1000::1", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        let b = ft(
            "fd5a:5052:1000::8",
            "fd5a:5052:1000::10",
            ip_proto::TCP,
            443,
        );
        let c = ft(
            "fd5a:5052:1000::22",
            "fd5a:5052:1000::29",
            ip_proto::UDP,
            17,
        );
        log.record_at_ms(&a, &DenyCode::Denied, 1_000);
        log.record_at_ms(&b, &DenyCode::NoMatch, 2_000);
        log.record_at_ms(&c, &DenyCode::Denied, 3_000);

        log.record_at_ms(&b, &DenyCode::NoMatch, 4_000);

        assert_eq!(
            snapshot(&log),
            vec![
                ("fd5a:5052:1000::8".to_string(), "NoMatch".to_string(), 2),
                ("fd5a:5052:1000::22".to_string(), "Denied".to_string(), 1),
                ("fd5a:5052:1000::1".to_string(), "Denied".to_string(), 1),
            ]
        );
    }

    /// Overfilling the window evicts the oldest entry and caps the length.
    #[test]
    fn window_evicts_oldest_beyond_capacity() {
        let log = DenyLog::default();
        for i in 0..=DENY_LOG_SIZE {
            let t = ft(
                &format!("fd5a:5052:1000::{:x}", i + 1),
                "fd5a:5052:1000::ffff",
                ip_proto::TCP,
                80,
            );
            log.record_at_ms(&t, &DenyCode::Denied, 1_000 + i as u64);
        }

        let all = log.recent(None, None);
        assert_eq!(all.len(), DENY_LOG_SIZE);
        assert!(
            !all.iter()
                .any(|e| e.source_addr.to_string() == "fd5a:5052:1000::1"),
            "the first-recorded key should have been evicted"
        );
    }

    /// A repeat on the oldest entry rescues it from eviction, which proves the
    /// hit path moves the entry rather than only bumping its count.
    #[test]
    fn repeat_rescues_oldest_entry_from_eviction() {
        let log = DenyLog::default();
        let oldest = ft(
            "fd5a:5052:1000::1",
            "fd5a:5052:1000::ffff",
            ip_proto::TCP,
            80,
        );
        log.record_at_ms(&oldest, &DenyCode::Denied, 1_000);
        for i in 1..DENY_LOG_SIZE {
            let t = ft(
                &format!("fd5a:5052:1000::{:x}", i + 1),
                "fd5a:5052:1000::ffff",
                ip_proto::TCP,
                80,
            );
            log.record_at_ms(&t, &DenyCode::Denied, 1_000 + i as u64);
        }

        // Refresh the oldest, then push one more distinct key to force an eviction.
        log.record_at_ms(&oldest, &DenyCode::Denied, 9_000);
        let extra = ft(
            "fd5a:5052:2000::1",
            "fd5a:5052:1000::ffff",
            ip_proto::TCP,
            80,
        );
        log.record_at_ms(&extra, &DenyCode::Denied, 9_001);

        let all = log.recent(None, None);
        assert_eq!(all.len(), DENY_LOG_SIZE);
        let rescued = all
            .iter()
            .find(|e| e.source_addr.to_string() == "fd5a:5052:1000::1")
            .expect("refreshed entry should have survived eviction");
        assert_eq!(rescued.count, 2);
        assert!(
            !all.iter()
                .any(|e| e.source_addr.to_string() == "fd5a:5052:1000::2"),
            "the now-oldest key should have been evicted instead"
        );
    }

    /// The deny code is part of the key: the same traffic denied two ways gets
    /// two entries, and a repeat only increments its own.
    #[test]
    fn different_deny_codes_are_separate_entries() {
        let log = DenyLog::default();
        let t = ft("fd5a:5052:1000::1", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        log.record_at_ms(&t, &DenyCode::Denied, 1_000);
        log.record_at_ms(&t, &DenyCode::NoMatch, 2_000);
        log.record_at_ms(&t, &DenyCode::NoMatch, 3_000);

        let all = log.recent(None, None);
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].deny_code.as_str(), all[0].count), ("NoMatch", 2));
        assert_eq!((all[1].deny_code.as_str(), all[1].count), ("Denied", 1));
    }

    /// `since` is inclusive and `limit` truncates from the newest-request end.
    #[test]
    fn since_is_inclusive_and_limit_truncates_from_newest() {
        let log = DenyLog::default();
        for i in 0..4u64 {
            let t = ft(
                &format!("fd5a:5052:1000::{:x}", i + 1),
                "fd5a:5052:1000::9",
                ip_proto::TCP,
                80,
            );
            log.record_at_ms(&t, &DenyCode::Denied, 1_000 + i * 1_000);
        }

        let since = log.recent(Some(2_000), None);
        assert_eq!(
            since
                .iter()
                .map(|e| e.last_deny_ms)
                .collect::<Vec<_>>()
                .as_slice(),
            [4_000, 3_000, 2_000],
            "the entry exactly at `since` must be included"
        );

        let limited = log.recent(None, Some(2));
        assert_eq!(
            limited
                .iter()
                .map(|e| e.last_deny_ms)
                .collect::<Vec<_>>()
                .as_slice(),
            [4_000, 3_000]
        );
    }

    /// A wall-clock rollback leaves an old timestamp in the middle of the
    /// window; `recent` must scan past it rather than stopping there.
    #[test]
    fn recent_scans_past_out_of_order_timestamps() {
        let log = DenyLog::default();
        let newer = ft("fd5a:5052:1000::1", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        let rolled_back = ft("fd5a:5052:1000::2", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        let recovered = ft("fd5a:5052:1000::3", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        log.record_at_ms(&newer, &DenyCode::Denied, 5_000);
        log.record_at_ms(&rolled_back, &DenyCode::Denied, 1_000); // clock went backwards
        log.record_at_ms(&recovered, &DenyCode::Denied, 6_000);

        let found = log.recent(Some(5_000), None);
        assert_eq!(
            found
                .iter()
                .map(|e| e.last_deny_ms)
                .collect::<Vec<_>>()
                .as_slice(),
            [6_000, 5_000],
            "the 1_000 entry must not terminate the scan"
        );
    }
}
