//! Detail-pane `Text` builders for actors, services, and visas.

use admin_api_types::{ActorDescriptor, NodeRecordBrief, ServiceDescriptor, VisaDescriptor};
use chrono::{DateTime, SecondsFormat, Utc};
use ratatui::text::{Line, Span, Text};
use std::time::SystemTime;
use thousands::Separable;

use super::format::{
    ago_suffix, auth_hdr, dir_str, flow_str, hm, remaining_str, session_key_summary, ts_or,
};
use super::text::{ATTR_KEY_STYLE, ATTR_VAL_STYLE, HEADING_STYLE, LABEL_W, labeled};

/// Build the full multi-line visa detail view for the Details pane.
/// Pure: no `self`, no frame — `width` is the inner (border-excluded) width.
pub(super) fn visa_detail_text(
    v: &VisaDescriptor,
    cn: Option<&str>,
    now: SystemTime,
    width: u16,
) -> Text<'static> {
    let w = width as usize;
    let mut lines: Vec<Line> = Vec::new();

    // Header: "visa <id>" left, remaining right-aligned, padded to width.
    let left = format!("visa {}", v.id);
    let right = remaining_str(v.expires, now);
    let pad = w.saturating_sub(left.len() + right.len());
    lines.push(Line::from(vec![
        Span::from("visa ").style(HEADING_STYLE),
        Span::from(v.id.to_string()),
        Span::from(" ".repeat(pad)),
        Span::from(right).style(HEADING_STYLE),
    ]));
    lines.push(Line::from(""));

    lines.extend(labeled("policy", &v.policy_id, width));
    lines.extend(labeled(
        "zpl",
        &format!("[{}] {}", dir_str(&v.direction), v.zpl),
        width,
    ));
    let requesting = match cn {
        Some(cn) => format!("{} ({cn})", v.requesting_node),
        None => v.requesting_node.clone(),
    };
    lines.extend(labeled("requesting", &requesting, width));
    lines.extend(labeled("flow", &flow_str(v), width));

    let created: DateTime<Utc> = v.created.into();
    let expires: DateTime<Utc> = v.expires.into();
    lines.extend(labeled(
        "created",
        &created.to_rfc3339_opts(SecondsFormat::Secs, true),
        width,
    ));
    let dur = v
        .expires
        .duration_since(v.created)
        .map(|d| hm(d.as_secs() / 60))
        .unwrap_or_else(|_| "0h 00m".to_string());
    lines.extend(labeled(
        "expires",
        &format!(
            "{}  (duration {dur})",
            expires.to_rfc3339_opts(SecondsFormat::Secs, true)
        ),
        width,
    ));

    // Signals: first on the label line, the rest indented under it.
    if v.signals.is_empty() {
        lines.extend(labeled("signals", "(none)", width));
    } else {
        for (i, sig) in v.signals.iter().enumerate() {
            let label = if i == 0 { "signals" } else { "" };
            lines.extend(labeled(label, sig, width));
        }
    }

    lines.extend(labeled(
        "session key",
        &session_key_summary(&v.session_key),
        width,
    ));

    Text::from(lines)
}

/// The `-- node --` block for a node actor's `NodeRecordBrief`.
/// `width` is the inner (border-excluded) pane width.
fn node_detail_lines(nd: &NodeRecordBrief, now: SystemTime, width: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();

    // Full-width "-- node ----" divider.
    let mut divider = String::from("-- node ");
    let pad = (width as usize).saturating_sub(divider.len());
    divider.push_str(&"-".repeat(pad));
    lines.push(Line::from(Span::from(divider).style(HEADING_STYLE)));

    lines.extend(labeled(
        "sync",
        if nd.in_sync { "YES" } else { "NO" },
        width,
    ));
    let last_contact = format!(
        "{}{}",
        ts_or(nd.last_contact, "never"),
        nd.last_contact
            .map(|t| ago_suffix(t, now))
            .unwrap_or_default(),
    );
    lines.extend(labeled("last contact", &last_contact, width));
    lines.extend(labeled(
        "vss port",
        &nd.vss_port.map(|p| p.to_string()).unwrap_or("-".into()),
        width,
    ));
    lines.extend(labeled(
        "visa reqs",
        &format!(
            "{}  (approved {}, denied {})",
            nd.visa_requests.separate_with_commas(),
            nd.approved_vreqs.separate_with_commas(),
            nd.denied_vreqs.separate_with_commas(),
        ),
        width,
    ));
    let last_vreq = format!(
        "{}{}",
        ts_or(nd.last_vreq, "never"),
        nd.last_vreq.map(|t| ago_suffix(t, now)).unwrap_or_default(),
    );
    lines.extend(labeled("last vreq", &last_vreq, width));
    lines.extend(labeled(
        "connect reqs",
        &nd.connect_requests.separate_with_commas(),
        width,
    ));
    // installed = live visas, pending = awaiting install, revoking = pending
    // revocation. `visas_enqueued` (queued IDs) is not surfaced here.
    lines.extend(labeled(
        "installs",
        &format!(
            "{} installed, {} pending, {} revoking",
            nd.visas.len().separate_with_commas(),
            nd.pending_install.separate_with_commas(),
            nd.pending_revocation.separate_with_commas(),
        ),
        width,
    ));
    let adapters = if nd.adapters.is_empty() {
        "(none)".to_string()
    } else {
        nd.adapters.join(", ")
    };
    lines.extend(labeled("adapters", &adapters, width));
    let links = if nd.links.is_empty() {
        "(none)".to_string()
    } else {
        nd.links.join(", ")
    };
    lines.extend(labeled("links", &links, width));

    lines
}

/// Build the full multi-line actor detail view for the Details pane.
/// `services` is the CNs' bound service names (already filtered by caller).
/// Pure: no `self`, no frame — `width` is the inner (border-excluded) width.
pub(super) fn actor_detail_text(
    a: &ActorDescriptor,
    services: &[&str],
    now: SystemTime,
    width: u16,
) -> Text<'static> {
    let w = width as usize;
    let mut lines: Vec<Line> = Vec::new();

    // Header: "actor <cn>" left; "[node]/[adapter]   <auth>" right, padded.
    let badge = if a.node { "[node]" } else { "[adapter]" };
    let right = format!("{badge}   {}", auth_hdr(a.auth_exp, now));
    let left = format!("actor {}", a.cn);
    let pad = w.saturating_sub(left.len() + right.len());
    lines.push(Line::from(vec![
        Span::from("actor ").style(HEADING_STYLE),
        Span::from(a.cn.clone()),
        Span::from(" ".repeat(pad)),
        Span::from(right).style(HEADING_STYLE),
    ]));
    lines.push(Line::from(""));

    lines.extend(labeled("identity", &a.ident, width));
    lines.extend(labeled("zpr addr", &a.zpr_addr, width));
    let created: DateTime<Utc> = a.ctime.into();
    lines.extend(labeled(
        "created",
        &created.to_rfc3339_opts(SecondsFormat::Secs, true),
        width,
    ));
    // auth exp: timestamp plus a relative "(in Xh Ym)"/"(EXPIRED)" suffix.
    let auth_suffix = match a.auth_exp {
        Some(e) => match e.duration_since(now) {
            Err(_) => "  (EXPIRED)".to_string(),
            Ok(d) => format!("  (in {})", hm(d.as_secs() / 60)),
        },
        None => String::new(),
    };
    lines.extend(labeled(
        "auth exp",
        &format!("{}{auth_suffix}", ts_or(a.auth_exp, "no auth")),
        width,
    ));

    // attributes: first "key=values" on the label line, rest indented.
    // Sort by key so the order is stable across refreshes (attrs arrive unordered).
    if a.attrs.is_empty() {
        lines.extend(labeled("attributes", "(none)", width));
    } else {
        let mut attrs: Vec<&_> = a.attrs.iter().collect();
        attrs.sort_by(|x, y| x.key.cmp(&y.key));
        let lw = LABEL_W as usize;
        for (i, attr) in attrs.iter().enumerate() {
            let label = if i == 0 { "attributes" } else { "" };
            // Colored key = value; one line per attribute.
            // ponytail: no wrap — attr values are short; long ones clip at the
            // right edge (vertical scroll won't help). Widen if that bites.
            lines.push(Line::from(vec![
                Span::from(format!("{label:<lw$}")).style(HEADING_STYLE),
                Span::from(attr.key.clone()).style(ATTR_KEY_STYLE),
                Span::from(" = "),
                Span::from(attr.value.join(", ")).style(ATTR_VAL_STYLE),
            ]));
        }
    }

    // services: one bound service name per line, or (none).
    if services.is_empty() {
        lines.extend(labeled("services", "(none)", width));
    } else {
        for (i, s) in services.iter().enumerate() {
            let label = if i == 0 { "services" } else { "" };
            lines.extend(labeled(label, s, width));
        }
    }

    // node block only for node actors.
    if let Some(nd) = &a.node_details {
        lines.extend(node_detail_lines(nd, now, width));
    }

    Text::from(lines)
}

/// Full multi-line detail view for a selected service. Header is the service
/// name; body is one labeled row per field. All fields are plain strings.
pub(super) fn service_detail_text(s: &ServiceDescriptor, width: u16) -> Text<'static> {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::from("service ").style(HEADING_STYLE),
        Span::from(s.service_name.clone()),
    ]));
    lines.push(Line::from(""));
    lines.extend(labeled("cn", &s.actor_cn, width));
    lines.extend(labeled("zpr addr", &s.zpr_addr, width));
    lines.extend(labeled("dock addr", &s.dock_zpr_addr, width));
    lines.extend(labeled("kind", &s.service_kind, width));
    lines.extend(labeled("endpoints", &s.service_endpoints, width));
    Text::from(lines)
}

#[cfg(test)]
mod tests {
    use super::{actor_detail_text, service_detail_text};
    use admin_api_types::{ActorDescriptor, ApiAttribute, NodeRecordBrief, ServiceDescriptor};
    use ratatui::text::Text;
    use std::time::{Duration, UNIX_EPOCH};

    /// A minimal ActorDescriptor; `node_details`/`attrs` set per-test.
    fn sample_actor() -> ActorDescriptor {
        ActorDescriptor {
            cn: "web-server-01".into(),
            ctime: UNIX_EPOCH,
            ident: "CN=web-server-01,O=ZPR".into(),
            node: false,
            zpr_addr: "fd5a:5052::b2".into(),
            attrs: vec![],
            auth_exp: None,
            node_details: None,
        }
    }

    /// A NodeRecordBrief fixture for the "-- node --" block.
    fn sample_node() -> NodeRecordBrief {
        NodeRecordBrief {
            pending_install: 3,
            last_contact: Some(UNIX_EPOCH + Duration::from_secs(600)),
            visa_requests: 1204,
            connect_requests: 5309,
            in_sync: true,
            approved_vreqs: 1180,
            denied_vreqs: 24,
            last_vreq: Some(UNIX_EPOCH + Duration::from_secs(500)),
            adapters: vec!["adapter-a".into(), "adapter-b".into()],
            links: vec!["node-2".into()],
            visas: vec![1, 2, 3],
            visas_enqueued: vec![4],
            pending_revocation: 0,
            vss_port: Some(8443),
        }
    }

    /// Join a Text's lines into one string for substring assertions.
    fn text_str(t: &Text<'static>) -> String {
        t.lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A node actor shows the badge, the node block, and its bound services.
    #[test]
    fn actor_detail_text_node() {
        let mut a = sample_actor();
        a.node = true;
        a.attrs = vec![ApiAttribute {
            key: "role".into(),
            value: vec!["node".into()],
            expires_at: UNIX_EPOCH,
        }];
        a.node_details = Some(sample_node());
        let s = text_str(&actor_detail_text(&a, &["https-web"], UNIX_EPOCH, 78));
        assert!(s.contains("[node]"));
        assert!(s.contains("-- node"));
        assert!(s.contains("sync"));
        assert!(s.contains("role = node"));
        assert!(s.contains("https-web"));
    }

    /// An adapter (no node_details) omits the node block; empty attrs/services
    /// render "(none)".
    #[test]
    fn actor_detail_text_adapter_empty() {
        let a = sample_actor(); // node=false, no details/attrs
        let s = text_str(&actor_detail_text(&a, &[], UNIX_EPOCH, 78));
        assert!(s.contains("[adapter]"));
        assert!(!s.contains("-- node"));
        assert!(s.contains("attributes   (none)"));
        assert!(s.contains("services     (none)"));
    }

    /// service_detail_text: header carries the service name and every field
    /// value shows up in the rendered lines.
    #[test]
    fn service_detail_text_fields() {
        let sd = ServiceDescriptor {
            service_name: "webproxy".into(),
            actor_cn: "actor-7".into(),
            zpr_addr: "fd5a:5052::1".into(),
            dock_zpr_addr: "fd5a:5052::2".into(),
            service_kind: "https".into(),
            service_endpoints: "https://host:443".into(),
        };
        let s = text_str(&service_detail_text(&sd, 78));
        assert!(s.contains("service webproxy"));
        assert!(s.contains("actor-7"));
        assert!(s.contains("fd5a:5052::1"));
        assert!(s.contains("fd5a:5052::2"));
        assert!(s.contains("https"));
        assert!(s.contains("https://host:443"));
    }
}
