use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::browse::RawRecord;

/// Severity of an anomaly: errors are clear RFC violations, warnings are
/// likely misconfigurations, informational notes are SHOULD-level deviations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// One RFC-referenced anomaly. All strings are owned so the analyzer stays
/// a pure snapshot function with no borrows into browser state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anomaly {
    /// Stable machine-readable identifier (`missing-addr`, `unicast-leak`, ...).
    pub kind: &'static str,
    pub severity: Severity,
    /// Owning service as `instance.service_type`, or `enumeration` for
    /// enumeration-row answers.
    pub service: String,
    pub record_name: Option<String>,
    pub rtype: Option<u16>,
    pub rtype_str: Option<String>,
    pub rdata: Option<String>,
    pub source: Option<String>,
    pub message: String,
    /// RFC reference, e.g. `RFC 6762 §10.2`.
    pub rfc: &'static str,
}

/// A service slice for analysis: borrows browser state, owns nothing.
pub struct ServiceView<'a> {
    pub instance: &'a str,
    pub service_type: &'a str,
    pub hostname: &'a str,
    pub answers: &'a [RawRecord],
}

/// Snapshot input for the analyzer. Built by the caller from live browser
/// state; the analyzer never touches query scheduling, ingest, or expiry.
pub struct Snapshot<'a> {
    pub services: Vec<ServiceView<'a>>,
    pub enum_answers: Vec<&'a RawRecord>,
    /// Lowercased hostnames with a queued address (suppresses
    /// `missing-addr` false positives while the address is in flight).
    pub pending_hosts: HashSet<String>,
}

/// TTLs below this are churn risks; above this are stale-cache risks.
/// The band between covers both observed bases (120s for SRV/A/AAAA and
/// 4500s for PTR/TXT/NS/SOA), so normal responders stay quiet.
const TTL_LOW: u32 = 10;
const TTL_HIGH: u32 = 7200;
/// TXT payloads above this risk fragmentation; wire bytes preferred.
const TXT_MAX: usize = 1300;

fn is_live(rec: &RawRecord, now: Instant) -> bool {
    rec.ttl > 0 && now.duration_since(rec.received_at).as_secs() as u32 <= rec.ttl
}

/// Analyze a snapshot, returning deduped anomalies sorted by severity then kind.
/// Dedup key is (kind, service, name, type, rdata): the same record seen from
/// several sources yields one anomaly, keeping the first source for context.
pub fn analyze(snap: &Snapshot) -> Vec<Anomaly> {
    let now = Instant::now();
    let mut out: Vec<Anomaly> = Vec::new();

    // Host -> has any live A/AAAA, across all services (one hostname backs
    // many services, so siblings share fate).
    let mut host_has_addr: HashMap<String, bool> = HashMap::new();
    for svc in &snap.services {
        for rec in svc.answers {
            if (rec.rtype == 1 || rec.rtype == 28) && is_live(rec, now) {
                host_has_addr.insert(rec.name.trim_end_matches('.').to_lowercase(), true);
            }
        }
    }

    for svc in &snap.services {
        let service_id = format!("{}.{}", svc.instance, svc.service_type);
        check_missing_addr(
            svc,
            &service_id,
            &host_has_addr,
            &snap.pending_hosts,
            &mut out,
        );
        check_type_format(svc, &service_id, &mut out);
        for rec in svc.answers {
            if !is_live(rec, now) {
                continue;
            }
            check_record(&service_id, rec, &mut out);
        }
        check_ttl_stable(svc, &service_id, now, &mut out);
    }

    for rec in &snap.enum_answers {
        if !is_live(rec, now) {
            continue;
        }
        check_record("enumeration", rec, &mut out);
    }

    out.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.kind.cmp(b.kind))
            .then_with(|| a.service.cmp(&b.service))
            .then_with(|| a.record_name.cmp(&b.record_name))
            .then_with(|| a.rdata.cmp(&b.rdata))
    });
    dedup(out)
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Error => 2,
        Severity::Warning => 1,
        Severity::Info => 0,
    }
}

fn dedup(mut items: Vec<Anomaly>) -> Vec<Anomaly> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for a in items.drain(..) {
        let key = (
            a.kind,
            a.service.clone(),
            a.record_name.clone().unwrap_or_default(),
            a.rtype.unwrap_or(0),
            a.rdata.clone().unwrap_or_default(),
        );
        if seen.insert(key) {
            out.push(a);
        }
    }
    out
}

fn check_missing_addr(
    svc: &ServiceView,
    service_id: &str,
    host_has_addr: &HashMap<String, bool>,
    pending_hosts: &HashSet<String>,
    out: &mut Vec<Anomaly>,
) {
    let host = svc.hostname.trim_end_matches('.');
    if host.is_empty() {
        return;
    }
    let key = host.to_lowercase();
    if host_has_addr.get(&key).copied().unwrap_or(false) {
        return;
    }
    if pending_hosts.contains(&key) {
        return;
    }
    // Only flag when the service actually has an SRV (a hostname with no
    // SRV yet is still resolving, not broken). Hostname alone is set from
    // SRV handling, so non-empty hostname implies SRV was seen.
    out.push(Anomaly {
        kind: "missing-addr",
        severity: Severity::Warning,
        service: service_id.to_string(),
        record_name: None,
        rtype: None,
        rtype_str: None,
        rdata: None,
        source: None,
        message: format!("hostname {host} has no live A/AAAA"),
        rfc: "RFC 6763 §12",
    });
}

fn check_type_format(svc: &ServiceView, service_id: &str, out: &mut Vec<Anomaly>) {
    let st = svc.service_type.trim_end_matches('.');
    if st.eq_ignore_ascii_case("_services._dns-sd._udp.local") {
        return;
    }
    if !is_valid_service_type(st) {
        out.push(Anomaly {
            kind: "type-format",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: None,
            rtype: None,
            rtype_str: None,
            rdata: None,
            source: None,
            message: format!("service type {st} is not _service._tcp.local or _service._udp.local"),
            rfc: "RFC 6763 §7",
        });
    }
}

fn is_valid_service_type(st: &str) -> bool {
    let parts: Vec<&str> = st.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let (svc, proto, local) = (parts[0], parts[1], parts[2]);
    if svc.len() < 2 || !svc.starts_with('_') {
        return false;
    }
    let label = &svc[1..];
    if label.len() > 15 || label.is_empty() {
        return false;
    }
    if !proto.eq_ignore_ascii_case("_tcp") && !proto.eq_ignore_ascii_case("_udp") {
        return false;
    }
    if !local.eq_ignore_ascii_case("local") {
        return false;
    }
    true
}

fn check_record(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let name = rec.name.clone();
    let rdata = rec.rdata.clone();
    let src = rec.source.to_string();

    // Unicast-only types leaking onto multicast.
    if matches!(rec.rtype, 2 | 6 | 15 | 255) {
        out.push(Anomaly {
            kind: "unicast-leak",
            severity: Severity::Error,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message: format!(
                "{} record leaked onto multicast (unicast-only type)",
                rec.rtype_str
            ),
            rfc: "RFC 6762 §3",
        });
    }

    // Cache-flush bit misuse: shared records must not set it.
    if rec.rtype == 12 && rec.flush_bit {
        out.push(Anomaly {
            kind: "shared-flush",
            severity: Severity::Error,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message: "shared PTR record has cache-flush bit set".to_string(),
            rfc: "RFC 6762 §10.2",
        });
    }
    // Unique records SHOULD set it; missing is only informational.
    if matches!(rec.rtype, 33 | 16 | 1 | 28) && !rec.flush_bit {
        out.push(Anomaly {
            kind: "unique-no-flush",
            severity: Severity::Info,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message: format!("unique {} record missing cache-flush bit", rec.rtype_str),
            rfc: "RFC 6762 §10.2",
        });
    }

    // TTL band.
    if rec.ttl < TTL_LOW {
        out.push(Anomaly {
            kind: "ttl-low",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message: format!("TTL {}s is far below the expected base", rec.ttl),
            rfc: "RFC 6762 §5.2",
        });
    } else if rec.ttl > TTL_HIGH {
        out.push(Anomaly {
            kind: "ttl-high",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(name),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata),
            source: Some(src),
            message: format!("TTL {}s is far above the expected base", rec.ttl),
            rfc: "RFC 6762 §5.2",
        });
    }

    // SRV target shape. Port is never checked: port 0 is valid.
    if rec.rtype == 33 {
        check_srv_target(service_id, rec, out);
    }

    // TXT size only. Valueless keys, keys without `=`, and empty payloads
    // are all valid and never flagged.
    if rec.rtype == 16 {
        let wire_len = if rec.wire.is_empty() {
            rec.rdata.len()
        } else {
            rec.wire.len()
        };
        if wire_len > TXT_MAX || rec.rdata.len() > TXT_MAX {
            out.push(Anomaly {
                kind: "txt-oversize",
                severity: Severity::Warning,
                service: service_id.to_string(),
                record_name: Some(rec.name.clone()),
                rtype: Some(rec.rtype),
                rtype_str: Some(rec.rtype_str.clone()),
                rdata: Some(rec.rdata.clone()),
                source: Some(rec.source.to_string()),
                message: format!("TXT payload ~{wire_len}B exceeds {TXT_MAX}B"),
                rfc: "RFC 6762 §17",
            });
        }
    }
}

fn check_srv_target(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let parts: Vec<&str> = rec.rdata.split_whitespace().collect();
    if parts.len() < 4 {
        out.push(Anomaly {
            kind: "srv-target",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(rec.name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rec.rdata.clone()),
            source: Some(rec.source.to_string()),
            message: "SRV rdata is malformed".to_string(),
            rfc: "RFC 6763 §12",
        });
        return;
    }
    let target = parts[3..].join(" ");
    let trimmed = target.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "." {
        out.push(Anomaly {
            kind: "srv-target",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(rec.name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rec.rdata.clone()),
            source: Some(rec.source.to_string()),
            message: "SRV target is empty".to_string(),
            rfc: "RFC 6763 §12",
        });
        return;
    }
    if !trimmed.to_ascii_lowercase().ends_with(".local") && !trimmed.eq_ignore_ascii_case("local") {
        out.push(Anomaly {
            kind: "srv-target",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(rec.name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rec.rdata.clone()),
            source: Some(rec.source.to_string()),
            message: format!("SRV target {target} is outside .local"),
            rfc: "RFC 6763 §12",
        });
    }
}

fn check_ttl_stable(svc: &ServiceView, service_id: &str, now: Instant, out: &mut Vec<Anomaly>) {
    let mut bases: HashMap<(String, u16), HashSet<u32>> = HashMap::new();
    for rec in svc.answers {
        if !is_live(rec, now) {
            continue;
        }
        // Only track types where a stable base matters.
        if !matches!(rec.rtype, 12 | 33 | 16 | 1 | 28) {
            continue;
        }
        bases
            .entry((rec.name.trim_end_matches('.').to_lowercase(), rec.rtype))
            .or_default()
            .insert(rec.ttl);
    }
    for ((name, rtype), ttls) in bases {
        if ttls.len() > 1 {
            let mut sorted: Vec<u32> = ttls.into_iter().collect();
            sorted.sort_unstable();
            out.push(Anomaly {
                kind: "ttl-unstable",
                severity: Severity::Warning,
                service: service_id.to_string(),
                record_name: Some(name),
                rtype: Some(rtype),
                rtype_str: None,
                rdata: None,
                source: None,
                message: format!("unstable TTL bases {sorted:?} for same name/type"),
                rfc: "RFC 6762 §5.2",
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn test_source() -> SocketAddr {
        "192.168.1.2:5353".parse().unwrap()
    }

    fn rec(
        name: &str,
        rtype: u16,
        rtype_str: &str,
        rdata: &str,
        ttl: u32,
        flush: bool,
    ) -> RawRecord {
        RawRecord {
            name: name.to_string(),
            rtype,
            rtype_str: rtype_str.to_string(),
            flush_bit: flush,
            qu: false,
            ttl,
            rdata: rdata.to_string(),
            wire: Vec::new(),
            source: test_source(),
            iface: String::new(),
            ifindex: 0,
            received_at: Instant::now(),
        }
    }

    fn aged(mut r: RawRecord, secs: u64) -> RawRecord {
        r.received_at = Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .unwrap_or_else(Instant::now);
        r
    }

    fn analyze_service(
        instance: &str,
        service_type: &str,
        hostname: &str,
        answers: &[RawRecord],
    ) -> Vec<Anomaly> {
        let services = vec![ServiceView {
            instance,
            service_type,
            hostname,
            answers,
        }];
        let snap = Snapshot {
            services,
            enum_answers: Vec::new(),
            pending_hosts: HashSet::new(),
        };
        analyze(&snap)
    }

    #[test]
    fn missing_addr_flags_srv_without_a_or_aaaa() {
        let answers = vec![
            rec(
                "My._http._tcp.local.",
                12,
                "PTR",
                "My._http._tcp.local.",
                120,
                false,
            ),
            rec(
                "My._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 myhost.local.",
                120,
                true,
            ),
        ];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        assert!(found.iter().any(|a| a.kind == "missing-addr"));
    }

    #[test]
    fn missing_addr_quiet_when_addr_present() {
        let answers = vec![
            rec(
                "My._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 myhost.local.",
                120,
                true,
            ),
            rec("myhost.local.", 1, "A", "192.168.1.10", 120, true),
        ];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        assert!(!found.iter().any(|a| a.kind == "missing-addr"));
    }

    #[test]
    fn missing_addr_suppressed_by_pending() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            120,
            true,
        )];
        let services = vec![ServiceView {
            instance: "My",
            service_type: "_http._tcp.local",
            hostname: "myhost.local.",
            answers: &answers,
        }];
        let snap = Snapshot {
            services,
            enum_answers: Vec::new(),
            pending_hosts: HashSet::from(["myhost.local".to_string()]),
        };
        assert!(!analyze(&snap).iter().any(|a| a.kind == "missing-addr"));
    }

    #[test]
    fn unicast_leak_flags_soa_and_ns() {
        let answers = vec![
            rec(
                "host.local.",
                6,
                "SOA",
                "host.local. admin 1 2 3 4 5",
                120,
                false,
            ),
            rec("host.local.", 2, "NS", "host.local.", 120, false),
        ];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        assert_eq!(found.iter().filter(|a| a.kind == "unicast-leak").count(), 2);
        assert!(found
            .iter()
            .filter(|a| a.kind == "unicast-leak")
            .all(|a| a.severity == Severity::Error));
    }

    #[test]
    fn shared_ptr_flush_is_error() {
        let answers = vec![rec(
            "_http._tcp.local.",
            12,
            "PTR",
            "My._http._tcp.local.",
            120,
            true,
        )];
        let found = analyze_service("My", "_http._tcp.local", "", &answers);
        assert!(found
            .iter()
            .any(|a| a.kind == "shared-flush" && a.severity == Severity::Error));
    }

    #[test]
    fn unique_missing_flush_is_info_only() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            120,
            false,
        )];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == "unique-no-flush")
            .expect("expected info");
        assert_eq!(item.severity, Severity::Info);
    }

    #[test]
    fn ttl_band_keeps_120_and_4500_quiet() {
        let answers = vec![
            rec("a.local.", 1, "A", "192.168.1.1", 120, true),
            rec(
                "_http._tcp.local.",
                12,
                "PTR",
                "X._http._tcp.local.",
                4500,
                false,
            ),
            rec("X._http._tcp.local.", 16, "TXT", "k=v", 4500, true),
        ];
        let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
        assert!(!found
            .iter()
            .any(|a| a.kind == "ttl-low" || a.kind == "ttl-high"));
    }

    #[test]
    fn ttl_extremes_flagged() {
        let answers = vec![
            rec("a.local.", 1, "A", "192.168.1.1", 5, true),
            rec("b.local.", 28, "AAAA", "fe80::1", 20000, true),
        ];
        let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
        assert!(found.iter().any(|a| a.kind == "ttl-low"));
        assert!(found.iter().any(|a| a.kind == "ttl-high"));
    }

    #[test]
    fn ttl_unstable_flags_mixed_bases() {
        let mut r1 = rec("a.local.", 1, "A", "192.168.1.1", 120, true);
        let mut r2 = rec("a.local.", 1, "A", "192.168.1.2", 4500, true);
        // Distinct rdata keeps both live; distinct TTL bases are the signal.
        let _ = (&mut r1, &mut r2);
        let answers = vec![r1, r2];
        let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
        assert!(found.iter().any(|a| a.kind == "ttl-unstable"));
    }

    #[test]
    fn port_zero_never_flagged() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 0 myhost.local.",
            120,
            true,
        )];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        assert!(!found.iter().any(|a| a.kind == "srv-target"));
    }

    #[test]
    fn srv_target_outside_local_flagged() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 example.com.",
            120,
            true,
        )];
        let found = analyze_service("My", "_http._tcp.local", "example.com.", &answers);
        assert!(found.iter().any(|a| a.kind == "srv-target"));
    }

    #[test]
    fn txt_valueless_empty_and_missing_equals_quiet() {
        let answers = vec![
            rec("X._http._tcp.local.", 16, "TXT", "flag-only", 120, true),
            rec("X._http._tcp.local.", 16, "TXT", "", 120, true),
            rec("X._http._tcp.local.", 16, "TXT", "k=v; bare", 120, true),
        ];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        assert!(!found.iter().any(|a| a.kind == "txt-oversize"));
    }

    #[test]
    fn txt_oversize_flagged() {
        let big = "k=".to_string() + &"x".repeat(1400);
        let answers = vec![rec("X._http._tcp.local.", 16, "TXT", &big, 120, true)];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        assert!(found.iter().any(|a| a.kind == "txt-oversize"));
    }

    #[test]
    fn type_format_flags_bad_shape() {
        let answers = vec![];
        let found = analyze_service("X", "http.tcp.local", "", &answers);
        assert!(found.iter().any(|a| a.kind == "type-format"));
    }

    #[test]
    fn type_format_accepts_tcp_udp_and_enum() {
        for t in [
            "_http._tcp.local",
            "_printer._udp.local",
            "_services._dns-sd._udp.local",
        ] {
            let found = analyze_service("X", t, "", &[]);
            assert!(
                !found.iter().any(|a| a.kind == "type-format"),
                "type {t} should be quiet"
            );
        }
    }

    #[test]
    fn goodbye_and_expired_never_flagged() {
        let mut gone = rec("a.local.", 1, "A", "192.168.1.1", 0, false);
        let _ = &mut gone;
        let old = aged(rec("b.local.", 28, "AAAA", "fe80::1", 120, true), 500);
        let answers = vec![gone, old];
        let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
        assert!(
            found.is_empty()
                || !found
                    .iter()
                    .any(|a| a.kind == "unicast-leak" || a.kind == "ttl-low")
        );
        // Expired AAAA must not trigger missing-addr either via itself; the
        // hostname here has no SRV target overlap, and goodbye is excluded.
        assert!(!found.iter().any(|a| a.kind == "ttl-high"));
    }
}
