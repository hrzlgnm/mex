use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
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
    pub subtypes: &'a [String],
}

/// Snapshot input for the analyzer. Built by the caller from live browser
/// state; the analyzer never touches query scheduling, ingest, or expiry.
pub struct Snapshot<'a> {
    pub services: Vec<ServiceView<'a>>,
    pub enum_answers: Vec<&'a RawRecord>,
    /// Lowercased hostnames with a queued address (suppresses
    /// `missing-addr` false positives while the address is in flight).
    pub pending_hosts: HashSet<String>,
    /// Observed questions flattened across services, pending instances,
    /// and enumeration rows. The owning service id rides along
    /// (`instance.service_type`, or `enumeration`).
    pub questions: Vec<QuestionView<'a>>,
}

/// One observed question for analysis: borrows the row, owns the small
/// service id string.
#[derive(Clone, Debug)]
pub struct QuestionView<'a> {
    pub service: String,
    pub name: &'a str,
    pub rtype: u16,
    pub rtype_str: &'a str,
    pub source: SocketAddr,
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
        // A retained hostname outlives its SRV (expiry, goodbye): only a
        // live SRV proves the service still claims the host.
        let has_live_srv = svc.answers.iter().any(|r| r.rtype == 33 && is_live(r, now));
        check_missing_addr(
            svc,
            &service_id,
            &host_has_addr,
            &snap.pending_hosts,
            has_live_srv,
            &mut out,
        );
        check_type_format(svc, &service_id, &mut out);
        check_subtypes(svc, &service_id, &mut out);
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
        // Enumeration PTR targets name service types (or subtypes): a
        // malformed target means the name itself violates DNS-SD naming,
        // so flag the PTR row itself (with full record identity, so the
        // Answers table marks it).
        if rec.rtype == 12 {
            let target = rec.rdata.trim_end_matches('.');
            if let Some(reason) = service_type_problem(target) {
                out.push(Anomaly {
                    kind: "type-format",
                    severity: Severity::Warning,
                    service: "enumeration".to_string(),
                    record_name: Some(rec.name.clone()),
                    rtype: Some(rec.rtype),
                    rtype_str: Some(rec.rtype_str.clone()),
                    rdata: Some(rec.rdata.clone()),
                    source: Some(rec.source.to_string()),
                    message: format!("enumerated type {target} invalid: {reason}"),
                    rfc: "RFC 6763 §7",
                });
            }
        }
    }

    // Observed questions for unicast-only types: a querier asking
    // multicast for what can only live in unicast is the same leak from
    // the demand side. Stored rows are already capped and refreshed on
    // re-ask, so every row on file is worth marking.
    for q in &snap.questions {
        check_question(q, &mut out);
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
        // Every finding with a known announcer names it, so overlay rows and
        // dump messages read identically whether the finding is service- or
        // enumeration-level. Findings without an announcer (missing-addr,
        // service-level type-format, ttl-unstable) are untouched.
        .into_iter()
        .map(|mut a| {
            if let Some(src) = a.source.clone() {
                a.message.push_str(&format!(" (from {src})"));
            }
            a
        })
        .collect()
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Error => 2,
        Severity::Warning => 1,
        Severity::Info => 0,
    }
}

/// Display/dedup key for rdata: SOA serials churn constantly (one bump
/// per announcement), so rows differing only in serial share one finding
/// and one marker. All other types pass through untouched.
pub(crate) fn anomaly_match_key(rtype: u16, rdata: &str) -> String {
    if rtype == 6 {
        normalize_soa_rdata(rdata.to_string())
    } else {
        rdata.to_string()
    }
}

fn dedup(mut items: Vec<Anomaly>) -> Vec<Anomaly> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for a in items.drain(..) {
        // SOA serials churn constantly (one bump per announcement), so two
        // leaks differing only in serial are the same finding. Normalize
        // the serial away for the dedup key; the stored rdata keeps it.
        let rdata_key = match (a.kind, a.rtype) {
            ("unicast-leak", Some(6)) => anomaly_match_key(6, &a.rdata.clone().unwrap_or_default()),
            _ => a.rdata.clone().unwrap_or_default(),
        };
        // Questions carry no rdata: tell queriers apart by source, so each
        // leaking querier keeps its own finding and every row can mark.
        // Answers keep the established behavior (one finding no matter how
        // many sources announce it).
        let source_key = match a.kind {
            "unicast-question" => a.source.clone().unwrap_or_default(),
            _ => String::new(),
        };
        let key = (
            a.kind,
            a.service.clone(),
            a.record_name.clone().unwrap_or_default(),
            a.rtype.unwrap_or(0),
            rdata_key,
            source_key,
        );
        if seen.insert(key) {
            out.push(a);
        }
    }
    out
}

/// Mask the serial (third field) of `mname rname serial refresh retry
/// expire minimum` so serial bumps don't multiply findings.
fn normalize_soa_rdata(rdata: String) -> String {
    let mut parts = rdata.split_whitespace();
    let (mname, rname) = (parts.next(), parts.next());
    match (mname, rname, parts.next()) {
        (Some(m), Some(r), Some(_)) => {
            let rest: Vec<&str> = parts.collect();
            let mut out = format!("{m} {r} *");
            for p in rest {
                out.push(' ');
                out.push_str(p);
            }
            out
        }
        _ => rdata,
    }
}

fn check_missing_addr(
    svc: &ServiceView,
    service_id: &str,
    host_has_addr: &HashMap<String, bool>,
    pending_hosts: &HashSet<String>,
    has_live_srv: bool,
    out: &mut Vec<Anomaly>,
) {
    if !has_live_srv {
        return;
    }
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
    // A retained hostname outlives its SRV (expiry, goodbye): the caller
    // passes whether a live SRV still claims the host, and only then is a
    // missing address meaningful.
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
    if let Some(reason) = service_type_problem(st) {
        out.push(Anomaly {
            kind: "type-format",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: None,
            rtype: None,
            rtype_str: None,
            rdata: None,
            source: None,
            message: format!("service type {st} invalid: {reason}"),
            rfc: "RFC 6763 §7",
        });
    }
}

/// Why a service type string is invalid, if it is. `None` means valid.
/// Split out so confirmed services and enumeration PTR targets share
/// one verdict and one message. Accepts the `_subtype._sub._service._tcp`
/// subtype form (RFC 6763 §7.1) as well as plain types.
fn service_type_problem(st: &str) -> Option<String> {
    let parts: Vec<&str> = st.split('.').collect();
    match parts.as_slice() {
        [svc, proto, local] => {
            if let Some(reason) = label_problem(svc) {
                return Some(reason);
            }
            if !proto.eq_ignore_ascii_case("_tcp") && !proto.eq_ignore_ascii_case("_udp") {
                return Some("protocol must be _tcp or _udp".to_string());
            }
            if !local.eq_ignore_ascii_case("local") {
                return Some("must end in .local".to_string());
            }
            None
        }
        [sub, sub_kw, svc, proto, local] => {
            if let Some(reason) = label_problem(sub) {
                return Some(format!("subtype {reason}"));
            }
            if !sub_kw.eq_ignore_ascii_case("_sub") {
                return Some(
                    "expected _service._tcp.local or _subtype._sub._service._tcp.local".to_string(),
                );
            }
            if let Some(reason) = label_problem(svc) {
                return Some(reason);
            }
            if !proto.eq_ignore_ascii_case("_tcp") && !proto.eq_ignore_ascii_case("_udp") {
                return Some("protocol must be _tcp or _udp".to_string());
            }
            if !local.eq_ignore_ascii_case("local") {
                return Some("must end in .local".to_string());
            }
            None
        }
        _ => Some("expected _service._tcp.local or _subtype._sub._service._tcp.local".to_string()),
    }
}

/// Why an underscore-led service/subtype label is invalid, if it is.
/// Structural only: leading underscore, non-empty, containing a letter,
/// not starting or ending with a hyphen. Charset and length are
/// deliberately loose: inner underscores and long labels ship in real
/// devices (e.g. NVIDIA) and pass avahi/Apple responders on .local, so
/// flagging them is noise, not signal.
fn label_problem(label: &str) -> Option<String> {
    if label.len() < 2 || !label.starts_with('_') {
        return Some("service label must start with '_'".to_string());
    }
    let body = &label[1..];
    if body.is_empty() {
        return Some("service label is empty".to_string());
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Some(format!(
            "service label '{body}' may only contain letters, digits, hyphens, and underscores"
        ));
    }
    if !body.bytes().any(|b| b.is_ascii_alphabetic()) {
        return Some(format!("service label '{body}' must contain a letter"));
    }
    if body.starts_with('-') || body.ends_with('-') {
        return Some(format!(
            "service label '{body}' must not start or end with '-'"
        ));
    }
    None
}

/// Subtype labels registered on a confirmed service share the service
/// naming rules; a malformed one is a service-level finding.
fn check_subtypes(svc: &ServiceView, service_id: &str, out: &mut Vec<Anomaly>) {
    for sub in svc.subtypes {
        if let Some(reason) = label_problem(sub.trim_end_matches('.')) {
            out.push(Anomaly {
                kind: "type-format",
                severity: Severity::Warning,
                service: service_id.to_string(),
                record_name: None,
                rtype: None,
                rtype_str: None,
                rdata: None,
                source: None,
                message: format!("subtype {sub} invalid: {reason}"),
                rfc: "RFC 6763 §7.1",
            });
        }
    }
}

/// Whether a PTR owner name is a reverse-mapping name. Those PTRs are
/// unique (one address, one owner), unlike service/enumeration PTRs.
fn is_reverse_ptr(name: &str) -> bool {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    lower.ends_with(".in-addr.arpa") || lower.ends_with(".ip6.arpa")
}

/// Shared verdict for unicast-only types observed on multicast: definite
/// violations (SOA/NS/ANY) are errors, the MX soft case is a warning, and
/// everything else is `None` (quiet). Used by answer checks.
pub(crate) fn unicast_severity(rtype: u16) -> Option<Severity> {
    match rtype {
        2 | 6 | 255 => Some(Severity::Error),
        15 => Some(Severity::Warning),
        _ => None,
    }
}

/// Verdict for observed *questions*. Same as answers, except QTYPE ANY
/// (255) is excluded: probes for unique ownership use QTYPE ANY
/// (RFC 6762 §8.1, §6.1), so ANY questions are routine demand, while ANY
/// *answers* are meaningless on the wire and stay flagged.
pub(crate) fn question_unicast_severity(rtype: u16) -> Option<Severity> {
    match rtype {
        2 | 6 => Some(Severity::Error),
        15 => Some(Severity::Warning),
        _ => None,
    }
}

/// Numeric type for a displayed `rtype_str` (`A` → 1, …, `TYPE47` → 47).
/// `None` means unrecognised: the row stays quiet rather than guessing.
pub(crate) fn rtype_from_str(s: &str) -> Option<u16> {
    match s {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "PTR" => Some(12),
        "NSEC" => Some(47),
        "ANY" => Some(255),
        _ => s.strip_prefix("TYPE").and_then(|n| n.parse().ok()),
    }
}

/// One observed question asking multicast for a unicast-only type: the
/// demand-side twin of `unicast-leak`. Port 0 can never be a real querier,
/// so our own inferred sends stay quiet here, not just in the UI.
fn check_question(q: &QuestionView, out: &mut Vec<Anomaly>) {
    if q.source.port() == 0 {
        return;
    }
    let Some(severity) = question_unicast_severity(q.rtype) else {
        return;
    };
    let name = q.name.to_string();
    out.push(Anomaly {
        kind: "unicast-question",
        severity,
        service: q.service.clone(),
        record_name: Some(name.clone()),
        rtype: Some(q.rtype),
        rtype_str: Some(q.rtype_str.to_string()),
        rdata: None,
        source: Some(q.source.to_string()),
        message: format!(
            "{} question for {name} on multicast (unicast-only type)",
            q.rtype_str,
        ),
        rfc: "RFC 6762 §3",
    });
}

fn check_record(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let name = rec.name.clone();
    let rdata = rec.rdata.clone();
    let src = rec.source.to_string();

    // Unicast-only types leaking onto multicast. MX is the soft case:
    // nothing in the RFCs legitimizes mail routing over mDNS, but unlike
    // SOA/NS/ANY it is not an explicitly unicast-only type, so it stays
    // a warning about a possible leak rather than a definite violation.
    // Single shared verdict (also used for observed questions): definite
    // violations are errors, suspected leaks are warnings.
    if let Some(severity) = unicast_severity(rec.rtype) {
        let message = if severity == Severity::Error {
            format!(
                "{} record leaked onto multicast (unicast-only type)",
                rec.rtype_str
            )
        } else {
            format!(
                "{} record on multicast (possible unicast leak)",
                rec.rtype_str
            )
        };
        out.push(Anomaly {
            kind: "unicast-leak",
            severity,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message,
            rfc: "RFC 6762 §3",
        });
    }

    // Cache-flush bit misuse: shared records must not set it. Reverse
    // mapping PTRs are the exception: the RFC treats them as unique (no
    // other host may claim the same address), so the bit is correct there.
    if rec.rtype == 12 && rec.flush_bit && !is_reverse_ptr(&rec.name) {
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
    // Unique records SHOULD set it; missing is only informational. Scoped
    // to SRV/TXT: omitting the bit on A/AAAA is universal practice across
    // embedded stacks, so flagging it is pure noise (removed, not tuned).
    if matches!(rec.rtype, 33 | 16) && !rec.flush_bit {
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

    // PTR base TTL: service and enumeration PTRs conventionally use
    // 4500s (75 min). A PTR arriving at 120s/60s was usually re-announced
    // with the generic 120s default instead. TXT is deliberately excluded:
    // stacks (e.g. avahi) publish TXT at 120s by default, so flagging it
    // would be noise, not signal.
    if rec.rtype == 12 && rec.ttl <= 120 {
        // Enumeration rows all share the owner name, so name the
        // enumerated type: otherwise every finding reads identically.
        // The announcer is appended centrally below.
        let message = if service_id == "enumeration" {
            format!(
                "PTR for {} base TTL {}s far below the conventional 4500s",
                rec.rdata.trim_end_matches('.'),
                rec.ttl
            )
        } else {
            format!("PTR base TTL {}s far below the conventional 4500s", rec.ttl)
        };
        out.push(Anomaly {
            kind: "ttl-base-mismatch",
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(rec.name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rec.rdata.clone()),
            source: Some(rec.source.to_string()),
            message,
            rfc: "RFC 6762 §10",
        });
    }

    // SRV target shape. Port is never checked: port 0 is valid.
    if rec.rtype == 33 {
        check_srv_target(service_id, rec, out);
    }

    // TXT size only: measure the decoded payload, not the full wire
    // record (owner name + header). Valueless keys, keys without `=`,
    // and empty payloads are all valid and never flagged.
    if rec.rtype == 16 {
        // Encoded length is this plus ~1 length byte per TXT string;
        // negligible against the threshold, so the decoded length rules.
        let payload_len = rec.rdata.len();
        if payload_len > TXT_MAX {
            out.push(Anomaly {
                kind: "txt-oversize",
                severity: Severity::Warning,
                service: service_id.to_string(),
                record_name: Some(rec.name.clone()),
                rtype: Some(rec.rtype),
                rtype_str: Some(rec.rtype_str.clone()),
                rdata: Some(rec.rdata.clone()),
                source: Some(rec.source.to_string()),
                message: format!("TXT payload ~{payload_len}B exceeds {TXT_MAX}B"),
                rfc: "RFC 6762 §17",
            });
        }
    }
}

fn check_srv_target(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let parts: Vec<&str> = rec.rdata.split_whitespace().collect();
    if parts.len() < 4 {
        out.push(srv_anomaly(service_id, rec, "SRV rdata is malformed"));
        return;
    }
    // Priority, weight, and port are 16-bit fields; port 0 stays valid.
    for (field, value) in [
        ("priority", parts[0]),
        ("weight", parts[1]),
        ("port", parts[2]),
    ] {
        if value.parse::<u16>().is_err() {
            out.push(srv_anomaly(
                service_id,
                rec,
                &format!("SRV {field} '{value}' is not a 16-bit number"),
            ));
            return;
        }
    }
    let target = parts[3..].join(" ");
    let trimmed = target.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "." {
        out.push(srv_anomaly(service_id, rec, "SRV target is empty"));
        return;
    }
    if let Some(reason) = dns_name_problem(trimmed) {
        out.push(srv_anomaly(
            service_id,
            rec,
            &format!("SRV target {target} invalid: {reason}"),
        ));
        return;
    }
    if !trimmed.to_ascii_lowercase().ends_with(".local") && !trimmed.eq_ignore_ascii_case("local") {
        out.push(srv_anomaly(
            service_id,
            rec,
            &format!("SRV target {target} is outside .local"),
        ));
    }
}

fn srv_anomaly(service_id: &str, rec: &RawRecord, message: &str) -> Anomaly {
    Anomaly {
        kind: "srv-target",
        severity: Severity::Warning,
        service: service_id.to_string(),
        record_name: Some(rec.name.clone()),
        rtype: Some(rec.rtype),
        rtype_str: Some(rec.rtype_str.clone()),
        rdata: Some(rec.rdata.clone()),
        source: Some(rec.source.to_string()),
        message: message.to_string(),
        rfc: "RFC 6763 §12",
    }
}

/// Basic DNS-name shape: dot-separated non-empty labels of at most 63
/// bytes, 255 bytes overall. Internationalized names pass through.
fn dns_name_problem(name: &str) -> Option<String> {
    if name.len() > 255 {
        return Some("name exceeds 255 bytes".to_string());
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Some("name has an empty label".to_string());
        }
        if label.len() > 63 {
            return Some(format!(
                "label '{}' exceeds 63 bytes",
                label.chars().take(12).collect::<String>()
            ));
        }
    }
    None
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
        analyze_service_sub(instance, service_type, hostname, answers, &[])
    }

    fn analyze_service_sub(
        instance: &str,
        service_type: &str,
        hostname: &str,
        answers: &[RawRecord],
        subtypes: &[String],
    ) -> Vec<Anomaly> {
        let services = vec![ServiceView {
            instance,
            service_type,
            hostname,
            answers,
            subtypes,
        }];
        let snap = Snapshot {
            services,
            enum_answers: Vec::new(),
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
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
            subtypes: &[],
        }];
        let snap = Snapshot {
            services,
            enum_answers: Vec::new(),
            pending_hosts: HashSet::from(["myhost.local".to_string()]),
            questions: Vec::new(),
        };
        assert!(!analyze(&snap).iter().any(|a| a.kind == "missing-addr"));
    }

    #[test]
    fn missing_addr_quiet_without_live_srv() {
        // Retained hostname after the SRV expired: nothing claims the host
        // anymore, so a missing address is not an anomaly.
        let answers = vec![aged(
            rec(
                "My._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 myhost.local.",
                120,
                true,
            ),
            500,
        )];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        assert!(!found.iter().any(|a| a.kind == "missing-addr"));
    }

    #[test]
    fn missing_addr_quiet_on_srv_goodbye() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            0,
            false,
        )];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        assert!(!found.iter().any(|a| a.kind == "missing-addr"));
    }

    #[test]
    fn unicast_severity_maps_known_types() {
        // Single shared verdict for answers and (later) questions: definite
        // unicast-only violations are errors, the MX soft case is a warning,
        // everything else is quiet.
        use super::unicast_severity;
        use super::Severity;
        assert_eq!(unicast_severity(2), Some(Severity::Error));
        assert_eq!(unicast_severity(6), Some(Severity::Error));
        assert_eq!(unicast_severity(255), Some(Severity::Error));
        assert_eq!(unicast_severity(15), Some(Severity::Warning));
        assert_eq!(unicast_severity(1), None);
        assert_eq!(unicast_severity(12), None);
        assert_eq!(unicast_severity(5), None);
    }

    #[test]
    fn unicast_leak_flags_any_as_error() {
        let answers = vec![rec("host.local.", 255, "ANY", "", 120, false)];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == "unicast-leak")
            .expect("expected ANY leak");
        assert_eq!(item.severity, Severity::Error);
    }

    #[test]
    fn enumeration_soa_leak_names_service_and_source() {
        let enum_rec = rec(
            "_services._dns-sd._udp.local.",
            6,
            "SOA",
            "host.local. admin 1794425867 21600 1800 43200 10",
            120,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&enum_rec],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        let item = analyze(&snap)
            .iter()
            .find(|a| a.kind == "unicast-leak")
            .expect("expected enumeration SOA leak")
            .clone();
        assert_eq!(item.service, "enumeration");
        assert_eq!(item.severity, Severity::Error);
        assert!(
            item.message.contains("192.168.1.2"),
            "message should name the announcer, got: {}",
            item.message
        );
    }

    fn qview(service: &str, name: &str, rtype: u16, source: SocketAddr) -> QuestionView<'static> {
        // Leak the service id for the snapshot lifetime: tests only.
        let service: &'static str = Box::leak(service.to_string().into_boxed_str());
        let rtype_str: &'static str = Box::leak(
            match rtype {
                2 => "NS",
                6 => "SOA",
                15 => "MX",
                255 => "ANY",
                _ => "PTR",
            }
            .to_string()
            .into_boxed_str(),
        );
        let name: &'static str = Box::leak(name.to_string().into_boxed_str());
        QuestionView {
            service: service.to_string(),
            name,
            rtype,
            rtype_str,
            source,
        }
    }

    fn analyze_questions(questions: &[QuestionView]) -> Vec<Anomaly> {
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: Vec::new(),
            pending_hosts: HashSet::new(),
            questions: questions.to_vec(),
        };
        analyze(&snap)
    }

    #[test]
    fn rtype_from_str_round_trips() {
        use super::rtype_from_str;
        assert_eq!(rtype_from_str("A"), Some(1));
        assert_eq!(rtype_from_str("SOA"), Some(6));
        assert_eq!(rtype_from_str("ANY"), Some(255));
        assert_eq!(rtype_from_str("TYPE47"), Some(47));
        assert_eq!(rtype_from_str("bogus"), None);
    }

    #[test]
    fn unicast_question_flags_soa_with_querier() {
        let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, querier)]);
        let item = found
            .iter()
            .find(|a| a.kind == "unicast-question")
            .expect("expected SOA question leak");
        assert_eq!(item.severity, Severity::Error);
        assert_eq!(item.service, "My._http._tcp.local");
        assert_eq!(item.record_name.as_deref(), Some("fritz.box."));
        assert_eq!(item.rtype, Some(6));
        assert!(
            item.message.contains("192.168.1.9"),
            "message should name the querier, got: {}",
            item.message
        );
        assert!(
            item.message.contains("fritz.box"),
            "message should name the queried name, got: {}",
            item.message
        );
    }

    #[test]
    fn unicast_question_mx_is_warning() {
        let found = analyze_questions(&[qview(
            "My._http._tcp.local",
            "mail.local.",
            15,
            test_source(),
        )]);
        let item = found
            .iter()
            .find(|a| a.kind == "unicast-question")
            .expect("expected MX question leak");
        assert_eq!(item.severity, Severity::Warning);
    }

    #[test]
    fn unicast_question_self_port_zero_excluded() {
        // Port 0 can never be a real mDNS querier: our own inferred sends
        // (SELF_SOURCE) must never flag.
        let zelf: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, zelf)]);
        assert!(
            !found.iter().any(|a| a.kind == "unicast-question"),
            "self sends must stay quiet"
        );
    }

    #[test]
    fn unicast_question_quiet_for_multicast_types() {
        let found = analyze_questions(&[qview(
            "My._http._tcp.local",
            "_http._tcp.local.",
            12,
            test_source(),
        )]);
        assert!(
            !found.iter().any(|a| a.kind == "unicast-question"),
            "multicast-type questions must stay quiet"
        );
    }

    #[test]
    fn unicast_question_dedups_per_querier() {
        let a: SocketAddr = "192.168.1.9:5353".parse().unwrap();
        let b: SocketAddr = "192.168.1.10:5353".parse().unwrap();
        // Same querier asking twice: one finding.
        let found = analyze_questions(&[
            qview("My._http._tcp.local", "fritz.box.", 6, a),
            qview("My._http._tcp.local", "fritz.box.", 6, a),
        ]);
        assert_eq!(
            found
                .iter()
                .filter(|a| a.kind == "unicast-question")
                .count(),
            1
        );
        // Two queriers: one finding each, so every row can mark.
        let found = analyze_questions(&[
            qview("My._http._tcp.local", "fritz.box.", 6, a),
            qview("My._http._tcp.local", "fritz.box.", 6, b),
        ]);
        assert_eq!(
            found
                .iter()
                .filter(|a| a.kind == "unicast-question")
                .count(),
            2
        );
    }

    #[test]
    fn unicast_question_ns_is_error_any_is_quiet_probe() {
        // NS questions have no legitimate multicast use; ANY questions
        // are ownership probes (RFC 6762 §8.1, §6.1) and must stay quiet.
        let found = analyze_questions(&[qview(
            "My._http._tcp.local",
            "host.local.",
            2,
            test_source(),
        )]);
        let item = found
            .iter()
            .find(|a| a.kind == "unicast-question")
            .expect("expected NS question leak");
        assert_eq!(item.severity, Severity::Error);
        assert_eq!(item.rtype_str.as_deref(), Some("NS"));
        let found = analyze_questions(&[qview(
            "My._http._tcp.local",
            "host.local.",
            255,
            test_source(),
        )]);
        assert!(
            !found.iter().any(|a| a.kind == "unicast-question"),
            "ANY probe questions must stay quiet"
        );
    }

    #[test]
    fn unicast_leak_same_answer_from_two_sources_is_one_finding() {
        // Demand-side findings split per querier, but answer sightings
        // keep the established behavior: one finding no matter how many
        // sources announce it.
        let mut second = rec("host.local.", 2, "NS", "host.local.", 120, false);
        second.source = "192.168.1.9:5353".parse().unwrap();
        let answers = vec![
            rec("host.local.", 2, "NS", "host.local.", 120, false),
            second,
        ];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        assert_eq!(
            found.iter().filter(|a| a.kind == "unicast-leak").count(),
            1,
            "same answer from two sources must stay one finding"
        );
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
    fn reverse_ptr_flush_is_not_an_error() {
        // Reverse-mapping PTRs are unique (one address, one owner), so the
        // flush bit is correct there. Both v4 and v6 forms stay quiet.
        for name in [
            "Android.local.37.178.168.192.in-addr.arpa.",
            "Android.local.8.A.8.E.A.F.E.F.F.F.0.A.D.B.8.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.D.F.ip6.arpa.",
        ] {
            let answers = vec![rec(name, 12, "PTR", "Android.local.", 120, true)];
            let found = analyze_service("X", "_http._tcp.local", "", &answers);
            assert!(
                !found.iter().any(|a| a.kind == "shared-flush"),
                "reverse PTR {name} should be quiet"
            );
        }
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
    fn addr_records_without_flush_are_quiet() {
        // Omitting the bit on A/AAAA is universal practice, not signal.
        let answers = vec![
            rec(
                "My._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 myhost.local.",
                120,
                true,
            ),
            rec("myhost.local.", 1, "A", "192.168.1.10", 120, false),
            rec("myhost.local.", 28, "AAAA", "fe80::1", 120, false),
        ];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        assert!(!found.iter().any(|a| a.kind == "unique-no-flush"));
    }

    #[test]
    fn mx_leak_is_warning_not_error() {
        let answers = vec![rec("host.local.", 15, "MX", "10 host.local.", 120, false)];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == "unicast-leak")
            .expect("expected leak");
        assert_eq!(item.severity, Severity::Warning);
    }

    #[test]
    fn ptr_with_short_base_ttl_is_flagged() {
        for ttl in [60, 120] {
            let answers = vec![rec(
                "_http._tcp.local.",
                12,
                "PTR",
                "X._http._tcp.local.",
                ttl,
                false,
            )];
            let found = analyze_service("X", "_http._tcp.local", "", &answers);
            let item = found
                .iter()
                .find(|a| a.kind == "ttl-base-mismatch")
                .unwrap_or_else(|| panic!("PTR@{ttl} should be flagged"));
            assert_eq!(item.severity, Severity::Warning);
        }
    }

    #[test]
    fn enumeration_ttl_mismatch_names_type_and_source() {
        let enum_rec = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_http._tcp.local.",
            120,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&enum_rec],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        let item = analyze(&snap)
            .iter()
            .find(|a| a.kind == "ttl-base-mismatch")
            .expect("expected enumeration ttl-base-mismatch")
            .clone();
        assert!(
            item.message.contains("_http._tcp.local"),
            "message should name the enumerated type, got: {}",
            item.message
        );
        assert!(
            item.message.contains("192.168.1.2"),
            "message should name the announcer, got: {}",
            item.message
        );
    }

    #[test]
    fn ptr_with_4500_base_is_quiet() {
        let answers = vec![rec(
            "_http._tcp.local.",
            12,
            "PTR",
            "X._http._tcp.local.",
            4500,
            false,
        )];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        assert!(!found.iter().any(|a| a.kind == "ttl-base-mismatch"));
    }

    #[test]
    fn srv_with_120_base_is_quiet() {
        // 120s is the normal SRV base; the 4500 expectation is PTR-only.
        let answers = vec![rec(
            "X._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            120,
            true,
        )];
        let found = analyze_service("X", "_http._tcp.local", "myhost.local.", &answers);
        assert!(!found.iter().any(|a| a.kind == "ttl-base-mismatch"));
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
    fn type_format_rejects_bad_labels() {
        for t in [
            "_80._tcp.local",
            "_-bad._tcp.local",
            "_bad-._tcp.local",
            "_http._sctp.local",
        ] {
            let found = analyze_service("X", t, "", &[]);
            assert!(
                found.iter().any(|a| a.kind == "type-format"),
                "type {t} should be flagged"
            );
        }
    }

    #[test]
    fn type_format_accepts_valid_subtype_label() {
        let subtypes = vec!["_printer".to_string()];
        let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &subtypes);
        assert!(!found.iter().any(|a| a.kind == "type-format"));
    }

    #[test]
    fn type_format_flags_bad_subtype_label() {
        let subtypes = vec!["_80".to_string()];
        let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &subtypes);
        assert!(found.iter().any(|a| a.kind == "type-format"));
    }

    #[test]
    fn srv_rejects_non_numeric_fields() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "fast quick 80 myhost.local.",
            120,
            true,
        )];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        assert!(found.iter().any(|a| a.kind == "srv-target"));
    }

    #[test]
    fn srv_rejects_empty_dns_label_in_target() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 foo..local.",
            120,
            true,
        )];
        let found = analyze_service("My", "_http._tcp.local", "foo..local.", &answers);
        assert!(found.iter().any(|a| a.kind == "srv-target"));
    }

    #[test]
    fn txt_wire_overhead_alone_is_quiet() {
        let mut r = rec("X._http._tcp.local.", 16, "TXT", "k=v", 120, true);
        r.wire = vec![0u8; 1400];
        let found = analyze_service("X", "_http._tcp.local", "", &[r]);
        assert!(!found.iter().any(|a| a.kind == "txt-oversize"));
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
    fn type_format_ignores_label_length_and_underscores() {
        // Neither the RFC's 15-character limit nor inner underscores are
        // enforced by real stacks, so the SHIELD's real type stays quiet.
        let found = analyze_service("SHIELD", "_nv_shield_remote._tcp.local", "", &[]);
        assert!(!found.iter().any(|a| a.kind == "type-format"));
    }

    #[test]
    fn enumeration_ptr_with_bad_type_flags_row() {
        let enum_rec = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_80._tcp.local.",
            4500,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&enum_rec],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        let found = analyze(&snap);
        let item = found
            .iter()
            .find(|a| a.kind == "type-format" && a.service == "enumeration")
            .expect("expected enumeration type-format");
        // Full record identity so the Answers table can mark the PTR row.
        assert_eq!(
            item.record_name.as_deref(),
            Some("_services._dns-sd._udp.local.")
        );
        assert_eq!(item.rtype, Some(12));
        assert!(item.rdata.is_some());
    }

    #[test]
    fn enumeration_ptr_with_good_type_stays_quiet() {
        let enum_rec = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_http._tcp.local.",
            4500,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&enum_rec],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        assert!(!analyze(&snap).iter().any(|a| a.kind == "type-format"));
    }

    #[test]
    fn enumeration_ptr_with_valid_subtype_stays_quiet() {
        let enum_rec = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_printer._sub._http._tcp.local.",
            4500,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&enum_rec],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        assert!(!analyze(&snap).iter().any(|a| a.kind == "type-format"));
    }

    #[test]
    fn enumeration_ptr_with_bad_subtype_flags_row() {
        let enum_rec = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_-bad._sub._http._tcp.local.",
            4500,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&enum_rec],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        assert!(analyze(&snap)
            .iter()
            .any(|a| a.kind == "type-format" && a.service == "enumeration"));
    }

    #[test]
    fn soa_match_key_ignores_serial_for_display() {
        // The Answers pane matches rows against findings by key: two live
        // SOA rows differing only in serial must share one display key so
        // both mark while counting as one finding.
        let a = super::anomaly_match_key(6, "host.local. admin 1794425867 21600 1800 43200 10");
        let b = super::anomaly_match_key(6, "host.local. admin 1794425874 21600 1800 43200 10");
        assert_eq!(a, b);
        // Non-SOA rdata passes through untouched.
        assert_eq!(super::anomaly_match_key(1, "192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn soa_serial_churn_dedups_to_one_leak() {
        let answers = vec![
            rec(
                "host.local.",
                6,
                "SOA",
                "host.local. admin 1794425867 21600 1800 43200 10",
                4500,
                false,
            ),
            rec(
                "host.local.",
                6,
                "SOA",
                "host.local. admin 1794425874 21600 1800 43200 10",
                4500,
                false,
            ),
        ];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        assert_eq!(
            found.iter().filter(|a| a.kind == "unicast-leak").count(),
            1,
            "serial-only differences must not multiply findings"
        );
    }

    #[test]
    fn unicast_soa_expired_and_goodbye_never_flagged() {
        let old = aged(
            rec(
                "host.local.",
                6,
                "SOA",
                "host.local. admin 1794425867 21600 1800 43200 10",
                120,
                false,
            ),
            500,
        );
        let gone = rec(
            "host.local.",
            6,
            "SOA",
            "host.local. admin 1794425874 21600 1800 43200 10",
            0,
            false,
        );
        let answers = vec![old, gone];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        assert!(
            !found.iter().any(|a| a.kind == "unicast-leak"),
            "expired and goodbye SOA must not leak-flag"
        );
    }

    #[test]
    fn multicast_types_and_cname_stay_quiet_for_leak() {
        let answers = vec![
            rec(
                "_http._tcp.local.",
                12,
                "PTR",
                "X._http._tcp.local.",
                4500,
                false,
            ),
            rec(
                "X._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 h.local.",
                120,
                true,
            ),
            rec("X._http._tcp.local.", 16, "TXT", "k=v", 4500, true),
            rec("h.local.", 1, "A", "192.168.1.1", 120, true),
            rec("h.local.", 28, "AAAA", "fe80::1", 120, true),
            rec("alias.local.", 5, "CNAME", "h.local.", 120, false),
        ];
        let found = analyze_service("X", "_http._tcp.local", "h.local.", &answers);
        assert!(
            !found.iter().any(|a| a.kind == "unicast-leak"),
            "valid multicast types and CNAME must not leak-flag"
        );
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
