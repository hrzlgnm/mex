use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::browse::RawRecord;

/// Service identity carried by findings: `instance.service_type`, or
/// `enumeration` for enumeration-row answers. Single definition shared
/// by the analyzer and the pane filters so the two cannot drift.
pub const ENUMERATION_SERVICE: &str = "enumeration";

/// Service identity for a confirmed or pending instance.
pub fn service_id(instance: &str, service_type: &str) -> String {
    format!("{instance}.{service_type}")
}

/// Severity of an anomaly: errors are clear RFC violations, warnings are
/// likely misconfigurations, informational notes are observations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// Stable machine-readable identifier for an anomaly kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AnomalyKind {
    MissingAddr,
    UnresolvedSrvTarget,
    UnicastLeak,
    UnicastQuestion,
    TtlLow,
    TtlHigh,
    TtlMismatch,
    TtlUnstable,
    NonUtf8,
    SharedFlush,
    NoFlush,
    TxtOversize,
    SrvTarget,
    TypeFormat,
    EnumSubtype,
}

impl AnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyKind::MissingAddr => "missing-addr",
            AnomalyKind::UnresolvedSrvTarget => "unresolved-srv-target",
            AnomalyKind::UnicastLeak => "unicast-leak",
            AnomalyKind::UnicastQuestion => "unicast-question",
            AnomalyKind::TtlLow => "ttl-low",
            AnomalyKind::TtlHigh => "ttl-high",
            AnomalyKind::TtlMismatch => "ttl-mismatch",
            AnomalyKind::TtlUnstable => "ttl-unstable",
            AnomalyKind::NonUtf8 => "non-utf8-name",
            AnomalyKind::SharedFlush => "shared-flush",
            AnomalyKind::NoFlush => "no-flush",
            AnomalyKind::TxtOversize => "txt-oversize",
            AnomalyKind::SrvTarget => "srv-target",
            AnomalyKind::TypeFormat => "type-format",
            AnomalyKind::EnumSubtype => "enum-subtype",
        }
    }

    /// Whether the TTL itself is the problem (marks the TTL cell, not the type).
    pub fn is_ttl(self) -> bool {
        matches!(
            self,
            AnomalyKind::TtlLow
                | AnomalyKind::TtlHigh
                | AnomalyKind::TtlMismatch
                | AnomalyKind::TtlUnstable
        )
    }

    /// Whether this is a demand-side unicast-only question finding.
    pub fn is_question(self) -> bool {
        self == AnomalyKind::UnicastQuestion
    }
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialOrd for AnomalyKind {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AnomalyKind {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

/// One RFC-referenced anomaly. All strings are owned so the analyzer stays
/// a pure snapshot function with no borrows into browser state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anomaly {
    /// Stable machine-readable identifier (`missing-addr`, `unicast-leak`, ...).
    pub kind: AnomalyKind,
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
    /// RFC obligation level: `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`,
    /// or `MAY`. Separates violations from recommendation deviations.
    pub requirement: &'static str,
}

impl Anomaly {
    /// Whether the finding surfaces outside the metrics overlay: errors
    /// and warnings mark table rows and fill the Anomalies pane, while
    /// informational notes stay in the overlay.
    pub fn is_surfaced(&self) -> bool {
        !matches!(self.severity, Severity::Info)
    }
}

/// A service slice for analysis: borrows browser state, owns nothing.
pub struct ServiceView<'a> {
    pub instance: &'a str,
    pub service_type: &'a str,
    pub hostname: &'a str,
    pub answers: &'a [RawRecord],
    pub subtypes: &'a [Vec<u8>],
}

/// Snapshot input for the analyzer. Built by the caller from live browser
/// state; the analyzer never touches query scheduling, ingest, or expiry.
pub struct Snapshot<'a> {
    pub services: Vec<ServiceView<'a>>,
    pub enum_answers: Vec<&'a RawRecord>,
    /// Lowercased hostnames with a queued address (suppresses
    /// `unresolved-srv-target` while the address is in flight).
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

/// One transmitted A/AAAA lookup for a live SRV target.
#[derive(Clone, Debug)]
pub struct AddressQueryView {
    pub service: String,
    pub hostname: String,
    pub rtype: u16,
    pub transmitted_at: Instant,
    pub interfaces: String,
}

const ADDRESS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

struct AddressEvidence<'a> {
    host_has_addr: &'a HashMap<String, bool>,
    host_addr_latest: &'a HashMap<(String, u16), Instant>,
    pending_hosts: &'a HashSet<String>,
    queries: &'a [AddressQueryView],
    events: &'a [crate::browse::Event],
    now: Instant,
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
#[cfg(test)]
pub fn analyze(snap: &Snapshot) -> Vec<Anomaly> {
    analyze_observations(snap, &[], &[])
}

/// Analyze browser state and retained response packets. Packet-scoped checks
/// use `events` rather than inferring responder behavior from the cache.
pub fn analyze_observations(
    snap: &Snapshot,
    events: &[crate::browse::Event],
    address_queries: &[AddressQueryView],
) -> Vec<Anomaly> {
    let now = Instant::now();
    let mut out: Vec<Anomaly> = Vec::new();

    let mut host_has_addr: HashMap<String, bool> = HashMap::new();
    let mut host_addr_latest: HashMap<(String, u16), Instant> = HashMap::new();
    for svc in &snap.services {
        for rec in svc.answers {
            if matches!(rec.rtype, 1 | 28) {
                let key = rec.name.trim_end_matches('.').to_lowercase();
                if rec.ttl > 0 {
                    host_addr_latest
                        .entry((key.clone(), rec.rtype))
                        .and_modify(|at| *at = (*at).max(rec.received_at))
                        .or_insert(rec.received_at);
                }
                if is_live(rec, now) {
                    host_has_addr.insert(key, true);
                }
            }
        }
    }

    let address_evidence = AddressEvidence {
        host_has_addr: &host_has_addr,
        host_addr_latest: &host_addr_latest,
        pending_hosts: &snap.pending_hosts,
        queries: address_queries,
        events,
        now,
    };

    for svc in &snap.services {
        let service_id = service_id(svc.instance, svc.service_type);
        check_unresolved_srv_target(svc, &service_id, &address_evidence, &mut out);
        // A retained hostname outlives its SRV (expiry, goodbye): only a
        // live SRV proves the service still claims the host.
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
        check_record(ENUMERATION_SERVICE, rec, &mut out);
        // Enumeration PTR targets name service types (or subtypes): a
        // malformed target means the name itself violates DNS-SD naming,
        // so flag the PTR row itself (with full record identity, so the
        // Answers table marks it).
        if rec.rtype == 12 {
            let target = rec.rdata.trim_end_matches('.');
            let target_labels = rec.ptr_target_labels.as_deref();
            let type_problem = target_labels
                .map(service_type_wire_labels_problem)
                .unwrap_or_else(|| service_type_problem(target));
            let subtype = target_labels
                .map(is_subtype_wire_labels)
                .unwrap_or_else(|| is_subtype_target(target));
            let target_display = target_labels
                .map(display_type_target)
                .unwrap_or_else(|| target.to_string());
            if let Some(reason) = type_problem {
                out.push(Anomaly {
                    kind: AnomalyKind::TypeFormat,
                    severity: Severity::Warning,
                    service: ENUMERATION_SERVICE.to_string(),
                    record_name: Some(rec.name.clone()),
                    rtype: Some(rec.rtype),
                    rtype_str: Some(rec.rtype_str.clone()),
                    rdata: Some(rec.rdata.clone()),
                    source: Some(rec.source.to_string()),
                    message: format!("bad enumerated type {target_display}: {reason}"),
                    rfc: "RFC 6763 §7",
                    requirement: "MUST",
                });
            } else if subtype {
                // RFC 6763 §9 enumerates base service types; a subtype
                // (e.g. _T35._sub._matterd._udp.local) is queried
                // separately and does not belong in the enumeration list.
                out.push(Anomaly {
                    kind: AnomalyKind::EnumSubtype,
                    severity: Severity::Warning,
                    service: ENUMERATION_SERVICE.to_string(),
                    record_name: Some(rec.name.clone()),
                    rtype: Some(rec.rtype),
                    rtype_str: Some(rec.rtype_str.clone()),
                    rdata: Some(rec.rdata.clone()),
                    source: Some(rec.source.to_string()),
                    message: format!("{target_display} is a subtype; want base type"),
                    rfc: "RFC 6763 §9",
                    requirement: "SHOULD",
                });
            }
        }
    }

    for event in events {
        check_missing_addr_packet(event, now, &mut out);
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
            .then_with(|| a.kind.cmp(&b.kind))
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
            (AnomalyKind::UnicastLeak, Some(6)) => {
                anomaly_match_key(6, &a.rdata.clone().unwrap_or_default())
            }
            (AnomalyKind::EnumSubtype | AnomalyKind::TypeFormat, Some(12))
                if a.service == ENUMERATION_SERVICE =>
            {
                a.message.clone()
            }
            _ => a.rdata.clone().unwrap_or_default(),
        };
        // Questions carry no rdata: tell queriers apart by source, so each
        // leaking querier keeps its own finding and every row can mark.
        // Answers keep the established behavior (one finding no matter how
        // many sources announce it) — except context-gated kinds, where
        // the same rdata via multicast vs unicast (or answer vs
        // authority) is a different verdict and must not collapse.
        let source_key = match a.kind {
            AnomalyKind::UnicastQuestion => a.source.clone().unwrap_or_default(),
            _ => String::new(),
        };
        let context_key = match a.kind {
            AnomalyKind::UnicastLeak | AnomalyKind::NoFlush => a.message.clone(),
            _ => String::new(),
        };
        let key = (
            a.kind,
            a.service.clone(),
            a.record_name.clone().unwrap_or_default(),
            a.rtype.unwrap_or(0),
            rdata_key,
            source_key,
            context_key,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressQueryOutcome {
    NoData,
    NxDomain,
    NoResponse,
    Inconclusive,
    UnattributedNxDomain,
    NotQueried,
    Pending,
    Answered,
}

fn check_unresolved_srv_target(
    svc: &ServiceView,
    service_id: &str,
    evidence: &AddressEvidence<'_>,
    out: &mut Vec<Anomaly>,
) {
    let host = svc.hostname.trim_end_matches('.');
    if host.is_empty() {
        return;
    }
    let Some(srv) = svc.answers.iter().find(|rec| {
        rec.rtype == 33
            && is_live(rec, evidence.now)
            && rec
                .rdata
                .split_whitespace()
                .last()
                .is_some_and(|target| target.trim_end_matches('.').eq_ignore_ascii_case(host))
    }) else {
        return;
    };
    let host_key = host.to_lowercase();
    if evidence
        .host_has_addr
        .get(&host_key)
        .copied()
        .unwrap_or(false)
        || evidence.pending_hosts.contains(&host_key)
    {
        return;
    }

    let outcomes: Vec<_> = [1, 28]
        .into_iter()
        .map(|rtype| {
            let query = evidence.queries.iter().filter(|query| {
                query.service == service_id
                    && query
                        .hostname
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(host)
                    && query.rtype == rtype
            });
            let Some(query) = query.max_by_key(|query| query.transmitted_at) else {
                return (rtype, AddressQueryOutcome::NotQueried, None);
            };
            if evidence
                .host_addr_latest
                .get(&(host_key.clone(), rtype))
                .is_some_and(|at| *at > query.transmitted_at)
            {
                return (rtype, AddressQueryOutcome::Answered, None);
            }
            if let Some(record) = evidence.events.iter().find_map(|event| {
                event.answers.iter().find(|record| {
                    event.rcode == Some(3)
                        && record.rtype == 5
                        && record.name.trim_end_matches('.').eq_ignore_ascii_case(host)
                        && record.section == crate::browse::RecordSection::Answer
                        && record.received_at >= query.transmitted_at
                        && is_live(record, evidence.now)
                })
            }) {
                return (
                    rtype,
                    AddressQueryOutcome::NxDomain,
                    Some((record.source.to_string(), record.iface.clone())),
                );
            }
            if let Some(record) = evidence.events.iter().find_map(|event| {
                event.answers.iter().find(|record| {
                    event.rcode == Some(0)
                        && record.rtype == 47
                        && record.name.trim_end_matches('.').eq_ignore_ascii_case(host)
                        && matches!(
                            record.section,
                            crate::browse::RecordSection::Answer
                                | crate::browse::RecordSection::Authority
                        )
                        && record.received_at >= query.transmitted_at
                        && is_live(record, evidence.now)
                        && !record
                            .rdata
                            .split_whitespace()
                            .skip(1)
                            .filter_map(rtype_from_str)
                            .any(|present| present == rtype)
                })
            }) {
                return (
                    rtype,
                    AddressQueryOutcome::NoData,
                    Some((record.source.to_string(), record.iface.clone())),
                );
            }
            if evidence
                .events
                .iter()
                .any(|event| event.rcode.is_some() && event.received_at >= query.transmitted_at)
            {
                let outcome = if evidence.events.iter().any(|event| {
                    event.rcode == Some(3) && event.received_at >= query.transmitted_at
                }) {
                    AddressQueryOutcome::UnattributedNxDomain
                } else {
                    AddressQueryOutcome::Inconclusive
                };
                return (rtype, outcome, None);
            }
            let outcome = if evidence.now.saturating_duration_since(query.transmitted_at)
                >= ADDRESS_RESPONSE_TIMEOUT
            {
                AddressQueryOutcome::NoResponse
            } else {
                AddressQueryOutcome::Pending
            };
            (rtype, outcome, None)
        })
        .collect();

    let interfaces = evidence
        .queries
        .iter()
        .find(|query| {
            query.service == service_id
                && query
                    .hostname
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(host)
        })
        .map(|query| query.interfaces.as_str())
        .unwrap_or_default();

    if outcomes.iter().any(|(_, outcome, _)| {
        matches!(
            outcome,
            AddressQueryOutcome::Pending | AddressQueryOutcome::Answered
        )
    }) || !outcomes.iter().any(|(_, outcome, _)| {
        matches!(
            outcome,
            AddressQueryOutcome::NoData
                | AddressQueryOutcome::NxDomain
                | AddressQueryOutcome::NoResponse
                | AddressQueryOutcome::Inconclusive
                | AddressQueryOutcome::UnattributedNxDomain
        )
    }) {
        return;
    }

    let (a_outcome, a_context) = (&outcomes[0].1, &outcomes[0].2);
    let (aaaa_outcome, aaaa_context) = (&outcomes[1].1, &outcomes[1].2);
    let explicit_negative = matches!(a_outcome, AddressQueryOutcome::NxDomain)
        || matches!(aaaa_outcome, AddressQueryOutcome::NxDomain)
        || (matches!(a_outcome, AddressQueryOutcome::NoData)
            && matches!(aaaa_outcome, AddressQueryOutcome::NoData));
    let outcome_text = |outcome: AddressQueryOutcome| match outcome {
        AddressQueryOutcome::NoData => "NODATA",
        AddressQueryOutcome::NxDomain => "NXDOMAIN",
        AddressQueryOutcome::NoResponse => "no response",
        AddressQueryOutcome::Inconclusive => "unattributed mDNS response",
        AddressQueryOutcome::UnattributedNxDomain => "unattributed NXDOMAIN response",
        AddressQueryOutcome::NotQueried => "not queried",
        AddressQueryOutcome::Pending => "pending",
        AddressQueryOutcome::Answered => "answered",
    };
    let source_context = a_context.as_ref().or(aaaa_context.as_ref());
    let record_name = Some(srv.name.clone());
    let rdata = Some(srv.rdata.clone());
    let source = source_context.map(|(source, _)| source.clone());
    let query_interfaces = if interfaces.is_empty() {
        String::new()
    } else {
        format!(" across mDNS interfaces {interfaces}")
    };
    let response_interface = source_context
        .as_ref()
        .filter(|(_, iface)| !iface.is_empty())
        .map(|(_, iface)| format!("; response on {iface}"))
        .unwrap_or_default();
    let unicast_note = if host_key != "local" && !host_key.ends_with(".local") {
        "; unicast DNS may still resolve this target"
    } else {
        ""
    };
    let message = format!(
        "A: {}; AAAA: {} for {host} via mDNS{query_interfaces}{response_interface}{}",
        outcome_text(outcomes[0].1),
        outcome_text(outcomes[1].1),
        if explicit_negative {
            ""
        } else {
            "; lookup inconclusive"
        }
    ) + unicast_note;
    out.push(Anomaly {
        kind: AnomalyKind::UnresolvedSrvTarget,
        severity: if explicit_negative {
            Severity::Warning
        } else {
            Severity::Info
        },
        service: service_id.to_string(),
        record_name,
        rtype: Some(33),
        rtype_str: Some("SRV".to_string()),
        rdata,
        source,
        message,
        rfc: "RFC 6762 §6",
        requirement: "MAY",
    });
}

fn is_dns_sd_instance_ptr(name: &str) -> bool {
    let labels: Vec<_> = name.trim_end_matches('.').split('.').collect();
    let is_protocol =
        |label: &str| label.eq_ignore_ascii_case("_tcp") || label.eq_ignore_ascii_case("_udp");
    match labels.as_slice() {
        [service, protocol, local] => {
            service.starts_with('_') && is_protocol(protocol) && local.eq_ignore_ascii_case("local")
        }
        [subtype, sub, service, protocol, local] => {
            subtype.starts_with('_')
                && sub.eq_ignore_ascii_case("_sub")
                && service.starts_with('_')
                && is_protocol(protocol)
                && local.eq_ignore_ascii_case("local")
        }
        _ => false,
    }
}

fn check_missing_addr_packet(event: &crate::browse::Event, now: Instant, out: &mut Vec<Anomaly>) {
    if event.rcode != Some(0) {
        return;
    }
    for ptr in event.answers.iter().filter(|rec| {
        rec.rtype == 12
            && rec.section == crate::browse::RecordSection::Answer
            && is_live(rec, now)
            && is_dns_sd_instance_ptr(&rec.name)
    }) {
        let mut missing_hosts = Vec::new();
        let mut seen_hosts = HashSet::new();
        for srv in event.answers.iter().filter(|rec| {
            rec.rtype == 33
                && rec.name.eq_ignore_ascii_case(&ptr.rdata)
                && rec.section != crate::browse::RecordSection::Question
                && is_live(rec, now)
        }) {
            let Some(host) = srv.rdata.split_whitespace().last() else {
                continue;
            };
            if host == "."
                || event.answers.iter().any(|rec| {
                    matches!(rec.rtype, 1 | 28)
                        && rec.section == crate::browse::RecordSection::Additional
                        && rec.name.eq_ignore_ascii_case(host)
                        && is_live(rec, now)
                })
            {
                continue;
            }
            let host = host.trim_end_matches('.');
            if seen_hosts.insert(host.to_lowercase()) {
                missing_hosts.push(host.to_string());
            }
        }
        if missing_hosts.is_empty() {
            continue;
        }
        let ingress = if !ptr.iface.is_empty() {
            format!(" on {}", ptr.iface)
        } else if ptr.ifindex != 0 {
            format!(" on if#{}", ptr.ifindex)
        } else {
            String::new()
        };
        out.push(Anomaly {
            kind: AnomalyKind::MissingAddr,
            severity: Severity::Info,
            service: service_id_from_ptr(&ptr.rdata),
            record_name: Some(ptr.name.clone()),
            rtype: Some(ptr.rtype),
            rtype_str: Some(ptr.rtype_str.clone()),
            rdata: Some(ptr.rdata.clone()),
            source: Some(event.source.to_string()),
            message: format!(
                "PTR response packet from {}{} (Answer) omitted Additional A/AAAA for SRV target{} {}",
                event.source,
                ingress,
                if missing_hosts.len() == 1 { "" } else { "s" },
                missing_hosts.join(", ")
            ),
            rfc: "RFC 6763 §12.1/§12.2",
            requirement: "SHOULD",
        });
    }
}

fn service_id_from_ptr(target: &str) -> String {
    let target = target.trim_end_matches('.');
    let Some((instance, service_type)) = target.split_once('.') else {
        return target.to_string();
    };
    service_id(instance, service_type)
}

fn check_type_format(svc: &ServiceView, service_id: &str, out: &mut Vec<Anomaly>) {
    let st = svc.service_type.trim_end_matches('.');
    if st.eq_ignore_ascii_case("_services._dns-sd._udp.local") {
        return;
    }
    // Reverse-mapping names map addresses to hostnames; they are not
    // service types and must never flag here (ingest refuses to browse
    // them, this is the backstop for any other path).
    if is_reverse_ptr(st) {
        return;
    }
    if let Some(reason) = service_type_problem(st) {
        out.push(Anomaly {
            kind: AnomalyKind::TypeFormat,
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: None,
            rtype: None,
            rtype_str: None,
            rdata: None,
            source: None,
            message: format!("bad type {st}: {reason}"),
            rfc: "RFC 6763 §7",
            requirement: "MUST",
        });
    }
}

/// Why a service type string is invalid, if it is. `None` means valid.
/// Split out so confirmed services and enumeration PTR targets share
/// one verdict and one message. Accepts `subtype._sub._service._tcp`
/// (RFC 6763 §7.1) as well as plain service types.
fn service_type_problem(st: &str) -> Option<String> {
    let parts: Vec<&[u8]> = st.split('.').map(str::as_bytes).collect();
    service_type_labels_problem(&parts)
}

fn service_type_labels_problem(parts: &[&[u8]]) -> Option<String> {
    match parts {
        [svc, proto, local] => {
            if let Some(reason) = service_label_problem(svc) {
                return Some(reason);
            }
            if !proto.eq_ignore_ascii_case(b"_tcp") && !proto.eq_ignore_ascii_case(b"_udp") {
                return Some("protocol must be _tcp or _udp".to_string());
            }
            if !local.eq_ignore_ascii_case(b"local") {
                return Some("must end in .local".to_string());
            }
            None
        }
        [sub, sub_kw, svc, proto, local] => {
            if let Some(reason) = subtype_problem(sub) {
                return Some(format!("subtype {reason}"));
            }
            if !sub_kw.eq_ignore_ascii_case(b"_sub") {
                return Some(
                    "expected _service._tcp.local or subtype._sub._service._tcp.local".to_string(),
                );
            }
            if let Some(reason) = service_label_problem(svc) {
                return Some(reason);
            }
            if !proto.eq_ignore_ascii_case(b"_tcp") && !proto.eq_ignore_ascii_case(b"_udp") {
                return Some("protocol must be _tcp or _udp".to_string());
            }
            if !local.eq_ignore_ascii_case(b"local") {
                return Some("must end in .local".to_string());
            }
            None
        }
        _ => Some("expected _service._tcp.local or subtype._sub._service._tcp.local".to_string()),
    }
}

fn service_type_wire_labels_problem(labels: &[Vec<u8>]) -> Option<String> {
    service_type_labels_problem(&labels.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

fn service_label_problem(label: &[u8]) -> Option<String> {
    match std::str::from_utf8(label) {
        Ok(label) => label_problem(label),
        Err(_) => Some("service label must be ASCII".to_string()),
    }
}

/// Whether an enumeration target is a subtype (`subtype._sub._svc._tcp.local`).
/// Valid subtypes pass service-type validation but still don't belong in
/// `_services._dns-sd._udp.local` (RFC 6763 §9 lists base types).
fn is_subtype_target(st: &str) -> bool {
    let parts: Vec<&[u8]> = st.split('.').map(str::as_bytes).collect();
    is_subtype_labels(&parts)
}

fn is_subtype_wire_labels(labels: &[Vec<u8>]) -> bool {
    is_subtype_labels(&labels.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

fn is_subtype_labels(labels: &[&[u8]]) -> bool {
    matches!(labels, [_, sub_kw, _, _, _] if sub_kw.eq_ignore_ascii_case(b"_sub"))
}

fn display_type_target(labels: &[Vec<u8>]) -> String {
    let is_subtype = is_subtype_wire_labels(labels);
    labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            if index == 0 && is_subtype {
                display_subtype(label)
            } else {
                String::from_utf8_lossy(label).into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Why an underscore-led service label is invalid, if it is.
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

fn subtype_problem(subtype: &[u8]) -> Option<String> {
    if subtype.is_empty() {
        return Some("subtype is empty".to_string());
    }
    if subtype.len() > 63 {
        return Some(format!(
            "subtype label exceeds 63 bytes ({} bytes)",
            subtype.len()
        ));
    }
    None
}

/// Render subtype octets without losing or disguising non-printable bytes.
pub(crate) fn display_subtype(subtype: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut display = String::new();
    for &byte in subtype {
        if (0x20..=0x7e).contains(&byte) && byte != b'\\' && byte != b'.' {
            display.push(char::from(byte));
        } else if byte == b'\\' {
            display.push_str("\\\\");
        } else {
            display.push_str("\\x");
            display.push(char::from(HEX[usize::from(byte >> 4)]));
            display.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    display
}

/// Subtype identifiers follow RFC 6763 §7.1, not service-label rules.
fn check_subtypes(svc: &ServiceView, service_id: &str, out: &mut Vec<Anomaly>) {
    for sub in svc.subtypes {
        if let Some(reason) = subtype_problem(sub) {
            out.push(Anomaly {
                kind: AnomalyKind::TypeFormat,
                severity: Severity::Warning,
                service: service_id.to_string(),
                record_name: None,
                rtype: None,
                rtype_str: None,
                rdata: None,
                source: None,
                message: format!("bad subtype {}: {reason}", display_subtype(sub)),
                rfc: "RFC 6763 §7.1",
                requirement: "MUST",
            });
        }
    }
}

/// Row identity for a finding (`QRY …` for demand-side questions,
/// `TYPE name` otherwise): the shared core of every display scope.
fn finding_scope(a: &Anomaly) -> String {
    match (&a.record_name, a.rtype_str.as_deref()) {
        (Some(name), Some(rtype)) if a.kind.is_question() => {
            format!("QRY {rtype} {name}")
        }
        (Some(name), Some(rtype)) => format!("{rtype} {name}"),
        _ => String::new(),
    }
}

/// How many findings share each pointed-to row identity, keyed by
/// lowercased `(record name, type)`: rows whose identity repeats name
/// their rdata so identical findings tell apart. Shared by the pane
/// and the overlay so repeated identities disambiguate the same way.
pub(crate) fn identity_counts<'a, I>(items: I) -> HashMap<(String, u16), usize>
where
    I: IntoIterator<Item = &'a Anomaly>,
{
    let mut counts = HashMap::new();
    for a in items {
        if let (Some(name), Some(rtype)) = (&a.record_name, a.rtype) {
            *counts
                .entry((name.trim_end_matches('.').to_lowercase(), rtype))
                .or_insert(0) += 1;
        }
    }
    counts
}

/// Display scope for a finding, shared by the Anomalies pane and the
/// metrics overlay: empty for service-level findings and enumeration
/// rows (constant owner; the message carries the target instead), the
/// QRY or `TYPE name` identity otherwise — plus `= rdata` when siblings
/// share the identity so every row stays tellable-apart, unless the
/// rdata just repeats the service itself (the usual PTR shape: the
/// service column already names it). Question findings always keep
/// their QRY scope: the queried type varies.
pub(crate) fn visible_scope(a: &Anomaly, identity_count: &HashMap<(String, u16), usize>) -> String {
    if is_enumeration_row(&a.service, a.record_name.as_deref()) && !a.kind.is_question() {
        return String::new();
    }
    let base = finding_scope(a);
    if base.is_empty() {
        return base;
    }
    let key = (
        a.record_name
            .as_deref()
            .unwrap_or("")
            .trim_end_matches('.')
            .to_lowercase(),
        a.rtype.unwrap_or(0),
    );
    match (&a.rdata, identity_count.get(&key)) {
        (Some(rdata), Some(&n))
            if n > 1
                && !rdata
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(a.service.trim_end_matches('.')) =>
        {
            format!("{base} = {rdata}")
        }
        _ => base,
    }
}

/// Whether a finding sits on the enumeration row itself (owner
/// `_services._dns-sd._udp.local`): its scope is constant across every
/// enumeration finding, so views omit it and let the message carry the
/// varying target instead.
pub(crate) fn is_enumeration_row(service: &str, record_name: Option<&str>) -> bool {
    service == ENUMERATION_SERVICE
        && record_name.is_some_and(|n| {
            n.trim_end_matches('.')
                .eq_ignore_ascii_case("_services._dns-sd._udp.local")
        })
}

/// Whether a PTR owner name is a reverse-mapping name. Those PTRs are
/// unique (one address, one owner), unlike service/enumeration PTRs.
pub(crate) fn is_reverse_ptr(name: &str) -> bool {
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

/// One-shot (stub) resolver per RFC 6762 §5.1: port 5353 signals a
/// compliant continuous querier (§5.2), so any other source port is a
/// stub asking from an ephemeral port — anything at or above 1024
/// reads as one-shot, i.e. "not a full 5353 querier" (this deliberately
/// includes registered-range ports). Port 0 is our own inferred send
/// path, never a real querier; well-known ports stay untagged since no
/// defined mDNS querier lives there.
pub(crate) fn is_one_shot_querier(source: &SocketAddr) -> bool {
    source.port() != 5353 && source.port() >= 1024
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
    let requirement = match severity {
        Severity::Error => "MUST NOT",
        _ => "SHOULD NOT",
    };
    // A stub resolver asking from an ephemeral port explains the leak
    // differently than a full mDNS stack, so the finding says which.
    let message = if is_one_shot_querier(&q.source) {
        "unicast-only type on multicast (one-shot querier)".to_string()
    } else {
        "unicast-only type on multicast".to_string()
    };
    out.push(Anomaly {
        kind: AnomalyKind::UnicastQuestion,
        severity,
        service: q.service.clone(),
        record_name: Some(name.clone()),
        rtype: Some(q.rtype),
        rtype_str: Some(q.rtype_str.to_string()),
        rdata: None,
        source: Some(q.source.to_string()),
        message,
        rfc: "RFC 6762 §3",
        requirement,
    });
}

fn check_record(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let name = rec.name.clone();
    let rdata = rec.rdata.clone();
    let src = rec.source.to_string();

    // Non-UTF-8 names: mDNS names MUST be precomposed UTF-8
    // (RFC 6762 §16), so bytes outside UTF-8 come from a non-compliant
    // sender. The display strings are lossy, and a refresh query built
    // from them asks for a name the responder does not own — flag the
    // row so that failure is explained instead of silent.
    if rec.invalid_utf8 {
        out.push(Anomaly {
            kind: AnomalyKind::NonUtf8,
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message: "name contains non-UTF-8 bytes".to_string(),
            rfc: "RFC 6762 §16",
            requirement: "MUST NOT",
        });
    }

    // Unicast-only types on mDNS. Definite violations (Error) require
    // confirmed context: a multicast-destination answer section (RFC 6762
    // §3 defines no NS/SOA delegations for .local). The same type via a
    // unicast reply or a non-answer section is only a Warning pending
    // capture verification — the destination/section is named so users
    // can tell which case they have.
    if let Some(base) = unicast_severity(rec.rtype) {
        let confirmed = rec.dst_is_multicast && rec.section == crate::browse::RecordSection::Answer;
        let context = if !rec.dst_is_multicast {
            "unicast reply".to_string()
        } else {
            format!("{:?} section", rec.section).to_lowercase()
        };
        let (severity, message, requirement) = if confirmed {
            // The overlay has no record columns, so the message keeps the
            // rtype: it names what is not defined for mDNS.
            let message = if base == Severity::Error {
                format!("{} not defined for mDNS", rec.rtype_str)
            } else {
                format!("{} possible unicast leak", rec.rtype_str)
            };
            let requirement = match base {
                Severity::Error => "MUST NOT",
                _ => "SHOULD NOT",
            };
            (base, message, requirement)
        } else {
            (
                Severity::Warning,
                format!(
                    "{} outside multicast answer ({context}); verify",
                    rec.rtype_str
                ),
                "SHOULD NOT",
            )
        };
        out.push(Anomaly {
            kind: AnomalyKind::UnicastLeak,
            severity,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message,
            rfc: "RFC 6762 §3",
            requirement,
        });
    }

    // Cache-flush bit misuse: shared records must not set it. Reverse
    // mapping PTRs are the exception: the RFC treats them as unique (no
    // other host may claim the same address), so the bit is correct there.
    // Enumeration rows share one owner, so the message names the target
    // for the same reason as ttl-mismatch: both renderers show the
    // message verbatim there.
    if rec.rtype == 12 && rec.flush_bit && !is_reverse_ptr(&rec.name) {
        let message = if service_id == ENUMERATION_SERVICE {
            format!(
                "shared PTR record {} has cache-flush bit set",
                rec.rdata.trim_end_matches('.')
            )
        } else {
            "shared record with flush bit set".to_string()
        };
        out.push(Anomaly {
            kind: AnomalyKind::SharedFlush,
            severity: Severity::Error,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message,
            rfc: "RFC 6762 §10.2",
            requirement: "MUST NOT",
        });
    }
    // Unique records SHOULD set the cache-flush bit after uniqueness is
    // established (RFC 6762 §10.2), but only in multicast responses: in
    // legacy unicast responses and in known-answer sections the bit MUST
    // NOT be set, so a missing bit there is not anomalous. Promote to
    // Warning only for confirmed multicast answers; otherwise Info.
    // Scoped to SRV/TXT: omitting the bit on A/AAAA is universal practice
    // across embedded stacks, so flagging it is pure noise (removed).
    if matches!(rec.rtype, 33 | 16) && !rec.flush_bit {
        let confirmed = rec.dst_is_multicast && rec.section == crate::browse::RecordSection::Answer;
        let message = if confirmed {
            "missing flush bit; coherency risk".to_string()
        } else {
            "missing flush bit".to_string()
        };
        out.push(Anomaly {
            kind: AnomalyKind::NoFlush,
            severity: if confirmed {
                Severity::Warning
            } else {
                Severity::Info
            },
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message,
            rfc: "RFC 6762 §10.2",
            requirement: "SHOULD",
        });
    }

    // TTL band. Recommendations per RFC 6762 §10 (SHOULD): 120s base
    // for SRV/A/AAAA, 4500s for PTR/TXT. Values outside [10s, 7200s] risk
    // churn or stale caches.
    if rec.ttl < TTL_LOW {
        out.push(Anomaly {
            kind: AnomalyKind::TtlLow,
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message: format!("TTL {}s, want ~{}s", rec.ttl, expected_base(rec.rtype)),
            rfc: "RFC 6762 §5.2",
            requirement: "SHOULD",
        });
    } else if rec.ttl > TTL_HIGH {
        out.push(Anomaly {
            kind: AnomalyKind::TtlHigh,
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(name),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata),
            source: Some(src),
            message: format!("TTL {}s, want ~{}s", rec.ttl, expected_base(rec.rtype)),
            rfc: "RFC 6762 §5.2",
            requirement: "SHOULD",
        });
    }

    // PTR base TTL: service and enumeration PTRs conventionally use
    // 4500s (75 min). A PTR arriving at 120s/60s was usually re-announced
    // with the generic 120s default instead. TXT is deliberately excluded:
    // stacks (e.g. avahi) publish TXT at 120s by default, so flagging it
    // would be noise, not signal. Reverse-mapping PTRs are excluded too:
    // they are unique with a 120s base, not the 4500s shared convention.
    // This is a SHOULD-level deviation (RFC 6762 §10), not a violation:
    // Info, since 60/120s values are common in real implementations and
    // only increase cache-refresh traffic.
    if rec.rtype == 12 && rec.ttl <= 120 && !is_reverse_ptr(&rec.name) {
        // Enumeration rows all share the owner name, so name the
        // enumerated type: otherwise every finding reads identically.
        // The announcer is appended centrally below.
        // The row shows the TTL and target; the message repeats the
        // observed TTL (the overlay has no record columns) and, for
        // enumeration rows, the target that tells identical rows apart.
        let message = if service_id == ENUMERATION_SERVICE {
            format!(
                "PTR {} TTL {}s; want 4500s",
                rec.rdata.trim_end_matches('.'),
                rec.ttl
            )
        } else {
            format!("PTR base TTL {}s; want 4500s", rec.ttl)
        };
        out.push(Anomaly {
            kind: AnomalyKind::TtlMismatch,
            severity: Severity::Info,
            service: service_id.to_string(),
            record_name: Some(rec.name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rec.rdata.clone()),
            source: Some(rec.source.to_string()),
            message,
            rfc: "RFC 6762 §10",
            requirement: "SHOULD",
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
        // The row shows the payload; the overlay has no record columns,
        // so the message repeats the observed length.
        let payload_len = rec.rdata.len();
        if payload_len > TXT_MAX {
            out.push(Anomaly {
                kind: AnomalyKind::TxtOversize,
                severity: Severity::Warning,
                service: service_id.to_string(),
                record_name: Some(rec.name.clone()),
                rtype: Some(rec.rtype),
                rtype_str: Some(rec.rtype_str.clone()),
                rdata: Some(rec.rdata.clone()),
                source: Some(rec.source.to_string()),
                message: format!("TXT ~{payload_len}B, max {TXT_MAX}B"),
                rfc: "RFC 6762 §17",
                requirement: "SHOULD",
            });
        }
    }
}

fn check_srv_target(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let parts: Vec<&str> = rec.rdata.split_whitespace().collect();
    if parts.len() < 4 {
        out.push(srv_anomaly(service_id, rec, "malformed rdata"));
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
                &format!("bad {field}: want 16-bit"),
            ));
            return;
        }
    }
    let target = parts[3..].join(" ");
    let trimmed = target.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "." {
        out.push(srv_anomaly(service_id, rec, "empty target"));
        return;
    }
    if let Some(reason) = dns_name_problem(trimmed) {
        out.push(srv_anomaly(
            service_id,
            rec,
            &format!("bad target: {reason}"),
        ));
        return;
    }
    if !trimmed.to_ascii_lowercase().ends_with(".local") && !trimmed.eq_ignore_ascii_case("local") {
        // A target outside .local is not inherently invalid: DNS-SD may
        // reference hostnames resolved via unicast DNS. Info, worded as a
        // resolution note rather than a violation.
        out.push(srv_anomaly_info(
            service_id,
            rec,
            "target needs unicast DNS",
        ));
    }
}

fn srv_anomaly_info(service_id: &str, rec: &RawRecord, message: &str) -> Anomaly {
    Anomaly {
        kind: AnomalyKind::SrvTarget,
        severity: Severity::Info,
        service: service_id.to_string(),
        record_name: Some(rec.name.clone()),
        rtype: Some(rec.rtype),
        rtype_str: Some(rec.rtype_str.clone()),
        rdata: Some(rec.rdata.clone()),
        source: Some(rec.source.to_string()),
        message: message.to_string(),
        rfc: "RFC 6763 §12",
        requirement: "MAY",
    }
}

fn srv_anomaly(service_id: &str, rec: &RawRecord, message: &str) -> Anomaly {
    Anomaly {
        kind: AnomalyKind::SrvTarget,
        severity: Severity::Warning,
        service: service_id.to_string(),
        record_name: Some(rec.name.clone()),
        rtype: Some(rec.rtype),
        rtype_str: Some(rec.rtype_str.clone()),
        rdata: Some(rec.rdata.clone()),
        source: Some(rec.source.to_string()),
        message: message.to_string(),
        rfc: "RFC 6763 §12",
        requirement: "MUST",
    }
}

/// Recommended TTL base per type (RFC 6762 §10, SHOULD): 4500s for
/// shared PTR/TXT, 120s for unique SRV/A/AAAA. Used in TTL messages so
/// users see observed vs recommended values.
fn expected_base(rtype: u16) -> u32 {
    match rtype {
        12 | 16 => 4500,
        _ => 120,
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
            // Type label from a live row of the same type, so the
            // finding carries the same row identity the tables mark.
            let rtype_str = svc
                .answers
                .iter()
                .find(|r| r.rtype == rtype)
                .map(|r| r.rtype_str.clone());
            out.push(Anomaly {
                kind: AnomalyKind::TtlUnstable,
                severity: Severity::Warning,
                service: service_id.to_string(),
                record_name: Some(name),
                rtype: Some(rtype),
                rtype_str,
                rdata: None,
                source: None,
                message: format!("mixed TTL bases {sorted:?}"),
                rfc: "RFC 6762 §5.2",
                requirement: "SHOULD",
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
        rec_with(
            name,
            rtype,
            rtype_str,
            rdata,
            ttl,
            flush,
            true,
            crate::browse::RecordSection::Answer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rec_with(
        name: &str,
        rtype: u16,
        rtype_str: &str,
        rdata: &str,
        ttl: u32,
        flush: bool,
        dst_is_multicast: bool,
        section: crate::browse::RecordSection,
    ) -> RawRecord {
        RawRecord {
            name: name.to_string(),
            owner_labels: name
                .trim_end_matches('.')
                .split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect(),
            ptr_target_labels: (rtype == 12).then(|| {
                rdata
                    .trim_end_matches('.')
                    .split('.')
                    .map(|label| label.as_bytes().to_vec())
                    .collect()
            }),
            rtype,
            rtype_str: rtype_str.to_string(),
            flush_bit: flush,
            qu: false,
            invalid_utf8: false,
            ttl,
            rdata: rdata.to_string(),
            wire: Vec::new(),
            source: test_source(),
            iface: String::new(),
            ifindex: 0,
            dst_is_multicast,
            section,
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
        subtypes: &[Vec<u8>],
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
            .find(|a| a.kind == AnomalyKind::UnicastLeak)
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
            .find(|a| a.kind == AnomalyKind::UnicastLeak)
            .expect("expected enumeration SOA leak")
            .clone();
        assert_eq!(item.service, "enumeration");
        assert_eq!(item.severity, Severity::Error);
        assert_eq!(
            item.source.as_deref(),
            Some("192.168.1.2:5353"),
            "finding should name the announcer, got: {:?}",
            item.source
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
    fn non_utf8_name_is_warning_with_rfc_ref() {
        let mut bad = rec(
            "Test._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            120,
            true,
        );
        bad.invalid_utf8 = true;
        let found = analyze_service("Test", "_http._tcp.local", "myhost.local.", &[bad])
            .into_iter()
            .find(|a| a.kind == AnomalyKind::NonUtf8)
            .expect("expected non-utf8-name");
        assert_eq!(found.severity, Severity::Warning);
        assert_eq!(found.rfc, "RFC 6762 §16");
        assert_eq!(found.requirement, "MUST NOT");
        // A clean row with the same shape stays quiet for this kind.
        let clean = vec![rec(
            "Test._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            120,
            true,
        )];
        let found = analyze_service("Test", "_http._tcp.local", "myhost.local.", &clean);
        assert!(found.iter().all(|a| a.kind != AnomalyKind::NonUtf8));
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
            .find(|a| a.kind == AnomalyKind::UnicastQuestion)
            .expect("expected SOA question leak");
        assert_eq!(item.severity, Severity::Error);
        assert_eq!(item.service, "My._http._tcp.local");
        assert_eq!(item.record_name.as_deref(), Some("fritz.box."));
        assert_eq!(item.rtype, Some(6));
        assert_eq!(
            item.source.as_deref(),
            Some("192.168.1.9:5353"),
            "finding should name the querier, got: {:?}",
            item.source
        );
    }

    #[test]
    fn unicast_question_marks_one_shot_querier() {
        // A stub resolver asking from an ephemeral port (§5.1) reads
        // differently than a full mDNS stack on 5353.
        let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, stub)]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastQuestion)
            .expect("expected SOA question leak");
        assert!(
            item.message.contains("one-shot"),
            "stub resolver should be tagged, got: {}",
            item.message
        );
        let found =
            analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, test_source())]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastQuestion)
            .expect("expected SOA question leak");
        assert!(
            !item.message.contains("one-shot"),
            "compliant querier stays untagged, got: {}",
            item.message
        );
        // Well-known ports are no defined mDNS querier either: leave the
        // finding untagged rather than guessing.
        let dns: SocketAddr = "192.168.1.9:53".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, dns)]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastQuestion)
            .expect("expected SOA question leak");
        assert!(
            !item.message.contains("one-shot"),
            "well-known port stays untagged, got: {}",
            item.message
        );
        // Registered-range ports are not full 5353 queriers either, so
        // they read as one-shot by design.
        let other: SocketAddr = "192.168.1.9:5354".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, other)]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastQuestion)
            .expect("expected SOA question leak");
        assert!(
            item.message.contains("one-shot"),
            "non-5353 port reads as one-shot, got: {}",
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
            .find(|a| a.kind == AnomalyKind::UnicastQuestion)
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
            !found.iter().any(|a| a.kind == AnomalyKind::UnicastQuestion),
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
            !found.iter().any(|a| a.kind == AnomalyKind::UnicastQuestion),
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
                .filter(|a| a.kind == AnomalyKind::UnicastQuestion)
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
                .filter(|a| a.kind == AnomalyKind::UnicastQuestion)
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
            .find(|a| a.kind == AnomalyKind::UnicastQuestion)
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
            !found.iter().any(|a| a.kind == AnomalyKind::UnicastQuestion),
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
            found
                .iter()
                .filter(|a| a.kind == AnomalyKind::UnicastLeak)
                .count(),
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
        assert_eq!(
            found
                .iter()
                .filter(|a| a.kind == AnomalyKind::UnicastLeak)
                .count(),
            2
        );
        assert!(found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnicastLeak)
            .all(|a| a.severity == Severity::Error));
    }

    #[test]
    fn unicast_leak_downgraded_outside_multicast_answer() {
        use crate::browse::RecordSection;
        // Same SOA via unicast reply and via authority section: Warning
        // pending verification, naming the context for the user.
        for (mcast, section) in [
            (false, RecordSection::Answer),
            (true, RecordSection::Authority),
            (true, RecordSection::Additional),
        ] {
            let answers = vec![rec_with(
                "host.local.",
                6,
                "SOA",
                "host.local. admin 1 2 3 4 5",
                120,
                false,
                mcast,
                section,
            )];
            let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
            let item = found
                .iter()
                .find(|a| a.kind == AnomalyKind::UnicastLeak)
                .expect("expected leak");
            assert_eq!(
                item.severity,
                Severity::Warning,
                "mcast={mcast} section={section:?}"
            );
            assert!(item.message.contains("; verify"), "got: {}", item.message);
        }
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
            .any(|a| a.kind == AnomalyKind::SharedFlush && a.severity == Severity::Error));
    }

    #[test]
    fn enumeration_shared_flush_names_target() {
        // Enumeration rows share one owner, so the message names the
        // target: both renderers show the message verbatim there.
        let flushed = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_fog._tcp.local.",
            4500,
            true,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&flushed],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        let item = analyze(&snap)
            .iter()
            .find(|a| a.kind == AnomalyKind::SharedFlush && a.service == "enumeration")
            .expect("expected enumeration shared-flush")
            .clone();
        assert!(
            item.message.contains("_fog._tcp.local"),
            "enum finding should name its target, got: {}",
            item.message
        );
        // Service-level PTRs keep the short message: the row names them.
        let found = analyze_service(
            "X",
            "_http._tcp.local",
            "",
            &[rec(
                "_http._tcp.local.",
                12,
                "PTR",
                "X._http._tcp.local.",
                4500,
                true,
            )],
        );
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::SharedFlush)
            .expect("expected shared-flush");
        assert_eq!(item.message, "shared record with flush bit set");
    }

    #[test]
    fn visible_scope_disambiguates_only_foreign_rdata() {
        fn finding(service: &str, rdata: &str) -> Anomaly {
            Anomaly {
                kind: AnomalyKind::SharedFlush,
                severity: Severity::Error,
                service: service.to_string(),
                record_name: Some("_http._tcp.local.".to_string()),
                rtype: Some(12),
                rtype_str: Some("PTR".to_string()),
                rdata: Some(rdata.to_string()),
                source: Some("192.168.1.2:5353".to_string()),
                message: "shared record with flush bit set".to_string(),
                rfc: "RFC 6762 §10.2",
                requirement: "MUST NOT",
            }
        }
        // Same service, same owner and type: the foreign target tells the
        // rows apart, the self-naming one stays short.
        let same = finding("Test._http._tcp.local", "Test._http._tcp.local.");
        let other = finding("Test._http._tcp.local", "Other._http._tcp.local.");
        let counts = identity_counts([&same, &other]);
        assert_eq!(visible_scope(&same, &counts), "PTR _http._tcp.local.");
        assert_eq!(
            visible_scope(&other, &counts),
            "PTR _http._tcp.local. = Other._http._tcp.local."
        );
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
                !found.iter().any(|a| a.kind == AnomalyKind::SharedFlush),
                "reverse PTR {name} should be quiet"
            );
        }
    }

    #[test]
    fn unique_missing_flush_warns_when_confirmed() {
        // Multicast answer without the bit: cache-coherency risk (Warning).
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
            .find(|a| a.kind == AnomalyKind::NoFlush)
            .expect("expected finding");
        assert_eq!(item.severity, Severity::Warning);
        // Same record via unicast reply: Info only (bit MUST NOT be set
        // in legacy unicast, so its absence is not a coherency signal).
        let answers = vec![rec_with(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            120,
            false,
            false,
            crate::browse::RecordSection::Answer,
        )];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::NoFlush)
            .expect("expected finding");
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
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::NoFlush));
    }

    #[test]
    fn mx_leak_is_warning_not_error() {
        let answers = vec![rec("host.local.", 15, "MX", "10 host.local.", 120, false)];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastLeak)
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
                .find(|a| a.kind == AnomalyKind::TtlMismatch)
                .unwrap_or_else(|| panic!("PTR@{ttl} should be flagged"));
            assert_eq!(item.severity, Severity::Info);
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
            .find(|a| a.kind == AnomalyKind::TtlMismatch)
            .expect("expected enumeration ttl-mismatch")
            .clone();
        assert_eq!(
            item.rdata.as_deref(),
            Some("_http._tcp.local."),
            "finding should point at the enumerated type, got: {:?}",
            item.rdata
        );
        assert_eq!(
            item.source.as_deref(),
            Some("192.168.1.2:5353"),
            "finding should name the announcer, got: {:?}",
            item.source
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
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TtlMismatch));
    }

    #[test]
    fn reverse_ptr_with_120_base_is_quiet() {
        // Reverse-mapping PTRs are unique with a 120s base, not the 4500s
        // service PTR convention, so they must not flag ttl-mismatch.
        for name in [
            "1.0.0.127.in-addr.arpa.",
            "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ] {
            let answers = vec![rec(name, 12, "PTR", "myhost.local.", 120, true)];
            let found = analyze_service("X", "_http._tcp.local", "", &answers);
            assert!(
                !found.iter().any(|a| a.kind == AnomalyKind::TtlMismatch),
                "reverse PTR {name} at 120s should be quiet"
            );
        }
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
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TtlMismatch));
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
            .any(|a| a.kind == AnomalyKind::TtlLow || a.kind == AnomalyKind::TtlHigh));
    }

    #[test]
    fn ttl_extremes_flagged() {
        let answers = vec![
            rec("a.local.", 1, "A", "192.168.1.1", 5, true),
            rec("b.local.", 28, "AAAA", "fe80::1", 20000, true),
        ];
        let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
        assert!(found.iter().any(|a| a.kind == AnomalyKind::TtlLow));
        assert!(found.iter().any(|a| a.kind == AnomalyKind::TtlHigh));
    }

    #[test]
    fn ttl_unstable_flags_mixed_bases() {
        let mut r1 = rec("a.local.", 1, "A", "192.168.1.1", 120, true);
        let mut r2 = rec("a.local.", 1, "A", "192.168.1.2", 4500, true);
        // Distinct rdata keeps both live; distinct TTL bases are the signal.
        let _ = (&mut r1, &mut r2);
        let answers = vec![r1, r2];
        let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
        assert!(found.iter().any(|a| a.kind == AnomalyKind::TtlUnstable));
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
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::SrvTarget));
    }

    #[test]
    fn srv_target_outside_local_is_info() {
        let answers = vec![rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 example.com.",
            120,
            true,
        )];
        let found = analyze_service("My", "_http._tcp.local", "example.com.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::SrvTarget)
            .expect("expected srv-target");
        assert_eq!(item.severity, Severity::Info);
        assert!(
            item.message.contains("needs unicast DNS"),
            "got: {}",
            item.message
        );
    }

    #[test]
    fn txt_valueless_empty_and_missing_equals_quiet() {
        let answers = vec![
            rec("X._http._tcp.local.", 16, "TXT", "flag-only", 120, true),
            rec("X._http._tcp.local.", 16, "TXT", "", 120, true),
            rec("X._http._tcp.local.", 16, "TXT", "k=v; bare", 120, true),
        ];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TxtOversize));
    }

    #[test]
    fn txt_oversize_flagged() {
        let big = "k=".to_string() + &"x".repeat(1400);
        let answers = vec![rec("X._http._tcp.local.", 16, "TXT", &big, 120, true)];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        assert!(found.iter().any(|a| a.kind == AnomalyKind::TxtOversize));
    }

    #[test]
    fn reverse_service_type_is_not_a_type_format() {
        // Reverse-mapping names map addresses to hostnames; they are not
        // service types, so a reverse-named service must stay quiet even
        // if one ever reaches the analyzer.
        let found = analyze_service("Android", "local.37.178.168.192.in-addr.arpa", "", &[]);
        assert!(
            !found.iter().any(|a| a.kind == AnomalyKind::TypeFormat),
            "reverse name must not flag, got: {found:?}"
        );
    }

    #[test]
    fn type_format_flags_bad_shape() {
        let answers = vec![];
        let found = analyze_service("X", "http.tcp.local", "", &answers);
        assert!(found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
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
                found.iter().any(|a| a.kind == AnomalyKind::TypeFormat),
                "type {t} should be flagged"
            );
        }
    }

    #[test]
    fn type_format_accepts_valid_subtype_label() {
        let subtypes = vec![b"_printer".to_vec()];
        let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &subtypes);
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
    }

    #[test]
    fn type_format_accepts_subtype_with_arbitrary_octets() {
        let subtypes = vec![b"uuid%group\xff".to_vec()];
        let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &subtypes);
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
    }

    #[test]
    fn type_format_accepts_63_byte_subtype_and_rejects_longer_label() {
        let accepted = vec![b'x'; 63];
        let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &[accepted]);
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));

        let rejected = vec![b'x'; 64];
        let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &[rejected]);
        assert!(found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
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
        assert!(found.iter().any(|a| a.kind == AnomalyKind::SrvTarget));
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
        assert!(found.iter().any(|a| a.kind == AnomalyKind::SrvTarget));
    }

    #[test]
    fn txt_wire_overhead_alone_is_quiet() {
        let mut r = rec("X._http._tcp.local.", 16, "TXT", "k=v", 120, true);
        r.wire = vec![0u8; 1400];
        let found = analyze_service("X", "_http._tcp.local", "", &[r]);
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TxtOversize));
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
                !found.iter().any(|a| a.kind == AnomalyKind::TypeFormat),
                "type {t} should be quiet"
            );
        }
    }

    #[test]
    fn type_format_ignores_label_length_and_underscores() {
        // Neither the RFC's 15-character limit nor inner underscores are
        // enforced by real stacks, so the SHIELD's real type stays quiet.
        let found = analyze_service("SHIELD", "_nv_shield_remote._tcp.local", "", &[]);
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
    }

    #[test]
    fn enumeration_subtype_target_flags_new_kind() {
        let subtype = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_T35._sub._matterd._udp.local.",
            4500,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&subtype],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        let found = analyze(&snap);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::EnumSubtype)
            .expect("expected enum-subtype");
        assert_eq!(item.severity, Severity::Warning);
        // The message names the subtype: enumeration rows all share one
        // scope, so the target tells identical rows apart.
        assert!(
            item.message.contains("_T35._sub._matterd._udp.local"),
            "message should name the subtype, got: {}",
            item.message
        );
        // Valid subtype: no naming-shape finding alongside.
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
        let base = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_http._tcp.local.",
            4500,
            false,
        );
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![&base],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };
        assert!(
            !analyze(&snap)
                .iter()
                .any(|a| a.kind == AnomalyKind::EnumSubtype),
            "base types stay quiet"
        );
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
            .find(|a| a.kind == AnomalyKind::TypeFormat && a.service == "enumeration")
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
        assert!(!analyze(&snap)
            .iter()
            .any(|a| a.kind == AnomalyKind::TypeFormat));
    }

    #[test]
    fn enumeration_subtype_validates_raw_octets_not_lossy_display() {
        let label: &'static [u8] = Box::leak(b"uuid.\xff".to_vec().into_boxed_slice());
        let labels: &'static [simple_dns::Label<'static>] = Box::leak(
            vec![
                simple_dns::Label::new_unchecked(label),
                simple_dns::Label::new_unchecked(&b"_sub"[..]),
                simple_dns::Label::new_unchecked(&b"_http"[..]),
                simple_dns::Label::new_unchecked(&b"_tcp"[..]),
                simple_dns::Label::new_unchecked(&b"local"[..]),
            ]
            .into_boxed_slice(),
        );
        let mut packet = simple_dns::Packet::new_reply(0);
        packet.answers.push(simple_dns::ResourceRecord::new(
            simple_dns::Name::new_unchecked("_services._dns-sd._udp.local."),
            simple_dns::CLASS::IN,
            4500,
            simple_dns::rdata::RData::PTR(simple_dns::Name::new_with_labels(labels).into()),
        ));
        let bytes = packet.build_bytes_vec().unwrap();
        let event = crate::browse::parse_packet(
            &bytes,
            test_source(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251)),
            "br0",
            3,
        )
        .unwrap();
        let subtype = &event.answers[0];
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![subtype],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
        };

        let found = analyze(&snap);
        assert!(found.iter().any(|a| a.kind == AnomalyKind::EnumSubtype));
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
        assert!(found
            .iter()
            .find(|a| a.kind == AnomalyKind::EnumSubtype)
            .unwrap()
            .message
            .contains(r"uuid\x2E\xFF._sub._http._tcp.local"));
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
        assert!(!analyze(&snap)
            .iter()
            .any(|a| a.kind == AnomalyKind::TypeFormat));
    }

    #[test]
    fn enumeration_ptr_with_overlong_subtype_flags_row() {
        let target = format!("{}._sub._http._tcp.local.", "x".repeat(64));
        let enum_rec = rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            &target,
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
            .any(|a| a.kind == AnomalyKind::TypeFormat && a.service == "enumeration"));
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
            found
                .iter()
                .filter(|a| a.kind == AnomalyKind::UnicastLeak)
                .count(),
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
            !found.iter().any(|a| a.kind == AnomalyKind::UnicastLeak),
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
            !found.iter().any(|a| a.kind == AnomalyKind::UnicastLeak),
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
                    .any(|a| a.kind == AnomalyKind::UnicastLeak || a.kind == AnomalyKind::TtlLow)
        );
        // Expired AAAA must not trigger missing-addr either via itself; the
        // hostname here has no SRV target overlap, and goodbye is excluded.
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TtlHigh));
    }
}
