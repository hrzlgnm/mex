// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::app::ENUM_SERVICE;
use crate::browse::{rtype_from_str, RawRecord};

/// Service identity carried by findings: `instance.service_type`, or
/// `enumeration` for enumeration-row answers. Single definition shared
/// by the analyzer and the pane filters so the two cannot drift.
pub const ENUMERATION_SERVICE: &str = "enumeration";

/// Catch-all service identity for out-of-scope sightings whose owner
/// name matches no known service, pending instance or host (e.g. a
/// router's `fritz.box.` SOA). Shown in the metrics overlay and dumps.
pub const UNATTRIBUTED_SERVICE: &str = "unattributed";

/// Types mex accepts both as mDNS answers and as questions: A, NS,
/// CNAME, PTR, HINFO, TXT, AAAA, SRV. HINFO is in because Avahi can
/// publish it (`publish-hinfo=yes`). `browse::RTYPE_NAMES` names exactly
/// these plus NSEC and ANY (a test keeps them in step).
fn is_mdns_common_type(rtype: u16) -> bool {
    matches!(rtype, 1 | 2 | 5 | 12 | 13 | 16 | 28 | 33)
}

/// Record types mex accepts as mDNS answers: the common types plus
/// NSEC (negative answers, RFC 6762 §6.1). Every other type is out of
/// scope: never decoded, never an Answers row, only a sighting behind
/// a finding. Single source of truth for ingest routing, parsing and
/// verdicts.
pub(crate) fn is_mdns_answer_type(rtype: u16) -> bool {
    is_mdns_common_type(rtype) || rtype == 47
}

/// Question types mex accepts: the common types plus ANY (255); NSEC
/// is answer-only (responders send it unasked). Every other QTYPE is
/// out of scope: never a Questions row, only a sighting behind a
/// finding.
pub(crate) fn is_mdns_question_type(rtype: u16) -> bool {
    is_mdns_common_type(rtype) || rtype == 255
}

/// Service identity for a confirmed or pending instance.
pub fn service_id(instance: &str, service_type: &str) -> String {
    format!("{instance}.{service_type}")
}

/// Finding owner for a record or question owned by a hostname (an SRV
/// target): the lowercased name without its root dot. One host backs
/// many services, so host-owned evidence is recorded once, under the
/// host, and every service on it shows it in a `host` block.
pub fn host_id(hostname: &str) -> String {
    hostname.trim_end_matches('.').to_lowercase()
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
    /// Order for picking the worst of several findings (error highest).
    pub fn rank(self) -> u8 {
        severity_rank(self)
    }

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
    UnresolvedSrvTarget,
    UnicastStyleResponse,
    UnsupportedType,
    UnsupportedQuestion,
    NsecInvertedBitmap,
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
    ConflictingAnswers,
}

impl AnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyKind::UnresolvedSrvTarget => "unresolved-srv-target",
            AnomalyKind::UnicastStyleResponse => "unicast-style-response",
            AnomalyKind::UnsupportedType => "unsupported-type",
            AnomalyKind::UnsupportedQuestion => "unsupported-question",
            AnomalyKind::NsecInvertedBitmap => "nsec-inverted-bitmap",
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
            AnomalyKind::ConflictingAnswers => "conflicting-answers",
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

    /// Whether this is a demand-side (observed question) finding.
    pub fn is_question(self) -> bool {
        matches!(self, AnomalyKind::UnsupportedQuestion)
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
    /// Stable machine-readable identifier (`unresolved-srv-target`, `unicast-style-response`, ...).
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
    /// Empty when the cited text carries no RFC 2119 keyword (descriptive
    /// statements and heuristics); views then show the citation alone.
    pub requirement: &'static str,
    /// Response context for record-level findings whose verdict depends
    /// on where and why the record arrived (unicast-style responses):
    /// the DNS section, and the question it most likely answered.
    pub response: Option<ResponseContext>,
    /// Responder groups behind a `conflicting-answers` finding (#247):
    /// sources announcing one identical address set. Empty otherwise.
    pub responders: Vec<Responder>,
}

/// Sources that announce the same address set for a hostname on one
/// link, with the device name behind them when one is known (#246).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Responder {
    pub sources: Vec<String>,
    pub name: Option<String>,
    pub addresses: Vec<String>,
}

/// Where a flagged record sat in its response and what asked for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseContext {
    pub section: crate::browse::RecordSection,
    pub trigger: Option<crate::browse::QueryTrigger>,
}

/// A service slice for analysis: borrows browser state, owns nothing.
pub struct ServiceView<'a> {
    pub instance: &'a str,
    pub service_type: &'a str,
    pub answers: &'a [RawRecord],
    pub subtypes: &'a [Vec<u8>],
    /// Address types (1, 28) the service's own responder denies via NSEC
    /// (#245), each for one host or (`None`) every host of the service:
    /// their lookups are not judged.
    pub denied_address_types: Vec<(u16, Option<String>)>,
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
    /// Out-of-scope records kept only as evidence (never answer rows),
    /// with their attributed service id (or `unattributed`).
    pub sightings: Vec<(String, &'a RawRecord)>,
    /// Live A/AAAA announcements per hostname that a live service points
    /// at (selected host or live SRV target), for `conflicting-answers`.
    pub host_addresses: Vec<HostAddressView<'a>>,
    /// Device names behind responder IPs (#246), for finding messages
    /// only: never part of a finding's identity.
    pub device_names: HashMap<std::net::IpAddr, String>,
}

/// Every A/AAAA record mex holds for one hostname (host id form).
pub struct HostAddressView<'a> {
    pub host: String,
    pub records: Vec<&'a RawRecord>,
}

/// One observed question for analysis: borrows the row, owns the small
/// service id string.
#[derive(Clone, Debug)]
pub struct QuestionView<'a> {
    pub service: String,
    pub name: &'a str,
    pub rtype: u16,
    pub rtype_str: &'a str,
    /// The querier's socket address: port checks (one-shot, our own
    /// port-0 sends) need it as an address.
    pub source: SocketAddr,
    /// The querier as findings name it: `address@iface` (or the IPv6
    /// zone) when the ingress link is known, like
    /// `RawRecord::source_label`, so one address on two links stays two
    /// findings.
    pub source_label: String,
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
    /// Live address families per host: (lowercased host, 1 | 28).
    host_has_addr: &'a HashSet<(String, u16)>,
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

/// Responders on one link announcing different live address sets for one
/// hostname and family (#247). Sources with identical sets form one
/// responder group (one device on several transports); a source with no
/// address of a family is absent from that family. Warning when any
/// disagreeing record claims uniqueness (cache-flush, RFC 6762 §9) or the
/// name is in an mDNS domain (unique there, §8/§9); Info otherwise
/// (e.g. `fritz.box` from a mesh: an observation, not a violation).
fn check_conflicting_answers(
    view: &HostAddressView<'_>,
    names: &HashMap<std::net::IpAddr, String>,
    now: Instant,
    out: &mut Vec<Anomaly>,
) {
    use std::collections::{BTreeMap, BTreeSet};
    // (family, link) -> source -> (label, addresses), plus any flush bit.
    type Sets = BTreeMap<SocketAddr, (String, BTreeSet<String>)>;
    let mut groups: BTreeMap<(u16, String), (Sets, bool)> = BTreeMap::new();
    for rec in &view.records {
        if !matches!(rec.rtype, 1 | 28) || !is_live(rec, now) {
            continue;
        }
        let addr = rec
            .rdata
            .trim()
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| rec.rdata.trim().to_string());
        let (sets, flush) = groups.entry((rec.rtype, rec.iface.clone())).or_default();
        *flush |= rec.flush_bit;
        sets.entry(rec.source)
            .or_insert_with(|| (rec.source_label(), BTreeSet::new()))
            .1
            .insert(addr);
    }
    for ((rtype, iface), (sets, flush)) in groups {
        // Identical sets are one responder (one device, several sources).
        let mut by_set: BTreeMap<BTreeSet<String>, Vec<(SocketAddr, String)>> = BTreeMap::new();
        for (source, (label, addrs)) in sets {
            by_set.entry(addrs).or_default().push((source, label));
        }
        if by_set.len() < 2 {
            continue;
        }
        let responders: Vec<Responder> = by_set
            .into_iter()
            .map(|(addrs, sources)| Responder {
                name: sources
                    .iter()
                    .find_map(|(s, _)| names.get(&s.ip()).cloned()),
                sources: sources.into_iter().map(|(_, label)| label).collect(),
                addresses: addrs.into_iter().collect(),
            })
            .collect();
        let family = if rtype == 1 { "A" } else { "AAAA" };
        let severity = if flush || is_mdns_domain(&view.host) {
            Severity::Warning
        } else {
            Severity::Info
        };
        let link = if iface.is_empty() {
            String::new()
        } else {
            format!(" on {iface}")
        };
        let detail: Vec<String> = responders
            .iter()
            .map(|r| {
                let who = match &r.name {
                    Some(name) => format!("{} ({name})", r.sources.join(", ")),
                    None => r.sources.join(", "),
                };
                format!("{who} → {}", r.addresses.join(", "))
            })
            .collect();
        out.push(Anomaly {
            kind: AnomalyKind::ConflictingAnswers,
            severity,
            service: view.host.clone(),
            record_name: Some(view.host.clone()),
            rtype: Some(rtype),
            rtype_str: Some(family.to_string()),
            rdata: None,
            source: None,
            message: format!(
                "{} responders disagree on {} {family}{link}: {}",
                responders.len(),
                view.host,
                detail.join("; ")
            ),
            rfc: "RFC 6762 §9",
            requirement: "",
            response: None,
            responders,
        });
    }
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

    let mut host_has_addr: HashSet<(String, u16)> = HashSet::new();
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
                    host_has_addr.insert((key, rec.rtype));
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

    for (service, rec) in &snap.sightings {
        if is_live(rec, now) {
            check_record(service, rec, &mut out);
        }
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
                    response: None,
                    responders: Vec::new(),
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
                    requirement: "",
                    response: None,
                    responders: Vec::new(),
                });
            }
        }
    }

    // Observed questions for out-of-scope types: the demand-side twin
    // of an out-of-scope response record. They arrive as sightings
    // (never Questions rows), bounded and refreshed on re-ask.
    for q in &snap.questions {
        check_question(q, &mut out);
    }

    for view in &snap.host_addresses {
        check_conflicting_answers(view, &snap.device_names, now, &mut out);
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

fn dedup(mut items: Vec<Anomaly>) -> Vec<Anomaly> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for a in items.drain(..) {
        // Out-of-scope sightings carry only `rdlength=<n>`: rdata churn
        // (e.g. SOA serial bumps) must not multiply findings, so their
        // identity ignores it.
        let rdata_key = match (a.kind, a.rtype) {
            (AnomalyKind::UnicastStyleResponse | AnomalyKind::UnsupportedType, _) => String::new(),
            (AnomalyKind::EnumSubtype | AnomalyKind::TypeFormat, Some(12))
                if a.service == ENUMERATION_SERVICE =>
            {
                a.message.clone()
            }
            _ => a.rdata.clone().unwrap_or_default(),
        };
        // Questions carry no rdata: tell queriers apart by source, so each
        // querier keeps its own finding and every row can mark.
        // Out-of-scope records have no Answers row to list their
        // responders, so their findings are the only per-source record:
        // keep one per source too.
        // Other answers keep the established behavior (one finding no
        // matter how many sources announce it, the rows show them) —
        // except context-gated kinds, where the same rdata via multicast
        // vs unicast (or answer vs authority) is a different verdict and
        // must not collapse.
        let source_key = match a.kind {
            AnomalyKind::UnsupportedQuestion
            | AnomalyKind::UnicastStyleResponse
            | AnomalyKind::UnsupportedType => a.source.clone().unwrap_or_default(),
            _ => String::new(),
        };
        let context_key = match a.kind {
            AnomalyKind::UnicastStyleResponse
            | AnomalyKind::UnsupportedType
            | AnomalyKind::NoFlush
            | AnomalyKind::UnresolvedSrvTarget => a.message.clone(),
            // One finding per (host, family, link): the analyzer emits
            // one per group, and the message names the link.
            AnomalyKind::ConflictingAnswers => a.message.clone(),
            _ => String::new(),
        };
        // DNS names compare case-insensitively (RFC 6762 §16): a querier
        // re-asking the same name in another case is the same question.
        let name_key = match (a.kind.is_question(), a.record_name.as_deref()) {
            (true, Some(name)) => name.trim_end_matches('.').to_ascii_lowercase(),
            (_, name) => name.unwrap_or_default().to_string(),
        };
        let key = (
            a.kind,
            a.service.clone(),
            name_key,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressQueryOutcome {
    /// The service's own responder denies this type via NSEC (#245).
    Denied,
    NoData,
    NoResponse,
    Inconclusive,
    NotQueried,
    Pending,
    ExpiredAnswer,
}

/// The address types denied for one SRV target: denials for that host
/// and those for every host of the service.
pub(crate) fn denied_for_host(denied: &[(u16, Option<String>)], host: &str) -> Vec<u16> {
    let mut types: Vec<u16> = denied
        .iter()
        .filter(|(_, h)| {
            h.as_deref()
                .is_none_or(|h| h.eq_ignore_ascii_case(host.trim_end_matches('.')))
        })
        .map(|(t, _)| *t)
        .collect();
    types.sort_unstable();
    types.dedup();
    types
}

fn check_unresolved_srv_target(
    svc: &ServiceView,
    service_id: &str,
    evidence: &AddressEvidence<'_>,
    out: &mut Vec<Anomaly>,
) {
    let mut targets = HashSet::new();
    for srv in svc
        .answers
        .iter()
        .filter(|rec| rec.rtype == 33 && is_live(rec, evidence.now))
    {
        if let Some(host) = srv.rdata.split_whitespace().last() {
            if host != "." && targets.insert(host.trim_end_matches('.').to_lowercase()) {
                check_unresolved_target(svc, service_id, host, evidence, out);
            }
        }
    }
}

fn check_unresolved_target(
    svc: &ServiceView,
    service_id: &str,
    host: &str,
    evidence: &AddressEvidence<'_>,
    out: &mut Vec<Anomaly>,
) {
    let host = host.trim_end_matches('.');
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
    // Resolved if the host has a live address in a family this service
    // doesn't deny: a sibling's AAAA says nothing about an IPv4-only one.
    let denied = denied_for_host(&svc.denied_address_types, host);
    let resolved = [1, 28].into_iter().any(|rtype| {
        !denied.contains(&rtype) && evidence.host_has_addr.contains(&(host_key.clone(), rtype))
    });
    if resolved || evidence.pending_hosts.contains(&host_key) {
        return;
    }

    let mut interfaces: Vec<&str> = evidence
        .queries
        .iter()
        .filter(|q| {
            q.service == service_id && q.hostname.trim_end_matches('.').eq_ignore_ascii_case(host)
        })
        .flat_map(|q| q.interfaces.split(", "))
        .collect();
    if interfaces.contains(&"") {
        interfaces.retain(|iface| !iface.is_empty());
        interfaces.extend(
            evidence
                .events
                .iter()
                .flat_map(|event| &event.answers)
                .filter(|rec| rec.name.trim_end_matches('.').eq_ignore_ascii_case(host))
                .map(|rec| rec.iface.as_str()),
        );
        if interfaces.is_empty() {
            interfaces.push("");
        }
    }
    interfaces.sort_unstable();
    interfaces.dedup();
    for interface in interfaces {
        check_unresolved_path(
            srv,
            service_id,
            host,
            interface,
            &denied_for_host(&svc.denied_address_types, host),
            evidence,
            out,
        );
    }
}

fn check_unresolved_path(
    srv: &RawRecord,
    service_id: &str,
    host: &str,
    interface: &str,
    denied: &[u16],
    evidence: &AddressEvidence<'_>,
    out: &mut Vec<Anomaly>,
) {
    // Both families denied by the service itself: nothing to look up.
    if denied.contains(&1) && denied.contains(&28) {
        return;
    }
    let host_key = host.to_lowercase();
    let host_key = host_key.as_str();
    let on_path = |record: &RawRecord| interface.is_empty() || record.iface == interface;
    // RFC 6762 §18.11: responses with a non-zero RCODE MUST be silently
    // ignored, so they never count as evidence (no NXDOMAIN in mDNS;
    // negative answers are NSEC, §6.1).
    let matching_response = |event: &crate::browse::Event, at: Instant| {
        if event.rcode != Some(0) || event.received_at < at {
            return false;
        }
        let rows: Vec<_> = event.answers.iter().chain(&event.questions).collect();
        rows.is_empty()
            || rows.iter().any(|rec| {
                on_path(rec) && rec.name.trim_end_matches('.').eq_ignore_ascii_case(host)
            })
    };
    let outcomes: Vec<_> = [1, 28]
        .into_iter()
        .map(|rtype| {
            if denied.contains(&rtype) {
                return (rtype, AddressQueryOutcome::Denied, None);
            }
            let query = evidence.queries.iter().filter(|query| {
                query.service == service_id
                    && query
                        .hostname
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(host)
                    && query.rtype == rtype
                    && (query.interfaces.is_empty()
                        || query.interfaces.split(", ").any(|path| path == interface))
            });
            let Some(query) = query.max_by_key(|query| query.transmitted_at) else {
                return (rtype, AddressQueryOutcome::NotQueried, None);
            };
            if let Some(record) = evidence.events.iter().find_map(|event| {
                event.answers.iter().find(|record| {
                    event.rcode == Some(0)
                        && on_path(record)
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
                .host_addr_latest
                .get(&(host_key.to_string(), rtype))
                .is_some_and(|at| *at > query.transmitted_at)
            {
                return (rtype, AddressQueryOutcome::ExpiredAnswer, None);
            }
            if evidence
                .events
                .iter()
                .any(|event| matching_response(event, query.transmitted_at))
            {
                return (rtype, AddressQueryOutcome::Inconclusive, None);
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

    if outcomes
        .iter()
        .any(|(_, outcome, _)| matches!(outcome, AddressQueryOutcome::Pending))
        || !outcomes.iter().any(|(_, outcome, _)| {
            matches!(
                outcome,
                AddressQueryOutcome::NoData
                    | AddressQueryOutcome::NoResponse
                    | AddressQueryOutcome::Inconclusive
                    | AddressQueryOutcome::ExpiredAnswer
            )
        })
    {
        return;
    }

    let (a_outcome, a_context) = (&outcomes[0].1, &outcomes[0].2);
    let (aaaa_outcome, aaaa_context) = (&outcomes[1].1, &outcomes[1].2);
    // The only explicit negative in mDNS is an NSEC denying both address
    // types (RFC 6762 §6.1); a type the service itself denies counts as
    // denied too.
    let negative = |o: &AddressQueryOutcome| {
        matches!(o, AddressQueryOutcome::NoData | AddressQueryOutcome::Denied)
    };
    let explicit_negative = negative(a_outcome) && negative(aaaa_outcome);
    let outcome_text = |outcome: AddressQueryOutcome| match outcome {
        AddressQueryOutcome::Denied => "denied by NSEC",
        AddressQueryOutcome::NoData => "NODATA",
        AddressQueryOutcome::NoResponse => "no response",
        AddressQueryOutcome::Inconclusive => "unattributed mDNS response",
        AddressQueryOutcome::NotQueried => "not queried",
        AddressQueryOutcome::Pending => "pending",
        AddressQueryOutcome::ExpiredAnswer => "answered; address expired",
    };
    let source_context = a_context.as_ref().or(aaaa_context.as_ref());
    let record_name = Some(srv.name.clone());
    let rdata = Some(srv.rdata.clone());
    let source = source_context.map(|(source, _)| source.clone());
    let query_interfaces = if interface.is_empty() {
        String::new()
    } else {
        format!(" across mDNS interfaces {interface}")
    };
    let response_interface = source_context
        .as_ref()
        .filter(|(_, iface)| !iface.is_empty())
        .map(|(_, iface)| format!("; response on {iface}"))
        .unwrap_or_default();
    let unicast_note = if !crate::browse::is_local_name(host_key) {
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
        rfc: "RFC 6762 §6.1",
        requirement: "",
        response: None,
        responders: Vec::new(),
    });
}

fn check_type_format(svc: &ServiceView, service_id: &str, out: &mut Vec<Anomaly>) {
    let st = svc.service_type.trim_end_matches('.');
    if st.eq_ignore_ascii_case(ENUM_SERVICE) {
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
            response: None,
            responders: Vec::new(),
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
            if !crate::browse::is_proto_label(proto) {
                return Some("protocol must be _tcp or _udp".to_string());
            }
            if !local.eq_ignore_ascii_case(b"local") {
                return Some("must end in .local (RFC 6762 §3)".to_string());
            }
            None
        }
        [sub, sub_kw, svc, proto, local] => {
            if let Some(reason) = subtype_problem(sub) {
                return Some(format!("subtype {reason}"));
            }
            if !crate::browse::is_sub_label(sub_kw) {
                return Some(
                    "expected _service._tcp.local or subtype._sub._service._tcp.local".to_string(),
                );
            }
            if let Some(reason) = service_label_problem(svc) {
                return Some(reason);
            }
            if !crate::browse::is_proto_label(proto) {
                return Some("protocol must be _tcp or _udp".to_string());
            }
            if !local.eq_ignore_ascii_case(b"local") {
                return Some("must end in .local (RFC 6762 §3)".to_string());
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
    matches!(labels, [_, sub_kw, _, _, _] if crate::browse::is_sub_label(sub_kw))
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
                response: None,
                responders: Vec::new(),
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

/// Session-wide finding list with question findings collapsed: one
/// observed question files on every service whose instance, type or
/// host name it asks for (e.g. `fritz.box A` lands on each service whose
/// SRV target is `fritz.box`), so the analyzer emits one finding per
/// such service. Per-service panes need that fan-out; global views
/// (metrics overlay, state dump) list the question once instead. Each
/// kept finding comes with the other services it also filed on, in
/// order. Non-question findings pass through untouched.
pub(crate) fn collapse_questions(found: &[Anomaly]) -> Vec<(&Anomaly, Vec<&str>)> {
    type Key<'a> = (AnomalyKind, String, Option<u16>, Option<&'a str>, &'a str);
    let mut out: Vec<(&Anomaly, Vec<&str>)> = Vec::with_capacity(found.len());
    let mut seen: HashMap<Key<'_>, usize> = HashMap::new();
    for a in found {
        if !a.kind.is_question() {
            out.push((a, Vec::new()));
            continue;
        }
        let key = (
            a.kind,
            a.record_name
                .as_deref()
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_lowercase(),
            a.rtype,
            a.source.as_deref(),
            a.message.as_str(),
        );
        match seen.get(&key) {
            Some(&i) => out[i].1.push(a.service.as_str()),
            None => {
                seen.insert(key, out.len());
                out.push((a, Vec::new()));
            }
        }
    }
    out
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

/// Display scope for a finding, shared by the inline finding rows and
/// the metrics overlay: empty for service-level findings and enumeration
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
        && record_name.is_some_and(|n| n.trim_end_matches('.').eq_ignore_ascii_case(ENUM_SERVICE))
}

/// Whether a PTR owner name is a reverse-mapping name. Those PTRs are
/// unique (one address, one owner), unlike service/enumeration PTRs.
pub(crate) fn is_reverse_ptr(name: &str) -> bool {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    lower.ends_with(".in-addr.arpa") || lower.ends_with(".ip6.arpa")
}

/// Verdict for a unicast-style record (SOA or ANY) in an mDNS response,
/// by type, section and owner domain: `(severity, reason, rfc,
/// requirement)`. `None` for every other type: in-scope types raise no
/// such finding, and the remaining out-of-scope types get
/// `unsupported_type_verdict`.
///
/// * ANY is a QTYPE and never an RR type (RFC 1035 §3.2.3): Error.
/// * SOA in the Authority section is a unicast-style negative answer;
///   mDNS denies records with NSEC (§6.1): Warning. §6.1's MUST is about
///   sending the NSEC, which a per-record check cannot see, so no
///   requirement level is claimed.
/// * SOA elsewhere: for mDNS-domain names §12 states there is none
///   (Warning, no 2119 keyword); for other names (a router answering for
///   its unicast zone, e.g. `fritz.box`, which §3 allows to be asked)
///   it is real zone data: Info.
///
/// Known answers ride in queries, not responses, so they are capped at
/// Info.
pub(crate) fn unicast_style_verdict(
    rtype: u16,
    section: crate::browse::RecordSection,
    mdns_name: bool,
) -> Option<(Severity, &'static str, &'static str, &'static str)> {
    use crate::browse::RecordSection;
    let (severity, reason, rfc) = match rtype {
        255 => (
            Severity::Error,
            "a query type, never a record type",
            "RFC 1035 §3.2.3",
        ),
        6 if section == RecordSection::Authority => (
            Severity::Warning,
            "mDNS uses NSEC for negative answers",
            "RFC 6762 §6.1",
        ),
        6 if mdns_name => (Severity::Warning, "mDNS zones have no SOA", "RFC 6762 §12"),
        6 => (Severity::Info, "unicast zone data", "RFC 6762 §3"),
        _ => return None,
    };
    let severity = if section == RecordSection::KnownAnswer {
        Severity::Info
    } else {
        severity
    };
    Some((severity, reason, rfc, ""))
}

/// Verdict for an out-of-scope record type that is not unicast-style
/// (MX, unknown `TYPEnn`, …): Warning, capped at Info for known answers.
/// RFC 6763 §12 lists the records DNS-SD over mDNS involves; the rest
/// is outside mex's scope, so no requirement level is claimed.
/// `None` for in-scope types and for SOA/ANY, which
/// `unicast_style_verdict` covers.
pub(crate) fn unsupported_type_verdict(
    rtype: u16,
    section: crate::browse::RecordSection,
) -> Option<Severity> {
    if is_mdns_answer_type(rtype) || matches!(rtype, 6 | 255) {
        return None;
    }
    Some(if section == crate::browse::RecordSection::KnownAnswer {
        Severity::Info
    } else {
        Severity::Warning
    })
}

/// Section name as shown in finding messages (`Authority section`).
fn section_title(section: crate::browse::RecordSection) -> &'static str {
    use crate::browse::RecordSection;
    match section {
        RecordSection::Answer => "Answer",
        RecordSection::Authority => "Authority",
        RecordSection::Additional => "Additional",
        RecordSection::KnownAnswer => "Known-Answer",
        RecordSection::Question => "Question",
    }
}

/// Verdict for observed *questions* outside `is_mdns_question_type`:
/// informational only, `(reason, rfc)`. RFC 6762 §3 requires every
/// query for a `.local` name to go to the mDNS multicast group, so
/// asking is compliant; it just asks for something mex does not
/// support. SOA gets §12's reason: no such record exists in mDNS.
pub(crate) fn unsupported_question_verdict(rtype: u16) -> Option<(&'static str, &'static str)> {
    match rtype {
        _ if is_mdns_question_type(rtype) => None,
        6 => Some((
            "asks for a type that does not exist in mDNS",
            "RFC 6762 §12",
        )),
        _ => Some(("asks for a type outside mDNS scope", "RFC 6763 §12")),
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

/// One observed question for a type outside `is_mdns_question_type`:
/// the demand-side twin of `unicast-style-response` / `unsupported-type`.
/// Port 0 can never be a real querier, so our own inferred sends stay
/// quiet here, not just in the UI.
fn check_question(q: &QuestionView, out: &mut Vec<Anomaly>) {
    if q.source.port() == 0 {
        return;
    }
    // A stub resolver asking from an ephemeral port explains the question
    // differently than a full mDNS stack, so each finding says which.
    let one_shot = if is_one_shot_querier(&q.source) {
        " (one-shot querier)"
    } else {
        ""
    };
    let finding = |kind, severity, message: String, rfc, requirement| Anomaly {
        kind,
        severity,
        service: q.service.clone(),
        record_name: Some(q.name.to_string()),
        rtype: Some(q.rtype),
        rtype_str: Some(q.rtype_str.to_string()),
        rdata: None,
        source: Some(q.source_label.clone()),
        message,
        rfc,
        requirement,
        response: None,
        responders: Vec::new(),
    };
    // Questions for names outside the mDNS domains are not flagged: the
    // only ones filed here ask for a service's SRV target (e.g.
    // `fritz.box`), which DNS-SD browsers (mex, avahi) legitimately
    // resolve over mDNS on the link that advertised it (RFC 6762 §3
    // allows it). The §13 fail-over case, global names typed by a user,
    // never matches a service and so never reaches the analyzer.
    if let Some((reason, rfc)) = unsupported_question_verdict(q.rtype) {
        out.push(finding(
            AnomalyKind::UnsupportedQuestion,
            Severity::Info,
            format!("{reason}{one_shot}"),
            rfc,
            "",
        ));
    }
}

/// Whether a name lives in a Multicast DNS domain: `.local.` (RFC 6762
/// §3) or the IPv4/IPv6 link-local reverse mapping zones (§4), where
/// queries MUST go to the mDNS multicast group.
pub(crate) fn is_mdns_domain(name: &str) -> bool {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    [
        "local",
        "254.169.in-addr.arpa",
        "8.e.f.ip6.arpa",
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
    ]
    .iter()
    .any(|zone| lower == *zone || lower.ends_with(&format!(".{zone}")))
}

/// Per-record checks. A known answer rides in a query (RFC 6762 §7.1):
/// it is the querier's belief, not a responder's claim, so every
/// finding it raises is capped at Info, and its TTL (the remaining one)
/// gets no TTL checks at all.
fn check_record(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let first = out.len();
    check_record_claims(service_id, rec, out);
    if rec.section == crate::browse::RecordSection::KnownAnswer {
        for a in &mut out[first..] {
            a.severity = Severity::Info;
        }
    }
}

fn check_record_claims(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
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
            response: None,
            responders: Vec::new(),
        });
    }

    // Out-of-scope records: one finding per record, never a row.
    // Unicast-style ones (SOA/ANY) get a verdict by type, section and
    // owner domain (see `unicast_style_verdict`); every other
    // out-of-scope type gets `unsupported_type_verdict`. Unicast replies
    // to 5353 are mDNS responses too (RFC 6762 §6.7), so the destination
    // only shows in the message. The section and the question that most
    // likely triggered the response travel in `response`, so dumps can
    // sort these from real answers and from replies to our own queries.
    let section = section_title(rec.section);
    let unicast = if rec.dst_is_multicast {
        ""
    } else {
        "; unicast reply"
    };
    // These findings stand in for the Answers rows out-of-scope records
    // no longer get, so they name the source like a row does
    // (`address@iface`), one finding per source and link.
    let response_finding = |kind, severity, message, rfc, requirement| Anomaly {
        kind,
        severity,
        service: service_id.to_string(),
        record_name: Some(name.clone()),
        rtype: Some(rec.rtype),
        rtype_str: Some(rec.rtype_str.clone()),
        rdata: Some(rdata.clone()),
        source: Some(rec.source_label()),
        message,
        rfc,
        requirement,
        response: Some(ResponseContext {
            section: rec.section,
            trigger: rec.trigger.clone(),
        }),
        responders: Vec::new(),
    };
    if let Some((severity, reason, rfc, requirement)) =
        unicast_style_verdict(rec.rtype, rec.section, is_mdns_domain(&rec.name))
    {
        let message = if rec.rtype == 255 {
            format!("ANY record in {section} section ({reason}){unicast}")
        } else {
            format!(
                "unicast DNS-style answer over mDNS: {} in {section} section ({reason}){unicast}",
                rec.rtype_str
            )
        };
        out.push(response_finding(
            AnomalyKind::UnicastStyleResponse,
            severity,
            message,
            rfc,
            requirement,
        ));
    }
    if let Some(severity) = unsupported_type_verdict(rec.rtype, rec.section) {
        out.push(response_finding(
            AnomalyKind::UnsupportedType,
            severity,
            format!(
                "record type {} is outside mDNS scope, in {section} section{unicast}",
                rec.rtype_str
            ),
            "RFC 6763 §12",
            "",
        ));
    }

    // Older python-zeroconf: an NSEC owned by the instance name whose
    // bitmap lists only the *missing* address types. RFC 6762 §6.1 has
    // the bitmap list the types that exist, so read literally it claims
    // the instance has only A/AAAA, contradicting its SRV/TXT. mex treats
    // it as a denial (#245); flag the inversion as an observation.
    if rec.rtype == 47
        && rec
            .name
            .trim_end_matches('.')
            .eq_ignore_ascii_case(service_id)
    {
        let (address, other) = crate::browse::nsec_address_types(&rec.rdata);
        if !address.is_empty() && !other {
            out.push(Anomaly {
                kind: AnomalyKind::NsecInvertedBitmap,
                severity: Severity::Info,
                service: service_id.to_string(),
                record_name: Some(name.clone()),
                rtype: Some(rec.rtype),
                rtype_str: Some(rec.rtype_str.clone()),
                rdata: Some(rdata.clone()),
                source: Some(src.clone()),
                message: "instance NSEC lists only missing address types (inverted bitmap)"
                    .to_string(),
                rfc: "RFC 6762 §6.1",
                requirement: "",
                response: None,
                responders: Vec::new(),
            });
        }
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
            response: None,
            responders: Vec::new(),
        });
    }
    // Unique records MUST carry the cache-flush bit in responses to port
    // 5353 (RFC 6762 §10.2), answer and additional sections alike. The
    // bit MUST NOT be set only in legacy unicast responses (to a querier
    // port other than 5353, §6.7), and known answers ride in queries, so
    // a missing bit there is not anomalous. mex only listens on 5353, so
    // every response it receives — multicast or a unicast reply to its
    // QU questions — is a non-legacy one: Warning with the MUST.
    // Authority/known-answer rows stay Info with no requirement level.
    // Scoped to SRV/TXT: omitting the bit on A/AAAA is universal practice
    // across embedded stacks, so flagging it is pure noise (removed).
    if matches!(rec.rtype, 33 | 16) && !rec.flush_bit {
        let confirmed = matches!(
            rec.section,
            crate::browse::RecordSection::Answer | crate::browse::RecordSection::Additional
        );
        let message = match (confirmed, rec.dst_is_multicast) {
            (true, true) => "missing flush bit; coherency risk".to_string(),
            (true, false) => "missing flush bit; coherency risk (unicast reply)".to_string(),
            (false, _) => "missing flush bit".to_string(),
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
            requirement: if confirmed { "MUST" } else { "" },
            response: None,
            responders: Vec::new(),
        });
    }

    // A known answer carries the querier's *remaining* TTL (RFC 6762
    // §7.1), not the responder's: TTL checks say nothing about it.
    let ttl_is_remaining = rec.section == crate::browse::RecordSection::KnownAnswer;

    // TTL band. Recommendations per RFC 6762 §10 (SHOULD): 120s base
    // for SRV/A/AAAA, 4500s for PTR/TXT. Values outside [10s, 7200s] risk
    // churn or stale caches.
    if ttl_is_remaining {
        // No TTL verdicts for known answers.
    } else if rec.ttl < TTL_LOW {
        out.push(Anomaly {
            kind: AnomalyKind::TtlLow,
            severity: Severity::Warning,
            service: service_id.to_string(),
            record_name: Some(name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rdata.clone()),
            source: Some(src.clone()),
            message: format!(
                "TTL {}s, want ~{}s",
                rec.ttl,
                expected_base(rec.rtype, &rec.name)
            ),
            rfc: "RFC 6762 §10",
            requirement: "SHOULD",
            response: None,
            responders: Vec::new(),
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
            message: format!(
                "TTL {}s, want ~{}s",
                rec.ttl,
                expected_base(rec.rtype, &rec.name)
            ),
            rfc: "RFC 6762 §10",
            requirement: "SHOULD",
            response: None,
            responders: Vec::new(),
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
    if !ttl_is_remaining && rec.rtype == 12 && rec.ttl <= 120 && !is_reverse_ptr(&rec.name) {
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
            response: None,
            responders: Vec::new(),
        });
    }

    // SRV target shape. Port is never checked: port 0 is valid.
    if rec.rtype == 33 {
        check_srv_target(service_id, rec, out);
    }

    // TXT size only: RFC 6763 §6.2 sizes the TXT record data, so measure
    // RDLENGTH (length bytes included), not the full wire record (owner
    // name + header) nor the lossy `; `-joined display string. Valueless
    // keys, keys without `=`, and empty payloads are all valid and never
    // flagged.
    if rec.rtype == 16 {
        // The row shows the payload; the overlay has no record columns,
        // so the message repeats the observed length. Rows without a
        // wire encoding fall back to the display length.
        let payload_len = crate::browse::wire_rdata_len(&rec.wire).unwrap_or(rec.rdata.len());
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
                message: format!("TXT {payload_len}B, max {TXT_MAX}B"),
                rfc: "RFC 6763 §6.2",
                requirement: "SHOULD NOT",
                response: None,
                responders: Vec::new(),
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
    // RFC 2782: a target of "." means the service is decidedly not
    // available at this name. Valid, so only worth a note.
    if target.trim() == "." {
        out.push(srv_anomaly_info(
            service_id,
            rec,
            "target \".\": service not available at this name",
        ));
        return;
    }
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
    if !crate::browse::is_local_name(trimmed) {
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
        rfc: "RFC 2782",
        requirement: "",
        response: None,
        responders: Vec::new(),
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
        rfc: "RFC 2782",
        requirement: "MUST",
        response: None,
        responders: Vec::new(),
    }
}

/// Recommended TTL base per type (RFC 6762 §10, SHOULD): 120s for
/// records whose name or rdata is a host name (SRV, A/AAAA, reverse
/// mapping PTR), 4500s for the rest (service PTR, TXT). Used in TTL
/// messages so users see observed vs recommended values.
fn expected_base(rtype: u16, name: &str) -> u32 {
    match rtype {
        12 if is_reverse_ptr(name) => 120,
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
                rfc: "RFC 6762 §10",
                requirement: "",
                response: None,
                responders: Vec::new(),
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
            trigger: None,
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
        _hostname: &str,
        answers: &[RawRecord],
        subtypes: &[Vec<u8>],
    ) -> Vec<Anomaly> {
        let services = vec![ServiceView {
            instance,
            service_type,
            answers,
            subtypes,
            denied_address_types: Vec::new(),
        }];
        let snap = Snapshot {
            services,
            enum_answers: Vec::new(),
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
        };
        analyze(&snap)
    }

    #[test]
    fn denied_types_are_scoped_to_their_host() {
        // An RFC denial for host X must not suppress the lookup for an
        // alternate SRV target Y; a legacy denial (None) covers every host.
        let denied = vec![(28, Some("knulp.local".to_string())), (1, None)];
        assert_eq!(denied_for_host(&denied, "knulp.local."), vec![1, 28]);
        assert_eq!(denied_for_host(&denied, "KNULP.local"), vec![1, 28]);
        assert_eq!(denied_for_host(&denied, "other.local"), vec![1]);
        assert!(denied_for_host(&[], "knulp.local").is_empty());
    }

    #[test]
    fn unicast_style_verdict_by_type_section_and_domain() {
        use super::unicast_style_verdict as v;
        use crate::browse::RecordSection::*;
        let sev = |rtype, section, mdns| v(rtype, section, mdns).map(|(s, _, rfc, _)| (s, rfc));
        // ANY is never an RR type, wherever it sits.
        assert_eq!(
            sev(255, Answer, true),
            Some((Severity::Error, "RFC 1035 §3.2.3"))
        );
        // SOA in Authority is a unicast-style negative answer (§6.1 NSEC),
        // whatever the owner domain.
        for mdns in [true, false] {
            assert_eq!(
                sev(6, Authority, mdns),
                Some((Severity::Warning, "RFC 6762 §6.1"))
            );
        }
        // SOA as an answer: none exist in mDNS zones; real data elsewhere.
        assert_eq!(
            sev(6, Answer, true),
            Some((Severity::Warning, "RFC 6762 §12"))
        );
        assert_eq!(sev(6, Answer, false), Some((Severity::Info, "RFC 6762 §3")));
        // Known answers ride in queries: never above Info.
        assert_eq!(
            sev(255, KnownAnswer, true).map(|(s, _)| s),
            Some(Severity::Info)
        );
        // No requirement level is ever claimed.
        assert!([6, 255]
            .into_iter()
            .all(|t| v(t, Authority, true).is_some_and(|(_, _, _, req)| req.is_empty())));
        // In-scope types (NS included) and other out-of-scope types
        // (MX: `unsupported_type_verdict`) get no unicast-style verdict.
        for rtype in [1, 2, 5, 12, 13, 15, 16, 28, 33, 47] {
            assert_eq!(v(rtype, Answer, true), None, "type {rtype}");
        }
    }

    #[test]
    fn unsupported_type_verdict_covers_only_the_rest() {
        use super::unsupported_type_verdict as v;
        use crate::browse::RecordSection::*;
        for rtype in [1, 2, 5, 6, 12, 13, 16, 28, 33, 47, 255] {
            assert_eq!(v(rtype, Answer), None, "type {rtype}");
        }
        assert_eq!(v(15, Answer), Some(Severity::Warning));
        assert_eq!(v(65, Additional), Some(Severity::Warning));
        assert_eq!(v(15, KnownAnswer), Some(Severity::Info));
    }

    #[test]
    fn findings_cite_the_rfc_text_that_covers_them() {
        let answers = vec![
            rec("host.local.", 6, "SOA", "a b 1 2 3 4 5", 4500, false),
            rec("host.local.", 255, "ANY", "", 120, false),
            rec(
                "My._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 host.local.",
                3,
                false,
            ),
            rec(
                "My._http._tcp.local.",
                16,
                "TXT",
                &"k=v".repeat(500),
                4500,
                true,
            ),
        ];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let cite = |kind: AnomalyKind, rtype: u16| {
            found
                .iter()
                .find(|a| a.kind == kind && a.rtype == Some(rtype))
                .map(|a| (a.rfc, a.requirement))
                .unwrap_or_else(|| panic!("missing {kind} for type {rtype}"))
        };
        // §12 states NS/SOA don't exist in mDNS without a 2119 keyword.
        assert_eq!(
            cite(AnomalyKind::UnicastStyleResponse, 6),
            ("RFC 6762 §12", "")
        );
        // ANY is a QTYPE, never an RR type; RFC 1035 has no 2119 keyword.
        assert_eq!(
            cite(AnomalyKind::UnicastStyleResponse, 255),
            ("RFC 1035 §3.2.3", "")
        );
        // §10.2: the host MUST set the flush bit on unique RRSet members.
        assert_eq!(cite(AnomalyKind::NoFlush, 33), ("RFC 6762 §10.2", "MUST"));
        // TTL recommendations live in §10, not §5.2 query scheduling.
        assert_eq!(cite(AnomalyKind::TtlLow, 33), ("RFC 6762 §10", "SHOULD"));
        // TXT > 1300 bytes is NOT RECOMMENDED (RFC 6763 §6.2).
        assert_eq!(
            cite(AnomalyKind::TxtOversize, 16),
            ("RFC 6763 §6.2", "SHOULD NOT")
        );
    }

    #[test]
    fn unicast_style_response_soa_for_global_name_is_info() {
        // A router answering a query for its own unicast zone over mDNS:
        // §12 does not cover fritz.box, so this is an observation only.
        let answers = vec![
            rec("fritz.box.", 2, "NS", "fritz.box.", 10, false),
            rec("fritz.box.", 6, "TYPE6", "rdlength=49", 10, false),
        ];
        let found = analyze_service("Fritzel", "_fbox._tcp.local", "fritz.box.", &answers);
        let found_rows: Vec<_> = found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnicastStyleResponse)
            .collect();
        assert_eq!(found_rows.len(), 1);
        for item in found_rows {
            assert_eq!(item.rtype, Some(6));
            assert_eq!(item.severity, Severity::Info);
            assert_eq!(item.rfc, "RFC 6762 §3");
            assert_eq!(item.requirement, "");
            assert!(
                item.message.contains("in Answer section"),
                "{}",
                item.message
            );
        }
        // The same SOA owned by a .local name: mDNS zones have none (§12).
        let answers = vec![rec("host.local.", 6, "TYPE6", "rdlength=22", 120, false)];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
            .expect("expected SOA unicast-style response");
        assert_eq!(item.severity, Severity::Warning);
        assert_eq!(item.rfc, "RFC 6762 §12");
    }

    #[test]
    fn unicast_style_response_flags_any_as_error() {
        let answers = vec![rec("host.local.", 255, "ANY", "", 120, false)];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
            .expect("expected ANY unicast-style response");
        assert_eq!(item.severity, Severity::Error);
    }

    #[test]
    fn enumeration_soa_response_names_service_and_source() {
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
        };
        let item = analyze(&snap)
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
            .expect("expected enumeration SOA unicast-style response")
            .clone();
        assert_eq!(item.service, "enumeration");
        assert_eq!(item.severity, Severity::Warning);
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
        let rtype_str: &'static str = Box::leak(crate::browse::rtype_label(rtype).into_boxed_str());
        let name: &'static str = Box::leak(name.to_string().into_boxed_str());
        QuestionView {
            service: service.to_string(),
            name,
            rtype,
            rtype_str,
            source,
            source_label: source.to_string(),
        }
    }

    fn analyze_questions(questions: &[QuestionView]) -> Vec<Anomaly> {
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: Vec::new(),
            pending_hosts: HashSet::new(),
            questions: questions.to_vec(),
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
    fn unicast_question_flags_soa_with_querier() {
        let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, querier)]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .expect("expected SOA question finding");
        // RFC 6762 §3 requires .local queries on multicast: asking is
        // compliant, the record just cannot exist (§12).
        assert_eq!(item.severity, Severity::Info);
        assert_eq!((item.rfc, item.requirement), ("RFC 6762 §12", ""));
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
            .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .expect("expected SOA unicast question");
        assert!(
            item.message.contains("one-shot"),
            "stub resolver should be tagged, got: {}",
            item.message
        );
        let found =
            analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, test_source())]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .expect("expected SOA unicast question");
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
            .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .expect("expected SOA unicast question");
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
            .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .expect("expected SOA unicast question");
        assert!(
            item.message.contains("one-shot"),
            "non-5353 port reads as one-shot, got: {}",
            item.message
        );
    }

    #[test]
    fn unsupported_question_mx_and_nsec_are_info() {
        // MX is outside mex's mDNS scope; NSEC is answer-only (responders
        // send it unasked as a negative answer, RFC 6762 §6.1).
        for rtype in [15, 47] {
            let found = analyze_questions(&[qview(
                "My._http._tcp.local",
                "mail.local.",
                rtype,
                test_source(),
            )]);
            let item = found
                .iter()
                .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
                .unwrap_or_else(|| panic!("expected a finding for type {rtype}"));
            assert_eq!(item.severity, Severity::Info);
            assert_eq!(item.rfc, "RFC 6763 §12");
        }
    }

    #[test]
    fn questions_for_global_names_are_not_flagged_as_such() {
        // Resolving a global SRV target over mDNS is ordinary DNS-SD: an
        // A query for fritz.box stays quiet.
        let found =
            analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 1, test_source())]);
        assert!(found.is_empty(), "got: {found:?}");
        // SOA for it only flags the unicast-only type.
        let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, stub)]);
        let kinds: Vec<_> = found.iter().map(|a| a.kind.as_str()).collect();
        assert_eq!(kinds, ["unsupported-question"]);
        assert!(found[0].message.ends_with("(one-shot querier)"));
    }

    #[test]
    fn mdns_domains_cover_local_and_link_local_reverse_zones() {
        for name in [
            "host.local.",
            "HOST.LOCAL",
            "local.",
            "_http._tcp.local.",
            "10.1.254.169.in-addr.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
            "b.e.f.ip6.arpa.",
        ] {
            assert!(is_mdns_domain(name), "{name} is an mDNS domain");
        }
        // Lookalikes outside the zones are global.
        for name in ["notlocal.", "10.1.168.192.in-addr.arpa.", "c.e.f.ip6.arpa."] {
            assert!(!is_mdns_domain(name), "{name} is not an mDNS domain");
        }
    }

    #[test]
    fn unicast_question_self_and_per_querier() {
        let zelf: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "host.local.", 6, zelf)]);
        assert!(found.is_empty(), "own sends stay quiet, got: {found:?}");
        let a: SocketAddr = "192.168.1.9:5353".parse().unwrap();
        let b: SocketAddr = "192.168.1.10:5353".parse().unwrap();
        let found = analyze_questions(&[
            qview("My._http._tcp.local", "host.local.", 6, a),
            qview("My._http._tcp.local", "host.local.", 6, a),
            qview("My._http._tcp.local", "host.local.", 6, b),
        ]);
        assert_eq!(
            found
                .iter()
                .filter(|f| f.kind == AnomalyKind::UnsupportedQuestion)
                .count(),
            2,
            "one finding per querier"
        );
        assert!(found.iter().all(|f| f.kind.is_question()));
    }

    #[test]
    fn question_findings_dedup_names_case_insensitively() {
        let found = analyze_questions(&[
            qview("My._http._tcp.local", "fritz.box.", 6, test_source()),
            qview("My._http._tcp.local", "FRITZ.Box", 6, test_source()),
        ]);
        assert_eq!(
            found
                .iter()
                .filter(|a| a.kind == AnomalyKind::UnsupportedQuestion)
                .count(),
            1,
            "unicast-question must not split on name case, got: {found:?}"
        );
    }

    #[test]
    fn unicast_question_self_port_zero_excluded() {
        // Port 0 can never be a real mDNS querier: our own inferred sends
        // (SELF_SOURCE) must never flag.
        let zelf: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, zelf)]);
        assert!(
            !found
                .iter()
                .any(|a| a.kind == AnomalyKind::UnsupportedQuestion),
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
            !found
                .iter()
                .any(|a| a.kind == AnomalyKind::UnsupportedQuestion),
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
                .filter(|a| a.kind == AnomalyKind::UnsupportedQuestion)
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
                .filter(|a| a.kind == AnomalyKind::UnsupportedQuestion)
                .count(),
            2
        );
    }

    #[test]
    fn in_scope_questions_are_quiet_soa_is_info() {
        // NS and HINFO are in scope; ANY questions are ownership probes
        // (RFC 6762 §8.1, §6.1). None of them is flagged.
        for rtype in [1, 2, 5, 12, 13, 16, 28, 33, 255] {
            let found = analyze_questions(&[qview(
                "My._http._tcp.local",
                "host.local.",
                rtype,
                test_source(),
            )]);
            assert!(
                !found
                    .iter()
                    .any(|a| a.kind == AnomalyKind::UnsupportedQuestion),
                "type {rtype} must stay quiet"
            );
        }
        // SOA questions can never be answered in mDNS (§12).
        let found = analyze_questions(&[qview(
            "My._http._tcp.local",
            "host.local.",
            6,
            test_source(),
        )]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .expect("expected SOA question finding");
        assert_eq!(item.severity, Severity::Info);
        assert_eq!(item.rfc, "RFC 6762 §12");
        assert_eq!(item.rtype_str.as_deref(), Some("TYPE6"));
    }

    #[test]
    fn unicast_style_response_keeps_one_finding_per_source() {
        // Out-of-scope records have no Answers row listing their
        // responders: each source keeps its own finding, whatever the
        // rdata length.
        let mut second = rec("host.local.", 6, "TYPE6", "rdlength=24", 120, false);
        second.source = "192.168.1.9:5353".parse().unwrap();
        let answers = vec![
            rec("host.local.", 6, "TYPE6", "rdlength=22", 120, false),
            second,
        ];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        assert_eq!(
            found
                .iter()
                .filter(|a| a.kind == AnomalyKind::UnicastStyleResponse)
                .count(),
            2,
            "each responder keeps its own finding"
        );
    }

    #[test]
    fn unicast_style_response_flags_soa_not_ns() {
        let answers = vec![
            rec("host.local.", 6, "TYPE6", "rdlength=22", 120, false),
            rec("host.local.", 2, "NS", "host.local.", 120, false),
        ];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let flagged: Vec<_> = found
            .iter()
            .filter(|a| {
                matches!(
                    a.kind,
                    AnomalyKind::UnicastStyleResponse | AnomalyKind::UnsupportedType
                )
            })
            .collect();
        // SOA: mDNS zones have none (§12). NS is in scope: no finding.
        assert_eq!(flagged.len(), 1, "{flagged:?}");
        assert_eq!(flagged[0].rtype, Some(6));
        assert_eq!(flagged[0].kind, AnomalyKind::UnicastStyleResponse);
        assert_eq!(flagged[0].severity, Severity::Warning);
    }

    #[test]
    fn unsupported_type_flags_mx_but_not_in_scope_types() {
        let mut ka = rec("host.local.", 15, "TYPE15", "rdlength=9", 120, false);
        ka.section = crate::browse::RecordSection::KnownAnswer;
        let answers = vec![
            rec("host.local.", 15, "TYPE15", "rdlength=9", 120, false),
            rec("host.local.", 99, "TYPE99", "rdlength=4", 120, false),
            rec("host.local.", 5, "CNAME", "alias.local.", 120, false),
            rec("host.local.", 13, "HINFO", "X86_64 LINUX", 120, false),
            rec("host.local.", 47, "NSEC", "host.local. A", 120, false),
        ];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        let unsupported: Vec<_> = found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnsupportedType)
            .collect();
        let mut types: Vec<_> = unsupported.iter().filter_map(|a| a.rtype).collect();
        types.sort_unstable();
        assert_eq!(types, vec![15, 99], "{unsupported:?}");
        assert!(unsupported.iter().all(|a| a.severity == Severity::Warning));
        assert!(!found
            .iter()
            .any(|a| a.kind == AnomalyKind::UnicastStyleResponse));
        // Known answers ride in queries: capped at Info.
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &[ka]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnsupportedType)
            .expect("expected known-answer finding");
        assert_eq!(item.severity, Severity::Info);
    }

    #[test]
    fn unicast_style_response_names_section_and_unicast_reply() {
        use crate::browse::{QueryTrigger, RecordSection};
        // The message names the section and a unicast destination; the
        // finding carries section and trigger for dumps.
        for (mcast, section, want) in [
            (
                true,
                RecordSection::Authority,
                "unicast DNS-style answer over mDNS: SOA in Authority section \
                 (mDNS uses NSEC for negative answers)",
            ),
            (
                false,
                RecordSection::Answer,
                "unicast DNS-style answer over mDNS: SOA in Answer section \
                 (mDNS zones have no SOA); unicast reply",
            ),
            (
                true,
                RecordSection::Additional,
                "unicast DNS-style answer over mDNS: SOA in Additional section \
                 (mDNS zones have no SOA)",
            ),
        ] {
            let mut soa = rec_with(
                "host.local.",
                6,
                "SOA",
                "host.local. admin 1 2 3 4 5",
                120,
                false,
                mcast,
                section,
            );
            soa.trigger = Some(QueryTrigger {
                question: "host.local. A".to_string(),
                own: true,
            });
            let found = analyze_service("My", "_http._tcp.local", "host.local.", &[soa]);
            let item = found
                .iter()
                .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
                .expect("expected unicast-style response");
            assert_eq!(item.severity, Severity::Warning, "{section:?}");
            assert_eq!(item.message, want);
            let ctx = item.response.as_ref().expect("response context");
            assert_eq!(ctx.section, section);
            assert_eq!(
                ctx.trigger.as_ref().map(|t| (t.question.as_str(), t.own)),
                Some(("host.local. A", true))
            );
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
                response: None,
                responders: Vec::new(),
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
        assert_eq!(item.requirement, "MUST");
        // Same record via unicast reply: mex listens on 5353, so this is
        // a non-legacy response and the MUST still applies (§6.7, §10.2).
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
        assert_eq!(item.severity, Severity::Warning);
        assert_eq!(item.requirement, "MUST");
        assert!(
            item.message.ends_with("(unicast reply)"),
            "{}",
            item.message
        );
    }

    #[test]
    fn missing_flush_by_section() {
        use crate::browse::RecordSection;
        let verdict = |section| {
            let answers = vec![rec_with(
                "My._http._tcp.local.",
                16,
                "TXT",
                "k=v",
                4500,
                false,
                true,
                section,
            )];
            let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
            let item = found
                .iter()
                .find(|a| a.kind == AnomalyKind::NoFlush)
                .expect("expected finding")
                .clone();
            (item.severity, item.requirement)
        };
        // Additional records in a response are held to the same MUST.
        assert_eq!(
            verdict(RecordSection::Additional),
            (Severity::Warning, "MUST")
        );
        // Known answers ride in queries and authority rows in probes: no
        // response-side MUST applies, so the absence stays informational.
        assert_eq!(verdict(RecordSection::KnownAnswer), (Severity::Info, ""));
        assert_eq!(verdict(RecordSection::Authority), (Severity::Info, ""));
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
    fn mx_answer_is_quiet() {
        // Neither RFC 6762 nor RFC 6763 restricts MX in mDNS.
        let answers = vec![rec("host.local.", 15, "MX", "10 host.local.", 120, false)];
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
        assert!(!found
            .iter()
            .any(|a| a.kind == AnomalyKind::UnicastStyleResponse));
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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

    /// Standalone TXT wire record: uncompressed owner, header, then
    /// `strings` as length-prefixed character strings.
    fn txt_wire(owner: &str, strings: &[&[u8]]) -> Vec<u8> {
        let mut wire = Vec::new();
        for label in owner.trim_end_matches('.').split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        wire.extend_from_slice(&[0, 16, 0x80, 1, 0, 0, 0x11, 0x94]);
        let rdata: Vec<u8> = strings
            .iter()
            .flat_map(|s| std::iter::once(s.len() as u8).chain(s.iter().copied()))
            .collect();
        wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        wire.extend_from_slice(&rdata);
        wire
    }

    #[test]
    fn txt_oversize_measures_wire_rdata() {
        // Non-UTF-8 values display as 3-byte U+FFFD each: the lossy
        // display string tops 1300 bytes while the wire RDATA does not.
        let value = vec![0xffu8; 240];
        let strings: Vec<&[u8]> = vec![&value; 5];
        let mut small = rec(
            "X._http._tcp.local.",
            16,
            "TXT",
            &"\u{fffd}".repeat(1200),
            4500,
            true,
        );
        small.wire = txt_wire("X._http._tcp.local.", &strings);
        let found = analyze_service("X", "_http._tcp.local", "", &[small]);
        assert!(
            !found.iter().any(|a| a.kind == AnomalyKind::TxtOversize),
            "1205-byte RDATA stays under the limit, got: {found:?}"
        );

        // Many short strings: the length bytes push RDATA over the limit
        // although the joined display string is shorter.
        let short = *b"k=v";
        let strings: Vec<&[u8]> = vec![&short; 330];
        let mut big = rec(
            "X._http._tcp.local.",
            16,
            "TXT",
            &vec!["k=v"; 330].join("; ")[..1290],
            4500,
            true,
        );
        big.wire = txt_wire("X._http._tcp.local.", &strings);
        let found = analyze_service("X", "_http._tcp.local", "", &[big]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::TxtOversize)
            .expect("1320-byte RDATA is oversize");
        assert_eq!(item.message, "TXT 1320B, max 1300B");
    }

    #[test]
    fn srv_root_target_is_service_unavailable_note() {
        // RFC 2782: "." means the service is decidedly not available.
        let answers = vec![rec("X._http._tcp.local.", 33, "SRV", "0 0 0 .", 120, true)];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::SrvTarget)
            .expect("root target note");
        assert_eq!(item.severity, Severity::Info);
        assert_eq!((item.rfc, item.requirement), ("RFC 2782", ""));
        assert!(item.message.contains("not available"), "{}", item.message);
        assert!(!found
            .iter()
            .any(|a| a.kind == AnomalyKind::UnresolvedSrvTarget));
    }

    #[test]
    fn reverse_ptr_ttl_wants_host_name_base() {
        // RFC 6762 §10: reverse mapping PTRs carry a host name in rdata,
        // so their recommended TTL is 120 s, not 4500 s.
        let answers = vec![rec(
            "10.1.168.192.in-addr.arpa.",
            12,
            "PTR",
            "host.local.",
            7300,
            true,
        )];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::TtlHigh)
            .expect("ttl-high");
        assert_eq!(item.message, "TTL 7300s, want ~120s");
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
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
            sightings: Vec::new(),
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
        };
        assert!(analyze(&snap)
            .iter()
            .any(|a| a.kind == AnomalyKind::TypeFormat && a.service == "enumeration"));
    }

    #[test]
    fn soa_serial_churn_dedups_to_one_finding() {
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
                .filter(|a| a.kind == AnomalyKind::UnicastStyleResponse)
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
            !found
                .iter()
                .any(|a| a.kind == AnomalyKind::UnicastStyleResponse),
            "expired and goodbye SOA must not be flagged"
        );
    }

    #[test]
    fn multicast_types_and_cname_stay_quiet_for_unicast_style() {
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
            !found
                .iter()
                .any(|a| a.kind == AnomalyKind::UnicastStyleResponse),
            "valid multicast types and CNAME must not be flagged"
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
                    .any(|a| a.kind == AnomalyKind::UnicastStyleResponse
                        || a.kind == AnomalyKind::TtlLow)
        );
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::TtlHigh));
    }
}
