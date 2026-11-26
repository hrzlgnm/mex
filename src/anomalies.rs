// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::browse::{rtype_from_str, RawRecord, ENUM_SERVICE};

mod naming;
mod questions;
mod records;
mod resolve;
mod scope;
pub(crate) use naming::display_subtype;
pub(crate) use naming::is_mdns_domain;
use naming::*;
pub(crate) use questions::is_one_shot_querier;
pub(crate) use questions::unicast_style_verdict;
pub(crate) use questions::unsupported_type_verdict;
use questions::*;
use records::*;
use resolve::*;
pub(crate) use scope::collapse_questions;
pub(crate) use scope::identity_counts;
pub(crate) use scope::visible_scope;

/// Service identity carried by findings: the service's presentation-form
/// name (`browse::instance_name`, instance label escaped), or
/// `enumeration` for enumeration-row answers. Single definition shared
/// by the analyzer and the pane filters so the two cannot drift.
pub const ENUMERATION_SERVICE: &str = "enumeration";

/// Catch-all service identity for out-of-scope sightings whose owner
/// name matches no known service, pending instance or host (e.g. a
/// router's `fritz.box.` SOA). Shown in the diagnostics overlay and dumps.
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

/// Service identity for a confirmed or pending instance: its
/// presentation-form name (`browse::instance_name`), so a dot inside
/// the instance label never merges two instances (#386).
pub fn service_id(instance: &str, service_type: &str) -> String {
    crate::browse::instance_name(instance, service_type)
}

/// Finding owner for a record or question owned by a hostname (an SRV
/// target): the lowercased name without its root dot. One host backs
/// many services, so host-owned evidence is recorded once, under the
/// host, and every service on it shows it in a `host` block.
pub fn host_id(hostname: &str) -> String {
    hostname.trim_end_matches('.').to_ascii_lowercase()
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
    /// Owning service as its presentation-form name (`service_id`), or
    /// `enumeration` for enumeration-row answers.
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
    /// (`service_id`, or `enumeration`).
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

fn is_live(rec: &RawRecord, now: Instant) -> bool {
    rec.ttl > 0 && now.duration_since(rec.received_at).as_secs() as u32 <= rec.ttl
}

/// Responders on one link announcing different live address sets for one
/// hostname and family (#247). Sources with identical sets form one
/// responder group (one device on several transports); a source with no
/// address of a family is absent from that family. Groups that answer
/// from an address the hostname announces on that link (either family)
/// are the host itself, one NIC each, and merge into one responder: a
/// multi-homed host answering per interface (RFC 6762 §6.2, §14) is not
/// a conflict (#271). Warning when any
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
    // Link = interface name plus index: a name can be unknown, and two
    // unnamed links must not merge.
    let mut groups: BTreeMap<(u16, String, u32), (Sets, bool)> = BTreeMap::new();
    // (link) -> every address the hostname announces there, both families.
    let mut host_ips: BTreeMap<(String, u32), BTreeSet<std::net::IpAddr>> = BTreeMap::new();
    for rec in &view.records {
        if !matches!(rec.rtype, 1 | 28) || !is_live(rec, now) {
            continue;
        }
        let ip = rec.rdata.trim().parse::<std::net::IpAddr>();
        if let Ok(ip) = ip {
            host_ips
                .entry((rec.iface.clone(), rec.ifindex))
                .or_default()
                .insert(ip);
        }
        let addr = ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| rec.rdata.trim().to_string());
        let (sets, flush) = groups
            .entry((rec.rtype, rec.iface.clone(), rec.ifindex))
            .or_default();
        *flush |= rec.flush_bit;
        sets.entry(rec.source)
            .or_insert_with(|| (rec.source_label(), BTreeSet::new()))
            .1
            .insert(addr);
    }
    for ((rtype, iface, ifindex), (sets, flush)) in groups {
        // Identical sets are one responder (one device, several sources).
        let mut by_set: BTreeMap<BTreeSet<String>, Vec<(SocketAddr, String)>> = BTreeMap::new();
        for (source, (label, addrs)) in sets {
            by_set.entry(addrs).or_default().push((source, label));
        }
        // The host's own groups (one per NIC) merge into one responder.
        let own = host_ips.get(&(iface.clone(), ifindex));
        let is_host = |sources: &[(SocketAddr, String)]| {
            own.is_some_and(|ips| sources.iter().any(|(s, _)| ips.contains(&s.ip())))
        };
        // Re-keyed by the merged set, so a responder agreeing with the
        // host as a whole is still the same set.
        let (host, mut by_set): (BTreeMap<_, _>, BTreeMap<_, _>) = by_set
            .into_iter()
            .partition(|(_, sources)| is_host(sources));
        if !host.is_empty() {
            let mut host_addrs = BTreeSet::new();
            let mut host_sources = Vec::new();
            for (addrs, sources) in host {
                host_addrs.extend(addrs);
                host_sources.extend(sources);
            }
            by_set.entry(host_addrs).or_default().extend(host_sources);
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
        let link = match (iface.is_empty(), ifindex) {
            (false, _) => format!(" on {iface}"),
            (true, 0) => String::new(),
            (true, index) => format!(" on #{index}"),
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
/// Dedup key is (kind, service, name, type, rdata, source): the same record
/// seen from several sources yields one anomaly per source, so each source's
/// Answers row shows its own finding.
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
                let key = rec.name.trim_end_matches('.').to_ascii_lowercase();
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
                .unwrap_or_else(|| crate::browse::unescape_name(target));
            if let Some(reason) = type_problem {
                out.push(Anomaly {
                    kind: AnomalyKind::TypeFormat,
                    severity: Severity::Warning,
                    service: ENUMERATION_SERVICE.to_string(),
                    record_name: Some(rec.name.clone()),
                    rtype: Some(rec.rtype),
                    rtype_str: Some(rec.rtype_str.clone()),
                    rdata: Some(rec.rdata.clone()),
                    source: Some(rec.source_label()),
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
                    source: Some(rec.source_label()),
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
        // One finding per source: questions carry no rdata, so queriers
        // differ only by source; out-of-scope records have no Answers row,
        // so their findings are the only per-source record; and record
        // findings sit next to the row of the source that sent them
        // (`finding_matches_record`), so a record announced from several
        // sources (IPv4 and IPv6, several NICs) must keep a finding per
        // source, or only the first source's row would show it. Record
        // findings name the interface-qualified `source_label()`, so one
        // address heard on two links also keeps a finding per link.
        // Context-gated kinds also key on the message below, where the
        // same rdata via multicast vs unicast (or answer vs authority) is
        // a different verdict and must not collapse.
        let source_key = a.source.clone().unwrap_or_default();
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

/// Whether a PTR owner name is a reverse-mapping name. Those PTRs are
/// unique (one address, one owner), unlike service/enumeration PTRs.
pub(crate) fn is_reverse_ptr(name: &str) -> bool {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    lower.ends_with(".in-addr.arpa") || lower.ends_with(".ip6.arpa")
}

#[cfg(test)]
mod tests;
