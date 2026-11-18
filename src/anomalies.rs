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
