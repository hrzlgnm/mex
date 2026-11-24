// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

pub(super) const ADDRESS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) struct AddressEvidence<'a> {
    /// Live address families per host: (lowercased host, 1 | 28).
    pub(super) host_has_addr: &'a HashSet<(String, u16)>,
    pub(super) host_addr_latest: &'a HashMap<(String, u16), Instant>,
    pub(super) pending_hosts: &'a HashSet<String>,
    pub(super) queries: &'a [AddressQueryView],
    pub(super) events: &'a [crate::browse::Event],
    pub(super) now: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressQueryOutcome {
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

pub(super) fn check_unresolved_srv_target(
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
            if host != "." && targets.insert(host.trim_end_matches('.').to_ascii_lowercase()) {
                check_unresolved_target(svc, service_id, host, evidence, out);
            }
        }
    }
}

pub(super) fn check_unresolved_target(
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
    let host_key = host.to_ascii_lowercase();
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

pub(super) fn check_unresolved_path(
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
    let host_key = host.to_ascii_lowercase();
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
