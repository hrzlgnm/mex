// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// TTLs below this are churn risks; above this are stale-cache risks.
/// The band between covers both observed bases (120s for SRV/A/AAAA and
/// 4500s for PTR/TXT/NS/SOA), so normal responders stay quiet.
pub(super) const TTL_LOW: u32 = 10;

pub(super) const TTL_HIGH: u32 = 7200;

/// TXT payloads above this risk fragmentation; wire bytes preferred.
pub(super) const TXT_MAX: usize = 1300;

/// Per-record checks. A known answer rides in a query (RFC 6762 §7.1):
/// it is the querier's belief, not a responder's claim, so every
/// finding it raises is capped at Info, and its TTL (the remaining one)
/// gets no TTL checks at all.
pub(super) fn check_record(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let first = out.len();
    check_record_claims(service_id, rec, out);
    if rec.section == crate::browse::RecordSection::KnownAnswer {
        for a in &mut out[first..] {
            a.severity = Severity::Info;
        }
    }
}

pub(super) fn check_record_claims(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
    let name = rec.name.clone();
    let rdata = rec.rdata.clone();
    let src = rec.source_label();

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
            source: Some(rec.source_label()),
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
                source: Some(rec.source_label()),
                message: format!("TXT {payload_len}B, max {TXT_MAX}B"),
                rfc: "RFC 6763 §6.2",
                requirement: "SHOULD NOT",
                response: None,
                responders: Vec::new(),
            });
        }
    }
}

pub(super) fn check_srv_target(service_id: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
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

pub(super) fn srv_anomaly_info(service_id: &str, rec: &RawRecord, message: &str) -> Anomaly {
    Anomaly {
        kind: AnomalyKind::SrvTarget,
        severity: Severity::Info,
        service: service_id.to_string(),
        record_name: Some(rec.name.clone()),
        rtype: Some(rec.rtype),
        rtype_str: Some(rec.rtype_str.clone()),
        rdata: Some(rec.rdata.clone()),
        source: Some(rec.source_label()),
        message: message.to_string(),
        rfc: "RFC 2782",
        requirement: "",
        response: None,
        responders: Vec::new(),
    }
}

pub(super) fn srv_anomaly(service_id: &str, rec: &RawRecord, message: &str) -> Anomaly {
    Anomaly {
        kind: AnomalyKind::SrvTarget,
        severity: Severity::Warning,
        service: service_id.to_string(),
        record_name: Some(rec.name.clone()),
        rtype: Some(rec.rtype),
        rtype_str: Some(rec.rtype_str.clone()),
        rdata: Some(rec.rdata.clone()),
        source: Some(rec.source_label()),
        message: message.to_string(),
        rfc: "RFC 2782",
        requirement: "MUST",
        response: None,
        responders: Vec::new(),
    }
}

pub(super) fn check_ttl_stable(
    svc: &ServiceView,
    service_id: &str,
    now: Instant,
    out: &mut Vec<Anomaly>,
) {
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
