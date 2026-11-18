// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

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
pub(super) fn section_title(section: crate::browse::RecordSection) -> &'static str {
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
pub(super) fn check_question(q: &QuestionView, out: &mut Vec<Anomaly>) {
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
