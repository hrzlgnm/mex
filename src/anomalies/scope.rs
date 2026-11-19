// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// Row identity for a finding (`QRY …` for demand-side questions,
/// `TYPE name` otherwise): the shared core of every display scope.
pub(super) fn finding_scope(a: &Anomaly) -> String {
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
/// (diagnostics overlay, state dump) list the question once instead. Each
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
/// the diagnostics overlay: empty for service-level findings and enumeration
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
