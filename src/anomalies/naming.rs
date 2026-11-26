// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

pub(super) fn check_type_format(svc: &ServiceView, service_id: &str, out: &mut Vec<Anomaly>) {
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
            message: format!("bad type {}: {reason}", crate::browse::unescape_name(st)),
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
pub(super) fn service_type_problem(st: &str) -> Option<String> {
    let labels = crate::browse::presentation_labels(st);
    let parts: Vec<&[u8]> = labels.iter().map(String::as_bytes).collect();
    service_type_labels_problem(&parts)
}

pub(super) fn service_type_labels_problem(parts: &[&[u8]]) -> Option<String> {
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

pub(super) fn service_type_wire_labels_problem(labels: &[Vec<u8>]) -> Option<String> {
    service_type_labels_problem(&labels.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

pub(super) fn service_label_problem(label: &[u8]) -> Option<String> {
    match std::str::from_utf8(label) {
        Ok(label) => label_problem(label),
        Err(_) => Some("service label must be ASCII".to_string()),
    }
}

/// Whether an enumeration target is a subtype (`subtype._sub._svc._tcp.local`).
/// Valid subtypes pass service-type validation but still don't belong in
/// `_services._dns-sd._udp.local` (RFC 6763 §9 lists base types).
pub(super) fn is_subtype_target(st: &str) -> bool {
    let labels = crate::browse::presentation_labels(st);
    let parts: Vec<&[u8]> = labels.iter().map(String::as_bytes).collect();
    is_subtype_labels(&parts)
}

pub(super) fn is_subtype_wire_labels(labels: &[Vec<u8>]) -> bool {
    is_subtype_labels(&labels.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

pub(super) fn is_subtype_labels(labels: &[&[u8]]) -> bool {
    matches!(labels, [_, sub_kw, _, _, _] if crate::browse::is_sub_label(sub_kw))
}

pub(super) fn display_type_target(labels: &[Vec<u8>]) -> String {
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
pub(super) fn label_problem(label: &str) -> Option<String> {
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

pub(super) fn subtype_problem(subtype: &[u8]) -> Option<String> {
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
pub(super) fn check_subtypes(svc: &ServiceView, service_id: &str, out: &mut Vec<Anomaly>) {
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

/// Recommended TTL base per type (RFC 6762 §10, SHOULD): 120s for
/// records whose name or rdata is a host name (SRV, A/AAAA, reverse
/// mapping PTR), 4500s for the rest (service PTR, TXT). Used in TTL
/// messages so users see observed vs recommended values.
pub(super) fn expected_base(rtype: u16, name: &str) -> u32 {
    match rtype {
        12 if is_reverse_ptr(name) => 120,
        12 | 16 => 4500,
        _ => 120,
    }
}

/// Basic DNS-name shape: dot-separated non-empty labels of at most 63
/// bytes, 255 bytes overall. Internationalized names pass through.
pub(super) fn dns_name_problem(name: &str) -> Option<String> {
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
