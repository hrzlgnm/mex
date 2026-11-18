use super::*;

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
