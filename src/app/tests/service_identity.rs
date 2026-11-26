// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Instance identity (#386): instance `a.b` of `_x._tcp.local` and
//! instance `a` of `b._x._tcp.local` read the same once flattened. Names
//! are keyed in presentation form, so the first is `a\.b._x._tcp.local`
//! and the two never share a key, a denial, a finding, a question, a
//! refresh row or a query.

use super::*;

/// Well-formed: one instance label `a.b`.
const DOTTED: &str = "a\\.b._x._tcp.local.";
/// Malformed: instance `a` of the type `b._x._tcp.local`.
const PLAIN: &str = "a.b._x._tcp.local.";

fn srv(owner: &str, port: u16) -> browse::RawRecord {
    let mut srv = raw_record(owner, 33, "SRV", &format!("0 0 {port} h.local."), 120);
    srv.flush_bit = true;
    srv
}

/// Both instances live on host `h.local`, each with its own SRV and TXT.
fn colliding_app() -> App {
    let mut app = App::new().unwrap();
    for (owner, port, txt) in [(DOTTED, 80, "who=dotted"), (PLAIN, 81, "who=plain")] {
        ingest(&mut app, &srv(owner, port));
        ingest(&mut app, &raw_record(owner, 16, "TXT", txt, 120));
    }
    ingest(
        &mut app,
        &raw_record("h.local.", 28, "AAAA", "fd00::1", 120),
    );
    app
}

fn service<'a>(app: &'a App, instance: &str, service_type: &str) -> &'a ServiceEntry {
    app.services
        .iter()
        .find(|s| s.instance == instance && s.service_type == service_type)
        .unwrap_or_else(|| panic!("no service {instance} of {service_type}"))
}

fn dotted(app: &App) -> &ServiceEntry {
    service(app, "a.b", "_x._tcp.local")
}

fn plain(app: &App) -> &ServiceEntry {
    service(app, "a", "b._x._tcp.local")
}

fn rows_of(svc: &ServiceEntry, rtype: u16) -> Vec<&browse::RawRecord> {
    svc.answers.iter().filter(|r| r.rtype == rtype).collect()
}

#[test]
fn colliding_instances_are_two_services_with_their_own_rows() {
    let app = colliding_app();
    assert_eq!(app.services.len(), 2);
    for (svc, port, txt) in [
        (dotted(&app), 80, "who=dotted"),
        (plain(&app), 81, "who=plain"),
    ] {
        assert_eq!(svc.port, port);
        let txts = rows_of(svc, 16);
        assert_eq!(txts.len(), 1, "{}: {txts:?}", svc.instance);
        assert_eq!(txts[0].rdata, txt);
        assert_eq!(rows_of(svc, 33).len(), 1);
    }
}

#[test]
fn legacy_denial_keeps_addresses_off_only_its_own_instance() {
    let mut app = colliding_app();
    ingest(
        &mut app,
        &raw_record(DOTTED, 47, "NSEC", &format!("{DOTTED} AAAA"), 120),
    );
    assert!(rows_of(dotted(&app), 28).is_empty(), "denied on a.b");
    assert_eq!(rows_of(plain(&app), 28).len(), 1, "kept on a");
}

#[test]
fn own_question_is_filed_on_its_instance_only() {
    let mut app = colliding_app();
    app.route_own_question(DOTTED, 33, false);
    assert_eq!(dotted(&app).questions.len(), 1);
    assert!(plain(&app).questions.is_empty());
}

#[test]
fn observed_question_is_filed_on_its_instance_only() {
    let mut app = colliding_app();
    app.ingest_event(&query_event(
        PLAIN,
        16,
        "TXT",
        false,
        Vec::new(),
        remote_source(),
    ));
    assert_eq!(plain(&app).questions.len(), 1);
    assert!(dotted(&app).questions.is_empty());
}

#[test]
fn sighting_resolves_to_the_instance_it_names() {
    let mut app = colliding_app();
    ingest(
        &mut app,
        &raw_record(DOTTED, 15, "TYPE15", "rdlength=9", 120),
    );
    let found = findings_of(&app, anomalies::AnomalyKind::UnsupportedType);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].service, "a\\.b._x._tcp.local");
}

#[test]
fn type_format_finding_lands_on_the_malformed_instance_only() {
    let app = colliding_app();
    let found = findings_of(&app, anomalies::AnomalyKind::TypeFormat);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].service, "a.b._x._tcp.local");
    // The message shows the type as it reads, without escapes.
    assert!(
        found[0].message.starts_with("bad type b._x._tcp.local:"),
        "{}",
        found[0].message
    );
}

#[test]
fn refresh_state_is_kept_per_instance() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &srv(DOTTED, 80));
    let dotted_key = ("a\\.b._x._tcp.local".to_string(), 33);
    let plain_key = ("a.b._x._tcp.local".to_string(), 33);
    assert!(app.has_live_answer(&dotted_key));
    assert!(
        !app.has_live_answer(&plain_key),
        "a.b's SRV is no answer for a"
    );
    assert!(app.has_fresh_unique_answer(&dotted_key));
    assert!(!app.has_fresh_unique_answer(&plain_key));
}

#[test]
fn query_interests_are_kept_per_instance() {
    let app = colliding_app();
    let desired = app.desired_continuous();
    for rtype in [33, 16] {
        assert_eq!(
            desired.get(&("a\\.b._x._tcp.local".to_string(), rtype)),
            Some(&"a\\.b._x._tcp.local".to_string())
        );
        assert_eq!(
            desired.get(&("a.b._x._tcp.local".to_string(), rtype)),
            Some(&"a.b._x._tcp.local".to_string())
        );
    }
}

#[test]
fn expiry_keeps_each_instance_on_its_own_records() {
    let mut app = colliding_app();
    // Only the malformed instance's TXT runs out.
    for svc in &mut app.services {
        if svc.instance == "a" {
            for r in &mut svc.answers {
                if r.rtype == 16 {
                    r.received_at = Instant::now() - Duration::from_secs(121);
                }
            }
        }
    }
    app.evict_expired();
    let live: Vec<_> = app
        .desired_continuous()
        .into_keys()
        .filter(|(_, rtype)| *rtype == 16)
        .collect();
    assert!(live.contains(&("a\\.b._x._tcp.local".to_string(), 16)));
    assert_eq!(app.services.len(), 2, "both still within their SRV");
}

#[test]
fn state_dump_lists_colliding_instances_apart() {
    let mut app = colliding_app();
    app.route_own_question(DOTTED, 33, false);
    let dump = app.state_dump();
    assert_eq!(dump.services.len(), 2);
    let find = |instance: &str| {
        dump.services
            .iter()
            .find(|s| s.instance == instance)
            .unwrap_or_else(|| panic!("no dumped {instance}"))
    };
    assert_eq!(find("a.b").service_type, "_x._tcp.local");
    assert_eq!(find("a").service_type, "b._x._tcp.local");
    assert_eq!(find("a.b").questions.len(), 1);
    assert!(find("a").questions.is_empty());
}

#[test]
fn late_ptr_for_dotted_instance_finds_its_service() {
    let mut app = colliding_app();
    ingest(
        &mut app,
        &raw_record("_x._tcp.local.", 12, "PTR", DOTTED, 4500),
    );
    assert!(app.pending_instances.is_empty());
    assert_eq!(rows_of(dotted(&app), 12).len(), 1);
    assert!(rows_of(plain(&app), 12).is_empty());
}

#[test]
fn views_show_names_without_escapes() {
    let mut app = colliding_app();
    ingest(
        &mut app,
        &raw_record("_x._tcp.local.", 12, "PTR", DOTTED, 4500),
    );
    // The PTR row's target reads as the instance name, unescaped.
    let ptr = rows_of(dotted(&app), 12)[0].clone();
    assert_eq!(
        browse::display_rdata(ptr.rtype, &ptr.rdata),
        "a.b._x._tcp.local."
    );
    // TXT text keeps its backslashes.
    assert_eq!(browse::display_rdata(16, "k=a\\.b"), "k=a\\.b");
}

#[test]
fn pending_dotted_instance_is_dumped_under_its_own_name() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_x._tcp.local.", 12, "PTR", DOTTED, 4500),
    );
    let dump = app.state_dump();
    let names: Vec<_> = dump.pending.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["a\\.b._x._tcp.local"]);
}

#[test]
fn known_type_split_keeps_an_escaped_dot_in_the_instance() {
    // Owners without wire labels fall back to known types.
    let mut app = App::new().unwrap();
    app.scheduler
        .known_types_mut()
        .insert("_x._tcp.local".to_string());
    assert_eq!(
        app.split_instance_type("a\\.b._x._tcp.local"),
        Some(("a.b".to_string(), "_x._tcp.local".to_string()))
    );
    // The dot before the known type is escaped: no label starts there.
    assert_eq!(app.split_instance_type("a\\._x._tcp.local"), None);
}
