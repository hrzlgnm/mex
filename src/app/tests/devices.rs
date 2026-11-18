// --- #246: the device behind a source address ---

use super::*;

#[test]
fn host_block_findings_name_their_source_device() {
    let mut app = fritz_mesh();
    for source in [REPEATER, BOX_LL, BOX_V4] {
        soa_from(&mut app, source);
    }
    select_instance(&mut app, "Fritzel");
    // Exact match on the repeater's own A record.
    assert!(
        finding_line(&app, REPEATER).contains(&format!("{REPEATER} (FritzBoxRepeater)")),
        "{}",
        finding_line(&app, REPEATER)
    );
    // Link-local source, matched by interface ID: inferred.
    assert!(
        finding_line(&app, BOX_LL).contains(&format!("{BOX_LL} (~fritz)")),
        "{}",
        finding_line(&app, BOX_LL)
    );
    // Never announced: stays bare.
    let bare = finding_line(&app, BOX_V4);
    assert!(!bare.contains(&format!("{BOX_V4} (")), "{bare}");
    // Naming never changes finding identity or counts.
    assert_eq!(
        findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse).len(),
        3
    );
}

#[test]
fn own_announcement_beats_a_proxy_and_dump_lists_every_name() {
    let mut app = fritz_mesh();
    // The main box answers for the repeater's address under another
    // name: the repeater's own announcement still names `.109`.
    ingest(
        &mut app,
        &from(
            raw_record("Proxied.local.", 1, "A", "192.168.178.109", 120),
            BOX_V4,
        ),
    );
    soa_from(&mut app, REPEATER);
    select_instance(&mut app, "Fritzel");
    let line = finding_line(&app, REPEATER);
    assert!(line.contains("(FritzBoxRepeater)"), "{line}");
    let dump = app.state_dump();
    let finding = dump
        .anomalies
        .iter()
        .find(|a| a.source.as_deref() == Some(REPEATER))
        .expect("repeater finding");
    assert_eq!(
        finding.source_names,
        ["FritzBoxRepeater.fritz.box", "Proxied.local"]
    );
    assert!(!finding.source_name_inferred);
}

#[test]
fn several_own_names_prefer_local_then_alphabetical() {
    let mut app = fritz_mesh();
    ingest(
        &mut app,
        &from(
            raw_record("Repeater.local.", 1, "A", "192.168.178.109", 120),
            REPEATER,
        ),
    );
    soa_from(&mut app, REPEATER);
    select_instance(&mut app, "Fritzel");
    assert!(finding_line(&app, REPEATER).contains("(Repeater)"));
    let dump = app.state_dump();
    let finding = dump
        .anomalies
        .iter()
        .find(|a| a.source.as_deref() == Some(REPEATER))
        .unwrap();
    assert_eq!(
        finding.source_names,
        ["Repeater.local", "FritzBoxRepeater.fritz.box"]
    );
}

#[test]
fn expiry_and_goodbye_remove_the_name() {
    for gone in ["goodbye", "expired"] {
        let mut app = fritz_mesh();
        soa_from(&mut app, REPEATER);
        if gone == "goodbye" {
            // A real goodbye packet from the repeater.
            ingest(
                &mut app,
                &from(
                    raw_record("FritzBoxRepeater.fritz.box.", 1, "A", "192.168.178.109", 0),
                    REPEATER,
                ),
            );
        } else {
            // The repeater's A record waits in the pending addresses
            // (no service points at it); let its TTL elapse.
            for rec in app.pending_addrs.values_mut().flatten() {
                if rec.rtype == 1 {
                    rec.received_at = Instant::now()
                        .checked_sub(Duration::from_secs(500))
                        .unwrap_or_else(Instant::now);
                }
            }
        }
        select_instance(&mut app, "Fritzel");
        let line = finding_line(&app, REPEATER);
        assert!(!line.contains("(FritzBoxRepeater)"), "{gone}: {line}");
    }
}

#[test]
fn questions_pane_names_queriers_and_keeps_one_shot() {
    let mut app = fritz_mesh();
    select_instance(&mut app, "Fritzel");
    for source in [REPEATER, "192.168.178.109:45678"] {
        app.ingest_event(&query_event(
            "Fritzel._fbox._tcp.local.",
            16,
            "TXT",
            false,
            Vec::new(),
            source.parse().unwrap(),
        ));
    }
    let buf = render_to_buffer(&app, 200, 40);
    let text = rect_text(&buf, app.layout.questions_rect.get());
    assert!(
        text.contains(&format!("{REPEATER} (FritzBoxRepeater)")),
        "{text}"
    );
    assert!(
        text.contains("192.168.178.109:45678 (one-shot, FritzBoxRepeater)"),
        "{text}"
    );
}

#[test]
fn answers_name_foreign_responders_only() {
    let mut app = fritz_mesh();
    // The repeater answers for the box's name: foreign responder.
    ingest(
        &mut app,
        &from(
            raw_record("fritz.box.", 28, "AAAA", "fd00::ca0e:14ff:feff:416", 120),
            REPEATER,
        ),
    );
    // The box itself (link-local, inferred `fritz`) re-sends the TXT
    // without the flush bit: its own host, but a finding.
    ingest(
        &mut app,
        &from(
            raw_record("Fritzel._fbox._tcp.local.", 16, "TXT", "a=1", 4500),
            BOX_LL,
        ),
    );
    select_instance(&mut app, "Fritzel");
    let lines = answers_text(&app);
    let foreign = lines
        .iter()
        .find(|l| l.contains("fd00::ca0e:14ff:feff:416"))
        .unwrap();
    assert!(foreign.contains("(FritzBoxRepeater)"), "{foreign}");
    let txt = lines
        .iter()
        .position(|l| l.starts_with("│TXT"))
        .unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(!lines[txt].contains("(~fritz)"), "own host: {}", lines[txt]);
    // Its finding child row doesn't repeat the source (#266).
    assert!(lines[txt + 1].contains("no-flush"), "{lines:#?}");
    assert!(!lines[txt + 1].contains("(~fritz)"), "{}", lines[txt + 1]);
    assert!(!lines[txt + 1].contains("fe80::"), "{}", lines[txt + 1]);
}

#[test]
fn unattributed_findings_name_their_source() {
    let mut app = fritz_mesh();
    ingest(
        &mut app,
        &from(
            raw_record("other.example.", 6, "TYPE6", "rdlength=30", 4500),
            REPEATER,
        ),
    );
    let pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Unattributed))
        .expect("(unattributed) entry");
    app.view_state.selected_display = pos;
    app.clamp_selection();
    assert!(finding_line(&app, REPEATER).contains("(FritzBoxRepeater)"));
}

#[test]
fn dump_adds_name_fields_only_when_named() {
    let mut app = fritz_mesh();
    for source in [REPEATER, BOX_LL, BOX_V4] {
        soa_from(&mut app, source);
    }
    let json = serde_json::to_value(app.state_dump()).unwrap();
    let anomalies = json["anomalies"].as_array().unwrap();
    let by_source = |src: &str| {
        anomalies
            .iter()
            .find(|a| a["source"] == src)
            .unwrap_or_else(|| panic!("finding from {src}"))
    };
    assert_eq!(
        by_source(REPEATER)["source_names"],
        serde_json::json!(["FritzBoxRepeater.fritz.box"])
    );
    assert!(by_source(REPEATER).get("source_name_inferred").is_none());
    assert_eq!(
        by_source(BOX_LL)["source_names"],
        serde_json::json!(["fritz.box"])
    );
    assert_eq!(by_source(BOX_LL)["source_name_inferred"], true);
    let bare = by_source(BOX_V4);
    assert!(bare.get("source_names").is_none(), "{bare}");
    assert!(bare.get("source_name_inferred").is_none(), "{bare}");
    // Answer rows: the repeater answering for the box's name is named.
    ingest(
        &mut app,
        &from(
            raw_record("fritz.box.", 28, "AAAA", "fd00::ca0e:14ff:feff:416", 120),
            REPEATER,
        ),
    );
    let json = serde_json::to_value(app.state_dump()).unwrap();
    let rows: Vec<&serde_json::Value> = json["services"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["answers"].as_array().unwrap().iter())
        .collect();
    let a = rows
        .iter()
        .find(|r| r["source"] == REPEATER)
        .expect("repeater row");
    assert_eq!(a["source"], REPEATER);
    assert_eq!(
        a["source_names"],
        serde_json::json!(["FritzBoxRepeater.fritz.box"])
    );
}

#[test]
fn withheld_host_address_still_names_its_device() {
    // Only one service on knulp, and it denies AAAA (legacy NSEC):
    // the AAAA is withheld from every service but stays a live host
    // address, so a querier at it is still named.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &srv_on_knulp(DACP));
    ingest(&mut app, &legacy_aaaa_denial());
    let mut aaaa = aaaa_knulp();
    aaaa.source = "[fd00::1]:5353".parse().unwrap();
    ingest(&mut app, &aaaa);
    assert!(!rows_of(&app, DACP).contains(&28), "denied on the service");
    app.ingest_event(&query_event(
        DACP,
        16,
        "TXT",
        false,
        Vec::new(),
        "[fd00::1]:5353".parse().unwrap(),
    ));
    let dump = app.state_dump();
    let question = dump
        .services
        .iter()
        .flat_map(|s| s.questions.iter())
        .find(|q| q.source == "[fd00::1]:5353")
        .expect("question row");
    assert_eq!(question.source_names, ["knulp.local"]);
}

/// The router zone's SOA, heard from `source`.
fn soa_from(app: &mut App, source: &str) {
    ingest(
        app,
        &from(
            raw_record("fritz.box.", 6, "TYPE6", "rdlength=49", 4500),
            source,
        ),
    );
}

/// The finding row in the Answers pane whose source column starts
/// with `source`.
fn finding_line(app: &App, source: &str) -> String {
    let lines = answers_text(app);
    lines
        .iter()
        .find(|l| l.contains(source) && l.contains("unicast-style-response"))
        .unwrap_or_else(|| panic!("finding row from {source}: {lines:#?}"))
        .clone()
}
