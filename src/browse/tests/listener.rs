// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn v6_dest_carries_interface_scope() {
    match mdns_dest_v6(7) {
        SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 7),
        _ => panic!("expected v6 mDNS dest"),
    }
}

#[test]
fn multicast_loop_is_enabled() {
    // Loop on, so responders on this host hear our queries; our own
    // copies are dropped by `SentCopies`. Failure here is loud
    // (startup errors propagate).
    let std4 = create_v4_socket().unwrap().try_clone_std().unwrap();
    assert!(socket2::Socket::from(std4).multicast_loop_v4().unwrap());
    let std6 = create_v6_socket().unwrap().try_clone_std().unwrap();
    assert!(socket2::Socket::from(std6).multicast_loop_v6().unwrap());
}

#[test]
fn v6_socket_is_v6_only() {
    // v4 traffic belongs to the v4 socket alone: no v4-mapped
    // packets on the v6 socket, whatever the platform default.
    let std6 = create_v6_socket().unwrap().try_clone_std().unwrap();
    assert!(socket2::Socket::from(std6).only_v6().unwrap());
}

#[test]
fn poll_timeout_waits_for_refresh_unless_reads_are_pending() {
    let now = Instant::now();
    let refresh = now + Duration::from_secs(7);
    assert_eq!(poll_timeout(now, refresh, false), Duration::from_secs(7));
    assert_eq!(poll_timeout(now, refresh, true), Duration::ZERO);
    // A due (or overdue) refresh never yields a zero timeout: no spin.
    assert_eq!(poll_timeout(now, now, false), Duration::from_millis(1));
    assert_eq!(
        poll_timeout(now + Duration::from_secs(1), now, false),
        Duration::from_millis(1)
    );
}

#[test]
fn drain_stops_at_would_block_budget_or_closed_receiver() {
    let mut left = 3;
    let empty = drain_budgeted(10, || {
        if left == 0 {
            return ReadStep::WouldBlock;
        }
        left -= 1;
        ReadStep::Handled
    });
    assert_eq!(empty, Drained::Empty);
    let mut reads = 0;
    let capped = drain_budgeted(4, || {
        reads += 1;
        ReadStep::Handled
    });
    assert_eq!((capped, reads), (Drained::Budget, 4));
    assert_eq!(drain_budgeted(4, || ReadStep::Closed), Drained::Closed);
}

#[test]
fn query_send_wakes_the_poll_and_is_drained() {
    // A queued query wakes the loop at once (no sleep to wait out)
    // and is sent exactly once.
    let mut poll = mio::Poll::new().unwrap();
    let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).unwrap());
    let (tx, rx) = mpsc::channel();
    let query_tx = QueryTx {
        tx: Some(tx),
        waker,
        transmit: Arc::new(TransmitState::new(true, true)),
    };
    let req = QueryRequest {
        name: "_http._tcp.local".to_string(),
        record_type: TYPE::PTR,
        known_answers: Vec::new(),
        qu: false,
    };
    assert!(query_tx.send(req.clone()));
    assert!(query_tx.send(req));
    let mut events = mio::Events::with_capacity(4);
    let started = Instant::now();
    poll.poll(&mut events, Some(Duration::from_secs(5)))
        .unwrap();
    assert!(
        events.iter().any(|e| e.token() == WAKER_TOKEN),
        "the waker fired"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "woken, not timed out"
    );
    let mut names = Vec::new();
    assert_eq!(
        drain_queries(&rx, QUERY_BUDGET, |q| names.push(q.name.clone())),
        (2, QueueState::Empty)
    );
    assert_eq!(names, vec!["_http._tcp.local"; 2]);
    assert_eq!(
        drain_queries(&rx, QUERY_BUDGET, |_| {}),
        (0, QueueState::Empty),
        "drained once"
    );
}

#[test]
fn dropping_the_query_sender_stops_the_listener() {
    // The app dropping its QueryTx must stop the listener at once, so
    // its sockets close with the app: waiting for the next datagram
    // leaks them on a quiet network (the AUR build ran out of file
    // descriptors after ~200 test apps). No datagram arrives here, and
    // only the listener and the QueryTx hold the waker, as in `spawn`;
    // without a delivered wake the loop would sleep until the 10 s
    // interface refresh.
    let poll = mio::Poll::new().unwrap();
    let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).unwrap());
    let transmit = Arc::new(TransmitState::new(false, false));
    let (tx, _events) = mpsc::channel();
    let (query_tx, query_rx) = mpsc::channel();
    let mut listener = Listener::new(
        poll,
        None,
        None,
        tx,
        query_rx,
        SharedWithApp {
            drops: Arc::new(DropStats::default()),
            transmit: transmit.clone(),
            waker: waker.clone(),
            own_sends: mpsc::channel().0,
        },
        Some(HashSet::new()),
    );
    listener.next_refresh = Instant::now() + IFACE_REFRESH;
    let (done_tx, done_rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        listener.run();
        let _ = done_tx.send(());
    });
    let query_tx = QueryTx {
        tx: Some(query_tx),
        waker,
        transmit,
    };
    // Let the loop reach its poll before the drop.
    thread::sleep(Duration::from_millis(50));
    drop(query_tx);
    assert!(
        done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the listener stopped when its QueryTx was dropped"
    );
    thread.join().unwrap();
}

#[test]
fn query_drain_is_budgeted_per_pass() {
    // A query burst can't hold off socket reads: one pass sends at
    // most the budget and reports the rest as pending.
    let (tx, rx) = mpsc::channel();
    for i in 0..5 {
        tx.send(QueryRequest {
            name: format!("q{i}.local"),
            record_type: TYPE::A,
            known_answers: Vec::new(),
            qu: false,
        })
        .unwrap();
    }
    let mut sent = Vec::new();
    assert_eq!(
        drain_queries(&rx, 3, |q| sent.push(q.name.clone())),
        (3, QueueState::More)
    );
    assert_eq!(
        drain_queries(&rx, 3, |q| sent.push(q.name.clone())),
        (2, QueueState::Empty)
    );
    assert_eq!(
        sent,
        ["q0.local", "q1.local", "q2.local", "q3.local", "q4.local"]
    );
}

#[test]
fn startup_needs_at_least_one_socket() {
    assert!(require_transport(true, true).is_ok());
    assert!(require_transport(true, false).is_ok());
    assert!(require_transport(false, true).is_ok());
    let err = require_transport(false, false).unwrap_err().to_string();
    assert!(err.contains("no mDNS socket"), "{err}");
}

#[test]
fn listener_runs_with_one_family_missing() {
    // One family failing to open must not stop the other: a missing
    // socket is skipped by refresh and reads.
    let poll = mio::Poll::new().unwrap();
    let v4 = FamilySocket::open(Family::V4, poll.registry()).expect("v4 socket");
    let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).unwrap());
    let (tx, _rx) = mpsc::channel();
    let (_query_tx, query_rx) = mpsc::channel();
    let mut listener = Listener::new(
        poll,
        Some(v4),
        None,
        tx,
        query_rx,
        SharedWithApp {
            drops: Arc::new(DropStats::default()),
            transmit: Arc::new(TransmitState::new(true, false)),
            waker,
            own_sends: mpsc::channel().0,
        },
        Some(HashSet::new()),
    );
    listener.refresh();
    assert!(listener.ifaces_v6.is_empty());
    assert!(
        listener.read_family(Family::V6),
        "missing family is a no-op"
    );
    assert!(listener.read_family(Family::V4), "open family drains");
    assert!(listener.v4.is_some(), "socket put back after the drain");
}

#[test]
fn multicast_ttl_is_255() {
    // RFC 6762 §11: mDNS packets go out with TTL 255.
    let std4 = create_v4_socket().unwrap().try_clone_std().unwrap();
    assert_eq!(socket2::Socket::from(std4).multicast_ttl_v4().unwrap(), 255);
    let std6 = create_v6_socket().unwrap().try_clone_std().unwrap();
    assert_eq!(
        socket2::Socket::from(std6).multicast_hops_v6().unwrap(),
        255
    );
}

#[test]
fn malformed_packets_are_counted_with_source() {
    let drops = DropStats::default();
    assert_eq!(drops.malformed_total(), 0);
    assert!(drops.malformed_last().is_none());
    drops.note_malformed(test_source());
    drops.note_malformed(test_source());
    assert_eq!(drops.malformed_total(), 2);
    assert_eq!(drops.malformed_last().unwrap().0, test_source());
    // Off-link accounting is untouched by malformed traffic.
    assert_eq!(drops.total(), 0);
    assert!(drops.last().is_none());
}

/// Ingress index of the one link `bare_listener` knows.
const TEST_LINK: u32 = 42;

/// A listener with no sockets that knows one link (`eth-test`,
/// 192.168.178.0/24, matching `test_source()`), for driving datagram
/// handling without network traffic.
fn bare_listener(
    selection: Option<HashSet<String>>,
) -> (Listener, mpsc::Receiver<Event>, Arc<DropStats>) {
    let poll = mio::Poll::new().unwrap();
    let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).unwrap());
    let drops = Arc::new(DropStats::default());
    let (tx, rx) = mpsc::channel();
    let (_query_tx, query_rx) = mpsc::channel();
    let mut listener = Listener::new(
        poll,
        None,
        None,
        tx,
        query_rx,
        SharedWithApp {
            drops: drops.clone(),
            transmit: Arc::new(TransmitState::new(true, true)),
            waker,
            own_sends: mpsc::channel().0,
        },
        selection,
    );
    listener.ifnames.insert(TEST_LINK, "eth-test".to_string());
    listener.subnets.insert(
        TEST_LINK,
        vec![(
            IpAddr::V4(Ipv4Addr::new(192, 168, 178, 1)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        )],
    );
    (listener, rx, drops)
}

/// Hand `bytes` to the listener as if the socket had just received them.
fn deliver(
    listener: &mut Listener,
    bytes: &[u8],
    src: SocketAddr,
    dst: IpAddr,
    ifindex: u32,
) -> ReadStep {
    listener.buf[..bytes.len()].copy_from_slice(bytes);
    listener.handle_recv(Ok((
        bytes.len(),
        socket_pktinfo::PktInfo {
            if_index: u64::from(ifindex),
            addr_src: src,
            addr_dst: dst,
        },
    )))
}

/// A well-formed one-question mDNS query.
fn query_bytes() -> Vec<u8> {
    let mut q = Packet::new_query(0);
    q.questions.push(Question::new(
        simple_dns::Name::new_unchecked("_http._tcp.local."),
        QTYPE::TYPE(TYPE::PTR),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    q.build_bytes_vec().unwrap()
}

fn multicast_v4() -> IpAddr {
    IpAddr::V4(MDNS_V4)
}

#[test]
fn malformed_datagram_is_counted_not_forwarded() {
    let (mut listener, events, drops) = bare_listener(None);
    let step = deliver(
        &mut listener,
        &[0xde, 0xad, 0xbe],
        test_source(),
        multicast_v4(),
        TEST_LINK,
    );
    assert!(matches!(step, ReadStep::Handled));
    assert_eq!(drops.malformed_total(), 1);
    assert_eq!(drops.malformed_last().unwrap().0, test_source());
    assert!(events.try_recv().is_err(), "no event for junk");
    assert_eq!(drops.total(), 0, "not an off-link drop");
}

#[test]
fn recv_error_ends_the_drain_like_would_block() {
    // One failing read neither stops the listener nor spins: the drain
    // ends, readiness re-arms and the next datagram announces itself.
    let (mut listener, events, drops) = bare_listener(None);
    for kind in [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::WouldBlock,
    ] {
        assert!(matches!(
            listener.handle_recv(Err(kind.into())),
            ReadStep::WouldBlock
        ));
    }
    assert!(events.try_recv().is_err());
    assert_eq!((drops.total(), drops.malformed_total()), (0, 0));
}

#[test]
fn off_link_unicast_is_refused_and_counted() {
    // RFC 6762 §11: a unicast-destination packet must come from a
    // local subnet of its ingress link.
    let (mut listener, events, drops) = bare_listener(None);
    let unicast = IpAddr::V4(Ipv4Addr::new(192, 168, 178, 5));
    let spoofer: SocketAddr = "10.9.9.9:5353".parse().unwrap();
    let step = deliver(&mut listener, &query_bytes(), spoofer, unicast, TEST_LINK);
    assert!(matches!(step, ReadStep::Handled));
    assert_eq!(drops.total(), 1);
    assert_eq!(drops.last().unwrap().0, spoofer);
    assert!(events.try_recv().is_err(), "refused, not forwarded");

    // The same packet from an on-link source is delivered.
    let step = deliver(
        &mut listener,
        &query_bytes(),
        test_source(),
        unicast,
        TEST_LINK,
    );
    assert!(matches!(step, ReadStep::Handled));
    assert_eq!(events.try_recv().unwrap().source, test_source());
    assert_eq!(drops.total(), 1, "on-link source not counted");
}

#[test]
fn off_selection_ingress_is_dropped_silently() {
    // An explicit `-i` selection drops ingress from other links,
    // without counting it as off-link or malformed.
    let selection = HashSet::from(["other".to_string()]);
    let (mut listener, events, drops) = bare_listener(Some(selection));
    let step = deliver(
        &mut listener,
        &query_bytes(),
        test_source(),
        multicast_v4(),
        TEST_LINK,
    );
    assert!(matches!(step, ReadStep::Handled));
    assert!(events.try_recv().is_err());
    assert_eq!((drops.total(), drops.malformed_total()), (0, 0));
}

#[test]
fn unknown_ingress_link_is_backfilled_once_and_still_delivered() {
    // An index no host reports: the backfill scan finds nothing and
    // remembers the index, so later packets don't rescan.
    let (mut listener, events, _drops) = bare_listener(None);
    let unmapped = 0x7fff_fff0;
    let step = deliver(
        &mut listener,
        &query_bytes(),
        test_source(),
        multicast_v4(),
        unmapped,
    );
    assert!(matches!(step, ReadStep::Handled));
    assert!(listener.unknown.contains(&unmapped));
    assert!(!listener.ifnames.contains_key(&unmapped));
    // Multicast destination, no selection: delivered without a name.
    let ev = events.try_recv().unwrap();
    assert_eq!(ev.questions[0].iface, "");

    // A link the host does report but the cached maps miss: the scan
    // fills its name in before the packet is filed. Hosts with no
    // addressed link (isolated sandboxes) have nothing to backfill.
    let (host_links, _) = link_maps();
    let Some((&idx, name)) = host_links.iter().next() else {
        eprintln!("skipping backfill hit: host reports no addressed link");
        return;
    };
    // Force the miss even if the host link shares `TEST_LINK`'s index.
    listener.ifnames.remove(&idx);
    listener.subnets.remove(&idx);
    deliver(
        &mut listener,
        &query_bytes(),
        test_source(),
        multicast_v4(),
        idx,
    );
    assert_eq!(listener.ifnames.get(&idx), Some(name));
    assert_eq!(events.try_recv().unwrap().questions[0].iface, *name);
}

#[test]
fn own_query_copy_is_dropped_on_loopback() {
    let (mut listener, events, drops) = bare_listener(None);
    let bytes = query_bytes();
    listener.sent_copies.record(&bytes, Instant::now());
    let step = deliver(
        &mut listener,
        &bytes,
        test_source(),
        multicast_v4(),
        TEST_LINK,
    );
    assert!(matches!(step, ReadStep::Handled));
    assert!(events.try_recv().is_err(), "our own copy is not a querier");
    assert_eq!((drops.total(), drops.malformed_total()), (0, 0));
    // One drop per sent copy: a second identical packet is remote.
    deliver(
        &mut listener,
        &bytes,
        test_source(),
        multicast_v4(),
        TEST_LINK,
    );
    assert!(events.try_recv().is_ok());
}

#[test]
fn closed_event_receiver_stops_the_drain() {
    let (mut listener, events, _drops) = bare_listener(None);
    drop(events);
    let step = deliver(
        &mut listener,
        &query_bytes(),
        test_source(),
        multicast_v4(),
        TEST_LINK,
    );
    assert!(matches!(step, ReadStep::Closed));
}

#[test]
fn failed_socket_open_yields_no_socket() {
    let poll = mio::Poll::new().unwrap();
    let opened = FamilySocket::open_with(Family::V4, poll.registry(), || {
        Err(anyhow::anyhow!("no socket for you"))
    });
    assert!(opened.is_none());
}

#[test]
fn run_refreshes_interfaces_when_due() {
    // A due refresh runs at the top of the loop pass and reschedules;
    // the dropped query sender then stops the loop.
    let (mut listener, _events, _drops) = bare_listener(Some(HashSet::new()));
    let (query_tx, query_rx) = mpsc::channel();
    drop(query_tx);
    listener.query_rx = query_rx;
    let started = Instant::now();
    listener.next_refresh = started;
    listener.run();
    assert!(listener.next_refresh >= started + IFACE_REFRESH);
}

#[test]
fn query_send_fails_once_the_listener_is_gone() {
    // The listener dropped its queue (it stopped): `send` reports the
    // request as not accepted instead of pretending it was queued.
    let poll = mio::Poll::new().unwrap();
    let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).unwrap());
    let (tx, rx) = mpsc::channel();
    drop(rx);
    let query_tx = QueryTx {
        tx: Some(tx),
        waker,
        transmit: Arc::new(TransmitState::new(true, true)),
    };
    assert!(!query_tx.send(QueryRequest {
        name: "_http._tcp.local".to_string(),
        record_type: TYPE::PTR,
        known_answers: Vec::new(),
        qu: false,
    }));
}

#[test]
fn drop_counts_survive_a_poisoned_last_source_lock() {
    // A panic while holding a last-source lock must not take the
    // listener down with it: counting goes on, the last source is
    // simply unknown from then on.
    let drops = Arc::new(DropStats::default());
    let poisoner = drops.clone();
    let _ = thread::spawn(move || {
        let _last = poisoner.last.lock().unwrap();
        let _malformed = poisoner.malformed_last.lock().unwrap();
        panic!("poison both locks");
    })
    .join();
    drops.note(test_source());
    drops.note_malformed(test_source());
    assert_eq!((drops.total(), drops.malformed_total()), (1, 1));
    assert!(drops.last().is_none());
    assert!(drops.malformed_last().is_none());
}

#[test]
fn an_ipv4_copy_s_link_index_comes_from_the_name_map() {
    // #431: received records carry the index `ifnames` names; our IPv4
    // copies are pinned by address, so their index is looked up by name.
    let ifnames = HashMap::from([(2, "eth0".to_string()), (3, "wlan0".to_string())]);
    assert_eq!(link_index(&ifnames, "wlan0"), 3);
    assert_eq!(link_index(&ifnames, "gone0"), 0, "unknown: matches no copy");
}
