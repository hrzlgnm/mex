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
fn dropping_the_query_sender_wakes_and_stops_the_listener() {
    // The app dropping its QueryTx must stop the listener at once, so
    // its sockets close with the app: waiting for the next datagram
    // leaks them on a quiet network (the AUR build ran out of file
    // descriptors after ~200 test apps).
    let mut poll = mio::Poll::new().unwrap();
    let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).unwrap());
    // The listener's handle (`SharedWithApp::waker`).
    let _listener_waker = waker.clone();
    let (tx, rx) = mpsc::channel();
    let query_tx = QueryTx {
        tx: Some(tx),
        waker,
        transmit: Arc::new(TransmitState::new(true, true)),
    };
    drop(query_tx);
    let mut events = mio::Events::with_capacity(4);
    poll.poll(&mut events, Some(Duration::from_secs(5)))
        .unwrap();
    assert!(
        events.iter().any(|e| e.token() == WAKER_TOKEN),
        "the drop woke the listener"
    );
    assert_eq!(
        drain_queries(&rx, QUERY_BUDGET, |_| {}),
        (0, QueueState::Closed)
    );
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
