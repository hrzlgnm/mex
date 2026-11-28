// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// A transmit-state change worth one log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PauseLog {
    /// The family's link list became empty: its queries stop.
    Paused,
    /// The family has a usable link again: its queries resume.
    Resumed,
}

pub(super) fn create_v4_socket() -> Result<PktInfoUdpSocket> {
    let socket = PktInfoUdpSocket::new(Domain::IPV4)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    // Multicast loop on: on Unix the option governs whether our own
    // outgoing multicast reaches sockets on this host, so with it off,
    // responders here (avahi, python-zeroconf) never hear our queries.
    // (On Windows it applies to receive instead.) Our own looped-back
    // copies are dropped on receive by `SentCopies`.
    socket.set_multicast_loop_v4(true)?;
    // RFC 6762 §11 sends with IP TTL 255 (a SHOULD for responses, and
    // ecosystem convention for queries too): link-local scope is
    // unaffected, but legacy checkers discard anything else.
    socket.set_multicast_ttl_v4(255)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket.bind(&addr.into())?;
    Ok(socket)
}

pub(super) fn create_v6_socket() -> Result<PktInfoUdpSocket> {
    let socket = PktInfoUdpSocket::new(Domain::IPV6)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    // Loop on, as for v4: local responders must hear our queries.
    socket.set_multicast_loop_v6(true)?;
    socket.set_multicast_hops_v6(255)?;
    // v6 only: v4 traffic belongs to the v4 socket alone. The pktinfo
    // wrapper has no setter, so set it through a duplicate handle (same
    // underlying socket) before bind; platform defaults differ (Linux
    // and macOS dual-stack, Windows v6-only).
    socket2::SockRef::from(&socket.try_clone_std()?).set_only_v6(true)?;
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// mDNS destination for one interface: link-local multicast needs the
/// egress interface's scope id, otherwise the packet leaves via whatever
/// the kernel picks as the default multicast interface (or fails).
pub(super) fn mdns_dest_v6(ifindex: u32) -> SocketAddr {
    SocketAddr::from(SocketAddrV6::new(MDNS_V6, MDNS_PORT, 0, ifindex))
}

/// Poll tokens: one per family socket, plus the query waker.
pub(super) const V4_TOKEN: mio::Token = mio::Token(0);

pub(super) const V6_TOKEN: mio::Token = mio::Token(1);

pub(super) const WAKER_TOKEN: mio::Token = mio::Token(2);

/// Datagrams read from one socket per loop pass before the other gets
/// its turn, so a burst on one family can't starve the other.
pub(super) const READ_BUDGET: usize = 64;

/// One family's socket: the pktinfo socket does every read (ingress
/// interface) and send; a duplicate of the same socket is registered
/// with the poll for readiness only, as mdns-sd does.
pub(super) struct FamilySocket {
    pub(super) family: Family,
    pub(super) token: mio::Token,
    pub(super) pktinfo: PktInfoUdpSocket,
    pub(super) readiness: mio::net::UdpSocket,
    /// The last pass stopped at `READ_BUDGET`: more may be waiting, and
    /// edge-triggered readiness won't announce it again.
    pub(super) pending: bool,
}

impl FamilySocket {
    pub(super) fn open(family: Family, registry: &mio::Registry) -> Option<Self> {
        let create = match family {
            Family::V4 => create_v4_socket,
            Family::V6 => create_v6_socket,
        };
        Self::open_with(family, registry, create)
    }

    /// `open` with the socket creator injected, so tests can fail it.
    pub(super) fn open_with(
        family: Family,
        registry: &mio::Registry,
        create: impl FnOnce() -> Result<PktInfoUdpSocket>,
    ) -> Option<Self> {
        let (label, token) = match family {
            Family::V4 => ("v4", V4_TOKEN),
            Family::V6 => ("v6", V6_TOKEN),
        };
        let opened = (|| -> Result<Self> {
            let pktinfo = create()?;
            let mut readiness = mio::net::UdpSocket::from_std(pktinfo.try_clone_std()?);
            registry.register(&mut readiness, token, mio::Interest::READABLE)?;
            Ok(Self {
                family,
                token,
                pktinfo,
                readiness,
                pending: false,
            })
        })();
        match opened {
            Ok(socket) => Some(socket),
            Err(e) => {
                log::error!("mex: {label} socket: {e}");
                None
            }
        }
    }
}

/// How one budgeted drain of a socket ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Drained {
    /// Read until `WouldBlock` (or an error): re-arm readiness.
    Empty,
    /// Stopped at the budget: more may be waiting.
    Budget,
    /// The event receiver is gone: the app has stopped.
    Closed,
}

/// One read attempt, as the drain sees it.
pub(super) enum ReadStep {
    /// A datagram was read and handled; keep going.
    Handled,
    /// Nothing more to read right now.
    WouldBlock,
    /// The event receiver is gone.
    Closed,
}

/// Read up to `budget` datagrams with `read`, stopping early on
/// `WouldBlock` or a closed receiver.
pub(super) fn drain_budgeted(budget: usize, mut read: impl FnMut() -> ReadStep) -> Drained {
    for _ in 0..budget {
        match read() {
            ReadStep::Handled => {}
            ReadStep::WouldBlock => return Drained::Empty,
            ReadStep::Closed => return Drained::Closed,
        }
    }
    Drained::Budget
}

/// Poll timeout: zero while a socket has unread datagrams left over
/// from its budget, else the time until the next interface refresh,
/// at least 1 ms so a due refresh never spins.
pub(super) fn poll_timeout(now: Instant, next_refresh: Instant, pending: bool) -> Duration {
    if pending {
        return Duration::ZERO;
    }
    next_refresh
        .saturating_duration_since(now)
        .max(Duration::from_millis(1))
}

/// mex can do nothing without a socket: with neither family open,
/// startup fails instead of running a listener that can never receive
/// (or shut down) while queries vanish. One open family is enough.
pub(super) fn require_transport(v4_open: bool, v6_open: bool) -> Result<()> {
    if v4_open || v6_open {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "no mDNS socket could be opened (neither IPv4 nor IPv6)"
        ))
    }
}

/// Queries sent per loop pass before the sockets get their turn, so a
/// burst of queries can't hold off reads (and overflow receive buffers).
pub(super) const QUERY_BUDGET: usize = 64;

/// What a query drain left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QueueState {
    /// Nothing waiting.
    Empty,
    /// The budget was reached; more may be waiting.
    More,
    /// The app dropped its `QueryTx`: the listener must stop.
    Closed,
}

/// Send queued batches until `budget` packets went out. `send` returns
/// how many packets a batch took; a batch counts at least one, so batches
/// that send nothing (every pin or send failed) can't drain the whole
/// queue in one pass. A batch is never split across passes, so one large
/// batch may overrun the budget once. Returns the packets
/// sent and what is left in the queue. Wakes may coalesce, so the queue
/// is drained on every pass.
pub(super) fn drain_queries<T>(
    rx: &mpsc::Receiver<T>,
    budget: usize,
    mut send: impl FnMut(&T) -> usize,
) -> (usize, QueueState) {
    let mut sent = 0;
    while sent < budget {
        match rx.try_recv() {
            Ok(batch) => {
                sent += send(&batch).max(1);
            }
            Err(mpsc::TryRecvError::Empty) => return (sent, QueueState::Empty),
            Err(mpsc::TryRecvError::Disconnected) => return (sent, QueueState::Closed),
        }
    }
    (sent, QueueState::More)
}

/// The kernel index of the link named `name`, as received packets carry
/// it (`ifnames` is the same map that names them), or 0 when unknown.
pub(super) fn link_index(ifnames: &HashMap<u32, String>, name: &str) -> u32 {
    ifnames
        .iter()
        .find_map(|(idx, n)| (n == name).then_some(*idx))
        .unwrap_or(0)
}

/// State the listener updates and the app thread reads.
pub(super) struct SharedWithApp {
    pub(super) drops: Arc<DropStats>,
    pub(super) transmit: Arc<TransmitState>,
    /// Kept open by the listener: a wake from the app's `QueryTx` drop
    /// would be lost if the drop closed the waker's last handle first.
    pub(super) waker: Arc<mio::Waker>,
    /// Where each sent query copy is reported (#431).
    pub(super) own_sends: mpsc::Sender<OwnSend>,
}

/// The single listener: one thread, one poll loop over both family
/// sockets and the query waker. Per-link state (interface lists, name
/// and subnet maps) is shared by both families and refreshed once per
/// `IFACE_REFRESH`, which also bounds the poll timeout: an idle network
/// wakes the thread once per refresh.
pub(super) struct Listener {
    pub(super) poll: mio::Poll,
    pub(super) v4: Option<FamilySocket>,
    pub(super) v6: Option<FamilySocket>,
    pub(super) tx: mpsc::Sender<Event>,
    pub(super) query_rx: mpsc::Receiver<QueryBatch>,
    pub(super) drops: Arc<DropStats>,
    pub(super) selection: Option<HashSet<String>>,
    pub(super) ifaces_v4: Vec<(String, Ipv4Addr)>,
    pub(super) ifaces_v6: Vec<(String, u32)>,
    pub(super) ifnames: HashMap<u32, String>,
    pub(super) subnets: SubnetMap,
    pub(super) unknown: HashSet<u32>,
    pub(super) next_refresh: Instant,
    /// The last pass stopped at `QUERY_BUDGET`: more may be queued,
    /// and the waker won't announce them again.
    pub(super) queries_pending: bool,
    pub(super) send_failures: SendFailures,
    /// Our own sent query copies, dropped when they loop back.
    pub(super) sent_copies: SentCopies,
    pub(super) transmit: Arc<TransmitState>,
    pub(super) own_sends: mpsc::Sender<OwnSend>,
    pub(super) buf: Vec<u8>,
    /// See `SharedWithApp::waker`.
    _waker: Arc<mio::Waker>,
}

impl Listener {
    pub(super) fn new(
        poll: mio::Poll,
        v4: Option<FamilySocket>,
        v6: Option<FamilySocket>,
        tx: mpsc::Sender<Event>,
        query_rx: mpsc::Receiver<QueryBatch>,
        shared: SharedWithApp,
        selection: Option<HashSet<String>>,
    ) -> Self {
        let SharedWithApp {
            drops,
            transmit,
            waker,
            own_sends,
        } = shared;
        Self {
            poll,
            v4,
            v6,
            tx,
            query_rx,
            drops,
            selection,
            ifaces_v4: Vec::new(),
            ifaces_v6: Vec::new(),
            ifnames: HashMap::new(),
            subnets: HashMap::new(),
            unknown: HashSet::new(),
            next_refresh: Instant::now(),
            queries_pending: false,
            send_failures: SendFailures::default(),
            sent_copies: SentCopies::default(),
            transmit,
            own_sends,
            buf: vec![0u8; 65535],
            _waker: waker,
        }
    }

    pub(super) fn run(&mut self) {
        let mut events = mio::Events::with_capacity(16);
        loop {
            if Instant::now() >= self.next_refresh {
                self.refresh();
                self.next_refresh = Instant::now() + IFACE_REFRESH;
            }
            if !self.send_queued() {
                return;
            }
            // Sockets left over from a budget-capped pass go first.
            for family in [Family::V4, Family::V6] {
                if self.socket(family).is_some_and(|s| s.pending) && !self.read_family(family) {
                    return;
                }
            }
            let pending = self.queries_pending
                || [&self.v4, &self.v6]
                    .into_iter()
                    .flatten()
                    .any(|s| s.pending);
            let timeout = poll_timeout(Instant::now(), self.next_refresh, pending);
            if let Err(e) = self.poll.poll(&mut events, Some(timeout)) {
                if e.kind() != std::io::ErrorKind::Interrupted {
                    log::error!("mex: poll error: {e}");
                    thread::sleep(Duration::from_secs(1));
                }
                continue;
            }
            for event in &events {
                let family = match event.token() {
                    V4_TOKEN => Family::V4,
                    V6_TOKEN => Family::V6,
                    // Queries are sent at the top of every pass.
                    _ => continue,
                };
                if !self.read_family(family) {
                    return;
                }
            }
        }
    }

    pub(super) fn socket(&self, family: Family) -> Option<&FamilySocket> {
        match family {
            Family::V4 => self.v4.as_ref(),
            Family::V6 => self.v6.as_ref(),
        }
    }

    /// Recompute both families' interface lists and the shared link
    /// maps, and (re)join the mDNS group on every listed link. Joins run
    /// unconditionally every pass: they are idempotent, and a rejoin is
    /// required after an interface went away and came back (same name,
    /// new incarnation).
    pub(super) fn refresh(&mut self) {
        log::debug!("mex: refreshing interface list");
        (self.ifnames, self.subnets) = link_maps();
        self.unknown.clear();
        if let Some(socket) = &self.v4 {
            self.ifaces_v4 = v4_interfaces(self.selection.as_ref());
            for (name, ip) in &self.ifaces_v4 {
                if let Err(e) = socket.pktinfo.join_multicast_v4(&MDNS_V4, ip) {
                    // Duplicate joins report AddrInUse; the membership
                    // is already in place, so only log real failures.
                    if e.kind() != std::io::ErrorKind::AddrInUse {
                        log::warn!("mex: v4 mcast {name}: {e}");
                    }
                }
            }
        }
        if let Some(socket) = &self.v6 {
            self.ifaces_v6 = v6_interfaces(self.selection.as_ref());
            for (name, idx) in &self.ifaces_v6 {
                if let Err(e) = socket.pktinfo.join_multicast_v6(&MDNS_V6, *idx) {
                    if e.kind() != std::io::ErrorKind::AddrInUse {
                        log::warn!("mex: v6 mcast {name}: {e}");
                    }
                }
            }
        }
        // Links gone from the lists forget their send-failure state.
        self.send_failures.retain_links(
            Family::V4,
            self.ifaces_v4.iter().map(|(name, _)| name.as_str()),
        );
        self.send_failures.retain_links(
            Family::V6,
            self.ifaces_v6.iter().map(|(name, _)| name.as_str()),
        );
        // A family with an open socket but no usable link sends nothing;
        // publish both families in one step and log each pause and
        // resume once.
        let v4 = self.v4.as_ref().map(|_| !self.ifaces_v4.is_empty());
        let v6 = self.v6.as_ref().map(|_| !self.ifaces_v6.is_empty());
        let transitions = self.transmit.update(v4, v6);
        for (family, transition) in [Family::V4, Family::V6].into_iter().zip(transitions) {
            let label = family.label();
            match transition {
                Some(PauseLog::Paused) => {
                    log::info!("mex: no usable {label} interface; {label} queries paused")
                }
                Some(PauseLog::Resumed) => {
                    log::info!("mex: {label} interface usable again; {label} queries resumed")
                }
                None => {}
            }
        }
    }

    /// Send queued queries (up to the budget) on each open family.
    /// Returns `false` when the app has stopped (its `QueryTx` is gone).
    pub(super) fn send_queued(&mut self) -> bool {
        let Self {
            v4,
            v6,
            query_rx,
            ifaces_v4,
            ifaces_v6,
            send_failures,
            sent_copies,
            own_sends,
            ifnames,
            ..
        } = self;
        let (_, queue) = drain_queries(query_rx, QUERY_BUDGET, |batch| {
            let mut packets = 0;
            for socket in [v4.as_ref(), v6.as_ref()].into_iter().flatten() {
                for sent in send_on_all_interfaces(
                    &socket.pktinfo,
                    batch,
                    socket.family,
                    ifaces_v4,
                    ifaces_v6,
                    send_failures,
                    sent_copies,
                ) {
                    let mut sent = sent;
                    if sent.ifindex == 0 {
                        sent.ifindex = link_index(ifnames, &sent.iface);
                    }
                    packets += 1;
                    // A closed channel means the app is gone; the closed
                    // query queue stops this loop right after.
                    let _ = own_sends.send(sent);
                }
            }
            packets
        });
        self.queries_pending = queue == QueueState::More;
        queue != QueueState::Closed
    }

    /// Drain one family's socket within the budget. Re-arms readiness
    /// once it is empty (as mdns-sd does; this keeps Windows readiness
    /// right too). Returns `false` when the app has stopped.
    pub(super) fn read_family(&mut self, family: Family) -> bool {
        let Some(mut socket) = (match family {
            Family::V4 => self.v4.take(),
            Family::V6 => self.v6.take(),
        }) else {
            return true;
        };
        let drained = drain_budgeted(READ_BUDGET, || self.read_one(&socket.pktinfo));
        socket.pending = drained == Drained::Budget;
        if drained == Drained::Empty {
            if let Err(e) = self.poll.registry().reregister(
                &mut socket.readiness,
                socket.token,
                mio::Interest::READABLE,
            ) {
                log::error!("mex: re-arming {family:?} socket: {e}");
            }
        }
        match family {
            Family::V4 => self.v4 = Some(socket),
            Family::V6 => self.v6 = Some(socket),
        }
        drained != Drained::Closed
    }

    /// Read and handle one datagram.
    pub(super) fn read_one(&mut self, socket: &PktInfoUdpSocket) -> ReadStep {
        let received = socket.recv(&mut self.buf);
        self.handle_recv(received)
    }

    /// Handle one recv result; a received datagram is in
    /// `self.buf[..len]`, with its ingress interface and addresses.
    pub(super) fn handle_recv(
        &mut self,
        received: std::io::Result<(usize, socket_pktinfo::PktInfo)>,
    ) -> ReadStep {
        let (len, info) = match received {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return ReadStep::WouldBlock,
            Err(e) => {
                // Stop this drain; readiness re-arms and the next datagram
                // announces itself.
                log::error!("mex: recv error: {e}");
                return ReadStep::WouldBlock;
            }
        };
        let raw = self.buf[..len].to_vec();
        // Our own query copy looping back (multicast loop is on so local
        // responders hear us): not a remote querier, drop it.
        if self.sent_copies.take(&raw, Instant::now()) {
            return ReadStep::Handled;
        }
        let ifindex = info.if_index as u32;
        if !self.ifnames.contains_key(&ifindex) || !self.subnets.contains_key(&ifindex) {
            // Stale maps (interface appeared mid-window) or an index
            // if-addrs never reports: re-query once instead of waiting
            // out the 10s refresh.
            backfill_link(
                ifindex,
                &mut self.ifnames,
                &mut self.subnets,
                &mut self.unknown,
                &link_maps,
            );
        }
        // RFC 6762 §11: multicast-destination packets are local
        // regardless of source; unicast-destination ones must come from
        // a local subnet, else silently discard (this is the spoof guard
        // for our QU unicast replies).
        if !mdns_multicast_dest(&info.addr_dst)
            && !source_on_link(&self.subnets, ifindex, &info.addr_src.ip())
        {
            self.drops.note(info.addr_src);
            return ReadStep::Handled;
        }
        let iface = self.ifnames.get(&ifindex).map(String::as_str).unwrap_or("");
        // Explicit selection drops off-selection ingress, including
        // unicast replies that bypass multicast group membership.
        if !interface_selected(iface, self.selection.as_ref()) {
            return ReadStep::Handled;
        }
        match parse_packet(&raw, info.addr_src, info.addr_dst, iface, ifindex) {
            Some(ev) => {
                if self.tx.send(ev).is_err() {
                    return ReadStep::Closed;
                }
            }
            None => self.drops.note_malformed(info.addr_src),
        }
        ReadStep::Handled
    }
}
