# mex

A terminal UI for browsing mDNS (Multicast DNS / DNS-SD) traffic on the local
network: services, their records, who is asking, and the raw packets behind
it all.

Built with Rust ([ratatui](https://ratatui.rs/), [crossterm](https://github.com/crossterm-rs/crossterm),
[hickory-proto](https://github.com/hickory-dns/hickory-dns)). Listens
passively on UDP port 5353 (IPv4 + IPv6 multicast) and also sends the
standard browse queries (service enumeration, PTR/SRV/TXT/A/AAAA).

## Usage

```sh
mex [OPTIONS]

Options:
      --passive  Listen only: never transmit queries, just observe announcements
  -h, --help     Print help
  -V, --version  Print version
```

Prebuilt Linux binaries (x86_64 glibc + musl static) are attached to
[GitHub releases](https://github.com/hrzlgnm/mex/releases). On Arch Linux,
install from the [AUR](https://aur.archlinux.org/packages/mex) instead:

```sh
yay -S mex
```
With
`--passive`, mex transmits nothing: no startup QU batch, no continuous
queries, no TTL refreshes — the view shows recently heard traffic
decaying by TTL instead of actively maintained state.

## Layout

- **Left — Hosts.** Collapsible tree grouped by hostname (`printer.local`);
  each header shows `(service count) · primary address (+extra)` — e.g.
  `printer.local (2) · 192.168.1.10 (+1)` — with `(+N)` only when more
  than one live address is known. Each row shows `instance [short
  type:port]` (`http.tcp` is short for `_http._tcp.local`, e.g.
  `My Printer [http.tcp:9100]`) with the state dot
  up front. `Up`/`Down` skips open headers (collapsed ones stay
  selectable), the selection is inverted, and the pane title always names
  the selected row's host.
- **Right top — Answers.** For the selected service: derived rows
  (`srvc`, `subt`), then one row per observed raw record
  (deduplicated across responders, sorted by type then source) with
  remaining TTL (heat-colored by requery schedule: yellow once past
  80% elapsed — a refresh is due — red past ~95% or expired), flush bit,
  source, and rdata. Multi-pair TXT records
  expand into unlabeled child rows. Records announced by this host are
  highlighted; goodbye (TTL 0) records show as expired.
- **Right middle — Questions.** Recently observed queries asking for this
  service, newest first (capped), with per-query age instead of TTL.
  Questions from this host are highlighted like local records.
- **Right bottom — Hex.** Wire bytes of the selected record or question
  packet, falling back to the service's latest packet.

## Keys

| Key | Action |
| --- | ------ |
| `Tab` / `Shift+Tab` | switch pane (Hosts → Answers → Questions) |
| `Up` / `Down`, `j` / `k` | move within the focused pane |
| `h` / `l`, `←` / `→` | jump between host groups |
| `H` / `L` | first / last host group |
| `Home` / `End` | first / last row of the focused pane |
| `PageUp` / `PageDown`, `b` / `f`, `Space` | page |
| `Enter` | fold / unfold host (Hosts) or TXT record (Answers) |
| `+` / `-` | fold / unfold host (Hosts) |
| `*` | collapse all host groups / unfold all |
| `Ctrl+↑/↓`, `Ctrl+j/k`, `Shift+↑/↓`, `J` / `K` | scroll Answers viewport freely |
| `m` | metrics overlay (traffic, discovery, queries, links) |
| `q` / `Esc` / `Ctrl+C` | quit (`m` / `Esc` closes the overlay first) |

The header always shows the live hints. In the metrics overlay, `j`/`k`
and paging keys scroll instead, and `Tab`/`Enter` do nothing.

## Build & run

```sh
cargo build
./target/debug/mex
```

Requires no external commands — interface enumeration goes through the
`if-addrs` crate. No root needed. Without a TTY it runs headless and logs
to stderr.

## Known limitations

**Quiet publishers' subtypes are undiscoverable.** A service subtype (e.g.
`_magic._sub._test._tcp`) can only be learned two ways: from a
`_services._dns-sd._udp` enumeration that lists it, or by overhearing
subtype traffic (startup announcements, someone else's subtype
queries/responses). Some responders (e.g. avahi) do not list subtypes in
their enumeration answers, and there is no DNS query that enumerates
_unknown_ subtype labels. So if mex starts after such a publisher has gone
quiet, it shows the service but not its subtype; starting mex first (or
any subtype traffic while it runs) picks it up normally via the
announcement burst. Once learned, subtype enumerations are re-queried to
stay fresh.
