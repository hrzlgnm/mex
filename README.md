# mex

[![Scc Count Badge](https://sloc.xyz/github/hrzlgnm/mex)](https://github.com/hrzlgnm/mex)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/hrzlgnm/mex/total)
[![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/hrzlgnm/mex/latest/total)](https://github.com/hrzlgnm/mex/releases/latest)
[![GitHub Release](https://img.shields.io/github/v/release/hrzlgnm/mex)](https://github.com/hrzlgnm/mex/releases/latest)
[![GitHub Release Date](https://img.shields.io/github/release-date/hrzlgnm/mex)](https://github.com/hrzlgnm/mex/releases/latest)
[![AUR Version](https://img.shields.io/aur/version/mex)](https://aur.archlinux.org/packages/mex)
[![License: MIT](https://img.shields.io/github/license/hrzlgnm/mex)](https://github.com/hrzlgnm/mex/blob/main/LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/hrzlgnm/mex/ci.yml)](https://github.com/hrzlgnm/mex/actions)

<p align="center">
  <img src="packaging/linux/mex.svg" width="128" height="128" alt="mex icon">
</p>

Terminal UI to browse and debug mDNS/DNS-SD on the local link — live
services, records, queries, and raw packets.

Built with Rust ([ratatui](https://ratatui.rs/), [crossterm](https://github.com/crossterm-rs/crossterm),
[hickory-proto](https://github.com/hickory-dns/hickory-dns)). Listens
passively on UDP port 5353 (IPv4 + IPv6 multicast) and also sends the
standard browse queries (service enumeration, PTR/SRV/TXT/A/AAAA).

## Contents

- [Install](#install)
- [Usage](#usage)
- [Layout](#layout)
- [Keys](#keys)
- [Anomalies](#anomalies)
- [Build & run](#build--run)
- [Known limitations](#known-limitations)

## Install

Prebuilt binaries are attached to
[GitHub releases](https://github.com/hrzlgnm/mex/releases): Linux
binaries (x86_64 glibc + musl static) and macOS DMGs (Apple Silicon +
Intel). On Arch Linux, install from the
[AUR](https://aur.archlinux.org/packages/mex) instead:

```sh
yay -S mex
```

On macOS, install via [Homebrew](https://brew.sh/):

```sh
brew tap hrzlgnm/tap
brew install --cask mex
```

Or directly without tapping:

```sh
brew install --cask hrzlgnm/tap/mex
```

## Usage

```sh
mex [OPTIONS]

Options:
      --passive            Listen only: never transmit queries, just observe announcements
  -i, --interfaces <IFACES>  Network interfaces to use for mDNS discovery (e.g., br0, eth0)
  -h, --help               Print help
  -V, --version            Print version
```

With `--passive`, mex transmits nothing: no startup QU batch, no continuous
queries, no TTL refreshes — the view shows recently heard traffic
decaying by TTL instead of actively maintained state.

With `-i/--interfaces`, mex joins, queries, and ingests only the named
links (repeatable and comma-separated: `-i br0,eth0`). Unknown names abort
at startup with the available list; an explicit selection overrides the
default loopback/container skip. Without the flag, all usable links are
browsed as before.

## Layout

- **Left — Hosts.** Collapsible tree grouped by hostname (`printer`,
  `.local` stripped as redundant);
  each header shows `(service count) · primary address (+extra)` — e.g.
  `printer (2) · 192.168.1.10 (+1)` — with `(+N)` only when more
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
  packet, falling back to the service's latest packet. `Tab` focuses it
  for scrolling.
- **Mouse.** Drag the shared pane borders to resize Hosts vs detail and
  Answers / Questions / Anomalies / Hex (the seam lights up). Click a row to
  focus its pane and move the cursor there; clicking a host header
  folds it. While mouse input is captured, use Shift+drag to select
  text in most terminals.

## Keys

| Key | Action |
| --- | ------ |
| `Tab` / `Shift+Tab` | switch pane (Hosts → Answers → Questions → Anomalies → Hex) |
| `Up` / `Down`, `j` / `k` | move within the focused pane (scroll Hex / Anomalies when focused) |
| `h` / `l`, `←` / `→` | jump between host groups |
| `H` / `L` | first / last host group |
| `Home` / `End` | first / last row of the focused pane (top / bottom of Hex) |
| `PageUp` / `PageDown`, `b` / `f`, `Space` | page (viewport scroll in Hex) |
| `Enter` | fold / unfold host (Hosts) or TXT record (Answers) |
| `+` / `-` | fold / unfold host (Hosts) |
| `*` | collapse all host groups / unfold all |
| `Ctrl+↑/↓`, `Ctrl+k`, `Shift+↑/↓`, `J` / `K` | scroll Answers viewport freely (Hex viewport when Hex focused) |
| `Ctrl+J` | dump mex state to JSON, `<timestamp>-mex-dump.json` (experimental; tokens, public URLs/hosts redacted) |
| `m` | metrics overlay (traffic, discovery, queries, links) |
| `q` / `Esc` / `Ctrl+C` | quit (`m` / `Esc` closes the overlay first) |
| `Ctrl+Z` (unix) | suspend to shell (`fg` resumes) |
| mouse drag on pane borders | resize panes |
| mouse click | focus pane + move cursor (host header folds) |
| mouse wheel | move cursor one row / scroll one line (focused pane; overlay when open) |

The header always shows the live hints. In the metrics overlay, `j`/`k`
and paging keys scroll instead, and `Tab`/`Enter` do nothing.

## Anomalies

mex continuously checks observed traffic against the mDNS/DNS-SD RFCs
and surfaces each deviation as an anomaly with a severity:

- **error** — a definite RFC violation in confirmed packet context
  (e.g. a shared record with the cache-flush bit set, NS/SOA answered
  in a multicast answer section).
- **warning** — a likely misconfiguration (e.g. a `.local` service with
  no address records, a subtype listed in service enumeration).
- **info** — a SHOULD-level deviation, shown only in the metrics
  overlay and state dumps (e.g. a PTR re-announced with a 120 s TTL
  instead of the recommended 4500 s, a unique record missing its
  cache-flush bit, an SRV target outside `.local`).

Findings show up in several places: anomalous Answers rows get a `!`
marker (on the type cell, or on the TTL cell when the TTL itself is
the problem), anomalous Questions rows get one on the type, instances
carry a `[!N]` badge in the Hosts pane, and the Anomalies pane lists
every finding for the selected service with a `>` marker on the
highlighted row's findings. The metrics overlay (`m`) lists all
findings with severity icons, and `Ctrl+J` state dumps include the
full list.

| Finding | Meaning |
| --- | --- |
| `missing-addr` (warning: `.local`, info: otherwise) | hostname with a live SRV record but no live A/AAAA (RFC 6763 §12, SHOULD) |
| `type-format` (warning) | malformed service type, subtype, or enumerated type (RFC 6763 §7, MUST) |
| `enum-subtype` (warning) | subtype listed in service enumeration instead of a base type (RFC 6763 §9, SHOULD) |
| `shared-flush` (error) | shared PTR record with the cache-flush bit set (RFC 6762 §10.2, MUST NOT) |
| `unique-no-flush` (warning when confirmed, else info) | unique SRV/TXT record missing the cache-flush bit (RFC 6762 §10.2, SHOULD); confirmed only in a multicast answer |
| `unicast-leak` (error when confirmed, else warning) | NS/SOA/ANY/MX outside unicast DNS (RFC 6762 §3); confirmed only in a multicast answer, otherwise pending capture verification |
| `unicast-question` (error: NS/SOA, warning: MX) | multicast question asking for a unicast-only type (RFC 6762 §3); ANY questions are ownership probes and stay quiet |
| `ttl-low` / `ttl-high` (warning) | TTL below 10 s (churn risk) or above 7200 s (stale-cache risk) (RFC 6762 §5.2, SHOULD) |
| `ttl-mismatch` (info) | service PTR at ≤ 120 s instead of the recommended 4500 s base (RFC 6762 §10, SHOULD) |
| `ttl-unstable` (warning) | same name and type announced with different TTL bases (RFC 6762 §5.2, SHOULD) |
| `srv-target` (warning: malformed, info: outside `.local`) | SRV target malformed (MUST) or requiring resolution outside mDNS (MAY) (RFC 6763 §12) |
| `txt-oversize` (warning) | TXT payload over ~1300 B, risking fragmentation (RFC 6762 §17, SHOULD) |

Reverse-mapping PTRs (`*.in-addr.arpa`, `*.ip6.arpa`) are exempt from
the shared-record rules: they are unique records. Omitting the flush
bit on A/AAAA records and publishing TXT records at 120 s are
universal practice and stay quiet.

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
