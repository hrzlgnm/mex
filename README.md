# mex

[![Scc Count Badge](https://sloc.xyz/github/hrzlgnm/mex)](https://github.com/hrzlgnm/mex)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/hrzlgnm/mex/total)
[![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/hrzlgnm/mex/latest/total)](https://github.com/hrzlgnm/mex/releases/latest)
[![GitHub Release](https://img.shields.io/github/v/release/hrzlgnm/mex)](https://github.com/hrzlgnm/mex/releases/latest)
[![GitHub Release Date](https://img.shields.io/github/release-date/hrzlgnm/mex)](https://github.com/hrzlgnm/mex/releases/latest)
[![AUR Version](https://img.shields.io/aur/version/mex)](https://aur.archlinux.org/packages/mex)
[![License: MIT](https://img.shields.io/github/license/hrzlgnm/mex)](https://github.com/hrzlgnm/mex/blob/main/LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/hrzlgnm/mex/ci.yml)](https://github.com/hrzlgnm/mex/actions)
[![Test Coverage](https://codecov.io/gh/hrzlgnm/mex/branch/main/graph/badge.svg)](https://codecov.io/gh/hrzlgnm/mex)

<p align="center">
  <img src="packaging/linux/mex.svg" width="128" height="128" alt="mex icon">
</p>

Terminal UI to browse and debug mDNS/DNS-SD on the local link — live
services, records, queries, and raw packets.

Built with Rust ([ratatui](https://ratatui.rs/), [crossterm](https://github.com/crossterm-rs/crossterm),
[simple-dns](https://github.com/balliegojr/simple-dns)). Listens
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
      --log-file <PATH>    Override the default log file (state-dir mex.log on Linux,
                           ~/Library/Logs/mex on macOS, %LOCALAPPDATA%\mex\logs on Windows).
                           Appended; rotated past 5 MiB with 3 backups kept. Without it,
                           both modes log to the default file; headless mode additionally
                           logs warnings to stderr.
      --log-level <LEVEL>  Minimum log level recorded by every active sink
                           (off, error, warn, info, debug, trace). Default: split
                           defaults (file info, stderr warn).
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
  `.local` stripped as redundant, hostname in *italic* as app-side
  grouping, not a wire record);
  each header shows `(service count) · primary address (+extra)` — e.g.
  `printer (2) · 192.168.1.10 (+1)` — with `(+N)` only when more
  than one live address is known. Each row shows `instance [short
  type:port]` (`http.tcp` is short for `_http._tcp.local`, e.g.
  `My Printer [http.tcp:9100]`) with the state dot
  up front. `Up`/`Down` skips open headers (collapsed ones stay
  selectable), the selection is inverted, and the pane title always names
  the selected row's host.
- **Right top — Answers.** For the selected service: derived rows
  (`srvc`, `subt`, in *italic* as constructed summaries, not wire
  records), then one row per observed raw record
  (one row per source and ingress link, sorted by type then source) with
  remaining TTL (heat-colored by requery schedule: yellow once past
  80% elapsed — a refresh is due — red past ~95% or expired), flush bit,
  source, and rdata. Multi-pair TXT records
  expand into unlabeled child rows. Records announced by this host are
  highlighted; goodbye (TTL 0) records show `bye` (dimmed, dark gray: a clean
  withdrawal) and expired ones `exp` (red) in TTL. Only the mDNS
  answer types A, AAAA, NS, CNAME, PTR, TXT, SRV, NSEC and HINFO become
  rows; see [Out-of-scope types](#out-of-scope-types). An address family
  the service's own responder denies with an NSEC (e.g. an IPv4-only
  service on a host that also has IPv6) shows no rows on that service;
  sibling services and the host header keep it.
- **Right middle — Questions.** Recently observed queries asking for this
  service, newest first, with per-query age instead of TTL. A row
  stays while its querier asked within the last 75 minutes (the long
  mDNS TTL), so steady queriers keep theirs; up to 100 per list.
  Only questions for A, AAAA, NS, CNAME, PTR, TXT, SRV, HINFO and ANY
  become rows.
  Questions from this host are highlighted like local records.
  Queriers asking from an ephemeral port ([RFC 6762 §5.1](https://www.rfc-editor.org/rfc/rfc6762#section-5.1)) are tagged
  `(one-shot)`: stub resolvers, not full continuous queriers.
- **Device names.** A source address is named after the device that
  announces it: `192.168.178.109:5353 (FritzBoxRepeater)`. The name
  comes from a live A/AAAA record carrying that address (the device's
  own announcement wins over a proxy's), shortened to its first label.
  An IPv6 link-local source that no record names exactly is matched by
  its interface ID against the device's global/ULA AAAA and marked
  inferred (`(~fritz)`). Unannounced addresses stay bare. Queriers and
  block / `(unattributed)` finding rows are always named; answer rows
  only when the responder is not the service's own host. Dumps carry every candidate name
  (`source_names`, `source_name_inferred`).
- **Right bottom — Hex.** Wire bytes of the selected record or question
  packet, falling back to the service's latest packet. `Tab` focuses it
  for scrolling.
- **Mouse.** Drag the shared pane borders to resize Hosts vs detail and
  Answers / Questions / Hex (the seam lights up). Click a row to
  focus its pane and move the cursor there; clicking a host header
  folds it. While mouse input is captured, use Shift+drag to select
  text in most terminals.

## Keys

| Key | Action |
| --- | ------ |
| `Tab` / `Shift+Tab` | switch pane (Hosts → Answers → Questions → Hex) |
| `Up` / `Down`, `j` / `k` | move within the focused pane (scroll Hex when focused) |
| `h` / `l`, `←` / `→` | jump between host groups |
| `H` / `L` | first / last host group |
| `Home` / `End` | first / last row of the focused pane (top / bottom of Hex) |
| `PageUp` / `PageDown`, `b` / `f`, `Space` | page (viewport scroll in Hex) |
| `Enter` | fold / unfold host (Hosts) or TXT record (Answers) |
| `+` / `-` | fold / unfold host (Hosts) |
| `r` | send the `self` question under the cursor now (Questions; its LAST then reads `manual`; QM, at most once per second per question, never in passive mode) |
| `*` | collapse all host groups / unfold all |
| `Ctrl+↑/↓`, `Ctrl+k`, `Shift+↑/↓`, `J` / `K` | scroll Answers viewport freely (Hex viewport when Hex focused) |
| `Ctrl+J` | dump mex state to JSON, `<timestamp>-mex-<version>.json` (experimental; redaction is heuristic, review before sharing) |
| `d` | diagnostics overlay (traffic, discovery, queries, links, process) |
| `q` / `Esc` / `Ctrl+C` | quit (`d` / `Esc` closes the overlay first) |
| `Ctrl+Z` (unix) | suspend to shell (`fg` resumes) |
| mouse drag on pane borders | resize panes |
| mouse click | focus pane + move cursor (host header folds) |
| mouse wheel | move cursor one row / scroll one line (focused pane; overlay when open) |

The header always shows the live hints. In the diagnostics overlay, `j`/`k`
and paging keys scroll instead, and `Tab`/`Enter` do nothing.

## Anomalies

mex continuously checks observed traffic against the mDNS/DNS-SD RFCs
and surfaces each deviation as an anomaly with a severity:

- **error** — a definite RFC violation in confirmed packet context
  (e.g. a shared record with the cache-flush bit set, an ANY record in
  a response).
- **warning** — a likely misconfiguration (e.g. a `.local` service with
  no address records, a subtype listed in service enumeration, an SOA
  sent as a unicast-style negative answer).
- **info** — a SHOULD-level deviation or an observation (e.g. a PTR
  re-announced with a 120 s TTL instead of the recommended 4500 s, a
  unique record missing its cache-flush bit, an SRV target outside
  `.local`, a question for SOA).

Findings sit next to their owner:

- A record's findings follow its Answers row as child rows (before any
  TXT pairs, never folded by `Enter`); the row itself carries the level
  icon of its worst finding, severity-colored, on the TTL cell for TTL
  kinds and on the type cell otherwise. Goodbye and expired rows carry
  neither. A record announced from several sources (IPv4 and IPv6, or
  several interfaces) carries its findings on each source's row.
- Findings about the service as a whole sit in a `service` block at the
  top of the Answers pane (an `enumeration` block on the enumeration
  entry); findings owned by the service's host sit in a `host <name>`
  block, on every service of that host.
- Findings with no owner (no service, host or enumeration entry matches)
  are listed under an `(unattributed)` Hosts-pane entry, grouped by
  name, shown only while such findings exist.
- The cursor skips finding rows and blocks.
- Hosts-pane instances and `[enum]` carry a `[<worst icon> N]` badge
  counting every finding, info included; host headers and
  `(unattributed)` carry one for their own findings, counted once.
- The Answers and Questions pane titles append `· <worst icon> N` for
  the findings they show.

A finding row reads `<kind> <record>: <message> (<rfc>, <requirement>)`
— the requirement is omitted when the cited text has no RFC 2119 keyword,
the level icon carries the severity (no severity word), and
enumeration-row findings omit their constant scope. Under its record or
question, a finding row starts in the second column (TTL / LAST) and
repeats neither the source nor the icon: the parent row shows both. In
`service` / `host` blocks and the `(unattributed)` view, where no parent
row names the responder, it shows `<icon>` and the announcer/querier
(with its device name) in the source column. The diagnostics overlay
(`d`) shows only a session-wide summary (`N error · N warning · N info`);
`Ctrl+J` state dumps include the full list. A question that asks for a
name shared by several services (e.g. an SRV target) shows on each of
their panes, but the summary and the dump count it once
(`also_services`).

Omitting A/AAAA records from PTR/SRV replies is not flagged.
`unresolved-srv-target` reports outcomes of transmitted address queries for live
SRV targets on each mDNS interface (warning when NSEC denies both A and AAAA,
info for inconclusive lookups).

| Finding | Meaning |
| --- | --- |
| `type-format` (warning) | malformed service type, subtype, or enumerated type ([RFC 6763 §7](https://www.rfc-editor.org/rfc/rfc6763#section-7), MUST) |
| `enum-subtype` (warning) | subtype listed in service enumeration instead of a base type ([RFC 6763 §9](https://www.rfc-editor.org/rfc/rfc6763#section-9)) |
| `conflicting-answers` (warning: cache-flush bit or mDNS domain, info: shared records elsewhere) | responders on one link announce different live A or AAAA sets for a hostname a service points at; sources with identical sets count as one responder (one device on several transports), as do sources answering from an address the hostname announces on that link (one host with several NICs, answering per interface: [RFC 6762 §6.2](https://www.rfc-editor.org/rfc/rfc6762#section-6.2), [§14](https://www.rfc-editor.org/rfc/rfc6762#section-14)), and each group is named after its device; owned by the host ([RFC 6762 §9](https://www.rfc-editor.org/rfc/rfc6762#section-9)) |
| `shared-flush` (error) | shared PTR record with the cache-flush bit set ([RFC 6762 §10.2](https://www.rfc-editor.org/rfc/rfc6762#section-10.2), MUST NOT) |
| `no-flush` (warning when confirmed, else info) | unique SRV/TXT record missing the cache-flush bit ([RFC 6762 §10.2](https://www.rfc-editor.org/rfc/rfc6762#section-10.2), MUST when confirmed); confirmed in the answer or additional section of any response mex receives, including unicast replies, since mex only listens on port 5353 and so never gets legacy unicast responses ([RFC 6762 §6.7](https://www.rfc-editor.org/rfc/rfc6762#section-6.7)) |
| `unicast-style-response` (error, warning or info) | an mDNS response carrying unicast DNS-style records, one finding per record, naming its section: ANY is error (a query type, never a record type, [RFC 1035 §3.2.3](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.3)); SOA in the Authority section is a warning (a unicast-style negative answer, where mDNS uses NSEC, [RFC 6762 §6.1](https://www.rfc-editor.org/rfc/rfc6762#section-6.1)); other SOA is a warning for names in mDNS domains (`.local` and the link-local reverse zones; mDNS zones have none, [RFC 6762 §12](https://www.rfc-editor.org/rfc/rfc6762#section-12)) and info for names outside them, such as a router's `fritz.box` zone ([RFC 6762 §3](https://www.rfc-editor.org/rfc/rfc6762#section-3)); known answers are always info. State dumps add `section` and, when a question for the same name was seen up to 1 s before, `in_response_to` (`name TYPE`) and `in_response_to_own` (whether this mex instance asked) |
| `unsupported-type` (warning; known answers info) | an mDNS response carrying any other out-of-scope record type (MX, unknown `TYPEnn`, …); DNS-SD over mDNS uses only the in-scope types ([RFC 6763 §12](https://www.rfc-editor.org/rfc/rfc6763#section-12)); state dumps add `section` and `in_response_to` like `unicast-style-response` |
| `nsec-inverted-bitmap` (info) | an NSEC owned by a service instance whose bitmap lists only the *missing* address types (older python-zeroconf); RFC 6762 §6.1 has the bitmap list the types that exist ([RFC 6762 §6.1](https://www.rfc-editor.org/rfc/rfc6762#section-6.1)); mex still honours it as an address denial |
| `unsupported-question` (info) | multicast question for an out-of-scope type: SOA never exists in mDNS ([RFC 6762 §12](https://www.rfc-editor.org/rfc/rfc6762#section-12)), others are outside mDNS scope ([RFC 6763 §12](https://www.rfc-editor.org/rfc/rfc6763#section-12)); asking is compliant, since [RFC 6762 §3](https://www.rfc-editor.org/rfc/rfc6762#section-3) requires `.local` queries on multicast; ANY questions are ownership probes and stay quiet; ephemeral-port queriers are tagged one-shot |
| `query-rate-limit` (warning) | a querier on port 5353 asked the same question on one link again less than a second later, within the retained packets; the message gives the count and the shortest gap ([RFC 6762 §5.2](https://www.rfc-editor.org/rfc/rfc6762#section-5.2), MUST: at least 1 s, then doubling; only the 1 s floor is checked); probes and one-shot queriers stay quiet |
| `multicast-rate-limit` (warning) | a responder multicast the same record on one link again less than a second later, within the retained packets ([RFC 6762 §6](https://www.rfc-editor.org/rfc/rfc6762#section-6), MUST NOT); each repeat renews the cached row, so its TTL never counts down and its refresh never fires. Sits on the record's Answers row in every service it is filed under; the message gives the count, the shortest gap and, when one was seen just before, the question and querier the repeats most likely answered (a querier known as a device is named as that device with every address it asked from, so one host asking over IPv4 and IPv6 reads the same; an unknown one by the copy's own address family first). "The same record" folds the case of names, name-valued rdata included, and compares out-of-scope records by a digest of their content. Unicast replies and goodbyes stay quiet; an answer to a probe may come early, but the next copy must still wait a second after it |
| `query-aa-bit` (warning) | a querier set the Authoritative Answer bit in a query, within the retained packets; the message gives how many of that question's queries carried it ([RFC 6762 §18.4](https://www.rfc-editor.org/rfc/rfc6762#section-18.4), MUST be zero in queries; receivers ignore it). Probes and one-shot queriers are held to it too; responses never raise it |
| `misplaced-known-answer` (warning) | a querier put known answers (records answering its question) in its query's Additional section, within the retained packets; known answers belong in the Answer section, so responders don't suppress on them and answer anyway ([RFC 6762 §7.1](https://www.rfc-editor.org/rfc/rfc6762#section-7.1)). The message names the record and counts the queries; EDNS0 OPT and probes never raise it |
| `ttl-low` / `ttl-high` (warning) | TTL below 10 s (churn risk) or above 7200 s (stale-cache risk) ([RFC 6762 §10](https://www.rfc-editor.org/rfc/rfc6762#section-10), SHOULD) |
| `ttl-mismatch` (info) | service PTR at ≤ 120 s instead of the recommended 4500 s base ([RFC 6762 §10](https://www.rfc-editor.org/rfc/rfc6762#section-10), SHOULD) |
| `ttl-unstable` (warning) | same name and type announced with different TTL bases ([RFC 6762 §10](https://www.rfc-editor.org/rfc/rfc6762#section-10)) |
| `srv-target` (warning: malformed, info: target needs unicast DNS or is `.`) | SRV target malformed (MUST), resolving outside mDNS, or `.` (service decidedly not available) ([RFC 2782](https://www.rfc-editor.org/rfc/rfc2782)) |
| `txt-oversize` (warning) | TXT RDATA (wire bytes) over 1300 B, risking fragmentation ([RFC 6763 §6.2](https://www.rfc-editor.org/rfc/rfc6763#section-6.2), SHOULD NOT) |

### Out-of-scope types

mex supports a fixed set of mDNS types:

- **Answers:** A, AAAA, NS, CNAME, PTR, TXT, SRV, NSEC (negative
  answers, [RFC 6762 §6.1](https://www.rfc-editor.org/rfc/rfc6762#section-6.1))
  and HINFO (Avahi publishes it with `publish-hinfo=yes`).
- **Questions:** A, AAAA, NS, CNAME, PTR, TXT, SRV, HINFO and ANY.

Every other type is out of scope. Such a record or question (including
a known answer carried in a query, whose finding names the Known-Answer
section and stays info) never becomes an Answers or Questions row; it
is kept only as evidence for a `unicast-style-response`,
`unsupported-type` or `unsupported-question` finding, owned by the name
it was seen for: a service instance, or a hostname (any live SRV target)
once for all services on that host, or `unattributed` when nothing
matches (e.g. a router's `fritz.box.` SOA before any service points at
it). Ownership is resolved live, so a service that appears later claims
its host's earlier sightings for that host. Out-of-scope types are named only by number
(`TYPE6` for SOA, `TYPE15` for MX), and their rdata is never decoded,
so a malformed one cannot drop the rest of its packet: mex keeps only
its length (`rdlength=<n>`). A record finding lives for its TTL and is
cleared by a goodbye; repeated records from the same source in the same
section (e.g. SOA serial bumps) stay one finding, while each responder
keeps its own, named with its interface like an Answers row
(`169.254.1.1:5353@enp0s25`). Findings from known
answers are always info, and a known answer's TTL (the querier's
remaining one) gets no TTL checks. EDNS0 OPT pseudo-records are not records and
are ignored. At most 256 sightings are kept; the diagnostics overlay counts
evictions.

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

**Subtypes of quiet publishers can remain hidden.** DNS-SD has no query
that enumerates a service type's subtypes, so mex learns a subtype (e.g.
`_printer._sub._http._tcp`) only from traffic: the publisher's
announcement, another client's subtype query or response, or a service
enumeration that lists it (non-standard, flagged as `enum-subtype`).

Start mex before the publisher, or trigger subtype traffic. Once seen,
the subtype is refreshed like any other record.
