# mex

A terminal UI for browsing mDNS (Multicast DNS / DNS-SD) traffic on the local
network: services, their records, who is asking, and the raw packets behind
it all.

Built with Rust ([ratatui](https://ratatui.rs/), [crossterm](https://github.com/crossterm-rs/crossterm),
[hickory-proto](https://github.com/hickory-dns/hickory-dns)). Listens
passively on UDP port 5353 (IPv4 + IPv6 multicast) and also sends the
standard browse queries (service enumeration, PTR/SRV/TXT/A/AAAA).

## Layout

- **Left — Services.** Collapsible tree grouped by service type
  (`http.tcp` is short for `_http._tcp.local`), instances below it.
- **Right top — Records.** For the selected service: derived rows
  (`SRVC`, `SUBT`, `HOST`, `QRY`), then one row per observed raw record
  (deduplicated across responders, sorted by type then source) with
  remaining TTL, flush bit, source, and rdata. Multi-pair TXT records
  expand inline into child rows. Locally published records are highlighted.
  Goodbyes (TTL 0) and observed questions show up here too.
- **Right bottom — Hex.** Wire bytes of the selected record or query
  packet, falling back to the service's latest packet.

## Keys

| Key                    | Action                              |
| ---------------------- | ----------------------------------- |
| `Up` / `Down`          | select service (skips open headers) |
| `j` / `k`              | select record row                   |
| `Space` / `Enter`      | fold / unfold                       |
| `←` / `→`              | collapse / expand                   |
| `q` / `Esc` / `Ctrl+C` | quit                                |

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
