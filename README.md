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
| `c` / `R`              | clear services / clear packet log   |
| `q` / `Esc` / `Ctrl+C` | quit                                |

## Build & run

```sh
cargo build
./target/debug/mex
```

Requires the `ip` command (interface enumeration) on Linux. No root needed.
Without a TTY it runs headless and logs to stderr.
