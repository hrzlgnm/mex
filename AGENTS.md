# AGENTS.md — mex

## Build & check

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

No codegen, no external commands. Multicast sockets need no root.
Headless run (no TTY) logs to stderr.

## Layout

* `src/main.rs` — entry, TUI init/restore.
* `src/browse.rs` — raw mDNS transport: v4/v6 sockets on `224.0.0.251:5353` /
  `[FF02::FB]:5353` via `socket-pktinfo`, `send_query` (QM/QU + known
  answers, one copy per interface), packet parse with ingress interface.
  Down, point-to-point, `lo`/`docker`/`veth` interfaces are skipped,
  unless explicitly selected via `-i/--interfaces` (user intent wins;
  selected-but-down links wait for the rejoin refresh).
  Multicast loop disabled; unicast-dst packets from off-link subnets are
  refused (RFC 6762 §11) with a metrics counter.
* `src/app.rs` — browser state, query scheduling, ingest/expire, selection.
* `src/ui.rs` — ratatui rendering only, no state mutations.

## Query scheduling (RFC 6762 §5.2, §5.4, §7.1)

* Continuous browsing (`App::continuous`): first query after 20–120ms random,
  then ≥1s, doubling each time, capped at 1/hour. No fixed 60s re-poll.
* Cache refresh (`App::requeries`): re-ask at ~80/85/90/95% of TTL with 0–2%
  random variation; after four misses the record expires at 100% TTL.
  Hourly is only the cap for unanswered continuous browsing.
* Known-answer suppression is PTR-only (shared records, §7.1): only answers
  with ≥half the original TTL remaining, sent with remaining TTL, scoped to
  the egress interface.
* QU bit only on the startup enumeration batch; everything else is QM.
* A/AAAA query names keep wire case; dedup keys are lowercase.
* No queries for dead interests: `evict_expired` prunes `continuous`,
  `requeries`, `enum_known`, `known_types` to live names.
* Records show the ingress interface (`%iface` for IPv6 link-local,
  `@iface` otherwise) from IP_PKTINFO.
* Unique answers (flush bit) dampen the exponential stream to hourly;
  the 80%-TTL refresh takes over.

## Workflow

* Changes land via pull requests against `main`; never push to `main` directly.
* Create branches from `origin/main` (`git fetch origin` first).
* Commit messages must follow Conventional Commits (`feat:`, `fix:`, `docs:`,
  …): release-please owns the changelog and derives releases from them.

## Conventions

* `cargo fmt` before commit; clippy with `-D warnings` must pass.
* Prefer editing existing files; no new deps without need
  (`hickory-proto` uses the `mdns` feature for the QU bit).
* Random jitter uses the std-only `rand_u32` helper in `app.rs`.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues (via `gh`). See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context: `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
