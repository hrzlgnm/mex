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
* `src/logging.rs` — the logger: stderr/file sink, size-rotated log file,
  `take_log_error` for the TUI status line.
* `src/browse.rs` — raw mDNS transport: v4/v6 sockets on `224.0.0.251:5353` /
  `[FF02::FB]:5353` via `socket-pktinfo`, `send_query` (QM/QU + known
  answers, one copy per interface), packet parse with ingress interface.
  One listener thread drives both sockets from a `mio` poll loop
  (readiness via a duplicate handle, reads via pktinfo, drained with a
  per-pass budget, then re-armed); `QueryTx::send` wakes it, queued queries
  are sent with a per-pass budget too, and the poll timeout is the 10 s
  interface refresh. The v6 socket is v6-only. Startup fails only when
  neither family's socket opens.
  Down, point-to-point, `lo`/`docker`/`veth` interfaces are skipped,
  unless explicitly selected via `-i/--interfaces` (user intent wins;
  selected-but-down links wait for the rejoin refresh). A family with no
  usable link sends nothing (no unpinned fallback); its pause and resume
  are logged once each.
  Multicast loop enabled, so responders on this host (avahi,
  python-zeroconf) hear our queries; our own looped-back query copies are
  dropped by exact bytes (`SentCopies`, one drop per sent copy). The
  loopback interface stays out unless selected with `-i`. Unicast-dst
  packets from off-link subnets are refused (RFC 6762 §11) with a metrics
  counter.
  Only in-scope types (`anomalies::is_mdns_answer_type` /
  `is_mdns_question_type`) are decoded or named; every other record keeps
  just `rdlength=<n>` (on-wire RDLENGTH) and renders as `TYPEnn`; the
  packet walk relabels them opaque before `Packet::parse`, so their rdata
  is never decoded. EDNS0 OPT pseudo-records are skipped entirely.
  Child modules: `iface` (interface discovery and `-i` selection),
  `listener` (sockets, mio loop, budgets), `send` (query encoding,
  per-interface sending, `SentCopies`), `wire` (packet walk, record and
  question rows, field extraction, type names). `browse.rs` keeps the
  shared types (`RawRecord`, `Event`, `QueryTx`, `TransmitState`,
  `DropStats`) and `spawn`, and re-exports the public API at its old
  paths.
* `src/app.rs` — browser state, query scheduling, ingest/expire, selection.
  Out-of-scope records, known answers and questions go to `sightings`
  (never rows, never query drivers; capped, expired by TTL/time), with
  owners resolved at analysis time: instance names to their service,
  hostnames once to the host (`anomalies::host_id`), shown in every
  sibling service's pane.
  NSEC address denials (`address_denials`): a hostname NSEC arriving with
  a service's SRV (RFC form) or an instance NSEC listing only A/AAAA
  (legacy zeroconf form) keeps that address type off that one service
  (`push_record` gate, retroactive removal); the host header keeps it as a
  withheld address, and the service drives no query interest for it.
  `app::denials::AddressDenials` owns the denials and withheld addresses;
  `App` only takes newly denied rows off their service.
  `App` methods live in child modules by job: `schedule` (continuous
  browsing, cache refresh, known answers, §7.3 suppression; its state is
  `Scheduler`, changed elsewhere only through its methods), `ingest`
  (record handlers, `push_record`, goodbyes), `denials`, `sightings`,
  `questions` (question routing), `input` (keys, mouse, selection),
  `view` (read-only accessors for `ui`; `App` has no public fields), `metrics`, `findings`
  (analyzer snapshot), `state_dump`. `app.rs` keeps the types, constants,
  free helpers, construction, run loops and eviction. Child-module
  methods are `pub(super)` (same reach as a private `app` method).
  Its tests live in `src/app/tests/`: shared fixtures in `mod.rs`, one
  file per topic (scheduling, ingest, input, …, or the issue they cover).
* `src/devices.rs` — device names behind source addresses (#246): an
  `AddressBook` built on demand from live A/AAAA records
  (`App::address_book`), exact match first (own announcement beats a
  proxy), then IPv6 interface-ID match for link-local sources
  (inferred). Presentation and dumps only; never feeds the analyzer.
* `src/anomalies.rs` — the analyzer: finding types, the snapshot views,
  `analyze_observations`, dedup and the conflicting-answers check. Child
  modules: `records` (record claims, SRV targets, TTLs), `resolve`
  (unresolved targets, address-query evidence), `naming` (service type,
  label and subtype checks), `questions` (question verdicts), `scope`
  (finding display scopes).
* `src/ui.rs` — ratatui rendering only. It reads focus, selection and
  pane splits through `App::view_state()` (`app::ViewState`, changed only
  by input). The only state draw writes is
  `app::Layout` (via `App::layout()`): pane geometry, viewport heights,
  row maps, hex hit boxes and the scroll offsets it clamps.
  Child modules per pane: `services`, `records`, `questions`, `hex`,
  `metrics` (overlay); `ui.rs` keeps terminal init/restore/suspend, the
  frame layout and shared cell/finding helpers.

## Query scheduling (RFC 6762 §5.2, §5.4, §7.1)

* Continuous browsing (`App::continuous`): first query after 20–120ms random,
  then ≥1s, doubling each time, capped at 1/hour. No fixed 60s re-poll.
* Cache refresh (`App::requeries`): re-ask at ~80/85/90/95% of TTL with 0–2%
  random variation; after four misses the record expires at 100% TTL.
  The refresh itself never goes hourly; hourly is only the
  continuous-browsing cap.
* Known-answer suppression is PTR-only (shared records, §7.1): only answers
  with ≥half the original TTL remaining, sent with remaining TTL, scoped to
  the egress interface.
* QU bit only on the startup enumeration batch; everything else is QM.
* A/AAAA query names keep wire case; dedup keys are lowercase.
* No queries for dead interests: `evict_expired` prunes `continuous`,
  `requeries`, `enum_known`, `known_types` to live names.
* Records show the ingress interface (`%iface` for IPv6 link-local,
  `@iface` otherwise) from IP_PKTINFO.
* Unique answers (flush bit) dampen the exponential stream to hourly,
  also when cached before the interest appeared (e.g. A/AAAA additionals);
  the 80%-TTL refresh takes over.
* While no family can transmit (`browse::TransmitState`, set by the
  listener's pause/resume), both schedules hold: nothing is counted as
  sent, discovery doesn't back off, refresh attempts aren't used (records
  still expire at 100% TTL). On resume `continuous` is cleared, so
  discovery restarts with the startup schedule (jitter, startup QU).

## Workflow

* Agents must work only in a fresh, separate worktree created from `origin/main`;
  never edit the primary checkout or reuse a stale worktree. Create the worktree
  (and fetch `origin` first) before making any changes.
* Changes land via pull requests against `main`; never push to `main` directly.
* Create branches from `origin/main` (`git fetch origin` first).
* Each branch/PR carries one logical change. Never mix unrelated edits
  (code, CI, docs, deps) in one branch — split them into separate PRs.
* Commit messages must follow Conventional Commits (`feat:`, `fix:`, `docs:`,
  …): release-please owns the changelog and derives releases from them.
* Before opening a PR, proofread the title/body plus any new user-facing
  text and run `typos` (CI enforces it via `typos.toml`).
* When implementing an issue, ensure it is closed by adding `Closes #<issue>`
  to the PR body, so GitHub auto-closes the linked issue on merge.

## Conventions

* `cargo fmt` before commit; clippy with `-D warnings` must pass.
* Prefer editing existing files; no new deps without need
  (`simple-dns` exposes the mDNS QU bit and cache-flush bit natively).
* Random jitter uses the std-only `rand_u32` helper in `app.rs`.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues (via `gh`). See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context: `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
