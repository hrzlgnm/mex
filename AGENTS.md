# AGENTS.md — mex

## Build & check

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Test coverage (CI's informational `📊 Coverage` job does the same and
attaches `lcov.info` plus an HTML report to the run):

```sh
rustup component add llvm-tools-preview                  # once
cargo install --locked cargo-llvm-cov --version 0.9.1    # once, as CI
cargo llvm-cov --locked --ignore-filename-regex '(^|/)src/.*/tests/' --summary-only
cargo llvm-cov --locked --ignore-filename-regex '(^|/)src/.*/tests/' --open
```

No codegen, no external commands. Multicast sockets need no root.
Headless run (no TTY) logs to stderr.

## Layout

* `src/main.rs` — entry, TUI init/restore.
* `src/logging.rs` — the logger: stderr/file sink, size-rotated log file,
  `take_log_error` for the TUI status line.
* `src/browse.rs` — raw mDNS transport: v4/v6 sockets on `224.0.0.251:5353` /
  `[FF02::FB]:5353` via `socket-pktinfo`, query batches (`QueryBatch`:
  one tick's questions, each QM/QU with its known answers and the links it
  goes out on, packed into as few packets as fit per egress interface, one
  copy per interface that has a question for it),
  packet parse with ingress interface.
  One listener thread drives both sockets from a `mio` poll loop
  (readiness via a duplicate handle, reads via pktinfo, drained with a
  per-pass budget, then re-armed); `QueryTx::send` wakes it, queued queries
  are sent with a per-pass budget too, and the poll timeout is the 10 s
  interface refresh. Dropping the app's `QueryTx` wakes the loop and
  stops it, so the sockets close with the app. The v6 socket is
  v6-only. Startup fails only when neither family's socket opens.
  Down, point-to-point, `lo`/`docker`/`veth` interfaces are skipped,
  unless explicitly selected via `-i/--interfaces` (user intent wins;
  selected-but-down links wait for the rejoin refresh). A family with no
  usable link sends nothing (no unpinned fallback); its pause and resume
  are logged once each.
  Multicast loop enabled, so responders on this host (avahi,
  python-zeroconf) hear our queries; our own looped-back query copies are
  dropped by exact bytes (`SentCopies`, one drop per sent copy); each
  copy that left is instead reported to the app as a `browse::OwnSend`
  (questions, egress link, family, send instant) on its own channel. The
  loopback interface stays out unless selected with `-i`. Unicast-dst
  packets from off-link subnets are refused (RFC 6762 §11) with a diagnostics
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
  paths. Tests live in `src/browse/tests/`, one file per child module
  plus `transmit`.
* `src/app.rs` — browser state, query scheduling, ingest/expire, selection.
  Our own sent copies (`OwnSend`, #431) are kept apart from received
  packets, no older than a second before the oldest retained one and
  capped; only the multicast-rate check reads them (mex as the trigger,
  copies after our queries), never a view, counter or other check.
  Messages with a non-zero OPCODE (RFC 6762 §18.3, `Event::is_ignored`)
  and responses with a non-zero RCODE (§18.11) stop at ingest but stay in
  the packet log; non-zero-OPCODE ones are also dropped before the
  analyzer and counted in diagnostics.
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
  browsing, cache refresh, known answers, §7.3 suppression; its state and
  the cache-independent rules (backoff, refresh postponing, §7.3
  duplicate suppression, provenance, response triggers) live on
  `Scheduler`, unit-tested without an `App` in `app/tests/scheduler.rs`), `ingest`
  (record handlers, `push_record`, goodbyes), `denials`, `sightings`,
  `questions` (question routing), `input` (keys, mouse, selection),
  `view` (read-only accessors for `ui`; `App` has no public fields), `diagnostics`, `findings`
  (analyzer snapshot), `state_dump`, `rusage` (mex's own process cost:
  rusage plus current-memory sample, pure rows and dump entries).
  `app.rs` keeps the types, constants,
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
  label and subtype checks), `questions` (question verdicts), `rate`
  (sends repeated within a second, over the retained packets, and
  `QuestionTally`, the per-question, per-link query count `header` and
  `placement` share), `header`
  (query header bits, over the retained packets), `placement` (records in
  query sections responders ignore), `scope`
  (finding display scopes). Tests live in `src/anomalies/tests/`, one file
  per topic.
* `src/ui.rs` — ratatui rendering only. It reads focus, selection and
  pane splits through `App::view_state()` (`app::ViewState`, changed only
  by input). The only state draw writes is
  `app::Layout` (via `App::layout()`): pane geometry, viewport heights,
  row maps (`app::DrawnRows`: each drawn row's owner, by identity so a
  reorder before a click can't retarget it, and its height, since
  wrapped findings take several lines), hex hit boxes and the scroll
  offsets it clamps.
  Child modules per pane: `services`, `records`, `questions`, `hex`,
  `diagnostics` (overlay); `ui.rs` keeps terminal init/restore/suspend, the
  frame layout and shared cell/finding helpers.

## Query scheduling (RFC 6762 §5.2, §5.4, §7.1)

* Continuous browsing (`App::continuous`): first query after 20–120ms random,
  then ≥1s, doubling each time, capped at 1/hour. No fixed 60s re-poll.
  Streams first created in one pass share one 20–120ms delay, so questions
  learned together stay due on the same tick.
* Packing (#430): every question due in one tick (continuous and refresh,
  §7.3-suppressed ones left out, a question due twice in once with the
  union of its known answers) goes into `App::outbox` and leaves as one
  `QueryBatch` at the end of `send_queries`. The listener encodes it per
  egress interface into as few packets as fit 9000 bytes (§17), splitting
  at question boundaries; only a question too large alone sheds known
  answers. The send budget counts packets. The manual refresh sends its
  own one-question batch at once.
* Cache refresh (`App::requeries`): re-ask at ~80/85/90/95% of TTL with 0–2%
  random variation; after four misses the record expires at 100% TTL.
  The refresh itself never goes hourly; hourly is only the
  continuous-browsing cap.
* Known-answer suppression is PTR-only (shared records, §7.1): only answers
  with ≥half the original TTL remaining, sent with remaining TTL, scoped to
  the egress interface.
* QU bit only on the startup enumeration batch; everything else is QM.
* A/AAAA query names keep wire case.
* No queries for dead interests: `evict_expired` prunes `continuous`,
  `requeries`, `enum_known`, `known_types` to live names.
* Records show the ingress interface (`%iface` for IPv6 link-local,
  `@iface` otherwise) from IP_PKTINFO.
* Unique answers (flush bit, or SRV/TXT/A/AAAA, unique by type even when a
  responder leaves the bit off; RFC 6762 §7.1, #438) dampen the exponential
  stream per link (#441): an answer covers the link it came in on
  (`Scheduler::covered`, by interface name, or the IPv6 index when the name
  is unresolved), the stream then asks only the other usable links
  (`QueryRequest::links`), and drops to hourly once every usable link is
  covered (or at once for an answer whose link is unknown). A link that
  appears later restarts a dampened stream with the startup schedule, and a
  §7.3 overheard query stands in for ours only on its own link. One usable
  link behaves as before: the stream dampens to hourly,
  also when cached before the interest appeared (e.g. A/AAAA additionals);
  the 80%-TTL refresh takes over.
* While no family can transmit (`browse::TransmitState`, set by the
  listener's pause/resume), both schedules hold: nothing is counted as
  sent, discovery doesn't back off, refresh attempts aren't used (records
  still expire at 100% TTL). On resume `continuous` is cleared, so
  discovery restarts with the startup schedule (jitter, startup QU).
* Manual refresh (`r` on a `self` Questions row): one QM query now, with
  the scheduled known answers, recorded as `QueryOrigin::Manual` (LAST
  reads `manual`; no popup). Not §7.3-suppressed (and it consumes an
  overheard entry), uses no refresh attempt, moves no backoff, starts no
  stream (only postpones an existing one), and a refresh due within 1 s
  after it waits. Held back within 1 s of any send of that question, for
  NSEC-denied address types, in passive mode and while transmission is
  on hold.

## Workflow

* Run every git command that talks to the remote (`fetch`, `pull`, `push`)
  after `export GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes"`
  in the same shell command: the SSH agent offers hardware security keys
  first, and those fail without a human at the device.
* Before making any change for a new task, run `git fetch origin`, then
  `git worktree add --no-track -b <branch> ../mex-wt-<topic> origin/main`: a
  worktree created for this task, never one left from an earlier task, on a
  new branch cut from `origin/main`. `--no-track` keeps the branch from
  tracking `main`; publish it with `git push -u origin <branch>`.
* Do all edits in the task's worktree, leaving the primary checkout as is.
  Continue an open pull request's branch where `git worktree list` shows it
  checked out; if nowhere, recreate a worktree with
  `git worktree add ../mex-wt-<topic> <branch>`.
* Changes land via pull requests against `main`; never push to `main` directly.
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
* Names fold ASCII only: keys and comparisons use `to_ascii_lowercase` /
  `eq_ignore_ascii_case` (RFC 6762 §16: `A`-`Z` match `a`-`z`, every other
  byte compares exactly, so `É` and `é` are two names). `to_lowercase` is for
  display sort orders.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues (via `gh`). See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context: `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
