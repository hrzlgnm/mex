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
  Only in-scope types (`anomalies::is_mdns_answer_type` /
  `is_mdns_question_type`) are decoded or named; every other record keeps
  just `rdlength=<n>` (on-wire RDLENGTH) and renders as `TYPEnn`; the
  packet walk relabels them opaque before `Packet::parse`, so their rdata
  is never decoded. EDNS0 OPT pseudo-records are skipped entirely.
* `src/app.rs` — browser state, query scheduling, ingest/expire, selection.
  Out-of-scope records, known answers and questions go to `sightings`
  (never rows, never query drivers; capped, expired by TTL/time), with
  owners resolved at analysis time: instance names to their service,
  hostnames once to the host (`anomalies::host_id`), shown in every
  sibling service's pane.
* `src/ui.rs` — ratatui rendering only, no state mutations.

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
