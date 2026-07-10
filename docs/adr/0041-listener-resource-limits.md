# ADR-0041: Listener resource limits

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 31
- **Builds on:** ADR-0036 (P26 sc-native HTTP transport — names three of the
  four gaps closed here), ADR-0040 (P29 access control — the seam where a
  busy/error status is already written before the wire handshake), ADR-0039
  (P28 DoS hardening — `MAX_OBJECT_SIZE`, composed with, not replaced by,
  this phase's spool cap)
- **Research:** `docs/research/bounded-server-patterns.md` (ticket #27,
  std-only bounded-server survey pinned to file:line). Decided at the
  decision level via the wayfinder map, ticket #28.

## Context

ADR-0036 shipped `sc serve --http` with three accepted-but-open consequences:
unbounded thread-per-connection (no pool, cap, or backpressure), no
idle-transfer watchdog (the opening's 30s read timeout is cleared once
`wire::serve` takes over), and no accept-loop backoff (a sustained
`EMFILE`/`ENFILE` hot-spins `listener.incoming()`). The #27 research pass
found a fourth gap neither ADR-0036 nor `docs/THREAT-MODEL.md` had named: the
aggregate incoming-pack spool is unbounded, and the read-only rejection path
drains it too (`wire.rs`'s `EC_READONLY` arm spools the whole pack before
replying, so an `ro`-token client can still write arbitrary bytes to disk).
This phase closes all four, dep-free, with no wire-protocol change.

## Decision

`sc serve` gains three new flags plus one hardcoded internal behavior, all
scoped to the listener (`--stdio` is unaffected except where noted):

1. **`--max-connections <n>` (default 32, 0 = unlimited).** An atomic
   live-connection counter (`SlotGuard`, RAII-decremented on every exit path
   — clean return, error, panic unwind). At the limit, a new connection is
   accepted, immediately written a busy status at the HTTP opening — the
   same pre-handshake seam ADR-0040's `401`/`404` already use — and closed.
   No queuing: for long-lived multi-verb wire sessions, fail-fast beats an
   invisible wait. Default 32 matches `git-daemon --max-connections`, the
   closest prior-art analog for a bare TCP git-style server.

2. **`--timeout <secs>` (default 300, 0 = disabled).** Read *and* write
   timeouts are set on the `TcpStream` once the session begins and persist
   for the whole session, replacing (not merely preceding) the opening's
   `OPENING_READ_TIMEOUT` — previously that 30s timeout was cleared outright
   after the `200` status. A timeout trip is connection-fatal: mid-stream
   abort desyncs the frame stream (no partial-frame recovery is possible),
   so the connection is dropped rather than resumed; `TempPackGuard` cleans
   any spooled pack file on the resulting unwind. Under P25 chunking, a
   per-syscall timeout is inherently progress-based — only a true zero-byte
   stall trips it, not a slow-but-moving transfer. The opening keeps its
   existing, unchanged 30s.

3. **`--max-pack-size <bytes>` (default 16 GiB, 0 = unlimited, floor 256 MiB
   = `MAX_OBJECT_SIZE`).** Applies to **both** `--http` and `--stdio` — it
   lives in `WirePolicy` (`crates/repo/src/wire.rs`), the shared layer both
   transports call into, not in `ServeLimits` (the `--http`-only listener
   config). A configured non-zero value below `MAX_OBJECT_SIZE` is rejected
   as invalid config at startup. Enforcement is a counted mid-stream abort in
   the pack-stream readers (mirroring git's `receive.maxInputSize`): once the
   running total crosses the cap, the reader stops, a best-effort
   `EC_TOO_LARGE` reply is written (best-effort because the abort already
   desynced the stream — the reply is a courtesy, not a guarantee the client
   parses it before the socket closes), and the connection is torn down.
   This composes above, and never replaces, ADR-0039's existing per-frame
   wire-length cap, per-record pack cap, and zstd decompression-bomb guard —
   this is an *aggregate* bound across an entire incoming pack, those are
   *per-unit* bounds within it.

4. **Read-only drain cap — `RO_DRAIN_CAP` (8 MiB, hardcoded).** The
   deliberate pre-`EC_READONLY` drain (draining keeps a wire connection in
   sync when the client has already started streaming a pack the server is
   about to reject) now stops at ~8 MiB. An honest misconfiguration — a
   read-only-scoped client attempting a small legitimate push — still gets
   the clean typed `EC_READONLY` error. A hostile or careless bulk spool
   past that size is dropped mid-send instead of fully drained to disk, so
   an `ro`-token connection can no longer be used to write unbounded bytes
   to `.sc/tmp` regardless of the eventual rejection. This gap was never
   named in ADR-0036 or the threat model before this phase's research pass
   found it — P31 both names and closes it.

5. **Accept-loop backoff (hardcoded, no flag).** Go `net/http`'s exact
   shape: on an accept error, sleep starting at 5ms, doubling on each
   consecutive error, capped at 1s, reset to 5ms on the next successful
   accept. Turns fd exhaustion (`EMFILE`/`ENFILE`) from a busy-loop into a
   paced retry. No operator knob — Go ships this knobless too, and no
   tuning story exists yet to justify one.

## Recorded divergences from prior art

- **Timeout on by default, unlike `git-daemon`'s `--timeout` (default 0 /
  disabled).** A defaults-off knob does not close an audit-tracked High — a
  silent or write-stalled peer parking a server thread forever is exactly
  the DoS shape this phase exists to close, and without a reaper the
  connection cap (#1) is hostage to any single stalled client holding a
  slot forever. 300s, not a shorter value, because the one legitimate
  casualty of a shorter deadline is a client computing between verbs (e.g.
  `sc ws run` doing real work mid-session).
- **Finite 16 GiB spool default, unlike git's unlimited
  `receive.maxInputSize` (default 0).** `sc serve` deployments often share
  the same volume as the working tree/`.sc/tmp` spool, and this phase's
  posture is fail-closed defaults throughout rather than borrowing git's
  unbounded default.

## Rejected alternatives

- **Block-at-accept semaphore (queue rather than shed at the connection
  cap).** Rejected: a wire connection is a long-lived, many-verb session,
  not a one-shot HTTP request — an invisible queued wait is worse UX than a
  clear, immediately retryable busy status.
- **git-daemon's grace-then-shed pattern.** Rejected as unnecessary
  complexity for this MVP; the immediate busy-status-and-close is simpler
  and gives the client the same actionable signal sooner.
- **The Rust Book's fixed-size thread-pool-with-queue pattern.** Rejected
  for the same reason as the semaphore: it trades a clear rejection for an
  invisible queue, wrong shape for long-lived sessions.
- **A reserved-fd accept-loop shed (hold back N fds for cleanup work).**
  Rejected: the connection cap (#1) already demotes fd exhaustion to
  external pressure (e.g. other processes on the host) rather than a
  self-inflicted condition; the refinement can ride a later hardening pass
  if real-world churn ever proves the need.
- **Env-var or `.sc/config`-file knobs for these limits.** Rejected for
  this phase: no `.sc/config` surface exists yet, and CLI flags are
  consistent with every other `sc serve` option shipped so far
  (`--read-only`, `--allow-public`, ADR-0040's token flags). A config-file
  surface is a separate, larger decision not scoped here.
- **An sshd-`MaxStartups`-style pre-auth sub-cap distinct from the total
  connection cap.** Deliberately deferred until real-world churn patterns
  justify a second knob; one total cap is the simpler starting shape.

## Consequences

- ADR-0036's three named accepted-but-open consequences (unbounded
  thread-per-connection, no idle-transfer watchdog, no accept-loop backoff)
  are closed by this phase.
- The aggregate-spool gap — never named in ADR-0036 or the threat model,
  surfaced only by the #27 research pass — is both named and closed,
  including its read-only-drain-path variant.
- `PROTOCOL_VERSION` stays 3: none of the four bounds touch the wire
  protocol. `EC_TOO_LARGE` degrades gracefully to opaque message text on an
  old client that doesn't recognize the code, matching `EC_READONLY`'s
  precedent from ADR-0040.
- Zero new dependencies.
- `--stdio` gains only the pack-size cap (shared `WirePolicy`); connection
  count, session timeout, and accept backoff are `--http`-listener-specific
  concepts that don't apply to a single ssh-spawned stdio session.
- Proven by `demo/run_limits_demo.sh` (the floor-cap enforcement on the push
  path and the busy-status shed under `--max-connections`); the timeout
  reaper and accept-backoff pacing are unit-test-proven rather than
  demo-proven, since reliably forcing a real stalled-socket or fd-exhaustion
  condition in a demo script is impractical.

## Threat model honesty

- **Defends:** thread/fd exhaustion from unbounded connection churn (cap +
  shed); a stalled or hostile-slow peer holding a server thread forever
  (session timeout, both directions); unbounded disk consumption from an
  oversized or endless incoming pack, on both transports and including the
  read-only-drain path (spool cap + drain cap); accept-loop hot-spin under
  sustained fd exhaustion (backoff).
- **Does NOT defend:** a client operating within all four bounds but still
  malicious in content (these are resource bounds, not content/auth
  controls — see ADR-0040 for the access-control layer); distributed
  multi-connection exhaustion below the per-listener cap (e.g. many
  distinct source IPs each opening a few connections) — no per-IP or
  per-token sub-limiting exists; a legitimate transfer that is simply
  slower than 300s of true zero-byte stall is unaffected, but an operator
  with a much slower network than anticipated must raise `--timeout`
  explicitly.
