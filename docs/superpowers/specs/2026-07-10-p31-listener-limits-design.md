# P31: HTTP listener resource limits — design

- **Date:** 2026-07-10
- **Spec issue:** [#38 — P31: HTTP listener resource limits (sc serve --http)](https://github.com/git-agentic/src-control/issues/38)
- **Decision trail:** wayfinder map [#24](https://github.com/git-agentic/src-control/issues/24) →
  decision [#28](https://github.com/git-agentic/src-control/issues/28), research
  [#27](https://github.com/git-agentic/src-control/issues/27)
  (`docs/research/bounded-server-patterns.md`)
- **Closes:** audit High #2 — ADR-0036's three named operational boundaries
  (unbounded thread-per-connection, no idle-transfer watchdog, no accept-loop
  backoff) **plus** the unbounded aggregate pack spool the research surfaced
  (reachable by read-only clients via the drain-for-sync arm, `wire.rs`).

Zero new dependencies. `PROTOCOL_VERSION` stays 3.

## Goal

`sc serve` survives hostile or broken clients with bounded threads, bounded
disk, and a live accept loop — with defaults that protect out of the box and
per-invocation flags for operators who need different numbers.

## CLI surface

`sc serve` gains three flags:

| Flag | Default | 0 means | Scope |
|---|---|---|---|
| `--max-connections <n>` | 32 | unlimited | `--http` only (refused with `--stdio`) |
| `--timeout <secs>` | 300 | disabled | `--http` only (refused with `--stdio`) |
| `--max-pack-size <bytes>` | 16 GiB | unlimited | **both** `--http` and `--stdio` |

- `--max-pack-size` values below `MAX_OBJECT_SIZE` (256 MiB) are rejected at
  parse time with a clear error (a cap that can't fit one maximal object is a
  misconfiguration, not a policy).
- `--max-connections`/`--timeout` are socket/accept-loop mechanics, so they are
  meaningless for `--stdio` (ssh owns that transport's sockets) and refused
  there rather than silently ignored.
- `--max-pack-size` applies to both transports because the spool mechanism is
  the shared wire layer and disk exhaustion is transport-agnostic (decision:
  brainstorm 2026-07-10; same default everywhere).

The flags build a `ServeLimits` struct in the CLI; no config file, no env vars
(both rejected on decision ticket #28 / brainstorm).

## Listener changes (`crates/repo/src/http_transport.rs`)

**Connection limit — atomic slots + RAII guard.** `serve_http_listener` holds
an `Arc<AtomicUsize>`. Per accepted socket, before spawning: increment; if the
new count exceeds the limit, write HTTP status **503**, close, decrement — no
wire handshake, no thread. Otherwise the connection thread owns a `SlotGuard`
whose `Drop` decrements, so panics and every error path free the slot
(the `TempPackGuard` discipline). No queuing: for long-lived wire sessions,
fail-fast-with-status beats invisible waits (decision #28).

**Idle/progress deadline.** `handle_http_connection` currently clears the 30s
opening read timeout before the wire handoff (`set_read_timeout(None)`); it
instead sets the configured session timeout on **both** read and write sides
(`set_read_timeout` + `set_write_timeout`) — a write timeout covers a client
that stops *reading* mid-`GetPack`, which today parks the thread in a blocking
`write`. Under P25 chunking (≤ `SC_PACK_CHUNK` frames) a per-syscall timeout is
progress-based: slow-but-flowing transfers never trip it; only true zero-byte
stalls do. On timeout the error is **connection-fatal** (frame desync makes
recovery impossible): log to stderr, thread exits, guard frees the slot,
`TempPackGuard` removes any partial spool. Both `io::ErrorKind::WouldBlock`
(Unix) and `TimedOut` (Windows) are treated as timeout. The opening keeps its
existing stricter 30s.

**Accept-loop backoff.** On `listener.incoming()` errors: sleep 5ms, doubling
per consecutive error to a 1s cap, reset on the next successful accept — Go's
`net/http` shape verbatim, hardcoded, no knob, no reserved-fd trick
(decision #28). This turns fd exhaustion from a busy-loop into a paced retry.

## Wire-layer changes (`crates/repo/src/wire.rs`)

**`WirePolicy` replaces the bare bool.** `serve_with_policy(root, r, w,
read_only: bool)` becomes `serve_with_policy(root, r, w, policy: WirePolicy)`
where

```rust
pub struct WirePolicy {
    pub read_only: bool,
    pub max_pack_size: u64, // 0 = unlimited
    pub ro_drain_cap: u64,  // constant: 8 MiB
}
```

The existing `serve` wrapper maps to `WirePolicy { read_only: false,
max_pack_size: <default>, ro_drain_cap: RO_DRAIN_CAP }`; `--stdio` and `--http`
both construct it from `ServeLimits`. In-crate callers update; this is a
pre-1.0 in-workspace signature change, not a wire change.

**Spool cap — counted abort mid-stream.** `read_pack_stream` and
`spill_pack_stream` gain a byte budget. The running total is checked as chunk
frames arrive (git's `receive.maxInputSize` shape: abort *while counting*,
never after materializing); exceeding it raises a new typed
`Error::PackTooLarge { limit }`, the partial spool is removed by the guard,
and the server replies with a new wire error code **`EC_TOO_LARGE = 6`**.
Old clients degrade gracefully — unknown codes already fall back to
`Error::Remote(msg)` — so no protocol version bump. The cap composes *above*
ADR-0039's per-frame/per-record/decompression caps; it never replaces them.

**Read-only drain cap.** The RO `PutPack` arm's drain-for-sync
(`spill_pack_stream` then drop) is capped at **8 MiB** (`RO_DRAIN_CAP`): a pack
that ends within the cap gets today's clean typed `EC_READONLY` reply; a larger
one gets a best-effort `EC_READONLY` write and the connection is closed
(sync is unrecoverable past the cap by design — decision #28: honest
misconfigurations keep the clear error, hostile bulk spools almost nothing).

## Client-side mapping (`http_transport.rs`, `wire.rs`)

- Opening status `503` → a typed, clearly retryable error
  ("server busy (connection limit reached) — retry later").
- `EC_TOO_LARGE` → `Error::PackTooLarge` with the server's limit in the
  message, so `sc push` prints an actionable failure.

## Error handling summary

| Event | Server behavior | Client sees |
|---|---|---|
| Accept while full | 503 + close, no handshake | "server busy, retry" |
| Zero-byte stall > timeout | log + drop connection, spool cleaned | connection error |
| Pack exceeds `--max-pack-size` | abort mid-stream, `EC_TOO_LARGE`, spool cleaned, connection continues | "pack exceeds server limit (N)" |
| RO push ≤ 8 MiB | drain, `EC_READONLY` (unchanged) | "read-only" |
| RO push > 8 MiB | best-effort `EC_READONLY`, close | read-only error or connection error |
| Accept error (EMFILE etc.) | 5ms→1s backoff, loop stays alive | connect delay/refusal |

## Testing

Pinned regression tests per bound:

1. Slot exhaustion: fill `--max-connections 1` with a held session; second
   connect gets the busy error; after the first closes, a third succeeds
   (slot actually freed).
2. Guard leak check: a connection whose handler errors (bad opening) frees its
   slot.
3. Stall reaping: a client that connects, handshakes, then goes silent is
   dropped after the (test-shortened) timeout; `.sc/tmp` empty afterwards.
4. Write-side stall: a client that stops reading mid-`GetPack` is dropped.
5. Spool cap: a pack exceeding a small `--max-pack-size` fails mid-stream with
   the typed error, `.sc/tmp` is empty, and the same connection can issue a
   subsequent successful request.
6. Config floor: `--max-pack-size` below `MAX_OBJECT_SIZE` refused at startup.
7. RO drain: small RO push still gets `EC_READONLY`; oversized RO push gets the
   connection closed, ≤ 8 MiB spooled (assert via temp-dir observation), zero
   residue after.
8. Backoff: consecutive accept-error handling doesn't busy-loop (shape test via
   injected error source or timing bound).
9. `--stdio` spool cap: same as (5) over the wire-harness stdio path.

`demo/run_limits_demo.sh`: real loopback TCP; proves busy-status at the cap,
stall reaping, spool-cap rejection with zero `.sc/tmp` residue on both ends —
run twice (the repo's demo discipline).

## Documentation

- **New ADR** (next number): the four bounds; the two recorded
  divergences-from-prior-art (timeout on-by-default vs git-daemon's off;
  finite 16 GiB spool default vs git's unlimited `receive.maxInputSize`);
  the 8 MiB drain posture; the both-transports scope of the spool cap.
- **`docs/THREAT-MODEL.md`:** mark ADR-0036's three boundaries closed; name and
  close the aggregate-spool gap; carry the two map re-affirmation wordings —
  env-var secret exposure (#31: same-user adversary defeats the identity key;
  fd/stdin stays an additive deferred mode) and signature replay (#32:
  ancestry is already id-bound; the residue is ref binding only —
  "replayable to a ref tip within its own history").
- **CLAUDE.md:** the three new flags on the serve command block; ADR-0036's
  "accepted design consequences" paragraph updated to point here.

## Non-goals

Pre-auth connection sub-caps (sshd MaxStartups shape), reserved-fd shedding,
client-side spool caps, any config-file surface — recorded follow-ons, not
this phase.
