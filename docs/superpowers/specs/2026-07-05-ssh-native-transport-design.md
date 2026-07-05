# SSH-native network transport (Phase 12) — design

- **Date:** 2026-07-05
- **Status:** Approved for planning
- **Depends on:** P6 sync (`Transport` trait), P8 packs (`get_pack`/`put_pack`),
  ADR-0021 durability & concurrency (CAS ref updates, locking)

## Goal

Make `sc clone / fetch / push` work between machines over SSH, using an
sc-native wire protocol. This is the first network transport; it turns
src-control from local-only into a real DVCS.

**Success bar:** a scripted, self-contained demo proves the full round trip
over the exact `ssh://` code path by spawning `sc serve --stdio` through an
`SC_SSH` shim (no sshd required); real `ssh://` remotes work when `sc` is on
the server's `PATH`, exercised manually.

## Approach (chosen: trait-mirror RPC)

Mirror the existing 8-verb `Transport` trait over a framed stdio protocol.
The client spawns `ssh host sc serve --stdio <path>` and speaks frames over
the child's stdin/stdout; the server is a dispatch loop around the existing
`LocalTransport`, so CAS ref updates, pack verification, and BLAKE3-on-read
are reused verbatim. Zero new dependencies; auth is SSH's.

Rejected alternatives:
- **Purpose-built session protocol (git smart-protocol style):** fewer round
  trips, but a second sync code path and re-solves CAS/verification the trait
  impls already solved. The trait-mirror protocol can grow composite opcodes
  later if latency ever matters.
- **Embedded SSH library (`russh`):** removes the external `ssh` dependency
  but drags in a large crate plus our own key/agent/host-verification
  handling; against the project's lean-deps taste, and Git proves shelling
  out is fine.

## Wire protocol

- **Framing:** every message is `u32 big-endian payload length` + payload.
  Request payload = 1-byte opcode + fields in core's length-prefixed style.
  Response payload = 1-byte status (`OK`/`ERR`) + body. The u32 length caps a
  frame at 4 GiB — acceptable while packs are built in memory; streaming is a
  noted follow-on.
- **Handshake:** both sides exchange `HELLO {protocol_version: 1}` first.
  Version mismatch fails with a clear error before any repo access.
- **Opcodes:** `Hello`, `Bye`, plus one per trait verb — `ListRefs`,
  `HeadBranch`, `HasObject`, `GetObject`, `PutObject`, `UpdateRef`,
  `GetPack`, `PutPack`. Nothing else: the server cannot be asked to read
  arbitrary paths or execute anything.
- **Typed errors:** `ERR` carries an error code + message. `NonFastForward`,
  `NotARepo`, and `UnknownObject` round-trip as themselves (push semantics
  depend on `NonFastForward`); everything else degrades to a generic code
  with the message string.

## Architecture

```
sc push/fetch/clone (client)
  └─ sync.rs — unchanged, drives the Transport trait
      └─ StdioTransport (new) — frames verbs over a child's stdin/stdout
          └─ child: `ssh [user@]host -- sc serve --stdio <path>`
              └─ sc serve --stdio — decode frame, call verb on…
                  └─ LocalTransport (existing) — CAS, pack verify, BLAKE3
```

Concurrent sessions against one repo are safe because `LocalTransport` verbs
already lock as needed (ADR-0021). Confidentiality is unchanged by
construction: objects travel as canonical bytes, so protected-path ciphertext
and secret objects cross the wire encrypted; BLAKE3 verification on `put`
catches tampering.

## CLI surface & URL handling

- `sc remote add origin ssh://[user@]host[:port]/abs/path` — stored verbatim
  in `.sc/config`. Sync code dispatches on scheme: no scheme →
  `LocalTransport`; `ssh://` → `StdioTransport`; git remotes keep their
  existing path above the trait. `sc clone` accepts an `ssh://` source and
  seeds `origin` with it.
- **Spawning:** `<SC_SSH or "ssh"> [-p port] [user@]host -- sc serve --stdio
  <path>`. The `SC_SSH` override (Git's `GIT_SSH` pattern) lets tests and the
  demo substitute a shim that ignores the host argument and execs
  `sc serve --stdio` locally — exercising the entire ssh:// code path except
  the sshd hop.
- `sc serve --stdio <path>` — refuses if `<path>` is not an sc repo (typed
  `NotARepo` over the wire), then loops until `Bye`/EOF. Stdio only; no
  daemon mode, no ports.

## Code layout

No new crates, no new dependencies; respects `cli → repo → … → core`.

- `crates/repo/src/wire.rs` — frame codec, opcodes, error-code mapping, and
  `serve(transport, reader, writer)`: the dispatch loop, generic over
  `Read`/`Write` so it is unit-testable in-process.
- `crates/repo/src/transport.rs` (or sibling `stdio_transport.rs`) —
  `StdioTransport` implementing `Transport` over a child process; a
  constructor takes a prepared `Command` so tests can spawn the binary
  directly.
- `crates/cli` — `serve` subcommand, `ssh://` URL parsing, `SC_SSH`
  resolution.

Accepted chattiness: push's fast-forward ancestry walk may issue several
small `GetObject` round trips when the remote tip is not known locally.
Metadata-sized; composite opcodes are the upgrade path if it ever hurts.

## Error handling

- ssh exiting nonzero before `HELLO` (auth failure, `sc` missing on the
  remote) surfaces the child's stderr, not a bare "connection closed".
- Mid-session EOF → a clear "connection lost" error; the client never
  silently retries.
- Malformed or oversized frames are protocol errors that terminate the
  session on either side.
- Interrupted push is safe by inherited ordering: objects/packs land before
  the ref CAS, so a dropped connection leaves at worst unreachable objects
  (GC's job), never a torn ref. A test pins this.

## Security posture

Authn/authz is entirely SSH's; we never touch credentials. The serve surface
is 8 verbs against one repo path, supplied by the client's own SSH account —
the same trust model as `git-upload-pack`. The phase moves ciphertext only,
never plaintext.

## Testing

- **Unit:** frame codec round-trips; error-code mapping (esp.
  `NonFastForward`); version-mismatch rejection; in-process `serve()` loop
  against a temp repo.
- **Integration** (cli crate, via `CARGO_BIN_EXE_sc`): clone/fetch/push over
  a spawned `sc serve --stdio`; racing-push CAS refusal over the wire;
  ssh:// end-to-end via the `SC_SSH` shim; ciphertext-stays-ciphertext on an
  unauthorized clone; dropped-connection-mid-push leaves refs intact.
- Temp repos clean up after themselves per project convention.

## Demo & docs

- `demo/run_ssh_remote_demo.sh`: init repo A with a commit + a protected
  path; `remote add` with an `ssh://fakehost/...` URL; `SC_SSH` shim; then
  clone → modify → push → fetch → merge between two repos, ending with the
  confidentiality proof (clone holder cannot decrypt) and a non-fast-forward
  push refusal.
- Docs: ADR-0022 (network transport over SSH), ARCHITECTURE.md phase
  section, CLAUDE.md command list.

## Explicit non-goals (this phase)

- HTTP transport / daemon mode, network Git remotes, streaming frames
  (>4 GiB packs), composite opcodes, retry/resume, credential handling of
  any kind.
