# ADR-0035: Streaming pack transfer (bounded-RAM, >4 GiB)

- **Status:** Accepted
- **Date:** 2026-07-08
- **Phase:** 25
- **Builds on:** ADR-0022 (SSH stdio wire protocol), ADR-0015 (packfiles + pack verification)

## Context

P12's stdio wire protocol (ADR-0022) frames every message with a `u32`
length prefix, and `read_frame_inner` buffers the whole frame into
`vec![0u8; len]`. The pack rides as a single `PutPack(Vec<u8>)` request /
`get_pack` response frame. Two consequences: a pack ≥ 4 GiB cannot be sent
(`write_frame` errors above `u32::MAX`), and even a sub-4 GiB pack is
fully resident in RAM on both sender and receiver. This is the first phase
of the scale-&-reach horizon (P25 streaming → P26 HTTP transport → P27
partial clone); it must lift the cap AND bound memory before the larger
transport features build on the wire.

## Decision

Spec: `docs/superpowers/specs/2026-07-08-p25-streaming-transfer-design.md`.

**Bounded-RAM streaming, wire path only.** Only `get_pack`/`put_pack`
stream; the other six Transport verbs stay single-frame. The in-process
`LocalTransport` path is out of scope.

A pack becomes a multi-frame stream under the **unchanged** `u32` header:
a **start** frame, **N chunk** frames each ≤ `CHUNK_SIZE` (~1 MiB), and an
**end** frame. Every chunk fits the existing prefix, so the header format
never changes and the six small verbs are byte-identical to P12.

- **Sender** builds the pack to an ephemeral temp file (P8's pack writer)
  and streams it in `CHUNK_SIZE` reads — peak RAM one chunk.
- **Receiver** appends chunk frames to an ephemeral temp pack file, then
  on **end** verifies + ingests **from disk** (P8 pack verification reads
  by path) and removes the temp — peak RAM one chunk + verify window.
- Ingest stays **atomic after full verify** — a mid-stream failure lands
  nothing.
- The temp pack is removed on success AND on any mid-stream
  error/teardown (guarded) — the ephemeral-disk invariant holds, zero
  residue.

**Drop v1.** `PROTOCOL_VERSION` bumps to 2; both ends must be v2. There is
ONE pack encoding (always the chunk stream) — no legacy single-frame path
retained. The Hello handshake rejects a version mismatch clearly.
Acceptable because src-control is pre-deployment (no old `sc serve` peers
in the field).

## Consequences

- Packs of any size transfer over ssh:// (and the coming HTTP transport)
  with memory bounded to one chunk + the verify window on each side.
- Signatures (P22) ride the pack unchanged; `index_incoming` runs after
  ingestion from the temp file; protected/confidential content (P9/P10) is
  opaque bytes to the transport — all unchanged by construction.
- One pack encoding to maintain (v1 dropped) — simpler, at the cost of no
  interop with a P12-vintage peer.
- The in-process local path still buffers (out of scope) — a local clone
  of a >4 GiB repo is unaffected by this phase.
- **Boundary: the headline "bounded RAM on both sides" holds for the
  server and the wire, NOT for the client application layer.** The build
  went further than this ADR's original scope on the `LocalTransport`
  plumbing itself — `LocalTransport::build_pack_tempfile`/`ingest_pack_file`
  (`crates/repo/src/transport.rs`) stream one object/one record at a time
  through a temp pack file for BOTH `get_pack` and `put_pack`, and
  `wire::serve` (`crates/repo/src/wire.rs`) uses the same temp-file spill on
  the server end of an ssh connection, so a malicious or oversized transfer
  cannot balloon server-side RAM. But the CLIENT-side caller one layer up,
  `crates/repo/src/sync.rs`, was not rewired to this machinery:
  `transfer_objects` (shared by `fetch` and `clone_url`) still does
  `let mut pack = Vec::new(); transport.get_pack(..., &mut pack)`, destreaming
  the whole pack into a `Vec<u8>` before handing it to (non-streaming)
  `parse_pack`; `Repo::push` still assembles `send: Vec<(ObjectId, Vec<u8>)>`
  entirely in RAM before calling `build_pack`. So today: the wire itself
  streams in `CHUNK_SIZE` frames either direction, and the server-side
  temp-file dance is genuinely bounded, but the ssh **client's** own memory
  footprint for a fetch/clone/push is still ~one pack's worth. Follow-on:
  route `sync.rs`'s client-side fetch/push through `build_pack_tempfile`/
  `ingest_pack_file` (or equivalent streaming glue) so the client layer gets
  the same bound the server and wire already have.

## Alternatives considered

- **Widen the frame header to u64, keep full buffering.** Lifts the 4 GiB
  cap with a smaller change but still holds the whole pack in RAM twice —
  "streaming" in name only. Rejected: the point is bounded memory.
- **Keep a v1 fallback (negotiate min version).** Robust interop with old
  peers but two pack encodings to maintain forever. Rejected as needless
  for a pre-deployment project.
- **Resumable/interrupted-transfer resume.** A failed stream restarts from
  scratch; offset-resume is deferred (larger protocol surface, own risk).

## Refinements discovered during the build

Every prior phase's Refinements section holds this one to the same bar:
every claim below is checked against the shipped code, not the plan.

1. **`PackWriter` is byte-identical to `build_pack`, pinned by test, not
   just asserted in a comment.** `crates/core/src/pack.rs`'s incremental
   `PackWriter<W: Write>` (`new`/`write_object`/`finish`) writes the exact
   same `[magic][version]` header and `[id:32][compressed_len:4][compressed
   data:N]` record framing `build_pack` does, tracking only a running byte
   offset and the (small) index in RAM rather than the whole pack body —
   the regression test `pack_writer_matches_build_pack_byte_for_byte`
   builds the same object set both ways and diffs the output bytes.
   `finish` also refuses (`Error::PackCorrupt`) if fewer than the promised
   object count was written, so a short write can't silently produce a
   truncated-but-valid-looking pack.
2. **`parse_pack_reader`'s EOF-at-record-boundary termination is the one
   subtle piece — the pack format carries no object count.** Unlike
   `parse_pack` (which knows `pack.len()`), a `Read` stream has no length to
   check against, so `parse_pack_reader` (`crates/core/src/pack.rs`) reads
   each record's 32-byte id with a helper (`read_up_to`) that tolerates a
   clean 0-byte read at the very start of a record as "end of pack" — `0`
   bytes read there is the normal termination case, `1..32` is a genuine
   truncation error, and a full 32-byte read continues into the record's
   length + payload via ordinary `read_exact` (which itself already treats
   a short read as an error). Every record's hash is verified against its
   claimed id before the caller's callback runs, exactly as `parse_pack`
   does for the whole-buffer case.
3. **The chunk framing is two new opcodes riding the UNCHANGED `u32` frame
   header, plus one env-var test/tuning seam.** `crates/repo/src/wire.rs`
   adds `ST_PACK_CHUNK = 0x20` and `ST_PACK_END = 0x21` as ordinary framed
   messages (`write_pack_stream`/`read_pack_stream`); `CHUNK_SIZE = 1 <<
   20` (1 MiB) is the production default, and `pack_chunk_size()` reads
   `SC_PACK_CHUNK` (bytes, must parse as a nonzero `usize`) fresh at each
   stream start, falling back to `CHUNK_SIZE` — the demo (`demo/
   run_streaming_demo.sh`) sets `SC_PACK_CHUNK=4096` to force a ~1 MiB pack
   across 250+ chunk frames instead of one, and the unit tests
   (`crates/repo/src/wire.rs`) drive the same seam with chunk sizes as
   small as 7 bytes. `PROTOCOL_VERSION` bumped `1 → 2` as planned; a v1
   peer is rejected cleanly at the `Hello` handshake in both directions,
   not silently misparsed.
4. **Two-pass atomic-after-verify ingest, and exactly why re-reading the
   spilled file (not the live connection) is what makes the per-record
   length prefix safe.** `ingest_pack_file` (`crates/repo/src/
   transport.rs`) opens the same on-disk temp pack file TWICE: pass 1 runs
   `parse_pack_reader` writing nothing (verify-only), pass 2 re-opens and
   runs it again, this time calling `store.put` per verified record — so a
   corrupt or truncated record anywhere in the pack is caught before a
   single object from that pack reaches the store. The doc comment on
   `ingest_pack_file` spells out the reason this is safe where reading
   straight off an untrusted socket would not be: `parse_pack_reader`
   trusts each record's `u32` length prefix and allocates `vec![0u8; len]`
   for it (up to 4 GiB, unchecked) — read live off a socket that is a
   memory-exhaustion footgun, but read off an already-fully-spilled file,
   the maximum any record's length prefix can possibly claim is bounded by
   the file's own size on disk, which was itself bounded by however many
   bytes the sender actually sent. No separate per-record cap was added to
   `parse_pack_reader` itself; every call site in the codebase reads a
   spilled file, never a live connection, so the invariant holds by
   construction rather than by a cap that could drift out of sync.
5. **The temp-file guard is one RAII type used by both directions and both
   transports.** `TempPackGuard` (`crates/repo/src/transport.rs`) reserves
   a path under `.sc/tmp/` (`Layout::tmp_dir`, new in P25) keyed by pid +
   a monotonic per-process counter (unique enough for concurrent transfers
   within one process) and removes the file on `Drop` — success,
   verification failure, or a dropped connection alike, since `Drop` runs
   regardless of how the scope was exited. `LocalTransport::
   build_pack_tempfile` (sender) and `wire::serve`'s `spill_pack_stream`
   (receiver, destreaming `ST_PACK_CHUNK` frames straight to the guarded
   file) are the two call sites; `TempPackGuard::new` does not remove
   `.sc/tmp/` itself, matching how `.sc/ws/` and other `.sc/` scratch dirs
   are left in place between uses — only the per-transfer file inside it is
   guaranteed gone.
6. **Chunk framing is deliberately scoped to the wire boundary only —
   `LocalTransport` keeps raw pack bytes.** `Transport::get_pack`/
   `put_pack`'s signatures are unchanged (`&mut dyn Write` / `&mut dyn
   Read` of raw `.pack` bytes); `write_pack_stream`/`read_pack_stream` are
   called only from `wire::serve` and `stdio_transport::WireClient` — the
   two ends of an actual ssh:// connection. A same-process `LocalTransport`
   call (used by a local-path clone/fetch/push) never touches the chunk
   opcodes at all, matching the spec's "wire path only" scope from Context
   above.
7. **The boundary this ADR's Consequences section states plainly: the
   client application layer (`crates/repo/src/sync.rs`) is not bounded.**
   See the Consequences entry above for the exact functions
   (`transfer_objects`, `push`) and the follow-on. This was caught in
   final review, not planned — the spec's headline promised bounded RAM on
   both sides, and the server/wire genuinely deliver that, but the ssh
   client's own fetch/push call sites were never rewired off the
   pre-P25 `Vec<u8>` + `build_pack`/`parse_pack` path.
