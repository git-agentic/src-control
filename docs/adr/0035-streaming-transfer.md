# ADR-0035: Streaming pack transfer (bounded-RAM, >4 GiB)

- **Status:** Proposed
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

## Alternatives considered

- **Widen the frame header to u64, keep full buffering.** Lifts the 4 GiB
  cap with a smaller change but still holds the whole pack in RAM twice —
  "streaming" in name only. Rejected: the point is bounded memory.
- **Keep a v1 fallback (negotiate min version).** Robust interop with old
  peers but two pack encodings to maintain forever. Rejected as needless
  for a pre-deployment project.
- **Resumable/interrupted-transfer resume.** A failed stream restarts from
  scratch; offset-resume is deferred (larger protocol surface, own risk).
