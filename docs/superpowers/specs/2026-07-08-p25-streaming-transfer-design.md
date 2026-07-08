# P25 — Streaming pack transfer: design

**Date:** 2026-07-08
**Status:** Approved
**ADR:** 0035 (Proposed → Accepted when built)
**Horizon:** Scale & reach (P25 streaming → P26 HTTP transport → P27 partial clone)

## Problem

P12's stdio wire protocol frames every message with a `u32` length prefix
and `read_frame_inner` buffers the whole frame into `vec![0u8; len]`. The
pack rides as a single `PutPack(Vec<u8>)` request / `get_pack` response
frame, so today:

1. A pack ≥ 4 GiB cannot be sent — `write_frame` errors above `u32::MAX`.
2. Even a sub-4 GiB pack is fully resident in RAM on BOTH sender and
   receiver (the sender's built `Vec`, the receiver's `vec![0u8; len]`).

P25 lifts the cap AND bounds memory: streaming means neither side ever
holds more than one chunk + the verify window, regardless of pack size.

## Decided design

**Bounded RAM — real streaming** (user-decided over a bare u64-cap lift).
**Scope: the wire path only.** Only `get_pack` / `put_pack` stream; the
other six Transport verbs (Hello, list_refs, head_branch, has_object,
get_object, put_object, update_ref) stay single-frame — they are tiny.
The in-process `LocalTransport` path is out of scope (a local clone can
touch the filesystem directly). Streaming is an ssh:// (and future HTTP)
concern.

### Wire encoding — a multi-frame pack stream under the unchanged u32 header

A pack is no longer one frame. It is a sequence, each element a normal
`u32`-length-prefixed frame:

- one **start** frame (opcode identifying a pack stream + any metadata),
- **N chunk** frames, each carrying ≤ `CHUNK_SIZE` bytes (a constant,
  ~1 MiB, well under `u32::MAX`),
- one **end** frame.

Every chunk fits the existing `u32` prefix, so the frame header format is
**unchanged** and all six small verbs are byte-identical to P12. A small
pack simply streams as a start + one chunk + end.

**Version: drop v1** (user-decided). `PROTOCOL_VERSION` bumps to 2 and
BOTH ends must be v2 — there is ONE pack encoding (always the chunk
stream), no legacy single-frame `PutPack(Vec<u8>)` path retained. The
Hello handshake rejects a version mismatch with a clear error (a v1 peer
cannot talk to a v2 peer, and vice versa) rather than silently
misframing. Acceptable because src-control is pre-deployment — there are
no old `sc serve` peers in the field.

### Bounded memory — the actual guarantee

- **Sender.** `get_pack` builds its pack to an **ephemeral temp file**
  (reusing P8's pack writer) instead of returning a `Vec<u8>`, then the
  wire streams it in `CHUNK_SIZE` reads. `put_pack`'s sender streams from
  its built pack file the same way. Peak sender RAM = one chunk.
- **Receiver.** Incoming chunk frames append to an ephemeral temp pack
  file. On the **end** frame, the pack is verified + ingested **from
  disk** (P8 pack verification already reads pack files by path), then the
  temp is removed. Peak receiver RAM = one chunk + the verify window —
  independent of pack size.
- **Atomic ingest after full verify** (P8/P12 discipline, unchanged):
  nothing lands in the object store until the whole pack verifies, so a
  mid-stream failure ingests NOTHING.

### Transport API

The pack verbs become streaming-capable on the wire path:
`get_pack(wants, haves)` produces a pack **source** the wire can stream
(a temp pack file path / reader) rather than a `Vec<u8>`; `put_pack`
consumes a pack **sink/reader** (the temp file the receiver spilled)
rather than `&[u8]`. `LocalTransport` keeps its existing buffered
behavior for the in-process path (out of scope for streaming) — the exact
signature split (a streaming variant vs. reworked signatures) is a plan
decision, but the wire client (`stdio_transport`) and server (`sc serve`)
are the only streaming callers.

### Disk invariant

The temp pack lives in the repo's scratch/tmp area and is removed on
success AND on any mid-stream error/teardown (guarded, RAII-style) —
composes with the ephemeral-disk rule. Zero residue after the transfer,
success or failure.

## Interactions (unchanged by construction)

- **Signatures (P22)** ride inside the pack — ingested with it; the
  receiver-side `index_incoming` runs after ingestion from the temp file,
  exactly as today.
- **Protected / confidential content (P9/P10)** is opaque bytes to the
  transport — streaming changes nothing.
- **Pack verification (P8)** already reads a pack by path; the receiver
  verifies the spilled temp pack through it verbatim.
- **The other six verbs** are untouched.

## Testing & demo

- Unit: chunk-framing round-trip (a payload spanning many `CHUNK_SIZE`
  boundaries reassembles byte-identical, including an exact-multiple and a
  ragged-last-chunk case); the start/chunk/end opcode sequence decodes
  correctly and a malformed sequence — chunk-before-start, missing end,
  end-without-start — is a clean `Protocol` error; version mismatch at
  handshake errors clearly.
- Temp-spill lifecycle: the temp pack is removed after a successful ingest
  AND after an injected mid-stream error (assert the path is gone, zero
  residue) — mirrors the disk-invariant test discipline.
- Integration: clone / fetch / push over the `SC_SSH` shim with a
  deliberately tiny `CHUNK_SIZE` (a test override) so a few-MB pack
  streams as many chunks — round-trips byte-identical, receiver store
  matches sender, zero temp residue. Signatures (P22) survive the streamed
  transfer.
- `demo/run_streaming_demo.sh` (or an extension of
  `run_ssh_remote_demo.sh`): a repo with a large-ish blob clones over
  ssh:// under a small chunk size, proving multi-frame streaming end to
  end and zero residue. (A literal 4 GiB+ transfer is not demoed; the
  tiny-chunk override exercises the exact streaming path with modest
  data — the mechanism, not the scale.)

## Out of scope

Local-path (in-process `LocalTransport`) streaming — wire only.
Resumable / interrupted-transfer resume (a failed stream restarts from
scratch, not from an offset). Compression tuning of the chunk stream. The
HTTP transport (P26). Backward compatibility with a v1 peer (v1 dropped).
The receiving-repo in-progress push guard (a tracked Deferred follow-on;
close it opportunistically only if this phase's code lands in
`update_ref`, else leave it Deferred).
