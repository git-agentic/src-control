# P25 — Streaming Pack Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bounded-RAM streaming of `get_pack`/`put_pack` over the wire — packs of any size transfer with peak memory of one object + the verify window per side (spec: `docs/superpowers/specs/2026-07-08-p25-streaming-transfer-design.md`, ADR-0035). First phase of the P25–P27 scale-&-reach horizon.

**Architecture:** Core gains an incremental pack writer and a streaming (reader-based) pack parser that produce/consume the **byte-identical** existing pack format. The wire gains a multi-frame pack stream (start + N chunk frames ≤ `CHUNK_SIZE` + end) under the unchanged `u32` header. The `Transport` pack verbs reshape to reader/writer-based signatures — the API change lands **behavior-preserving (still single-frame, still buffered) first**, then a later task swaps the wire internals to the chunk stream and the sender/receiver to temp-file-backed bounded-RAM paths. `LocalTransport` stays buffered (out of scope).

**Tech Stack:** Rust stable, existing crates, **no new dependencies** (stream over `Read`/`Write`, not mmap).

## Global Constraints

- Bounded RAM is the guarantee: the wire sender and receiver never hold the whole pack — peak is one object (ingest) / one chunk (wire) + the verify window (spec).
- Streaming is the **wire path only**: `get_pack`/`put_pack`. The other six verbs stay single-frame. `LocalTransport` (in-process) stays buffered — out of scope (spec).
- The pack format is **unchanged** — the incremental writer must produce byte-identical output to `build_pack`, or pack ids/format diverge (content-addressing invariant, CLAUDE.md).
- **Atomic ingest after full verify**: nothing lands in the store until the whole pack verifies — the receiver does a verify pass over the temp pack, THEN an ingest pass (spec; two bounded passes, not one buffered parse).
- Temp pack files live in the repo scratch/tmp area, removed on success AND on any mid-stream error/teardown (guarded, RAII) — the ephemeral-disk invariant, zero residue (spec, CLAUDE.md).
- **Drop v1**: `PROTOCOL_VERSION` bumps to 2, both ends must be v2, one pack encoding (the chunk stream), handshake rejects a version mismatch — the bump + v1-drop is atomic with the streaming switch (Task 4) (spec).
- Signatures (P22 `index_incoming`), protected content (P9/P10), and pack verification (P8) are unchanged by construction (spec).
- `CHUNK_SIZE` is a `pub(crate)` constant (~1 MiB); streaming fns take chunk size as a **parameter** so tests force a tiny value (spec).
- No new dependencies; tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: core — incremental pack writer + streaming (reader) parser (+ ROADMAP flip)

**Files:**
- Modify: `crates/core/src/pack.rs` (add `PackWriter` + `parse_pack_reader`; keep `build_pack`/`parse_pack` intact)
- Modify: `crates/core/src/lib.rs` (export the new items if the module re-exports)
- Modify: `ROADMAP.md` (flip Active to P25 + spec; mirror the P24 flip's shape — the Active section currently reads "None — the P21–P24 horizon is complete…"; replace with P25 active + a "Scale & reach (P25–P27)" note)

**Interfaces (produced, consumed by Tasks 2–4):**
```rust
// Incremental pack writer: appends objects one at a time to any Write,
// accumulating only the (small) index in RAM. Produces byte-identical
// output to build_pack for the same object sequence.
pub struct PackWriter<W: Write> { /* w, count_written, expected_count, index entries */ }
impl<W: Write> PackWriter<W> {
    /// Start a pack for exactly `count` objects (the header records the count,
    /// so it must be known up front — get_pack knows its id set).
    pub fn new(w: W, count: u32) -> Result<Self>;   // writes the pack header
    /// Append one object's canonical bytes; verifies id == BLAKE3(bytes) is
    /// the caller's job (ids come from the store). Updates the running index.
    pub fn write_object(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()>;
    /// Finish: returns the index bytes (same layout parse_index expects).
    /// Errors if fewer than `count` objects were written.
    pub fn finish(self) -> Result<Vec<u8>>;
}

/// Stream a pack from a reader, yielding each (id, Object) after verifying
/// its hash — WITHOUT holding the whole pack. Reads the header (count) then
/// each record sequentially; `f` is called per record. Peak RAM = one object.
pub fn parse_pack_reader<R: Read>(r: R, f: impl FnMut(ObjectId, Object) -> Result<()>) -> Result<()>;
```

- [ ] **Step 1: ROADMAP flip.**
- [ ] **Step 2: READ `crates/core/src/pack.rs` fully first** — the exact header layout (magic/version/count), per-record framing (how `parse_pack` walks records), and the index entry layout (`parse_index`/`IndexEntry`). Record in the report the exact byte layout so `PackWriter` reproduces it.
- [ ] **Step 3: Failing tests** (pack.rs in-module):
  - `pack_writer_matches_build_pack_byte_for_byte`: pick 3 objects; `let (want_pack, want_idx) = build_pack(&objs)`; feed the SAME objects in the SAME order through `PackWriter` → assert the written pack bytes == `want_pack` AND `finish()` == `want_idx`. (This pins format identity — the content-addressing invariant.)
  - `parse_pack_reader_round_trips_and_verifies`: `build_pack` 3 objects; `parse_pack_reader` over a `&pack[..]` cursor collects `(id, obj)` → equals `parse_pack(&pack)`'s output; a pack with one byte of a record corrupted → `parse_pack_reader` returns `Err` (hash mismatch) at that record.
  - `pack_writer_finish_short_count_errors`: `new(w, 3)` then write 2 → `finish()` errors.
- [ ] **Step 4: Implement** `PackWriter` and `parse_pack_reader` against the layout from Step 2. `PackWriter::new` writes the header with `count`; `write_object` writes the record framing `build_pack` uses and pushes an index entry (id, offset, len); `finish` serializes the index exactly as `build_pack`'s index half. `parse_pack_reader` reads the header, loops `count` times reading one record, reconstructs the `Object`, verifies `BLAKE3(canonical) == id`, calls `f`.
- [ ] **Step 5: Run** `cargo test -p scl-core pack` then `cargo test` → green (build_pack/parse_pack untouched, all existing pack tests pass). **Step 6: Commit** — `git commit -am "feat(core): incremental PackWriter + streaming parse_pack_reader — byte-identical to build_pack, bounded-RAM (P25)"`

---

### Task 2: wire — chunk-stream framing + CHUNK_SIZE (additive; version still 1)

**Files:**
- Modify: `crates/repo/src/wire.rs` (add pack-stream opcodes + `write_pack_stream`/`read_pack_stream`; do NOT touch `Request`/`Response` pack encoding yet, do NOT bump `PROTOCOL_VERSION` yet)

**Interfaces (produced, consumed by Task 4):**
```rust
pub const CHUNK_SIZE: usize = 1 << 20;  // 1 MiB
// Frame opcodes for the pack sub-stream (distinct from OP_GET_PACK/OP_PUT_PACK):
//   ST_PACK_CHUNK (a data chunk, payload = up to chunk_size bytes)
//   ST_PACK_END   (end marker, empty payload)
// The start of a pack stream is the OK/response or request frame that
// introduces it (Task 4 wires which); Task 2 provides the chunk+end framing.

/// Stream everything from `src` to `w` as ST_PACK_CHUNK frames of at most
/// `chunk_size` bytes each, terminated by one ST_PACK_END frame. Peak RAM =
/// chunk_size. `chunk_size` is a parameter so tests force a tiny value.
pub fn write_pack_stream(w: &mut impl Write, src: &mut impl Read, chunk_size: usize) -> Result<()>;

/// Read ST_PACK_CHUNK frames from `r`, writing each chunk's bytes to `sink`,
/// until ST_PACK_END. Errors on a malformed sequence (a non-chunk/non-end
/// frame, or EOF before END). Peak RAM = one chunk. Returns total bytes.
pub fn read_pack_stream(r: &mut impl Read, sink: &mut impl Write) -> Result<u64>;
```

- [ ] **Step 1: Failing tests** (wire.rs in-module):
  - `pack_stream_round_trip_many_chunks`: a 10 000-byte payload, `write_pack_stream(.., chunk_size=7)` into a buffer, then `read_pack_stream` from that buffer into a sink → sink == original; assert the buffer contains > 1 chunk frame (many frames written).
  - `pack_stream_exact_multiple_and_ragged`: payloads of exactly `2*chunk_size` and `2*chunk_size+3` both round-trip (boundary cases).
  - `pack_stream_empty`: a 0-byte payload round-trips (start immediately END).
  - `read_pack_stream_rejects_missing_end`: feed chunk frames then EOF (no END) → `Err(Protocol)`; feed a wrong-opcode frame mid-stream → `Err(Protocol)`.
- [ ] **Step 2: Implement** `write_pack_stream` (loop: read up to `chunk_size` from `src`, if 0 bytes read write `ST_PACK_END` and stop, else write an `ST_PACK_CHUNK` frame; use the existing `write_frame`) and `read_pack_stream` (loop: `read_frame`; match first byte — `ST_PACK_CHUNK` → write rest to sink; `ST_PACK_END` → return; else `Err(Protocol("unexpected frame in pack stream"))`). Add `CHUNK_SIZE` and the opcodes.
- [ ] **Step 3: Run** `cargo test -p scl-repo wire` + `cargo test` → green (nothing else changed; version still 1). **Step 4: Commit** — `git commit -am "feat(repo): chunk-stream wire framing (write/read_pack_stream) + CHUNK_SIZE — additive, unversioned (P25)"`

---

### Task 3: Transport API reshape to reader/writer — behavior-preserving

**Files:**
- Modify: `crates/repo/src/transport.rs` (the `Transport` trait pack verbs + `LocalTransport` impls + the in-file tests)
- Modify: `crates/repo/src/stdio_transport.rs` (the wire client impls — still single-frame internally this task)
- Modify: `crates/repo/src/sync.rs` (clone/fetch/push call sites)

**Interfaces (produced, consumed by Task 4):**
```rust
// Reshaped Transport pack verbs — reader/writer-based:
trait Transport {
    /// Stream the pack for (wants − haves) into `out`. (Impl may buffer.)
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId], out: &mut dyn Write) -> Result<()>;
    /// Ingest a pack read from `src`; returns the ingested ids.
    fn put_pack(&self, src: &mut dyn Read) -> Result<Vec<ObjectId>>;
}
```

- [ ] **Step 1: Failing/adjust tests** — update the existing `get_pack_excludes_haves_and_put_pack_verifies` and the sync/stdio tests to the new signatures: capture `get_pack` output via a `Vec<u8>` writer, feed `put_pack` via a `&pack[..]` cursor. Keep every assertion (same ids, same verification) — this task is behavior-preserving.
- [ ] **Step 2: Implement.**
  - `LocalTransport::get_pack(.., out)`: unchanged body up to the built `pack: Vec<u8>` (still `build_pack` — local buffered is fine), then `out.write_all(&pack)?`.
  - `LocalTransport::put_pack(src)`: `let mut buf = Vec::new(); src.read_to_end(&mut buf)?;` then the existing `parse_pack(&buf)` + write loop + `index_incoming` verbatim.
  - `stdio_transport` client: `get_pack(.., out)` → `let pack = self.call(GetPack{..})?; out.write_all(&pack)?;` (still single-frame); `put_pack(src)` → `read_to_end` then the existing single-frame `PutPack(buf)` call.
  - `sync.rs`: at each `get_pack`/`put_pack` call, provide a `Vec<u8>` writer / `&pack[..]` reader; the local build_pack sites (sync.rs:194) are unaffected (they build for local use, not via the trait).
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test` + `bash demo/run_ssh_remote_demo.sh` + `bash demo/run_git_remote_demo.sh` → all green (pure reshape; ssh round-trip must still work, still single-frame, still 4 GiB-capped). **Step 4: Commit** — `git commit -am "refactor(repo): Transport pack verbs reader/writer-based — behavior-preserving reshape ahead of streaming (P25)"`

---

### Task 4: wire streaming end-to-end — bounded sender + receiver, v2, temp lifecycle

**Files:**
- Modify: `crates/repo/src/wire.rs` (`PROTOCOL_VERSION = 2`; remove the single-frame `Request::PutPack(Vec<u8>)` payload + `OP_PUT_PACK`-carries-bytes and the `get_pack` single-frame response; the serve loop streams)
- Modify: `crates/repo/src/stdio_transport.rs` (client get_pack/put_pack stream)
- Modify: `crates/repo/src/transport.rs` (a bounded `LocalTransport`-independent receiver helper — see below — OR keep it in wire/serve)
- Create: a small temp-pack guard (RAII removal) — place beside the receiver code (`stdio_transport.rs`/`wire.rs`); reuse the repo scratch/tmp helper (grep how P13/P20 temp checkouts pick a dir; use the same base under `.sc/`)

**Interfaces:**
- Consumes Task 1 (`PackWriter`, `parse_pack_reader`), Task 2 (`write_pack_stream`/`read_pack_stream`, `CHUNK_SIZE`), Task 3 (reader/writer verbs).
- **Bounded receiver ingest** (atomic-after-verify, two passes over the temp file):
```rust
// In the crate (repo): ingest a pack file with bounded RAM, atomically.
// Pass 1: parse_pack_reader over the temp file verifying every record's
// hash, writing NOTHING. Pass 2: parse_pack_reader again, this time
// store.put each object. Then index_incoming. Peak RAM = one object.
fn ingest_pack_file(layout: &Layout, store: &mut Store, path: &Path) -> Result<Vec<ObjectId>>;
```

- [ ] **Step 1: Failing tests:**
  - `streaming_push_and_fetch_round_trip_tiny_chunks` (stdio_transport tests, via the in-process client↔serve harness the existing tests use): build a repo with several objects; drive a `get_pack` and a `put_pack` through the wire with `CHUNK_SIZE` forced tiny (thread a test chunk size — see Step 3) → receiver store == sender objects, ids match, `parse_pack_reader`-level verification exercised. Assert the transfer used multiple chunk frames.
  - `streaming_receiver_leaves_zero_residue_on_success_and_error`: after a successful `put_pack`, the temp pack path is gone; inject a corrupt final chunk (flip a byte) → `put_pack` errns AND the temp pack path is gone AND the store gained NO objects (atomic-after-verify: pass 1 fails before any write).
  - `handshake_rejects_v1_peer`: a hand-rolled peer answering Hello with version 1 → the v2 client errors clearly (adapt the existing `handshake_rejects_version_skew` test to the new constant).
  - Update `run_ssh_remote_demo`-backed integration expectations if any test asserts the old single-frame encoding.
- [ ] **Step 2: Implement the receiver** (`ingest_pack_file`, two-pass, bounded) and wire it: on `PutPack`, the serve loop `read_pack_stream`s the incoming chunks into a temp pack file (RAII-guarded removal), calls `ingest_pack_file`, responds with the ids body; on the client `put_pack(src)`, stream `src` to the server via `write_pack_stream` after the request opcode, then read the ids response.
- [ ] **Step 3: Implement the sender** (bounded): `LocalTransport::get_pack(.., out)` — replace `build_pack`-to-Vec with: gather the id set (as today), open a temp pack file, `PackWriter::new(file, count)`, loop the ids writing each object via `write_object` (peak RAM one object), `finish()`, then `write_pack_stream(out, &mut tempfile, CHUNK_SIZE)` and remove the temp. Client `get_pack(.., out)`: send the `GetPack` request, then `read_pack_stream` the server's chunk stream into `out`. **Chunk-size test override**: add a `pub(crate)` seam — the cleanest is a `wire::pack_chunk_size()` reading an `AtomicUsize` that defaults to `CHUNK_SIZE` and a `#[cfg(test)] set_pack_chunk_size_for_test(n)` — OR thread `chunk_size` through the serve/client stream calls from a field. Pick one; state it in the report. Bump `PROTOCOL_VERSION = 2` and delete the single-frame pack encoding here (v1 dropped).
- [ ] **Step 4: Run** `cargo test -p scl-repo` + `cargo test` + `bash demo/run_ssh_remote_demo.sh` + `bash demo/run_git_remote_demo.sh` → all green (the ssh demo now exercises the streamed path; git-remote is the export/import regression gate). **Step 5: Commit** — `git commit -am "feat(repo): streaming pack transfer end-to-end — bounded sender (PackWriter) + receiver (spill+two-pass verify), v2, zero residue (P25)"`

---

### Task 5: Demo + docs

**Files:**
- Create: `demo/run_streaming_demo.sh` (mode 755)
- Modify: `docs/adr/0035-streaming-transfer.md` (→ Accepted + refinements, code-verified — the exact pack-stream framing, the two-pass atomic ingest, the chunk-size test seam, the temp guard), `docs/adr/README.md` (0035 → Accepted), `ROADMAP.md` (P25 → Done + BOTH a `## Done` narrative bullet AND the completed-phases table row — the P22 missing-bullet lesson; Active → "None — P25 done; P26 HTTP transport is next up"), `CLAUDE.md` (a `**Phase 25 is built.**` paragraph; note the ssh demo now streams and the v1-drop / v2 requirement; no new user command — streaming is transparent)

- [ ] **Step 1: Demo** (house style; read `demo/run_ssh_remote_demo.sh` first — reuse its `SC_SSH` shim). Sequence: init a repo, add a large-ish blob (e.g. a few hundred KB, or generate ~1 MB) + commit; force a tiny chunk size (via `SC_PACK_CHUNK` env if you implemented the atomic seam to read an env var, or a test-only knob — pick a mechanism a shell demo can drive; if none, the demo asserts a normal-chunk clone round-trips and the UNIT tests carry the many-chunks proof — state which in the report); clone over `ssh://` through the shim; assert the clone's `sc log`/object set matches the origin byte-for-byte (a signed commit from P22 verifies clean in the clone — proves signatures rode the stream); assert zero temp residue (`find` for stray pack temps). Run twice; zero-residue trap.
- [ ] **Step 2: Docs** (P24-completion commit shape; refinement candidates: the PackWriter byte-identity guarantee, the two-pass atomic ingest, the chunk-size seam mechanism chosen, where the temp guard lives, the exact opcodes).
- [ ] **Step 3: Full verification** — `cargo test && bash demo/run_streaming_demo.sh && bash demo/run_ssh_remote_demo.sh && bash demo/run_git_remote_demo.sh && bash demo/run_provenance_demo.sh && git diff main -- '*Cargo.toml'` (all green; empty dep diff — NO new dependency; the ssh/provenance demos are the transport + signature-riding regression gates; run_protect_demo.sh pre-P8 failure known — skip).
- [ ] **Step 4: Commit** — `git commit -am "docs+demo: accept ADR-0035 streaming pack transfer; ssh streams >4GiB bounded-RAM (P25)"`
