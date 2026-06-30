# P8 — Packfiles, GC, loose-object refinements + bulk-pack transfer: design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-06-30
- **Phase:** 8
- **Refines:** ADR-0015 (firm to Accepted at build time)
- **Builds on:** Phase 3 persistent store (ADR-0011), P4 merge (ADR-0012),
  P6 remotes (ADR-0013), P7 encrypted paths (ADR-0014)

## Goal

Bounded object-store growth and space reclamation for persistent (`.sc/`) repos.
Today every object is a flat, uncompressed loose file at `.sc/objects/<hex>`;
unreachable objects (from abandoned/amended work, rewrapped secrets, superseded
encrypted blobs) accumulate forever, directories grow unbounded, and remote
transfer is object-at-a-time. P8 adds a **packfile format**, a **`sc gc`**
command that compacts reachable objects and prunes unreachable ones, **sharded +
zstd-compressed** loose storage, and **bulk-pack transfer** over the P6
`Transport`.

The content-addressing invariant is unchanged throughout: packed and loose
objects are the same canonical bytes, BLAKE3-verified on every read. Packing and
compression are storage-layout changes only.

## Decisions (locked: brainstorm)

1. **Combined scope.** All four pieces ship in this round: packfiles +
   pack-aware reads, `sc gc` (reachability prune + repack), loose-object
   refinements (sharding + zstd), and bulk-pack transfer wired into P6.
2. **Full safe GC root set.** Reachability walks from **all branch tips +
   resolved HEAD (including detached) + all `refs/remotes/*` + `MERGE_HEAD` when
   a merge is in progress.** The ADR's literal "tips + HEAD" is insufficient:
   pruning remote-tracking history corrupts fetch/push state, and detached-HEAD
   or paused-merge work would be silently lost. The walk itself
   (`reachable_objects`) already covers snapshots→trees→blobs, the `secrets`
   registry, and encrypted blobs (they are ordinary tree entries) — the gap is
   only the roots.
3. **24h mtime grace window, configurable.** Unreachable **loose** objects are
   pruned only once their file mtime is older than the grace window (default 24h,
   overridable via flag/config). Content-addressed objects carry no embedded
   timestamp, so loose-file mtime is the only available age signal — which is why
   GC is designed before/with packing rather than after (packing destroys
   per-object mtime).
4. **Read-both, write-new migration.** The read path resolves legacy flat,
   sharded+zstd loose, and packed objects. New loose writes use sharded+zstd.
   `gc` migrates legacy flat files as a side effect (packed if reachable, pruned
   if unreachable+old). No separate migration command; pre-P8 repos just open.
5. **`gc` is persistent-only.** It operates on `.sc/` refs; ephemeral mode has no
   refs and never packs/prunes. The Phase 1 zero-residue invariant is untouched.
6. **Packed unreachable objects are dropped without grace** (see §3 algorithm
   step 6). The grace window protects *loose* objects (recently written, possibly
   staged); a *packed* object survived a prior `gc`, so it was reachable then and
   is old now. This mirrors git's model (grace protects loose objects, repack
   drops unreachable packed objects).

## Out of scope (this round)

- Delta compression between objects inside a pack (each record is independently
  zstd-compressed; no cross-object deltas). Revisit if pack size demands it.
- Pack `.idx` fanout tables / mmap optimization. A sorted array + binary search
  is enough at current scale.
- Concurrent / incremental GC. `gc` is a stop-the-world batch under the existing
  single-writer lock.
- Reflog-style "keep recently-abandoned tips" beyond the mtime grace window.

## Architecture

Strict dependency direction preserved: `cli → repo → {vfs, gitio, crypto} → core`.

### `core` — pack format, pack-aware store, loose refinements

`core` owns all on-disk object resolution. New `zstd` dependency lives here (the
quarantine rule bars only git/crypto/worktree from leaking out of their crates;
`core` may take ordinary deps).

**Loose layout.** Loose objects move to `objects/<aa>/<rest-of-hex>` where `<aa>`
is the first two hex chars of the id. Payload is `zstd(canonical encode())`.

- Write path: shard directory + zstd-compress before the existing tmp-write +
  atomic-rename. Filename is the hex id of the *decompressed* canonical bytes.
- Read path resolution order on a resident/spill miss:
  1. sharded loose `objects/<aa>/<rest>`,
  2. legacy flat loose `objects/<hex>`,
  3. pack indexes.
  Bytes are zstd-decompressed (falling back to raw for legacy uncompressed
  files), then BLAKE3-verified against the id, then decoded. A mismatch is
  `Malformed`.

**Packfile format.**

```
objects/pack/<packhash>.pack   header(magic+ver) ++ records
objects/pack/<packhash>.idx    header(magic+ver) + u64 count + sorted entries
```

- A `.pack` record is `varint(compressed_len) ++ zstd(encode() bytes)`. No id is
  stored in the body; the id is recovered by decompress+BLAKE3 and lives in the
  index.
- An `.idx` entry is `32-byte ObjectId ++ u64 offset ++ u64 length`, entries
  sorted by id for binary search.
- `packhash = BLAKE3(.pack bytes)`, naming both files.
- On `open_persistent`, the store scans `objects/pack/*.idx` into an in-memory
  map `id → (pack path, offset, len)`; refreshed after `gc` writes a new pack.

**Store API additions** (behind the existing `Store` surface — callers
unaffected):

- `delete(id)` — remove a loose object file (sharded or flat). Never touches
  packs (pack removal is repack's job).
- `list_loose()` — enumerate loose object ids by walking shard dirs (and legacy
  flat files). Used by `gc` for prune candidates and migration sources.
- `loose_mtime(id)` — file mtime for grace decisions.
- `write_pack(ids) -> packhash` — read those objects, write `.pack` + `.idx`,
  load the new index. Used by `gc` and `get_pack`.
- `pack_contains(id)` / `read_pack_object(id)` as needed by the resolution path.

New `Error` variants: `PackCorrupt`, `BadPackIndex`; decompression failure or
hash mismatch on any read surfaces as `Malformed`.

### `repo` — gc orchestration, root-set enumeration, transport pack methods

**Root-set helpers** (new — no API enumerates all refs today):

- list all `refs/heads/*` tips,
- list all `refs/remotes/*/*` tips,
- resolve HEAD including the detached (HEAD-points-at-snapshot) case,
- `MERGE_HEAD` via the existing `merge_state` module.

**`gc` algorithm** — under `RepoLock` (refuses to run without it):

1. Gather the full safe root set (Decision 2).
2. `reachable = reachable_objects(&mut store, &roots)` (existing walk in
   `reachable.rs`).
3. **Repack:** `store.write_pack(reachable)` → one fresh `.pack` + `.idx`.
4. **Drop redundant loose copies:** for each reachable object now in the new
   pack, `delete` its loose file immediately (no grace — it is preserved in the
   pack).
5. **Prune unreachable loose:** for each loose object not in `reachable`,
   `delete` it iff `loose_mtime(id)` is older than the grace window. Recent
   unreachable objects are kept (protects staged/racing work).
6. **Drop superseded packs:** the new pack holds the entire reachable set, so any
   prior pack is redundant for reachable objects; remove prior pack files.
   Unreachable objects that lived only in an old pack are dropped here without
   grace (Decision 6).
7. Migration is implicit: legacy flat files enumerated in step 2/5 get packed
   (if reachable) or pruned (if unreachable+old) by the same pass.

`gc` is idempotent: a second run with no new work writes a pack equal to the
current reachable set and deletes nothing further.

**Transport pack methods.** The existing `LocalTransport::get_object` /
`has_object` read the remote's flat `objects/<hex>` directly — this breaks once
the remote shards/compresses/packs. They must resolve via the same loose-or-pack
logic (open a `Store` on the remote, or share the resolution helper). Two new
trait methods:

- `get_pack(wants: &[ObjectId], haves: &[ObjectId]) -> Vec<u8>` — remote computes
  `reachable(wants) − closure(haves)`, packs it, returns the `.pack` bytes.
- `put_pack(bytes: &[u8]) -> Vec<ObjectId>` — receive a pack, BLAKE3-verify
  **every** record, index it, write each object into the store, return the
  contained ids. The caller updates refs afterward (a pack never moves refs).

Object-at-a-time methods stay for negotiation (`list_refs`, `has_object`) and
back-compat.

### `cli` — `sc gc` + transfer wiring

- `sc gc [--prune-expire <dur>]` (default 24h). Reports objects packed, loose
  pruned, packs removed, bytes reclaimed.
- **Push:** compute objects the remote lacks (reachable from pushed tips minus
  what the remote has) → one `put_pack` → `update_ref`.
- **Clone/fetch:** `get_pack(wants = remote tips, haves = local tips)` → apply →
  update remote-tracking refs.

## Data flow

- **Write (commit):** object → sharded path + zstd → tmp-write + rename. Pack
  files are written only by `gc` / `get_pack`.
- **Read (any get):** resident → spill → sharded loose → flat loose → pack
  index. Decompress → BLAKE3-verify → decode at every disk hit.
- **gc:** lock → roots → reachable walk → write pack → delete redundant loose →
  prune old unreachable loose → drop old packs → unlock.
- **push:** local reachable-minus-remote-has → pack → `put_pack` → `update_ref`.
- **clone/fetch:** `get_pack(wants, haves)` → verify+index+write → update
  remote-tracking refs.

## Error handling

- Every packed/loose read BLAKE3-verifies the decompressed canonical bytes
  against the id; mismatch → `Malformed`. `put_pack` rejects the whole pack if
  any record fails verification (`CorruptObject` / `PackCorrupt`).
- A malformed `.idx` (bad magic, truncated, unsorted) → `BadPackIndex`; the store
  refuses to load it rather than silently skipping objects.
- `gc` errors (not the lock holder, a root that fails to resolve) abort the pass
  before any deletion; deletions happen only after the new pack is durably
  written and verified, so an interrupted `gc` never loses a reachable object.

## Testing

- **Pack roundtrip:** write N objects to a pack, read each back, ids verify;
  flip a `.pack` byte → `Malformed`; corrupt a `.idx` → `BadPackIndex`.
- **Loose refinements:** sharded+zstd roundtrip; a legacy flat *uncompressed*
  file still reads after the upgrade.
- **gc reachability:** repo with reachable + unreachable (old + recent) objects →
  reachable survive (now packed, loose gone), recent-unreachable kept,
  old-unreachable pruned. Idempotent second run is a no-op for deletions.
- **Root-set protection:** separate cases where the only ref to an object is a
  detached HEAD / a `refs/remotes/*` ref / `MERGE_HEAD` — each must protect its
  objects from prune.
- **Lock:** `gc` without the lock errors; `gc` holds the lock for the whole pass.
- **Transport:** push and clone via pack move exactly the right closure; a
  tampered pack is rejected by `put_pack`; remote read resolves packed/sharded
  objects (not just flat).
- **Invariants:** ephemeral mode never packs/gcs (zero-residue untouched);
  persistent `gc` reclaims measurable space. Extend `demo/run_repo_demo.sh` to
  show `gc` shrinking `.sc/` after abandoned work.
