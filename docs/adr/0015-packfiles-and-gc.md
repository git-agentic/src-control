# ADR-0015: Packfiles and reachability-based garbage collection

- **Status:** Accepted
- **Date:** 2026-06-25
- **Phase:** 8
- **Adapts:** git.agentic ADR-0006/0011 (backend trait `delete`/`list_prefix`),
  and its on-disk object sharding + zstd compression

## Context

Phase 3 stores every object as a loose file at `.sc/objects/<hex>`. This is simple
and legible but does not scale: many small files waste inodes and slow directory
walks, unreachable objects (from amended/abandoned work, rewrapped secrets, or
superseded encrypted blobs) accumulate forever, and remote transfer (P6) is
object-at-a-time. We need compaction and space reclamation. The flat,
uncompressed `.sc/objects/<hex>` layout also wastes space and strains a single
directory as object counts grow.

## Decision

Add a **packfile format** and a **`sc gc`** command:

- **Packfile** — a single file concatenating many objects' canonical encodings
  with a companion index mapping `ObjectId → (offset, length)`. The store gains a
  pack-aware read path: on a miss in loose objects, consult pack indexes. Loose
  objects remain the write path; packing is a batch operation.
- **`sc gc`** — compute the reachable set by walking from all refs (branch tips +
  HEAD) through snapshots → trees → blobs/secrets/protected objects, write the
  reachable objects into a packfile, and drop objects that are unreachable **and**
  older than a safety grace window (to avoid racing in-progress work). Reachability
  must include secret/protected-blob objects referenced by snapshot registries and
  policies, not just the file tree.
- **Transfer integration** — P6's `Transport` can move a packfile in bulk instead
  of object-by-object once both ends understand the pack format.
- **Loose-object storage refinements** (adapted from git.agentic): shard loose
  objects into `objects/<first-2-hex>/<rest>` to keep directories small, and
  **zstd-compress** object payloads on disk (the canonical bytes are decompressed
  and BLAKE3-verified on read, so the content-address invariant is unchanged).
  The store gains `delete` and `list_prefix` operations (the latter for orphan
  enumeration during GC), matching the backend trait P6 introduces.

## Consequences

- Bounded object-store growth and far fewer files; faster cold reads via the pack
  index.
- The content-addressing invariant is unchanged: packed objects are the same
  bytes, verified by BLAKE3 on read; packing is purely a storage layout change.
- GC must be conservative — only collect provably unreachable objects past a grace
  window — to never drop reachable history; the single-writer lock (Phase 3)
  prevents concurrent mutation during a GC pass.
- A loose↔pack read path adds complexity to the store; it stays behind the
  existing `Store` API so callers are unaffected.

## Alternatives considered

- **No packing; periodic prune only.** Reclaims space but leaves the
  many-small-files scaling problem and object-at-a-time transfer; insufficient.
- **Embedded KV store as the backend.** Solves packing/compaction but hides the
  hand-owned format behind a third-party engine — rejected earlier (ADR-0011) and
  still inconsistent with the "own the format" thesis.
- **Aggressive immediate GC (no grace window).** Simpler but risks deleting
  objects for work that is staged but not yet ref-pointed; rejected for safety.

## Implementation notes (locked in during build)

Two clarifications were settled during Phase 8 implementation:

1. **Safe GC root set expanded.** The decision text says "all refs (branch tips +
   HEAD)" — the build added `refs/remotes/*` (all remote-tracking refs) and
   `MERGE_HEAD` (when a merge is in progress) to the root set. Branch tips + HEAD
   alone was insufficient; remote-tracking refs and in-progress merge heads must
   also be kept.

2. **Grace window applies to loose objects only.** Packed unreachable objects are
   dropped immediately on repack — they survived at least one prior GC cycle so
   the grace period has already passed. Only loose objects are guarded by the
   mtime-based grace window (default 24 h, configurable via
   `sc gc --prune-expire <dur>`). GC never drops a reachable object; deletions
   happen only after the new pack is durably written.

Additionally, each pack record stores a 32-byte id prefix before the compressed
payload — a lightweight tamper-verification handle that `parse_pack` can check
without a separate index lookup.
