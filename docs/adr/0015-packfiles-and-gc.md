# ADR-0015: Packfiles and reachability-based garbage collection

- **Status:** Proposed
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
