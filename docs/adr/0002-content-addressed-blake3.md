# ADR-0002: Content-addressed objects keyed by BLAKE3

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** Foundation

## Context

The system needs an object model that supports cheap deduplication, verifiable
integrity, and identical addressing across machines (so a snapshot built on one
host matches the same content built on another). It also needs to carry four
kinds of object — file content, directories, snapshots, and (Phase 2) secrets —
through fork, checkout, and clone uniformly.

## Decision

Every object's identity is the **BLAKE3 hash of its canonical serialization**:
`ObjectId = BLAKE3(encode(object))`. Objects are immutable and stored by that id.

The four object kinds are `Blob`, `Tree`, `Snapshot`, and `Secret`. The encoding
is deterministic: a one-byte kind tag, length-prefixed fields, and **tree entries
sorted by name**, so the same logical content always produces the same id.

BLAKE3 was chosen over SHA-1 (cryptographically broken; Git's legacy choice) and
SHA-256 (Git's transition hash) because it is faster, parallel, and tree-
structured, which aligns with future incremental and verified-streaming hashing.

## Consequences

- Identical content is stored once and shares an address — the basis for cheap
  forks and the dedup the store relies on.
- Integrity is intrinsic: a blob fetched from RAM or rehydrated from spill is
  re-addressable and therefore verifiable.
- The canonical encoding is **part of the format contract**. Changing it changes
  every id, so it must be treated as a breaking change with test updates. (See
  the invariant in CLAUDE.md.)
- A per-entry `perms` field is reserved in `Tree` entries now, so the long-term
  per-file permission model lands without a format break.

## Alternatives considered

- **SHA-1 (Git-compatible ids).** Would ease 1:1 Git interop but inherits a
  broken hash and a 40-year-old format. We import from Git (ADR-0007) rather than
  share its object ids, so compatibility at the hash level buys little.
- **SHA-256.** Safe but slower and not tree-structured; no advantage over BLAKE3
  for our access patterns.
- **Random UUIDs / sequential ids.** Lose dedup and verifiability entirely.
