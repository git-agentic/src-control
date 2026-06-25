# ADR-0011: Persistent loose-object store and git-like working tree

- **Status:** Accepted
- **Date:** 2026-06-25
- **Phase:** Post-Phase-2 (persistence)

## Context

Phases 1–2 kept everything in RAM. To use src-control as a real VCS — and to let
committed secrets survive between `sc` invocations — the object store and refs
must be durable on disk.

## Decision

- **Loose content-addressed objects.** Each object is a file at
  `.sc/objects/<hex>` whose contents are the canonical `Object::encode()` bytes,
  so `BLAKE3(contents) == filename`. Reuses the existing encoding and `ObjectId`;
  no new format. Packing is deferred.
- **Write-through persistence.** `core::Store` gains a `Persistent(PathBuf)`
  backend: every `put` writes the object durably (idempotent tmp+rename) before
  returning; a read-miss loads+verifies+decodes from disk; blob eviction drops
  only the RAM copy because disk is authoritative.
- **Mode-scoped disk invariant.** Ephemeral mode (agents, `sc demo`) keeps the
  zero-residue guarantee unchanged. Persistent mode (`sc init` repos) writes to
  `.sc/` by design; `.sc/` is user-owned durable state, like `.git`.
- **Git-like working tree.** `.sc/` sits at a repo root; the files beside it are
  the working tree. `commit` snapshots it; `switch` materializes a branch tip
  (refusing if tracked files are modified or deleted, to prevent data loss);
  `status` diffs working tree vs HEAD. Refs are symbolic-HEAD + `refs/heads/*`,
  updated atomically; a `.sc/lock` enforces single-writer.

## Consequences

- src-control is usable as a standalone local VCS (init/commit/status/log/branch/
  switch) and secrets persist across invocations.
- `core` stays free of Git/worktree/crypto deps; the repo layer lives in the new
  `scl-repo` crate (`cli → repo → {vfs, crypto} → core`; `cli` continues to link
  `gitio` directly for the `import` command).
- Merge, packfiles/gc, fsync tuning, and remotes are explicit follow-ons.

## Alternatives considered

- **Single packfile + index** / **embedded KV (redb/sled).** More robust at scale
  but heavier and hide the hand-owned format; rejected for the MVP in favor of
  legible loose objects (which the ephemeral spill backend already prototyped).
