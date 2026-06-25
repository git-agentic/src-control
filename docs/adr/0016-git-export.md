# ADR-0016: Git export for round-trip interop

- **Status:** Proposed
- **Date:** 2026-06-25
- **Phase:** 9

## Context

`gitio` currently imports a Git repository's HEAD into our store (ADR-0007) but
cannot write back. The thesis is to interoperate with Git, not replace it; teams
need to push src-control history into a Git repo for coexistence, migration, and
existing tooling (`git log`, hosting, CI).

## Decision

Add **`sc export --to <git-repo>`** that maps src-control objects to Git objects,
keeping the translation **quarantined in `gitio`** (the only crate linking `gix`,
per ADR-0007):

- **Blob → Git blob**, **Tree → Git tree** (translating our sorted, mode-bearing
  entries to Git's tree format), **Snapshot → Git commit** (root tree + parents +
  author/message; our `i64` timestamp maps to Git's commit time).
- Export walks from selected refs and writes the equivalent Git object graph, then
  updates a Git ref to the exported commit. Re-export is idempotent: identical
  history maps to identical Git objects.
- **Secrets and encrypted-path objects** have no native Git representation. The
  initial policy is to **export them as their ciphertext blobs** (so nothing
  plaintext leaks) under a reserved path, and to **warn** that confidentiality
  semantics are not enforced by Git on the far side. (A stricter "refuse to export
  protected content" mode is a documented option.)

Import (ADR-0007) plus export gives round-trip interop; full bidirectional sync
(treating Git as a remote via the P6 `Transport`) is a later extension.

## Consequences

- src-control history becomes visible to and migratable into the Git ecosystem.
- The `gix` dependency stays in `gitio`; export is the symmetric peer of import,
  so the boundary and invariant are unchanged.
- Mapping is mostly mechanical because both models are content-addressed DAGs of
  blobs/trees/commits; the lossy points are our extra metadata (secrets registry,
  protection policy, per-entry `perms`) which Git trees cannot carry and which the
  export must handle explicitly rather than silently drop.

## Alternatives considered

- **Git as the on-disk format (no native store).** Abandons the thesis of owning
  the object format and the features that depend on it (committed secrets,
  encrypted paths, in-RAM clones); rejected from the start.
- **One-way migration dump only (no idempotent re-export).** Simpler but breaks
  ongoing coexistence; we want repeatable export so a src-control repo can
  continuously mirror to Git.
- **Exporting decrypted content for Git compatibility.** Would leak protected
  content into an unprotected store; rejected — export preserves ciphertext.
