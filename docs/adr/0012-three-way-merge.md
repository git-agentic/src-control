# ADR-0012: Three-way merge with a snapshot common ancestor

- **Status:** Proposed
- **Date:** 2026-06-25
- **Phase:** 4

## Context

Phase 3 added named branches and commits whose `Snapshot` records `parents`.
There is no way yet to combine two branches' work. Merge is the practical gap
before remotes are useful: fetching remote work is only valuable if it can be
integrated.

## Decision

Implement **three-way merge** keyed on a common ancestor found by walking
`Snapshot.parents`:

1. **Find the merge base** — the lowest common ancestor of the two branch tips by
   walking the parent DAG. (Initial implementation may assume a single-parent
   history; the algorithm generalizes when merge commits introduce a second
   parent.)
2. **Per-path three-way merge** of the base tree, ours, and theirs:
   - changed on one side only → take that side;
   - changed identically on both → take it;
   - changed differently on both → **conflict**.
3. **Conflicts are detected and represented**, not silently resolved. For text
   blobs, write standard conflict markers into the materialized working file; the
   merge stops short of writing a merge snapshot until conflicts are resolved and
   re-committed. A clean merge writes a **merge snapshot** with two `parents`.

`sc merge <branch>` performs the merge into the current branch. Secrets/encrypted
entries (Phase 2/P7) merge by registry/policy entry, not by byte content.

## Consequences

- Branches become genuinely collaborative; `fetch` (P6) + `merge` is the standard
  loop.
- **Destructive-operation safety:** `merge` refuses on a dirty working tree and
  `merge --abort` is the explicit, reversible escape hatch — consistent with the
  cross-cutting destructive-op approval-gate principle (no silent loss of
  uncommitted work). See ROADMAP "Cross-cutting principles".
- `Snapshot.parents` is already a `Vec`, so merge commits (two parents) need no
  format change.
- Conflict representation in the working tree means a merge can leave the tree in
  a "needs resolution" state — `status` must surface that.
- The merge-base walk must handle the multi-parent DAG correctly once merge
  commits exist; tests must cover criss-cross histories.

## Alternatives considered

- **Two-way (no base) merge.** Simpler but produces far more spurious conflicts;
  rejected — the snapshot DAG gives us a base for free.
- **Auto-resolve by recency/ours/theirs.** Hides real conflicts and risks silent
  data loss; rejected as a default (may be offered as an explicit strategy flag
  later).
- **Rebase instead of merge.** Useful but rewrites history and is a larger UX;
  deferred (see ROADMAP "Deferred").
