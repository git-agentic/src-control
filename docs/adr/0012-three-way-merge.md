# ADR-0012: Three-way merge with a snapshot common ancestor

- **Status:** Accepted
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

**As built (P4):** line-level diff3 is hand-rolled (LCS-based, in `scl_repo::diff3`);
the conflict workflow uses `.sc/MERGE_HEAD` + `.sc/MERGE_CONFLICTS` with a
merge-aware `commit` that records both parents; fast-forward and
already-up-to-date are short-circuits; binary conflicts keep ours and write a
`<path>.theirs` sidecar; a secret-registry conflict aborts the merge atomically.

## Amendment (P37c-i, ADR-0049)

Two behaviors changed, both fixes:

- **Mode is merged separately from content.** Content still resolves by blob id
  (and the `PROTECTED` bit for protected paths). The mode of the result is then
  a three-way on the modes of the entries that exist: equal wins, a side equal
  to base yields to the side that changed, a lone survivor (delete/modify)
  keeps its own mode, and when both sides changed differently executable wins.
  Previously the mode followed whichever side's entry was kept, so a mode-only
  change on one side was silently dropped (the unchanged side's blob id equalled
  the changed side's, so the unchanged side's entry won).
- **A file/directory collision is rejected before any output is written.**
  When the merged result would make a name both a file and a directory (`x` and
  `x/child`), the merge fails with `PathCollision` naming the path. This
  covers every caller of the file merge: `sc merge`, cherry-pick, rebase, the
  merge into a private branch and the `sc ws harvest` auto-merge check (a
  colliding workspace falls back to a `work-<i>` branch). Previously
  the tree writer emitted both a blob and a tree with that name and
  materialization failed after changing working files.

## Alternatives considered

- **Two-way (no base) merge.** Simpler but produces far more spurious conflicts;
  rejected — the snapshot DAG gives us a base for free.
- **Auto-resolve by recency/ours/theirs.** Hides real conflicts and risks silent
  data loss; rejected as a default (may be offered as an explicit strategy flag
  later).
- **Rebase instead of merge.** Useful but rewrites history and is a larger UX;
  deferred (see ROADMAP "Deferred").
