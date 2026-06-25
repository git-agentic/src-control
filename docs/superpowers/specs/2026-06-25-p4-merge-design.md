# P4 — Merge & conflict resolution: design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-06-25
- **Phase:** 4 (first roadmap phase)
- **Refines:** ADR-0012 (firm to Accepted at build time with the refinements below)

## Goal

Combine the work of two branches. `sc merge <branch>` performs a three-way merge
of the current branch and the named branch using their common ancestor. Clean
merges produce a two-parent merge snapshot automatically; conflicts are detected,
marked in the working tree, and resolved by the user before committing. This makes
the Phase 3 branches genuinely collaborative and sets up the fetch→merge loop for
P5 (remotes).

## Decisions (locked during brainstorming + ADR-0012)

1. **Three-way merge** keyed on the lowest common ancestor (LCA) found by walking
   the `Snapshot.parents` DAG.
2. **Line-level (diff3-style) granularity**, **hand-rolled** (no external crate):
   non-overlapping line edits on each side merge cleanly; only overlapping regions
   conflict.
3. **Conflict workflow = MERGE_HEAD state + resolve + commit** (Option A): clean
   merges auto-commit a two-parent snapshot; conflicts write markers + persist
   merge state and stop; the user resolves in the working tree and `sc commit`
   finalizes the two-parent snapshot; `sc merge --abort` restores.
4. Fast-forward when one tip is an ancestor of the other; conservative,
   atomic aborts for cases with no safe in-tree resolution.

## Out of scope (this round)

- Rebase, cherry-pick, octopus (>2 parent) merges.
- Rename/move detection (a rename reads as delete + add).
- Merge strategy flags (`--ours`/`--theirs`/`-X`); a single default strategy.
- Interactive/3-pane conflict resolution UX beyond in-tree markers.

## Architecture

All work lands in `scl-repo` (no changes needed to `core`/`vfs`/`crypto` beyond
generalizing one repo method). New modules:

- **`crates/repo/src/diff3.rs`** — pure, dependency-free line-level three-way
  merge. `merge_lines(base, ours, theirs) -> Merged` where
  `Merged { text: String, conflicted: bool }`. Built on a Longest-Common-
  Subsequence diff of base→ours and base→theirs, then a diff3 reconciliation:
  regions changed on only one side are taken; regions changed on both
  identically are taken once; regions changed on both differently emit
  `<<<<<<< ours / ======= / >>>>>>> theirs` markers and set `conflicted`.
  Operates on `\n`-split lines; preserves a trailing-newline flag.
- **`crates/repo/src/merge.rs`** — orchestration: `merge_base`, the per-path
  three-way resolution, conflict collection, and merged-tree construction.
- **`crates/repo/src/merge_state.rs`** — read/write/clear the on-disk merge state.
- **`crates/repo/src/repo.rs`** — `merge`, `merge_abort`, merge-aware `commit`,
  and a generalized `commit_snapshot` taking `parents: Vec<ObjectId>`.

### Generalizing `commit_snapshot`

Today `commit_snapshot(root, parent: Option<ObjectId>, secrets, author, message)`.
Change the signature to `parents: Vec<ObjectId>` and update the two existing
callers (`commit` passes `head_tip().into_iter().collect()`; the secrets path in
`secrets.rs` likewise). A merge commit passes `vec![ours, theirs]`.

## Components & data flow

### Merge base (LCA)

`merge_base(a, b) -> Option<ObjectId>`: breadth-first walk the ancestor sets of
both tips over `Snapshot.parents`; return the first commit reachable from both
(the lowest common ancestor). Returns `None` if the histories share no ancestor.
The algorithm must traverse multi-parent merge commits, not assume linear history.

### `sc merge <branch>`

1. **Guard:** refuse if a merge is already in progress (`.sc/MERGE_HEAD` exists →
   `Error::MergeInProgress`) or the working tree is dirty (`status()` shows
   modified/deleted → same guard as `switch`).
2. Resolve `theirs` = tip of `<branch>` (`Error::NoSuchBranch` if missing) and
   `ours` = current `head_tip()`.
3. **Ancestor checks:**
   - theirs is an ancestor of ours → "already up to date", no-op.
   - ours is an ancestor of theirs → **fast-forward**: advance the current branch
     ref to theirs, materialize theirs into the working tree, done (no merge
     commit).
4. Otherwise `base = merge_base(ours, theirs)`; `None` → `Error::NoCommonAncestor`,
   no changes.
5. **Secrets registry three-way merge** (before touching files, so a registry
   conflict aborts atomically): for each name across base/ours/theirs `secrets`
   maps, take the changed side; same name changed differently on both →
   `Error::SecretMergeConflict(name)`, no changes. Otherwise compute the merged
   registry.
6. **Per-path file three-way** over `tree_file_ids(base/ours/theirs)`:
   - present/identical handling (added one side, deleted one side, unchanged
     side, both-equal) resolves without conflict;
   - both changed differently:
     - **UTF-8 text** → `diff3::merge_lines`; clean result merges, else markers +
       record the path as conflicted;
     - **binary / non-UTF-8** → leave *ours* at the path, write *theirs* to
       `<path>.theirs`, record the path as conflicted.
7. Build the merged root tree from the resolved file set via `vfs::write_tree`,
   carrying the merged secrets registry.
8. **No conflicts** → write merge snapshot `Snapshot { root, parents: [ours,
   theirs], secrets: merged, author, message: "merge <branch>" }`, advance the
   branch ref, materialize the merged tree. **Conflicts** → materialize the merged
   working tree (markers/sidecars in place), write `.sc/MERGE_HEAD` = theirs +
   the conflicted-path list, and stop with `Error::MergeConflicts(n)` (a
   user-facing summary, not a crash).

### Merge state (`.sc/MERGE_HEAD`)

A small text file holding the `theirs` snapshot id; a companion
`.sc/MERGE_CONFLICTS` lists conflicted paths (one per line). Written atomically
(tmp+rename), removed on a successful merge commit or `--abort`. Single-writer
lock (Phase 3) already serializes access.

### Merge-aware `commit`

When `.sc/MERGE_HEAD` exists, `commit` builds the snapshot with
`parents: [head_tip, MERGE_HEAD]` (the two-parent merge commit), then clears the
merge state. (It does not re-scan for conflict markers; resolving is the user's
responsibility — a later refinement could warn on leftover markers.)

### `sc merge --abort`

Restore the working tree to the pre-merge `ours` snapshot via
`materialize(ours_root)`, remove any `<path>.theirs` sidecars that were created,
and clear the merge state. Errors if no merge is in progress.

### Mid-merge guards

- `status` reports "merge in progress (N conflicts): <paths>" when `MERGE_HEAD`
  exists, in addition to the normal working-tree diff.
- `switch` and a second `merge` refuse while a merge is in progress
  (`Error::MergeInProgress`).

## CLI

- `sc merge <branch>` — perform the merge (or fast-forward).
- `sc merge --abort` — abandon an in-progress merge.
- `sc commit` — unchanged invocation; finalizes a merge when one is in progress.
- `sc status` — now also surfaces merge-in-progress state.

## Error handling

New `scl-repo::Error` variants (thiserror): `MergeInProgress`,
`MergeConflicts(usize)` (carries the count; the CLI prints the conflicted paths),
`NoCommonAncestor`, `SecretMergeConflict(String)`. The CLI maps via `anyhow`;
`MergeConflicts` is presented as actionable guidance (resolve listed files, then
`sc commit`), not an error stack.

## Testing

- **`diff3` unit tests** (pure, no IO): non-overlapping edits merge clean; both
  sides add different lines at the same spot → conflict markers; one side edits, a
  region the other deletes → conflict; identical edits on both sides → no
  conflict; trailing-newline preservation; empty-file and whole-file-replaced
  cases.
- **`merge_base`**: linear history; a criss-cross / two-parent merge-commit DAG
  picks the correct LCA; unrelated histories → `None`.
- **Repo-level**: fast-forward advances the ref with no merge commit;
  already-up-to-date is a no-op; a clean three-way merge writes a snapshot with
  two parents and the merged content; a conflicting merge writes markers + `.sc/
  MERGE_HEAD` + conflict list and stops; resolving then `sc commit` produces the
  two-parent snapshot and clears state; `sc merge --abort` restores the pre-merge
  tree and removes sidecars; merge refuses on a dirty tree and while a merge is
  already in progress; binary conflict writes `<path>.theirs`; a secrets-registry
  conflict aborts atomically with no changes.
- **End-to-end** in `demo/` or an integration test: branch, divergent commits on
  each, `sc merge`, resolve a conflict, `sc commit`, `sc log` shows the
  two-parent merge.

Every new behavior ships with a test, per project convention.

## ADR

Firm **ADR-0012** from Proposed to Accepted when this ships, recording the
refinements decided here: line-level **hand-rolled** diff3; the MERGE_HEAD
state + resolve + commit workflow; fast-forward handling; and the conservative
binary / secrets-registry conflict policies.

## Open follow-ons (not this round)

- Rename/move detection; merge strategy flags; rebase/cherry-pick.
- Warn (or block) on committing a tree that still contains conflict markers.
- Richer conflict-resolution UX.
