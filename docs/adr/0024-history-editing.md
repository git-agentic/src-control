# ADR-0024: History editing via replay + operation log

- **Status:** Accepted
- **Date:** 2026-07-06
- **Phase:** 14
- **Builds on:** ADR-0012 (three-way merge), ADR-0015 (gc), ADR-0023 (agent
  workspaces — the branch-proliferation workload)

## Context

Every `sc work` session mints N `work-<i>` branches; three-way merge is the
only integration tool. The snapshot model (ADR-0003) promises cheap, safe
history editing: objects are immutable, so "editing" is adding snapshots and
moving refs.

## Decision

- **Replay is merge.** Cherry-picking commit C onto tip T is
  diff3(base = C's first parent, ours = T, theirs = C), computed by the
  existing P4 machinery (`three_way_files`, extracted from `three_way`).
  Root commits use an empty base. Merge commits and protected content are
  refused (typed errors) — the latter inherits P4's fail-closed guard.
- **Cherry-pick resolves; rebase is atomic.** A conflicted pick writes P4
  markers plus `.sc/PICK_HEAD`; the next `sc commit` completes it
  single-parent. A conflicted rebase aborts wholesale with refs and working
  tree untouched.
- **One operation log, all operations.** Append-only `.sc/oplog` records
  HEAD and every touched local ref before/after each ref-moving operation.
  `sc undo` restores the last record's before-state and appends its own
  record, so undo-of-undo is redo. Local-only, like a reflog.
- **GC interplay:** oplog-referenced snapshot ids are reachability roots;
  gc trims records older than the prune-expire window (always keeping the
  most recent), bounding the root set.

## Alternatives considered

- Operations as CAS objects (op + view objects, jj-style time travel):
  format break for capability the file oplog already delivers; natural
  later upgrade.
- Git-style stop-and-continue rebase: a persisted multi-step state machine;
  atomic rebase + per-commit cherry-pick covers the workload, `--continue`
  can layer on later.
- Per-ref reflogs: wrong unit — undo works on operations, which move
  several refs.

## Consequences

- Undo never dangles: anything the oplog can restore is a gc root until the
  record is trimmed; past the horizon undo reports "nothing to undo".
- A torn operation (crash between ref write and oplog append) loses its
  undo record but never fabricates one (refs first, oplog last).
- Rebase abandons already-built snapshots on abort — ordinary gc fodder.
- Replay does not carry secret-registry changes: `sc rebase`/`sc cherry-pick`
  warn when they skip a commit's registry change instead of replaying it
  (follow-on: registry replay).

## Refinements during the build

- **Materialize before the ref move, not after.** The original sketch of
  `cherry_pick`/`rebase`'s clean path moved the branch ref and then
  materialized the working tree. Review corrected the ordering to match
  `merge`'s existing crash discipline: build the snapshot in the CAS,
  materialize the working tree, *then* move the branch ref — the ref update
  is the atomic commit point, so a crash before it leaves both tip and tree
  consistently at the pre-operation state instead of a moved ref pointing at
  an unmaterialized tree.
- **`oplog::record` heals a torn tail before appending.** A crash mid-append
  can leave a partial trailing block. Rather than treat that as fatal or
  append blindly after it (which would hide the new record behind corrupt
  bytes), `record()` truncates the torn tail first, so the next real record
  is always visible and a crash can't silently poison future undo/oplog
  reads.
- **Undo of the initial commit is refused, not un-borne.** There is no
  working tree to materialize back to before the first commit; rather than
  delete the branch ref and leave stale tracked files on disk, `undo`
  refuses with a typed error pointing at an intermediate step instead. A
  deliberate scope cut, not an oversight.
- **`sc undo` surfaces skipped protected paths.** Re-materializing during
  undo can hit protected paths the caller has no key for. `UndoOutcome`
  carries a `skipped` list (mirroring `switch`'s existing behavior) instead
  of silently leaving stale plaintext or failing the whole undo.
- **`sc protect` yields two oplog records, not one.** `protect` first
  persists the new protection rule as a policy-only commit, then runs the
  ordinary commit path to encrypt matching working-tree files — two
  distinct ref moves, so two oplog records (policy commit, then encryption
  commit). This gives undo a coherent before/after chain instead of
  collapsing a two-step operation into one record that could only be
  undone atomically.
