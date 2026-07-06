# History editing: cherry-pick + rebase + undo (Phase 14) — design

- **Date:** 2026-07-06
- **Status:** Approved for planning
- **Depends on:** P4 merge (diff3 core, conflict representation, merge-state
  pattern), P8 gc (reachability roots, prune-expire window), P13
  (`build_snapshot`, dirty-tree guard conventions, `sc work` branch
  proliferation as the motivating workload)

## Goal

Give src-control the integration toolkit that P13 made urgent — every
`sc work` session mints N `work-<i>` branches and three-way merge is the only
way to land them — while advancing the ADR-0003 snapshot thesis: history
"editing" never mutates objects, it only adds snapshots and moves refs, which
makes a universal `sc undo` cheap and safe.

**Success bar:** `demo/run_history_demo.sh` proves the P13→P14 story end to
end: `sc work --agents 3` → cherry-pick one agent's commit → rebase another's
branch onto the updated main → `sc undo` restores the pre-rebase refs
byte-identically → a second `sc undo` redoes it → final `sc log` shows linear
history. Zero new dependencies.

## Approach (chosen: compose from P4's merge core, file-backed oplog)

Cherry-pick is a three-way merge with a different base: picking commit C onto
tip T is diff3(base = C's first parent, ours = T, theirs = C) — the P4
machinery computes this today. Rebase is that replay folded over a commit
range, atomic. Undo is a repo-wide operation log that records ref states
before/after each operation; restoring the before-state is the whole
implementation, because the CAS never loses the old snapshots.

Rejected alternatives:
- **Operations as CAS objects (Jujutsu-deep):** op + view objects giving a
  browsable operation DAG and time-travel. Thesis-purest, but a format break
  (new object kinds) for capability the file oplog already delivers. Record
  in ADR-0024 as the natural later upgrade if the oplog proves its worth.
- **Git-style stop-and-continue rebase:** a persisted multi-step state
  machine; deferred — atomic rebase plus cherry-pick-with-resolve covers the
  integration workload, and `--continue` can layer on top later.
- **Per-ref reflogs:** wrong unit — undoing one *operation* that moved
  several refs needs cross-ref coordination anyway.

## Command surface

```
sc cherry-pick <ref> [--author <who>]   # replay one commit onto the current branch
sc rebase <target> [--author <who>]     # replay current branch onto <target>'s tip
sc undo                                 # revert the last operation (run again to redo)
sc oplog                                # list recent operations, newest first
```

- `<ref>`/`<target>` resolve like `sc merge`'s argument (`refs::resolve_tip`:
  local branch, or `remote/branch` remote-tracking ref).
- Author resolution: `--author` > `$SC_AUTHOR` > OS user (same as
  commit/merge). Replayed snapshots get fresh timestamps and the resolved
  author; original message is preserved (rebase) — cherry-pick appends
  ` (cherry-picked from <short-id>)` to the message.
- Cherry-pick and rebase refuse when: the working tree is dirty (same
  protection-aware check as `switch`), a merge is in progress, or a pick is
  in progress. `sc undo` refuses on a dirty tree only when the restore has
  to re-materialize the working tree — i.e. it moves the current branch's
  tip or changes which branch HEAD names (undoing a `switch`).

## Replay core

New module `crates/repo/src/replay.rs`:

```
replay_commit(store, commit_id, onto_root) -> Replayed(new_root)
                                            | Conflicts(Vec<path>)
                                            | Empty
```

- diff3 with base = the commit's **first parent's** root (a root commit —
  no parents — uses the empty tree as base), ours = `onto_root`, theirs =
  the commit's root. Reuses P4's merge internals verbatim; no second merge
  implementation.
- `Empty`: the replayed tree equals `onto_root` (change already present) —
  callers skip the commit with a printed note.
- Commits with 2+ parents are refused before replay with a typed error
  (`Error::CannotReplayMerge`) — no mainline selection in MVP.
- Protection/secrets policy on replayed snapshots: carried from the
  **ours** side (the branch being landed on), same rule as P4 merge.

## Cherry-pick semantics

1. Preflight: clean tree, no merge/pick in progress, ref resolves, target
   commit is not a merge commit, current branch is born.
2. `replay_commit` onto the current tip's root.
   - `Replayed(root)` → `build_snapshot` with single parent = current tip,
     ours-side protection/secrets, message + ` (cherry-picked from <id>)`;
     advance the current branch; materialize the new tip (identity-aware,
     like `switch`). One oplog record.
   - `Empty` → print "already applied — nothing to do"; no snapshot, no
     oplog record.
   - `Conflicts(paths)` → write P4-style conflict markers/sidecars into the
     working tree for the conflicted paths (clean paths from the replay are
     also materialized) and write a pick-state file recording the picked
     commit id. **No ref moves.** The next `sc commit` completes the pick as
     an ordinary single-parent commit and clears the state (the completing
     commit is what gets oplog-logged, as a commit).
3. Pick state: `.sc/PICK_HEAD` (single hex id + newline), sibling of the
   merge-state file, mutually exclusive with it. `sc status` reports
   "cherry-pick in progress: <short-id>"; `sc merge`/`sc rebase`/
   `sc cherry-pick`/`sc switch` refuse while it exists. A `sc cherry-pick
   --abort` is **not** in scope; recovery is: resolve and commit, or restore
   the working tree manually and delete the state via a future op (recorded
   as a follow-on).

## Rebase semantics

1. Preflight: clean tree, no merge/pick in progress, `<target>` resolves,
   current branch born.
2. Resolve merge-base(current tip, target tip).
   - Target is an ancestor of current tip (or equals it) → no-op, print
     "already up to date". No oplog record.
   - Current tip is an ancestor of target → fast-forward the branch ref to
     target tip, materialize. One oplog record.
3. Otherwise: collect the commit range merge-base..current-tip
   (first-parent order, oldest first). If any commit in the range is a merge
   commit → refuse with `Error::CannotReplayMerge` naming it, refs
   untouched.
4. Replay each commit in order onto the accumulating root (starting from
   target tip's root), building snapshots in the CAS only (parents chain:
   first replayed snapshot's parent = target tip). `Empty` replays are
   skipped with a note.
   - Any `Conflicts` → **abort the whole rebase**: refs untouched, working
     tree untouched, error names the offending commit and paths, suggests
     `sc merge` or per-commit `sc cherry-pick`. Already-built CAS snapshots
     are unreferenced garbage for `sc gc` — by design.
5. All replayed → move the current branch ref once, to the last new
   snapshot; materialize the new tip. One oplog record.

## Oplog + undo

**Format.** Append-only text file `.sc/oplog`, one block per operation,
line-oriented and human-readable (house style: hand-rolled like refs/wire,
no serde):

```
op <seq>
ts <unix-seconds>
desc <one-line description, e.g. "rebase work-2 onto main">
head <branch-name-before> <branch-name-after>
ref <name> <before-hex|-> <after-hex|->
ref <name> <before-hex|-> <after-hex|->
end
```

`-` means "absent" (branch created → before `-`; a future delete → after
`-`). `head` records the symbolic HEAD branch name (switch changes it;
most ops don't). Only **touched** refs are recorded. Local branches only —
remote-tracking refs are excluded in v1 (fetch is re-runnable; undoing it
is low value).

**What gets logged.** One record per CLI-level operation that moves local
refs or HEAD, written at the operation's single exit point: `commit`
(including merge-completing and pick-completing commits), `merge` (ff and
merge-commit forms), `branch`, `switch`, `cherry-pick` (clean form),
`rebase` (ff and replay forms), each `sc work` session (one record covering
all harvested branches), secret/protect operations that commit
(`secret add/rotate/grant/revoke`, `protect`, `grant`, `revoke` — described
as such), and `undo` itself. No-ops log nothing.

**Undo.** `sc undo` reads the last record and restores every recorded ref
and the HEAD pointer to their before-state (creating/deleting branch files
as needed). If the restore moves the current branch's tip, it requires a
clean tree and re-materializes (identity-aware). It then appends its own
record (desc `undo of op <seq>: <desc>`), whose before/after are the
inverse — so a second `sc undo` is redo, with zero extra machinery. An
empty oplog → typed "nothing to undo" error.

**GC interplay** (the one real trap): undo must never point a ref at a
pruned object. `sc gc` gains two rules:
1. Every snapshot id appearing in any oplog record (before or after) is a
   reachability root.
2. Before computing roots, gc trims oplog records older than the
   prune-expire window (default 14d, `--prune-expire` honored), always
   keeping at least the most recent record. Trimming bounds the root set;
   an undo past the trimmed horizon is simply "nothing to undo".

The oplog is local state, like a reflog: `clone` does not copy it, and
fetch/push/transport ignore it.

## Invariants

- **No object mutation.** Every P14 command only adds CAS objects and moves
  refs — the property that makes undo total and safe. Content addressing
  and object encoding are untouched (no new object kinds).
- **No silent destruction.** Dirty-tree refusals everywhere a materialize
  can overwrite; atomic rebase (all-or-nothing ref movement); typed errors
  for merge-in-range, nothing-to-undo, and in-progress-state collisions.
- **Dependency rule unchanged**; `replay.rs` and `oplog.rs` live in
  `crates/repo`. Zero new dependencies.
- Ephemeral/persistent mode boundary untouched (all of P14 is
  persistent-mode).

## Error handling

- New typed errors in `crates/repo/src/error.rs`:
  `CannotReplayMerge(ObjectId)`, `NothingToUndo`,
  `PickInProgress(ObjectId)` (also blocks other ops the way
  merge-in-progress does today).
- A crash between oplog append and ref write (or vice versa): writes are
  ordered **refs first, oplog last**, so a torn operation at worst loses
  its undo record — it never fabricates an undo to a state that was never
  reached. Oplog append itself is a single `O_APPEND` write of one block.
- Corrupt/unparseable trailing oplog block: `sc undo`/`sc oplog` report it
  and treat the log as ending at the last parseable record (never panic,
  never guess).

## Testing

- `replay.rs`: clean replay, conflict detection, `Empty` detection, root
  commit (empty-tree base), merge-commit refusal.
- Cherry-pick: clean pick advances branch + materializes; message suffix;
  conflict path writes markers + PICK_HEAD and moves no refs; completing
  `sc commit` is single-parent and clears state; mutual exclusion with
  merge state; dirty-tree refusal.
- Rebase: no-op and ff fast paths; multi-commit replay preserves messages
  and order; `Empty` skip; conflict aborts with refs byte-identical
  (compare full refs dir before/after); merge-in-range refusal; tip
  materialized.
- Oplog/undo: every logged op round-trips (do → undo → refs byte-identical
  to before; undo → undo → refs equal to after); branch-create undo deletes
  the branch file; switch undo restores HEAD + working tree; work-session
  undo removes all harvested branches; nothing-to-undo error; corrupt-tail
  tolerance.
- GC: oplog-referenced snapshots survive `sc gc` that would otherwise prune
  them; trimmed records release their roots; `sc undo` after trim reports
  nothing-to-undo rather than dangling.
- All disk tests clean up and assert the path is gone.

## Demo

`demo/run_history_demo.sh` (house style: set -euo pipefail, fail() gates,
zero-residue check): base repo → `sc work --agents 3` → merge agent 1 →
`sc cherry-pick work-2`'s commit onto main → `sc rebase main` from agent 3's
branch (switch to work-3 first) → `sc undo` proves the pre-rebase ref state
restored (byte-compare refs) → `sc undo` again proves redo → `sc log` shows
the linear result → zero residual session dirs.

## Documentation

- **ADR-0024 — history editing via replay + oplog** (Proposed → Accepted at
  build completion): records the replay-is-merge composition, the file
  oplog vs op-objects decision, atomic rebase vs stop-and-continue, and the
  gc-roots/trim rule.
- **ROADMAP.md:** P14 into `## Active` at phase start; Done + table row at
  completion. Deferred list gains: `sc cherry-pick --abort` / pick-state
  recovery command, `sc rebase --continue` (stop-and-continue),
  merge-commit replay with mainline selection, op-objects in the CAS
  (Jujutsu-deep upgrade), remote-tracking refs in the oplog.
- **CLAUDE.md / ARCHITECTURE.md:** Phase 14 section + command list at
  completion, same choreography as P13.

## Out of scope (deferred, recorded in ROADMAP.md)

- `sc amend` (commit-with-parent-swap; natural P15 candidate with the
  oplog already in place).
- Stop-and-continue rebase; cherry-pick `--abort`.
- Replaying merge commits (mainline selection).
- Operation objects in the CAS / `sc op log` time-travel beyond undo/redo.
- Oplog entries for remote-tracking refs.
