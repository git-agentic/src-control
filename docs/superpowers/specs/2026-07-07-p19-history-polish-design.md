# P19 — History-editing polish: design

**Date:** 2026-07-07
**Status:** Approved
**ADR:** 0029 (Proposed → Accepted when built)
**Horizon:** `2026-07-07-roadmap-horizon-p16-p20-design.md`

## Problem

P14 deliberately scoped out the ergonomics that make history editing
livable: no `amend`, a rebase that aborts wholesale on the first conflict,
no way to abandon a conflicted cherry-pick except completing it, and a
refusal to replay merge commits at all. With P16 settling rule-merge
semantics and agent workflows (P13/P20) multiplying branches, the human
integrating them needs these tools.

## Decided design

All four features ride the P14/P15 replay core (`three_way_files`, the
perms-aware replay completion, `merge_secrets` registry replay) — no
second merge implementation. Every ref-moving operation is oplog-recorded
and undoable; the ref update remains the atomic commit point.

### `sc amend [-m <msg>]`

Replace the tip commit with one built from the current working tree:
same parents as the tip (amending a merge commit or the initial commit
both work naturally — parents are preserved, including the empty set),
message kept from the old tip unless `-m` supplies a new one. Runs the
full commit pipeline: `.scignore`, the P5 scanner gate, protected-path
re-encryption, secret registry carried. Refuses when unborn or when any
merge/pick/rebase is in progress. Oplog-recorded ("amend"); one `sc undo`
restores the old tip. No pushed-commit guard: sc keeps no authoritative
record of what remote observers have seen — rewriting shared history is
the user's judgment call, as in git. Documented, not enforced.

### Resumable rebase (stop-and-continue becomes the DEFAULT — user-decided)

On the first conflict, `sc rebase <target>` now STOPS instead of
aborting:

- P4-style conflict markers land in the working tree (plus sidecars,
  exactly like a conflicted pick).
- `.sc/REBASE_STATE` persists: the original branch name and tip, the
  accumulated new tip so far (the fold's progress), the ordered list of
  remaining commit ids, and the conflicted commit id. Mirrors
  `pick_state.rs` (plain files under `.sc/`, guarded by the single-writer
  lock). Identity key material is NEVER persisted.
- The branch ref does NOT move — ADR-0024's real guarantee (refs
  untouched until done) is preserved; only the "never leaves in-progress
  state" cosmetic changes. A crash mid-rebase leaves only gc-collectible
  state plus the state files, which `sc rebase --abort` clears.

`sc rebase --continue [--identity <key>]` completes the conflicted commit
from the resolved working tree (the pick-completion machinery, single
parent), then resumes folding the remainder — possibly stopping again on
a later conflict. At final completion the branch ref moves once, and ONE
oplog record covers the whole rebase (before = the original tip, after =
the final tip), so one `sc undo` reverts the entire rebase regardless of
how many stops it had. `--identity` is re-supplied at `--continue` when
the remaining range needs it (same rules as P15 replay).

`sc rebase --abort` deletes the state files and re-materializes the
working tree from the untouched original tip.

Interactions:
- `sc status` reports "rebase in progress" with the conflicted commit and
  progress (k of n).
- `sc commit`, `sc merge`, `sc cherry-pick`, `sc rewrap`, and `sc rebase`
  (a second one) all refuse while a rebase is in progress — the
  `rebase_state::in_progress` guard joins the P17 guard family
  (`MergeInProgress`/`PickInProgress` pattern; new error variant
  `RebaseInProgress`).
- `sc gc` treats the accumulated in-progress tip (from `REBASE_STATE`) as
  a reachability root, like `MERGE_DECIDED_ROOT`/`PICK_DECIDED_ROOT`,
  gated on the state files' presence.
- Completion with unresolved markers still in the tree follows the
  established P4 completion behavior (the user's responsibility), same as
  merge/pick completion today.

### `sc cherry-pick --abort`

Valid only while a pick is in progress: deletes `PICK_HEAD`,
`PICK_CONFLICTS`, and `PICK_DECIDED_ROOT`, then re-materializes the
working tree from the tip (which a conflicted pick never moved). NO oplog
record: no ref moved during the conflicted pick, so there is nothing to
undo — abort is itself the inverse operation.

### Merge-commit replay: `sc cherry-pick <ref> --mainline <N>`

Picking a merge commit becomes possible with an explicit 1-indexed parent
selection (git semantics): the replay base is parent N of the merge, and
the pick applies "what the merge changed relative to parent N" onto the
current branch. Without `--mainline`, picking a merge commit stays
refused — the error now hints at the flag. `--mainline` on a non-merge
commit is an error. Out of scope here: `sc rebase` over a range
containing merge commits stays refused (unchanged); linearizing history
is a different feature.

## Testing & demo

- `amend`: tip replaced (old tip's parents preserved, including merge and
  root cases), message default vs `-m`, scanner/protected/registry
  pipeline exercised, refusals (unborn, each in-progress state), undo
  round trip.
- Rebase: single-stop → resolve → `--continue` → completion → ONE oplog
  record → one `sc undo` reverts all; multi-stop rebase (two conflicting
  commits) resumes twice; `--abort` restores a byte-identical working
  tree and leaves refs untouched; crash-residue simulation (state files
  present, fresh process) → status reports, guards hold, abort clears;
  gc while stopped keeps the accumulated tip alive.
- `cherry-pick --abort`: conflicted pick → abort → tree byte-identical to
  pre-pick, state files gone; abort with no pick in progress errors.
- `--mainline`: pick a merge with N=1 vs N=2 yields the respective
  deltas; non-merge + `--mainline` errors; merge without `--mainline`
  errors with the hint.
- Guards: every pairwise in-progress combination refuses with the right
  typed error.
- Extended `demo/run_history_demo.sh`: an interrupted-and-resumed rebase
  and an aborted cherry-pick, per the horizon's demoable outcome.

## Out of scope

Interactive rebase (reordering/squashing), rebase over merge commits /
history linearization, `--continue` for cherry-pick (the next `sc commit`
already completes a conflicted pick, P14), pushed-commit amend guards,
multi-step undo of a stopped rebase's internal progress (undo operates on
completed operations only).
