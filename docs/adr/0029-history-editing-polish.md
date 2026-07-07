# ADR-0029: History-editing polish — amend, resumable rebase, pick abort, merge replay

- **Status:** Accepted
- **Date:** 2026-07-07
- **Phase:** 19
- **Builds on:** ADR-0024 (history editing), ADR-0025 (protected merge & replay), ADR-0026 (rule-merge semantics)
- **Spec:** `docs/superpowers/specs/2026-07-07-p19-history-polish-design.md`

## Context

ADR-0024 deliberately scoped out `sc amend`, stop-and-continue rebase,
`cherry-pick --abort`, and merge-commit replay. With ADR-0026 settling how
protection rules merge, the replay core's semantics are stable enough to
build the remaining ergonomics without rework — and P13/P20 agent
workflows multiply the branches a human must integrate.

## Decision

Four additions riding the existing P14/P15 replay core, no second merge
implementation:

- **`sc amend [-m <msg>]`** rebuilds the tip commit from the current
  working tree with the tip's own parents (merge and root commits amend
  naturally), message kept unless `-m`, through the full commit pipeline
  (scanner, `.scignore`, protected re-encryption, registry carried).
  Oplog-recorded and undoable. No pushed-commit guard — sc keeps no
  authoritative record of remote observers; documented, not enforced.
- **Resumable rebase, stop-and-continue as the DEFAULT** (user-decided,
  revising ADR-0024's atomic-abort): a conflict stops with P4 markers and
  a persisted `.sc/REBASE_STATE` (original branch+tip, accumulated new
  tip, remaining commit ids, conflicted commit — never identity key
  material). The branch ref does not move until final completion, so
  ADR-0024's real guarantee (refs untouched until done) is preserved.
  `sc rebase --continue [--identity]` completes the conflicted commit via
  the pick-completion machinery and resumes the fold; completion moves
  the ref once and writes ONE oplog record for the whole rebase (one
  `sc undo` reverts it all). `sc rebase --abort` clears state and
  re-materializes the untouched tip. `rebase_state::in_progress` joins
  the guard family (`RebaseInProgress`) on commit/merge/pick/rewrap/
  rebase; `sc status` reports progress; gc roots the accumulated tip via
  the state file.
- **`sc cherry-pick --abort`** clears `PICK_HEAD`/`PICK_CONFLICTS`/
  `PICK_DECIDED_ROOT` and re-materializes the (never-moved) tip. No oplog
  record: no ref moved, abort is its own inverse.
- **`sc cherry-pick <ref> --mainline <N>`** replays a merge commit with
  base = its 1-indexed parent N (git semantics). Merge picks without the
  flag stay refused, now with a hint; `--mainline` on a non-merge errors.
  Rebase over merge-containing ranges stays refused (linearization is a
  different feature).

## Consequences

- An interrupted rebase becomes resumable rather than all-or-nothing; the
  extended history demo proves interrupt → resolve → `--continue` and an
  aborted pick.
- New persisted in-progress state (`REBASE_STATE`) that status, gc, and
  the guard family must respect — the same pattern as merge/pick state,
  now three-way.
- Undo granularity is per-operation: a multi-stop rebase is still one
  oplog record, one undo. In-progress internal steps are not undoable
  (abort covers that).

## Alternatives considered

- **Keep atomic-only rebase (flag-gated resumability):** preserves the
  ADR-0024 contract literally but hides the useful behavior behind a flag
  nobody remembers; rejected by the user in the phase brainstorm since
  refs-untouched survives the default change.
- **Oplog-record the pick abort:** records a no-op (no ref moved) and
  makes `sc undo` after an abort confusingly "redo nothing"; rejected.
- **Rebase merges via --rebase-merges-style replay:** far larger surface
  (recreating merge topology); deferred with history linearization.

## Refinements discovered during the build

- **Two behavior-preserving extractions, done as groundwork before the
  resumable-rebase work.** `Repo::assemble_completion_snapshot`
  (`crates/repo/src/repo.rs`) pulls the pick-completion snapshot assembly
  out of `commit`'s pick-completion arm, so `rebase_continue` reuses the
  exact same pipeline a resolved cherry-pick uses (scanner gate, protected
  re-encryption, decided-root carry-forward) instead of a second
  implementation. Doing this exposed that `Repo::tracked_paths` (private,
  reads `.scignore` against a tip) was hardcoded to `head_tip()` — wrong
  for a rebase fold, where the completing parent is the fold's accumulated
  tip (`acc_tip`), not necessarily HEAD, while the rebase is stopped. Left
  as `head_tip()`, the naive extraction would have silently DROPPED files
  ignore-matched relative to the wrong tip. It was generalized to
  `tracked_paths_at(tip: Option<ObjectId>)`, with `tracked_paths()` now a
  thin `self.tracked_paths_at(self.head_tip()?)` wrapper
  (`crates/repo/src/repo.rs:125-149`). The shared rebase fold,
  `Repo::rebase_fold_and_finish` (`crates/repo/src/replay.rs:756`), is the
  second extraction: both `rebase`'s first pass and `rebase_continue`'s
  resumed fold call it, so there is exactly one fold implementation
  regardless of how many times a rebase stops. This was adjudicated real
  (not cosmetic) in review, specifically because of the `tracked_paths`
  bug it would otherwise have shipped.
- **A Critical, found in review: `rebase --continue` was not
  error-recoverable.** The original `rebase_continue` cleared
  `REBASE_STATE` before calling the resumed fold — so a typed error from
  the fold on a LATER commit in the range (`ProtectedMergeNeedsIdentity`
  or `NotAuthorized` when `--identity` was omitted, or
  `SecretMergeConflict`) destroyed resumability: the state was already
  gone, so the user had no `--continue` to retry and no `--abort` to fall
  back to. Fixed (`crates/repo/src/replay.rs`, commit `0f7611a`): state is
  now cleared only by the fold's own completion tail
  (`rebase_fold_and_finish`, after the ref move and the oplog record) or
  overwritten by the next stop — never up front in `rebase_continue`. To
  keep a retried `--continue` idempotent, `RebaseState` gained a
  `resolved: bool` field (`crates/repo/src/rebase_state.rs`, defaulting to
  `false` on parse for on-disk forward-compatibility with pre-fix state
  files): once `assemble_completion_snapshot` succeeds for the conflicted
  commit, state is immediately rewritten with `acc_tip` advanced and
  `resolved = true` **before** the fold is attempted, so a retry after a
  fold error sees `resolved == true` and skips straight to the fold
  instead of re-completing (double-applying) the already-landed commit.
  Regression test:
  `rebase_continue_error_preserves_state_and_retry_succeeds`
  (`crates/repo/src/replay.rs`).
- **`rebase_abort` and `cherry_pick_abort` both needed a deletion
  baseline, not a full clean materialize.** The original
  `rebase_abort`/`cherry_pick_abort` re-materialized with `old_root: None`
  (a full clean rewrite from the pre-rebase/pre-pick tip), which does not
  delete anything the STOP's own conflict-materialize had pulled onto disk
  from the other side (e.g. a target-only or theirs-only new file) — that
  file simply isn't touched by a clean materialize that only writes what
  the target tree names, so it survives as untracked residue. Both now
  pass the persisted decided root
  (`REBASE_DECIDED_ROOT`/`PICK_DECIDED_ROOT` — the tree the stop actually,
  currently wrote to disk) as `old_root`, mirroring `merge_abort`'s
  established `theirs_root`-as-`old_root` pattern
  (`crates/repo/src/replay.rs:1058` for `rebase_abort`,
  `crates/repo/src/replay.rs:561` for `cherry_pick_abort`, which documents
  itself as mirroring `rebase_abort`'s fix exactly). Review-caught, not
  self-discovered: the residue-drop itself is pinned by the regression test
  `rebase_abort_drops_stop_materialized_target_files` (it deliberately picks
  a target-only new file so the fix is discriminating). The extended demo's
  cherry-pick-abort checksum step (`demo/run_history_demo.sh`, section 10)
  is a narrower proof — its conflict only touches the one shared file, so it
  confirms byte-identical restore on the happy path but does not by itself
  exercise the residue-drop fix.
- **A second Important: mainline picks based the secret-registry
  three-way on the wrong parent.** `--mainline <N>` (`crates/repo/src/
  replay.rs`) resolves file replay against the chosen parent N via
  `base_override` in `replay_commit`, but the secret-registry three-way
  (`merged_registry_for_replay`) originally still defaulted to the
  commit's FIRST parent regardless of `--mainline` — a silent
  wrong-registry bug: a mainline-2 pick could apply file changes relative
  to parent 2 while computing its secret delta relative to parent 1,
  landing (or dropping) secrets the mainline selection never intended.
  Both call sites now thread the SAME resolved parent through
  `base_override` (`merged_registry_for_replay`'s own `base_override`
  parameter, `crates/repo/src/replay.rs:34-53`, and the cherry-pick
  dispatch at `crates/repo/src/replay.rs:343-385`), so file replay and
  registry replay agree on what "relative to parent N" means. Regression
  test: `mainline_pick_registry_bases_off_chosen_parent`
  (`crates/repo/src/replay.rs:1621`). `sc amend` avoids this whole class of
  bug structurally rather than by parallel-plumbing: it reuses the shared
  `snapshot_files` pipeline (`crates/repo/src/repo.rs:201`) with a
  `parents_override` parameter (`crates/repo/src/repo.rs:492-522`) that
  swaps in the tip's own parents in place of `[tip]`, so there is exactly
  one commit-assembly path and no second place for files and registry to
  disagree.
- **`CannotReplayMerge` is now contextualized per call site.** The error
  used to carry one generic message regardless of caller. Cherry-pick's
  single-commit replay (`replay_commit`, `crates/repo/src/replay.rs:165`)
  now hints `--mainline <N>`, since a pick operates on one commit and a
  flag can resolve it directly. Rebase's range pre-scan
  (`crates/repo/src/replay.rs:715`) instead says "linearize or drop it
  first" — a rebase replays a whole linear range, so there is no single
  "relative to which parent" choice a flag could offer; the fix is
  structural (drop the merge from the range, or linearize it), not a flag.
- **Oplog granularity: ONE record per completed multi-stop rebase, and
  pick abort writes none.** `rebase_fold_and_finish`
  (`crates/repo/src/replay.rs:951`) records exactly one oplog entry at its
  completion tail, `before = original_tip` (the rebase's pre-rebase tip,
  captured once at the very start and threaded through every stop),
  `after = acc_tip` — true regardless of how many times the rebase
  stopped and was resumed, since intermediate stops never move the branch
  ref or write to the oplog. `cherry_pick_abort`
  (`crates/repo/src/replay.rs:561`) writes no oplog record at all: no ref
  ever moved during a stopped pick, so abort is its own inverse and there
  is nothing for `sc undo` to usefully reverse. Known cosmetic gap, not
  fixed here: the oplog description's `({replayed} replayed, {skipped}
  skipped)` counts are computed fresh inside each call to
  `rebase_fold_and_finish` (`crates/repo/src/replay.rs:775-776`, reset to
  0 every invocation), so a multi-stop rebase's final oplog line reports
  only the LAST segment's counts (typically "0 replayed" or "1 replayed"
  for the tail fold), not the cumulative total across all stops — the ref
  move and undo/redo semantics are correct, only the printed description
  undercounts. Ledger'd as a follow-on rather than fixed in P19.
- **Final-review fixes: `switch`/`undo` were missing the rebase guard,
  `--continue` could force-write over a moved branch, and a conflicted
  mainline pick's completion recomputed the registry against the wrong
  parent.** Three findings from the whole-branch final review, all fixed
  before merge. (1) Critical: `switch_with_identity`
  (`crates/repo/src/repo.rs:1156`) and `undo` (`crates/repo/src/oplog.rs:341`)
  guarded merge- and pick-in-progress but not rebase-in-progress — a
  stopped rebase's branch could be switched away from or undone, and the
  next `--continue` would silently force-write over the discarded work.
  Fixed with the same 3-line `rebase_state::in_progress` guard `commit`/
  `merge`/`cherry_pick`/`rebase`/`rewrap` already have. Regression tests:
  `switch_refused_during_stopped_rebase`, `undo_refused_during_stopped_rebase`
  (`crates/repo/src/repo.rs`). (2) Important: `rebase_continue`
  (`crates/repo/src/replay.rs`) force-wrote `acc_tip` over the branch ref
  at completion without checking it still equalled `RebaseState`'s
  `original_tip` — `sc secret add`/`sc protect` and friends have no
  in-progress guard of their own and can move the tip while the rebase is
  stopped, so completing silently discarded that commit. Fixed by refusing
  up front, before any state mutation, with a typed
  `Error::InvalidArgument` naming both tips when they disagree — state is
  left untouched, so `--abort` still works. Regression test:
  `rebase_continue_refuses_when_branch_moved` (`crates/repo/src/replay.rs`).
  (3) Important: a CONFLICTED `--mainline` pick's completion recomputed the
  secret-registry three-way against the picked commit's first parent
  instead of the mainline-resolved parent — the same bug class the clean
  path already closed (`mainline_pick_registry_bases_off_chosen_parent`),
  still open on the conflict path because `pick_state` did not persist the
  `--mainline` selection. Fixed by persisting it: `pick_state` gained an
  optional `PICK_MAINLINE_BASE` (`crates/repo/src/pick_state.rs`, same
  absent-means-`None` backward-compatible shape as `PICK_DECIDED_ROOT`),
  written alongside the decided root when a mainline pick conflicts
  (`crates/repo/src/replay.rs:544`), and threaded through
  `assemble_completion_snapshot` → `snapshot_files` as a new
  `pick_registry_base` parameter into the same `merged_registry_for_replay`
  call the clean path already fixed. Rebase's own fold completion (which
  also calls `assemble_completion_snapshot`) always passes `None` — rebase
  has no `--mainline` concept, since `rebase` refuses up front if a merge
  commit is anywhere in the replayed range. Regression test:
  `conflicted_mainline_pick_completion_bases_registry_off_chosen_parent`
  (`crates/repo/src/replay.rs`), which forces a mainline-2 pick with both a
  file conflict and a B-side secret and asserts no spurious secret delta
  after resolving and completing via `sc commit`.
