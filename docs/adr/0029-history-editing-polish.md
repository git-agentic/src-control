# ADR-0029: History-editing polish — amend, resumable rebase, pick abort, merge replay

- **Status:** Proposed
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
