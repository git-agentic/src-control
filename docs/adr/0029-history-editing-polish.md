# ADR-0029: History-editing polish — amend, resumable rebase, pick abort, merge replay

- **Status:** Proposed
- **Date:** 2026-07-07
- **Phase:** 19
- **Builds on:** ADR-0024 (history editing), ADR-0025 (protected merge & replay)

## Context

ADR-0024 deliberately scoped out `sc amend`, stop-and-continue rebase,
`cherry-pick --abort`, and merge-commit replay. With ADR-0026 settling how
protection rules merge, the replay core's semantics are stable enough to
build the remaining ergonomics without rework — and P13/P20 agent
workflows multiply the branches a human must integrate.

## Decision

Four additions riding the existing P14/P15 replay core, no second merge
implementation: `sc amend` (replace the tip commit, oplog-recorded),
`sc rebase --continue` (persist rebase progress so a conflict stops
instead of aborting, resumable after resolution), `sc cherry-pick --abort`
(discard pick state and restore the pre-pick working tree), and
merge-commit replay with explicit mainline selection (lifting ADR-0024's
refuse-on-merge-commit rule). Every ref-mover records an oplog entry and
is undoable; the ref update remains the atomic commit point.

## Consequences

- An interrupted rebase becomes resumable rather than all-or-nothing;
  the extended history demo proves interrupt → resolve → `--continue`.
- Rebase gains persisted in-progress state (like `PICK_HEAD`), which gc
  and status must respect.

## Alternatives considered

- **Keep atomic-only rebase:** simplest, but long replays over
  conflict-prone history become unusable.
- **Build before P16:** risks reworking replay's rule handling once
  tombstone semantics land.
