# ADR-0030: Agent sessions and auto-merge of clean results

- **Status:** Proposed
- **Date:** 2026-07-07
- **Phase:** 20
- **Builds on:** ADR-0023 (agent workspaces), ADR-0012 (three-way merge), ADR-0024 (oplog)

## Context

ADR-0023 scoped `sc work` to a one-command session: fork, run, harvest,
teardown within a single process. Real agent workflows outlive one
invocation, and integrating N clean `work-<i>` branches by hand is
mechanical toil the tool can absorb.

## Decision

Durable workspace sessions: `sc ws fork` / `sc ws list` / `sc ws run` /
`sc ws harvest` / `sc ws abandon` persist session state under `.sc/`
across invocations. Ephemeral checkouts remain zero-residue on teardown —
the mode-scoped disk invariant holds, with the session bounded by an
explicit `harvest`/`abandon` instead of one process lifetime. On harvest,
results that merge cleanly onto a designated integration branch land
automatically; anything conflicting falls back to a `work-<i>` branch for
manual `sc merge`. No conflict markers ever land unattended. All ref
moves are oplog-recorded and undoable.

## Consequences

- Fork workspaces, return in a later invocation, harvest — clean results
  integrate without manual merges; the demo proves the multi-invocation
  round trip.
- Session state in `.sc/` must be crash-safe and gc-aware (workspace
  snapshots become reachability roots while a session is live).

## Alternatives considered

- **Long-lived daemon process:** keeps worktrees in RAM between commands
  but adds a lifecycle/IPC surface; persisted session state over the
  existing store is simpler and crash-safer.
- **Auto-merge everything with markers:** violates the no-silent-
  destruction principle; conflicted work must be a deliberate human merge.
