# ADR-0024: History editing via replay + operation log

- **Status:** Proposed
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
