# ADR-0023: Agent workspaces — vfs-backed sessions over the persistent store

- **Status:** Proposed
- **Date:** 2026-07-06

## Context

The in-memory-clones pillar (Phase 1) exists only in the ephemeral demo;
persistent repos (Phase 3+) have no way to fork N parallel workspaces for
agents and collect their results. Real agent processes need real files, and
an in-RAM overlay only lives as long as one process.

## Decision

One-command sessions: `sc work --agents N -- <cmd>` forks N vfs worktrees
from HEAD inside the repo's existing budget-bounded persistent store (the
store on disk is the reconstruction source, so eviction is safe and the
Phase 1 spill backend is unnecessary in this path), materializes each fork
to an ephemeral temp checkout with the P7-aware `materialize`, runs the
agent commands concurrently (optionally with secrets injected via the
`sc run` path), and harvests each changed workspace to a flat `work-<i>`
branch through the commit path — scanner gate and `.scignore` included.
Integration is the existing `sc merge`. The user's branch, HEAD, and
working tree are never touched; teardown leaves zero residue outside
`.sc/`.

Branch names are flat (`work-1`, not `work/1`): the ref-resolution grammar
reserves `name/branch` for remote-tracking refs.

## Alternatives considered

- **Direct checkouts without vfs:** nominal fusion; loses the shared
  budget-bounded cache that makes N forks cheap.
- **Interactive sessions across invocations:** needs a daemon or persisted
  overlay; deferred.
- **Auto-merging clean results into the current branch:** silent mutation
  of the user's branch during teardown violates the no-silent-destruction
  principle; deferred as an explicit follow-on.

## Consequences

- A session holds the single-writer lock for its whole lifetime; concurrent
  `sc` commands are locked out (same model as every other command).
- A failed agent's partial work is still harvested — failure is reported,
  work is never destroyed.
- The ephemeral/persistent mode invariant is amended: a `sc work` session
  is a bounded ephemeral session hosted by a persistent repo; the
  persistent store is the only durable surface.
