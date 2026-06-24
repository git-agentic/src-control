# ADR-0006: Bounded blob budget with LRU eviction and optional spill

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** 1

## Context

Keeping worktrees in RAM (ADR-0005) means a large repo, or many agents, could
exhaust the heap. We need a predictable bound on memory and a defined behaviour
when that bound is reached — without silently losing data.

## Decision

The store enforces a **configurable byte budget over resident blob content**.
Trees, snapshots, and secrets are small and always kept resident (not counted
against the blob budget, not evictable). Only blobs — which are reconstructible
— are evictable, using an **LRU policy**.

Behaviour at the budget:

- **Without spill (default):** an insert that cannot fit, and cannot be made to
  fit by evicting colder blobs, fails loudly with `Error::BudgetExceeded`. The
  store never silently drops data to stay under budget.
- **With spill enabled:** the coldest evictable blobs are written to a
  **content-addressed** spill directory (filename = `ObjectId`, so writes are
  idempotent and verifiable on read-back) and dropped from RAM. A read miss
  rehydrates from spill, which may itself evict other blobs. The spill directory
  lives under a session temp root and is **removed when the `Store` is dropped**.

**Dirty overlay writes are pinned in the worktree and never spilled**, because
they are not yet reconstructible from the store.

## Consequences

- Resident memory is bounded and predictable; the demo runs many agents under a
  4 MiB budget and reports evictions/rehydrations.
- The zero-residue guarantee (ADR-0005) survives spill: even with spill enabled,
  the temp directory is gone after teardown.
- Eviction currently scans resident blobs to find the LRU victim — O(n) per
  eviction. Acceptable and clearly documented for the MVP; can be upgraded to an
  intrusive LRU list / heap if profiling shows it matters.
- `BudgetExceeded` carries `needed`, `available`, and `budget` so callers and
  operators can act on it.

## Alternatives considered

- **Unbounded RAM.** Simplest, but forfeits the core Phase 1 promise on large
  repos.
- **Silent eviction without spill (drop and re-fetch from Git later).** Couples
  the store to Git and risks correctness; rejected in favour of failing loudly or
  spilling deterministically.
- **mmap-backed store.** Pushes memory management to the OS page cache but
  reintroduces disk files and weakens the zero-residue story; not for the MVP.
