# ADR-0003: Snapshot-and-tag model over a Git-style staging model

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** Foundation

## Context

The long-term thesis is a Jujutsu-inspired snapshot-and-tag model rather than
Git's index/staging-area model. The MVP does not need full history operations,
but the object model it commits to now should not paint Phase 2+ into a corner.
The question is what a "commit" is in our model.

## Decision

A **`Snapshot`** is the unit of recorded state: a root tree id plus metadata
(parent snapshot ids, author, timestamp, message). The working copy is itself a
snapshot that gets amended, rather than a staging area that must be explicitly
`add`-ed and then `commit`-ed. There is no index.

In Phase 1, a worktree's `commit` simply materializes its current effective file
set (base ∪ overlay − removals) into a new `Snapshot` whose parent is the base.
Snapshots are cheap and content-addressed, so taking one is just hashing trees
that mostly already exist.

## Consequences

- No staging concept to model, document, or teach — fewer moving parts in the
  MVP and a smaller surface for agents to misuse.
- Snapshots form a DAG via `parents`, leaving room for history, merge, and
  rebase-style operations later without a format change.
- Branch/tag naming is intentionally **out of MVP scope**; refs can be added as
  a thin mutable name→snapshot map on top of the immutable object store.
- Because a snapshot is a pure function of its content, two agents that make the
  same edits produce the **same** snapshot id — useful for reproducibility, and
  observable in the demo.

## Alternatives considered

- **Git index/staging model.** Familiar, but the staging area is a well-known
  source of user confusion and adds state we would have to reimplement for no
  near-term benefit.
- **Pure event/operation log (à la some CRDT VCS designs).** Powerful for
  collaboration but far heavier than the MVP needs; can be layered later if
  warranted.
