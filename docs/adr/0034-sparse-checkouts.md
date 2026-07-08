# ADR-0034: Sparse checkouts / sub-tree sharing

- **Status:** Proposed
- **Date:** 2026-07-08
- **Phase:** 24
- **Builds on:** ADR-0011 (working tree), ADR-0025 (absent-entry carry discipline), ADR-0003 (snapshot model)

## Context

The working tree is all-or-nothing: `switch` materializes the whole
snapshot, and `commit` reads the whole tree. Monorepo-scale use wants to
materialize one subtree and leave the rest on the CAS — and P15 already
built the key discipline (commits carrying forward absent entries the
checkout skipped, for protected files a keyless user can't read).
Sparseness generalizes that carry to user-chosen prefixes.

## Decision

Sparse CHECKOUT only (user-decided): all objects stay in the CAS, only a
subset materializes to disk. Partial clone (objects outside the prefix
never fetched — promisor store, prefix-scoped packs) is deferred.
Spec: `docs/superpowers/specs/2026-07-08-p24-sparse-checkouts-design.md`.

A persistent sparse spec (user-decided over a per-switch flag) at
`.sc/sparse` — local, uncommitted, a prefix set matching P7's
`matching_prefix` boundary rule; empty/absent = full materialization.
`sc sparse set <prefix…>` / `sc sparse show` / `sc sparse disable`.

The whole feature is ONE generalized predicate: `commit` already carries
forward absent files it cannot prove were deleted (the ADR-0025 P15
discipline). P24 widens the carry from "absent AND protected-and-not-a-
recipient" to "absent AND (that OR outside the sparse set)." So an
out-of-sparse absent file is carried from the tip verbatim (byte-
identical subtree); an in-sparse absent file is a genuine deletion.
`tracked_paths`/`read_worktree`/`diff_worktree` scope to the spec the
same way. No new object model, no snapshot format change.

Interactions settled: a clean merge/pick/rebase change to an out-of-
sparse path lands in the CAS without materializing (P15 tree-id
precedent); a CONFLICT there is reported with a "widen your sparse set to
resolve `<path>`" message rather than auto-materializing (and `sc resolve`
errors the same way, while `sc conflicts` still inspects via DAG-derived
versions). Protected and sparse are orthogonal — the carry composes.
`sc ws` workspaces inherit the host's `.sc/sparse`.

## Consequences

- Working in one subtree of a large repo leaves the rest off disk;
  commits don't disturb absent parts (byte-identical carried subtrees).
- The memory-budget story (ADR-0006) composes: sparse materialization
  bounds checkout cost the way the budget bounds resident blobs.
- gc is unchanged: all objects stay reachable (sparse is a disk view, not
  an object-set change).

## Alternatives considered

- **Shallow (history-truncating) clone instead:** orthogonal axis; does
  not help tree width, punts on the carry discipline.
- **Virtual filesystem (FUSE) materialization:** rejected for the same
  reasons as ADR-0005.
