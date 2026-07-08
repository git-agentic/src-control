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

## Decision (direction — firmed by the phase brainstorm)

A per-repo sparse specification (prefix set) that scopes `switch`
materialization and `status`/`commit`'s working-tree reads; commits carry
all unmaterialized subtrees from the tip verbatim (the ADR-0025 absent-
carry generalized from "can't read" to "chose not to materialize").
Command shape (`sc switch --sparse <prefix>` vs. a persistent
`sc sparse set` config) and whether per-prefix partial CLONE (objects
never fetched) is in scope are the phase brainstorm's decisions.

## Consequences

- Working in one subtree of a large repo leaves the rest off disk;
  commits don't disturb absent parts (byte-identical carried subtrees).
- The memory-budget story (ADR-0006) composes: sparse materialization
  bounds checkout cost the way the budget bounds resident blobs.
- Interactions to settle in the brainstorm: merge/pick/rebase conflicts
  in absent prefixes, protected paths inside/outside the sparse set,
  `sc ws` sessions of sparse repos.

## Alternatives considered

- **Shallow (history-truncating) clone instead:** orthogonal axis; does
  not help tree width, punts on the carry discipline.
- **Virtual filesystem (FUSE) materialization:** rejected for the same
  reasons as ADR-0005.
