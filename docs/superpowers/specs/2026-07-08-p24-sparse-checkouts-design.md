# P24 — Sparse checkouts: design

**Date:** 2026-07-08
**Status:** Approved
**ADR:** 0034 (Proposed → Accepted when built)
**Horizon:** `2026-07-08-roadmap-horizon-p21-p24-design.md`

## Problem

The working tree is all-or-nothing: `switch` materializes the whole
snapshot and `commit` reads the whole tree. Monorepo-width use wants to
materialize one subtree and leave the rest on the CAS. P15 already built
the key discipline — commits carry forward absent entries the checkout
skipped — so sparseness generalizes that carry from "can't read" to
"chose not to materialize."

## Decided design

**Sparse CHECKOUT only** (user-decided): all objects remain in the CAS;
only a subset materializes to disk. Partial *clone* (objects outside the
prefix never fetched/stored — promisor store, prefix-scoped packs) is
explicitly deferred; it is a much larger transport+store feature.

### The sparse spec

A persisted prefix set at `.sc/sparse` (user-decided: persistent config,
not a per-switch flag). Local and uncommitted — each clone chooses its
own view — atomic-write, one prefix per line, mirroring the other `.sc/`
state files. **Empty or absent = full materialization** (today's default,
unchanged). Prefix matching reuses P7's `matching_prefix` path-boundary
logic (a prefix governs a path iff the path equals it or lies under it at
a `/` boundary — never a textual-prefix sibling).

Commands:
- `sc sparse set <prefix…>` — write the spec and re-materialize the
  working tree to match (materialize matching paths, remove now-excluded
  ones from disk).
- `sc sparse show` — print the active spec (`--json`); nothing when full.
- `sc sparse disable` — clear the spec and re-materialize fully.

### The one correctness mechanism

`commit` already carries forward absent files it cannot prove were
deleted (`repo.rs`, the P15 discipline: "cannot distinguish absent
because deleted from absent because a non-recipient couldn't
materialize"). P24 **generalizes the carry predicate** from

> carry-if-absent AND (protected AND caller-not-a-recipient)

to

> carry-if-absent AND (that OR the path is outside the sparse set)

So a file absent from disk **outside** the sparse prefixes is carried
from the tip verbatim (byte-identical subtree — the demoable guarantee);
a file absent from disk **inside** the sparse set is a genuine deletion.
`tracked_paths` / `read_worktree` / `diff_worktree` scope their
working-tree view to the sparse set the same way. This single predicate,
threaded through the read side, IS the feature — no new object model, no
snapshot format change.

### Materialization & budget

`switch` and `sparse set` materialize only entries matching a sparse
prefix; the rest never touch disk. Composes with the memory budget
(ADR-0006): sparse materialization bounds checkout cost the way the
budget bounds resident blobs. `sc status` shows the active sparse spec so
an absent subtree is never misread as a mass deletion.

### Interactions (settled)

- **Merge / pick / rebase, path OUTSIDE the sparse set.** The
  conflict/decided-tree machinery already operates on tree ids without
  materializing (P15's ciphertext-id fast paths are the precedent), so a
  CLEAN resolution lands in the CAS and carries forward without touching
  disk. A CONFLICT on an out-of-sparse path cannot be edited on disk, so
  the op reports it and refuses to auto-materialize outside the spec,
  with a clear "widen your sparse set to resolve `<path>`" message.
  `sc conflicts` (P23) still inspects it via DAG-derived versions without
  materializing; `sc resolve` writes only if the path is in the sparse
  set, else errors with the same widen hint.
- **Protected paths.** Orthogonal: a path can be protected AND outside
  the sparse set; the carry composes (carry if absent for EITHER reason).
  Inside-sparse protected paths materialize per P7 unchanged.
- **`sc ws` sessions.** Workspaces inherit the host repo's sparse spec
  (fork copies `.sc/sparse` into each `.sc/ws/<i>/` checkout);
  materialization and harvest carry out-of-sparse subtrees exactly as
  switch/commit do.

## Testing & demo

- Unit: the generalized carry predicate — absent-outside-sparse carried,
  absent-inside-sparse deleted, absent-protected still carried, a path
  both protected AND outside-sparse carried; prefix matching at path
  boundaries (via `matching_prefix`).
- Integration:
  - `sc sparse set <prefix>` → `sc switch` materializes only the subset →
    edit + commit → the out-of-sparse subtrees are byte-identical in the
    new snapshot (same tree ids); `sc sparse disable` re-materializes
    fully.
  - a merge with a clean out-of-sparse change lands; an out-of-sparse
    conflict refuses with the widen hint; `sc resolve` on an out-of-sparse
    path errors with the widen hint.
  - a sparse `sc ws` session round-trips (fork inherits the spec, harvest
    carries the absent rest).
  - `sc status` reports the sparse spec; absent subtrees are not listed as
    deletions.
- `demo/run_sparse_demo.sh`: a multi-subtree repo — `sc sparse set` one
  subtree, prove the rest is absent from disk (`find`), commit, prove the
  absent subtrees survive byte-identical (tree id or `sc log`/checkout of
  a full clone), then `sc sparse disable` brings them back. Zero residue.

## Out of scope

Partial clone (promisor store / prefix-scoped fetch); auto-widening the
sparse set to resolve a conflict (explicit `sc sparse set` instead);
committing the sparse spec (it stays local per-clone); glob/negation
patterns in the spec (prefixes only, matching `.scignore`'s subset
philosophy); sparse-aware gc (all objects stay reachable — gc is
unchanged).

**Boundary (found during the build, not designed in): a transient
out-of-sparse write during a mixed conflict.** `materialize_conflict_state`
gates its own conflict *markers* against the sparse spec up front — an
out-of-sparse conflicted path refuses with a widen hint before anything is
written. That gate covers only the marker-write loop; the same function's
`to_encrypt`/sidecar-decrypt write loops (protected-content re-encryption
inputs and `.theirs` sidecars for an *in-sparse* conflict) are not
sparse-scoped. So when an IN-sparse conflict co-occurs with an OUT-of-
sparse protected/I2 clean change in the same merge, that out-of-sparse
plaintext is written to disk outside the sparse view for the duration of
the conflict window. Not data loss (completion's `read_worktree` re-lands
it in the CAS same as any other carried file; abort removes it) and not a
new disclosure (the diff3 content-merge that produced the plaintext
already required an authorized identity; the I2 case is pre-existing
plaintext) — a bounded disk-hygiene boundary, out of scope for this phase.
Follow-on: extend the sparse gate to the `to_encrypt`/sidecar write loops.
See ADR-0034's Consequences section and CLAUDE.md's Phase 24 paragraph.
