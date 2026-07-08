# P23 — Merge ergonomics: design

**Date:** 2026-07-08
**Status:** Approved
**ADR:** 0033 (Proposed → Accepted when built)
**Horizon:** `2026-07-08-roadmap-horizon-p21-p24-design.md`

## Problem

P4 chose conflict detection/representation (markers + sidecars) and
deferred resolution UX. Every operation since has widened the surfaces
that produce conflicts (merge, cherry-pick, stopped rebase, ws fallback)
while resolution stayed "hand-edit the markers." This phase adds
inspection and bulk resolution — **merge semantics unchanged**.

## Decided design

A presentation + resolution layer over P4's existing conflict
representation (per-op `<STATE>_CONFLICTS` path list + working-tree
markers / `.theirs` sidecars). Nothing about conflict detection or
completion changes.

### One conflict-source abstraction

`conflict_versions(path) -> { base, ours, theirs }` re-derives the three
versions from the DAG (authoritative — NOT parsed from lossy markers),
dispatching on the active in-progress operation:

| Op | ours | theirs | base |
|----|------|--------|------|
| merge | branch tip | `MERGE_HEAD` | merge-base(ours, theirs) |
| cherry-pick | branch tip | `PICK_HEAD` | picked commit's first parent |
| rebase-stop | `REBASE_STATE.acc_tip` | the conflicted commit | conflicted commit's first parent |

The active op is selected the same way `sc status` already reports it
(merge/pick/rebase in-progress checks, in that precedence). Each version
is the path's blob pulled from that snapshot's tree; a path absent on a
side yields a "(absent)" version, not an error. Protected-path versions
decrypt through P15's `decrypt_with` when `--identity` is supplied;
without it on a protected path, `ProtectedMergeNeedsIdentity`.

### `sc conflicts [<path>] [--identity <key>]`

- No path: list every conflicted path (the active op's `read_conflicts`)
  with a kind tag — text / binary / protected — classified from the
  tree entry (PROTECTED perms → protected; non-UTF8 or sidecar present →
  binary; else text). `--json` for scripts.
- With a path: print base / ours / theirs (plaintext for protected under
  `--identity`), a three-way view; `(absent)` where a side lacks the path.

### `sc resolve --ours|--theirs <path…> [--identity <key>]`

For each listed path (all must be currently conflicted, else a clear
per-path error; refuses when no op is in progress):

1. Write the chosen side's content to the working file — clean, no
   markers.
2. Remove any `.theirs` / `.base` sidecar for that path.
3. Drop the path from the active op's `<STATE>_CONFLICTS` record
   (atomic rewrite; the record stays accurate for `status`/`conflicts`).

Text/binary need no key. A protected path needs `--identity` to DECRYPT
the chosen side into working-tree plaintext — resolve does NOT
re-encrypt; re-encryption happens at completion through the existing
commit path (P15 discipline: plaintext never enters the CAS at resolve
time either). Completion is unchanged: `sc commit` (merge/pick) or
`sc rebase --continue` (rebase-stop).

### Marker-aware `sc status`

The in-progress sections (P19/P21) gain per-path detail: each conflicted
path with its kind, and for protected paths the "needs --identity to
resolve" note — replacing today's bare count. `--json` mirrors it.

## Testing & demo

- Unit: `conflict_versions` per op (merge/pick/rebase — correct
  ours/theirs/base ids); kind classification (text/binary/protected);
  absent-on-one-side yields `(absent)`; protected-needs-identity gate.
- Integration:
  - `sc resolve --ours` and `--theirs` clear the record and write clean
    content, across merge, cherry-pick, AND stopped rebase.
  - A merge fully resolved via `sc resolve` completes with `sc commit`
    (no markers remain; the commit path is untouched).
  - A protected conflict resolved with `--identity`; re-encryption at
    completion verified (ciphertext in CAS, plaintext never).
  - `sc resolve` on a non-conflicted path errors; with no op in progress
    errors.
  - `sc status`/`sc conflicts` per-path detail matches the record.
- `demo/run_merge_ergonomics_demo.sh`: a conflicted merge — `sc conflicts`
  lists + inspects, `sc resolve --theirs`/`--ours` path-by-path, `sc
  commit` completes — zero hand-editing of markers; then the same for a
  protected conflict with `--identity`.

## Out of scope

Interactive/TUI resolvers; a merge-tool launch hook; partial/hunk-level
resolution (`resolve` is whole-file per side); changing conflict
representation or completion semantics; `--union`/`--base` resolution
modes (only `--ours`/`--theirs` in MVP).
