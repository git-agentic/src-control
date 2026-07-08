# ADR-0033: Merge ergonomics — conflict UX beyond markers

- **Status:** Proposed
- **Date:** 2026-07-08
- **Phase:** 23
- **Builds on:** ADR-0012 (three-way merge), ADR-0025 (protected conflicts), ADR-0029 (in-progress states)

## Context

P4 chose detection/representation (markers + sidecars) and deferred
resolution UX. Every phase since has widened the surfaces that produce
conflicts (merge, pick, stopped rebase, ws fallback branches) while the
resolution story remained "edit the markers by hand."

## Decision

Presentation and resolution tooling only; merge semantics unchanged.
Spec: `docs/superpowers/specs/2026-07-08-p23-merge-ergonomics-design.md`.

One `conflict_versions(path) -> {base, ours, theirs}` abstraction
re-derives the three versions from the DAG (authoritative, not parsed
from lossy markers), dispatching on the active op: merge (ours=tip,
theirs=`MERGE_HEAD`, base=merge-base), cherry-pick (theirs=`PICK_HEAD`,
base=picked parent), rebase-stop (ours=`REBASE_STATE.acc_tip`,
theirs=the conflicted commit, base=its parent).

- `sc conflicts [<path>] [--identity]` — no path lists conflicted paths
  with a kind tag (text/binary/protected); with a path shows base/ours/
  theirs (plaintext for protected under `--identity`).
- `sc resolve --ours|--theirs <path…> [--identity]` — writes the chosen
  side's clean content to the working file, drops sidecars, drops the
  path from the active `<STATE>_CONFLICTS` record. Text/binary need no
  key; protected paths need `--identity` to DECRYPT the chosen side
  (resolve never re-encrypts — completion's commit path does, so
  plaintext never enters the CAS at resolve time). Completion is the
  unchanged `sc commit` / `sc rebase --continue`.
- `sc status` gains per-path conflict detail with the protected
  identity-required note, replacing the bare count.

Uniform coverage of all conflict kinds including protected paths was the
brainstorm's decided scope (identity gate reuses P15's
`ProtectedMergeNeedsIdentity`). Whole-file-per-side only — no hunk-level
or `--union`/`--base` modes in the MVP.

## Consequences

- A conflicted merge/pick/stopped rebase becomes resolvable end-to-end
  without hand-editing markers; the demo proves it.
- Works uniformly across merge, pick, and rebase-stop conflicts because
  all three share the P4 conflict representation (and, after P21's
  extraction, one materialization helper).

## Alternatives considered

- **Interactive/TUI resolver:** far larger surface; deferred.
- **Changing conflict representation:** P4's markers+sidecars are shared
  by every downstream feature; UX layers on top instead.
