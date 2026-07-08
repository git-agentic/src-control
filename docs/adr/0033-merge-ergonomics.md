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

## Decision (direction — firmed by the phase brainstorm)

Presentation and resolution tooling only; merge semantics unchanged:

- `sc conflicts` lists conflicted paths for whatever operation is in
  progress and can show the base/ours/theirs versions of a path.
- `sc resolve --ours|--theirs <path…>` resolves listed paths wholesale,
  rewriting the working file and clearing its conflict record.
- `sc status` reports per-path conflict detail (not just counts), and
  the protected-conflict identity requirements are surfaced per path.

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
