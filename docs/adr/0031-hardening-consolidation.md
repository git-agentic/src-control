# ADR-0031: Hardening & consolidation sweep — closing the P16–P20 review tail

- **Status:** Proposed
- **Date:** 2026-07-08
- **Phase:** 21
- **Builds on:** ADR-0017 (P17 rewrap guards), ADR-0018/0028 (marks map), ADR-0029 (rebase state), ADR-0030 (ws sessions)

## Context

Every P16–P20 final review deferred a set of Minors and named follow-ons,
now pooled in ROADMAP's Deferred list. One is a live-demonstrated hazard:
policy ops (`grant`/`revoke`/`secret add`/`secret rotate`/`protect`) are
not guarded against in-progress merge/pick/rebase state — P19's final
review showed an unguarded `secret add` mid-stopped-rebase whose commit
the completion machinery then discarded (the moved-tip refusal added
there is a backstop, not the fix). The rest is compounding friction:
marks that can point at pruned git objects with no recovery story,
aborts that silently drop the protected-skip list `merge_abort` reports,
stale status text, misleading oplog counts, and a conflict-
materialization block copied verbatim three times.

## Decision

One consolidation phase, no new capability axis:

- Policy ops join the `MergeInProgress`/`PickInProgress`/
  `RebaseInProgress` guard family (same three-line pattern as rewrap and
  the ref-movers), each with a refusal test.
- Marks staleness gets a typed error naming the recovery (`sc fetch`
  rebuilds the mirror and re-syncs marks) instead of surfacing raw
  object-missing failures.
- Rebase/pick aborts return and print the protected-skip list
  (merge_abort parity); status text distinguishes the resolved-awaiting-
  continue window; multi-stop rebase oplog descriptions report cumulative
  counts; `sc ws list` names an undone-landing state truthfully; the ws
  demo's no-marker check walks the tree.
- The conflict-materialization triplication (merge / pick / rebase fold)
  is extracted into one helper under the P19 extraction discipline:
  existing tests stay green with zero test edits.

Every closed review finding's original repro becomes a pinned regression
test.

## Consequences

- Shipped pillars stop carrying known hazards into the P22+ work; the
  guard family is finally uniform across every state-writing operation.
- Pure-hardening phase: the demo story is all existing demos green plus
  the new pinned tests — no new demo script.

## Alternatives considered

- **Sprinkle the debt across the next capability phases:** each item is
  small, but they touch four different subsystems — bundling keeps the
  review focus on hazards rather than splitting attention inside feature
  reviews.
- **Guards-only minimal phase:** leaves the marks recovery and
  triplication to rot; the sweep is only days-scale in total.
