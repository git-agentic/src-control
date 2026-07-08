# Roadmap horizon P21–P24 — design

**Date:** 2026-07-08
**Status:** Approved (roadmap-level; each phase gets its own focused
brainstorm → spec → plan when it becomes active)

## Goal of this horizon

Consolidate, then complete the trust story, then invest in daily feel and
scale. P16–P20 shipped five capability phases whose final reviews caught
live-proven hazards; the fixes landed per-phase, but a tail of adjacent
debt accumulated in ROADMAP's Deferred list — including one item (policy
ops unguarded during in-progress operations) that P19's final review
demonstrated live. This horizon leads with a hardening sweep for the same
reason P16 led the last one: shipped claims should not carry known
hazards into new work.

## Phases

### P21 — Hardening & consolidation (ADR-0031)

One sweep, no new capability axis:

- **Policy-op in-progress guards.** `grant`, `revoke`, `secret add`,
  `secret rotate` (and `protect`) gain the
  `MergeInProgress`/`PickInProgress`/`RebaseInProgress` guard family.
  P19's final review demonstrated the hazard live: an unguarded `secret
  add` during a stopped rebase moved the tip and (pre-backstop) had its
  commit silently discarded by `--continue`. The moved-tip refusal is a
  backstop; guarding the ops is the durable fix.
- **Marks-map staleness recovery** (P18 follow-on): a clear, typed error
  when marks reference pruned git objects, and a documented/automated
  re-fetch rebuild path.
- **P19/P20 ergonomics minors:** rebase/pick aborts surface the
  protected-skip list (merge_abort parity); stale "resolve conflicts"
  status text in the resolved-but-not-continued window; multi-stop
  rebase's oplog description counts; ws-list-after-undo vocabulary;
  ws demo no-marker scan tightened to a tree walk.
- **Conflict-materialization extraction:** the three verbatim copies
  (merge / pick / rebase-fold) collapse into one helper, pinned by the
  existing conflict tests staying green with zero test edits (the P19
  extraction discipline).

Demoable outcome: honest regression proof — all existing demos green,
plus a targeted test per closed item (each review finding's repro becomes
a pinned test).

### P22 — Signed commits & provenance (ADR-0032)

The governance pillar. Commits optionally signed with the identity
infrastructure P2/P7 built; signature covers the canonical snapshot
encoding; the carrier must not change content-addressed ids (sidecar
registry vs. detached signature store is the phase brainstorm's central
question). `sc log` shows verification status; `sc verify` walks history;
trust policy (which keys are trusted) rides `recipients.toml` like escrow
does. Signing crypto stays quarantined in `crates/crypto` (likely adds
Ed25519 — the one justified new dependency).

Demoable outcome: sign commits, tamper with history in a clone, `sc
verify` catches it; unsigned/untrusted commits are visibly flagged.

### P23 — Merge ergonomics (ADR-0033)

Conflict UX beyond P4's markers, semantics unchanged: `sc conflicts`
(list + inspect base/ours/theirs for each conflicted path), `sc resolve
--ours|--theirs <path>` bulk resolution, marker-aware `sc status` detail.

Demoable outcome: a conflicted merge resolved end-to-end without hand-
editing markers.

### P24 — Sparse checkouts / sub-tree sharing (ADR-0034)

The monorepo axis: materialize only a subset of the tree
(`sc switch --sparse <prefix>` shape TBD in its brainstorm), commits stay
correct by carrying unmaterialized subtrees from the tip (generalizing
P15's absent-protected-files carry discipline). Per-prefix partial clone
is the stretch-scope decision for its brainstorm.

Demoable outcome: work in one subtree of a large repo with the rest
absent from disk; commits don't disturb the absent parts.

## Ordering rationale

- **P21 first** — the debt items are each hours-scale but compounding,
  and one is a live-demonstrated hazard.
- **P22 before P23/P24** — provenance is the last unbuilt piece of the
  security thesis and touches the object model's surroundings; settle it
  before more surface accretes.
- **P23 before P24** — conflict UX pays off daily; sparse checkout opens
  a new axis whose users will also want that UX.

## Explicitly still deferred beyond this horizon

HTTP transport (sc-native), streaming (>4 GiB) frames, operation objects
in the CAS + oplog entries for remote-tracking refs, named/multiple ws
sessions, network-Git same-remote edge cases, richer trust models beyond
key lists (delegation, expiry).
