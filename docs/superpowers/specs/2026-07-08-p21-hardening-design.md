# P21 — Hardening & consolidation: design

**Date:** 2026-07-08
**Status:** Approved
**ADR:** 0031 (Proposed → Accepted when built)
**Horizon:** `2026-07-08-roadmap-horizon-p21-p24-design.md`

## Problem

P16–P20's reviews left a pooled debt tail, including one live-demonstrated
hazard (unguarded policy ops during in-progress operations, P19 final
review I1). Each item is hours-scale; together they compound. This phase
closes the tail before new capability work begins.

## Decided design — five work areas

### 1. Policy-op in-progress guards (the live hazard)

Every commit-creating policy op — `grant`, `revoke`, `protect`,
`secret add`, `secret rotate` — gains the standard three-guard block
(`MergeInProgress` / `PickInProgress` / `RebaseInProgress`), the same
pattern `rewrap` and the ref-movers use. Escrow ops need no guards
(recipients.toml only; no commit). One refusal test per op per state
(parameterized/looped for compactness). P19's moved-tip refusal in
`rebase_continue` stays as defense-in-depth. The pinned regression test
is P19-I1's own scenario: `secret add` during a stopped rebase is now
refused up front.

### 2. Marks-map staleness: self-healing push (no new subcommand)

The dangerous direction is push/export: a stale mark lets export REUSE a
git commit id that `git gc` pruned in the target, producing a broken
parent chain. Fix at the only point of use: when export would reuse a
known git commit, verify it exists in the target repo (gitio object
read); a missing one is treated as unknown — re-synthesized — with one
stderr line ("marks referenced N pruned git commit(s); re-synthesized").
The fetch direction is already harmless (stale entries are never looked
up). Explicitly rejected: a `sc marks verify` subcommand — self-heal
beats a tool users must know to run.

### 3. Abort/status ergonomics (P19 tail)

- `rebase_abort` and `cherry_pick_abort` return the protected-skip list
  and the CLI prints it (`merge_abort` parity).
- `sc status` distinguishes the resolved-awaiting-continue window
  ("conflict resolved — run `sc rebase --continue`") from unresolved
  conflicts.
- Multi-stop rebase oplog descriptions report CUMULATIVE replayed/skipped
  counts, threaded through `REBASE_STATE` (which already persists across
  stops; gains two counter fields, backward-parse defaulting to 0).
- The ref-write→state-clear crash window in the rebase completion tail
  gets its explanatory comment (duplicate-oplog-record recovery
  semantics).

### 4. Conflict-materialization extraction

The three verbatim copies (merge in `repo.rs`, pick and rebase-fold in
`replay.rs`) collapse into one `pub(crate)` helper. Discipline as
established (P19): behavior-preserving, existing conflict tests stay
green with ZERO test edits, landed as its own commit before anything else
touches those regions.

### 5. ws/demo small items (P20 ledger)

- `sc ws list` names an undone-landing state truthfully (e.g.
  "landed (undone by sc undo)") instead of "abandoned".
- `ws_changed` no longer re-parses the manifest per call; `sc ws list`
  reads it once.
- `demo/run_ws_demo.sh`'s no-marker check becomes a recursive tree walk.
- `ws_harvest` gets a doc comment stating the at-least-once landing
  semantics (kill-9 between landing and teardown re-lands as a duplicate
  empty-delta merge — content-safe).

Deliberately left open, rationale documented in the ADR: the inert
pre-crash `work-<i>` ref sub-window (narrow, harmless, reviewer-accepted)
and `BadRef`'s reuse for state-file parse errors (repo-wide convention).

## Testing & demo

Every closed finding's original repro is pinned as a regression test.
No new demo script: the phase's demoable outcome is all existing demos
green (`run_demo`, `secret-demo`, repo, git-remote, ssh, lifecycle, work,
history, protected-merge, revoke, rewrap, network-git, ws — except the
known pre-P8 `run_protect_demo.sh` failure, which is OUT of P21's scope)
plus the new tests. The ADR records this as the deliberate shape of a
hardening phase.

## Out of scope

The pre-P8 `run_protect_demo.sh` failure (pre-existing, unrelated
subsystem); operation objects in the CAS; named ws sessions; any new
capability surface; `sc branch -d` (the inert-ref window stays
documented instead).
