# ADR-0030: Agent sessions and auto-merge of clean results

- **Status:** Proposed
- **Date:** 2026-07-07
- **Phase:** 20
- **Builds on:** ADR-0023 (agent workspaces), ADR-0012 (three-way merge), ADR-0024 (oplog)
- **Spec:** `docs/superpowers/specs/2026-07-07-p20-agent-sessions-design.md`

## Context

ADR-0023 scoped `sc work` to a one-command session: fork, run, harvest,
teardown within a single process. Real agent workflows outlive one
invocation, and integrating N clean `work-<i>` branches by hand is
mechanical toil the tool can absorb.

## Decision

Durable sessions whose workspace state IS the checkout directory. One
unnamed session per repo: `sc ws fork --agents N` materializes N
checkouts from the current tip into `.sc/ws/<i>/` (P7-aware) and writes
an atomic manifest (`.sc/ws/session.toml`: base snapshot, base branch,
dirs; never key material). Agents work in the dirs directly across
invocations; `sc ws list`/`run` mirror P13's env + secret-injection
surface. `sc ws abandon` drops workspaces without an oplog record
(nothing moved).

`sc ws harvest [--into <branch>] [--identity <key>]` processes
workspaces in ascending order through P13's existing `harvest_workspace`
pipeline (scanner, `.scignore`, protected re-encryption), then
auto-merges each candidate onto the landing branch — default the
session's **base branch** (user-decided), `--into` overrides. Clean
merges (including ff) land immediately, one oplog record per landing,
cumulatively (each merge sees the previous). Anything conflicted —
including protected divergences lacking `--identity` — falls back to a
flat `work-<i>` branch (collision-suffixed), landing branch untouched,
no conflict markers written unattended. Harvest is a ref-mover and joins
the P19 guard family. The session ends (dirs + manifest removed, zero
residue) when no workspaces remain.

Crash-safety: manifest atomic-write; a crash mid-session preserves the
session. gc roots the base snapshot gated on manifest presence (the
P15/P19 state-gating discipline); candidates become branch/merge-
reachable within the lock-held harvest, leaving no prunable window.

The mode-scoped disk invariant holds: `.sc/` is durable by design, and
session teardown removes `.sc/ws/` entirely — the ephemeral-checkout
guarantee is bounded by explicit harvest/abandon instead of one process
lifetime. `sc work` (P13) is unchanged.

## Consequences

- Fork workspaces, return in later invocations, harvest — clean results
  land on the base branch without manual merges; the demo proves the
  multi-invocation round trip, cumulative landings, a conflict fallback,
  and an undo of a landing.
- New persisted session state that gc and the guard family respect —
  the fourth in-progress-adjacent state, but NOT one that blocks other
  operations (only harvest itself is guarded as a ref-mover; fork/run/
  abandon coexist with normal work).
- Harvesting onto the currently-checked-out branch inherits the merge
  path's dirty-tree refusal — commit the user tree first.

## Alternatives considered

- **Long-lived daemon holding in-RAM worktrees:** lifecycle/IPC surface
  for no gain — durable checkout dirs give persistence for free and
  survive crashes; rejected (was the draft's stance too).
- **Snapshot-persistent sessions (re-materialize per invocation, `sc ws
  save`):** CAS churn, and agents holding open files across invocations
  break; rejected.
- **Auto-merge with markers on conflict:** violates the no-silent-
  destruction principle; conflicted work must be a deliberate human
  merge (fallback branches). Rejected in the draft; upheld.
- **Dedicated integration branch / mandatory `--into`:** safer-feeling
  but adds a manual merge to every session while landings are already
  individually undoable; user chose base-branch landing.
