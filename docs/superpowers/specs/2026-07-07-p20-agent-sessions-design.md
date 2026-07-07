# P20 — Agent sessions + auto-merge: design

**Date:** 2026-07-07
**Status:** Approved
**ADR:** 0030 (Proposed → Accepted when built)
**Horizon:** `2026-07-07-roadmap-horizon-p16-p20-design.md`

## Problem

P13's `sc work` is deliberately one-command: fork, run, harvest, teardown
inside a single process. Real agent workflows outlive one invocation, and
integrating N clean `work-<i>` branches by hand is mechanical toil.
ADR-0023 scoped both out; this phase closes them.

## Decided design

### Session model

**One unnamed session per repo** — `sc ws fork` refuses if a session
exists (the same one-at-a-time discipline as merge/pick/rebase state).

`sc ws fork --agents N [--identity <key>]` materializes N checkouts from
the current tip into `.sc/ws/<i>/` (P7-aware decryption, as P13) and
atomically writes `.sc/ws/session.toml`: base snapshot id, base branch
name, workspace dirs + status, author. The checkout dirs ARE the durable
workspace state: agents work in them directly across any number of `sc`
invocations. No key material is ever stored in the manifest.

Disk invariant: `.sc/` is durable by design (persistent mode); when the
session ends (every workspace harvested or abandoned), `.sc/ws/` is
deleted — zero residue after session end. `sc work` (P13) is unchanged;
`sc ws` is its multi-invocation sibling sharing `harvest_workspace` and
the run/secrets plumbing.

### Commands

- `sc ws fork --agents N [--identity <key>]` — start a session.
- `sc ws list` — each workspace's dir and changed/unchanged status vs the
  session base (and the base branch/snapshot).
- `sc ws run <i> [--with-secrets --identity <key>] -- <cmd>` — run a
  command in workspace i with `SC_WORKSPACE`/`SC_WORKSPACE_DIR` set and
  optional decrypted-secret injection (P13 parity via the `sc run` path).
- `sc ws harvest [--into <branch>] [--identity <key>]` — see below.
- `sc ws abandon [<i>]` — drop one workspace (or all); deletes its dir;
  clears the session when none remain. No oplog record (no ref moved).

### Harvest + auto-merge (user-decided: land on the session's base branch)

`sc ws harvest`, workspaces in ascending index order:

1. Unchanged workspace → skipped, dir torn down.
2. Changed workspace → P13's existing `harvest_workspace` pipeline
   (`.scignore`, P5 scanner gate, protected re-encryption) produces a
   candidate snapshot (child of the session base). **[As shipped: a
   scanner-Rejected workspace stays LIVE (no candidate branch was ever
   created) so the offending file can be fixed in place and re-harvested
   — unlike P13's one-shot `sc work`, where rejection is terminal for
   the session. A durable, multi-invocation session can do better. See
   ADR-0030.]**
3. The candidate merges onto the **landing branch** — default the
   session's base branch, `--into <branch>` overrides — via the standard
   merge machinery:
   - **Clean (including fast-forward): lands immediately.** One oplog
     record per landing (undoable individually). Merges are cumulative:
     workspace k's merge sees workspaces 1..k-1's landings.
   - **Conflicted — including protected divergences lacking
     `--identity`: falls back to a `work-<i>` branch** exactly as P13
     does. The landing branch is untouched by that workspace, and no
     conflict markers are written anywhere unattended; the user resolves
     later with a manual `sc merge work-<i>`.
4. Harvested and fallback workspaces tear down their dirs; the session
   ends (manifest + `.sc/ws/` removed) when none remain. A partial
   harvest (some workspaces still live) leaves the session open.

Interactions:
- Harvesting onto the currently-checked-out branch goes through the
  normal merge path, so the existing dirty-working-tree refusal applies
  (resolve by committing/stashing the user tree first). Documented.
  **[As shipped: the landing branch (default the session's base branch,
  `--into` overrides) must BE the currently-checked-out branch; `sc ws
  harvest` refuses with an `InvalidArgument` naming the landing branch
  and a `sc switch` hint otherwise, because the merge machinery it
  reuses whole (`merge_with_identity`) is head-centric — see ADR-0030.]**
- Harvest is a ref-mover: it refuses while merge/pick/rebase state is in
  progress (the P19 guard family). Fork/list/run/abandon are not
  ref-movers and need no guards beyond the repo lock.
- Branch names stay flat (`work-<i>`) per ADR-0023's ref-grammar
  constraint; if `work-<i>` already exists, harvest picks the next free
  suffix (`work-<i>-2`, …) rather than clobbering.

### Crash-safety & gc

- The manifest is atomic-write. A crash mid-session leaves dirs +
  manifest intact: the next invocation sees the same session.
- gc roots the session's **base snapshot** (SNAPSHOT root, gated on the
  manifest's presence — the P15/P19 state-gating discipline). Checkout
  contents are plain files with no CAS exposure until harvest, so a
  pre-harvest crash loses nothing that was ever in the CAS.
- Candidate snapshots created during a harvest become reachable via the
  landed merge or the `work-<i>` branch in the same operation — no window
  where gc could prune them (harvest holds the repo lock throughout).

## Testing & demo

- Session round trip across process boundaries: fork → drop the Repo →
  reopen → list/run → harvest.
- Cumulative clean landings in ascending order (ws-2's merge sees ws-1's
  landing).
- Conflict fallback: landing branch untouched by the conflicted
  workspace; markers appear only when the user later runs
  `sc merge work-<i>`.
- `--into` override; unchanged-workspace skip; abandon (one and all)
  teardown; `work-<i>` collision suffixing.
- Crash residue: manifest + dirs with a fresh process → list/harvest
  work; gc mid-session keeps the base snapshot alive.
- Guards: harvest refused during merge/pick/rebase; fork refused when a
  session exists.
- Zero residue: `.sc/ws/` gone after the session ends (both harvest-all
  and abandon-all paths).
- `demo/run_ws_demo.sh` (self-checking, house style): fork in one `sc`
  invocation, edit workspaces in another, harvest in a third — two clean
  auto-merges land cumulatively + one conflict falls back to `work-<i>`;
  `sc undo` reverts the last landing; session end leaves `.sc/ws/` gone.

## Out of scope

Named/multiple concurrent sessions; workspace re-fork/refresh from a
newer tip; daemonized long-lived processes (the dirs make them
unnecessary); auto-merge across sessions; cross-repo sessions;
interactive conflict resolution inside harvest (fallback branches cover
it).
