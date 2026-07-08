# ADR-0030: Agent sessions and auto-merge of clean results

- **Status:** Accepted
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

## Refinements discovered during the build

- **[As-shipped precision note] The landing branch must be the
  currently-checked-out branch.** `sc ws harvest [--into <branch>]`
  resolves `landing = into.unwrap_or(&session.base_branch)`, then
  compares it against `refs::current_branch` and refuses with
  `InvalidArgument` naming both the landing branch and a `sc switch`
  hint if they differ (`crates/repo/src/ws.rs:407-413`, regression test
  `harvest_requires_landing_branch_checked_out`,
  `crates/repo/src/ws.rs:1019-1042`). This is not an incidental
  restriction: `ws_harvest` lands each candidate via
  `merge_with_identity` (`crates/repo/src/repo.rs:804`) unchanged — the
  merge machinery is head-centric (it reads/writes the *current* branch's
  tip and materializes into the *current* working tree) — and reusing
  that path whole, rather than re-deriving a headless variant, is the
  point of composing on top of existing merge instead of writing a
  second one. `--into` therefore only ever narrows which branch must
  already be checked out; it does not let harvest land on a branch that
  isn't.
- **[As-shipped precision note] A scanner-Rejected workspace stays
  live, not terminal.** When the P5 scanner rejects a candidate's
  plaintext (`HarvestResult::Rejected`), `ws_harvest` records the
  outcome and leaves the workspace's manifest entry `live = true` — no
  candidate branch was ever created (`harvest_workspace` never calls
  `write_branch_tip` on the `SecretDetected` path), so there is nothing
  to tear down and nothing to resolve
  (`crates/repo/src/ws.rs:488-498`). The agent can fix the offending
  file in place in the same checkout dir and re-run `sc ws harvest`,
  which re-diffs and proceeds normally (regression test
  `harvest_partial_leaves_session_open`,
  `crates/repo/src/ws.rs:1131-1175`, which drives exactly that
  fix-and-re-harvest cycle to a clean `Unchanged` resolution). This
  revises P13's `sc work`, where scanner rejection was terminal for the
  one-shot session (fork/run/harvest/teardown all inside one process, no
  later invocation to retry in) — a durable, multi-invocation session
  can do better, so P20 does.
- **Err(UpToDate) on a crash-recovery re-harvest resolves as an
  idempotent no-op Landed.** If a process is killed between
  `merge_with_identity` moving the landing ref and `resolve_and_teardown`
  persisting the workspace as resolved, a later `sc ws harvest` re-runs
  `harvest_workspace` against the same session base, dir, branch name,
  author, and message — at the same wall-clock second this mints an
  *identical* candidate snapshot id, already reachable from the landing
  branch. `merge_with_identity` reports this as `Err(UpToDate)` rather
  than `Ok`; `ws_harvest` treats that arm as a successful no-op
  resolution (deletes the now-redundant candidate branch, tears down the
  workspace, records `Landed` at the existing tip) rather than
  propagating an error (`crates/repo/src/ws.rs:525-546`). Reproduced and
  pinned by `harvest_reharvest_after_crash_window_is_idempotent`
  (`crates/repo/src/ws.rs:1177-1240`), which aligns to a fresh
  wall-clock second before landing so the reproduction doesn't race a
  second boundary.
- **A dirty-tree preflight runs before any candidate branch is minted.**
  `merge_with_identity` has its own dirty-working-tree guard, but it only
  fires *after* `harvest_workspace` has already created and committed
  the candidate branch for that workspace — and there is no CLI command
  that deletes a branch (`Branch` in `crates/cli/src/main.rs` only
  creates one), so a guard tripping mid-loop would leave a permanent
  stray `work-<i>` branch with no way to clean it up. `ws_harvest` now
  checks, up front, whether any live workspace actually diverged and, if
  so, runs the same uncommitted-changes check `merge_with_identity` uses
  before minting anything (`crates/repo/src/ws.rs:419-444`). A session
  where every live workspace is unchanged still harvests (and ends) even
  with a dirty tree, since nothing will be merged. Regression test
  `harvest_guards_and_dirty_tree` (`crates/repo/src/ws.rs:1079-1129`)
  asserts no stray `work-1` branch exists after the preflight refuses.
- **`resolve_and_teardown` writes the manifest before removing the
  workspace dir.** The reverse order would leave a crash window where
  the manifest still says `live = true` for a directory that no longer
  exists — wedging a later `ws_changed`/harvest call on an I/O error with
  no recorded recovery path. Manifest-first means a crash between the
  two steps leaves `live = false` recorded against a dir that happens to
  still be there (harmless: cleaned up by a future `ws_fork`'s root
  removal, or left as inert residue) (`crates/repo/src/ws.rs:595-613`,
  landed together with the dirty-tree preflight in the P20 review-fix
  commit).
- **The probe/merge disagreement bail states markers ARE on disk with a
  merge in progress.** If `would_merge_cleanly` predicts a clean merge
  but `merge_with_identity` returns `Err(MergeConflicts(_))` anyway (a
  probe/merge parameter-mirroring bug, not a normal user conflict),
  `ws_harvest` bails loudly before any teardown. The message was
  tightened during review from a hedge ("markers... may already be on
  disk... investigate before retrying") to a direct statement of fact:
  conflict markers ARE on disk in the landing branch's working tree, a
  merge IS now in progress, and it is resolvable the ordinary way
  (resolve the markers, `sc commit`) — the next `sc ws harvest` is
  guarded meanwhile by the existing merge-in-progress check
  (`crates/repo/src/ws.rs:547-572`).
- **The read-only probe composes `three_way` + `merge_secrets` with
  input assembly byte-identical to `merge_with_identity`; its inner
  `merge_secrets` arm is provably dead but kept for parity.**
  `would_merge_cleanly` calls `crate::merge::three_way(&mut store, base,
  ours, theirs, identity)` (`crates/repo/src/ws.rs:348`) with the exact
  same argument order `merge_with_identity` uses at
  `crates/repo/src/repo.rs:900` — same `merge_base` computation, same
  identity threading. Verified directly (not just asserted by the code's
  own doc comment): `three_way` (`crates/repo/src/merge.rs:122-150`)
  computes `merge_secrets(&base_snap.secrets, &ours_snap.secrets,
  &theirs_snap.secrets)` at line 133, *before* calling `three_way_files`
  at line 135, and propagates `Error::SecretMergeConflict` via `?` — so
  a secrets-only conflict surfaces through `three_way`'s own `Err`, which
  `would_merge_cleanly`'s outer `Err(e) => Err(e)` arm maps to `Err`
  before ever entering the inner `match` where the probe's own
  `merge_secrets` call lives. That inner call
  (`crates/repo/src/ws.rs:357-365`) is therefore unreachable whenever
  `three_way` returns `Ok` with no conflicts — kept anyway for parity
  with `three_way`'s internal check and documented as such in the doc
  comment, not because it does independent work. This is not a
  probe/merge disagreement: `merge_with_identity` calls `three_way` the
  same way, so a secret-only conflict is a hard `Err` there too — probe
  and real merge agree in every reachable case.
- **`SC_WORKSPACE` is set to `work-<i>`, deliberately matching the
  fallback-branch namespace.** `ws_run` sets `SC_WORKSPACE` to
  `format!("work-{}", entry.index)` (`crates/repo/src/ws.rs:302-304`),
  the same name a harvest fallback would mint for that index — label
  equals branch name, matching P13's parity convention (regression test
  `ws_run_sets_env_and_cwd`, `crates/repo/src/ws.rs:809-844`).
