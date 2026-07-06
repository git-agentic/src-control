# Agent workspaces (Phase 13) — design

- **Date:** 2026-07-06
- **Status:** Approved for planning
- **Depends on:** Phase 1 vfs (`vfs::Repo::fork`, budget + eviction), Phase 3
  persistent store (`Store::open_persistent`, commit machinery, repo lock),
  P4 merge (integration path), P5 scanner (harvest gate), P7 protected paths
  (checkout rules), Phase 2 secrets (`run_with_secret` injection)

## Goal

Fuse the two halves of the project: fork N in-RAM copy-on-write workspaces
*of a real persistent `.sc` repo*, run real agent processes in them, and
commit the results back as branches. The in-memory-clones thesis pillar
(Phase 1) finally meets the persistent VCS (Phase 3+) instead of living only
in the ephemeral demo.

**Success bar:** `sc work --agents 3 -- <cmd>` in a persistent repo produces
three `work-<i>` branches (one per changed workspace) integrable with the
existing `sc merge`, leaves zero residue outside `.sc/`, and a scripted demo
(`demo/run_work_demo.sh`) proves the round trip end-to-end including a
three-pillar variant with `--with-secrets`.

## Approach (chosen: vfs-backed session, persistent store as backing tier)

One session command opens a single budget-bounded `Store` over `.sc/objects`
(`Backend::Persistent` — already implemented in core), wraps it in
`vfs::Repo`, and forks N worktrees from HEAD. All N forks share one
Arc-shared blob cache; budget and eviction do real work, and eviction is
always safe because every object is reconstructible from disk — the
persistent store *replaces* the Phase 1 spill backend rather than adding to
it. Checkout, harvest, and commit reuse the existing `repo` machinery
verbatim.

Rejected alternatives:
- **Direct checkouts, no vfs:** materialize N temp checkouts straight from
  the store, harvest with the commit path. Least code, but the fusion with
  Phase 1 would be nominal — `git worktree` with extra steps; the in-RAM
  pillar still never meets the real repo.
- **Interactive session across invocations** (`sc ws fork/list/harvest` as
  separate commands): needs a daemon or a persisted-overlay format; blurs the
  ephemeral/persistent mode boundary and is a much bigger phase. Deferred —
  recorded in the roadmap.
- **In-process API only:** purest, but no external agent (compiler, editor,
  Claude Code) could ever touch a workspace; the demo stays synthetic.

## Command surface

```
sc work --agents N [--name <base>] [--budget-mb M]
        [--with-secrets --identity <key>] [--author <who>]
        -- <cmd> [args…]
```

- Runs from inside a persistent repo, forking from the current branch's HEAD.
  Refuses on an unborn branch (no commits yet). No dirty-tree guard: the
  user's working tree is never read or written — sessions fork from HEAD.
- Workspace labels double as branch names: `<base>-1..<base>-N`, where
  `<base>` defaults to `work` (`--name feature` → `feature-1..feature-N`).
  Names are **flat** (no `/`): the existing ref-resolution grammar reserves
  `name/branch` for remote-tracking refs (`refs::resolve_tip`), and
  `validate_branch_name` already rejects `/` — slash-named local branches
  would be unresolvable by `sc merge`.
- Each agent command runs with **cwd = its checkout dir** and env vars
  `SC_WORKSPACE=<label>`, `SC_WORKSPACE_DIR=<abs path>`.
- Agent commands run **concurrently** (one child process per workspace, all
  spawned, then all awaited).
- Exit code: `0` if every agent command exited 0 and every harvest succeeded;
  non-zero otherwise. A failed agent's workspace is **still harvested** —
  partial work lands on its branch rather than being destroyed; the failure
  is reported in the session summary.
- Session summary (stdout): per workspace — label, agent exit status,
  changed/unchanged, branch created (or scanner rejection / error).

## Session engine

New module `crates/repo/src/workspace.rs`. The dependency rule holds
unchanged: `cli → repo → {vfs, gitio, crypto} → core`, and `repo` already
depends on `vfs`.

Session flow:

1. **Lock.** Take the repo's single-writer lock for the whole session — no
   concurrent `sc commit`/`gc`/`switch` can race the harvest.
2. **Preflight (fail-fast, before any agent runs):**
   - resolve HEAD snapshot; refuse on unborn branch;
   - refuse if any target branch `<base>-<i>` already exists;
   - with `--with-secrets`: decrypt every registered secret once via the
     identity; refuse on unauthorized identity.
3. **Store + forks.** `Store::open_persistent(".sc/objects", budget)` →
   `vfs::Repo::new(store)` → `fork(head_snapshot, label)` per workspace.
   Default budget matches the existing demo default; `--budget-mb` overrides.
4. **Materialize.** Each workspace checks out to
   `<system tmp>/sc-work-<pid>/<label>/` using `repo`'s existing
   `materialize` (NOT `vfs::Worktree::checkout`), so P7 protected-path rules
   apply identically to `sc switch`: authorized identity → plaintext,
   otherwise protected files are skipped, never written as ciphertext.
5. **Run.** Spawn all agent commands; inject decrypted secrets into each
   child env via the same code path as `sc run` when `--with-secrets`. Wait
   for all.
6. **Harvest (sequential, under the held lock).** For each workspace:
   `read_worktree`/`diff_worktree` against its base snapshot — the same code
   `sc commit` uses, so `.scignore` and the P5 secret scanner apply. A
   scanner hit rejects that workspace's harvest loudly and continues with
   the others. Changed workspaces commit to branch `<label>` (parent = base
   session-start HEAD snapshot); unchanged workspaces are
   reported and dropped. The current branch and HEAD are never touched.
   Commit message defaults to the agent command line; author resolves as
   `--author` > `$SC_AUTHOR` > OS user (same as `sc commit`).
7. **Teardown.** Remove `<tmp>/sc-work-<pid>/` recursively; release the
   lock. Zero residue outside `.sc/`.

## Invariants

- **Mode composition, not violation.** The session's workspaces are
  ephemeral (temp checkouts removed on teardown); all `.sc/` writes go
  through the same commit path persistent mode already owns. CLAUDE.md's
  "modes are mutually exclusive" wording is amended to name this
  composition: a `sc work` session is a bounded ephemeral session *hosted
  by* a persistent repo, with the persistent store as the only durable
  surface.
- **Budget still fails loudly.** No spill backend in this path; over-budget
  inserts surface `BudgetExceeded` with a hint to raise `--budget-mb`. Never
  silently drop.
- **Blobs stay `Arc<[u8]>`-shared.** Forking N workspaces must not copy blob
  bytes; one store read serves all N.
- **No silent destruction.** Failed agents keep their branch; scanner
  rejections are reported, not swallowed; existing `<label>` branches
  cause refusal at preflight, not overwrite.
- **Content addressing unchanged.** No new object kinds, no encoding
  changes; workspace commits are ordinary snapshots.

## Error handling

- Crash mid-session: worst case is a stale temp dir (OS-cleaned tmpfs) and a
  stale repo lock — same recovery story as any interrupted `sc` command.
  Nothing under `.sc/` is ever half-written beyond what the existing commit
  path already guarantees (ADR-0021 durability).
- One workspace failing (agent non-zero, scanner rejection, harvest error)
  never aborts the others; every outcome appears in the summary and drives
  the exit code.
- `--with-secrets` without `--identity`, unknown identity, or unauthorized
  recipient: refuse at preflight, before any checkout exists.

## Testing

In `repo::workspace` tests (plus one CLI-level integration test):

- fork-N, edit distinct files per workspace, harvest → N branches, each
  mergeable; merged result contains all edits.
- unchanged workspace → no branch, reported as unchanged.
- scanner rejection: one workspace writes a plaintext secret → its harvest
  is rejected, siblings still land; exit code non-zero.
- branch collision: pre-existing `work-1` → session refuses at preflight.
- failed agent (non-zero exit) with changes → branch still created; exit
  code non-zero.
- teardown: assert the temp session dir is gone after success AND after a
  simulated harvest error.
- secrets injection: agent script echoes the env var to a file → harvested
  content proves injection (using a scanner-allowlisted marker value).
- budget: tiny `--budget-mb` over a large repo → loud `BudgetExceeded`.

Demo `demo/run_work_demo.sh`: init repo → base commit → `sc work --agents 3
-- <script editing different files>` → show three branches → `sc merge` them
→ independent before/after filesystem diff proving no residue outside
`.sc/`. A `--with-secrets` leg proves the three-pillar story.

## Documentation

- **ADR-0023 — agent workspaces** (Proposed → Accepted at build completion):
  records the vfs-backed-session decision and rejected alternatives.
- **CLAUDE.md / ARCHITECTURE.md:** Phase 13 section; amend the mode
  invariant wording as above; add `sc work` to the command list.
- **ROADMAP.md revision (part of this phase, first task):**
  - move **P12 — ssh-native transport** (ADR-0022) into Done — currently
    missing entirely;
  - add **P13 — agent workspaces** as the active phase with this spec's
    demoable outcome;
  - refresh **Deferred**: split "network transport" into shipped (ssh-native,
    P12) vs. remaining (HTTP transport, network Git remotes, >4 GiB streaming
    frames); keep bulk re-wrap, multiple escrow keys, sub-tree/partial
    sharing, merge ergonomics (rebase/cherry-pick), signed commits/provenance;
    add **interactive/daemon workspace sessions** and **auto-merge of clean
    workspace results** as new deferred items (explicitly out of P13 scope);
  - update the dependency graph and "why this order": P13 depends on Phase 1
    vfs + Phase 3 store, integrates via P4 merge, and composes with
    P5/P7/Phase 2 at zero marginal design cost.

## Out of scope (deferred, recorded in ROADMAP.md)

- Interactive/daemon sessions (`sc ws fork` … `sc ws harvest` across
  invocations).
- Auto-merging clean workspace results into the current branch.
- Workspace-aware `sc status`/`sc log` views of live sessions.
- Nested sessions / forking from a workspace branch mid-session.
