# ADR-0023: Agent workspaces — vfs-backed sessions over the persistent store

- **Status:** Accepted
- **Date:** 2026-07-06
- **Phase:** 13
- **Builds on:** ADR-0005 (in-RAM vfs), ADR-0011 (persistent store), ADR-0006 (memory budget)

## Context

The in-memory-clones pillar (Phase 1) exists only in the ephemeral demo;
persistent repos (Phase 3+) have no way to fork N parallel workspaces for
agents and collect their results. Real agent processes need real files, and
an in-RAM overlay only lives as long as one process.

## Decision

One-command sessions: `sc work --agents N -- <cmd>` forks N vfs worktrees
from HEAD inside the repo's existing budget-bounded persistent store (the
store on disk is the reconstruction source, so eviction is safe and the
Phase 1 spill backend is unnecessary in this path), materializes each fork
to an ephemeral temp checkout with the P7-aware `materialize`, runs the
agent commands concurrently (optionally with secrets injected via the
`sc run` path), and harvests each changed workspace to a flat `work-<i>`
branch through the commit path — scanner gate and `.scignore` included.
Integration is the existing `sc merge`. The user's branch, HEAD, and
working tree are never touched; teardown leaves zero residue outside
`.sc/`.

Branch names are flat (`work-1`, not `work/1`): the ref-resolution grammar
reserves `name/branch` for remote-tracking refs.

The Phase 1 fusion referenced above is store-level, not object-level: the
shared, budget-bounded blob cache (one `Arc`'d store behind the repo) serves
every workspace's reads and eviction, while each workspace's vfs fork handle
is just session bookkeeping — a cheap pointer into that shared cache, not an
independent copy of Phase 1's in-memory model.

## Alternatives considered

- **Direct checkouts without vfs:** nominal fusion; loses the shared
  budget-bounded cache that makes N forks cheap.
- **Interactive sessions across invocations:** needs a daemon or persisted
  overlay; deferred.
- **Auto-merging clean results into the current branch:** silent mutation
  of the user's branch during teardown violates the no-silent-destruction
  principle; deferred as an explicit follow-on.

## Consequences

- A session holds the single-writer lock for its whole lifetime; concurrent
  `sc` commands are locked out (same model as every other command).
- A failed agent's partial work is still harvested — failure is reported,
  work is never destroyed.
- The ephemeral/persistent mode invariant is amended: a `sc work` session
  is a bounded ephemeral session hosted by a persistent repo; the
  persistent store is the only durable surface.
- The P5 scanner catches recognizable secret shapes (AWS-style key ids and
  similar high-signal patterns); it cannot catch a low-entropy secret value
  an agent writes into a file verbatim — the same exposure `sc run` +
  `sc commit` already carry today, unchanged by this phase.

## Refinements during the build

- **Materialize all workspaces before spawning any agent.** The original
  plan spawned and materialized per-workspace in one pass. Review (commit
  36f3dea) found that interleaving them meant a materialize failure on
  workspace *k* could `?`-abort the session while workspaces `1..k-1` still
  had live agent children — orphaned processes racing the teardown guard's
  `remove_dir_all` underneath them. `Repo::work` now runs two clean passes:
  materialize every workspace first (the only fallible, `?`-aborting step),
  then spawn all agents and await them. A setup failure now never orphans a
  running child.
- **Budget semantics, precisely stated.** The spec said "eviction is safe
  under budget pressure"; the build sharpened this into two distinct,
  separately tested outcomes. When the *aggregate* resident set exceeds the
  budget but every individual blob still fits, the session succeeds and
  evicts reclaimable blobs (`vfs().stats().evictions > 0` is asserted in
  `workspace::tests::budget_evicts_when_reclaimable_and_fails_loudly_when_not`).
  Only when a *single* blob is larger than the budget itself — nothing left
  to reclaim — does the session fail loudly with `Error::BudgetExceeded`,
  matching the project's no-silent-drop invariant.
- **Scanner rejection is per-workspace, not session-wide.** `HarvestResult`
  carries a `Rejected(ScanReport)` variant so one workspace tripping the P5
  scanner (tested against a real AWS-style key id, `AKIAIOSFODNN7EXAMPLE`,
  in `plaintext_secret_in_workspace_is_rejected`) reports that workspace's
  outcome without aborting or discarding its siblings' harvests.
- **Spawn failure still harvests.** If the agent binary can't be exec'd at
  all, `agent_exit` is `None` but the session proceeds to harvest that
  workspace's checkout (`Unchanged`, since nothing ran) rather than treating
  spawn failure as fatal to the session — tested in
  `spawn_failure_is_reported_not_fatal`.
- **Demo recipient bootstrap.** `demo/run_work_demo.sh` exercises
  `--with-secrets` by running `sc keygen` and hand-writing
  `.sc/recipients.toml` before calling `sc secret add`, rather than relying
  on any auto-registration — recipient setup for secrets remains an explicit,
  out-of-band step, unchanged from Phase 2/11.
