# ADR-0031: Hardening & consolidation sweep — closing the P16–P20 review tail

- **Status:** Accepted
- **Date:** 2026-07-08
- **Phase:** 21
- **Builds on:** ADR-0017 (P17 rewrap guards), ADR-0018/0028 (marks map), ADR-0029 (rebase state), ADR-0030 (ws sessions)
- **Spec:** `docs/superpowers/specs/2026-07-08-p21-hardening-design.md`

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
- Marks staleness self-heals at the only dangerous point of use: export/
  push verifies each mark-reused git commit exists in the target before
  reuse, re-synthesizing (with a one-line stderr note) when `git gc`
  pruned it — a stale mark can otherwise produce a broken parent chain in
  the target repo. The fetch direction is already harmless. A
  `sc marks verify` subcommand was rejected: self-heal beats a tool the
  user must know to run.
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

## Refinements discovered during the build

- **[Review-adjudicated] The policy-op enumeration in the spec was
  incomplete.** The spec and this ADR's own Context/Decision text name
  `grant`/`revoke`/`protect`/`secret add`/`secret rotate` — five ops. The
  binding principle is broader: *every* commit-creating policy op needs
  the guard trio, and two more distinct-but-same-shaped ops were found
  during the build:
  - `secret_revoke` (`crates/repo/src/secrets.rs:134`) calls
    `commit_registry` — the same ref-moving helper `secret_add`/
    `secret_rotate`/`secret_grant` use — so it carries the identical
    unguarded-ref-mover hazard. Found and fixed inside Task 1 itself
    (the brief's own instruction to check it), not review-caught.
  - `secret_grant` (`crates/repo/src/secrets.rs:100` — distinct from
    `protect_ops::grant` at `crates/repo/src/protect_ops.rs:125`) has the
    same `commit_registry` hazard shape but was named in neither the
    spec's enumeration nor Task 1's binding test. Task 1 shipped without
    it, flagged the gap explicitly in its own report, and a review pass
    caught it as a Critical — fixed same-day in `fd43c7c` ("secret_grant
    joins the policy-op guard family"). The corrected, verified-in-code
    full list of seven guarded ops: `protect` (`protect_ops.rs:30`),
    `grant` (`protect_ops.rs:125`), `revoke` (`protect_ops.rs:197`),
    `secret add` (`secrets.rs:73`), `secret rotate` (`secrets.rs:183`),
    `secret grant` (`secrets.rs:100`), `secret revoke` (`secrets.rs:134`)
    — each opens with the same three-line `MergeInProgress`/
    `PickInProgress`/`RebaseInProgress` block before any commit-creating
    work.
- **Marks self-heal's existence check is commit-scoped, by design, not by
  oversight.** `GitTarget::has_object` (`crates/gitio/src/export.rs:113`)
  delegates to the already-open `gix::Repository` handle's own
  `has_object` — a cheap existence probe on the commit object only, not a
  walk of its tree/blob closure. A commit whose tree or blob content is
  missing but whose commit object survives is out of scope: `git gc`
  prunes unreachable objects transitively (reachability-atomic — a commit
  object is never left dangling with a pruned tree underneath it), so a
  commit-level existence check is sufficient for the failure mode this
  refinement actually defends against. Heal convergence is proven, not
  assumed: `stale_mark_mid_chain_resynthesizes_with_valid_parents`
  (`crates/gitio/src/export.rs:801`) corrupts a mid-chain mark, re-exports
  (`stale_marks == 1`, one dependent child re-synthesized with a valid
  parent chain), then re-exports a THIRD time with the healed marks map
  and asserts `stale_marks == 0` and `new_marks.is_empty()`
  (`crates/gitio/src/export.rs:898`) — the heal doesn't just recover once,
  it reaches a stable fixed point. Separately, the append-only
  `MarksStore` (`crates/repo/src/git_marks.rs:32`) has always resolved
  duplicate keys last-wins by construction: both `run_fetch_git` and
  `run_push_git` (`crates/cli/src/main.rs:1975-1978`, `:2032-2036`) fold
  `marks.load()`'s pairs into a `HashMap` via `.insert()` in file order,
  so a later append for the same git-oid key silently shadows an earlier
  one — the healing re-synthesis's freshly appended mark durably wins over
  the stale one on every subsequent load, with no special-casing needed.
- **Counters: an `Empty` replay with a changed secret registry still
  counts as replayed, not skipped.** `rebase_fold_and_finish`
  (`crates/repo/src/replay.rs:794-822`) computes `secrets_changed` before
  matching on the replay outcome and carries an explicit disambiguating
  comment at the two `Empty` arms: `ReplayOutcome::Empty if
  !secrets_changed` is a genuine no-op ("Empty in full — tree, this
  commit's own rules delta, AND the registry delta") and increments
  `skipped`; plain `ReplayOutcome::Empty` (tree-empty but the registry
  changed) "counts as replayed, not skipped" because a snapshot still
  lands. Getting this wrong would have silently dropped registry-only
  commits from a replayed range's landed count.
- **The conflict-materialization extraction landed as a `Repo` method in
  `repo.rs`, not a free function in `worktree.rs`.** `worktree.rs`'s
  functions (`materialize`, `safe_join`) take `&Layout`/`&mut Store`
  directly with no `Repo` context; the extracted helper
  (`materialize_conflict_state`, `crates/repo/src/repo.rs:1101`,
  `pub(crate)`) needs `self.vfs`/`self.layout`, matching how
  `merge_with_identity` and `merge_abort` already live as `Repo` methods
  in the same file. Because `replay.rs`'s `cherry_pick` and
  `rebase_fold_and_finish` are themselves defined in a second `impl Repo`
  block, both call sites reach the new method via plain `self.
  materialize_conflict_state(...)` with no new `use` — the stated goal
  going in. The write-order crash discipline (build the CAS tree from
  `carried` → materialize with the caller's `old_root`/`conflict_prot`/
  `identity` → write `to_encrypt` plaintext directly, AFTER materialize so
  its deletion pass doesn't remove it → write sidecars) is carried into
  the helper's own doc comment rather than left implicit, since it no
  longer has three adjacent copies to cross-reference.
- **`rebase_resolved()` is a sibling accessor, not a `rebase_progress`
  signature change.** `crates/repo/src/repo.rs:789` adds
  `pub fn rebase_resolved(&self) -> Result<bool>` alongside the existing
  `rebase_progress`, reading `RebaseState` a second time rather than
  widening `rebase_progress`'s 3-tuple return (which every existing call
  site across the crate and CLI destructures positionally). Two state
  reads in `sc status`'s human-readable path is an accepted, ledger'd
  tradeoff against rippling a signature change through call sites that
  don't need the new field.
- **ws/demo minors, as specified, with one addition beyond the spec's
  literal wording.** `ws_changed_for` (`crates/repo/src/ws.rs:250`) takes
  an already-loaded `WsSession` so `sc ws list`'s loop
  (`crates/cli/src/main.rs:1670-1686`) and `ws_harvest`'s per-entry checks
  parse the manifest once, not once per entry; the public `ws_changed`
  keeps its original signature (re-reads the manifest) so existing tests
  pin unchanged behavior, per the brief. The undone-landing vocabulary
  needed a new field, not just a label rename: `WsEntry.landed_tip:
  Option<ObjectId>` (`crates/repo/src/ws.rs:35-51`, backward-parse
  default `None` for pre-P21 manifests) is set only on a `Landed`
  resolution (including the idempotent `UpToDate` no-op landing); `sc ws
  list` calls `ws_status_label` (`crates/repo/src/ws.rs:268`), which
  checks whether `landed_tip` is still an ancestor
  (`crate::merge::is_ancestor`) of `session.base_branch`'s current tip and
  prints `"landed"` or `"landed (undone by sc undo)"` instead of the
  generic `"abandoned"` a manual `ws_abandon` (or a resolution that never
  landed anything, e.g. `Unchanged`/`FallbackBranch`) still shows. Known
  limitation, documented at the call site: the manifest doesn't record
  which branch an entry actually landed onto, so a workspace harvested
  with `--into <other-branch>` is still checked against `base_branch` and
  can misreport "undone" for a landing that's intact elsewhere — the
  common default-landing-branch case is unaffected, and storing a
  per-entry landing branch is a manifest schema change left out of scope
  for a label fix. Regression test: `harvest_partial_leaves_session_open`
  (`crates/repo/src/ws.rs:1293`), extended to assert the label before and
  after `sc undo`. `demo/run_ws_demo.sh`'s no-marker check became a
  recursive tree walk (`find "$repo" -path "$repo/.sc" -prune -o -type f
  -print0`), run twice in verification to confirm it isn't order-
  dependent.

Deliberately left open, as scoped: the inert pre-crash `work-<i>` ref
sub-window and `BadRef`'s reuse for state-file parse errors. Neither
surfaced a new concern during the build.
