# ADR-0034: Sparse checkouts / sub-tree sharing

- **Status:** Accepted
- **Date:** 2026-07-08
- **Phase:** 24
- **Builds on:** ADR-0011 (working tree), ADR-0025 (absent-entry carry discipline), ADR-0003 (snapshot model)

## Context

The working tree is all-or-nothing: `switch` materializes the whole
snapshot, and `commit` reads the whole tree. Monorepo-scale use wants to
materialize one subtree and leave the rest on the CAS — and P15 already
built the key discipline (commits carrying forward absent entries the
checkout skipped, for protected files a keyless user can't read).
Sparseness generalizes that carry to user-chosen prefixes.

## Decision

Sparse CHECKOUT only (user-decided): all objects stay in the CAS, only a
subset materializes to disk. Partial clone (objects outside the prefix
never fetched — promisor store, prefix-scoped packs) is deferred.
Spec: `docs/superpowers/specs/2026-07-08-p24-sparse-checkouts-design.md`.

A persistent sparse spec (user-decided over a per-switch flag) at
`.sc/sparse` — local, uncommitted, a prefix set matching P7's
`matching_prefix` boundary rule; empty/absent = full materialization.
`sc sparse set <prefix…>` / `sc sparse show` / `sc sparse disable`.

The whole feature is ONE generalized predicate: `commit` already carries
forward absent files it cannot prove were deleted (the ADR-0025 P15
discipline). P24 widens the carry from "absent AND protected-and-not-a-
recipient" to "absent AND (that OR outside the sparse set)." So an
out-of-sparse absent file is carried from the tip verbatim (byte-
identical subtree); an in-sparse absent file is a genuine deletion.
`tracked_paths`/`read_worktree`/`diff_worktree` scope to the spec the
same way. No new object model, no snapshot format change.

Interactions settled: a clean merge/pick/rebase change to an out-of-
sparse path lands in the CAS without materializing (P15 tree-id
precedent); a CONFLICT there is reported with a "widen your sparse set to
resolve `<path>`" message rather than auto-materializing (and `sc resolve`
errors the same way, while `sc conflicts` still inspects via DAG-derived
versions). Protected and sparse are orthogonal — the carry composes.
`sc ws` workspaces inherit the host's `.sc/sparse` at fork time; the
fork-time spec is persisted in `session.toml` and reused for that
workspace's diff/harvest regardless of later host spec changes (final-
review fix — see Consequences).

## Consequences

- Working in one subtree of a large repo leaves the rest off disk;
  commits don't disturb absent parts (byte-identical carried subtrees).
- The memory-budget story (ADR-0006) composes: sparse materialization
  bounds checkout cost the way the budget bounds resident blobs.
- gc is unchanged: all objects stay reachable (sparse is a disk view, not
  an object-set change).
- **Closed (#210): no out-of-sparse plaintext during a mixed conflict.**
  `Repo::materialize_conflict_state` (`crates/repo/src/repo.rs`) gates its
  conflict *markers* against the sparse spec up front, and since #210 the
  same gate covers the `to_encrypt` inputs (content-merged protected files,
  and ours' carried-plain files under a theirs-only rule). One outside the
  sparse view refuses the merge, cherry-pick or rebase with a widen hint
  (`sc sparse set`) before anything is written, exactly like an
  out-of-sparse conflicted path, so a stop, its completion and its abort
  leave nothing out of view on disk. From `rebase --continue` the hint
  says to widen with `sc sparse set` and rerun `--continue` (a widen is
  allowed mid-stop since #224, see refinement 5). Sidecars need no gate on
  a full clone: each is `<conflicted path>.theirs` beside a conflicted path
  that already passed the gate (so it is in view even under a file-exact
  spec such as `src/a.bin`), and abort and completion remove it; a partial
  clone checks the sidecar by its base path (#224), so a file-exact spec no
  longer refuses a valid in-view binary conflict (ADR-0049). The earlier build wrote that
  plaintext outside the view and left it there after completion (only
  abort removed it); this was never data loss or a new disclosure, only a
  view wider than advertised. The cost is that such a merge now needs the
  view widened first; the alternative, sealing the plaintext at the stop,
  would need its fresh wraps persisted with the decided root and was not
  worth the surface. The check already existed for partial clones
  (ADR-0049 decision 8); it now applies to every clone.

## Alternatives considered

- **Shallow (history-truncating) clone instead:** orthogonal axis; does
  not help tree width, punts on the carry discipline.
- **Virtual filesystem (FUSE) materialization:** rejected for the same
  reasons as ADR-0005.

## Refinements discovered during the build

Every prior phase's Refinements section holds this one to the same bar:
every claim below is checked against the shipped code, not the plan.

1. **The whole feature is one generalized carry predicate.** `commit`'s
   absent-path carry (`crates/repo/src/repo.rs`, `snapshot_files`'s carry
   block) widened from "absent AND still-protected-and-not-a-recipient" to
   "absent AND (that OR `!sparse.matches(path)`)" — a single `||` added to
   an existing condition, no new code path. A review pass caught a
   subtlety the design didn't call out: the carried entry's perms byte had
   to change from a hardcoded `scl_core::PROTECTED` to the *source* entry's
   own perms, because once a carried-plain out-of-sparse file could reach
   that arm (previously only protected paths could), hardcoding
   `PROTECTED` would silently mark a plain file protected on the next
   materialize. Mutation-pinned by
   `commit_carries_out_of_sparse_absent_path_verbatim`, which asserts both
   the carried blob id *and* `perms & PROTECTED == 0`.
2. **`materialize`'s dual-loop filter, and two self-caught reader bugs.**
   `crates/repo/src/worktree.rs::materialize` filters both its write loop
   (`if !sparse.matches(path) { continue; }`) and its `old_root` removal
   loop (`if !target.contains_key(p) || !sparse.matches(p) { remove }`) —
   the removal loop's sparse check is what makes `Repo::set_sparse`
   narrowing prune files that are still tracked by the target tree but now
   fall outside the spec. `Repo::set_sparse` calls `materialize` with
   `old_root = Some(head_root)` — target and old root are the same commit,
   so the write loop only re-touches files already on disk and the removal
   loop does the narrowing. Before this landed, two HEAD-vs-disk readers
   (`diff_worktree` and `diff_unified`) both misreported an out-of-sparse
   path as a user deletion; both were caught and fixed in the same pass
   (each now short-circuits `!sparse.matches(path)` to "expected absent,"
   the same treatment an unauthorized protected file already got from P15).
3. **The widen-error site, and what it does and doesn't cover.** A
   CONFLICTED protected/text path outside the sparse view can't be shown
   to the user (nowhere on disk to put markers without silently
   materializing a path they asked to exclude). The gate lives at the very
   top of `Repo::materialize_conflict_state` (`crates/repo/src/repo.rs`) —
   it checks every path in the operation's own `conflicted_paths` list
   against `sparse.matches` and returns `Error::InvalidArgument` with a
   "run `sc sparse set` to include it" hint *before* `carried` is written
   to the CAS, so no out-of-sparse marker is ever written, not even
   transiently. `crates/repo/src/conflicts.rs::resolve_path` carries the
   identical gate for `sc resolve`; `conflict_versions` deliberately does
   NOT gate, since inspecting a conflict (`sc conflicts <path>`) doesn't
   write to disk. A CLEAN out-of-sparse change never reaches either gate —
   it resolves on tree ids inside `three_way`/replay and lands via the
   ordinary `materialize` skip-write path, no markers involved at all. See
   the Consequences section above: since #210 the `to_encrypt`
   writes for an in-sparse conflict that co-occurs with an out-of-sparse
   clean change are refused by the same gate.
4. **`sc ws` inherits the host's sparse view, structurally, not by
   convention — and, after a final-review fix, durably against later host
   spec changes.** `Repo::sparse_spec()` is read once in `ws_fork` and
   threaded as a parameter into `workspace::materialize_workspace`
   (`crates/repo/src/ws.rs` / `workspace.rs`) — a forked workspace's
   checkout is sparse-filtered exactly like the host repo's own working
   tree, pinned by `ws_fork_inherits_sparse`. The original build left one
   gap, found in final review: `ws_harvest` re-read the host's *current*
   `.sc/sparse` at harvest time rather than the spec the workspace was
   actually materialized under, so a legitimate `sparse set`/`disable` on
   the host between fork and harvest made the never-materialized subtree
   read as a user deletion and silently drop it from the branch tip
   (`snapshot_files`'s carry predicate saw the wrong spec). The fix
   persists the fork-time prefixes in `WsSession`/`session.toml` and
   threads *that* recorded spec into `ws_changed_for` and `ws_harvest`'s
   call into `harvest_workspace` (which now also passes it on into
   `snapshot_files`, which takes the carry's sparse view as an explicit
   parameter instead of reading `self.sparse_spec()` ambiently) — so
   harvest always diffs and commits against the view the workspace was
   actually given, pinned by
   `ws_harvest_uses_fork_time_sparse_not_ambient`. The same
   parameterization closed a companion gap in `sc work`'s one-shot
   ephemeral agents, which stay full-checkout (`Sparse::default()`): before
   the fix, a host sparse spec made `snapshot_files` read the *host's*
   narrow view during harvest and silently revert an agent's genuine
   deletion of an out-of-sparse path, pinned by
   `sc_work_full_agent_deletion_survives_host_sparse`.
5. **`set_sparse`/`disable_sparse` refuse mid-conflict, except a strict
   widen.** Re-laying the working tree while a merge/pick/rebase is in
   progress would either destroy in-progress conflict markers or narrow
   away a path a conflicted operation still needs on disk — both refuse
   with the same `MergeInProgress`/`PickInProgress`/`RebaseInProgress`
   errors the P21 policy-op guards already use elsewhere, added in review
   before Task 4 landed rather than discovered after. `disable_sparse`,
   narrowing and sideways specs still refuse. Since #224 `set_sparse` accepts
   a spec that `Sparse::covers` the current one (every old prefix is matched
   by a new one) while the stop has a recorded decided root
   (`MERGE`/`PICK`/`REBASE_DECIDED_ROOT`), so `rebase --continue`'s
   out-of-view refusal can be fixed without losing the resolved commits.
   `Repo::widen_while_stopped` (`crates/repo/src/sparse.rs`) does not
   re-lay HEAD. For the decided root, the tip and (rebase) the accumulator
   it fills the new view's closure (lazy partial clones), preflights the
   view and runs `refuse_untracked_for_view_change`, then writes
   only the files `old` did not match (`worktree::lay_out_added_view`) and
   stores the spec last, so a crash leaves extra out-of-view files, never a
   view with files missing. The paths are recorded in `.sc/sparse-widen` before
   the first write (each file is written atomically) and the record is
   removed with the spec write or with the stopped op. A retry treats a
   recorded file already on disk with the decided root's bytes as its own
   earlier write; an unrecorded file, even with equal bytes, or a changed one
   still refuses (modes are not compared: `lay_out_added_view` writes none,
   #237). The record starts with the stop's decided-root id and is ignored
   when that does not match (a stale record). When the stop ends with the old
   view still in force (abort of a merge, pick or rebase, or the completion
   after an interrupted widen) `Repo::remove_widen_residue` deletes the
   recorded files that lie outside the view and still have the decided tree's
   bytes, before the op's state is cleared: the abort's own walk follows the
   other side's tree and the restored view, so it cannot see an ours-only
   file or a subtree never fetched for theirs. A file the user edited since is
   left. The cleanup runs before the working tree is read for completion, and a retry with a
   different target keeps the earlier target's paths recorded. On a
   partial clone the new view is recorded in `.sc/sparse-prev` before the
   writes, so the abort's removal walk covers files an interrupted widen
   laid; the marker is restored to its prior state once the spec is stored.
   The untracked-file guard checks only paths the old view did not match
   (those it laid out are not written, and a stopped op may have turned one
   into a directory). Widening to the same spec is a quiet no-op. The
   decided root is the right source: it is what completion carries an
   out-of-view path from (refinement 6). For a resumed rebase (`resolved`) the accumulator
   can differ from it outside the view, but the next `--continue` re-lays
   the tree from the accumulator under the new spec, so what the widen laid
   is overwritten there. A full spec is `disable` and stays refused. Markers, the resolution,
   `CONFLICT_PLAINTEXT` and sidecars are all in the old view, so they are not
   touched; the dirty-tree check is skipped (HEAD is stale mid-op). A
   protected file that comes into view is not decrypted (the stop does not
   persist its wrap map): it stays absent, is reported as skipped, and
   completion carries it from the decided root as for any absent protected
   path. Abort restores the original tip over the widened view and the spec
   stays widened. No oplog record is written (the spec change moves no
   ref); the repo lock is held by the CLI as for any mutation.
6. **Completion carries from the decided root, not the parents (#238).**
   A stopped merge, cherry-pick or rebase on a public branch records a
   decided root (`MERGE`/`PICK`/`REBASE_DECIDED_ROOT`); a merge into a
   private branch writes none and completes through `commit_private`, which
   this refinement does not cover. `snapshot_files` carries an absent
   out-of-view or still-protected path from the decided root. Earlier builds
   also read the tip and merge head, so a path the other side had cleanly
   deleted (an out-of-view file, or a protected file) came back from the tip
   and the deletion was silently lost; a file the other side turned into a
   directory was carried beside it, a corrupt tree. With a decided root the
   parents are no longer consulted: on a full clone it holds every surviving
   entry (protected ones as ciphertext), and conflicted paths and sealing
   inputs are on disk or in `CONFLICT_PLAINTEXT`. They stay the full fallback
   for state written without a decided root. Pinned by `sparse_completion.rs`
   (merge, pick, rebase: deletion kept, clean add and modify land, ours-side
   out-of-view changes kept, equal to the run without sparse; file to
   directory; an out-of-view exec bit; a protected deletion).
