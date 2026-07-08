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
- **Boundary: an out-of-sparse plaintext write during a mixed conflict
  that OUTLIVES the conflict window.** `Repo::materialize_conflict_state`
  (`crates/repo/src/repo.rs`) gates its own conflict *markers* against the
  sparse spec up front — an out-of-sparse conflicted path refuses with a
  widen hint before anything is written. But that gate only covers the
  marker-write loop; the same function's `to_encrypt`/sidecar-decrypt
  write loops (protected-content re-encryption inputs and `.theirs`
  sidecars for an *in-sparse* conflict) are not sparse-scoped. When an
  IN-sparse conflict co-occurs with an OUT-of-sparse protected/I2 clean
  change in the same merge, that out-of-sparse plaintext is written to
  disk outside the sparse view — and, verified by final-review testing,
  it **persists on disk after completion too**, not just during the
  conflict window: only `abort` removes it (its `!sparse.matches` removal
  arm runs on abort); completion's `read_worktree` re-lands the content in
  the CAS byte-correct, the same as any other carried file, but `commit`
  does not materialize, so it never deletes the on-disk file. The
  plaintext stays on disk until the next materializing operation (`switch`,
  `sparse set`/`disable`, another merge) re-lays the tree — there is no
  completion-time sweep. This is **not data loss** — the content lands in
  the CAS byte-correct either way — and **not a new disclosure**: the
  diff3 content-merge that produces the plaintext already required an
  authorized identity, and the I2 carried-plaintext case is pre-existing
  plaintext the sparse gate never claimed to hide from disk. It is a
  bounded disk-hygiene boundary — the sparse view stays wider than
  advertised, with no signal, until something else re-lays the tree — not
  a confidentiality or durability bug. Follow-on: extend the sparse gate
  to the `to_encrypt`/sidecar write loops so the view holds even
  mid-conflict (which would also close the post-completion persistence,
  since there would be nothing out-of-sparse to persist).

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
   the Consequences section above for the one write path this gate does
   *not* cover (`to_encrypt`/sidecar writes for an in-sparse conflict that
   co-occurs with an out-of-sparse clean change).
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
5. **`set_sparse`/`disable_sparse` refuse mid-conflict.** Re-laying the
   working tree while a merge/pick/rebase is in progress would either
   destroy in-progress conflict markers or narrow away a path a
   conflicted operation still needs on disk — both refuse with the same
   `MergeInProgress`/`PickInProgress`/`RebaseInProgress` errors the P21
   policy-op guards already use elsewhere, added in review before Task 4
   landed rather than discovered after.
