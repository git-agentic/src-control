# Task 2 report: self-healing marks on export (P21)

## Status
Done. Committed on branch `p21-hardening` at `2e20014`.

## What changed

### `crates/gitio/src/export.rs`
- Added `GitTarget::has_object(&self, id: gix::ObjectId) -> bool`, delegating to
  `gix::Repository::has_object` on the already-open handle held by `GitTarget`
  (no second repo-open — reuses the existing `self.repo`).
- In `export_branch`'s marks-seeding loop (was ~378), each `known_git_commits`
  entry is now verified with `target.has_object(g)` before being inserted into
  `commit_memo`. A hit seeds the memo as before (reused, not rewritten). A miss
  is counted in a new `stale_marks` counter and left out of the memo, so the
  post-order DAG walk treats that sc-id as unknown and re-synthesizes its git
  commit (and its tree/blobs, memoized independently) exactly like a
  never-exported commit — including rebuilding any dependent child commits
  whose parent oid needed the reused mark.
- `ExportReport` gained `pub stale_marks: usize`, populated from the counter
  and documented as "these ids also appear in `new_marks` with fresh oids."
- Added `#[test] stale_mark_is_reverified_and_resynthesized` in the `tests`
  module (after `export_reuses_known_marks_and_reports_new_ones`, using the
  same import-from-throwaway-git-repo setup): exports a 1-commit history,
  captures the real mark, replaces it with a valid-hex oid that does not
  exist in the target (`"a".repeat(40)`), re-exports with that stale map, and
  asserts: no error, `stale_marks == 1`, `new_marks` contains the sc id again,
  and both `git log --format=%H -1 refs/heads/main` and `git cat-file -p
  <commit>` on the target confirm the ref points at a real, readable commit
  (i.e. no broken parent chain was written).

### `crates/cli/src/main.rs`
- `run_push_git` (~line 2088-2101): after the existing
  `protected_blobs_as_ciphertext`/`secrets_dropped` warning block, added:
  ```rust
  if report.stale_marks > 0 {
      eprintln!(
          "  note: {} mark(s) referenced git commit(s) pruned from the target; re-synthesized with fresh ids",
          report.stale_marks
      );
  }
  ```
- `run_export` (~line 2194-2207): added the identical block after its own
  warning print. (This path always passes an empty `known_git_commits` map
  today, so `stale_marks` is currently always 0 there — the note is added per
  the brief for symmetry/future-proofing, e.g. if `run_export` ever grows a
  marks-reuse option.)

No `ExportOptions` test literals needed changes (they don't construct
`ExportReport`). No other `ExportReport` construction sites existed outside
`export_branch` itself.

## Tests run
- `cargo test -p scl-gitio` — 22 passed, including the new
  `stale_mark_is_reverified_and_resynthesized` and the pre-existing
  `export_reuses_known_marks_and_reports_new_ones` (unchanged, still passing —
  confirms the happy-path reuse behavior is undisturbed by the new
  existence check).
- `cargo test -p scl-cli` (includes the P18 e2e tests under `tests/git_remote.rs`
  such as `push_to_git_roundtrips_and_reuses_marks`, plus `main.rs`'s `tests`
  module network tests like `network_git_remote_round_trip_over_file_url` and
  `network_push_failure_is_retryable`) — all green, untouched.
- `cargo test` (full workspace) — 315+ passed across all crates, 0 failed.

## Concerns / notes
- `has_object` on `gix::Repository` (0.85.0) is a cheap existence probe (no
  full object parse), so the extra check per mark is low-cost even for large
  marks maps.
- The re-synthesis path is fully covered by the existing generic memo/walk
  logic — no special-casing was needed beyond not seeding the memo. This
  keeps the fix minimal and consistent with the rest of the file's
  content-addressed-reuse pattern.
- Confirmed via `git cat-file -p` in the test that the re-synthesized commit
  is well-formed and reachable through the ref, not just present in
  `new_marks` — directly validates the "no broken parent chain" requirement
  from the brief.

## P21 Review Fix (2026-07-08)

### Test Strengthening
- **Replaced** `stale_mark_is_reverified_and_resynthesized` (1-commit, insufficient)
  with `stale_mark_mid_chain_resynthesizes_with_valid_parents` (3-commit A→B→C).
- **Pattern** follows `import.rs::stale_mark_is_skipped_so_pruned_parent_is_reimported`:
  - Corrupt the MIDDLE commit B's mark to a nonexistent oid
  - Re-export with A valid, B stale, C not provided (so C re-synthesizes too)
  - Assert `stale_marks == 1`, `new_marks.len() == 2` (B and C re-synthesized)
  - Walk Git history from ref proving parent chain is valid: C's parent = B', B's parent = A
- **Convergence validation** (new): third export with healed marks (A original + B,C new)
  asserts `stale_marks == 0` and `new_marks.is_empty()` — heal converges.
- **Comment** added at `has_object` (line 109): "verifies the commit object only,
  not its tree/blob closure — sufficient under git-gc's reachability-atomic
  pruning; a commit with a corrupted tree is out of scope."
- **All tests pass**: `cargo test -p scl-gitio` (22 passed), full workspace (315+).
- **Commit**: `test(gitio): stale-mark heal proven mid-chain with valid parents + convergence; has_object scope documented (P21 review fix)`
