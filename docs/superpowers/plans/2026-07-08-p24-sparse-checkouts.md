# P24 — Sparse Checkouts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Materialize only a chosen subtree; commits carry unmaterialized subtrees byte-identically (spec: `docs/superpowers/specs/2026-07-08-p24-sparse-checkouts-design.md`, ADR-0034). Closes the P21–P24 horizon.

**Architecture:** A persistent `.sc/sparse` prefix set + a `Sparse` type. The entire correctness story is ONE generalized carry predicate: `commit` already carries absent files it can't prove were deleted (the P15 discipline); P24 widens that to also carry absent files outside the sparse set. `materialize` and the working-tree readers scope to the spec. **Task ordering is deliberate: the carry generalization (Task 2) lands BEFORE materialize filtering (Task 3), so there is never an intermediate state where `commit` would treat an unmaterialized subtree as a deletion.**

**Tech Stack:** Rust stable, existing crates, no new dependencies. No object-model or snapshot-format change; gc unchanged.

## Global Constraints

- Sparse CHECKOUT only — all objects stay in the CAS; no partial clone, no transport/store change (spec).
- `.sc/sparse` is local, uncommitted, atomic-write, one prefix per line; empty/absent = full materialization (today's default, unchanged) (spec).
- Prefix matching reuses P7's `matching_prefix` boundary rule (path == prefix or under it at a `/` boundary — never a textual-prefix sibling) (spec).
- The carry predicate generalizes to: carry-if-absent AND (protected-and-not-a-recipient OR outside the sparse set); absent AND inside-sparse = genuine deletion (spec).
- Out-of-sparse conflict: report + refuse to auto-materialize, "widen your sparse set to resolve `<path>`"; `sc resolve` on an out-of-sparse path errors the same; `sc conflicts` still inspects via DAG-derived versions (spec).
- `sc ws` workspaces inherit the host's `.sc/sparse` (spec).
- No new dependencies; tests next to code, disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: `sparse` module — persist, load, match (+ `sc sparse show`, ROADMAP flip)

**Files:**
- Create: `crates/repo/src/sparse.rs`
- Modify: `crates/repo/src/lib.rs` (register + re-export), `crates/repo/src/layout.rs` (add the `.sc/sparse` path if paths are centralized there — check how `.sc/oplog` is pathed)
- Modify: `crates/cli/src/main.rs` (`Sparse` clap command with a `Show` subcommand only this task; `set`/`disable` land in Task 3)
- Modify: `ROADMAP.md` (flip P24 to Active; Next-horizon section — P24 is the LAST phase, so mirror the horizon-complete wording the prior horizon used at P20, or "None — the P21–P24 horizon completes at P24" — read the current Active/horizon shape and match)

**Interfaces (produced, consumed by Tasks 2–4):**
```rust
/// A repo's sparse-checkout spec: the prefixes that materialize to disk.
/// Empty = full materialization (no sparseness).
pub struct Sparse { prefixes: Vec<String> }
impl Sparse {
    pub fn is_full(&self) -> bool;                 // no prefixes → materialize everything
    pub fn matches(&self, path: &str) -> bool;     // is_full → true; else P7-boundary match
    pub fn prefixes(&self) -> &[String];
}
// module fns (pathed off Layout):
pub fn load(layout: &Layout) -> Result<Sparse>;    // absent file → empty Sparse
pub fn store(layout: &Layout, s: &Sparse) -> Result<()>;  // atomic write; empty → remove the file
pub fn clear(layout: &Layout) -> Result<()>;
impl Repo { pub fn sparse_spec(&self) -> Result<Sparse>; }  // thin wrapper
```

- [ ] **Step 1: ROADMAP flip.**
- [ ] **Step 2: Failing tests** (sparse.rs in-module): `matches_full_when_empty` (empty Sparse.matches(anything) == true, is_full()); `matches_at_path_boundary` (spec `["src/"]`: `src/main.rs`→true, `src`→true, `srcfoo.rs`→false, `docs/x`→false — mirror P7's `prefix_matches_only_at_path_boundary` test); `store_load_round_trip` (store `["src/","docs/"]`, load equals; store empty removes the file and load→empty); `store_empty_removes_file` (tmp_root idiom, assert the `.sc/sparse` path is gone). Match logic: `is_full() || self.prefixes.iter().any(|p| <matching_prefix boundary check for p over path>)` — extract or reuse P7's boundary predicate (grep `matching_prefix` in protect.rs; the bare-form + `/`-boundary check).
- [ ] **Step 3: Implement** module + `Repo::sparse_spec`. CLI: `Sparse { #[command(subcommand)] op: SparseOp }`, `SparseOp::Show` → print prefixes one per line (or "sparse: disabled (full checkout)" when empty); `--json`. Dispatch it.
- [ ] **Step 4: Run** `cargo test -p scl-repo sparse` + `cargo test` → green. **Step 5: Commit** — `git commit -am "feat(repo,cli): .sc/sparse prefix spec + sc sparse show — persist/load/match, P7-boundary prefixes (P24)"`

---

### Task 2: The carry-predicate generalization (dormant until Task 3)

**Files:**
- Modify: `crates/repo/src/repo.rs` (the carry block starting ~line 333 in the plain/non-merge `commit` path, and the analogous carry in `snapshot_files`/completion assembly if it has its own — grep `carry` and read every carry site)

**Interfaces:**
- Consumes: Task 1's `Repo::sparse_spec` / `Sparse::matches`.
- Produces: no new public API; a widened internal carry predicate. After this task, an out-of-sparse absent path is carried verbatim from the tip — but since nothing materializes sparsely yet (Task 3), the only way to exercise it is a directly-written `.sc/sparse` spec, which the tests do.

- [ ] **Step 1: READ the full carry block first** (repo.rs ~325–420 and any sibling in `snapshot_files`). Write down, in the report, the exact current predicate that decides "carry this absent path forward" vs "treat as deleted." Today it is roughly: an absent path is carried iff it is still-protected under the landing rules (the committer may be a non-recipient). Confirm the precise condition before changing it.
- [ ] **Step 2: Failing tests** (repo.rs tests; `tmp_root`; write the sparse spec directly via `sparse::store` to exercise the predicate without needing Task 3's materialize):
  - `commit_carries_out_of_sparse_absent_path_verbatim`: repo with `src/a.txt` + `docs/b.txt` committed; write sparse spec `["src/"]`; DELETE `docs/b.txt` from disk (simulating it never being materialized); edit `src/a.txt`; `commit`; assert the new snapshot's tree still contains `docs/b.txt` with the SAME blob id as before (byte-identical carry), and `src/a.txt` has the edit.
  - `commit_treats_in_sparse_absent_path_as_deletion`: sparse `["src/"]`; delete `src/a.txt` (INSIDE sparse) from disk; commit; assert `src/a.txt` is GONE from the new snapshot (genuine deletion — inside-sparse absence is real).
  - `carry_composes_protected_and_sparse`: a protected path outside the sparse set, absent from disk, committed by a non-recipient → carried (both reasons apply); and a protected path INSIDE the sparse set absent from disk → still carried (protected reason alone, unchanged P15 behavior).
  - `no_sparse_spec_behaves_exactly_as_before`: empty sparse spec; delete a plain file; commit → it IS deleted (full-checkout default unchanged — this is the regression guard that the widening is dormant when sparse is off).
- [ ] **Step 3: Implement** the predicate widening: an absent HEAD-tracked path is carried iff `(still-protected-and-not-a-recipient) OR (!sparse.matches(path))`. Keep the carry SOURCE logic (decided tree → tip) unchanged; only the include-in-carry condition widens. Load `sparse_spec()` once at the top of the carry block.
- [ ] **Step 4: Run** `cargo test -p scl-repo` → green (every existing commit/merge test MUST stay green — the widening is a no-op when sparse is empty; if any breaks, the predicate widened too far). **Step 5: Commit** — `git commit -am "feat(repo): commit carries absent out-of-sparse paths verbatim — the P15 carry predicate generalized (P24)"`

---

### Task 3: Materialize + working-tree readers honor sparse; `sc sparse set/disable`

**Files:**
- Modify: `crates/repo/src/worktree.rs` (`materialize` filters target entries by a sparse predicate; `read_worktree`/`diff_worktree` already skip absent files, so confirm they need no change beyond not RE-materializing out-of-sparse — trace)
- Modify: `crates/repo/src/repo.rs` (`switch`/`sparse set`/`sparse disable` pass the spec into materialize; `set_sparse`/`disable_sparse` methods)
- Modify: `crates/cli/src/main.rs` (`SparseOp::Set { prefixes: Vec<String> }`, `SparseOp::Disable`)

**Interfaces:**
```rust
// worktree::materialize gains a sparse filter — simplest: a new param
pub fn materialize(layout, store, target_root, old_root, protection, identity, sparse: &Sparse) -> Result<Vec<String>>;
// (update ALL existing callers to pass the repo's spec, or Sparse::default()/full where a caller has no repo spec — grep callers: switch, merge materialize, rebase abort, ws fork's materialize_workspace, etc. A full Sparse is the safe default that preserves today's behavior.)
impl Repo {
    pub fn set_sparse(&self, prefixes: &[String], identity: Option<&scl_crypto::SecretKey>) -> Result<()>; // store + re-materialize
    pub fn disable_sparse(&self, identity: Option<&scl_crypto::SecretKey>) -> Result<()>;                  // clear + re-materialize full
}
```

- [ ] **Step 1: Failing tests** (repo.rs tests):
  - `set_sparse_materializes_only_the_subset`: commit `src/a.txt`+`docs/b.txt`; `set_sparse(["src/"], None)`; assert `src/a.txt` on disk, `docs/b.txt` NOT on disk, `.sc/sparse` persisted.
  - `disable_sparse_rematerializes_fully`: after the above, `disable_sparse(None)`; both files on disk; `.sc/sparse` gone.
  - `switch_honors_persisted_sparse`: set sparse `["src/"]`, branch + switch away and back; only `src/` materializes each time (the spec persists across switch).
  - `sparse_roundtrip_commit_then_full_clone_sees_all` (integration): set sparse, edit in-sparse, commit; a FULL checkout (disable or a fresh clone) shows the out-of-sparse subtree byte-identical — the end-to-end guarantee.
- [ ] **Step 2: Implement.** `materialize`: after computing `target` entries, filter to `sparse.matches(path)` for BOTH the write loop AND the old-root removal loop (don't delete an out-of-sparse file that isn't there anyway; and DON'T remove in-CAS entries — materialize only touches disk). `set_sparse`: `sparse::store` then materialize `head_tip`'s root with the new spec and `old_root = None` (full clean re-lay per the new view — or old_root = current head root to prune now-excluded files; choose and justify: `old_root = head root` prunes newly-excluded files from disk correctly). `disable_sparse`: `sparse::clear` then materialize full. CLI wires `Set`/`Disable` (identity via `resolve_identity_opt` for protected in-sparse decryption).
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test` → green (all existing materialize callers updated; switch/merge/ws tests undisturbed). **Step 4: Commit** — `git commit -am "feat(repo,cli): materialize honors the sparse spec; sc sparse set/disable re-lay the working tree (P24)"`

---

### Task 4: Interactions — conflict widen-hint, resolve gating, sparse-aware status, ws inherit

**Files:**
- Modify: `crates/repo/src/repo.rs`/`replay.rs` (merge/pick/rebase materialize of a CONFLICTED out-of-sparse path → the widen error instead of writing markers outside the spec)
- Modify: `crates/repo/src/conflicts.rs` (`resolve_path`: if the path is out-of-sparse, error with the widen hint — inspection via `conflict_versions` still works)
- Modify: `crates/cli/src/main.rs` (`run_status` prints the sparse spec line)
- Modify: `crates/repo/src/ws.rs` (fork copies `.sc/sparse` into each workspace checkout; materialize_workspace honors it)

**Interfaces:** Consumes Tasks 1–3.

- [ ] **Step 1: Failing tests:**
  - `merge_clean_out_of_sparse_change_lands`: sparse `["src/"]`; a branch changes only `docs/x` (clean, no conflict); merge → lands in the CAS, `docs/x` NOT on disk, new snapshot has the change. (Proves clean out-of-sparse merges need no materialization — the P15 tree-id path.)
  - `merge_conflict_out_of_sparse_reports_widen_hint`: sparse `["src/"]`; both sides conflict on `docs/x`; merge → error/conflict-state whose message names `docs/x` and says to widen the sparse set; NO markers written to disk outside src/.
  - `resolve_out_of_sparse_path_errors_widen`: with such a conflict, `resolve_path("docs/x", ...)` → error with the widen hint; but `conflict_versions("docs/x", ..)` still returns the versions (inspection works).
  - `ws_fork_inherits_sparse`: host repo sparse `["src/"]`; `ws_fork`; the workspace checkout has `src/` but not `docs/`; harvest carries `docs/` verbatim.
  - `status_shows_sparse_spec`: sparse set → `sc status` (repo-level or the status accessor) reports the active prefixes; absent out-of-sparse subtree NOT listed as deletions.
- [ ] **Step 2: Implement.** The conflict-materialization helper (P21's single `materialize_conflict_state`) is the choke point: before writing a marker/sidecar for a conflicted path, check `sparse.matches(path)`; if not, collect it into a "needs-widen" list and, after processing, return `Error::InvalidArgument("conflict in <path> is outside your sparse checkout; run `sc sparse set` to include it, then retry")` (or a typed `SparseConflictOutsideView` variant if cleaner — check error.rs conventions) WITHOUT having written any out-of-sparse marker. Clean (non-conflict) out-of-sparse changes already land via the tree-id path — confirm they don't route through disk materialization. `resolve_path`: `if !self.sparse_spec()?.matches(path) { return Err(widen) }` before writing. `run_status`: after the existing sections, `sparse: <prefixes>` when non-empty. `ws_fork`: copy `.sc/sparse` into the workspace's `.sc/` (or thread the spec into `materialize_workspace`).
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test` → green. **Step 4: Commit** — `git commit -am "feat(repo,cli): out-of-sparse conflicts report a widen hint; resolve gates on the spec; status shows it; ws inherits it (P24)"`

---

### Task 5: Demo + docs + horizon close-out

**Files:**
- Create: `demo/run_sparse_demo.sh` (mode 755)
- Modify: `docs/adr/0034-sparse-checkouts.md` (→ Accepted + refinements, code-verified — nine phases of precision precedent; carry-predicate exact wording, where materialize filters, the widen-error site), `docs/adr/README.md` (0034 → Accepted), `ROADMAP.md` (P24 → Done + BOTH narrative bullet AND completed-phases row — the P22 missing-bullet lesson; Active → "None — the P21–P24 horizon is complete; brainstorm the next horizon"; remove the now-empty Next-horizon section), `CLAUDE.md` (commands: `sc sparse set/show/disable`, demo line; a `**Phase 24 is built.**` paragraph)

- [ ] **Step 1: Demo** (house style; separate invocations; case-based assertions; identities outside the tree if the protected variant is included). Sequence: init a repo with `src/` and `docs/` and `lib/` subtrees, each with a file; commit; `sc sparse set src/`; assert (via `find`) `docs/` and `lib/` are ABSENT from disk while `src/` is present; `sc sparse show` lists `src/`; edit `src/a.txt`, `sc commit`; clone the repo full (or `sc sparse disable`) and assert `docs/`/`lib/` files are byte-identical to the pre-sparse content (the carry guarantee) AND the `src/` edit is present; `sc sparse disable` → all three subtrees back on disk. Zero-residue trap. Run twice.
- [ ] **Step 2: Docs** (P23-completion commit shape; refinements: the exact widened carry predicate + its site, materialize's dual-loop filter, the widen-error variant/site, ws inheritance mechanism).
- [ ] **Step 3: Full verification** — `cargo test && bash demo/run_sparse_demo.sh && bash demo/run_history_demo.sh && bash demo/run_protected_merge_demo.sh && bash demo/run_ws_demo.sh && git diff main -- '*Cargo.toml'` (all green — history/protected-merge/ws are the regression gates that sparse didn't disturb full-checkout behavior; empty dep diff; run_protect_demo.sh pre-P8 failure known, skip).
- [ ] **Step 4: Commit** — `git commit -am "docs+demo: accept ADR-0034 sparse checkouts; P21–P24 horizon complete (P24)"`
