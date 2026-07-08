# P23 — Merge Ergonomics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc conflicts` / `sc resolve --ours|--theirs` / marker-aware `sc status` over one DAG-derived conflict-version abstraction — resolve conflicts without hand-editing markers (spec: `docs/superpowers/specs/2026-07-08-p23-merge-ergonomics-design.md`, ADR-0033).

**Architecture:** A new `crates/repo/src/conflicts.rs` owns `conflict_versions(path) → {base, ours, theirs}`, dispatching on the active in-progress op (merge/pick/rebase-stop) to resolve three snapshot ids and pull the path's blob (decrypting protected via P15's `decrypt_with` under `--identity`). `sc resolve` writes the chosen side to the working file, drops sidecars, and drops the path from the active op's `<STATE>_CONFLICTS` record. Merge detection and completion (`sc commit` / `sc rebase --continue`) are untouched.

**Tech Stack:** Rust stable, existing crates, no new dependencies.

## Global Constraints

- Merge SEMANTICS, conflict detection, and completion are UNCHANGED — this is a presentation + resolution layer only (spec).
- `conflict_versions` re-derives from the DAG, NOT parsed from markers (spec).
- resolve DECRYPTS the chosen side for protected paths; it NEVER re-encrypts — re-encryption stays at completion via the commit path, so plaintext never enters the CAS at resolve time (spec, P15 discipline).
- Active-op precedence: merge, then pick, then rebase (the same order `sc status` uses) (spec).
- A path absent on a side yields `(absent)`, not an error (spec).
- Protected version without `--identity` → `ProtectedMergeNeedsIdentity` (spec, reused from P15).
- Whole-file-per-side only; only `--ours`/`--theirs` (no hunk/union/base modes) (spec).
- Tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: `conflicts` module — the version abstraction (+ ROADMAP flip)

**Files:**
- Create: `crates/repo/src/conflicts.rs`
- Modify: `crates/repo/src/lib.rs` (register `pub(crate) mod conflicts;` + re-export the public types)
- Modify: `ROADMAP.md` (flip P23 to Active; horizon table → P24; mirror the P22 flip)

**Interfaces (produced, consumed by Tasks 2–3):**

```rust
/// Which in-progress operation owns the current conflicts.
pub enum ActiveOp { Merge, Pick, Rebase }
/// One side's content for a path, or that the path is absent there.
pub enum Side { Present(Vec<u8>), Absent }
pub struct ConflictVersions { pub base: Side, pub ours: Side, pub theirs: Side }
/// Classification for display and to decide whether --identity is needed.
pub enum ConflictKind { Text, Binary, Protected }

impl Repo {
    /// The active in-progress op, by the status precedence (merge→pick→rebase),
    /// or None if none is in progress.
    pub fn active_conflict_op(&self) -> Result<Option<ActiveOp>>;
    /// The conflicted paths recorded for the active op (its <STATE>_CONFLICTS).
    pub fn active_conflicts(&self) -> Result<Vec<String>>;
    /// Classify a conflicted path (PROTECTED perms on either tip → Protected;
    /// else non-UTF8 ours/theirs content → Binary; else Text).
    pub fn conflict_kind(&self, path: &str) -> Result<ConflictKind>;
    /// base/ours/theirs for `path` under the active op. Protected paths
    /// require `identity` (else Error::ProtectedMergeNeedsIdentity(path)).
    pub fn conflict_versions(&self, path: &str, identity: Option<&scl_crypto::SecretKey>) -> Result<ConflictVersions>;
}
```

- [ ] **Step 1: ROADMAP flip** (Active names P23 + spec path; horizon table → "Next horizon (P24)").
- [ ] **Step 2: Failing tests** (conflicts.rs in-module; `tmp_root` idiom; build a repo with a real conflicted merge/pick/rebase per the setups in `replay.rs`/`repo.rs` merge tests — read those first). Required tests:
  - `active_op_precedence_and_none`: no op → None; write merge state → Merge; (pick/rebase similarly via their state modules).
  - `versions_from_merge`: main & other edit `a.txt` divergently from a common base; `sc merge` conflicts; `conflict_versions("a.txt", None)` returns base = the common-ancestor content, ours = main's, theirs = other's (assert exact bytes).
  - `versions_from_pick` and `versions_from_rebase_stop`: same shape, driving a conflicted `cherry_pick` and a stopped `rebase`; assert theirs/base track PICK_HEAD / the conflicted commit + its parent, ours tracks the branch tip / `acc_tip`.
  - `absent_side_is_absent`: a path added on one side only (add/delete conflict) → the missing side is `Side::Absent`.
  - `protected_needs_identity_then_decrypts`: a protected-path content conflict → `conflict_versions(path, None)` is `Err(ProtectedMergeNeedsIdentity)`; with the right identity, returns the decrypted plaintext of each side.
  - `kind_classification`: text path → Text; a non-UTF8 (binary) conflict → Binary; a protected path → Protected.
- [ ] **Step 3: Implement.** `active_conflict_op` = the merge/pick/rebase in-progress checks in status order. For each op derive `(ours_tip, theirs_id, base_id)` per the spec table:
  - merge: ours = `head_tip()`, theirs = `merge_state::read_merge_head`, base = `merge::merge_base(ours, theirs)`.
  - pick: theirs = `pick_state::read_pick_head`, base = that commit's first parent (`snapshot(theirs).parents[0]`); ours = `head_tip()`.
  - rebase: `let st = rebase_state::read()?`; ours = `st.acc_tip`, theirs = `st.conflicted`, base = `snapshot(st.conflicted).parents[0]`.
  Then `side_for(path, snapshot_id, identity)`: look up the path in that snapshot's tree (`worktree::tree_file_entries_with_perms` gives id+perms); absent → `Side::Absent`; PROTECTED perms → `decrypt_with` (needs identity, propagate `ProtectedMergeNeedsIdentity`); else load the blob bytes → `Side::Present`. `conflict_kind`: PROTECTED on the tip → Protected; else fetch ours/theirs bytes (None identity is fine — non-protected) and `std::str::from_utf8().is_err()` on either → Binary; else Text.
- [ ] **Step 4: Run** `cargo test -p scl-repo conflicts` then `cargo test` → green. **Step 5: Commit** — `git commit -am "feat(repo): conflict_versions — DAG-derived base/ours/theirs per active op, protected via decrypt_with (P23)"`

---

### Task 2: `Repo::resolve_path` — write a side, drop the record

**Files:**
- Modify: `crates/repo/src/conflicts.rs` (add `resolve_path` + the record-drop helper)
- Modify: each state module IF a `remove one path from <STATE>_CONFLICTS` helper doesn't exist — check `merge_state`/`pick_state`/`rebase_state`; they have `read_conflicts`/`write_conflicts` (rebase) or equivalents. Add `pub fn set_conflicts(layout, &[String])` where only `write` exists, mirroring `rebase_state::write_conflicts`.

**Interfaces:**
```rust
pub enum ResolveSide { Ours, Theirs }
impl Repo {
    /// Resolve one conflicted path to `side`: write that side's content to the
    /// working file (or delete the file if the side is Absent), remove any
    /// `.theirs`/`.base`/`.ours` sidecar, and drop `path` from the active op's
    /// conflict record. Protected paths need `identity` (decrypt only — never
    /// re-encrypts; completion's commit path does that). Errors if `path` is
    /// not currently conflicted or no op is in progress.
    pub fn resolve_path(&self, path: &str, side: ResolveSide, identity: Option<&scl_crypto::SecretKey>) -> Result<()>;
}
```

- [ ] **Step 1: Failing tests:**
  - `resolve_ours_writes_clean_and_drops_record` (merge): conflict on `a.txt`; `resolve_path("a.txt", Ours, None)`; working file == ours bytes (no `<<<<<<<`); `active_conflicts()` no longer lists `a.txt`.
  - `resolve_theirs_across_pick_and_rebase`: same for a conflicted pick and a stopped rebase, `--theirs`.
  - `resolve_absent_side_deletes_file`: add/delete conflict; resolving to the Absent side removes the working file and drops the record.
  - `resolve_removes_theirs_sidecar`: a binary conflict wrote `x.bin.theirs`; after resolve, the sidecar is gone.
  - `resolve_protected_needs_identity`: protected conflict, `resolve_path(.., None)` → `ProtectedMergeNeedsIdentity`; with identity, working file holds the decrypted chosen-side plaintext.
  - `resolved_merge_completes_via_commit`: conflict on one path, `resolve_path(Ours)`, then `repo.commit(...)` succeeds and the tip contains ours content — proving the completion path is untouched and a resolve-cleared merge commits. (If `commit` has a no-markers gate, this proves resolve satisfies it; if not, it proves the working-tree content is what lands.)
  - `resolve_nonconflicted_or_no_op_errors`.
- [ ] **Step 2: Implement.** Get `conflict_versions(path, identity)`; pick the `side`; if `Side::Absent` delete the working file (via the same path-join safety `worktree` uses — reuse `worktree::safe_join`/materialize's write helper, do NOT hand-roll path joins), else write bytes to `layout`-relative working path. Remove sidecars `{path}.theirs`, `{path}.base`, `{path}.ours` if present. Drop `path` from the record: read the active op's conflicts, retain != path, write back via that op's setter (atomic). All under the repo lock (resolve is a repo method; confirm it holds the lock like other mutating methods).
- [ ] **Step 3: Run** `cargo test -p scl-repo` → green. **Step 4: Commit** — `git commit -am "feat(repo): resolve_path — write a chosen side to the working tree, drop sidecars + the conflict record (P23)"`

---

### Task 3: CLI — `sc conflicts`, `sc resolve`, marker-aware `sc status`

**Files:**
- Modify: `crates/cli/src/main.rs` (new `Conflicts` and `Resolve` clap commands + dispatch; enrich `run_status`)

**Interfaces:**
- Consumes: Tasks 1–2 (`active_conflicts`, `conflict_kind`, `conflict_versions`, `resolve_path`, the enums).

- [ ] **Step 1: `sc conflicts`.**
```rust
/// List conflicts for the in-progress operation, or show one path's versions.
Conflicts {
    /// A path to show base/ours/theirs for; omit to list all conflicts.
    path: Option<String>,
    /// Identity for protected-path decryption.
    #[arg(long)] identity: Option<PathBuf>,
    #[arg(long)] json: bool,
},
```
`run_conflicts`: no op in progress → print "no conflicts (no merge/pick/rebase in progress)" and return Ok. No path: for each `active_conflicts()` path print `<path>  [<kind>]` (kind lower-cased; protected paths append " (needs --identity)"); `--json` emits `[{path, kind}]`. With a path: `conflict_versions(path, identity)`; print a three-section `--- base ---`/`--- ours ---`/`--- theirs ---` view, each section the bytes as UTF-8 (or `<binary N bytes>` when non-UTF8), `(absent)` for `Side::Absent`. Identity resolution: reuse `resolve_identity_opt` (the encryption-half loader).
- [ ] **Step 2: `sc resolve`.**
```rust
/// Resolve conflicted paths to one side without editing markers.
Resolve {
    #[arg(long, conflicts_with = "theirs")] ours: bool,
    #[arg(long)] theirs: bool,
    #[arg(required = true)] paths: Vec<String>,
    #[arg(long)] identity: Option<PathBuf>,
},
```
`run_resolve`: exactly one of `--ours`/`--theirs` (bail if neither/both — clap `conflicts_with` handles both; add the neither check). For each path call `resolve_path`; collect failures and report per-path but continue (a bad path shouldn't abort the good ones — print `resolved <path> (<side>)` / `error <path>: <e>`), exit 1 if any failed. After the loop, if `active_conflicts()` is now empty, print the completion hint for the active op (`run 'sc commit'` for merge/pick, `'sc rebase --continue'` for rebase).
- [ ] **Step 3: marker-aware status.** In `run_status` (~1224), under each in-progress banner, replace the bare list with per-path detail: for each `active_conflicts()` path, `  <path>  [<kind>]` + the protected note. Keep `--json` in sync (add a `conflicts: [{path, kind}]` array to the status JSON). Do NOT change the banner lines themselves (P19/P21 tests assert them).
- [ ] **Step 4: Run** `cargo test -p scl-cli` + `cargo test` → green (existing status/merge tests must be undisturbed). **Step 5: Commit** — `git commit -am "feat(cli): sc conflicts + sc resolve + per-path conflict detail in status (P23)"`

---

### Task 4: Demo + docs

**Files:**
- Create: `demo/run_merge_ergonomics_demo.sh` (mode 755)
- Modify: `docs/adr/0033-merge-ergonomics.md` (→ Accepted + refinements, code-verified), `docs/adr/README.md` (0033 → Accepted), `ROADMAP.md` (P23 → Done + table row; Active → "None — Phase 24 is next up"; horizon table P24), `CLAUDE.md` (commands: `sc conflicts`, `sc resolve`, demo line; a `**Phase 23 is built.**` paragraph)

- [ ] **Step 1: Demo.** House style (read `demo/run_history_demo.sh` first; case-based assertions for multiline output; `fail()`; trap; single build; separate invocations). Sequence: init; branch; divergent edits to a shared text file on main + branch so `sc merge` conflicts (exit 1); `sc conflicts` lists the path `[text]`; `sc conflicts <path>` shows base/ours/theirs sections (assert each section header present and the ours/theirs bytes differ); `sc resolve --theirs <path>` → assert working file == theirs content and contains NO `<<<<<<<`; `sc status` shows no remaining conflicts; `sc commit -m resolved` completes; `sc log` shows the merge commit. THEN a protected variant: protect a prefix for alice, create a content conflict on a protected file, `sc resolve --theirs <path> --identity alice.key` resolves it, `sc commit` completes, and a `sc conflicts <path> --identity` earlier showed decrypted plaintext. Identities OUTSIDE the working tree (P5 scanner). Run twice.
- [ ] **Step 2: Docs** (P22-completion commit shape; refinement candidates: where the version derivation landed, the absent-side handling, whether commit had a no-markers gate that resolve had to satisfy, sidecar-name set removed).
- [ ] **Step 3: Full verification** — `cargo test && bash demo/run_merge_ergonomics_demo.sh && bash demo/run_history_demo.sh && bash demo/run_protected_merge_demo.sh && git diff main -- '*Cargo.toml'` (all green; empty dep diff; the history + protected-merge demos are the semantics-unchanged regression gates; run_protect_demo.sh pre-P8 failure known — skip).
- [ ] **Step 4: Commit** — `git commit -am "docs+demo: accept ADR-0033 merge ergonomics; sc conflicts/resolve demo (P23)"`
