# P20 — Agent Sessions + Auto-Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc ws fork/list/run/harvest/abandon` — durable multi-invocation agent sessions under `.sc/ws/`, with clean workspace results auto-merging cumulatively onto the session's base branch (spec: `docs/superpowers/specs/2026-07-07-p20-agent-sessions-design.md`, ADR-0030).

**Architecture:** A new `crates/repo/src/ws.rs` owns the session: an atomic `session.toml` manifest + durable checkout dirs (`.sc/ws/<i>/`) that ARE the workspace state. Fork materializes from the tip (P7-aware); run mirrors P13's env/secrets plumbing; harvest reuses P13's `harvest_workspace` per dir, then probes each candidate with the read-only `merge::three_way` seam — clean lands via the standard `merge_with_identity` path (one oplog record each), conflicted keeps its `work-<i>` branch untouched-elsewhere. gc roots the base snapshot gated on manifest presence.

**Tech Stack:** Rust stable, existing crates only, no new dependencies.

## Global Constraints

- One unnamed session per repo; `fork` refuses if one exists (spec).
- The manifest never stores key material (spec).
- **No conflict markers written anywhere unattended**: the conflict probe must be read-only; a conflicted candidate leaves the landing branch AND the user's working tree untouched (spec).
- Clean landings are cumulative (ascending index; each merge sees the previous) with ONE oplog record per landing, individually undoable (spec).
- Conflict fallback keeps a flat `work-<i>` branch, collision-suffixed (`work-<i>-2`, …), never clobbering (spec).
- Session end (all harvested/abandoned) removes `.sc/ws/` entirely — zero residue; a partial harvest leaves the session open (spec).
- Harvest is a ref-mover: refuses during merge/pick/rebase in progress (P19 guard family). Fork/list/run/abandon are NOT guarded beyond the repo lock (spec).
- gc roots the session base snapshot (SNAPSHOT root) gated on manifest presence — the P15/P19 state-gating discipline (spec).
- `abandon` writes no oplog record (nothing moved) (spec).
- `sc work` (P13) behavior unchanged; `harvest_workspace` reused, not reimplemented (spec).
- Tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: `ws` session module — manifest, fork, list, abandon (+ gc root, CLI)

**Files:**
- Create: `crates/repo/src/ws.rs`
- Modify: `crates/repo/src/lib.rs` (register `pub(crate) mod ws;` + re-export the public types below)
- Modify: `crates/repo/src/gc.rs` (`roots`: base snapshot as SNAPSHOT root, gated on manifest — after the rebase block, same shape)
- Modify: `crates/cli/src/main.rs` (new `Ws { op: WsOp }` command; `WsOp::{Fork, List, Abandon}` this task)
- Modify: `ROADMAP.md` (flip P20 to Active; the "Next horizon" section is now empty — replace the table with a sentence: "P20 is the last phase of this horizon; a new horizon gets brainstormed at its completion." Mirror prior flips otherwise.)

**Interfaces:**
- Produces (in `scl_repo` via `ws.rs`):

```rust
/// One workspace's manifest entry.
pub struct WsEntry {
    pub index: u32,
    pub dir: PathBuf,          // .sc/ws/<i>/ absolute
    pub live: bool,            // false once harvested/abandoned
}
/// The session manifest (.sc/ws/session.toml). Never stores key material.
pub struct WsSession {
    pub base_snapshot: ObjectId,
    pub base_branch: String,
    pub author: String,
    pub workspaces: Vec<WsEntry>,
}
impl Repo {
    pub fn ws_fork(&self, agents: u32, author: &str, identity: Option<&scl_crypto::SecretKey>) -> Result<WsSession>;
    pub fn ws_session(&self) -> Result<Option<WsSession>>;              // list
    pub fn ws_changed(&self, entry: &WsEntry) -> Result<bool>;          // dirty vs base (diff_worktree)
    pub fn ws_abandon(&self, index: Option<u32>) -> Result<usize>;      // returns remaining live count
}
```

Manifest storage: TOML via the same hand-rolled k=v style the repo uses elsewhere OR `toml` (already a cli dep — NOT a repo dep; check `crates/repo/Cargo.toml`. If `toml` isn't already in repo's tree, use the line-oriented format of `rebase_state.rs` — no new dependencies is binding). Atomic write via the same helper `refs`/`rebase_state` use.

- [ ] **Step 1: ROADMAP flip** (as above).
- [ ] **Step 2: Failing tests** (in `ws.rs`; `tmp_root` idiom): `fork_creates_session_and_checkouts` (fork 2 → manifest exists, 2 dirs each containing the tip's files, base_snapshot == tip, refused second fork with InvalidArgument naming the session); `session_survives_process_boundary` (fork, drop repo, reopen, ws_session → Some with same entries; ws_changed false; edit a file in dir 1 → ws_changed true); `abandon_one_and_all` (abandon(Some(1)) → dir gone, entry.live false, session still open; abandon(None) → .sc/ws/ GONE entirely, ws_session → None); `manifest_never_stores_key_material` (fork with identity → read the manifest file text, assert no "scl-sk" substring); `gc_roots_ws_base_snapshot` (mirror gc.rs's rebase-root test: base snapshot survives `gc --prune-expire 0` while manifest exists; after abandon-all it may be pruned — assert both directions if the second half is cheap).
- [ ] **Step 3: Implement.** Fork: guard on existing manifest; read current branch + tip (Unborn error if none); create `.sc/ws/<i>/` dirs; materialize each via the SAME call `workspace.rs::work` uses for its temp checkouts (find it — `worktree::materialize` with the tip's root/protection/identity, into a `Layout::at(dir)`); write manifest last (atomic). List/changed: read manifest; changed = `worktree::diff_worktree(&Layout::at(dir), store, Some(base.root), &base.protection)` non-empty (exactly `harvest_workspace`'s check — extract or repeat the 5 lines, your judgment, but if repeating say so in a comment). Abandon: remove dir(s), rewrite manifest (or delete `.sc/ws/` when the last goes); no oplog. gc: after the rebase-state block in `roots()`, `if let Some(s) = ws::read_manifest(layout)? { out.push(s.base_snapshot); }` (adapt to the actual collection names).
- [ ] **Step 4: CLI.** `Ws { #[command(subcommand)] op: WsOp }`; `WsOp::Fork { #[arg(long)] agents: u32, #[arg(long)] identity: Option<PathBuf>, #[arg(long)] author: Option<String> }` → prints per-workspace dirs; `WsOp::List` → index, dir, changed/unchanged, plus base branch/snapshot header; `WsOp::Abandon { index: Option<u32> }` → prints what was dropped + remaining. Author resolution: the same helper `run_commit` uses.
- [ ] **Step 5: Run** `cargo test -p scl-repo ws` then `cargo test` → green.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(repo,cli): sc ws fork/list/abandon — durable checkout-dir sessions under .sc/ws with gc-rooted base (P20)"`

---

### Task 2: `sc ws run` — P13 env/secrets parity

**Files:**
- Modify: `crates/repo/src/ws.rs` (`pub fn ws_run`)
- Modify: `crates/cli/src/main.rs` (`WsOp::Run`)

**Interfaces:**
- Consumes: Task 1's `WsSession`/`WsEntry`; P13's env + secret-injection mechanics — read `workspace.rs`'s run block (~line 230, the `.env("SC_WORKSPACE", label)` region) and the `--with-secrets` path before writing anything; reuse the same building blocks (`run_with_secret`-family / whatever `work` uses), do not re-derive.
- Produces: `Repo::ws_run(&self, index: u32, cmd: &[String], with_secrets: bool, identity: Option<&scl_crypto::SecretKey>) -> Result<i32>` (child exit code).

- [ ] **Step 1: Failing tests**: `ws_run_sets_env_and_cwd` (fork 1; ws_run(1, ["sh","-c","echo $SC_WORKSPACE > env.txt; pwd > cwd.txt"]) → files inside the workspace dir contain "ws-1" (match P13's label format — check what SC_WORKSPACE holds there and mirror) and the dir path; exit code 0 returned); `ws_run_with_secrets_injects` (secret add; ws_run with with_secrets+identity; child echoes the env var named after the secret → value present — mirror P13's secret-env test); `ws_run_bad_index_errors`.
- [ ] **Step 2: Implement** — spawn in `entry.dir` with the env pair set; secrets injection through the same path `work --with-secrets` uses. Exit code passthrough (CLI exits with it, `drop(repo)` before `process::exit` — the `run_run` lock-leak pattern).
- [ ] **Step 3: Run** targeted + workspace tests → green. **Commit**: `git add -A && git commit -m "feat(repo,cli): sc ws run — per-workspace command execution with P13 env/secret parity (P20)"`

---

### Task 3: `sc ws harvest` — cumulative auto-merge with read-only conflict probe

**Files:**
- Modify: `crates/repo/src/ws.rs` (`pub fn ws_harvest`, the probe)
- Modify: `crates/repo/src/refs.rs` (`pub fn delete_branch(layout, name) -> Result<()>` — check first whether one exists; if not, add: remove the branch file, error NoSuchBranch if absent, refuse deleting the current branch)
- Modify: `crates/repo/src/workspace.rs` (only if needed: `harvest_workspace` is `pub(crate)` and already fits — signature `(repo, tip, dir, branch, author, message)`; do NOT change its behavior)
- Modify: `crates/cli/src/main.rs` (`WsOp::Harvest { into: Option<String>, identity: Option<PathBuf>, author: Option<String> }`)

**Interfaces:**
- Consumes: `merge::{merge_base, three_way, is_ancestor}` (merge.rs:17/38/122 — `three_way` computes `MergeResult`/`FileMerge` with `conflicts: Vec<String>` WITHOUT touching the working tree), `merge::merge_secrets` (merge.rs:450), `Repo::merge_with_identity(branch, author, identity) -> Result<(ObjectId, Vec<String>)>` (repo.rs:804), `harvest_workspace`, Task 1's session API.
- Produces:

```rust
pub enum WsHarvestOutcome {
    Landed { index: u32, merged_tip: ObjectId },
    FallbackBranch { index: u32, branch: String },
    Unchanged { index: u32 },
    Rejected { index: u32, report: String }, // P5 scanner (mirror HarvestResult::Rejected's payload type)
}
pub fn ws_harvest(&self, into: Option<&str>, author: &str, identity: Option<&scl_crypto::SecretKey>) -> Result<Vec<WsHarvestOutcome>>;
```

- [ ] **Step 1: Failing tests** (full bodies; model repo/branch setup on workspace.rs's P13 tests; every listed assertion must appear):

```rust
#[test]
fn harvest_lands_clean_results_cumulatively() {
    // fork 2 from main; ws-1 edits a.txt, ws-2 edits b.txt (disjoint).
    // harvest → both Landed, IN ORDER; main's tip contains BOTH edits;
    // exactly 2 new oplog records (one per landing); sc undo reverts ONLY
    // the second landing (a.txt edit still present, b.txt edit gone);
    // no work-1/work-2 branches remain; .sc/ws GONE (session ended).
}
#[test]
fn harvest_conflict_falls_back_without_touching_anything() {
    // fork 2; ws-1 clean edit on a.txt; ws-2 edits x.txt; ALSO commit a
    // conflicting x.txt change to main after fork (so ws-2's merge conflicts).
    // harvest → [Landed(1), FallbackBranch(2, "work-2")]; main tip contains
    // ws-1's edit and NOT ws-2's; work-2 branch exists with ws-2's commit;
    // NO conflict markers anywhere: main's working tree files contain no
    // "<<<<<<<" and merge_state::in_progress is false; session ended.
}
#[test]
fn harvest_requires_landing_branch_checked_out() {
    // fork from main, switch to other, harvest → InvalidArgument naming the
    // landing branch and suggesting sc switch; session still open; nothing moved.
}
#[test]
fn harvest_respects_into_and_collision_suffix() {
    // pre-create branch "work-2"; force ws-2 to conflict as above; harvest
    // → fallback branch is "work-2-2". --into with the checked-out branch
    // name behaves as default; --into a non-checked-out branch errors.
}
#[test]
fn harvest_guards_and_dirty_tree() {
    // (a) write pick state → harvest → PickInProgress (repeat for merge/rebase);
    // (b) dirty user working tree → harvest of a changed workspace →
    //     InvalidArgument (the merge path's dirty refusal), session intact.
}
#[test]
fn harvest_partial_leaves_session_open() {
    // fork 2; ws-1 changed, ws-2 conflicts→fallback... both resolve; instead:
    // make ws-2's harvest hit the scanner (plaintext secret) → Rejected;
    // ws-2 stays LIVE (rejected ≠ resolved: the agent must fix the file),
    // session still open with ws-2 only; fixing the file then re-harvesting
    // completes and ends the session.
}
```

DESIGN DECISION encoded in the last test (also record it in the spec as an as-shipped precision note at Task 5): a scanner-Rejected workspace stays live so the offending file can be fixed in place — P13 treated rejection as a terminal outcome for the one-shot session; a durable session can do better. If implementation reveals this conflicts with `harvest_workspace`'s contract, surface it in your report rather than silently choosing.

- [ ] **Step 2: Implement the probe.**

```rust
/// Read-only conflict probe: would merging `theirs` into `ours` land clean?
/// Composes the same primitives the real merge uses (three_way + merge_secrets)
/// but touches neither the working tree nor any ref — this is what guarantees
/// "no conflict markers land unattended" (ADR-0030). Identity/authorization
/// shortfalls on protected paths count as NOT clean (fallback), not errors.
fn would_merge_cleanly(&self, ours: ObjectId, theirs: ObjectId, identity: Option<&scl_crypto::SecretKey>) -> Result<bool> {
    let store_arc = self.vfs().store();
    let mut store = store_arc.lock().unwrap();
    if crate::merge::is_ancestor(&mut store, theirs, ours)? { return Ok(true); } // nothing to add → ff-ish no-op
    if crate::merge::is_ancestor(&mut store, ours, theirs)? { return Ok(true); } // pure ff
    let Some(base) = crate::merge::merge_base(&mut store, ours, theirs)? else { return Ok(false) };
    // Mirror merge_with_identity's argument assembly for three_way EXACTLY
    // (read repo.rs:804+ first): same protections, same identity threading.
    match crate::merge::three_way(&mut store, base, ours, theirs, /* …mirror… */) {
        Ok(m) if !m.conflicts.is_empty() => Ok(false),
        Ok(_) => {
            // Secrets can conflict independently of files.
            match crate::merge::merge_secrets(/* mirror the real call: base/ours/theirs registries */) {
                Ok(_) => Ok(true),
                Err(Error::SecretMergeConflict(_)) => Ok(false),
                Err(e) => Err(e),
            }
        }
        Err(Error::ProtectedMergeNeedsIdentity(_)) | Err(Error::NotAuthorized(_)) => Ok(false),
        Err(e) => Err(e),
    }
}
```

(The `/* …mirror… */` holes are deliberate: `three_way`/`merge_secrets`'s exact parameter lists must be copied from the real merge call sites, not guessed here — copy them, keeping identity threading identical. Everything else in this function is binding as written, including the error mapping.)

- [ ] **Step 3: Implement `ws_harvest`.** Guards (merge/pick/rebase in progress → typed errors). Resolve landing branch: `into.unwrap_or(&session.base_branch)`; REQUIRE it to be the currently-checked-out branch (`refs::current_branch`), else `InvalidArgument("landing branch '{b}' is not checked out; run `sc switch {b}` first")` — the merge machinery is head-centric, and reusing it whole is the point (record as spec precision note in Task 5). Then per live workspace ascending:
  1. `ws_changed`? No → `Unchanged`, tear down dir, mark resolved.
  2. Pick fallback branch name: `work-<i>`, suffix `-2`, `-3`… while `refs::resolve_tip` finds an existing one.
  3. `harvest_workspace(self, session.base_snapshot_tip…, &dir_layout_path, &branch, author, &format!("ws-{i} harvest"))` — NOTE: pass `tip = session.base_snapshot` (the candidate's parent is the session base, exactly P13's contract). `Rejected(report)` → outcome `Rejected`, workspace STAYS live, branch not created, continue.
  4. `Committed(id)` → probe `would_merge_cleanly(current_tip, id, identity)`:
     - clean → `let (merged, conflicts) = self.merge_with_identity(&branch, author, identity)?;` assert `conflicts.is_empty()` (the probe promised; if not, `Error::Internal`-style bail — a probe/merge disagreement is a bug, fail loudly, nothing torn down); then `refs::delete_branch(&self.layout, &branch)?` (the candidate ref served its purpose); outcome `Landed`; tear down dir, mark resolved. (`merge_with_identity` wrote its own oplog record — that IS the per-landing record.)
     - not clean → keep the branch; outcome `FallbackBranch`; tear down dir, mark resolved.
  5. Rewrite manifest after each workspace (crash mid-harvest loses nothing: resolved ones are torn down + recorded, live ones intact).
  End: if no live workspaces remain, remove `.sc/ws/` entirely.
- [ ] **Step 4: CLI** — `run_ws_harvest` prints one line per outcome (landed → merged tip short id; fallback → branch name + "resolve with `sc merge <branch>`"; rejected → scanner summary + "fix and re-run `sc ws harvest`"); exits 1 if any Fallback/Rejected (scriptable), 0 otherwise; `drop(repo)` before exit.
- [ ] **Step 5: Run** all Task 3 tests + `cargo test` → green. **Commit**: `git add -A && git commit -m "feat(repo,cli): sc ws harvest — read-only conflict probe, cumulative base-branch landings, work-<i> fallback (P20)"`

---

### Task 4: Demo — `demo/run_ws_demo.sh`

**Files:**
- Create: `demo/run_ws_demo.sh` (mode 755)

- [ ] **Step 1: Write it.** House style (read `demo/run_work_demo.sh` + `run_history_demo.sh` first; case-based assertions for multiline output; `fail()`; trap; single build). Sequence, each step a SEPARATE `sc` invocation (that's the phase's point — use the built binary, not a long-running process): (1) init repo, seed commit; (2) `sc ws fork --agents 3`; (3) edit ws-1 and ws-2 dirs disjointly, edit ws-3 to conflict with a direct commit made to main after the fork; (4) `sc ws list` shows 3 workspaces, changed flags right; (5) `sc ws harvest` → assert two "landed" lines + one "fallback" line + exit 1; `sc log` shows both landings on main; no markers in the tree (`grep -rL "<<<<<<<"` style check on working files); (6) `sc undo` → last landing reverted; redo; (7) `sc merge work-3` manually → markers NOW appear (user-attended), resolve, commit; (8) assert `.sc/ws` does not exist; RESULT lines.
- [ ] **Step 2: Run twice** + `bash demo/run_work_demo.sh` once (P13 regression). **Commit**: `git add demo/run_ws_demo.sh && git commit -m "demo: multi-invocation ws session — cumulative auto-merge, conflict fallback, undo, zero residue (P20)"`

---

### Task 5: Docs — accept ADR-0030, ROADMAP horizon close-out, CLAUDE.md

**Files:**
- Modify: `docs/adr/0030-agent-sessions-and-automerge.md` (→ Accepted + build refinements, every claim code-verified; include the two as-shipped precision notes: landing-branch-must-be-checked-out, scanner-Rejected-stays-live) + spec gets matching bracketed notes
- Modify: `docs/adr/README.md` (0030 → Accepted)
- Modify: `ROADMAP.md` (P20 → Done + completed-phases row; Active → "None — the P16–P20 horizon is complete; brainstorm the next horizon"; remove the emptied Next-horizon section)
- Modify: `CLAUDE.md` (Commands: the five `sc ws` subcommands + demo line; a `**Phase 20 is built.**` paragraph; the "Remaining follow-ons" list drops interactive workspace sessions + auto-merge of clean workspace results; the P13 paragraph gets the "→ multi-invocation sessions in P20" transition note on its one-command-scope sentence)

- [ ] **Step 1: Edits** (follow the P19 completion commit's shape).
- [ ] **Step 2: Verification** — `cargo test && bash demo/run_ws_demo.sh && bash demo/run_work_demo.sh && bash demo/run_history_demo.sh && git diff main -- '*Cargo.toml'` (all green; empty dep diff; run_protect_demo.sh pre-P8 failure known, skip).
- [ ] **Step 3: Commit** — `git add -A && git commit -m "docs+demo: accept ADR-0030 agent sessions + auto-merge; P16–P20 horizon complete"`
