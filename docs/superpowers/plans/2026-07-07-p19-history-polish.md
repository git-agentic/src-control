# P19 — History-Editing Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc amend`, resumable rebase (stop-and-continue default, `--continue`/`--abort`), `sc cherry-pick --abort`, and `sc cherry-pick --mainline <N>` — all on the P14/P15 replay core (spec: `docs/superpowers/specs/2026-07-07-p19-history-polish-design.md`, ADR-0029).

**Architecture:** A new `crates/repo/src/rebase_state.rs` (mirroring `pick_state.rs`) persists a stopped rebase's progress; the rebase fold's `Conflicts` arm writes markers + state instead of erroring; `--continue` completes the conflicted commit via the pick-completion snapshot assembly extracted from `Repo::commit` (no ref move) and resumes the fold. `amend` reuses the plain-commit assembly with the tip's parents. `--mainline` threads a base override into `replay_commit`.

**Tech Stack:** Rust stable, existing crates only. No new dependencies. `crates/crypto`/`crates/core` untouched.

## Global Constraints

- Every ref-moving operation is oplog-recorded and undoable; the ref update remains the atomic commit point (spec).
- A stopped rebase does NOT move the branch ref; ONE oplog record covers the whole completed rebase (before = original tip), one `sc undo` reverts it all (spec).
- Identity key material is NEVER persisted in `.sc/` state (spec).
- `rebase_state::in_progress` joins the guard family: `commit`, `merge`, `cherry_pick`, `rebase`, `rewrap` all refuse with typed `Error::RebaseInProgress` (spec).
- `sc gc` roots the stopped rebase's accumulated tip (SNAPSHOT root) and its decided tree if any (TREE root), gated on state presence (spec).
- `cherry-pick --abort` writes NO oplog record — no ref moved; abort is its own inverse (spec).
- `--mainline <N>` is 1-indexed; on a non-merge commit it errors; a merge pick without it stays refused with a hint (spec).
- No second merge implementation — everything composes `replay_commit`/`three_way_files`/`merged_registry_for_replay`/pick-completion machinery (spec).
- Tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: `rebase_state` module, `RebaseInProgress` guard family, status, gc roots

**Files:**
- Create: `crates/repo/src/rebase_state.rs`
- Modify: `crates/repo/src/lib.rs` (register `pub(crate) mod rebase_state;` — match `pick_state`'s visibility)
- Modify: `crates/repo/src/error.rs` (new variant after `PickInProgress`)
- Modify: `crates/repo/src/repo.rs` (`commit` ~361, `merge`/`merge_with_identity` ~596/613, guards; new accessors beside `pick_in_progress` ~575)
- Modify: `crates/repo/src/replay.rs` (`cherry_pick` ~287, `rebase` ~532 guard blocks)
- Modify: `crates/repo/src/rewrap.rs` (guard block at top of `rewrap`)
- Modify: `crates/repo/src/gc.rs` (`roots` ~39–95)
- Modify: `crates/cli/src/main.rs` (`run_status` — print rebase-in-progress; find it via `grep -n "fn run_status" crates/cli/src/main.rs`)
- Modify: `ROADMAP.md` (flip P19 to Active; horizon table → P20 only — mirror the P18 flip)

**Interfaces:**
- Produces (`crate::rebase_state`, consumed by Task 2):

```rust
/// A stopped rebase's persisted progress. All ids are hex in the file;
/// identity key material is NEVER stored here (spec).
pub struct RebaseState {
    pub branch: String,             // the branch being rebased
    pub original_tip: ObjectId,     // for --abort and the final oplog record
    pub target: String,             // display only (messages)
    pub acc_tip: ObjectId,          // fold progress: last landed snapshot
    pub conflicted: ObjectId,       // the commit that stopped us
    pub remaining: Vec<ObjectId>,   // commits still to replay, oldest first
    pub total: usize,               // for "k of n" status
    pub author: String,
}
pub fn write(layout: &Layout, st: &RebaseState) -> Result<()>;
pub fn read(layout: &Layout) -> Result<Option<RebaseState>>;
pub fn in_progress(layout: &Layout) -> bool;
pub fn clear(layout: &Layout) -> Result<()>;
pub fn write_decided_root(layout: &Layout, tree: ObjectId) -> Result<()>;
pub fn read_decided_root(layout: &Layout) -> Result<Option<ObjectId>>;
pub fn write_conflicts(layout: &Layout, paths: &[String]) -> Result<()>;
pub fn read_conflicts(layout: &Layout) -> Result<Vec<String>>;
```

- Produces: `Error::RebaseInProgress` (thiserror message: `"a rebase is already in progress (resolve and \`sc rebase --continue\`, or \`sc rebase --abort\`)"`), `Repo::rebase_in_progress(&self) -> bool`, `Repo::rebase_progress(&self) -> Result<Option<(ObjectId, usize, usize)>>` (conflicted, done_count, total).

- [ ] **Step 1: Flip P19 to Active in ROADMAP.md** (mirror the P18 flip commit's shape; horizon table shrinks to P20).

- [ ] **Step 2: Write the module + failing tests.** Read `crates/repo/src/pick_state.rs` END TO END first — `rebase_state.rs` mirrors its file layout, atomic-write helper use, HEAD-gating of the decided root (P15's crash-residue discipline: the decided root is only honored while `REBASE_STATE` exists), and doc-comment voice. Storage: one `REBASE_STATE` file, line-oriented (`branch`, `original_tip`, `target`, `acc_tip`, `conflicted`, `total`, `author`, then remaining ids one per line — a simple `k=v` header block + id list; parse strictly, `Error::BadRef` on malformed), plus `REBASE_CONFLICTS` and `REBASE_DECIDED_ROOT` files matching pick_state's equivalents. Tests (in-module): round-trip write/read/clear; `in_progress` truthiness; malformed file errors; decided-root gated on state presence (read returns None after `clear` even if the file was left behind — copy pick_state's gating if present, else gate in `read_decided_root` by checking `in_progress`).

- [ ] **Step 3: Wire the guard family + accessors + status + gc, with tests**

- Guards: add to `Repo::commit`, `Repo::merge`/`merge_with_identity`, `Repo::cherry_pick`, `Repo::rebase`, `Repo::rewrap`:
```rust
if crate::rebase_state::in_progress(&self.layout) {
    return Err(Error::RebaseInProgress);
}
```
(and `cherry_pick`/`rebase`/`rewrap` keep their existing merge/pick guards — order: merge, pick, rebase checks together at the top).
- Accessors beside `pick_in_progress` (repo.rs ~575): `rebase_in_progress`, `rebase_progress` (reads state; done = total − remaining.len() − 1 conflicted… define precisely: `done = total - remaining.len() - 1`, display as "stopped at commit {conflicted.short()} ({done + 1} of {total})").
- gc (`gc.rs::roots`): after the pick block (~93), add — `acc_tip` is a SNAPSHOT root; the decided root is a TREE root (same handling as `MERGE_DECIDED_ROOT`, see reachable.rs:72):
```rust
if let Some(st) = rebase_state::read(layout)? {
    out.push(st.acc_tip); // snapshot root: the fold's landed progress
}
if let Some(tree) = rebase_state::read_decided_root(layout)? {
    tree_roots.push(tree);
}
```
(match the actual variable names in `roots` — snapshot roots vs tree roots are collected separately there.)
- CLI `run_status`: after the pick-in-progress print, add the rebase line using `rebase_progress()`: `rebase in progress: stopped at <short> (<k> of <n>); resolve conflicts then 'sc rebase --continue', or 'sc rebase --abort'`.
- Tests: guard pairwise — write a `RebaseState` directly via `rebase_state::write`, then assert `commit`/`merge`/`cherry_pick`/`rebase`/`rewrap` each return `Err(Error::RebaseInProgress)` (one test, five asserts, tmp_root idiom); gc test mirroring `gc_protects_pick_head_and_pick_decided_root` (gc.rs:267) proving a stopped-state `acc_tip` snapshot and decided tree survive `gc --prune-expire 0`.

- [ ] **Step 4: Run** — `cargo test -p scl-repo rebase_state` then `cargo test` → green.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(repo): rebase_state module + RebaseInProgress guard family, status and gc integration (P19)"`

---

### Task 2: Resumable rebase — stop on conflict, `--continue`, `--abort`

**Files:**
- Modify: `crates/repo/src/replay.rs` (the fold's `Conflicts` arm ~695; new `pub fn rebase_continue`, `pub fn rebase_abort`; extend `RebaseResult`)
- Modify: `crates/repo/src/repo.rs` (extract the pick-completion snapshot assembly from `commit` into a `pub(crate)` helper — see Step 1)
- Modify: `crates/cli/src/main.rs` (Rebase clap variant + dispatch)

**Interfaces:**
- Consumes: Task 1's `rebase_state` API; existing `replay_commit`, `merged_registry_for_replay`, `worktree::materialize`, `build_snapshot`, `oplog::record`.
- Produces: `RebaseResult::Stopped { conflicted: ObjectId, paths: Vec<String>, done: usize, total: usize }` (new variant); `Repo::rebase_continue(&self, author: &str, identity: Option<&scl_crypto::SecretKey>) -> Result<RebaseResult>`; `Repo::rebase_abort(&self) -> Result<()>`; `pub(crate) fn Repo::assemble_completion_snapshot(&self, parent: ObjectId, completed: ObjectId, decided_root: Option<ObjectId>, author: &str, message: &str) -> Result<ObjectId>`.

- [ ] **Step 1: Extract the completion assembly (behavior-preserving refactor, pinned by the existing suite).** In `Repo::commit` (repo.rs ~361–460), the pick-completion arm builds a single-parent snapshot from the resolved working tree: read-worktree → scanner gate on plain files → protected re-encryption under unioned rules → carry decided-root entries → merge the picked commit's registry → `commit_snapshot`. Extract that assembly (everything EXCEPT the branch-ref move and oplog record) into `assemble_completion_snapshot(parent, completed, decided_root, author, message)`; `commit`'s pick arm calls it then moves the ref exactly as before. Gate: `cargo test -p scl-repo` must stay green with ZERO test edits — if any test needs changing, the extraction changed behavior; stop and fix. Commit this step separately: `git commit -m "refactor(repo): extract pick-completion snapshot assembly (no behavior change) — P19 groundwork"`.

- [ ] **Step 2: Write the failing integration tests** (replay.rs tests module, tmp_root idiom; helpers: build a repo where branch `feat` has 2–3 commits touching the same file as a diverged `main` so specific commits conflict):

```rust
#[test]
fn rebase_stops_on_conflict_and_continue_completes() {
    // main and feat diverge; feat's FIRST commit conflicts, second doesn't.
    // rebase → Stopped (refs untouched, markers present, status reports);
    // resolve; rebase_continue → Completed; branch ref moved ONCE; exactly
    // one oplog record for the rebase; one undo restores original tip.
}
#[test]
fn rebase_multi_stop_resumes_twice() { /* two conflicting commits: Stopped, continue, Stopped again, continue, Completed; still one oplog record */ }
#[test]
fn rebase_abort_restores_byte_identical_tree_and_refs() { /* stop, dirty the tree further, abort → working tree files byte-equal pre-rebase, branch tip unchanged, state files gone, no oplog record */ }
#[test]
fn rebase_continue_without_state_errors() { /* Error::InvalidArgument mentioning "no rebase in progress" */ }
#[test]
fn stopped_rebase_survives_process_boundary() { /* stop; drop(repo); reopen; rebase_progress reports; continue works */ }
```

Write these as REAL tests with full setup/assertions — model the divergence setup on the existing `rebase_*` tests in replay.rs (read them first; reuse their file-writing + branch/switch idioms). The comments above are the required assertions, not the test bodies. Every assertion listed must appear.

- [ ] **Step 3: Implement the stop.** In the fold's `Conflicts` arm (replay.rs ~695), replace the `return Err(RebaseConflicts…)` with the stop sequence — the same conflict-materialization the conflicted cherry-pick path performs (find it in `cherry_pick`'s `Conflicts` arm and reuse its marker-writing + decided-root persistence verbatim, pointed at the rebase state files instead of pick's):

```rust
ReplayOutcome::Conflicts { paths, decided_root } => {
    // Stop, don't abort (P19/ADR-0029): persist the fold's progress and put
    // P4 markers in the working tree. The branch ref does NOT move — the
    // atomic commit point stays at final completion.
    // (reuse the pick-conflict materialization here: markers + sidecars for
    //  `paths`, decided_root persisted via rebase_state::write_decided_root)
    let done = total - remaining_after_current.len() - 1;
    crate::rebase_state::write(&self.layout, &crate::rebase_state::RebaseState {
        branch: head.clone(),
        original_tip: ours_tip,
        target: target.to_string(),
        acc_tip,
        conflicted: commit,
        remaining: remaining_after_current,
        total,
        author: author.to_string(),
    })?;
    crate::rebase_state::write_conflicts(&self.layout, &paths)?;
    return Ok(RebaseResult::Stopped { conflicted: commit, paths, done, total });
}
```

Adapt the exact variable names to the fold (`range` must be tracked so `remaining_after_current` = commits after the conflicted one; `total = range.len()`). CHECK whether `ReplayOutcome::Conflicts` carries a decided root today (grep its definition ~replay.rs:52–70) — if it does, persist it; if the pick path computes it separately, mirror that computation. NOTE: the fold's pre-materialization dirty check already ran at rebase start; the conflict markers go into the CURRENT working tree exactly as a conflicted pick's do.

- [ ] **Step 4: Implement `rebase_continue` + `rebase_abort`.**

```rust
/// Resume a stopped rebase: complete the conflicted commit from the resolved
/// working tree (single parent = the fold's acc_tip; the extracted
/// pick-completion assembly), then keep folding the remaining commits.
/// Stops again on the next conflict. Completion moves the branch ref ONCE and
/// writes ONE oplog record for the whole rebase (before = original tip).
pub fn rebase_continue(
    &self,
    author: &str,
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<RebaseResult> {
    let Some(st) = crate::rebase_state::read(&self.layout)? else {
        return Err(Error::InvalidArgument(
            "no rebase in progress — nothing to continue".into(),
        ));
    };
    // 1. Complete the conflicted commit from the (resolved) working tree.
    let decided = crate::rebase_state::read_decided_root(&self.layout)?;
    let completed_msg = self.snapshot(&st.conflicted)?.message;
    let new_tip = self.assemble_completion_snapshot(
        st.acc_tip, st.conflicted, decided, author, &completed_msg,
    )?;
    crate::rebase_state::clear(&self.layout)?; // conflict resolved; fold resumes
    // 2. Resume the fold over st.remaining — factor the fold body from
    //    `rebase` into a shared fn so both call it (fold(acc_tip=new_tip,
    //    remaining, …)); on a new conflict it re-writes state (st.total
    //    preserved) and returns Stopped; on completion it materializes,
    //    moves the ref, and records ONE oplog entry with
    //    before = st.original_tip.
    self.rebase_fold_and_finish(st.branch, st.original_tip, st.target, new_tip, st.remaining, st.total, author, identity)
}

/// Abandon a stopped rebase: clear state and re-materialize the untouched
/// original tip. No oplog record — no ref ever moved.
pub fn rebase_abort(&self) -> Result<()> {
    let Some(st) = crate::rebase_state::read(&self.layout)? else {
        return Err(Error::InvalidArgument("no rebase in progress — nothing to abort".into()));
    };
    let snap = self.snapshot(&st.original_tip)?;
    {
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        // None for `from`: the tree carries conflict markers/sidecars that a
        // diff-based materialize could miss — do a full clean materialize.
        crate::worktree::materialize(&self.layout, &mut store, snap.root, None, &snap.protection, None)?;
    }
    crate::rebase_state::clear(&self.layout)
}
```

Refactor requirement embedded above: pull the fold loop + completion tail (materialize → `write_branch_tip` → `oplog::record`) out of `rebase` into `fn rebase_fold_and_finish(&self, head, original_tip, target, acc_tip, range, total, author, identity) -> Result<RebaseResult>` so `rebase` and `rebase_continue` share it — the oplog record's `before` MUST be the passed `original_tip`, not the current ref (that's what makes multi-stop = one record). `rebase` itself: compute range, then call the shared fold with `original_tip = ours_tip`, `total = range.len()`. Materialize-on-abort passes `identity: None` — protected files a keyless user can't decrypt are skipped exactly as `switch` does (consistent with P7 checkout semantics; the sidecar cleanup mirrors what `merge_abort` does — read `merge_abort` (repo.rs ~905) and reuse its stale-marker cleanup approach).

- [ ] **Step 5: CLI.** Rebase variant becomes:

```rust
Rebase {
    /// Branch/ref to replay the current branch onto.
    target: Option<String>,
    /// Resume a stopped rebase after resolving conflicts.
    #[arg(long, conflicts_with = "target")]
    r#continue: bool,
    /// Abandon a stopped rebase; restores the pre-rebase working tree.
    #[arg(long, conflicts_with_all = ["target", "continue"])]
    abort: bool,  // clap arg IDs drop the r# raw-identifier prefix
    /// Identity key to decrypt protected paths that diverged in content.
    #[arg(long)]
    identity: Option<PathBuf>,
},
```

Dispatch: exactly one of target/--continue/--abort (clap's conflicts + a "rebase needs a target, --continue, or --abort" bail when all absent). `Stopped` prints the conflicted paths + "resolve, then `sc rebase --continue`" and exits 1 (mirror how conflicted merge exits — check `run_merge`). Author resolution same helper as `run_merge`.

- [ ] **Step 6: Run all Task 2 tests + workspace** — `cargo test -p scl-repo rebase` then `cargo test` → green (RebaseConflicts error variant may now be dead — if so remove it AND its uses/tests, noting it in the commit message).
- [ ] **Step 7: Commit** — `git add -A && git commit -m "feat(repo,cli): resumable rebase — stop on conflict with persisted state, --continue resumes the fold, --abort restores; one oplog record per rebase (P19)"`

---

### Task 3: `sc amend`

**Files:**
- Modify: `crates/repo/src/repo.rs` (new `pub fn amend`)
- Modify: `crates/cli/src/main.rs` (new `Amend { message: Option<String> }` variant + `run_amend`)

**Interfaces:**
- Consumes: the plain-commit assembly inside `Repo::commit` (repo.rs ~361–460) — reuse its worktree-read/scanner/protected-encryption path; guards from Task 1.
- Produces: `Repo::amend(&self, author: &str, message: Option<&str>) -> Result<ObjectId>`.

- [ ] **Step 1: Failing tests** (repo.rs tests):

```rust
#[test]
fn amend_replaces_tip_preserving_parents_and_message() {
    // init, commit A, commit B; edit a file; amend with message: None
    // → new tip B' has B's parents (== [A]) and B's message; B is no longer
    // the branch tip; working-tree edit is IN B'; oplog has an "amend"
    // record; one undo restores B as tip.
}
#[test]
fn amend_with_message_overrides() { /* -m "new" → B'.message == "new" */ }
#[test]
fn amend_merge_commit_keeps_both_parents() { /* make a merge tip M (two parents), edit, amend → M' has the SAME two parents */ }
#[test]
fn amend_root_commit_keeps_empty_parents() { /* single initial commit, edit, amend → parents == [] */ }
#[test]
fn amend_refuses_unborn_and_in_progress_states() { /* unborn → Error::Unborn; then per state (merge_state/pick_state/rebase_state written directly) → the matching typed error */ }
#[test]
fn amend_runs_scanner_and_protection() { /* a plaintext secret in the tree → SecretDetected; a protected-path edit under a rule → new tip's blob is PROTECTED ciphertext wrapped for granted keys */ }
```

Full bodies required — model setup on neighboring commit/protect tests in the same module.

- [ ] **Step 2: Implement.**

```rust
/// Replace the tip commit with one built from the current working tree:
/// same parents as the tip (merge and root commits amend naturally),
/// message kept unless `message` overrides. Full commit pipeline (scanner,
/// .scignore, protected re-encryption, registry carried). Oplog-recorded
/// ("amend"); one undo restores the old tip. No pushed-commit guard — sc
/// has no authoritative record of remote observers (ADR-0029).
pub fn amend(&self, author: &str, message: Option<&str>) -> Result<ObjectId> {
    if crate::merge_state::in_progress(&self.layout) { return Err(Error::MergeInProgress); }
    if crate::pick_state::in_progress(&self.layout) { return Err(Error::PickInProgress); }
    if crate::rebase_state::in_progress(&self.layout) { return Err(Error::RebaseInProgress); }
    let tip = self.head_tip()?.ok_or(Error::Unborn)?;
    let tip_snap = self.snapshot(&tip)?;
    let msg = message.map(|m| m.to_string()).unwrap_or_else(|| tip_snap.message.clone());
    // …plain-commit assembly (worktree read → scanner → protected encryption
    // under the TIP's rules → registry carried from tip) with
    // parents = tip_snap.parents …
    // then: head/before, commit_snapshot(root, tip_snap.parents, secrets, protection, author, &msg),
    // materialize is NOT needed (tree came FROM the working tree),
    // oplog::record(&self.layout, "amend", &head, &head, &[(head, before, Some(id))])
}
```

The assembly reuse is the engineering judgment of this task: `commit`'s plain path likely isn't a separable function yet. Either extract it (like Task 2's completion extraction — behavior-preserving, suite stays green with zero test edits, separate commit) or, if the plain path is small enough to parameterize by `parents`, add the parameter internally. DO NOT copy-paste the assembly into `amend` — one pipeline, two callers (CLAUDE.md: no second implementation of a gated path; the scanner/protection gates must be impossible to miss).

- [ ] **Step 3: CLI** — `Amend { #[arg(short, long)] message: Option<String> }`; `run_amend` prints `amended <old-short> -> <new-short>`.
- [ ] **Step 4: Run** — `cargo test -p scl-repo amend` then `cargo test` → green.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(repo,cli): sc amend — rebuild the tip from the working tree, parents preserved, full commit pipeline (P19)"`

---

### Task 4: `cherry-pick --abort` and `--mainline <N>`

**Files:**
- Modify: `crates/repo/src/replay.rs` (`cherry_pick` signature + `replay_commit` base override; new `pub fn cherry_pick_abort`)
- Modify: `crates/cli/src/main.rs` (CherryPick variant: `--abort`, `--mainline`)

**Interfaces:**
- Consumes: `pick_state::{read_pick_head, clear}`, `worktree::materialize`; `replay_commit` (replay.rs ~141).
- Produces: `Repo::cherry_pick_abort(&self) -> Result<()>`; `cherry_pick` gains `mainline: Option<u32>` parameter; `replay_commit` gains `base_override: Option<ObjectId>`.

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn cherry_pick_abort_restores_pre_pick_tree() {
    // conflicted pick (existing conflicted-pick test setup); then abort →
    // working tree byte-equal to pre-pick (incl. NO markers/sidecars),
    // PICK_HEAD/PICK_CONFLICTS/PICK_DECIDED_ROOT gone, branch tip unchanged,
    // oplog record count UNCHANGED by the abort.
}
#[test]
fn cherry_pick_abort_without_pick_errors() { /* InvalidArgument mentioning "no cherry-pick in progress" */ }
#[test]
fn mainline_pick_applies_delta_relative_to_chosen_parent() {
    // Build M = merge of A-side and B-side (each side adds its own file).
    // On a fresh branch from A-side: pick M --mainline 1 → lands B-side's
    // addition only; --mainline 2 → lands A-side's addition only.
}
#[test]
fn mainline_validation() { /* merge without --mainline → err whose message names --mainline; --mainline on non-merge → InvalidArgument; --mainline 3 on a 2-parent merge → InvalidArgument */ }
```

- [ ] **Step 2: Implement `cherry_pick_abort`** (mirror `rebase_abort`'s materialize-from-tip + `merge_abort`'s marker cleanup; then `pick_state::clear`). No oplog record — add the one-line comment saying why (spec: no ref moved; abort is its own inverse).

- [ ] **Step 3: Implement `--mainline`.** `replay_commit` today derives base = the replayed commit's first parent (see its body ~replay.rs:141–170) — add `base_override: Option<ObjectId>` used in place of that derivation when `Some`; all existing callers pass `None`. In `cherry_pick(refname, author, identity, mainline: Option<u32>)`: resolve the picked snapshot; if `parents.len() >= 2`: require `mainline` (else keep the existing `CannotReplayMerge` error, extending its thiserror text with `"; use --mainline <N> to pick relative to parent N"`), validate `1 <= N <= parents.len()`, pass `base_override = Some(parents[N-1])`. If `parents.len() < 2` and `mainline.is_some()`: `InvalidArgument("--mainline only applies to merge commits")`. The rebase fold keeps refusing merges (unchanged — assert the existing test still passes).

- [ ] **Step 4: CLI** — CherryPick gains `#[arg(long)] abort: bool` (conflicts_with refname — make refname `Option<String>`) and `#[arg(long)] mainline: Option<u32>`; dispatch accordingly; update the two existing `cherry_pick(` call sites' signatures (grep for them).
- [ ] **Step 5: Run** — `cargo test -p scl-repo` (pick + mainline tests) then `cargo test` → green.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(repo,cli): cherry-pick --abort and --mainline merge picks (P19)"`

---

### Task 5: Demo + docs

**Files:**
- Modify: `demo/run_history_demo.sh` (extend, don't rewrite)
- Modify: `docs/adr/0029-history-editing-polish.md` (→ Accepted + build refinements, every claim code-verified — three prior phases bounced imprecise prose)
- Modify: `docs/adr/README.md` (0029 → Accepted)
- Modify: `ROADMAP.md` (P19 → Done + table row; Active → "None — Phase 20 is next up"; horizon table P20 only)
- Modify: `CLAUDE.md` (Commands: `sc amend`, rebase `--continue/--abort`, cherry-pick `--abort/--mainline`; Phase-19 paragraph; P14 paragraph's atomic-rebase sentence gets the "→ resumable in P19" transition note; "Remaining follow-ons" drops amend/--continue/--abort/merge-commit replay)

- [ ] **Step 1: Extend the demo.** Read `demo/run_history_demo.sh` end to end; append (house assertion style, no pipes into `grep -q` on multiline output — use the `case`-based pattern from run_network_git_demo.sh if matching multi-line output): (a) an interrupted-and-resumed rebase — construct a conflicting commit, `sc rebase main` exits 1 and `sc status` reports the stop, resolve, `sc rebase --continue` completes, `sc oplog` shows ONE rebase record, `sc undo` restores the pre-rebase tip; (b) an aborted cherry-pick — conflicted pick, `sc cherry-pick --abort`, tree byte-identical (compare a checksum of the file before/after), no pick state; (c) an `sc amend` message fix showing `sc log` tip message changed with history length unchanged. Run it twice.
- [ ] **Step 2: Docs edits** (follow the P18 completion commit's shape — `git log --grep "accept ADR-0028"`).
- [ ] **Step 3: Full verification** — `cargo test && bash demo/run_history_demo.sh && bash demo/run_protected_merge_demo.sh && git diff main -- '*Cargo.toml'` (all green, empty dep diff; run_protect_demo.sh pre-P8 failure known, skip).
- [ ] **Step 4: Commit** — `git add -A && git commit -m "docs+demo: accept ADR-0029 history-editing polish; extended history demo covers stop/continue, pick abort, amend"`
