# P14 — History Editing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc cherry-pick <ref>`, `sc rebase <target>`, `sc undo`, and `sc oplog` — replay-based history editing with a repo-wide operation log as the safety net.

**Architecture:** Cherry-pick is a three-way merge with base = the picked commit's first parent; rebase folds that replay over a commit range atomically. Both build on P4's `three_way` core (a small extraction, `three_way_files`, decouples file merging from secret-registry merging). A line-oriented append-only `.sc/oplog` records every ref-moving operation's before/after; `sc undo` restores the last record's before-state and logs itself, so double-undo is redo. `sc gc` treats oplog-referenced ids as roots and trims records past the grace window.

**Tech Stack:** Rust stable, edition 2021. Zero new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-06-p14-history-editing-design.md` — read it first. The oplog record grammar, undo semantics, and rebase atomicity rules there are binding.

## Global Constraints

- Dependency direction `cli → repo → {vfs, gitio, crypto} → core` unchanged; new modules `replay.rs`, `oplog.rs`, `pick_state.rs` live in `crates/repo`. No new dependencies.
- **No object mutation:** every command only adds CAS objects and moves refs. No new object kinds; content addressing untouched.
- **Protected content fails closed:** replay refuses when any involved tree has `PROTECTED` entries — same guard as `Repo::merge` (see `crates/repo/src/repo.rs` ~line 540, the `MergeProtected` block).
- **No silent destruction:** dirty-tree refusals before any materialize; atomic rebase (refs move once or not at all); typed errors, never panics, on corrupt oplog tails.
- Crash ordering: **refs first, oplog last** — a torn op loses its undo record, never fabricates one.
- The oplog is local: `clone`/fetch/push/transport never copy it.
- Errors: `thiserror` variants in `crates/repo/src/error.rs`; CLI uses `anyhow`.
- Every public type/fn gets an intent-explaining doc comment. Disk tests clean up and assert the path is gone. `cargo test` green before every commit.

## Existing interfaces you will build on (verified against the code)

- `merge::three_way(store, base, ours, theirs) -> Result<Merge>` where `Merge { files: Vec<(String, FileMode, Vec<u8>)>, sidecars: Vec<(String, Vec<u8>)>, conflicts: Vec<String>, secrets: BTreeMap<String, ObjectId> }` (crates/repo/src/merge.rs:58-180)
- `merge::merge_base(store, a, b) -> Result<Option<ObjectId>>`, `merge::is_ancestor(store, anc, desc) -> Result<bool>`
- `merge_state::{in_progress, read_merge_head, read_conflicts, write, clear}` (crates/repo/src/merge_state.rs) — the pattern `pick_state.rs` mirrors
- `Repo::build_snapshot(root, parents, secrets, protection, author, message) -> Result<ObjectId>` (pub(crate), persists only), `Repo::snapshot(&id) -> Result<Snapshot>`, `Repo::commit`, `Repo::status`, `Repo::vfs()` (P13)
- `refs::{resolve_tip, read_branch_tip, write_branch_tip, list_heads, current_branch, write_head, head_tip}`; `layout.ref_path(branch)`
- `worktree::materialize(layout, store, target_root, old_root, protection, identity)`
- `gc::run(layout, store, grace)` with private `fn roots(layout)` (crates/repo/src/gc.rs:33-49)
- CLI helpers: `open_repo()`, `resolve_author`, `fmt_utc(ts)` (crates/cli/src/main.rs)
- Existing error variants you'll reuse: `Error::{Unborn, UpToDate, MergeInProgress, NoSuchBranch, InvalidArgument, NoCommonAncestor}`

---

### Task 1: Roadmap P14 entry + ADR-0024 (Proposed)

**Files:**
- Modify: `ROADMAP.md`
- Create: `docs/adr/0024-history-editing.md`

**Interfaces:**
- Consumes: the P14 spec. Produces: docs only; Task 11 flips the ADR to Accepted.

- [ ] **Step 1: Add the Active section to ROADMAP.md**

Insert after the `## Done` section (the P13 bullet is the last Done entry):

```markdown
## Active

- **Phase 14 — History editing (`sc cherry-pick` / `sc rebase` / `sc undo`).**
  The integration kit P13 made urgent: replay one commit onto the current
  branch (cherry-pick, with P4-style conflict resolution completed by the
  next commit), replay a whole branch onto a new base (rebase — atomic: any
  conflict aborts with refs untouched), and a repo-wide operation log making
  every ref-moving operation undoable (`sc undo`; run twice = redo). Replay
  is P4's three-way merge with base = the picked commit's parent — no second
  merge implementation, no object mutation, undo is just moving refs back.
  Protected content fails closed, inherited from P4's merge guard.
  Spec: `docs/superpowers/specs/2026-07-06-p14-history-editing-design.md`.
  (ADR-0024, Proposed.)
```

Add to the `## Deferred` list:

```markdown
- **History-editing follow-ons:** `sc amend`, stop-and-continue rebase
  (`--continue`), cherry-pick `--abort`, merge-commit replay (mainline
  selection), protected-path replay (lifts with P4's protected-merge
  follow-on), operation objects in the CAS (Jujutsu-deep upgrade to the
  file oplog), oplog entries for remote-tracking refs.
```

- [ ] **Step 2: Write ADR-0024 (Proposed)**

Create `docs/adr/0024-history-editing.md`, matching ADR-0023's header format (`Status`/`Date`/`Phase`/`Builds on`):

```markdown
# ADR-0024: History editing via replay + operation log

- **Status:** Proposed
- **Date:** 2026-07-06
- **Phase:** 14
- **Builds on:** ADR-0012 (three-way merge), ADR-0015 (gc), ADR-0023 (agent
  workspaces — the branch-proliferation workload)

## Context

Every `sc work` session mints N `work-<i>` branches; three-way merge is the
only integration tool. The snapshot model (ADR-0003) promises cheap, safe
history editing: objects are immutable, so "editing" is adding snapshots and
moving refs.

## Decision

- **Replay is merge.** Cherry-picking commit C onto tip T is
  diff3(base = C's first parent, ours = T, theirs = C), computed by the
  existing P4 machinery (`three_way_files`, extracted from `three_way`).
  Root commits use an empty base. Merge commits and protected content are
  refused (typed errors) — the latter inherits P4's fail-closed guard.
- **Cherry-pick resolves; rebase is atomic.** A conflicted pick writes P4
  markers plus `.sc/PICK_HEAD`; the next `sc commit` completes it
  single-parent. A conflicted rebase aborts wholesale with refs and working
  tree untouched.
- **One operation log, all operations.** Append-only `.sc/oplog` records
  HEAD and every touched local ref before/after each ref-moving operation.
  `sc undo` restores the last record's before-state and appends its own
  record, so undo-of-undo is redo. Local-only, like a reflog.
- **GC interplay:** oplog-referenced snapshot ids are reachability roots;
  gc trims records older than the prune-expire window (always keeping the
  most recent), bounding the root set.

## Alternatives considered

- Operations as CAS objects (op + view objects, jj-style time travel):
  format break for capability the file oplog already delivers; natural
  later upgrade.
- Git-style stop-and-continue rebase: a persisted multi-step state machine;
  atomic rebase + per-commit cherry-pick covers the workload, `--continue`
  can layer on later.
- Per-ref reflogs: wrong unit — undo works on operations, which move
  several refs.

## Consequences

- Undo never dangles: anything the oplog can restore is a gc root until the
  record is trimmed; past the horizon undo reports "nothing to undo".
- A torn operation (crash between ref write and oplog append) loses its
  undo record but never fabricates one (refs first, oplog last).
- Rebase abandons already-built snapshots on abort — ordinary gc fodder.
```

- [ ] **Step 3: Commit**

```bash
git add ROADMAP.md docs/adr/0024-history-editing.md
git commit -m "docs: roadmap P14 active — history editing; ADR-0024 proposed"
```

---

### Task 2: Extract `three_way_files` from `three_way`

Pure refactor. Replay needs file-level three-way merging with an *optional* base (root commits) and *without* secret-registry merging. `three_way`'s per-path loop becomes `three_way_files`; `three_way` keeps its exact signature and behavior.

**Files:**
- Modify: `crates/repo/src/merge.rs:58-180`

**Interfaces:**
- Produces (used by Task 7):
  - `pub struct FileMerge { pub files: Vec<(String, FileMode, Vec<u8>)>, pub sidecars: Vec<(String, Vec<u8>)>, pub conflicts: Vec<String> }`
  - `pub(crate) fn three_way_files(store: &mut Store, base_root: Option<ObjectId>, ours_root: ObjectId, theirs_root: ObjectId) -> Result<FileMerge>` — `base_root: None` means empty base (every base lookup misses).
- `merge::Merge` and `three_way` keep their exact public shapes.

- [ ] **Step 1: Green baseline**

Run: `cargo test -p scl-repo`
Expected: PASS (record the count).

- [ ] **Step 2: Extract**

In `crates/repo/src/merge.rs`, add above `Merge`:

```rust
/// File-level result of a three-way tree merge (no secret registries).
/// Extracted from [`three_way`] so replay (P14) can merge trees against an
/// optional base — a root commit replays against the empty tree.
pub struct FileMerge {
    pub files: Vec<(String, FileMode, Vec<u8>)>,
    pub sidecars: Vec<(String, Vec<u8>)>,
    pub conflicts: Vec<String>,
}

/// Three-way merge of file trees by root id. `base_root: None` is the empty
/// base: every path reads as absent on the base side.
pub(crate) fn three_way_files(
    store: &mut Store,
    base_root: Option<ObjectId>,
    ours_root: ObjectId,
    theirs_root: ObjectId,
) -> Result<FileMerge> {
    let base_f = match base_root {
        Some(r) => tree_file_entries(store, r)?,
        None => Default::default(),
    };
    let ours_f = tree_file_entries(store, ours_root)?;
    let theirs_f = tree_file_entries(store, theirs_root)?;
    // ... the existing per-path loop from `three_way`, moved verbatim
    // (paths union, blob-id fast paths, diff3 text merge, binary sidecars,
    // delete/modify conflicts) ...
    Ok(FileMerge { files, sidecars, conflicts })
}
```

Then `three_way` becomes: read the three snapshots, `merge_secrets`, call `three_way_files(store, Some(base_snap.root), ours_snap.root, theirs_snap.root)?`, and assemble `Merge { files: fm.files, sidecars: fm.sidecars, conflicts: fm.conflicts, secrets }`. The moved loop must be byte-identical logic — a pure move.

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: PASS, same count as baseline.

- [ ] **Step 4: Commit**

```bash
git add crates/repo/src/merge.rs
git commit -m "refactor(repo): extract three_way_files — replay needs tree merging with optional base, no secrets (P14)"
```

---

### Task 3: `oplog.rs` — record format, append, read, trim

**Files:**
- Create: `crates/repo/src/oplog.rs`
- Modify: `crates/repo/src/lib.rs` (add `pub mod oplog;` alphabetically — between `merge_state` and `protect`)
- Modify: `crates/repo/src/layout.rs` (add accessor `pub fn oplog_path(&self) -> PathBuf { self.dot_sc.join("oplog") }` next to the other path accessors)

**Interfaces:**
- Produces (used by Tasks 4-9):

```rust
/// One logged operation: HEAD and every touched local ref, before/after.
#[derive(Debug, Clone, PartialEq)]
pub struct OpRecord {
    pub seq: u64,
    pub ts: i64,
    pub desc: String,
    /// Symbolic HEAD branch name before/after (equal for most ops).
    pub head_before: String,
    pub head_after: String,
    /// (branch, before, after); None = absent (created/deleted).
    pub refs: Vec<(String, Option<ObjectId>, Option<ObjectId>)>,
}

pub(crate) fn record(layout: &Layout, desc: &str, head_before: &str, head_after: &str,
                     refs: &[(String, Option<ObjectId>, Option<ObjectId>)]) -> Result<()>
pub(crate) fn read_all(layout: &Layout) -> Result<Vec<OpRecord>>   // corrupt-tail tolerant
pub(crate) fn last(layout: &Layout) -> Result<Option<OpRecord>>
pub(crate) fn trim_older_than(layout: &Layout, cutoff_ts: i64) -> Result<usize>  // keeps >=1 newest
pub(crate) fn referenced_ids(layout: &Layout) -> Result<Vec<ObjectId>>  // all before/after ids
```

- [ ] **Step 1: Write the failing tests**

Create the module with tests first (temp-dir helpers per house convention — unique `sc-oplog-test-<tag>-<pid>` dir, cleanup + gone-assertion):

```rust
#[test]
fn record_and_read_round_trip() {
    // record two ops; read_all returns both in order with seq 1, 2;
    // last() returns the second; referenced_ids contains all non-None ids.
}

#[test]
fn corrupt_tail_is_tolerated_not_fatal() {
    // record one op, then append garbage bytes ("op x\nnot-a-record\n");
    // read_all returns the one good record; last() likewise; no panic.
}

#[test]
fn trim_keeps_newest_and_drops_old() {
    // three records with ts 100, 200, 300; trim_older_than(250) leaves
    // exactly the ts-300 record (seq preserved); trim_older_than(1000)
    // still leaves the newest one (never empties the log).
}

#[test]
fn absent_refs_serialize_as_dash() {
    // record with refs [("work-1", None, Some(id))]; read back yields
    // (name, None, Some(id)).
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo oplog`
Expected: FAIL — module/functions not found (after adding `pub mod oplog;`).

- [ ] **Step 3: Implement**

Format exactly as the spec pins (one block per op):

```
op <seq>
ts <unix-seconds>
desc <one line>
head <before-name> <after-name>
ref <name> <before-hex|-> <after-hex|->
end
```

Implementation notes:
- `record`: `seq = last(layout)?.map(|r| r.seq + 1).unwrap_or(1)`; `ts` via the same `unix_now()` pattern `repo.rs` uses (copy the helper call, don't duplicate the fn — it's in repo.rs; if private, add `pub(crate)` to it). Serialize the block to one `String`, then a single write with `OpenOptions::new().create(true).append(true)`.
- `read_all`: parse line-by-line; on any malformed block, stop and return what parsed so far (tolerant tail). `desc` is everything after `"desc "` on that line (desc must not contain `\n`; `record` asserts/strips newlines).
- `trim_older_than`: read_all, retain records with `ts >= cutoff`, always retain the last record even if old, rewrite the file atomically (write temp + rename — copy the `atomic_write` helper pattern from `refs.rs`).
- `referenced_ids`: flat-map every `Some` id in every record's refs.

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo oplog`
Expected: PASS (4 tests). Then `cargo test` — all green.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/oplog.rs crates/repo/src/lib.rs crates/repo/src/layout.rs
git commit -m "feat(repo): oplog — append-only operation log with corrupt-tail tolerance and trim (P14)"
```

---

### Task 4: Instrument existing operations with oplog records

Every existing ref-moving operation appends one record at its exit point. Refs are written first, oplog last (crash ordering, Global Constraints).

**Files:**
- Modify: `crates/repo/src/repo.rs` (`commit`, `merge` — adopt-unborn, ff, and clean-merge exits — `branch`, `switch_with_identity`)
- Modify: `crates/repo/src/workspace.rs` (`Repo::work` — one record for the session)
- Modify: `crates/repo/src/secrets.rs` + `crates/repo/src/protect_ops.rs` (each op that calls `commit_snapshot`: `secret_add`, `secret grant/revoke/rotate` methods, and the three protect_ops call sites — grep `commit_snapshot(` to enumerate)
- Test: each file's existing test module

**Interfaces:**
- Consumes: `oplog::record` (Task 3).
- Produces: the logging convention Tasks 5/8/9 follow — capture `head = refs::current_branch(&self.layout)?` and the touched refs' before-values at the top of the op; call `oplog::record` after the last ref write, before returning. Desc strings (exact):
  - commit: `commit: <first line of message>` — a merge-completing commit (merge_head present) uses `commit (merge): <msg>`; a pick-completing commit (Task 6 adds pick state) will use `commit (pick): <msg>`
  - merge: `merge <branch> (ff)` / `merge <branch> (adopt)` / `merge <branch>`
  - branch: `branch <name>`
  - switch: `switch <name>`
  - work: `work: <N> agents, base <base_name>` with one ref line per harvested branch (created: before `-`)
  - secrets/protect: `secret add <name>` / `secret grant <name>` / `secret revoke <name>` / `secret rotate <name>` / `protect <prefix>` / `grant <prefix>` / `revoke <prefix>`

- [ ] **Step 1: Write the failing tests**

One test per instrumented op family, in the file that owns it (representative shapes — adapt setup to each module's existing helpers):

```rust
#[test]
fn commit_appends_oplog_record() {
    // init repo, write file, commit; oplog::last is Some with
    // desc starting "commit: ", head_before == head_after == "main",
    // refs == [("main", None-or-prev, Some(new_tip))].
}

#[test]
fn merge_ff_and_clean_merge_append_records() {
    // build two branches; ff-merge one → desc "merge <b> (ff)";
    // real merge → desc "merge <b>", after == merge snapshot id.
    // A CONFLICTED merge appends NO record (no refs moved).
}

#[test]
fn branch_switch_and_work_append_records() {
    // branch: refs [(name, None, Some(tip))]; switch: head_before "main",
    // head_after "<name>", refs empty; work session: one record, one ref
    // line per harvested branch.
}

#[test]
fn secret_add_appends_record() {
    // secret_add moves the current branch → record desc "secret add <name>".
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo oplog_record` (name tests so a shared substring selects them)
Expected: FAIL — no records written yet.

- [ ] **Step 3: Instrument**

Pattern (illustrated on `commit`; repeat at each site):

```rust
pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
    let head = refs::current_branch(&self.layout)?;
    let before = refs::read_branch_tip(&self.layout, &head)?;
    let merging = crate::merge_state::read_merge_head(&self.layout)?.is_some();
    // ... existing body through the ref advance + merge_state::clear ...
    let label = if merging { "commit (merge)" } else { "commit" };
    let first_line = message.lines().next().unwrap_or("");
    crate::oplog::record(
        &self.layout,
        &format!("{label}: {first_line}"),
        &head, &head,
        &[(head.clone(), before, Some(id))],
    )?;
    Ok(id)
}
```

Site notes:
- `merge`: three success exits (adopt-unborn, ff, clean). The conflict exit moves no refs → no record. Capture `before` before any write.
- `switch_with_identity`: head changes, no branch refs move → `refs: &[]`, `head_before`/`head_after` differ.
- `branch`: `refs: [(name, None, Some(tip))]`, head unchanged.
- `work` (workspace.rs): collect `(label, None, Some(id))` for each `HarvestResult::Committed` outcome; skip the record entirely if no branch was created.
- secrets/protect ops: they advance the current branch via `commit_snapshot` — capture before/after around that call; head unchanged.
- **Do not instrument `commit_snapshot` itself** — it's called by multiple ops that own their own descriptions; instrumenting it would double-log.

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: PASS, including all pre-existing tests (instrumentation must not change any op's observable behavior or error paths).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src
git commit -m "feat(repo): oplog records for all existing ref-moving operations (P14)"
```

---

### Task 5: `Repo::undo` + CLI `sc undo` / `sc oplog`

**Files:**
- Modify: `crates/repo/src/oplog.rs` (add `Repo::undo` in an `impl Repo` block, plus `pub fn oplog(&self) -> Result<Vec<OpRecord>>` accessor; house style per `secrets.rs`/`workspace.rs`)
- Modify: `crates/repo/src/error.rs` (add `#[error("nothing to undo")] NothingToUndo`)
- Modify: `crates/repo/src/lib.rs` (`pub use oplog::OpRecord;`)
- Modify: `crates/cli/src/main.rs` (subcommands `Undo`, `Oplog` + handlers)
- Test: `crates/repo/src/oplog.rs` tests

**Interfaces:**
- Consumes: Tasks 3-4.
- Produces: `pub fn undo(&self) -> Result<String>` — returns the undone record's `desc` for display. Semantics (binding, from the spec):
  1. `oplog::last` or `Err(NothingToUndo)`.
  2. Refuse (`Error::MergeInProgress` / pick guard once Task 6 lands) while a merge is in progress.
  3. Compute whether the restore must re-materialize: `head_before != head_after`, or the record's refs move the tip of the branch that will be current after restore (`head_before`). If so: dirty check first (same modified/deleted check `merge` uses), and capture the current tip's root as `old_root`.
  4. Restore: for each `(name, before, _after)`: `Some(id)` → `write_branch_tip`; `None` → `remove_file(layout.ref_path(name))` (ignore NotFound). Then `write_head(&layout, &rec.head_before)` if it changed.
  5. Re-materialize if needed: target = restored current branch tip's root (unborn after restore → materialize nothing, but this only occurs for undo-of-first-commit; use `Option`), `materialize(layout, store, target_root, old_root, &snap.protection, None)`.
  6. Append the inverse record: desc `undo of op <seq>: <desc>`, head swapped, each ref `(name, after, before)`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn undo_commit_restores_ref_and_double_undo_redoes() {
    // commit twice; undo → branch tip back to first commit (read_branch_tip),
    // objects still in store; undo again → tip back to second commit.
}

#[test]
fn undo_branch_create_deletes_the_ref_file() {
    // branch("feature"); undo → read_branch_tip("feature") is None and
    // the ref file is gone.
}

#[test]
fn undo_switch_restores_head_and_working_tree() {
    // two branches with different content; switch; undo → HEAD name back,
    // working file content matches the original branch.
}

#[test]
fn undo_work_session_removes_all_harvested_branches() {
    // run a 2-agent work session (reuse workspace test helpers);
    // undo → both work-* branches gone, main untouched.
}

#[test]
fn undo_with_dirty_tree_refuses_when_rematerialize_needed() {
    // commit, edit a tracked file (dirty), undo (which would move the tip)
    // → Err(InvalidArgument); refs unchanged.
}

#[test]
fn undo_merge_and_secret_add_round_trip() {
    // clean two-branch merge; undo → tip back to pre-merge commit (the
    // merge snapshot stays in the CAS); redo → merge tip again.
    // secret_add (moves the current branch); undo → tip back, secret gone
    // from the registry at HEAD.
}

#[test]
fn undo_on_empty_log_is_typed_error() {
    // fresh repo, no ops → Err(NothingToUndo).
}

#[test]
fn clone_does_not_copy_the_oplog() {
    // repo with oplog records; sc clone (Repo-level clone API — find it in
    // crates/repo/src/sync.rs / remote.rs and check HOW it copies: if it
    // copies objects+refs selectively, this test just documents the
    // invariant; if it copies .sc wholesale, EXCLUDE the oplog file in the
    // clone path) → destination repo's oplog::read_all is empty and
    // undo there reports NothingToUndo.
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo undo` → FAIL (no `undo`).

- [ ] **Step 3: Implement `Repo::undo` per the semantics above**

Ordering note (crash safety, Global Constraints): the restore's ref writes happen first, the inverse oplog record last.

- [ ] **Step 4: CLI**

```rust
/// Revert the last operation (run again to redo).
Undo,
/// List recent operations, newest first.
Oplog,
```

Handlers:

```rust
fn run_undo() -> Result<()> {
    let desc = open_repo()?.undo()?;
    println!("undid: {desc}");
    Ok(())
}

fn run_oplog() -> Result<()> {
    let repo = open_repo()?;
    for rec in repo.oplog()?.iter().rev() {
        println!("{:>4}  {}  {}", rec.seq, fmt_utc(rec.ts), rec.desc);
    }
    Ok(())
}
```

- [ ] **Step 5: Run tests** — `cargo test` → all green.

- [ ] **Step 6: Commit**

```bash
git add crates/repo/src crates/cli/src/main.rs
git commit -m "feat: sc undo + sc oplog — restore the last operation's ref state; double-undo is redo (P14)"
```

---

### Task 6: Pick state — `pick_state.rs`, commit completion, guards

**Files:**
- Create: `crates/repo/src/pick_state.rs` (mirror `merge_state.rs`: files `.sc/PICK_HEAD` + `.sc/PICK_CONFLICTS`)
- Modify: `crates/repo/src/lib.rs` (`pub mod pick_state;`)
- Modify: `crates/repo/src/error.rs`:

```rust
#[error("a cherry-pick is already in progress (resolve the marked files then `sc commit`)")]
PickInProgress,
#[error("cherry-pick produced {0} conflict(s); resolve the marked files then `sc commit`")]
PickConflicts(usize),
```

- Modify: `crates/repo/src/repo.rs` — `commit` clears pick state on success (and logs `commit (pick): …` when pick state was present); `merge` and `switch_with_identity` refuse with `PickInProgress` when pick state exists; `Repo::undo` (oplog.rs) refuses likewise.
- Modify: `crates/cli/src/main.rs` — `run_status` prints `cherry-pick in progress: <short-id>` (mirror how it reports merge-in-progress today; read the existing handler first).
- Add `pub fn pick_in_progress(&self) -> bool` and `pub fn pick_head(&self) -> Result<Option<ObjectId>>` on `Repo`.

**Interfaces:**
- Produces (used by Task 8): `pick_state::{in_progress, read_pick_head, read_conflicts, write(layout, picked: &ObjectId, conflicts: &[String]), clear}` — same shapes as `merge_state`'s equivalents.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn pick_state_round_trip_and_clear() { /* write → read id+conflicts → clear → in_progress false, files gone */ }

#[test]
fn commit_clears_pick_state_and_is_single_parent() {
    // write pick state manually, edit a file, commit → snapshot has ONE
    // parent, pick state cleared, oplog desc starts "commit (pick):".
}

#[test]
fn merge_switch_and_undo_refuse_during_pick() {
    // write pick state; merge → Err(PickInProgress); switch → same;
    // undo → same.
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo pick_state` → FAIL.

- [ ] **Step 3: Implement** (copy `merge_state.rs` structure; the completion path in `commit` must NOT add a second parent — pick state is informational + a guard, unlike `MERGE_HEAD`).

- [ ] **Step 4: Run tests** — `cargo test` → all green (existing merge/switch tests unaffected: no pick state present in them).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src crates/cli/src/main.rs
git commit -m "feat(repo): pick state — PICK_HEAD sibling of merge state; commit completes single-parent (P14)"
```

---

### Task 7: `replay.rs` — the replay core

**Files:**
- Create: `crates/repo/src/replay.rs`
- Modify: `crates/repo/src/lib.rs` (`pub mod replay;`)
- Modify: `crates/repo/src/error.rs`:

```rust
#[error("cannot replay merge commit {0} (mainline selection not supported)")]
CannotReplayMerge(ObjectId),
#[error("replay of protected paths is not yet supported (would corrupt encrypted files): {0}")]
ReplayProtected(String),
```

**Interfaces:**
- Consumes: `merge::three_way_files` (Task 2), `Repo::snapshot`, `repo.vfs().write_tree`, `worktree::tree_file_entries_with_perms` (protected guard — same shape as `Repo::merge`'s guard at repo.rs ~540).
- Produces (used by Tasks 8-9):

```rust
/// Result of replaying one commit onto a target tree.
pub(crate) enum ReplayOutcome {
    /// Merged tree written to the CAS.
    Clean { root: ObjectId },
    /// Replayed tree equals the target — change already present.
    Empty,
    /// Conflicting paths, with the merged working set (markers included)
    /// and sidecars, ready to materialize.
    Conflicts {
        files: Vec<(String, scl_core::FileMode, Vec<u8>)>,
        sidecars: Vec<(String, Vec<u8>)>,
        paths: Vec<String>,
    },
}

pub(crate) fn replay_commit(repo: &Repo, commit_id: ObjectId, onto_root: ObjectId) -> Result<ReplayOutcome>
```

Semantics (binding): refuse 2+-parent commits (`CannotReplayMerge`); base = first parent's root, `None` for a root commit; protected guard over base/onto/theirs trees (`ReplayProtected`, message names the commit id) BEFORE merging; `three_way_files`; conflicts → `Conflicts`; else `write_tree` → root == onto_root ? `Empty` : `Clean`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn clean_replay_produces_merged_root() {
    // main: base commit; branch b edits file X; main separately edits Y.
    // replay b's commit onto main's root → Clean, and the tree contains
    // both edits (read blob back via tree_file_ids).
}

#[test]
fn conflicting_replay_reports_paths_with_markers() {
    // both sides edit the same lines of X → Conflicts, paths == ["X"],
    // marker bytes ("<<<<<<<") present in files' X entry.
}

#[test]
fn already_applied_replay_is_empty() {
    // replay a commit whose change the target already has → Empty.
}

#[test]
fn root_commit_replays_against_empty_base() {
    // pick the very first commit of another lineage onto a tip → Clean
    // (its files simply add).
}

#[test]
fn merge_commit_and_protected_content_are_refused() {
    // 2-parent commit → Err(CannotReplayMerge(id));
    // protect a path + commit (reuse protect test helpers) → replaying
    // any involved snapshot → Err(ReplayProtected(_)).
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo replay` → FAIL.

- [ ] **Step 3: Implement** per the semantics block above. The protected guard is a copy of the loop in `Repo::merge` (repo.rs ~540) over `[base?, onto, theirs]` roots using `tree_file_entries_with_perms` and `perms & scl_core::PROTECTED`.

- [ ] **Step 4: Run tests** — `cargo test` → green.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/replay.rs crates/repo/src/lib.rs crates/repo/src/error.rs
git commit -m "feat(repo): replay core — cherry-pick is three-way merge with the commit's parent as base (P14)"
```

---

### Task 8: `Repo::cherry_pick` + CLI `sc cherry-pick`

**Files:**
- Modify: `crates/repo/src/replay.rs` (add `impl Repo` block)
- Modify: `crates/repo/src/lib.rs` (`pub use replay::PickResult;`)
- Modify: `crates/cli/src/main.rs` (subcommand + handler)
- Test: `crates/repo/src/replay.rs` tests

**Interfaces:**
- Consumes: `replay_commit`, `pick_state` (Task 6), `build_snapshot`, `oplog::record`, `worktree::materialize`, the dirty-check pattern from `Repo::merge` (repo.rs:463-468).
- Produces:

```rust
pub enum PickResult {
    Picked(ObjectId),
    /// Change already present on the current branch — nothing committed.
    AlreadyApplied,
}

pub fn cherry_pick(&self, refname: &str, author: &str) -> Result<PickResult>
```

Flow (binding): preflight — merge/pick in progress → typed errors; born branch (`Unborn`); resolve ref (`NoSuchBranch`); dirty check (modified/deleted, same as merge). Then `replay_commit(self, picked_tip, ours_root)`:
- `Clean { root }` → `build_snapshot(root, vec![ours_tip], ours_snap.secrets, ours_snap.protection, author, &format!("{} (cherry-picked from {})", picked_msg_first_line, picked_id.short()))`; `write_branch_tip`; `materialize(new_root, Some(ours_root), &ours_snap.protection, None)`; oplog record desc `cherry-pick <refname>`; `Ok(Picked(id))`.
- `Empty` → `Ok(AlreadyApplied)`, no record.
- `Conflicts { files, sidecars, paths }` → build the marker tree (`vfs.write_tree`) and materialize it over `ours_root` (exact pattern of `Repo::merge`'s conflict path, repo.rs:560-578, including sidecar writes), `pick_state::write(&layout, &picked_tip, &paths)`, `Err(PickConflicts(paths.len()))`. No refs move, no oplog record.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn clean_pick_advances_branch_and_materializes() {
    // work-1 style branch with one commit; cherry_pick from main →
    // Picked(id); main tip == id; snapshot has single parent == old main
    // tip; message ends "(cherry-picked from <short>)"; the edited file is
    // on disk; oplog last desc == "cherry-pick work-1".
}

#[test]
fn conflicting_pick_writes_markers_and_state_moves_no_refs() {
    // conflicting branches → Err(PickConflicts(1)); main tip unchanged;
    // PICK_HEAD == picked id; on-disk file contains "<<<<<<<";
    // then resolve + commit → single-parent commit, state cleared.
}

#[test]
fn already_applied_pick_is_a_noop() {
    // merge the branch first, then cherry_pick it → AlreadyApplied,
    // tip unchanged, no oplog record beyond the merge's.
}

#[test]
fn pick_preflight_guards() {
    // dirty tree → InvalidArgument; during merge → MergeInProgress;
    // during pick → PickInProgress; unknown ref → NoSuchBranch.
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo cherry_pick` → FAIL.

- [ ] **Step 3: Implement**, then **Step 4: CLI**

```rust
/// Replay one commit from another branch onto the current branch.
CherryPick {
    /// Branch or remote-tracking ref whose tip commit to pick.
    #[arg(value_name = "ref")]
    refname: String,
    /// Commit author (default $SC_AUTHOR, then the OS username).
    #[arg(long)]
    author: Option<String>,
},
```

Handler prints `picked <short-id>` or `already applied — nothing to do` (match on `PickResult`).

- [ ] **Step 5: Run tests** — `cargo test` → green.

- [ ] **Step 6: Commit**

```bash
git add crates/repo/src crates/cli/src/main.rs
git commit -m "feat: sc cherry-pick — replay a commit with P4-style conflict resolution (P14)"
```

---

### Task 9: `Repo::rebase` + CLI `sc rebase`

**Files:**
- Modify: `crates/repo/src/replay.rs` (add rebase to the `impl Repo` block)
- Modify: `crates/repo/src/error.rs`:

```rust
#[error("rebase: commit {commit} conflicts on {paths:?}; rebase aborted, refs untouched — resolve via `sc merge` or per-commit `sc cherry-pick`")]
RebaseConflicts { commit: ObjectId, paths: Vec<String> },
```

- Modify: `crates/repo/src/lib.rs` (`pub use replay::{PickResult, RebaseResult};`)
- Modify: `crates/cli/src/main.rs` (subcommand + handler)
- Test: `crates/repo/src/replay.rs` tests

**Interfaces:**
- Produces:

```rust
pub enum RebaseResult {
    /// Target already reachable from the current tip — nothing to do.
    AlreadyUpToDate,
    /// Current tip was an ancestor of target — ref fast-forwarded.
    FastForwarded(ObjectId),
    /// Commits replayed; branch now points at the last new snapshot.
    Rebased { new_tip: ObjectId, replayed: usize, skipped: usize },
}

pub fn rebase(&self, target: &str, author: &str) -> Result<RebaseResult>
```

Flow (binding): preflight identical to cherry-pick (guards, born, resolve, dirty). Then:
1. `is_ancestor(target_tip, ours_tip)` (or equal) → `AlreadyUpToDate` (no record).
2. `is_ancestor(ours_tip, target_tip)` → `write_branch_tip` to target tip + materialize (old_root = ours root, target's protection) + oplog `rebase onto <target> (ff)` → `FastForwarded`.
3. `merge_base` (`NoCommonAncestor` propagates). Collect the range: walk first-parent from ours_tip until base (exclusive), reverse to oldest-first. Any commit in the range with 2+ parents → `Err(CannotReplayMerge(id))`, refs untouched.
4. Fold: `acc_tip = target_tip; acc_root = target root; replayed = 0; skipped = 0`. For each commit: `replay_commit(self, c, acc_root)`:
   - `Clean{root}` → `build_snapshot(root, vec![acc_tip], target_snap.secrets, target_snap.protection, author, original_message)` (fresh timestamp, resolved author, message preserved verbatim); `acc_tip = id; acc_root = root; replayed += 1`.
   - `Empty` → `skipped += 1` (caller prints the note).
   - `Conflicts{paths, ..}` → `Err(RebaseConflicts { commit: c, paths })` — nothing written outside the CAS; working tree and refs untouched.
5. `write_branch_tip(current, acc_tip)`; materialize (`acc_root`, old = ours root, target protection, None); oplog `rebase onto <target> (<replayed> replayed, <skipped> skipped)` with the single ref line `(current, Some(ours_tip), Some(acc_tip))` → `Rebased`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn rebase_replays_commits_in_order_onto_target() {
    // main gains a commit; feature has two commits from the old base.
    // rebase(feature → main): Rebased{replayed: 2}; feature tip's parent
    // chain is main-tip ← c1' ← c2'; messages preserved in order; working
    // tree matches the final root.
}

#[test]
fn rebase_fast_paths() {
    // target ancestor of current → AlreadyUpToDate;
    // current ancestor of target → FastForwarded(target_tip), ref moved,
    // oplog desc "rebase onto <t> (ff)".
}

#[test]
fn conflicting_rebase_aborts_with_refs_byte_identical() {
    // snapshot the entire .sc/refs dir (path → bytes) before; conflicting
    // rebase → Err(RebaseConflicts{..}); refs dir byte-identical after;
    // working tree file unchanged; oplog has NO new record.
}

#[test]
fn rebase_skips_already_applied_commits() {
    // feature has commits A, B; main already contains A's change (via
    // cherry-pick) → Rebased{replayed: 1, skipped: 1}.
}

#[test]
fn rebase_range_with_merge_commit_is_refused() {
    // feature contains a merge commit → Err(CannotReplayMerge), refs untouched.
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo rebase` → FAIL.

- [ ] **Step 3: Implement**, then **Step 4: CLI**

```rust
/// Replay the current branch's commits onto another branch's tip.
Rebase {
    /// Branch or remote-tracking ref to rebase onto.
    target: String,
    /// Commit author (default $SC_AUTHOR, then the OS username).
    #[arg(long)]
    author: Option<String>,
},
```

Handler prints per variant: `already up to date` / `fast-forwarded to <short>` / `rebased: <replayed> replayed, <skipped> skipped, tip <short>`.

- [ ] **Step 5: Run tests** — `cargo test` → green.

- [ ] **Step 6: Commit**

```bash
git add crates/repo/src crates/cli/src/main.rs
git commit -m "feat: sc rebase — atomic replay onto a new base; any conflict aborts with refs untouched (P14)"
```

---

### Task 10: GC interplay — oplog roots + trim

**Files:**
- Modify: `crates/repo/src/gc.rs` (`roots`, `run`)
- Test: `crates/repo/src/gc.rs` tests

**Interfaces:**
- Consumes: `oplog::{referenced_ids, trim_older_than}` (Task 3).
- Produces: gc behavior only. Binding rules (spec): trim FIRST (records with `ts` older than `now - grace`, always keeping the newest record), then include every remaining record's before/after ids in `roots()`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn oplog_referenced_snapshots_survive_gc() {
    // commit twice, undo (tip back to c1; c2 now unreachable from refs but
    // referenced by the oplog); age the loose objects (the existing gc
    // tests show the mtime-backdating helper — reuse it); gc with zero
    // grace → c2 still readable from the store.
}

#[test]
fn gc_trims_old_oplog_records_and_releases_roots() {
    // craft an oplog with an old record (ts far past) referencing an
    // otherwise-unreachable snapshot + a fresh record; gc with small grace
    // → old record gone from oplog::read_all, its snapshot pruned (after
    // aging), fresh record retained; undo still works on the fresh one.
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo gc` → the new tests FAIL (c2 pruned / records untouched).

- [ ] **Step 3: Implement**

In `run`, before computing roots:

```rust
let cutoff = (SystemTime::now() - grace)
    .duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
oplog::trim_older_than(layout, cutoff)?;
```

In `roots`, after the merge-state root:

```rust
for id in crate::oplog::referenced_ids(layout)? {
    set.insert(id);
}
```

(Only snapshot ids appear in oplog refs; `reachable_objects` walks from them like any tip.)

- [ ] **Step 4: Run tests** — `cargo test` → green (pre-existing gc tests must still pass — their repos have oplog records now, but those records reference the same reachable tips).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/gc.rs
git commit -m "feat(repo): gc treats oplog ids as roots and trims records past the grace window — undo never dangles (P14)"
```

---

### Task 11: Demo + docs + ADR accept

**Files:**
- Create: `demo/run_history_demo.sh` (chmod +x)
- Modify: `CLAUDE.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `docs/adr/0024-history-editing.md`

**Interfaces:**
- Consumes: everything shipped; record real deviations in the ADR's "Refinements during the build".

- [ ] **Step 1: Demo script**

House style: `set -euo pipefail`, `fail()` gates (see `demo/run_work_demo.sh` — copy its structure, TMPDIR normalization, and zero-residue snapshot), self-contained mktemp repo, trap cleanup. Proof obligations (each a real gate that exits 1):

1. Base repo → `sc work --agents 3` (agents edit distinct files) → 3 branches.
2. `sc merge work-1`.
3. `sc cherry-pick work-2` → `sc log` head message contains `(cherry-picked from`.
4. `sc switch work-3` → `sc rebase main` → `sc log` shows work-3's commit atop main's (linear, no merge marker).
5. Snapshot `.sc/refs` (recursive byte copy) → `sc undo` → refs byte-identical to pre-rebase snapshot (diff -r).
6. `sc undo` again → refs byte-identical to post-rebase snapshot (redo proven).
7. `sc oplog` lists the operations newest-first.
8. Zero-residue check for `sc-work-*` session dirs (same as run_work_demo).

- [ ] **Step 2: Run it twice** — `bash demo/run_history_demo.sh` → RESULT line, exit 0, non-stateful.

- [ ] **Step 3: Docs**

- CLAUDE.md commands block (after the `sc work` lines):

```
cargo run --bin sc -- cherry-pick <ref>       # replay one commit onto the current branch
cargo run --bin sc -- rebase <target>         # replay current branch onto <target> (atomic;
                                              # conflicts abort with refs untouched)
cargo run --bin sc -- undo                    # revert the last operation (again = redo)
cargo run --bin sc -- oplog                   # list recent operations
bash demo/run_history_demo.sh                 # cherry-pick/rebase/undo round-trip proof
```

- CLAUDE.md: add a `**Phase 14 is built.**` paragraph after the Phase 13 one, covering: replay-is-merge composition, pick resolve-flow vs atomic rebase, oplog + undo/redo, gc roots + trim, protected-content fail-closed inheritance, oplog is local-only. Update "Remaining follow-ons" with the deferred items from ROADMAP (amend, --continue, --abort, mainline selection, protected replay, op-objects, remote refs in oplog).
- ARCHITECTURE.md: `## Phase 14 — history editing (built)` section, condensed from the above + the crash-ordering rule (refs first, oplog last).
- ROADMAP.md: move P14 from `## Active` (delete the section) into `## Done` past-tense with ADR cite; add the completed-phases table row:

```markdown
| **P14 — History editing** | Integrate agent branches; undo anything | `sc cherry-pick work-2`, `sc rebase main`, `sc undo`/redo round-trip proven by `demo/run_history_demo.sh` | [0024](docs/adr/0024-history-editing.md) |
```

- ADR-0024: Status → Accepted; append `## Refinements during the build` recording actual deviations.

- [ ] **Step 4: Final full check**

Run: `cargo test && bash demo/run_history_demo.sh && bash demo/run_work_demo.sh && bash demo/run_repo_demo.sh`
Expected: all pass (P13 and P3 demos prove no regression).

- [ ] **Step 5: Commit**

```bash
git add demo/run_history_demo.sh CLAUDE.md ARCHITECTURE.md ROADMAP.md docs/adr/0024-history-editing.md
git commit -m "docs+demo: accept ADR-0024 history editing; record P14; cherry-pick/rebase/undo round-trip proof"
```
