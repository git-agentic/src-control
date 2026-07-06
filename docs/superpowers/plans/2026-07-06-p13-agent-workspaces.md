# P13 — Agent Workspaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc work --agents N -- <cmd>` forks N in-RAM workspaces from a persistent repo's HEAD, materializes each to an ephemeral temp checkout, runs the agent command in each concurrently, and harvests changed workspaces to flat branches (`work-1..work-N`) — integrable with the existing `sc merge`, with zero residue outside `.sc/`.

**Architecture:** New `crates/repo/src/workspace.rs` module composing existing machinery: the repo's already-budget-bounded persistent `VfsRepo` (forks share one Arc'd blob cache; eviction is safe because `.sc/objects` is the reconstruction source — no spill backend), `worktree::materialize` for P7-aware checkout, and a refactored `Repo::commit` core (`snapshot_files`) for scanner-gated harvest. Secrets injection reuses the `sc run` decryption path via a new `secret_env` helper.

**Tech Stack:** Rust stable, edition 2021. Zero new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-06-p13-agent-workspaces-design.md` — read it first.

## Global Constraints

- Dependency direction: `cli → repo → {vfs, gitio, crypto} → core`. `workspace.rs` lives in `crates/repo` (repo already depends on vfs). No `gix` or RustCrypto outside their quarantine crates.
- No new dependencies in any `Cargo.toml`.
- Branch names are **flat** — `validate_branch_name` rejects `/`, and `refs::resolve_tip` reserves `name/branch` for remote-tracking refs. Workspace branches are `<base>-<i>` (default base `work`).
- Over-budget inserts fail loudly (`scl_core::Error::BudgetExceeded`); never silently drop data.
- Blobs stay `Arc<[u8]>`-shared: forking must not copy blob bytes.
- Tests that write to disk clean up after themselves and assert the path is gone.
- Every public type/fn gets a doc comment explaining intent, not mechanics.
- Errors: `thiserror` enums in `repo` (`crate::error::Error`), `anyhow` in `cli`.
- Run `cargo test` (whole workspace) before every commit; all tests green.

---

### Task 1: Roadmap revision + ADR-0023 (Proposed)

Docs only — brings the roadmap up to date (P12 is missing entirely) and records the P13 decision as a Proposed ADR, per the project's phase convention.

**Files:**
- Modify: `ROADMAP.md`
- Create: `docs/adr/0023-agent-workspaces.md`

**Interfaces:**
- Consumes: `docs/superpowers/specs/2026-07-06-p13-agent-workspaces-design.md` (the approved spec)
- Produces: nothing code-visible; Task 9 flips the ADR to Accepted.

- [ ] **Step 1: Add P12 and P13 to ROADMAP.md "Done" / active sections**

In `ROADMAP.md`, append to the `## Done` list after the P11 bullet:

```markdown
- **Phase 12 — Network transport over SSH.** A framed stdio wire protocol
  mirrors the 8 `Transport` verbs; `sc serve --stdio` dispatches onto the
  existing `LocalTransport` (CAS, pack verification reused verbatim); the
  client spawns the user's `ssh` for `ssh://` remotes, overridable via
  `SC_SSH` (GIT_SSH pattern) so tests and `demo/run_ssh_remote_demo.sh`
  drive the full ssh:// code path with no sshd. Zero new dependencies.
  Accepted limitations: 4 GiB frame cap, no repo paths with spaces over
  real ssh, `sc` must be on the server's PATH. (ADR-0022.)
```

Immediately after the `## Done` section, add a new section:

```markdown
## Active

- **Phase 13 — Agent workspaces (`sc work`).** Fuse the two halves of the
  project: fork N in-RAM copy-on-write workspaces from a persistent repo's
  HEAD (the repo's budget-bounded store is the backing tier — eviction is
  safe, no spill backend), materialize each to an ephemeral temp checkout,
  run real agent processes concurrently, and harvest changed workspaces to
  `work-<i>` branches through the commit path (so `.scignore` and the P5
  scanner gate apply). `--with-secrets` injects decrypted secrets into each
  agent's environment via the `sc run` path — one command exercising all
  three thesis pillars. Zero residue outside `.sc/`.
  Spec: `docs/superpowers/specs/2026-07-06-p13-agent-workspaces-design.md`.
  (ADR-0023, Proposed.)
```

Also add a row to the "Completed phases" table after the P11 row:

```markdown
| **P12 — SSH-native network transport** | Sync between machines | `sc clone ssh://host/path`, `sc fetch`/`push` over the wire via `sc serve --stdio`; `demo/run_ssh_remote_demo.sh` proves the round trip with no sshd | [0022](docs/adr/0022-ssh-native-transport.md) |
```

- [ ] **Step 2: Refresh the "Deferred beyond P11" section**

Rename the section to `## Deferred` and replace the first bullet (network transport) with:

```markdown
- **HTTP transport** and **network Git remotes** (GitHub over https/ssh).
  P12 shipped the sc-native SSH transport; P10's git-backed remotes still
  reach local `.git` paths only — network Git is a transport swap onto the
  same marks-map translation core.
- **Streaming (>4 GiB) wire frames** (P12 caps a frame at 4 GiB).
- **Interactive/daemon workspace sessions** (`sc ws fork` … `sc ws harvest`
  across invocations) and **auto-merge of clean workspace results** — both
  explicitly out of P13's one-command session scope.
```

Keep the remaining bullets (bulk re-wrap, multiple escrow keys, sub-tree/partial sharing, merge ergonomics, signed commits) unchanged.

- [ ] **Step 3: Update the dependency graph and "Why this order"**

In the `## Dependencies` code block, add:

```
Phase 6 transport trait ──> P12 SSH-native transport (ADR-0022)
Phase 1 vfs + Phase 3 store ──> P13 Agent workspaces (integrates via P4 merge;
                                composes with P5 scanner, P7 paths, Phase 2 secrets)
```

At the end of `## Why this order`, add:

```markdown
- **P12 (SSH transport)** turns src-control from local-only into a real DVCS;
  it slots after P10 because it generalizes the same Transport seam.
- **P13 (agent workspaces)** closes the original thesis loop: the Phase 1
  in-memory-clone engine finally serves the persistent repos every phase
  since Phase 3 built. It needs nothing beyond Phase 1 + Phase 3 machinery,
  but lands after the transports so harvested branches can travel.
```

- [ ] **Step 4: Write ADR-0023 (Proposed)**

Create `docs/adr/0023-agent-workspaces.md` following the format of `docs/adr/0022-ssh-native-transport.md` (read it for the house style). Content:

```markdown
# ADR-0023: Agent workspaces — vfs-backed sessions over the persistent store

- **Status:** Proposed
- **Date:** 2026-07-06

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
```

- [ ] **Step 5: Commit**

```bash
git add ROADMAP.md docs/adr/0023-agent-workspaces.md
git commit -m "docs: revise roadmap (record P12, add P13 agent workspaces); ADR-0023 proposed"
```

---

### Task 2: Extract `build_snapshot` + `snapshot_files` from `Repo::commit`

Pure refactor, no behavior change. `Repo::commit` currently interleaves reading the working tree, the scan/encrypt/carry-forward pipeline, snapshot persistence, and current-branch ref advancement. Harvest (Task 5) needs the middle — files → snapshot, advancing **no** refs — against an arbitrary parent tip.

**Files:**
- Modify: `crates/repo/src/repo.rs` (the `commit` fn at ~line 134, `commit_snapshot` at ~line 295)

**Interfaces:**
- Consumes: existing `Repo::commit` body, `Repo::commit_snapshot`.
- Produces (both `pub(crate)`, used by Task 5):
  - `fn snapshot_files(&self, files: Vec<(String, Vec<u8>, scl_core::FileMode)>, tip: Option<ObjectId>, merge_head: Option<ObjectId>, author: &str, message: &str) -> Result<ObjectId>` — full scan/encrypt/carry-forward pipeline + snapshot persistence; **advances no refs, touches no merge state**. Returns `Err(Error::SecretDetected(report))` on a scanner hit.
  - `fn build_snapshot(&self, root: ObjectId, parents: Vec<ObjectId>, secrets: BTreeMap<String, ObjectId>, protection: Protection, author: &str, message: &str) -> Result<ObjectId>` — persist a snapshot object only.
  - `Repo::commit` and `Repo::commit_snapshot` keep their exact public signatures and behavior.

- [ ] **Step 1: Run the existing suite to establish the green baseline**

Run: `cargo test -p scl-repo`
Expected: PASS (all existing tests green).

- [ ] **Step 2: Split `commit_snapshot` into `build_snapshot` + ref advance**

In `crates/repo/src/repo.rs`, replace the body of `commit_snapshot` and add `build_snapshot` directly above it:

```rust
    /// Persist a snapshot object (no ref movement). The workspace harvest
    /// (P13) commits to non-HEAD branches, so snapshot construction must not
    /// be welded to "advance the current branch".
    pub(crate) fn build_snapshot(
        &self,
        root: ObjectId,
        parents: Vec<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        protection: Protection,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let snap = Object::Snapshot(Snapshot {
            root,
            parents,
            author: author.to_string(),
            timestamp: unix_now(),
            message: message.to_string(),
            secrets,
            protection,
        });
        let store_arc = self.vfs.store();
        let id = store_arc.lock().unwrap().put(snap)?;
        Ok(id)
    }

    /// Build + persist a snapshot and advance the current branch ref.
    pub(crate) fn commit_snapshot(
        &self,
        root: ObjectId,
        parents: Vec<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        protection: Protection,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let id = self.build_snapshot(root, parents, secrets, protection, author, message)?;
        let branch = refs::current_branch(&self.layout)?;
        refs::write_branch_tip(&self.layout, &branch, &id)?;
        Ok(id)
    }
```

- [ ] **Step 3: Extract `snapshot_files` from `commit`**

Move the body of `commit` from the line `let (mut protection, secrets) = match (tip, merge_head) {` down to (and including) `protection.wrapped = fresh_wrapped;` plus the parents assembly, verbatim, into a new method placed directly above `commit`:

```rust
    /// The commit pipeline minus ref movement: split protected/plaintext files,
    /// scan the plaintext (Err(SecretDetected) on a hit), convergently encrypt
    /// protected files, carry forward absent still-protected content from
    /// `tip`, and persist the resulting snapshot with `tip` (+ `merge_head`)
    /// as parents. Used by `commit` (HEAD tip) and by workspace harvest (P13,
    /// arbitrary base tip, no merge head). Advances no refs.
    pub(crate) fn snapshot_files(
        &self,
        files: Vec<(String, Vec<u8>, scl_core::FileMode)>,
        tip: Option<ObjectId>,
        merge_head: Option<ObjectId>,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        // ... the moved body, unchanged, ending with:
        let mut parents: Vec<ObjectId> = tip.into_iter().collect();
        if let Some(theirs) = merge_head {
            parents.push(theirs);
        }
        self.build_snapshot(root, parents, secrets, protection, author, message)
    }
```

Then reduce `commit` to:

```rust
    pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
        let files = worktree::read_worktree(&self.layout, &self.tracked_paths()?)?;
        let tip = self.head_tip()?;
        let merge_head = crate::merge_state::read_merge_head(&self.layout)?;
        let id = self.snapshot_files(files, tip, merge_head, author, message)?;
        let branch = refs::current_branch(&self.layout)?;
        refs::write_branch_tip(&self.layout, &branch, &id)?;
        crate::merge_state::clear(&self.layout)?;
        Ok(id)
    }
```

Keep the existing doc comment on `commit`. The moved body must be byte-identical logic — this task changes structure, not behavior.

- [ ] **Step 4: Run the whole workspace suite**

Run: `cargo test`
Expected: PASS, same test count as Step 1's baseline (no tests added or removed).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/repo.rs
git commit -m "refactor(repo): extract build_snapshot + snapshot_files from commit — harvest needs snapshots without ref movement (P13)"
```

---

### Task 3: `Repo::open_with_budget`

`Repo::open_layout` hardcodes `DEFAULT_BUDGET`; `sc work --budget-mb` needs to size the session's shared cache.

**Files:**
- Modify: `crates/repo/src/repo.rs` (`open`, `open_layout` at ~lines 51–60)
- Test: `crates/repo/src/repo.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `pub fn open_with_budget(start: impl AsRef<Path>, budget_bytes: usize) -> Result<Repo>` — used by Task 7's CLI handler.

- [ ] **Step 1: Write the failing test**

Add to the existing `mod tests` in `crates/repo/src/repo.rs` (follow the file's existing temp-dir test helpers — read a neighboring test first and copy its setup/cleanup pattern):

```rust
    #[test]
    fn open_with_budget_bounds_the_store() {
        let dir = std::env::temp_dir().join(format!("sc-test-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            Repo::init(&dir).unwrap();
        } // drop → release lock
        let repo = Repo::open_with_budget(&dir, 4 * 1024 * 1024).unwrap();
        assert_eq!(repo.vfs().stats().budget_bytes, 4 * 1024 * 1024);
        drop(repo);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p scl-repo open_with_budget_bounds_the_store`
Expected: FAIL — `no function or associated item named 'open_with_budget'`.

- [ ] **Step 3: Implement**

```rust
    /// Open an existing repo with an explicit memory budget for the shared
    /// object cache (bytes). `open` uses `DEFAULT_BUDGET`; workspace sessions
    /// (`sc work --budget-mb`) size the cache to the fleet they fork.
    pub fn open_with_budget(start: impl AsRef<Path>, budget_bytes: usize) -> Result<Repo> {
        let layout = Layout::discover(start)?;
        Self::open_layout(layout, budget_bytes)
    }
```

Change `open_layout` to take the budget, and thread `DEFAULT_BUDGET` through the existing callers (`init`, `open`):

```rust
    fn open_layout(layout: Layout, budget_bytes: usize) -> Result<Repo> {
        let lock = RepoLock::acquire(&layout)?;
        let store = Store::open_persistent(layout.objects_dir(), budget_bytes)?;
        Ok(Repo { layout, vfs: VfsRepo::new(store), _lock: lock })
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/repo.rs
git commit -m "feat(repo): Repo::open_with_budget — size the shared cache for workspace sessions (P13)"
```

---

### Task 4: `Repo::secret_env` — decrypt-once env pairs, strict/lenient

`Repo::run` (in `crates/repo/src/secrets.rs`, ~line 219) decrypts every registered secret and injects it into ONE child. Workspace sessions need the same decryption once, injected into N children — and the spec wants strict preflight (unauthorized identity → refuse before any agent runs), whereas `run` warns-and-skips.

**Files:**
- Modify: `crates/repo/src/secrets.rs`
- Test: `crates/repo/src/secrets.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: existing `self.registry()`, `self.store_arc()`, `scl_crypto::open`.
- Produces: `pub(crate) fn secret_env(&self, identity: &scl_crypto::SecretKey, strict: bool) -> Result<Vec<(String, std::ffi::OsString)>>` — used by Task 6. `Repo::run` keeps its exact public signature and lenient behavior.

- [ ] **Step 1: Write the failing tests**

In `crates/repo/src/secrets.rs` tests (copy the existing test setup pattern for creating a repo with a secret — the module already has tests that call `secret_add`):

```rust
    #[test]
    fn secret_env_strict_rejects_non_recipient() {
        // setup: temp repo, one secret sealed to alice only (reuse the
        // module's existing setup helper/pattern), then:
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        let err = repo.secret_env(&mallory_sk, true).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
        // lenient mode skips instead:
        let envs = repo.secret_env(&mallory_sk, false).unwrap();
        assert!(envs.is_empty());
    }

    #[test]
    fn secret_env_decrypts_for_recipient() {
        // setup: secret "DB_URL" = b"v" sealed to alice
        let envs = repo.secret_env(&alice_sk, true).unwrap();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, "DB_URL");
        assert_eq!(envs[0].1, std::ffi::OsString::from("v"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo secret_env`
Expected: FAIL — `no method named 'secret_env'`.

- [ ] **Step 3: Implement by extracting the decryption loop from `run`**

```rust
    /// Decrypt every registered secret with `identity` into `(name, value)`
    /// env pairs. `strict: true` errors on the first secret the identity
    /// cannot open (workspace preflight — fail before any agent runs);
    /// `strict: false` warns and skips (`sc run` behavior).
    pub(crate) fn secret_env(
        &self,
        identity: &SecretKey,
        strict: bool,
    ) -> Result<Vec<(String, OsString)>> {
        let reg = self.registry()?;
        let mut envs: Vec<(String, OsString)> = Vec::new();
        for (name, id) in reg {
            let obj = {
                let arc = self.store_arc();
                let o = arc.lock().unwrap().get(&id)?;
                o
            };
            let secret = match obj {
                Object::Secret(s) => s,
                _ => continue,
            };
            match scl_crypto::open(&secret, identity) {
                Ok(plaintext) => {
                    #[cfg(unix)]
                    let val = {
                        use std::os::unix::ffi::OsStrExt;
                        std::ffi::OsStr::from_bytes(&plaintext).to_os_string()
                    };
                    #[cfg(not(unix))]
                    let val = OsString::from(std::str::from_utf8(&plaintext).map_err(
                        |_| Error::InvalidArgument(format!("secret {name} not UTF-8")),
                    )?);
                    envs.push((name, val));
                }
                Err(scl_crypto::Error::NotARecipient) if strict => {
                    return Err(Error::InvalidArgument(format!(
                        "identity is not a recipient of secret {name}"
                    )));
                }
                Err(scl_crypto::Error::NotARecipient) => {
                    eprintln!("warning: not authorized for secret {name}; skipping");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(envs)
    }
```

Preserve the existing NOTE comment about the un-zeroized `OsString` — move it with the code. Then reduce `run` to:

```rust
    pub fn run(&self, identity: &SecretKey, cmd: &[String]) -> Result<i32> {
        let envs = self.secret_env(identity, false)?;
        let (exe, args) =
            cmd.split_first().ok_or_else(|| Error::InvalidArgument("empty command".into()))?;
        let mut command = Command::new(exe);
        command.args(args);
        for (k, v) in &envs {
            command.env(k, v);
        }
        let status = command.status()?;
        Ok(status.code().unwrap_or(1))
    }
```

Keep `run`'s existing doc comment.

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo`
Expected: PASS, including all pre-existing secrets tests.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/secrets.rs
git commit -m "refactor(repo): extract secret_env from run — strict preflight decryption for workspace sessions (P13)"
```

---

### Task 5: `workspace.rs` — per-workspace primitives (materialize + harvest)

The two per-workspace operations, each testable without spawning any agent process.

**Files:**
- Create: `crates/repo/src/workspace.rs`
- Modify: `crates/repo/src/lib.rs` (add `pub mod workspace;` alphabetically after `pub mod wire;`; add `pub use workspace::HarvestResult;`)
- Test: `crates/repo/src/workspace.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `Repo::snapshot(&ObjectId)` (pub(crate)), `Repo::snapshot_files` (Task 2), `worktree::{materialize, read_worktree, diff_worktree, tree_file_ids}`, `refs::write_branch_tip`, `Layout::at`.
- Produces (used by Task 6):
  - `pub enum HarvestResult { Committed(ObjectId), Unchanged, Rejected(crate::scanner::ScanReport) }`
  - `pub(crate) fn materialize_workspace(repo: &Repo, tip: ObjectId, dir: &Path, identity: Option<&scl_crypto::SecretKey>) -> Result<Vec<String>>` (returns skipped protected paths)
  - `pub(crate) fn harvest_workspace(repo: &Repo, tip: ObjectId, dir: &Path, branch: &str, author: &str, message: &str) -> Result<HarvestResult>`

- [ ] **Step 1: Write the failing tests**

Create `crates/repo/src/workspace.rs` with module doc + tests first:

```rust
//! Agent workspace sessions (P13): fork N in-RAM workspaces from a persistent
//! repo's HEAD, materialize each to an ephemeral checkout, run agent commands,
//! and harvest changed workspaces back as branches. The repo's budget-bounded
//! persistent store is the backing tier — forks share one Arc'd blob cache and
//! eviction is always safe (every object is reconstructible from `.sc/objects`).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    /// Fresh persistent repo in a unique temp dir with one committed file.
    /// Returns (repo root, workspace scratch dir); caller removes both.
    fn setup(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("sc-ws-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("repo");
        let scratch = base.join("scratch");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        {
            let repo = Repo::init(&root).unwrap();
            std::fs::write(root.join("a.txt"), "base\n").unwrap();
            repo.commit("test", "base").unwrap();
        }
        (root, scratch)
    }

    fn teardown(root: &std::path::Path) {
        let base = root.parent().unwrap();
        std::fs::remove_dir_all(base).unwrap();
        assert!(!base.exists());
    }

    #[test]
    fn materialize_then_harvest_edit_creates_branch() {
        let (root, scratch) = setup("edit");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let dir = scratch.join("ws1");
        let skipped = materialize_workspace(&repo, tip, &dir, None).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(std::fs::read_to_string(dir.join("a.txt")).unwrap(), "base\n");

        std::fs::write(dir.join("a.txt"), "edited\n").unwrap();
        let res = harvest_workspace(&repo, tip, &dir, "work-1", "test", "msg").unwrap();
        let id = match res {
            HarvestResult::Committed(id) => id,
            other => panic!("expected Committed, got {other:?}"),
        };
        // Branch points at the new snapshot; parent is the base tip; HEAD untouched.
        assert_eq!(crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(), Some(id));
        assert_eq!(repo.snapshot(&id).unwrap().parents, vec![tip]);
        assert_eq!(repo.head_tip().unwrap(), Some(tip));
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn unchanged_workspace_creates_no_branch() {
        let (root, scratch) = setup("unchanged");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let dir = scratch.join("ws1");
        materialize_workspace(&repo, tip, &dir, None).unwrap();
        let res = harvest_workspace(&repo, tip, &dir, "work-1", "test", "msg").unwrap();
        assert!(matches!(res, HarvestResult::Unchanged));
        assert_eq!(crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(), None);
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn plaintext_secret_in_workspace_is_rejected() {
        let (root, scratch) = setup("scan");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let dir = scratch.join("ws1");
        materialize_workspace(&repo, tip, &dir, None).unwrap();
        // An AWS-style key id trips the P5 pattern rules.
        std::fs::write(dir.join("leak.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let res = harvest_workspace(&repo, tip, &dir, "work-1", "test", "msg").unwrap();
        assert!(matches!(res, HarvestResult::Rejected(_)));
        assert_eq!(crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(), None);
        drop(repo);
        teardown(&root);
    }
}
```

(If the scanner's test corpus uses a different canonical trigger string, copy the trigger used in `crates/repo/src/scanner.rs` tests instead of the AWS example key.)

- [ ] **Step 2: Register the module and run tests to verify they fail**

In `crates/repo/src/lib.rs`, add `pub mod workspace;` after `pub mod wire;` and `pub use workspace::HarvestResult;` in the re-export block.

Run: `cargo test -p scl-repo workspace`
Expected: FAIL — `materialize_workspace`/`harvest_workspace`/`HarvestResult` not found.

- [ ] **Step 3: Implement the primitives**

Above the tests module:

```rust
use std::path::Path;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::refs;
use crate::repo::Repo;
use crate::worktree;

/// Outcome of harvesting one workspace checkout.
#[derive(Debug)]
pub enum HarvestResult {
    /// Changes committed; the workspace branch points at this snapshot.
    Committed(ObjectId),
    /// Checkout identical to the base snapshot; no branch created.
    Unchanged,
    /// The P5 scanner found plaintext secrets; nothing was committed.
    Rejected(crate::scanner::ScanReport),
}

/// Materialize the snapshot at `tip` into `dir` (created if absent), applying
/// the same P7 protected-path rules as `sc switch`: decrypt with `identity`
/// when possible, otherwise skip. Returns the skipped protected paths.
pub(crate) fn materialize_workspace(
    repo: &Repo,
    tip: ObjectId,
    dir: &Path,
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<Vec<String>> {
    std::fs::create_dir_all(dir)?;
    let snap = repo.snapshot(&tip)?;
    let ws = Layout::at(dir);
    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();
    worktree::materialize(&ws, &mut store, snap.root, None, &snap.protection, identity)
}

/// Diff the checkout at `dir` against the base snapshot `tip`; if changed,
/// snapshot it through the full commit pipeline (scanner gate, protected-path
/// re-encryption, carry-forward) and point `branch` at the result. Never
/// touches HEAD or the current branch.
pub(crate) fn harvest_workspace(
    repo: &Repo,
    tip: ObjectId,
    dir: &Path,
    branch: &str,
    author: &str,
    message: &str,
) -> Result<HarvestResult> {
    let snap = repo.snapshot(&tip)?;
    let ws = Layout::at(dir);
    let (tracked, changed) = {
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let tracked: std::collections::BTreeSet<String> =
            worktree::tree_file_ids(&mut store, snap.root)?.into_keys().collect();
        let d = worktree::diff_worktree(&ws, &mut store, Some(snap.root), &snap.protection)?;
        (tracked, !(d.added.is_empty() && d.modified.is_empty() && d.deleted.is_empty()))
    };
    if !changed {
        return Ok(HarvestResult::Unchanged);
    }
    let files = worktree::read_worktree(&ws, &tracked)?;
    match repo.snapshot_files(files, Some(tip), None, author, message) {
        Ok(id) => {
            refs::write_branch_tip(repo.layout(), branch, &id)?;
            Ok(HarvestResult::Committed(id))
        }
        Err(Error::SecretDetected(report)) => Ok(HarvestResult::Rejected(report)),
        Err(e) => Err(e),
    }
}
```

Notes for the implementer:
- `Diff` (in `worktree.rs`) may carry extra fields beyond `added`/`modified`/`deleted` — check the struct and, if it has an emptiness helper, use it instead of the three-way check.
- `ScanReport` may need `#[derive(Debug)]` added for `HarvestResult`'s derive — add it if the compiler asks; it's a plain data struct.
- `repo.vfs()` is the existing public accessor (`crates/repo/src/repo.rs:714`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo workspace`
Expected: PASS (3 tests).

Run: `cargo test`
Expected: PASS (whole workspace).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/workspace.rs crates/repo/src/lib.rs
git commit -m "feat(repo): workspace primitives — P7-aware materialize + scanner-gated harvest to a branch (P13)"
```

---

### Task 6: `Repo::work` — session orchestration

Preflight → fork N in-RAM worktrees → materialize N checkouts → spawn agents concurrently → wait → harvest sequentially → teardown (Drop-guarded).

**Files:**
- Modify: `crates/repo/src/workspace.rs`
- Modify: `crates/repo/src/lib.rs` (extend the re-export: `pub use workspace::{HarvestResult, WorkOptions, WorkspaceOutcome};`)
- Test: `crates/repo/src/workspace.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: Task 5 primitives, `Repo::secret_env` (Task 4), `self.vfs.fork(tip, label)` (vfs), `crate::repo::validate_branch_name`, `refs::read_branch_tip`, `Error::{Unborn, InvalidArgument, BadRef}`.
- Produces (used by Task 7's CLI):

```rust
pub struct WorkOptions {
    pub agents: usize,
    /// Branch/label base; branches are `<base_name>-1..N`.
    pub base_name: String,
    pub cmd: Vec<String>,
    pub author: String,
    /// Commit message; defaults to the joined agent command line.
    pub message: Option<String>,
    /// Decrypts protected paths at checkout; also required by `with_secrets`.
    pub identity: Option<scl_crypto::SecretKey>,
    pub with_secrets: bool,
    /// Session temp root override (tests); default `$TMPDIR/sc-work-<pid>`.
    pub session_root: Option<std::path::PathBuf>,
}

pub struct WorkspaceOutcome {
    pub label: String,
    /// Agent exit code; None if the spawn failed or the exit was signal-killed.
    pub agent_exit: Option<i32>,
    pub harvest: Result<HarvestResult>,
}

impl Repo {
    pub fn work(&self, opts: WorkOptions) -> Result<Vec<WorkspaceOutcome>>;
}
```

- [ ] **Step 1: Write the failing tests**

Add to `workspace.rs` tests (reusing `setup`/`teardown` from Task 5):

```rust
    fn work_opts(agents: usize, cmd: &[&str], scratch: &std::path::Path) -> WorkOptions {
        WorkOptions {
            agents,
            base_name: "work".into(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            author: "test".into(),
            message: None,
            identity: None,
            with_secrets: false,
            session_root: Some(scratch.join("session")),
        }
    }

    #[test]
    fn work_session_forks_runs_and_harvests_n_branches() {
        let (root, scratch) = setup("session");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let opts = work_opts(3, &["sh", "-c", "echo \"$SC_WORKSPACE\" > out.txt"], &scratch);
        let session_root = opts.session_root.clone().unwrap();
        let outcomes = repo.work(opts).unwrap();
        assert_eq!(outcomes.len(), 3);
        for (i, o) in outcomes.iter().enumerate() {
            let label = format!("work-{}", i + 1);
            assert_eq!(o.label, label);
            assert_eq!(o.agent_exit, Some(0));
            let id = match o.harvest.as_ref().unwrap() {
                HarvestResult::Committed(id) => *id,
                other => panic!("expected Committed, got {other:?}"),
            };
            assert_eq!(crate::refs::read_branch_tip(repo.layout(), &label).unwrap(), Some(id));
        }
        // HEAD untouched; session temp dir gone (zero residue).
        assert_eq!(repo.head_tip().unwrap(), Some(tip));
        assert!(!session_root.exists());
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn unchanged_and_failed_agents_are_reported_not_destroyed() {
        let (root, scratch) = setup("mixed");
        let repo = Repo::open(&root).unwrap();
        // Agent 1..N all run the same cmd; use one that edits then fails.
        let opts =
            work_opts(1, &["sh", "-c", "echo partial > wip.txt; exit 3"], &scratch);
        let outcomes = repo.work(opts).unwrap();
        assert_eq!(outcomes[0].agent_exit, Some(3));
        // Partial work still harvested.
        assert!(matches!(outcomes[0].harvest.as_ref().unwrap(), HarvestResult::Committed(_)));

        // A no-op agent produces Unchanged and no branch.
        let opts2 = WorkOptions { base_name: "idle".into(), ..work_opts(1, &["true"], &scratch) };
        let outcomes2 = repo.work(opts2).unwrap();
        assert!(matches!(outcomes2[0].harvest.as_ref().unwrap(), HarvestResult::Unchanged));
        assert_eq!(crate::refs::read_branch_tip(repo.layout(), "idle-1").unwrap(), None);
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn preflight_refuses_collision_unborn_and_bad_input() {
        let (root, scratch) = setup("preflight");
        let repo = Repo::open(&root).unwrap();
        // Existing branch work-1 → refuse before running anything.
        repo.branch("work-1").unwrap();
        let opts = work_opts(2, &["true"], &scratch);
        let session_root = opts.session_root.clone().unwrap();
        assert!(matches!(repo.work(opts), Err(Error::BadRef(_))));
        assert!(!session_root.exists(), "refusal must not leave a session dir");
        // Zero agents / empty command.
        assert!(matches!(
            repo.work(work_opts(0, &["true"], &scratch)),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            repo.work(work_opts(1, &[], &scratch)),
            Err(Error::InvalidArgument(_))
        ));
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn with_secrets_injects_into_agent_env() {
        let (root, scratch) = setup("secrets");
        let repo = Repo::open(&root).unwrap();
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("DEMO_TOKEN", b"tok-123", &[pk]).unwrap();
        let mut opts =
            work_opts(1, &["sh", "-c", "printf %s \"$DEMO_TOKEN\" > tok.txt"], &scratch);
        opts.base_name = "sec".into();
        opts.with_secrets = true;
        opts.identity = Some(sk);
        let outcomes = repo.work(opts).unwrap();
        let id = match outcomes[0].harvest.as_ref().unwrap() {
            HarvestResult::Committed(id) => *id,
            other => panic!("expected Committed, got {other:?}"),
        };
        // Prove the decrypted value reached the agent: read tok.txt's blob
        // back out of the harvested snapshot.
        let roots = repo.snapshot(&id).unwrap().root;
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = crate::worktree::tree_file_ids(&mut store, roots).unwrap();
        let blob = store.get(ids.get("tok.txt").unwrap()).unwrap();
        match blob {
            scl_core::Object::Blob(b) => assert_eq!(&b[..], b"tok-123"),
            other => panic!("expected blob, got {other:?}"),
        }
        drop(store);
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn budget_evicts_when_reclaimable_and_fails_loudly_when_not() {
        let (root, scratch) = setup("budget");
        {
            // Two 3 MiB files: total 6 MiB exceeds the 4 MiB budget, but each
            // blob fits individually → the session must succeed via eviction.
            let repo = Repo::open(&root).unwrap();
            std::fs::write(root.join("x.bin"), vec![1u8; 3 * 1024 * 1024]).unwrap();
            std::fs::write(root.join("y.bin"), vec![2u8; 3 * 1024 * 1024]).unwrap();
            repo.commit("test", "two big files").unwrap();
        }
        {
            let repo = Repo::open_with_budget(&root, 4 * 1024 * 1024).unwrap();
            let outcomes = repo.work(work_opts(1, &["true"], &scratch)).unwrap();
            assert!(matches!(outcomes[0].harvest.as_ref().unwrap(), HarvestResult::Unchanged));
            assert!(repo.vfs().stats().evictions > 0, "over-budget session must evict");
        }
        {
            // Budget smaller than a single blob: nothing reclaimable → the
            // failure is loud (BudgetExceeded from core), never a silent drop.
            let repo = Repo::open_with_budget(&root, 1024 * 1024).unwrap();
            let err = repo.work(work_opts(1, &["true"], &scratch)).unwrap_err();
            assert!(err.to_string().contains("budget"), "unexpected error: {err}");
        }
        let repo = Repo::open(&root).unwrap();
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn forking_workspaces_copies_no_blob_bytes() {
        let (root, scratch) = setup("zerocopy");
        let repo = Repo::open(&root).unwrap();
        // Commit a 1 MiB file so resident bytes are measurable.
        std::fs::write(root.join("big.bin"), vec![0x5Au8; 1024 * 1024]).unwrap();
        repo.commit("test", "big").unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let before = repo.vfs().stats().resident_blob_bytes;
        let _forks: Vec<_> =
            (0..8).map(|i| repo.vfs().fork(tip, format!("z{i}")).unwrap()).collect();
        assert_eq!(
            repo.vfs().stats().resident_blob_bytes,
            before,
            "fork must not copy blob bytes"
        );
        drop(repo);
        let _ = &scratch; // scratch unused here
        teardown(&root);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo workspace`
Expected: FAIL — `WorkOptions`/`work` not found (Task 5 tests still pass).

- [ ] **Step 3: Implement `Repo::work`**

In `workspace.rs` (an `impl Repo` block in a non-`repo.rs` file follows the existing `secrets.rs` convention):

```rust
/// Options for a `sc work` session. See the P13 spec for semantics.
pub struct WorkOptions {
    pub agents: usize,
    pub base_name: String,
    pub cmd: Vec<String>,
    pub author: String,
    pub message: Option<String>,
    pub identity: Option<scl_crypto::SecretKey>,
    pub with_secrets: bool,
    pub session_root: Option<std::path::PathBuf>,
}

/// Per-workspace session result: what the agent did and what harvest kept.
pub struct WorkspaceOutcome {
    pub label: String,
    pub agent_exit: Option<i32>,
    pub harvest: Result<HarvestResult>,
}

/// Removes the session temp tree however the session exits (success, error,
/// or panic) — the zero-residue guarantee outside `.sc/`.
struct Teardown(std::path::PathBuf);
impl Drop for Teardown {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Repo {
    /// Run a one-command agent-workspace session: fork `agents` in-RAM
    /// workspaces from HEAD, materialize each to an ephemeral checkout, run
    /// `cmd` in each concurrently, and harvest changed workspaces to
    /// `<base_name>-<i>` branches. The current branch, HEAD, and the user's
    /// working tree are never touched. One workspace's failure (agent exit,
    /// scanner rejection, harvest error) never aborts its siblings.
    pub fn work(&self, opts: WorkOptions) -> Result<Vec<WorkspaceOutcome>> {
        if opts.agents == 0 {
            return Err(Error::InvalidArgument("agents must be >= 1".into()));
        }
        if opts.cmd.is_empty() {
            return Err(Error::InvalidArgument("empty agent command".into()));
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let labels: Vec<String> =
            (1..=opts.agents).map(|i| format!("{}-{i}", opts.base_name)).collect();
        for label in &labels {
            crate::repo::validate_branch_name(label)?;
            if refs::read_branch_tip(self.layout(), label)?.is_some() {
                return Err(Error::BadRef(format!("branch already exists: {label}")));
            }
        }
        let secret_envs = match (opts.with_secrets, &opts.identity) {
            (true, Some(sk)) => self.secret_env(sk, true)?,
            (true, None) => {
                return Err(Error::InvalidArgument(
                    "--with-secrets requires an identity".into(),
                ))
            }
            _ => Vec::new(),
        };

        let session_root = opts.session_root.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("sc-work-{}", std::process::id()))
        });
        let _teardown = Teardown(session_root.clone());

        // The session's in-RAM workspace handles: N forks pin the base
        // snapshot and share the store's Arc'd blobs (asserted zero-copy in
        // tests). Held for the session's lifetime.
        let mut _forks = Vec::with_capacity(labels.len());
        for label in &labels {
            _forks.push(self.vfs().fork(tip, label.clone())?);
        }

        let message = opts.message.clone().unwrap_or_else(|| opts.cmd.join(" "));
        let (exe, args) = opts.cmd.split_first().expect("checked non-empty above");

        // Spawn all agents first (they run concurrently), then await each.
        let mut children = Vec::with_capacity(labels.len());
        for label in &labels {
            let dir = session_root.join(label);
            materialize_workspace(self, tip, &dir, opts.identity.as_ref())?;
            let mut c = std::process::Command::new(exe);
            c.args(args)
                .current_dir(&dir)
                .env("SC_WORKSPACE", label)
                .env("SC_WORKSPACE_DIR", &dir);
            for (k, v) in &secret_envs {
                c.env(k, v);
            }
            children.push((label.clone(), dir, c.spawn()));
        }

        let mut outcomes = Vec::with_capacity(children.len());
        for (label, dir, spawn) in children {
            let agent_exit = match spawn {
                Ok(mut child) => child.wait().ok().and_then(|s| s.code()),
                Err(e) => {
                    eprintln!("workspace {label}: failed to spawn agent: {e}");
                    None
                }
            };
            let harvest = harvest_workspace(self, tip, &dir, &label, &opts.author, &message);
            outcomes.push(WorkspaceOutcome { label, agent_exit, harvest });
        }
        Ok(outcomes)
    }
}
```

Visibility note: `validate_branch_name` is `pub(crate)` in `repo.rs` — reachable from `workspace.rs`. `self.vfs()` is the public accessor; if `fork` needs `&mut` or the field directly, use `self.vfs` (the field is `pub(crate)`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo workspace`
Expected: PASS (7 tests: 3 from Task 5 + 4 new).

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/workspace.rs crates/repo/src/lib.rs
git commit -m "feat(repo): Repo::work — one-command agent-workspace session: fork, run, harvest, zero-residue teardown (P13)"
```

---

### Task 7: CLI `sc work`

**Files:**
- Modify: `crates/cli/src/main.rs` (subcommand enum ~line 100 area; dispatch match ~line 326 area; handler near `run_run` ~line 1132)

**Interfaces:**
- Consumes: `scl_repo::workspace::{WorkOptions, WorkspaceOutcome, HarvestResult}` (re-exported as `scl_repo::{WorkOptions, ...}`), `Repo::open_with_budget` (Task 3), existing helpers `open_repo()`, `resolve_author`, `load_identity`, `resolve_identity_opt`.
- Produces: the `sc work` subcommand.

- [ ] **Step 1: Add the subcommand definition**

In the `Cmd` enum, after the `Run` variant (mirror its `last = true` pattern):

```rust
    /// Fork N agent workspaces from HEAD, run a command in each, and harvest
    /// changed workspaces to `<name>-<i>` branches.
    Work {
        /// Number of workspaces to fork.
        #[arg(long, default_value_t = 2)]
        agents: usize,
        /// Branch/label base name (branches are `<name>-1..N`).
        #[arg(long, default_value = "work")]
        name: String,
        /// Memory budget for the session's shared object cache, in MiB.
        #[arg(long)]
        budget_mb: Option<usize>,
        /// Decrypt registered secrets and inject them into each agent's env.
        #[arg(long)]
        with_secrets: bool,
        /// Identity file (protected-path checkout and --with-secrets;
        /// default ~/.sc/identity or $SC_IDENTITY).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Commit author for harvested branches (default $SC_AUTHOR, then the
        /// OS username).
        #[arg(long)]
        author: Option<String>,
        /// Agent command and args after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
```

Add the dispatch arm:

```rust
        Cmd::Work { agents, name, budget_mb, with_secrets, identity, author, cmd } => {
            run_work(agents, name, budget_mb, with_secrets, identity, author, cmd)
        }
```

- [ ] **Step 2: Implement the handler**

Near `run_run`:

```rust
/// `sc work`: one-command agent-workspace session. Prints a per-workspace
/// summary; exits non-zero if any agent failed or any harvest was rejected.
fn run_work(
    agents: usize,
    name: String,
    budget_mb: Option<usize>,
    with_secrets: bool,
    identity: Option<PathBuf>,
    author: Option<String>,
    cmd: Vec<String>,
) -> Result<()> {
    let repo = match budget_mb {
        Some(mb) => Repo::open_with_budget(std::env::current_dir()?, mb * 1024 * 1024)?,
        None => open_repo()?,
    };
    // --with-secrets needs a loadable identity (hard error); otherwise the
    // identity is optional and only decrypts protected paths at checkout.
    let sk = if with_secrets {
        Some(load_identity(identity)?)
    } else {
        resolve_identity_opt(identity)?
    };
    let outcomes = repo.work(scl_repo::WorkOptions {
        agents,
        base_name: name,
        cmd,
        author: resolve_author(author),
        message: None,
        identity: sk,
        with_secrets,
        session_root: None,
    })?;

    let mut failed = false;
    println!("workspace        agent   result");
    for o in &outcomes {
        let agent = match o.agent_exit {
            Some(0) => "ok".to_string(),
            Some(code) => {
                failed = true;
                format!("exit {code}")
            }
            None => {
                failed = true;
                "spawn failed".to_string()
            }
        };
        let result = match &o.harvest {
            Ok(scl_repo::HarvestResult::Committed(id)) => {
                format!("branch {} @ {}", o.label, id.short())
            }
            Ok(scl_repo::HarvestResult::Unchanged) => "unchanged".to_string(),
            Ok(scl_repo::HarvestResult::Rejected(report)) => {
                failed = true;
                format!("REJECTED by secret scanner ({} finding(s))", report.findings.len())
            }
            Err(e) => {
                failed = true;
                format!("harvest error: {e}")
            }
        };
        println!("{:<16} {:<7} {result}", o.label, agent);
    }
    if !failed {
        println!("\nintegrate with: sc merge <branch>");
    }
    // Drop before exit so the RepoLock's Drop runs (process::exit skips
    // destructors — same reasoning as run_run).
    drop(repo);
    std::process::exit(if failed { 1 } else { 0 });
}
```

(`id.short()` is the existing `ObjectId` short-hex helper used by `sc log`; if the printable form differs, match `run_log`'s usage.)

- [ ] **Step 3: Write the CLI-level integration test**

Create `crates/cli/tests/work.rs` (Cargo builds the `sc` binary for integration tests and exposes its path as `CARGO_BIN_EXE_sc`):

```rust
//! End-to-end `sc work` through the real binary: init → commit → work →
//! merge, asserting the summary, the branches, and full cleanup.
use std::process::Command;

#[test]
fn sc_work_end_to_end() {
    let sc = env!("CARGO_BIN_EXE_sc");
    let base = std::env::temp_dir().join(format!("sc-cli-work-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(sc).args(args).current_dir(&base).output().unwrap();
        assert!(
            out.status.success(),
            "sc {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    run(&["init"]);
    std::fs::write(base.join("a.txt"), "base\n").unwrap();
    run(&["commit", "-m", "base", "--author", "test"]);
    let summary = run(&[
        "work", "--agents", "2", "--author", "test", "--",
        "sh", "-c", "echo \"$SC_WORKSPACE\" > out.txt",
    ]);
    assert!(summary.contains("work-1"), "summary missing work-1:\n{summary}");
    assert!(summary.contains("work-2"), "summary missing work-2:\n{summary}");
    run(&["merge", "work-1", "--author", "test"]);
    assert_eq!(std::fs::read_to_string(base.join("out.txt")).unwrap(), "work-1\n");
    std::fs::remove_dir_all(&base).unwrap();
    assert!(!base.exists());
}
```

Run: `cargo test -p scl-cli --test work`
Expected: PASS. (If the merge flag spelling differs, match the real CLI — check the `Merge` variant in `main.rs`.)

- [ ] **Step 4: Build and run an end-to-end smoke test by hand**

```bash
cargo build --bin sc
d=$(mktemp -d); cd "$d"
"$OLDPWD"/target/debug/sc init
echo base > a.txt
"$OLDPWD"/target/debug/sc commit -m base
"$OLDPWD"/target/debug/sc work --agents 3 -- sh -c 'echo "$SC_WORKSPACE" > out.txt'
"$OLDPWD"/target/debug/sc log --json | head -5
cd "$OLDPWD"; rm -rf "$d"
```

Expected: summary table with `work-1..work-3` each `ok` and `branch work-<i> @ <id>`; exit code 0; no `sc-work-*` dir left in `$TMPDIR`.

- [ ] **Step 5: Run the whole suite**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/cli/src/main.rs crates/cli/tests/work.rs
git commit -m "feat(cli): sc work — fork N agent workspaces, run a command in each, harvest to branches (P13)"
```

---

### Task 8: `demo/run_work_demo.sh` — end-to-end proof

Scripted proof: parallel agents → branches → merge → zero residue, plus a `--with-secrets` leg. Model the script's structure (set -euo pipefail, temp dirs, before/after find diff) on `demo/run_ssh_remote_demo.sh` — read it first and match its conventions.

**Files:**
- Create: `demo/run_work_demo.sh` (chmod +x)

**Interfaces:**
- Consumes: the built `sc` binary (`cargo build --bin sc`), Task 7's command.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# P13 proof: sc work forks N agent workspaces, harvests them to branches,
# merge integrates them, and the session leaves zero residue outside .sc/.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

work=$(mktemp -d "${TMPDIR:-/tmp}/sc-work-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
mkdir -p "$repo"
cd "$repo"

echo "=== setup: persistent repo with a base commit ==="
"$SC" init
printf 'alpha\n' > alpha.txt
printf 'beta\n'  > beta.txt
"$SC" commit -m "base" --author demo

echo
echo "=== snapshot the filesystem outside .sc/ (before) ==="
before=$(mktemp "$work/before.XXXXXX")
find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'sc-work-*' > "$before" || true

echo
echo "=== sc work: 3 agents, each edits a distinct file ==="
"$SC" work --agents 3 --author demo -- \
  sh -c 'echo "edited by $SC_WORKSPACE" > "file-$SC_WORKSPACE.txt"'

echo
echo "=== three branches exist and merge cleanly ==="
for i in 1 2 3; do
  "$SC" merge "work-$i" --author demo
done
"$SC" log | head -12
for i in 1 2 3; do
  test -f "file-work-$i.txt" || { echo "FAIL: missing file-work-$i.txt"; exit 1; }
done
echo "all three agents' edits merged ✔"

echo
echo "=== secrets leg: agents see the decrypted secret in their env ==="
# Recipient bootstrap: same pattern as demo/run_lifecycle_demo.sh.
key="$work/identity"
pk=$("$SC" keygen --out "$key" | grep 'public key' | awk '{print $3}')
printf '[recipients]\ndemo = "%s"\n' "$pk" > .sc/recipients.toml
"$SC" secret add DEMO_TOKEN --to demo --value 'tok-123'
"$SC" work --agents 1 --name sec --with-secrets --identity "$key" --author demo -- \
  sh -c 'printf "len=%s" "${#DEMO_TOKEN}" > secret-proof.txt'
"$SC" merge sec-1 --author demo
grep -q 'len=7' secret-proof.txt && echo "secret reached the agent env ✔"

echo
echo "=== zero-residue proof: no session dirs left in TMPDIR ==="
after=$(mktemp "$work/after.XXXXXX")
find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'sc-work-*' > "$after" || true
diff "$before" "$after" && echo "no residual session directories ✔"

echo
echo "RESULT: parallel agents → branches → merge, zero residue ✔"
```

Implementer notes:
- The proof obligations are fixed: an agent process must observe `DEMO_TOKEN` with the sealed value's length (7 for `tok-123`), the value must not trip P5 patterns, and the final filesystem diff must be empty. If any CLI flag differs from the script, fix the script to match the CLI (verified against `demo/run_lifecycle_demo.sh`), not the other way around.

- [ ] **Step 2: Run it**

Run: `bash demo/run_work_demo.sh`
Expected: ends with `RESULT: parallel agents → branches → merge, zero residue ✔`, exit 0.

- [ ] **Step 3: Commit**

```bash
chmod +x demo/run_work_demo.sh
git add demo/run_work_demo.sh
git commit -m "demo: sc work round-trip proof — parallel agents, harvest, merge, zero residue (P13)"
```

---

### Task 9: Docs — CLAUDE.md, ARCHITECTURE.md, ROADMAP status, ADR-0023 → Accepted

**Files:**
- Modify: `CLAUDE.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `docs/adr/0023-agent-workspaces.md`

**Interfaces:**
- Consumes: everything shipped in Tasks 2–8, including any deviations discovered during the build (record them in the ADR).

- [ ] **Step 1: CLAUDE.md**

1. In `## Commands`, after the `escrow show` line, add:

```
cargo run --bin sc -- work --agents 3 -- <cmd>   # fork agent workspaces, run <cmd> in each,
                                                 # harvest changed ones to work-<i> branches
                                                 # (--with-secrets --identity <key> injects
                                                 # decrypted secrets into each agent env)
bash demo/run_work_demo.sh                       # parallel-agents round-trip proof
```

2. In the **Disk invariant is mode-scoped** bullet, replace the final sentence ("The two modes are mutually exclusive — a session is either ephemeral or persistent, never a mix.") with:

```markdown
  The two modes compose in exactly one way: a `sc work` session (P13) is a
  bounded ephemeral session *hosted by* a persistent repo — temp checkouts
  are removed on teardown, and the only durable writes go through the same
  commit path persistent mode already owns. Otherwise a session is either
  ephemeral or persistent, never a mix.
```

3. After the "Phase 12 is built." paragraph, add:

```markdown
**Phase 13 is built.** Agent workspaces: `sc work --agents N -- <cmd>` forks
N in-RAM copy-on-write workspaces from HEAD inside the repo's budget-bounded
persistent store (eviction is safe — the store on disk is the reconstruction
source; no spill backend in this path), materializes each to an ephemeral
temp checkout with P7-aware decryption, runs the agent commands concurrently
(`SC_WORKSPACE`/`SC_WORKSPACE_DIR` in env; `--with-secrets --identity <key>`
injects decrypted secrets via the `sc run` path), and harvests each changed
workspace through the full commit pipeline (`.scignore`, P5 scanner gate,
protected-path re-encryption) to a flat `work-<i>` branch — integration is
plain `sc merge`. HEAD, the current branch, and the user's working tree are
never touched; a failed agent's partial work is still harvested; teardown
leaves zero residue outside `.sc/`. Branch names are flat because the ref
grammar reserves `name/branch` for remote-tracking refs. See ADR-0023.
```

4. Update the "Remaining follow-ons" line: remove nothing, add `interactive workspace sessions and auto-merge of clean workspace results` to the list.

- [ ] **Step 2: ARCHITECTURE.md**

Add a `## Phase 13 — agent workspaces (built)` section after the Phase 12 section, condensing the CLAUDE.md paragraph above plus one architecture note:

```markdown
## Phase 13 — agent workspaces (built)

`sc work` is the fusion of Phase 1 and Phase 3: the session engine
(`crates/repo/src/workspace.rs`) forks N vfs worktrees from HEAD *inside the
repo's own budget-bounded persistent store*, so all forks share one Arc'd
blob cache and eviction never needs a spill backend — `.sc/objects` is the
reconstruction source. Checkout reuses the P7-aware `materialize`; harvest
reuses the commit pipeline (`snapshot_files`, extracted from `commit`), so
the P5 scanner and `.scignore` gate agent output exactly like a human
commit. Each changed workspace becomes a flat `work-<i>` branch (the ref
grammar reserves `/` for remote-tracking refs); merge is the ordinary P4
path. The session holds the single-writer lock end to end, and teardown is
Drop-guarded: zero residue outside `.sc/` on success, error, or panic.
```

Also update the "Remaining follow-ons" list in ARCHITECTURE.md the same way as CLAUDE.md's.

- [ ] **Step 3: ROADMAP.md + ADR-0023**

- Move the P13 entry from `## Active` into `## Done` (reword to past tense, cite ADR-0023) and delete the `## Active` section; add a P13 row to the completed-phases table:

```markdown
| **P13 — Agent workspaces** | Parallel agents on a real repo | `sc work --agents 3 -- <cmd>` forks 3 in-RAM workspaces, runs the command in each, harvests to `work-1..3` branches; `sc merge` integrates; zero residue outside `.sc/` | [0023](docs/adr/0023-agent-workspaces.md) |
```

- In `docs/adr/0023-agent-workspaces.md`: set `**Status:** Accepted`, and append a `## Refinements during the build` section recording any deviations from the plan (there will be some — e.g. actual scanner trigger strings, `Diff` field details, demo recipient bootstrap).

- [ ] **Step 4: Final full check**

Run: `cargo test && bash demo/run_work_demo.sh && bash demo/run_repo_demo.sh`
Expected: all pass — the pre-existing repo demo proves no regression.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md ARCHITECTURE.md ROADMAP.md docs/adr/0023-agent-workspaces.md
git commit -m "docs: accept ADR-0023 agent workspaces; record P13 in CLAUDE/ARCHITECTURE/ROADMAP"
```
