# Persistent Store + Native Repo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give src-control a durable on-disk repository (`.sc/` with loose content-addressed objects, named branches, HEAD, and a git-like working tree) so commits and committed secrets survive across separate `sc` invocations.

**Architecture:** `core::Store` gains a `Persistent(PathBuf)` backend that write-throughs every `put` to `.sc/objects/<hex>` and rehydrates on read-miss (eviction just drops the RAM copy; disk is authoritative). A new `scl-repo` crate owns the `.sc/` layout, refs/HEAD/branches, working-tree snapshot/materialize, and the `init`/`commit`/`status`/`log`/`branch`/`switch`/`secret`/`run` orchestration. The CLI is a thin shell over `scl-repo`.

**Tech Stack:** Rust 2021. Reuses `scl-core` (objects/store), `scl-vfs` (tree building, checkout), `scl-crypto` (Phase 2 secrets). New deps: none required beyond `thiserror`/`anyhow` already in use.

**Source spec:** `docs/superpowers/specs/2026-06-25-persistent-store-design.md`

---

## Execution prerequisites

- Branch off `main`: `git checkout -b persistent-store`.
- Run `cargo test` after each task. The Phase 1 (`sc demo`) and Phase 2 (`sc secret-demo`) ephemeral flows must keep working unchanged.

## File structure

**Modify:**
- `crates/core/src/store.rs` — add `Backend` enum; persistent write-through / load / evict; helpers; tests.
- `crates/core/src/lib.rs` — export `Backend`.
- `crates/cli/src/main.rs` — update `StoreConfig` construction to the new `backend` field; add the new subcommands (Task 8).
- `crates/vfs/src/lib.rs` — add public `write_tree` helper.
- `Cargo.toml` — add `crates/repo` to members.
- `ARCHITECTURE.md`, `CLAUDE.md`, `docs/adr/` — docs (Task 9).

**Create:**
- `crates/repo/Cargo.toml`, `crates/repo/src/lib.rs`, `error.rs`, `layout.rs`, `refs.rs`, `lock.rs`, `worktree.rs`, `repo.rs`, `secrets.rs`.
- `docs/adr/0011-persistent-store-and-working-tree.md`.
- `demo/run_repo_demo.sh` — end-to-end CLI proof.

---

## Task 1: `core::Store` persistent backend

**Files:**
- Modify: `crates/core/src/store.rs`
- Modify: `crates/core/src/lib.rs`

- [ ] **Step 1: Introduce the `Backend` enum and refactor `StoreConfig`**

In `crates/core/src/store.rs`, replace the `StoreConfig`/`SpillPolicy` region. Keep `SpillPolicy` as-is; add `Backend` and change `StoreConfig` to hold a `backend`:

```rust
/// What to do when the blob budget is exhausted (ephemeral mode only).
#[derive(Clone, Debug)]
pub enum SpillPolicy {
    /// Never spill: an over-budget insert returns `BudgetExceeded`.
    Disallow,
    /// Spill evicted blobs to this directory (created lazily, removed on drop).
    SpillTo(PathBuf),
}

/// Where objects live. Ephemeral is the Phase 1 RAM-first store; Persistent
/// write-throughs every object to a durable `.sc/objects/` directory.
#[derive(Clone, Debug)]
pub enum Backend {
    /// RAM + optional ephemeral spill; the spill dir is removed on `Drop`.
    Ephemeral(SpillPolicy),
    /// RAM + write-through to this objects directory; never removed on `Drop`.
    Persistent(PathBuf),
}

#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Maximum resident blob bytes. Trees/snapshots/secrets are not counted.
    pub budget_bytes: usize,
    pub backend: Backend,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            budget_bytes: 512 * 1024 * 1024,
            backend: Backend::Ephemeral(SpillPolicy::Disallow),
        }
    }
}
```

- [ ] **Step 2: Update `Store` fields and constructors**

Replace the `Store` struct and `new`/`with_budget` with backend-aware versions, and add `open_persistent`. The `spilled` map and spill bookkeeping are used only in ephemeral mode.

```rust
pub struct Store {
    cfg: StoreConfig,
    resident: HashMap<ObjectId, Resident>,
    /// Ephemeral-spill bookkeeping (unused in Persistent mode).
    spilled: HashMap<ObjectId, usize>,
    clock: u64,
    resident_blob_bytes: usize,
    spill_dir_ready: bool,
    evictions: u64,
    rehydrations: u64,
}

impl Store {
    pub fn new(cfg: StoreConfig) -> Self {
        Store {
            cfg,
            resident: HashMap::new(),
            spilled: HashMap::new(),
            clock: 0,
            resident_blob_bytes: 0,
            spill_dir_ready: false,
            evictions: 0,
            rehydrations: 0,
        }
    }

    pub fn with_budget(budget_bytes: usize) -> Self {
        Store::new(StoreConfig { budget_bytes, ..Default::default() })
    }

    /// Open (or create) a persistent store backed by `objects_dir`.
    pub fn open_persistent(objects_dir: impl Into<PathBuf>, budget_bytes: usize) -> Result<Self> {
        let dir = objects_dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Store::new(StoreConfig {
            budget_bytes,
            backend: Backend::Persistent(dir),
        }))
    }

    fn persistent_dir(&self) -> Option<&PathBuf> {
        match &self.cfg.backend {
            Backend::Persistent(p) => Some(p),
            Backend::Ephemeral(_) => None,
        }
    }
}
```

- [ ] **Step 3: Write-through `put` and persistent-aware `get`**

Replace `put` and `get` with backend-aware versions. In persistent mode, `put` writes the full `encode()` bytes to disk (all kinds) before admitting to RAM; `get` loads+verifies+decodes from disk on a miss.

```rust
    /// Insert an object, returning its content address. Idempotent. In
    /// persistent mode the object is durably written before returning.
    pub fn put(&mut self, obj: Object) -> Result<ObjectId> {
        let id = obj.id();
        if self.resident.contains_key(&id) || self.spilled.contains_key(&id) {
            return Ok(id);
        }
        // Persistent: write-through (idempotent) before admitting to RAM.
        if self.persistent_dir().is_some() {
            self.write_object_file(&id, &obj.encode())?;
        }
        let blob_size = obj.blob_size();
        if blob_size > 0 {
            self.ensure_capacity(blob_size, &id)?;
            self.resident_blob_bytes += blob_size;
        }
        let t = self.tick();
        self.resident.insert(id, Resident { obj, blob_size, last_used: t });
        Ok(id)
    }

    /// Fetch an object, rehydrating from the backend on a miss.
    pub fn get(&mut self, id: &ObjectId) -> Result<Object> {
        if let Some(r) = self.resident.get_mut(id) {
            r.last_used = {
                self.clock += 1;
                self.clock
            };
            return Ok(r.obj.clone());
        }
        // Ephemeral spill rehydrate (blobs only).
        if let Some(&size) = self.spilled.get(id) {
            let obj = self.read_spill(id)?;
            self.ensure_capacity(size, id)?;
            self.spilled.remove(id);
            self.resident_blob_bytes += size;
            self.rehydrations += 1;
            let t = self.tick();
            self.resident.insert(*id, Resident { obj: obj.clone(), blob_size: size, last_used: t });
            return Ok(obj);
        }
        // Persistent backend: load any object kind from disk.
        if self.persistent_dir().is_some() {
            let obj = self.read_object_file(id)?;
            let blob_size = obj.blob_size();
            if blob_size > 0 {
                self.ensure_capacity(blob_size, id)?;
                self.resident_blob_bytes += blob_size;
            }
            self.rehydrations += 1;
            let t = self.tick();
            self.resident.insert(*id, Resident { obj: obj.clone(), blob_size, last_used: t });
            return Ok(obj);
        }
        Err(Error::NotFound(*id))
    }
```

- [ ] **Step 4: `contains`, eviction, and the persistent file codec**

Update `contains` to consult disk; make `ensure_capacity` drop RAM in persistent mode; add the object-file read/write helpers.

Replace `contains`:

```rust
    pub fn contains(&self, id: &ObjectId) -> bool {
        if self.resident.contains_key(id) || self.spilled.contains_key(id) {
            return true;
        }
        if let Some(dir) = self.persistent_dir() {
            return dir.join(id.to_hex()).exists();
        }
        false
    }
```

In `ensure_capacity`, the eviction branch currently matches on `self.cfg.spill`. Replace that `match` with a `Backend` match so persistent mode just drops the RAM copy:

```rust
            match &self.cfg.backend {
                Backend::Ephemeral(SpillPolicy::Disallow) => {
                    let available = self.evictable_bytes(incoming);
                    return Err(Error::BudgetExceeded {
                        needed,
                        available,
                        budget: self.cfg.budget_bytes,
                    });
                }
                Backend::Ephemeral(SpillPolicy::SpillTo(_)) => self.evict_to_spill(&victim)?,
                Backend::Persistent(_) => self.drop_resident_blob(&victim),
            }
```

Update `spill_dir()` to read from the backend (used by `evict_to_spill`/`ensure_spill_dir`/`Drop`):

```rust
    fn spill_dir(&self) -> Option<&PathBuf> {
        match &self.cfg.backend {
            Backend::Ephemeral(SpillPolicy::SpillTo(p)) => Some(p),
            _ => None,
        }
    }
```

Add the new helpers (next to the spill helpers):

```rust
    /// Persistent eviction: drop the RAM copy; the durable file is authoritative.
    fn drop_resident_blob(&mut self, id: &ObjectId) {
        if let Some(r) = self.resident.remove(id) {
            self.resident_blob_bytes -= r.blob_size;
            self.evictions += 1;
        }
    }

    /// Write `encode()` bytes to `objects/<hex>` idempotently (tmp + rename).
    fn write_object_file(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        let dir = self.persistent_dir().expect("persistent backend").clone();
        let final_path = dir.join(id.to_hex());
        if final_path.exists() {
            return Ok(());
        }
        let tmp = dir.join(format!("{}.tmp", id.to_hex()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &final_path)?;
        Ok(())
    }

    /// Read+verify+decode an object file. Hash mismatch => `Malformed`.
    fn read_object_file(&self, id: &ObjectId) -> Result<Object> {
        let dir = self.persistent_dir().ok_or(Error::NotFound(*id))?;
        let path = dir.join(id.to_hex());
        let bytes = std::fs::read(&path).map_err(|_| Error::NotFound(*id))?;
        if ObjectId::of(&bytes) != *id {
            return Err(Error::Malformed(format!("object {id} failed hash verification on read")));
        }
        Object::decode(&bytes)
    }
```

> Note: `read_object_file` returns `Error::Malformed` on a hash mismatch. `scl-repo` maps that to its own `CorruptObject` for callers (Task 3). `core` keeps no new error variant.

- [ ] **Step 5: Update `Drop` and existing call sites**

`Drop` already keys off `spill_dir_ready` + `spill_dir()`; since `spill_dir()` now returns `None` for `Persistent`, the persistent objects dir is never removed — no change needed beyond Step 4's `spill_dir()`. Verify the `Drop` impl still reads:

```rust
impl Drop for Store {
    fn drop(&mut self) {
        if self.spill_dir_ready {
            if let Some(dir) = self.spill_dir() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}
```

Update the existing `store.rs` tests that build `StoreConfig { budget_bytes, spill: ... }` to the new shape `StoreConfig { budget_bytes, backend: Backend::Ephemeral(...) }`. Specifically `lru_eviction_with_spill_roundtrips` becomes:

```rust
        let mut s = Store::new(StoreConfig {
            budget_bytes: 150,
            backend: Backend::Ephemeral(SpillPolicy::SpillTo(dir.clone())),
        });
```

- [ ] **Step 6: Export `Backend`**

In `crates/core/src/lib.rs`, add `Backend` to the `pub use store::{...}` line:

```rust
pub use store::{Backend, SpillPolicy, Store, StoreConfig, StoreStats};
```

- [ ] **Step 7: Add persistent-backend tests**

Add to the `tests` module in `crates/core/src/store.rs`:

```rust
    use crate::object::{Object, Snapshot, Tree};
    use std::collections::BTreeMap;

    fn temp_objects_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("scl-persist-{tag}-{}", std::process::id()))
    }

    #[test]
    fn persistent_put_then_reopen_reads_all_kinds() {
        let dir = temp_objects_dir("reopen");
        let _ = std::fs::remove_dir_all(&dir);
        let blob_id;
        let snap_id;
        {
            let mut s = Store::open_persistent(&dir, 1024).unwrap();
            blob_id = s.put(Object::blob(b"hello".to_vec())).unwrap();
            let root = s.put(Object::Tree(Tree::new(vec![]))).unwrap();
            snap_id = s
                .put(Object::Snapshot(Snapshot {
                    root,
                    parents: vec![],
                    author: "a".into(),
                    timestamp: 0,
                    message: "m".into(),
                    secrets: BTreeMap::new(),
                }))
                .unwrap();
        } // store dropped; nothing deleted
        // Reopen on the same dir: resident cache is empty, must load from disk.
        let mut s2 = Store::open_persistent(&dir, 1024).unwrap();
        assert_eq!(&s2.get(&blob_id).unwrap().encode(), &Object::blob(b"hello".to_vec()).encode());
        assert!(matches!(s2.get(&snap_id).unwrap(), Object::Snapshot(_)));
        drop(s2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persistent_corrupt_object_fails_hash_verify() {
        let dir = temp_objects_dir("corrupt");
        let _ = std::fs::remove_dir_all(&dir);
        let id;
        {
            let mut s = Store::open_persistent(&dir, 1024).unwrap();
            id = s.put(Object::blob(b"data".to_vec())).unwrap();
        }
        // Corrupt the file on disk.
        std::fs::write(dir.join(id.to_hex()), b"tampered").unwrap();
        let mut s2 = Store::open_persistent(&dir, 1024).unwrap();
        assert!(matches!(s2.get(&id), Err(Error::Malformed(_))));
        drop(s2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persistent_eviction_drops_ram_but_reloads_from_disk() {
        let dir = temp_objects_dir("evict");
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = Store::open_persistent(&dir, 150).unwrap();
        let a = s.put(Object::blob(vec![0xAA; 100])).unwrap();
        let _b = s.put(Object::blob(vec![0xBB; 100])).unwrap(); // forces a to evict from RAM
        assert!(s.stats().evictions >= 1);
        // a is gone from RAM but on disk; get reloads it.
        match s.get(&a).unwrap() {
            Object::Blob(b) => assert!(b.iter().all(|&x| x == 0xAA)),
            _ => panic!("wrong kind"),
        }
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
```

- [ ] **Step 8: Run tests and commit**

Run: `cargo test -p scl-core`
Expected: PASS (existing + 3 new persistent tests). Then fix CLI call sites if the workspace build breaks — but that is Task 8; scope this commit with `cargo test -p scl-core`.

```bash
git add crates/core/src/store.rs crates/core/src/lib.rs
git commit -m "feat(core): persistent write-through Store backend"
```

> The workspace will not fully build until the CLI call sites are updated (Task 8). `scl-vfs` uses `StoreConfig::default()` (unaffected). `scl-cli` constructs `StoreConfig { .. spill }` and WILL break — that is fixed in Task 8. Per-crate `cargo test -p scl-core` is green now.

---

## Task 2: `vfs` public `write_tree` helper

**Files:**
- Modify: `crates/vfs/src/lib.rs`

- [ ] **Step 1: Add the helper**

`scl-repo` needs to build a root tree from a flat working-tree file list without creating a snapshot. Add this method to `impl Repo` (it reuses the existing private `build_tree`):

```rust
    /// Put each file's blob and build the directory trees, returning the root
    /// tree id. Does not create a snapshot. Used by the persistent repo layer to
    /// snapshot a working directory.
    pub fn write_tree(&self, files: &[(String, Vec<u8>, FileMode)]) -> Result<ObjectId> {
        let mut map: BTreeMap<String, (ObjectId, FileMode)> = BTreeMap::new();
        {
            let mut store = self.store.lock().unwrap();
            for (path, bytes, mode) in files {
                let id = store.put(Object::blob(bytes.clone()))?;
                map.insert(normalize(path), (id, *mode));
            }
        }
        self.build_tree(&map)
    }
```

- [ ] **Step 2: Add a test**

Add to the `vfs` tests module:

```rust
    #[test]
    fn write_tree_then_fork_reads_files() {
        let r = repo();
        let root = r
            .write_tree(&[
                ("a.txt".into(), b"A".to_vec(), FileMode::FILE),
                ("dir/b.txt".into(), b"B".to_vec(), FileMode::FILE),
            ])
            .unwrap();
        let snap = {
            let mut store = r.store().lock().unwrap();
            store
                .put(Object::Snapshot(scl_core::Snapshot {
                    root,
                    parents: vec![],
                    author: "t".into(),
                    timestamp: 0,
                    message: "m".into(),
                    secrets: std::collections::BTreeMap::new(),
                }))
                .unwrap()
        };
        let wt = r.fork(snap, "v").unwrap();
        assert_eq!(&wt.read("a.txt").unwrap()[..], b"A");
        assert_eq!(&wt.read("dir/b.txt").unwrap()[..], b"B");
    }
```

- [ ] **Step 3: Run tests and commit**

Run: `cargo test -p scl-vfs`
Expected: PASS.

```bash
git add crates/vfs/src/lib.rs
git commit -m "feat(vfs): public write_tree helper for the repo layer"
```

---

## Task 3: `scl-repo` scaffold — layout, refs, lock

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/repo/Cargo.toml`, `crates/repo/src/lib.rs`, `crates/repo/src/error.rs`, `crates/repo/src/layout.rs`, `crates/repo/src/refs.rs`, `crates/repo/src/lock.rs`

- [ ] **Step 1: Add the crate to the workspace**

`Cargo.toml` members line:

```toml
members = ["crates/core", "crates/vfs", "crates/gitio", "crates/crypto", "crates/repo", "crates/cli"]
```

- [ ] **Step 2: Manifest**

Create `crates/repo/Cargo.toml`:

```toml
[package]
name = "scl-repo"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
scl-core = { path = "../core" }
scl-vfs = { path = "../vfs" }
scl-crypto = { path = "../crypto" }
thiserror = "2.0.18"
```

- [ ] **Step 3: Error type**

Create `crates/repo/src/error.rs`:

```rust
//! Errors for the persistent repository layer.

use scl_core::ObjectId;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a src-control repo (no .sc directory at or above the working dir)")]
    NotARepo,
    #[error("a repo already exists at {0}")]
    RepoExists(String),
    #[error("repo is locked by another process (remove {0} if stale)")]
    Locked(String),
    #[error("object {0} is corrupt (failed hash verification on read)")]
    CorruptObject(ObjectId),
    #[error("malformed ref: {0}")]
    BadRef(String),
    #[error("branch not found: {0}")]
    NoSuchBranch(String),
    #[error("operation requires at least one commit (branch is unborn)")]
    Unborn,
    #[error(transparent)]
    Core(#[from] scl_core::Error),
    #[error(transparent)]
    Vfs(#[from] scl_vfs::Error),
    #[error(transparent)]
    Crypto(#[from] scl_crypto::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 4: Layout (paths)**

Create `crates/repo/src/layout.rs`:

```rust
//! On-disk `.sc/` directory layout.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Resolved paths for a repo rooted at the directory containing `.sc/`.
#[derive(Clone, Debug)]
pub struct Layout {
    pub root: PathBuf,
    pub dot_sc: PathBuf,
}

impl Layout {
    /// The directory containing `.sc` for `root`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let dot_sc = root.join(".sc");
        Layout { root, dot_sc }
    }

    /// Search `start` and its ancestors for a `.sc/` directory.
    pub fn discover(start: impl AsRef<Path>) -> Result<Layout> {
        let mut cur = Some(start.as_ref().to_path_buf());
        while let Some(dir) = cur {
            if dir.join(".sc").is_dir() {
                return Ok(Layout::at(dir));
            }
            cur = dir.parent().map(|p| p.to_path_buf());
        }
        Err(Error::NotARepo)
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.dot_sc.join("objects")
    }
    pub fn refs_heads_dir(&self) -> PathBuf {
        self.dot_sc.join("refs").join("heads")
    }
    pub fn head_path(&self) -> PathBuf {
        self.dot_sc.join("HEAD")
    }
    pub fn lock_path(&self) -> PathBuf {
        self.dot_sc.join("lock")
    }
    pub fn ref_path(&self, branch: &str) -> PathBuf {
        self.refs_heads_dir().join(branch)
    }
}
```

- [ ] **Step 5: Refs + HEAD**

Create `crates/repo/src/refs.rs`:

```rust
//! HEAD and branch ref reading/writing. HEAD is symbolic (names a branch).

use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

const HEAD_PREFIX: &str = "ref: refs/heads/";

/// Write `HEAD` as a symbolic ref to `branch`.
pub fn write_head(layout: &Layout, branch: &str) -> Result<()> {
    atomic_write(&layout.head_path(), format!("{HEAD_PREFIX}{branch}\n").as_bytes())
}

/// The branch currently named by `HEAD`.
pub fn current_branch(layout: &Layout) -> Result<String> {
    let text = std::fs::read_to_string(layout.head_path())?;
    let line = text.trim();
    line.strip_prefix(HEAD_PREFIX)
        .map(|b| b.to_string())
        .ok_or_else(|| Error::BadRef(format!("HEAD is not symbolic: {line}")))
}

/// The tip snapshot of `branch`, or `None` if the branch is unborn.
pub fn read_branch_tip(layout: &Layout, branch: &str) -> Result<Option<ObjectId>> {
    let path = layout.ref_path(branch);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let hex = text.trim();
            ObjectId::from_str(hex)
                .map(Some)
                .map_err(|_| Error::BadRef(format!("ref {branch} has bad id: {hex}")))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Point `branch` at `id` (atomic).
pub fn write_branch_tip(layout: &Layout, branch: &str, id: &ObjectId) -> Result<()> {
    std::fs::create_dir_all(layout.refs_heads_dir())?;
    atomic_write(&layout.ref_path(branch), format!("{}\n", id.to_hex()).as_bytes())
}

/// The tip of the branch HEAD names (or None if unborn).
pub fn head_tip(layout: &Layout) -> Result<Option<ObjectId>> {
    read_branch_tip(layout, &current_branch(layout)?)
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
```

> `ObjectId::from_str` must exist. If `scl-core`'s `ObjectId` lacks `FromStr`, add it in `crates/core/src/id.rs` parsing 64 hex chars into `[u8;32]` (returning `Error::Malformed` on bad input), and re-export remains unchanged. Verify before relying on it.

- [ ] **Step 6: Lock**

Create `crates/repo/src/lock.rs`:

```rust
//! Single-writer repo lock via an exclusive lock file.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// RAII guard; removes the lock file on drop.
pub struct RepoLock {
    path: PathBuf,
}

impl RepoLock {
    /// Acquire the lock, or `Error::Locked` if already held.
    pub fn acquire(layout: &Layout) -> Result<RepoLock> {
        let path = layout.lock_path();
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => Ok(RepoLock { path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(Error::Locked(path.display().to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
```

- [ ] **Step 7: lib.rs wiring + tests**

Create `crates/repo/src/lib.rs`:

```rust
//! `scl-repo` — the durable on-disk repository: `.sc/` layout, refs/HEAD,
//! named branches, a git-like working tree, and commit/secret orchestration.

pub mod error;
pub mod layout;
pub mod lock;
pub mod refs;
pub mod repo;
pub mod secrets;
pub mod worktree;

pub use error::{Error, Result};
pub use repo::{Repo, Status};
```

> `repo`, `secrets`, `worktree` modules are created in Tasks 4–7. To build/test Task 3 in isolation, temporarily comment those three `pub mod` lines and the `pub use repo::...` line, then restore them in Task 4. (Alternatively do Tasks 3–7 as one unit and build at the end of Task 7.)

Add a test file section at the bottom of `refs.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::RepoLock;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-repo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(layout.refs_heads_dir()).unwrap();
        layout
    }

    #[test]
    fn head_and_branch_roundtrip() {
        let layout = tmp_layout("refs");
        write_head(&layout, "main").unwrap();
        assert_eq!(current_branch(&layout).unwrap(), "main");
        assert_eq!(head_tip(&layout).unwrap(), None); // unborn
        let id = ObjectId::of(b"snap");
        write_branch_tip(&layout, "main", &id).unwrap();
        assert_eq!(head_tip(&layout).unwrap(), Some(id));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn lock_is_exclusive() {
        let layout = tmp_layout("lock");
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        let l1 = RepoLock::acquire(&layout).unwrap();
        assert!(matches!(RepoLock::acquire(&layout), Err(Error::Locked(_))));
        drop(l1);
        let _l2 = RepoLock::acquire(&layout).unwrap(); // freed
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
```

- [ ] **Step 8: Run tests and commit**

Run: `cargo test -p scl-repo` (with the temporary module comments from Step 7 if doing Task 3 alone).
Expected: PASS (refs + lock tests). Also confirm/add `ObjectId::from_str` per Step 5's note.

```bash
git add Cargo.toml crates/repo crates/core/src/id.rs
git commit -m "feat(repo): scaffold scl-repo with layout, refs, lock"
```

---

## Task 4: Working-tree read / materialize / status diff

**Files:**
- Create: `crates/repo/src/worktree.rs`

- [ ] **Step 1: Implement worktree helpers**

Create `crates/repo/src/worktree.rs`:

```rust
//! Reading the on-disk working tree and diffing it against a snapshot.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{EntryKind, FileMode, ObjectId, Object, Store, Tree};

use crate::error::Result;
use crate::layout::Layout;

/// Read all working-tree files (skipping `.sc/`) as `(relpath, bytes, mode)`.
pub fn read_worktree(layout: &Layout) -> Result<Vec<(String, Vec<u8>, FileMode)>> {
    let mut out = Vec::new();
    walk_disk(&layout.root, &layout.root, &layout.dot_sc, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_disk(
    base: &Path,
    dir: &Path,
    skip: &Path,
    out: &mut Vec<(String, Vec<u8>, FileMode)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == skip {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_disk(base, &path, skip, out)?;
        } else if ft.is_file() {
            let rel = path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            let bytes = std::fs::read(&path)?;
            let mode = file_mode(&path);
            out.push((rel, bytes, mode));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(path: &Path) -> FileMode {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) if m.permissions().mode() & 0o111 != 0 => FileMode::EXEC,
        _ => FileMode::FILE,
    }
}
#[cfg(not(unix))]
fn file_mode(_path: &Path) -> FileMode {
    FileMode::FILE
}

/// Flatten a snapshot's root tree to `path -> blob id`.
pub fn tree_file_ids(store: &mut Store, root: ObjectId) -> Result<BTreeMap<String, ObjectId>> {
    let mut out = BTreeMap::new();
    walk_tree(store, root, String::new(), &mut out)?;
    Ok(out)
}

fn walk_tree(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    out: &mut BTreeMap<String, ObjectId>,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        match e.kind {
            EntryKind::Blob => {
                out.insert(path, e.id);
            }
            EntryKind::Tree => walk_tree(store, e.id, path, out)?,
        }
    }
    Ok(())
}

/// Difference between the working tree and a snapshot's root tree.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

/// Diff the working tree against `head_root` (None => unborn: all files added).
pub fn diff_worktree(
    layout: &Layout,
    store: &mut Store,
    head_root: Option<ObjectId>,
) -> Result<Diff> {
    let wt: BTreeMap<String, ObjectId> = read_worktree(layout)?
        .into_iter()
        .map(|(p, b, _)| (p, Object::blob(b).id()))
        .collect();
    let head = match head_root {
        Some(root) => tree_file_ids(store, root)?,
        None => BTreeMap::new(),
    };
    let mut diff = Diff::default();
    for (p, id) in &wt {
        match head.get(p) {
            None => diff.added.push(p.clone()),
            Some(hid) if hid != id => diff.modified.push(p.clone()),
            _ => {}
        }
    }
    for p in head.keys() {
        if !wt.contains_key(p) {
            diff.deleted.push(p.clone());
        }
    }
    Ok(diff)
}

/// Materialize a snapshot's file tree into the working dir, deleting working
/// files that are tracked by `old_root` but absent from the target.
pub fn materialize(
    layout: &Layout,
    store: &mut Store,
    target_root: ObjectId,
    old_root: Option<ObjectId>,
) -> Result<()> {
    let target = tree_file_ids(store, target_root)?;
    if let Some(old) = old_root {
        for p in tree_file_ids(store, old)?.keys() {
            if !target.contains_key(p) {
                let _ = std::fs::remove_file(layout.root.join(p));
            }
        }
    }
    for (path, blob_id) in &target {
        let bytes = match store.get(blob_id)? {
            Object::Blob(b) => b,
            _ => continue,
        };
        let full = layout.root.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&full, &bytes[..])?;
    }
    Ok(())
}
```

- [ ] **Step 2: Restore the `pub mod worktree;` line** in `lib.rs` if it was commented in Task 3.

- [ ] **Step 3: Run tests and commit**

Run: `cargo build -p scl-repo`
Expected: compiles. (Behavioral tests for these helpers come via the repo command tests in Task 5–6.)

```bash
git add crates/repo/src/worktree.rs crates/repo/src/lib.rs
git commit -m "feat(repo): working-tree read, diff, and materialize"
```

---

## Task 5: `Repo` — init, open, commit, log

**Files:**
- Create: `crates/repo/src/repo.rs`

- [ ] **Step 1: Implement the Repo core**

Create `crates/repo/src/repo.rs`:

```rust
//! The persistent repository: ties a persistent `Store` to the `.sc/` layout.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{Object, ObjectId, Snapshot, Store};
use scl_vfs::Repo as VfsRepo;

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lock::RepoLock;
use crate::refs;
use crate::worktree::{self, Diff};

const DEFAULT_BRANCH: &str = "main";
const DEFAULT_BUDGET: usize = 512 * 1024 * 1024;

/// Working-tree status against HEAD.
pub type Status = Diff;

/// A handle to an open persistent repo. Holds the single-writer lock for its
/// lifetime.
pub struct Repo {
    layout: Layout,
    vfs: VfsRepo,
    _lock: RepoLock,
}

impl Repo {
    /// Create a new repo at `root` (errors if `.sc/` already exists).
    pub fn init(root: impl AsRef<Path>) -> Result<Repo> {
        let layout = Layout::at(root.as_ref());
        if layout.dot_sc.exists() {
            return Err(Error::RepoExists(layout.dot_sc.display().to_string()));
        }
        std::fs::create_dir_all(layout.objects_dir())?;
        std::fs::create_dir_all(layout.refs_heads_dir())?;
        refs::write_head(&layout, DEFAULT_BRANCH)?;
        Self::open_layout(layout)
    }

    /// Open an existing repo by discovering `.sc/` at or above `start`.
    pub fn open(start: impl AsRef<Path>) -> Result<Repo> {
        let layout = Layout::discover(start)?;
        Self::open_layout(layout)
    }

    fn open_layout(layout: Layout) -> Result<Repo> {
        let lock = RepoLock::acquire(&layout)?;
        let store = Store::open_persistent(layout.objects_dir(), DEFAULT_BUDGET)?;
        Ok(Repo { layout, vfs: VfsRepo::new(store), _lock: lock })
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The tip snapshot of the current branch (None if unborn).
    pub fn head_tip(&self) -> Result<Option<ObjectId>> {
        refs::head_tip(&self.layout)
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.vfs.store().lock().unwrap()
    }

    /// The root tree of the current tip (None if unborn).
    fn head_root(&self) -> Result<Option<ObjectId>> {
        match self.head_tip()? {
            Some(tip) => Ok(Some(self.store().get_snapshot(&tip)?.root)),
            None => Ok(None),
        }
    }

    /// Snapshot the working tree into a new commit on the current branch.
    pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
        let files = worktree::read_worktree(&self.layout)?;
        let root = self.vfs.write_tree(&files)?;
        let tip = self.head_tip()?;
        let secrets = match tip {
            Some(t) => self.store().get_snapshot(&t)?.secrets,
            None => BTreeMap::new(),
        };
        self.commit_snapshot(root, tip, secrets, author, message)
    }

    /// Build + persist a snapshot and advance the current branch ref.
    pub(crate) fn commit_snapshot(
        &self,
        root: ObjectId,
        parent: Option<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let snap = Object::Snapshot(Snapshot {
            root,
            parents: parent.into_iter().collect(),
            author: author.to_string(),
            timestamp: 0,
            message: message.to_string(),
            secrets,
        });
        let id = self.store().put(snap)?;
        let branch = refs::current_branch(&self.layout)?;
        refs::write_branch_tip(&self.layout, &branch, &id)?;
        Ok(id)
    }

    /// Working-tree status against HEAD.
    pub fn status(&self) -> Result<Status> {
        let head_root = self.head_root()?;
        let mut store = self.store();
        worktree::diff_worktree(&self.layout, &mut store, head_root)
    }

    /// Snapshots from the current tip back through parents (newest first).
    pub fn log(&self) -> Result<Vec<(ObjectId, Snapshot)>> {
        let mut out = Vec::new();
        let mut next = self.head_tip()?;
        while let Some(id) = next {
            let snap = self.store().get_snapshot(&id)?;
            next = snap.parents.first().copied();
            out.push((id, snap));
        }
        Ok(out)
    }
}
```

- [ ] **Step 2: Restore `pub mod repo;` / `pub use repo::{Repo, Status};`** in `lib.rs` if commented.

- [ ] **Step 3: Add tests**

Add at the bottom of `repo.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-cmd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn init_commit_reopen_log() {
        let root = tmp_root("commit");
        {
            let repo = Repo::init(&root).unwrap();
            std::fs::write(root.join("README.md"), b"hello").unwrap();
            repo.commit("me", "first").unwrap();
        } // drop releases lock + Store
        let repo2 = Repo::open(&root).unwrap();
        let log = repo2.log().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1.message, "first");
        drop(repo2);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn status_reports_add_modify_delete() {
        let root = tmp_root("status");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("keep.txt"), b"v1").unwrap();
        std::fs::write(root.join("gone.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();
        // modify keep, delete gone, add new
        std::fs::write(root.join("keep.txt"), b"v2").unwrap();
        std::fs::remove_file(root.join("gone.txt")).unwrap();
        std::fs::write(root.join("new.txt"), b"n").unwrap();
        let s = repo.status().unwrap();
        assert_eq!(s.added, vec!["new.txt"]);
        assert_eq!(s.modified, vec!["keep.txt"]);
        assert_eq!(s.deleted, vec!["gone.txt"]);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p scl-repo`
Expected: PASS.

```bash
git add crates/repo/src/repo.rs crates/repo/src/lib.rs
git commit -m "feat(repo): init, commit, status, log"
```

---

## Task 6: `Repo` — branch and switch

**Files:**
- Modify: `crates/repo/src/repo.rs`

- [ ] **Step 1: Add branch/switch methods**

Add to `impl Repo`:

```rust
    /// List branch names (sorted) and whether each is the current HEAD branch.
    pub fn branches(&self) -> Result<Vec<(String, bool)>> {
        let current = refs::current_branch(&self.layout)?;
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.layout.refs_heads_dir()) {
            for e in entries {
                let e = e?;
                if e.file_type()?.is_file() {
                    names.push(e.file_name().to_string_lossy().into_owned());
                }
            }
        }
        names.sort();
        Ok(names.into_iter().map(|n| (n.clone(), n == current)).collect())
    }

    /// Create `name` pointing at the current tip (errors if unborn or exists).
    pub fn branch(&self, name: &str) -> Result<()> {
        if self.layout.ref_path(name).exists() {
            return Err(Error::BadRef(format!("branch already exists: {name}")));
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        refs::write_branch_tip(&self.layout, name, &tip)
    }

    /// Switch HEAD to `name` and materialize its tip into the working tree.
    pub fn switch(&self, name: &str) -> Result<()> {
        let target_tip = refs::read_branch_tip(&self.layout, name)?
            .ok_or_else(|| Error::NoSuchBranch(name.to_string()))?;
        let old_root = self.head_root()?;
        let target_root = self.store().get_snapshot(&target_tip)?.root;
        {
            let mut store = self.store();
            worktree::materialize(&self.layout, &mut store, target_root, old_root)?;
        }
        refs::write_head(&self.layout, name)
    }
```

- [ ] **Step 2: Add a test**

Add to the `repo.rs` tests module:

```rust
    #[test]
    fn branch_switch_materializes_and_repoints_head() {
        let root = tmp_root("branch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"on-main").unwrap();
        repo.commit("me", "main work").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        // commit a feature-only file
        std::fs::write(root.join("feature.txt"), b"f").unwrap();
        repo.commit("me", "feature work").unwrap();
        assert!(root.join("feature.txt").exists());
        // switch back to main: feature.txt must disappear, a.txt remain
        repo.switch("main").unwrap();
        assert!(!root.join("feature.txt").exists());
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"on-main");
        let branches = repo.branches().unwrap();
        assert!(branches.contains(&("main".to_string(), true)));
        assert!(branches.contains(&("feature".to_string(), false)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
```

- [ ] **Step 3: Run tests and commit**

Run: `cargo test -p scl-repo`
Expected: PASS.

```bash
git add crates/repo/src/repo.rs
git commit -m "feat(repo): named branches and switch"
```

---

## Task 7: `Repo` — secrets ops + run (cross-invocation proof)

**Files:**
- Create: `crates/repo/src/secrets.rs`

- [ ] **Step 1: Implement secrets ops + run**

Create `crates/repo/src/secrets.rs`:

```rust
//! Committed-secrets operations on a persistent repo. Each op produces a new
//! snapshot carrying the updated registry onto the current branch.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Command;

use scl_core::{Object, ObjectId};
use scl_crypto::{PublicKey, RecipientId, SecretKey};

use crate::error::{Error, Result};
use crate::repo::Repo;

/// One entry for `secret list`: name and how many recipients can read it.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretInfo {
    pub name: String,
    pub recipients: usize,
}

impl Repo {
    /// The current tip's secret registry (empty if unborn).
    fn registry(&self) -> Result<BTreeMap<String, ObjectId>> {
        match self.head_tip()? {
            Some(t) => Ok(self.snapshot(&t)?.secrets),
            None => Ok(BTreeMap::new()),
        }
    }

    /// Read a snapshot (helper to keep the store lock local).
    fn snapshot(&self, id: &ObjectId) -> Result<scl_core::Snapshot> {
        Ok(self.vfs_store().get_snapshot(id)?)
    }

    fn vfs_store(&self) -> std::sync::MutexGuard<'_, scl_core::Store> {
        self.vfs_handle().store().lock().unwrap()
    }

    /// Commit a changed registry, keeping the tip's file tree.
    fn commit_registry(
        &self,
        registry: BTreeMap<String, ObjectId>,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let tip = self.head_tip()?;
        let root = match tip {
            Some(t) => self.snapshot(&t)?.root,
            None => self.vfs_handle().write_tree(&[])?, // empty tree
        };
        self.commit_snapshot(root, tip, registry, author, message)
    }

    /// Seal `value` to `recipients` and register it under `name`.
    pub fn secret_add(&self, name: &str, value: &[u8], recipients: &[PublicKey]) -> Result<ObjectId> {
        let secret = scl_crypto::seal(name, value, recipients);
        let id = self.vfs_store().put(Object::Secret(secret))?;
        let mut reg = self.registry()?;
        reg.insert(name.to_string(), id);
        self.commit_registry(reg, "secret", &format!("add secret {name}"))
    }

    /// Grant `new` access to `name` by re-wrapping the DEK with `authorized`.
    pub fn secret_grant(&self, name: &str, authorized: &SecretKey, new: &PublicKey) -> Result<ObjectId> {
        let mut reg = self.registry()?;
        let sid = *reg.get(name).ok_or_else(|| Error::BadRef(format!("no secret {name}")))?;
        let secret = match self.vfs_store().get(&sid)? {
            Object::Secret(s) => s,
            _ => return Err(Error::BadRef(format!("{name} is not a secret"))),
        };
        let regranted = scl_crypto::rewrap_for(&secret, authorized, new)?;
        let new_id = self.vfs_store().put(Object::Secret(regranted))?;
        reg.insert(name.to_string(), new_id);
        self.commit_registry(reg, "secret", &format!("grant {name}"))
    }

    /// Revoke a recipient from `name` (metadata-only re-wrap).
    pub fn secret_revoke(&self, name: &str, recipient: &RecipientId) -> Result<ObjectId> {
        let mut reg = self.registry()?;
        let sid = *reg.get(name).ok_or_else(|| Error::BadRef(format!("no secret {name}")))?;
        let secret = match self.vfs_store().get(&sid)? {
            Object::Secret(s) => s,
            _ => return Err(Error::BadRef(format!("{name} is not a secret"))),
        };
        let revoked = scl_crypto::revoke(&secret, recipient);
        let new_id = self.vfs_store().put(Object::Secret(revoked))?;
        reg.insert(name.to_string(), new_id);
        self.commit_registry(reg, "secret", &format!("revoke from {name}"))
    }

    /// List secrets at HEAD with recipient counts.
    pub fn secret_list(&self) -> Result<Vec<SecretInfo>> {
        let reg = self.registry()?;
        let mut out = Vec::new();
        for (name, id) in reg {
            if let Object::Secret(s) = self.vfs_store().get(&id)? {
                out.push(SecretInfo { name, recipients: s.wrapped_keys.len() });
            }
        }
        Ok(out)
    }

    /// Decrypt all secrets the `identity` can read, inject into the environment,
    /// and run `cmd`. Secrets the identity cannot read are skipped with a
    /// stderr warning; a corrupt/tampered secret is a hard error. Returns the
    /// child's exit code.
    pub fn run(&self, identity: &SecretKey, cmd: &[String]) -> Result<i32> {
        let reg = self.registry()?;
        let mut envs: Vec<(String, OsString)> = Vec::new();
        for (name, id) in reg {
            let secret = match self.vfs_store().get(&id)? {
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
                    let val = OsString::from(
                        std::str::from_utf8(&plaintext)
                            .map_err(|_| Error::BadRef(format!("secret {name} not UTF-8")))?,
                    );
                    envs.push((name, val));
                }
                Err(scl_crypto::Error::NotARecipient) => {
                    eprintln!("warning: not authorized for secret {name}; skipping");
                }
                Err(e) => return Err(e.into()),
            }
        }
        let (exe, args) = cmd.split_first().ok_or_else(|| Error::BadRef("empty command".into()))?;
        let mut command = Command::new(exe);
        command.args(args);
        for (k, v) in &envs {
            command.env(k, v);
        }
        let status = command.status()?;
        Ok(status.code().unwrap_or(1))
    }
}
```

> This task needs two small accessors on `Repo` (from Task 5's `repo.rs`): make `commit_snapshot` already `pub(crate)`, and add a `pub(crate) fn vfs_handle(&self) -> &scl_vfs::Repo { &self.vfs }`. Add that accessor to `impl Repo` in `repo.rs`. Replace the `self.store()` private helper usages here with `self.vfs_store()` defined above (they lock the same store).

- [ ] **Step 2: Add the `vfs_handle` accessor to `repo.rs`**

In `crates/repo/src/repo.rs`, add to `impl Repo`:

```rust
    pub(crate) fn vfs_handle(&self) -> &VfsRepo {
        &self.vfs
    }
```

- [ ] **Step 3: Restore `pub mod secrets;`** in `lib.rs` if commented, and `pub use secrets::SecretInfo;`.

- [ ] **Step 4: Cross-invocation persistence test**

Add `crates/repo/src/secrets.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-sec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn secret_persists_across_reopen_and_run_injects() {
        let root = tmp_root("persist");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        {
            let repo = Repo::init(&root).unwrap();
            repo.secret_add("DB_URL", b"postgres://secret", &[alice_pk.clone()]).unwrap();
        } // dropped: store + lock released, secret only on disk now
        let repo2 = Repo::open(&root).unwrap();
        let list = repo2.secret_list().unwrap();
        assert_eq!(list, vec![SecretInfo { name: "DB_URL".into(), recipients: 1 }]);
        // run injects it into a child that echoes the value back via exit-code check
        let code = repo2
            .run(&alice_sk, &["sh".into(), "-c".into(), "test \"$DB_URL\" = postgres://secret".into()])
            .unwrap();
        assert_eq!(code, 0, "child saw the decrypted DB_URL");
        drop(repo2);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unauthorized_identity_is_skipped_not_failed() {
        let root = tmp_root("unauth");
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.secret_add("DB_URL", b"v", &[alice_pk]).unwrap();
        // mallory can't read it; run should still succeed (skip + warn), env unset
        let code = repo
            .run(&mallory_sk, &["sh".into(), "-c".into(), "test -z \"$DB_URL\"".into()])
            .unwrap();
        assert_eq!(code, 0, "DB_URL was not injected for unauthorized identity");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
```

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p scl-repo`
Expected: PASS (incl. the cross-invocation proof).

```bash
git add crates/repo/src/secrets.rs crates/repo/src/repo.rs crates/repo/src/lib.rs
git commit -m "feat(repo): committed-secrets ops + run, persisting across invocations"
```

---

## Task 8: CLI subcommands

**Files:**
- Modify: `crates/cli/Cargo.toml`
- Modify: `crates/cli/src/main.rs`

- [ ] **Step 1: Add the repo dependency**

In `crates/cli/Cargo.toml` `[dependencies]`:

```toml
scl-repo = { path = "../repo" }
```

- [ ] **Step 2: Fix the existing `StoreConfig` call sites for the `backend` field**

In `crates/cli/src/main.rs`, the demo functions build `StoreConfig { budget_bytes, spill }`. Update them. In `run_demo`:

```rust
    let backend = if args.spill {
        scl_core::Backend::Ephemeral(SpillPolicy::SpillTo(session_root.join("spill")))
    } else {
        scl_core::Backend::Ephemeral(SpillPolicy::Disallow)
    };
    let repo = Repo::new(Store::new(StoreConfig { budget_bytes, backend }));
```

In `run_secret_demo`, replace `spill: SpillPolicy::Disallow` with `backend: scl_core::Backend::Ephemeral(SpillPolicy::Disallow)`. (Search for every `StoreConfig {` in the file and fix.)

- [ ] **Step 3: Add the repo subcommands**

Add to the `Cmd` enum:

```rust
    /// Create a new persistent repo (.sc/) in the current directory.
    Init,
    /// Snapshot the working tree as a commit on the current branch.
    Commit {
        #[arg(short, long)]
        message: String,
        #[arg(long, default_value = "you")]
        author: String,
    },
    /// Show working-tree changes against HEAD.
    Status,
    /// Show commit history from HEAD.
    Log,
    /// Create a new branch at the current tip.
    Branch { name: String },
    /// Switch HEAD to a branch and materialize it.
    Switch { name: String },
    /// Committed-secret operations.
    Secret {
        #[command(subcommand)]
        op: SecretOp,
    },
    /// Decrypt authorized secrets, inject them, and run a command.
    Run {
        /// Identity file (default ~/.sc/identity or $SC_IDENTITY).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Command and args after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
```

Add the secret subcommand enum:

```rust
#[derive(Subcommand)]
enum SecretOp {
    /// Seal a value (read from --value or stdin) to named recipients.
    Add {
        name: String,
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        #[arg(long)]
        value: String,
    },
    /// Grant a recipient access by re-wrapping (requires your identity).
    Grant {
        name: String,
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Revoke a recipient (by recipient id).
    Revoke {
        name: String,
        #[arg(long)]
        recipient_id: String,
    },
    /// List committed secrets.
    List,
}
```

Add match arms in `main`:

```rust
        Cmd::Init => run_init(),
        Cmd::Commit { message, author } => run_commit(&author, &message),
        Cmd::Status => run_status(),
        Cmd::Log => run_log(),
        Cmd::Branch { name } => run_branch(&name),
        Cmd::Switch { name } => run_switch(&name),
        Cmd::Secret { op } => run_secret(op),
        Cmd::Run { identity, cmd } => run_run(identity, cmd),
```

- [ ] **Step 4: Implement the command handlers**

Add to `crates/cli/src/main.rs` (reuses `resolve_identity_path`/`load_recipients` from Phase 2):

```rust
fn open_repo() -> Result<scl_repo::Repo> {
    let cwd = std::env::current_dir()?;
    scl_repo::Repo::open(cwd).map_err(Into::into)
}

fn run_init() -> Result<()> {
    let repo = scl_repo::Repo::init(std::env::current_dir()?)?;
    println!("initialized empty src-control repo at {}", repo.layout().dot_sc.display());
    Ok(())
}

fn run_commit(author: &str, message: &str) -> Result<()> {
    let repo = open_repo()?;
    let id = repo.commit(author, message)?;
    println!("committed {}", id.short());
    Ok(())
}

fn run_status() -> Result<()> {
    let repo = open_repo()?;
    let s = repo.status()?;
    if s.added.is_empty() && s.modified.is_empty() && s.deleted.is_empty() {
        println!("clean (working tree matches HEAD)");
        return Ok(());
    }
    for p in &s.added {
        println!("A  {p}");
    }
    for p in &s.modified {
        println!("M  {p}");
    }
    for p in &s.deleted {
        println!("D  {p}");
    }
    Ok(())
}

fn run_log() -> Result<()> {
    let repo = open_repo()?;
    for (id, snap) in repo.log()? {
        println!("{} {} — {}", id.short(), snap.author, snap.message);
    }
    Ok(())
}

fn run_branch(name: &str) -> Result<()> {
    open_repo()?.branch(name)?;
    println!("created branch {name}");
    Ok(())
}

fn run_switch(name: &str) -> Result<()> {
    open_repo()?.switch(name)?;
    println!("switched to branch {name}");
    Ok(())
}

fn run_secret(op: SecretOp) -> Result<()> {
    let repo = open_repo()?;
    let recipients_path = repo.layout().root.join(".sc").join("recipients.toml");
    match op {
        SecretOp::Add { name, to, value } => {
            let dir = load_recipients(&recipients_path)?;
            let pks = resolve_names(&dir, &to)?;
            repo.secret_add(&name, value.as_bytes(), &pks)?;
            println!("added secret {name} for {} recipient(s)", to.len());
        }
        SecretOp::Grant { name, to, identity } => {
            let dir = load_recipients(&recipients_path)?;
            let pks = resolve_names(&dir, &to)?;
            let sk = load_identity(identity)?;
            for pk in &pks {
                repo.secret_grant(&name, &sk, pk)?;
            }
            println!("granted {name} to {} recipient(s)", to.len());
        }
        SecretOp::Revoke { name, recipient_id } => {
            let rid = scl_crypto::RecipientId::from_hex(&recipient_id)
                .map_err(|_| anyhow::anyhow!("bad recipient id"))?;
            repo.secret_revoke(&name, &rid)?;
            println!("revoked {recipient_id} from {name}");
        }
        SecretOp::List => {
            for info in repo.secret_list()? {
                println!("{}  ({} recipient(s))", info.name, info.recipients);
            }
        }
    }
    Ok(())
}

fn run_run(identity: Option<PathBuf>, cmd: Vec<String>) -> Result<()> {
    let repo = open_repo()?;
    let sk = load_identity(identity)?;
    let code = repo.run(&sk, &cmd)?;
    std::process::exit(code);
}

fn load_identity(flag: Option<PathBuf>) -> Result<scl_crypto::SecretKey> {
    let path = resolve_identity_path(flag);
    scl_crypto::FileKeyProvider::new(path).identity().map_err(Into::into)
}

fn resolve_names(
    dir: &std::collections::BTreeMap<String, scl_crypto::PublicKey>,
    names: &[String],
) -> Result<Vec<scl_crypto::PublicKey>> {
    names
        .iter()
        .map(|n| dir.get(n).cloned().ok_or_else(|| anyhow::anyhow!("unknown recipient: {n}")))
        .collect()
}
```

> Two small `scl-crypto` additions this needs: `FileKeyProvider::new` (already exists), `KeyProvider::identity` (exists), and `RecipientId::from_hex(&str) -> Result<RecipientId>`. If `RecipientId` has no `from_hex`, add a trivial constructor in `crates/crypto/src/key.rs` that validates 32 hex chars and wraps the string. Also remove the `#[allow(dead_code)]` on `resolve_identity_path` and `load_recipients` now that they have callers.

- [ ] **Step 5: Build, smoke-test, and run the suite**

Run:
```bash
cargo build
cargo test
```
Expected: workspace builds and all tests pass. Then a manual smoke test:
```bash
cd "$(mktemp -d)" && sc=/Users/tonibergholm/Developer/claude/src-control/target/debug/sc
"$sc" init && echo hi > a.txt && "$sc" commit -m first && "$sc" log && "$sc" status
```
Expected: init message, a commit id, log line, "clean".

- [ ] **Step 6: Commit**

```bash
git add crates/cli/Cargo.toml crates/cli/src/main.rs crates/crypto/src/key.rs
git commit -m "feat(cli): init/commit/status/log/branch/switch/secret/run"
```

---

## Task 9: End-to-end script + docs

**Files:**
- Create: `demo/run_repo_demo.sh`
- Create: `docs/adr/0011-persistent-store-and-working-tree.md`
- Modify: `ARCHITECTURE.md`, `CLAUDE.md`

- [ ] **Step 1: End-to-end CLI script**

Create `demo/run_repo_demo.sh` (mirrors `run_demo.sh`'s self-checking style):

```bash
#!/usr/bin/env bash
# End-to-end proof: a persistent repo survives across separate `sc` invocations,
# including a committed secret that decrypts in a later process.
set -euo pipefail

# Build once and resolve the binary to an absolute path BEFORE we cd away.
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Generate an identity (private key + public key for recipients.toml).
PUB="$("$SC" keygen --out "$WORK/id" | grep 'public key' | awk '{print $3}')"

cd "$WORK"
"$SC" init                                   # creates ./.sc (must not pre-exist)
printf '[recipients]\nme = "%s"\n' "$PUB" > .sc/recipients.toml

echo "v1" > app.txt
"$SC" commit -m "first commit" --author me
"$SC" branch feature
"$SC" switch feature
echo "feature" > feature.txt
"$SC" commit -m "feature work" --author me
"$SC" switch main
[ ! -f feature.txt ] || { echo "FAIL: feature.txt should be gone on main"; exit 1; }

SC_IDENTITY="$WORK/id" "$SC" secret add DB_URL --to me --value "postgres://app"
# A *new* `sc` process reads the secret back, proving cross-invocation persistence:
OUT="$(SC_IDENTITY="$WORK/id" "$SC" run -- sh -c 'printf %s "$DB_URL"')"
[ "$OUT" = "postgres://app" ] || { echo "FAIL: secret did not survive/inject ($OUT)"; exit 1; }

echo "RESULT: persistent repo survived across invocations; secret decrypted in a new process ✔"
```

Make it executable: `chmod +x demo/run_repo_demo.sh`. Run it: `bash demo/run_repo_demo.sh` — expect the success line. (Adjust the keygen/recipients wiring if the CLI's keygen output format differs; the script is the integration contract.)

- [ ] **Step 2: ADR-0011**

Create `docs/adr/0011-persistent-store-and-working-tree.md`:

```markdown
# ADR-0011: Persistent loose-object store and git-like working tree

- **Status:** Accepted
- **Date:** 2026-06-25
- **Phase:** Post-Phase-2 (persistence)

## Context

Phases 1–2 kept everything in RAM. To use src-control as a real VCS — and to let
committed secrets survive between `sc` invocations — the object store and refs
must be durable on disk.

## Decision

- **Loose content-addressed objects.** Each object is a file at
  `.sc/objects/<hex>` whose contents are the canonical `Object::encode()` bytes,
  so `BLAKE3(contents) == filename`. Reuses the existing encoding and `ObjectId`;
  no new format. Packing is deferred.
- **Write-through persistence.** `core::Store` gains a `Persistent(PathBuf)`
  backend: every `put` writes the object durably (idempotent tmp+rename) before
  returning; a read-miss loads+verifies+decodes from disk; blob eviction drops
  only the RAM copy because disk is authoritative.
- **Mode-scoped disk invariant.** Ephemeral mode (agents, `sc demo`) keeps the
  zero-residue guarantee unchanged. Persistent mode (`sc init` repos) writes to
  `.sc/` by design; `.sc/` is user-owned durable state, like `.git`.
- **Git-like working tree.** `.sc/` sits at a repo root; the files beside it are
  the working tree. `commit` snapshots it; `switch` materializes a branch tip;
  `status` diffs working tree vs HEAD. Refs are symbolic-HEAD + `refs/heads/*`,
  updated atomically; a `.sc/lock` enforces single-writer.

## Consequences

- src-control is usable as a standalone local VCS (init/commit/status/log/branch/
  switch) and secrets persist across invocations.
- `core` stays free of Git/worktree/crypto deps; the repo layer lives in the new
  `scl-repo` crate (`cli → repo → {vfs, gitio, crypto} → core`).
- Merge, packfiles/gc, fsync tuning, and remotes are explicit follow-ons.

## Alternatives considered

- **Single packfile + index** / **embedded KV (redb/sled).** More robust at scale
  but heavier and hide the hand-owned format; rejected for the MVP in favor of
  legible loose objects (which the ephemeral spill backend already prototyped).
```

- [ ] **Step 3: Update ARCHITECTURE.md and CLAUDE.md**

In `ARCHITECTURE.md`: add a "Persistence" section describing the `Persistent` Store backend, the `.sc/` layout, the `scl-repo` crate, the git-like working tree, and the mode-scoped invariant (reference ADR-0011). Update the crate list to five crates + `repo`.

In `CLAUDE.md`:
- Workspace layout block: add `crates/repo → persistent .sc/ repo: objects, refs, branches, working tree (depends on core/vfs/crypto)`.
- Dependency rule: `cli → repo → {vfs, gitio, crypto} → core`.
- Replace the "Disk is touched only by `Worktree::checkout`" invariant with the **mode-scoped** version: ephemeral mode keeps zero-residue (proven by `sc demo`); persistent mode writes to `.sc/` by design (user-owned durable state).
- Commands: add `sc init`, `sc commit -m`, `sc status`, `sc log`, `sc branch`, `sc switch`, `sc secret add/grant/revoke/list`, `sc run -- <cmd>`, and `bash demo/run_repo_demo.sh`.

- [ ] **Step 4: Run the suite and commit**

Run: `cargo test && bash demo/run_repo_demo.sh`
Expected: all tests pass; the demo prints its success line.

```bash
git add demo/run_repo_demo.sh docs/ ARCHITECTURE.md CLAUDE.md
git commit -m "docs: ADR-0011 + persistence docs; end-to-end repo demo script"
```

---

## Done criteria

- `cargo test` green across the workspace; `cargo build` warning-clean.
- `bash demo/run_repo_demo.sh` proves a persistent repo survives across invocations and a committed secret decrypts in a new process.
- Phase 1 `sc demo` and Phase 2 `sc secret-demo` (ephemeral) still pass unchanged.
- `sc init/commit/status/log/branch/switch/secret/run` work end to end.
- ADR-0011 added; ARCHITECTURE.md + CLAUDE.md reflect the persistent mode, `scl-repo`, and the mode-scoped invariant.
```

