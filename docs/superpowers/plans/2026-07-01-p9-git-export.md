# P9 — Git export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `sc export --to <git-repo>` that writes the current branch's full history into a Git repository, mapping our objects to Git objects, keeping `gix` quarantined in `gitio`.

**Architecture:** All Git-write logic lives in a new `crates/gitio/src/export.rs`. A first spike task pins the exact `gix` 0.85 write API behind insulating helpers expressed in our own terms (a `GitTarget` with `write_blob`/`write_tree`/`write_commit`/`set_ref_force`), so every later task translates our `Blob`/`Tree`/`Snapshot` objects through those helpers and never touches a `gix` type. Export walks the snapshot DAG post-order (parents before children), memoizing object→git-oid so re-export is idempotent, and fails closed on encrypted content unless opted in. The CLI resolves the branch tip from `repo` and passes it + the store down to `gitio`, so `repo` stays Git-agnostic.

**Tech Stack:** Rust 2021, `gix` 0.85 (Git object DB read+write; **only** in `gitio`), `scl-core` (our object model + `Store`), `anyhow` (gitio errors), `clap` (CLI). Tests shell out to the real `git` binary to verify canonical Git encoding (the import test already does this).

## Global Constraints

- **Dependency rule (strict):** `cli → repo → {vfs, gitio, crypto} → core`. **`gix` stays quarantined in `gitio`** — no other crate may link or reference it. `repo` must **not** depend on `gitio`; `cli` links both and passes the resolved snapshot tip + store down to `gitio` (same wiring as `import_head`). No `gix` type may appear in `gitio`'s public API (`ExportReport.git_commit` is a hex `String`, not a `gix::ObjectId`).
- **Content-addressing / canonical Git bytes:** Git orders tree entries as if a directory name carries a trailing `/` (so `some-dir.txt` sorts *before* directory `some-dir/`, the opposite of our plain `name.cmp`). Emitting the wrong order breaks both idempotency and interop. This is verified against the real `git` binary in Task 1 before anything builds on it.
- **Fail-closed on encrypted content:** if any reachable tree entry has the `PROTECTED` perms bit, or any exported snapshot's `secrets` registry is non-empty, export **refuses** (no Git repo created, no objects written) unless `--include-encrypted` is passed. With the flag: protected blobs export as their existing ciphertext, secrets are dropped, and a summary is reported. Never silently drop.
- **Idempotency:** deterministic object + signature mapping → identical Git oids on re-export. Signature synthesis: parse `Name <email>` from `author` if present, else name=`author`, empty email; committer = author; time = snapshot `timestamp` (i64 seconds); timezone `+0000`.
- **Scope:** current branch, full history, one target ref (default `refs/heads/<branch>`, `--ref` override), **overwrite** semantics. Target `--to <path>`: existing Git repo used as-is; absent path → `git init --bare`; existing non-Git path → error.
- Every public fn/type gets a doc comment. Every new behavior ships with a test that cleans up any disk/temp repo it creates.

---

## File map

**gitio (new):**
- `crates/gitio/src/export.rs` — the entire export path: `gix` write helpers (`GitTarget`), object translation, DAG walk, encrypted-content policy, `export_branch` + `ExportOptions` + `ExportReport`.

**gitio (modified):**
- `crates/gitio/src/lib.rs` — `mod export;` + `pub use export::{export_branch, ExportOptions, ExportReport};`.

**cli (modified):**
- `crates/cli/src/main.rs` — `Cmd::Export { .. }` + `run_export`.

**docs (modified):**
- `docs/adr/0016-git-export.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `demo/run_repo_demo.sh`.

---

## Task 1: `gix` write primitives + canonical tree-order verification (GATING)

Pin the exact `gix` 0.85 write API behind helpers expressed in our terms, and prove the emitted tree bytes match canonical Git. Everything else builds on this; do it first and get it exactly right.

**Files:**
- Create: `crates/gitio/src/export.rs`
- Modify: `crates/gitio/src/lib.rs`
- Test: `crates/gitio/src/export.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `gix` 0.85.
- Produces (used by all later tasks — these insulate `gix` so later tasks touch no `gix` types except constructing `GitTreeEntry`/`GitMode`/`GitSig`):
  - `struct GitTarget { repo: gix::Repository }`
  - `GitTarget::open_or_init_bare(path: &Path) -> anyhow::Result<GitTarget>`
  - `GitTarget::write_blob(&self, bytes: &[u8]) -> anyhow::Result<gix::ObjectId>`
  - `GitTarget::write_tree(&self, entries: Vec<GitTreeEntry>) -> anyhow::Result<gix::ObjectId>`
  - `GitTarget::write_commit(&self, tree: gix::ObjectId, parents: &[gix::ObjectId], sig: &GitSig, message: &str) -> anyhow::Result<gix::ObjectId>`
  - `GitTarget::set_ref_force(&self, ref_name: &str, target: gix::ObjectId) -> anyhow::Result<()>`
  - `GitTarget::set_head(&self, ref_name: &str) -> anyhow::Result<()>` (point HEAD symbolic-ref at `ref_name`)
  - `GitTarget::created: bool` field (true when this call created the repo — only then is `set_head` used)
  - `pub(crate) struct GitTreeEntry { pub name: String, pub mode: GitMode, pub oid: gix::ObjectId }`
  - `pub(crate) enum GitMode { File, Exec, Link, Tree }`
  - `pub(crate) struct GitSig { pub name: String, pub email: String, pub time_secs: i64 }`

> **Implementer note (read first):** the exact field/type names in `gix_object`, `gix_actor`, and `gix_date` for `gix` 0.85 may differ slightly from the code below. Your job in this task is to make these helpers **compile** and make the canonical-order test **pass**, adjusting `gix` internals as the compiler and the oid-equality assertion demand. The helper *signatures above* (our terms) must stay exactly as specified — later tasks depend on them. Keep all `gix` usage inside `export.rs`.

- [ ] **Step 1: Write the failing canonical-order test**

The critical fixture: a file `some-dir.txt` beside a directory `some-dir/` — these sort in opposite orders under plain-byte vs Git's trailing-slash rule, and can coexist on a filesystem (so the real `git` binary can produce the reference oid). Add to `crates/gitio/src/export.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e")
            .output()
            .expect("git runs")
    }

    // The reference tree oid produced by canonical git for:
    //   some-dir.txt        (file, content "x")
    //   some-dir/inner.txt  (file, content "y")
    fn git_reference_tree_oid() -> String {
        let dir = std::env::temp_dir().join(format!("scl-gitref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("some-dir")).unwrap();
        std::fs::write(dir.join("some-dir.txt"), b"x").unwrap();
        std::fs::write(dir.join("some-dir/inner.txt"), b"y").unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["add", "-A"]);
        let out = git(&dir, &["write-tree"]);
        let oid = String::from_utf8(out.stdout).unwrap().trim().to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        oid
    }

    #[test]
    fn write_tree_matches_canonical_git_order() {
        let dir = std::env::temp_dir().join(format!("scl-gixwrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = GitTarget::open_or_init_bare(&dir).unwrap();

        let x = t.write_blob(b"x").unwrap();
        let y = t.write_blob(b"y").unwrap();
        let inner = t.write_tree(vec![GitTreeEntry { name: "inner.txt".into(), mode: GitMode::File, oid: y }]).unwrap();
        // Deliberately pass entries in NON-git order to prove write_tree canonicalizes.
        let root = t.write_tree(vec![
            GitTreeEntry { name: "some-dir".into(), mode: GitMode::Tree, oid: inner },
            GitTreeEntry { name: "some-dir.txt".into(), mode: GitMode::File, oid: x },
        ]).unwrap();

        assert_eq!(root.to_hex().to_string(), git_reference_tree_oid());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blob_commit_ref_roundtrip() {
        let dir = std::env::temp_dir().join(format!("scl-gixrt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = GitTarget::open_or_init_bare(&dir).unwrap();
        let b = t.write_blob(b"hello").unwrap();
        let tree = t.write_tree(vec![GitTreeEntry { name: "f.txt".into(), mode: GitMode::File, oid: b }]).unwrap();
        let sig = GitSig { name: "Ada".into(), email: "ada@x".into(), time_secs: 1_700_000_000 };
        let c = t.write_commit(tree, &[], &sig, "init").unwrap();
        t.set_ref_force("refs/heads/main", c).unwrap();
        assert!(t.created, "a fresh init_bare must report created=true");
        t.set_head("refs/heads/main").unwrap();
        // git resolves the commit via HEAD (no explicit ref) — proves set_head worked.
        let out = git(&dir, &["--git-dir", dir.to_str().unwrap(), "log", "--format=%s", "-1"]);
        assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "init");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-gitio export::tests`
Expected: FAIL to compile (`export` module / helpers not defined).

- [ ] **Step 3: Implement the helpers**

Put this above the tests in `crates/gitio/src/export.rs`. Adjust `gix` internals until it compiles and the tests pass — the helper signatures stay as written.

```rust
//! Git *export* — the write half of the `gix` interop boundary (import is in
//! `lib.rs`). This is the only place, besides import, that touches `gix`.
//!
//! All `gix` types are confined to this file behind `GitTarget` and the small
//! `GitTreeEntry`/`GitMode`/`GitSig` value types, so the rest of export (and the
//! whole rest of the workspace) stays Git-agnostic.

use std::path::Path;

use anyhow::{Context, Result};

/// A Git repository we write objects and refs into.
pub(crate) struct GitTarget {
    repo: gix::Repository,
    /// True if THIS call created the repo (so we own its `HEAD`). We only point
    /// `HEAD` at the exported ref when we created the repo — never clobber the
    /// `HEAD` of a pre-existing repo (it may be someone's working checkout).
    pub(crate) created: bool,
}

/// One entry for `write_tree`, in our terms (not `gix`'s).
pub(crate) struct GitTreeEntry {
    pub name: String,
    pub mode: GitMode,
    pub oid: gix::ObjectId,
}

/// The four Git entry kinds we emit.
#[derive(Clone, Copy)]
pub(crate) enum GitMode {
    File,
    Exec,
    Link,
    Tree,
}

/// A synthesized Git signature (used for both author and committer).
pub(crate) struct GitSig {
    pub name: String,
    pub email: String,
    pub time_secs: i64,
}

impl GitMode {
    fn to_gix(self) -> gix::objs::tree::EntryMode {
        use gix::objs::tree::EntryKind;
        match self {
            GitMode::File => EntryKind::Blob,
            GitMode::Exec => EntryKind::BlobExecutable,
            GitMode::Link => EntryKind::Link,
            GitMode::Tree => EntryKind::Tree,
        }
        .into()
    }
}

impl GitTarget {
    /// Open an existing Git repo at `path`; if `path` does not exist, create a
    /// bare repo there. A path that exists but is not a Git repo is an error.
    pub(crate) fn open_or_init_bare(path: &Path) -> Result<GitTarget> {
        let (repo, created) = if path.exists() {
            (
                gix::open(path).with_context(|| {
                    format!("{} exists but is not a git repository", path.display())
                })?,
                false,
            )
        } else {
            (
                gix::init_bare(path)
                    .with_context(|| format!("initializing bare git repo at {}", path.display()))?,
                true,
            )
        };
        Ok(GitTarget { repo, created })
    }

    /// Point `HEAD` at `ref_name` (a symbolic ref). Only meaningful on a repo we
    /// created — a fresh `init_bare` HEAD may name `main`/`master` regardless of
    /// our branch, so a mirror needs HEAD pointed at the ref we actually wrote or
    /// `git log`/`import_head` (which resolve HEAD) see nothing.
    pub(crate) fn set_head(&self, ref_name: &str) -> Result<()> {
        use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
        use gix::refs::{FullName, Target};
        let target: FullName = ref_name.try_into().context("ref name for HEAD")?;
        self.repo
            .edit_reference(RefEdit {
                change: Change::Update {
                    log: LogChange { mode: RefLog::AndReference, force_create_reflog: false, message: "sc export".into() },
                    expected: PreviousValue::Any,
                    new: Target::Symbolic(target),
                },
                name: "HEAD".try_into().context("HEAD name")?,
                deref: false,
            })
            .context("pointing HEAD at exported ref")?;
        Ok(())
    }

    /// Write a blob, returning its Git oid.
    pub(crate) fn write_blob(&self, bytes: &[u8]) -> Result<gix::ObjectId> {
        Ok(self.repo.write_blob(bytes).context("writing git blob")?.detach())
    }

    /// Write a tree from `entries`, canonicalizing entry order to Git's rule.
    ///
    /// Git canonical order: compare entry names bytewise, EXCEPT a **tree** entry
    /// sorts as if its name had a trailing `/` appended. So file `some-dir.txt`
    /// sorts before directory `some-dir/` (`.` = 0x2e < `/` = 0x2f). We sort with
    /// this explicit rule rather than relying on any `gix` `Ord`, then build the
    /// tree in that order. Do NOT additionally call `tree.entries.sort()` — if
    /// `gix`'s ordering is plain-name it would re-scramble our correct order.
    pub(crate) fn write_tree(&self, mut entries: Vec<GitTreeEntry>) -> Result<gix::ObjectId> {
        fn sort_key(e: &GitTreeEntry) -> Vec<u8> {
            let mut k = e.name.as_bytes().to_vec();
            if matches!(e.mode, GitMode::Tree) {
                k.push(b'/');
            }
            k
        }
        entries.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));

        let mut tree = gix::objs::Tree::empty();
        for e in entries {
            tree.entries.push(gix::objs::tree::Entry {
                mode: e.mode.to_gix(),
                filename: e.name.into(),
                oid: e.oid,
            });
        }
        Ok(self.repo.write_object(&tree).context("writing git tree")?.detach())
    }

    /// Write a commit with explicit author=committer signature (deterministic).
    pub(crate) fn write_commit(
        &self,
        tree: gix::ObjectId,
        parents: &[gix::ObjectId],
        sig: &GitSig,
        message: &str,
    ) -> Result<gix::ObjectId> {
        let signature = gix::actor::Signature {
            name: sig.name.clone().into(),
            email: sig.email.clone().into(),
            time: gix::date::Time::new(sig.time_secs, 0),
        };
        let commit = gix::objs::Commit {
            tree,
            parents: parents.iter().copied().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        Ok(self.repo.write_object(&commit).context("writing git commit")?.detach())
    }

    /// Create or force-overwrite `ref_name` to point at `target` (mirror
    /// semantics — no fast-forward check).
    pub(crate) fn set_ref_force(&self, ref_name: &str, target: gix::ObjectId) -> Result<()> {
        use gix::refs::transaction::PreviousValue;
        self.repo
            .reference(ref_name, target, PreviousValue::Any, "sc export")
            .with_context(|| format!("updating ref {ref_name}"))?;
        Ok(())
    }
}
```

Add to `crates/gitio/src/lib.rs` (near the top, after the module doc):
```rust
mod export;
pub use export::{export_branch, ExportOptions, ExportReport};
```
(`export_branch`/`ExportOptions`/`ExportReport` don't exist until Task 3 — if the compiler complains about the unresolved re-export before Task 3, add just `mod export;` now and add the `pub use` in Task 3. Prefer adding `mod export;` only in this task.)

So in THIS task, add only:
```rust
mod export;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p scl-gitio export::tests`
Expected: PASS — both `write_tree_matches_canonical_git_order` (proving canonical order) and `blob_commit_ref_roundtrip` (proving blob/commit/ref writes AND that `set_head` makes HEAD resolvable). If the tree-order test fails, the sort rule is the culprit — the required order is stated in `write_tree`'s doc comment (bytewise, with a trailing `/` appended to **tree** entry names); do not fall back to a plain-name sort. Also confirm here what `gix::init_bare` names `HEAD` by default (`main` vs `master`) — `set_head` makes this irrelevant to correctness, but note it in your report.

- [ ] **Step 5: Commit**

```bash
git add crates/gitio/src/export.rs crates/gitio/src/lib.rs
git commit -m "feat(gitio): gix write primitives with canonical tree ordering (verified vs git)"
```

---

## Task 2: Object translation (blob/tree/commit) + signature synthesis

Translate our `Blob`/`Tree` objects to Git via the Task 1 helpers, with correct mode mapping and canonical order, plus the deterministic signature. Deliverable: map one snapshot's tree and write a single parentless commit that `git` reads back with correct file modes.

**Files:**
- Modify: `crates/gitio/src/export.rs`
- Test: `crates/gitio/src/export.rs` tests

**Interfaces:**
- Consumes: Task 1 `GitTarget`, `GitTreeEntry`, `GitMode`, `GitSig`; `scl_core::{Store, Object, ObjectId, Tree, TreeEntry, EntryKind, FileMode, Snapshot, PROTECTED}`.
- Produces (used by Task 3/4):
  - `fn synth_sig(author: &str, timestamp: i64) -> GitSig`
  - `fn map_blob(store, target, id, blob_memo) -> Result<gix::ObjectId>`
  - `fn map_tree(store, target, id, tree_memo, blob_memo, protected_count: &mut usize) -> Result<gix::ObjectId>`
  - `fn map_commit(store, target, snap: &Snapshot, tree_oid, parent_oids, ) -> Result<gix::ObjectId>` — writes the commit (used by the DAG driver).

- [ ] **Step 1: Write the failing test (single parentless snapshot → git)**

```rust
#[test]
fn single_snapshot_exports_files_and_modes() {
    use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode};
    use std::collections::{BTreeMap, HashMap};
    let mut store = Store::new(StoreConfig::default());
    let blob = store.put(Object::blob(b"fn main(){}".to_vec())).unwrap();
    let exec = store.put(Object::blob(b"#!/bin/sh\n".to_vec())).unwrap();
    let root = store.put(Object::Tree(Tree::new(vec![
        TreeEntry { name: "main.rs".into(), kind: EntryKind::Blob, id: blob, mode: FileMode::FILE, perms: 0 },
        TreeEntry { name: "run.sh".into(), kind: EntryKind::Blob, id: exec, mode: FileMode::EXEC, perms: 0 },
    ]))).unwrap();
    let snap = scl_core::Snapshot { root, parents: vec![], author: "Ada <ada@x>".into(), timestamp: 1_700_000_000, message: "c1".into(), secrets: BTreeMap::new(), protection: Default::default() };

    let dir = std::env::temp_dir().join(format!("scl-map1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let target = GitTarget::open_or_init_bare(&dir).unwrap();
    let mut tree_memo = HashMap::new();
    let mut blob_memo = HashMap::new();
    let mut protected = 0usize;
    let tree_oid = map_tree(&mut store, &target, root, &mut tree_memo, &mut blob_memo, &mut protected).unwrap();
    let cid = map_commit(&target, &snap, tree_oid, &[]).unwrap();
    target.set_ref_force("refs/heads/main", cid).unwrap();

    // git sees both files with correct modes (100644, 100755).
    let out = std::process::Command::new("git")
        .args(["--git-dir", dir.to_str().unwrap(), "ls-tree", "main"]).output().unwrap();
    let listing = String::from_utf8(out.stdout).unwrap();
    assert!(listing.contains("100644 blob") && listing.contains("main.rs"), "{listing}");
    assert!(listing.contains("100755 blob") && listing.contains("run.sh"), "{listing}");
    std::fs::remove_dir_all(&dir).unwrap();
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-gitio single_snapshot_exports_files_and_modes`
Expected: FAIL (`map_tree`/`map_commit`/`synth_sig` undefined).

- [ ] **Step 3: Implement translation**

Add to `crates/gitio/src/export.rs` (above tests). Add imports at the top: `use std::collections::HashMap;` and `use scl_core::{EntryKind, FileMode, Object, ObjectId, Snapshot, Store, PROTECTED};`.

```rust
/// Deterministic Git signature from our freeform author + i64 timestamp. If
/// `author` looks like `Name <email>`, split it; otherwise name=author, empty
/// email. Timezone is fixed at +0000 so re-export is byte-identical.
fn synth_sig(author: &str, timestamp: i64) -> GitSig {
    if let Some((name, rest)) = author.split_once('<') {
        if let Some(email) = rest.strip_suffix('>') {
            return GitSig { name: name.trim().to_string(), email: email.trim().to_string(), time_secs: timestamp };
        }
    }
    GitSig { name: author.to_string(), email: String::new(), time_secs: timestamp }
}

/// Write our blob to Git once (memoized by our ObjectId).
fn map_blob(
    store: &mut Store,
    target: &GitTarget,
    id: ObjectId,
    blob_memo: &mut HashMap<ObjectId, gix::ObjectId>,
) -> anyhow::Result<gix::ObjectId> {
    if let Some(&g) = blob_memo.get(&id) {
        return Ok(g);
    }
    let bytes = match store.get(&id)? {
        Object::Blob(b) => b,
        other => anyhow::bail!("expected blob for {id}, got {}", other.kind_name()),
    };
    let g = target.write_blob(&bytes)?;
    blob_memo.insert(id, g);
    Ok(g)
}

/// Recursively translate our tree to a Git tree (memoized). Increments
/// `protected_count` for every entry carrying the PROTECTED perms bit (the blob
/// is exported as-is — it is already ciphertext).
fn map_tree(
    store: &mut Store,
    target: &GitTarget,
    id: ObjectId,
    tree_memo: &mut HashMap<ObjectId, gix::ObjectId>,
    blob_memo: &mut HashMap<ObjectId, gix::ObjectId>,
    protected_count: &mut usize,
) -> anyhow::Result<gix::ObjectId> {
    if let Some(&g) = tree_memo.get(&id) {
        return Ok(g);
    }
    let tree = store.get_tree(&id)?;
    let mut git_entries = Vec::with_capacity(tree.entries.len());
    for e in &tree.entries {
        if e.perms & PROTECTED != 0 {
            *protected_count += 1;
        }
        let (mode, oid) = match e.kind {
            EntryKind::Tree => (
                GitMode::Tree,
                map_tree(store, target, e.id, tree_memo, blob_memo, protected_count)?,
            ),
            EntryKind::Blob => {
                let mode = match e.mode {
                    m if m == FileMode::EXEC => GitMode::Exec,
                    FileMode(0o120000) => GitMode::Link,
                    _ => GitMode::File,
                };
                (mode, map_blob(store, target, e.id, blob_memo)?)
            }
        };
        git_entries.push(GitTreeEntry { name: e.name.clone(), mode, oid });
    }
    let g = target.write_tree(git_entries)?;
    tree_memo.insert(id, g);
    Ok(g)
}

/// Write a Git commit for `snap` given its already-mapped tree + parent oids.
fn map_commit(
    target: &GitTarget,
    snap: &Snapshot,
    tree_oid: gix::ObjectId,
    parent_oids: &[gix::ObjectId],
) -> anyhow::Result<gix::ObjectId> {
    let sig = synth_sig(&snap.author, snap.timestamp);
    target.write_commit(tree_oid, parent_oids, &sig, &snap.message)
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p scl-gitio single_snapshot_exports_files_and_modes`
Expected: PASS.

- [ ] **Step 5: Add + run a signature-determinism unit test**

```rust
#[test]
fn synth_sig_parses_name_email_and_falls_back() {
    let a = synth_sig("Ada <ada@x>", 42);
    assert_eq!((a.name.as_str(), a.email.as_str(), a.time_secs), ("Ada", "ada@x", 42));
    let b = synth_sig("bare-name", 7);
    assert_eq!((b.name.as_str(), b.email.as_str(), b.time_secs), ("bare-name", "", 7));
}
```
Run: `cargo test -p scl-gitio synth_sig_parses_name_email_and_falls_back`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/gitio/src/export.rs
git commit -m "feat(gitio): translate blobs/trees/commits to git with deterministic signature"
```

---

## Task 3: DAG walk + `export_branch` + idempotency

Walk the snapshot DAG from the tip through all parents (post-order), memoize commits, write them with mapped parents, set the target ref, and return an `ExportReport`. Deliverable: multi-commit history exports with correct parent chain; re-export is byte-identical.

**Files:**
- Modify: `crates/gitio/src/export.rs`, `crates/gitio/src/lib.rs`
- Test: `crates/gitio/src/export.rs` tests

**Interfaces:**
- Consumes: Task 2 `map_tree`, `map_commit`; Task 1 `GitTarget`.
- Produces (used by Task 4/5):
  - `pub struct ExportOptions<'a> { pub to: &'a Path, pub ref_name: &'a str, pub include_encrypted: bool }`
  - `pub struct ExportReport { pub git_commit: String, pub commits_written: usize, pub protected_blobs_as_ciphertext: usize, pub secrets_dropped: usize }`
  - `pub fn export_branch(store: &mut Store, tip: ObjectId, opts: &ExportOptions) -> anyhow::Result<ExportReport>`

- [ ] **Step 1: Write the failing tests (history + idempotency)**

```rust
#[test]
fn exports_multi_commit_history_with_parents() {
    use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode, Snapshot};
    use std::collections::BTreeMap;
    let mut store = Store::new(StoreConfig::default());
    let mk = |store: &mut Store, content: &[u8], parents: Vec<scl_core::ObjectId>, msg: &str| {
        let b = store.put(Object::blob(content.to_vec())).unwrap();
        let root = store.put(Object::Tree(Tree::new(vec![
            TreeEntry { name: "a.txt".into(), kind: EntryKind::Blob, id: b, mode: FileMode::FILE, perms: 0 },
        ]))).unwrap();
        store.put(Object::Snapshot(Snapshot { root, parents, author: "t".into(), timestamp: 1, message: msg.into(), secrets: BTreeMap::new(), protection: Default::default() })).unwrap()
    };
    let c1 = mk(&mut store, b"one", vec![], "c1");
    let c2 = mk(&mut store, b"two", vec![c1], "c2");
    let c3 = mk(&mut store, b"three", vec![c2], "c3");

    let dir = std::env::temp_dir().join(format!("scl-hist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false };
    let report = export_branch(&mut store, c3, &opts).unwrap();
    assert_eq!(report.commits_written, 3);

    let out = std::process::Command::new("git")
        .args(["--git-dir", dir.to_str().unwrap(), "log", "--format=%s", "main"]).output().unwrap();
    let log = String::from_utf8(out.stdout).unwrap();
    assert_eq!(log.split_whitespace().collect::<Vec<_>>(), vec!["c3", "c2", "c1"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn re_export_is_idempotent() {
    use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode, Snapshot};
    use std::collections::BTreeMap;
    let mut store = Store::new(StoreConfig::default());
    let b = store.put(Object::blob(b"x".to_vec())).unwrap();
    let root = store.put(Object::Tree(Tree::new(vec![TreeEntry { name: "a".into(), kind: EntryKind::Blob, id: b, mode: FileMode::FILE, perms: 0 }]))).unwrap();
    let c = store.put(Object::Snapshot(Snapshot { root, parents: vec![], author: "t".into(), timestamp: 5, message: "m".into(), secrets: BTreeMap::new(), protection: Default::default() })).unwrap();

    let dir = std::env::temp_dir().join(format!("scl-idem-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false };
    let a = export_branch(&mut store, c, &opts).unwrap();
    let b2 = export_branch(&mut store, c, &opts).unwrap();
    assert_eq!(a.git_commit, b2.git_commit);
    std::fs::remove_dir_all(&dir).unwrap();
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-gitio exports_multi_commit_history_with_parents re_export_is_idempotent`
Expected: FAIL (`export_branch`/`ExportOptions`/`ExportReport` undefined).

- [ ] **Step 3: Implement the DAG driver + public API**

Add to `crates/gitio/src/export.rs`. Add `use std::path::Path;` if not already present (Task 1 added it).

```rust
/// Options controlling an export.
pub struct ExportOptions<'a> {
    /// Target Git repo path (existing repo, or created bare if absent).
    pub to: &'a Path,
    /// Ref to update, e.g. "refs/heads/main".
    pub ref_name: &'a str,
    /// Allow exporting protected ciphertext + dropping secrets.
    pub include_encrypted: bool,
}

/// Summary of an export. `git_commit` is a hex string so `cli` needs no `gix`.
pub struct ExportReport {
    pub git_commit: String,
    pub commits_written: usize,
    pub protected_blobs_as_ciphertext: usize,
    pub secrets_dropped: usize,
}

/// Export the snapshot DAG rooted at `tip` into the Git repo named by `opts`,
/// updating `opts.ref_name` to the exported commit. Re-export is idempotent.
///
/// (Encrypted-content policy is layered on in a later step; this base version
/// exports everything.)
pub fn export_branch(store: &mut Store, tip: ObjectId, opts: &ExportOptions) -> anyhow::Result<ExportReport> {
    let target = GitTarget::open_or_init_bare(opts.to)?;

    let mut commit_memo: HashMap<ObjectId, gix::ObjectId> = HashMap::new();
    let mut tree_memo: HashMap<ObjectId, gix::ObjectId> = HashMap::new();
    let mut blob_memo: HashMap<ObjectId, gix::ObjectId> = HashMap::new();
    let mut protected = 0usize;

    // Post-order DAG walk: a commit is written only after all its parents have
    // Git oids. Explicit stack (no recursion) so deep history can't overflow.
    let mut stack: Vec<(ObjectId, bool)> = vec![(tip, false)];
    while let Some((sid, ready)) = stack.pop() {
        if commit_memo.contains_key(&sid) {
            continue;
        }
        if ready {
            let snap = store.get_snapshot(&sid)?;
            let tree_oid = map_tree(store, &target, snap.root, &mut tree_memo, &mut blob_memo, &mut protected)?;
            let parent_oids: Vec<gix::ObjectId> =
                snap.parents.iter().map(|p| commit_memo[p]).collect();
            let cid = map_commit(&target, &snap, tree_oid, &parent_oids)?;
            commit_memo.insert(sid, cid);
        } else {
            stack.push((sid, true));
            let snap = store.get_snapshot(&sid)?;
            for p in &snap.parents {
                if !commit_memo.contains_key(p) {
                    stack.push((*p, false));
                }
            }
        }
    }

    let tip_git = commit_memo[&tip];
    target.set_ref_force(opts.ref_name, tip_git)?;
    // If we created the repo, point HEAD at the exported ref so `git log` and
    // `import_head` (which resolve HEAD) see the history. Never touch HEAD on a
    // pre-existing repo.
    if target.created {
        target.set_head(opts.ref_name)?;
    }

    Ok(ExportReport {
        git_commit: tip_git.to_hex().to_string(),
        commits_written: commit_memo.len(),
        protected_blobs_as_ciphertext: protected,
        secrets_dropped: 0,
    })
}
```

Update `crates/gitio/src/lib.rs` — add the re-export next to `mod export;`:
```rust
pub use export::{export_branch, ExportOptions, ExportReport};
```

- [ ] **Step 4: Run the tests + full gitio suite**

Run: `cargo test -p scl-gitio`
Expected: PASS (history, idempotency, Task 1/2 tests, and the existing `import_head_reconstructs_tree`).

- [ ] **Step 5: Add + run a round-trip test (git → import → export → re-import)**

```rust
#[test]
fn git_import_export_reimport_roundtrip() {
    use scl_core::{Store, StoreConfig};
    let src = std::env::temp_dir().join(format!("scl-rt-src-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("top.txt"), b"top").unwrap();
    std::fs::write(src.join("sub/inner.txt"), b"inner").unwrap();
    let g = |args: &[&str]| std::process::Command::new("git").args(args).current_dir(&src)
        .env("GIT_AUTHOR_NAME","t").env("GIT_AUTHOR_EMAIL","t@e")
        .env("GIT_COMMITTER_NAME","t").env("GIT_COMMITTER_EMAIL","t@e").output().unwrap();
    g(&["init","-q"]); g(&["add","."]); g(&["commit","-q","-m","init"]);

    let mut store = Store::new(StoreConfig::default());
    let snap = crate::import_head(&mut store, &src).unwrap();

    let dst = std::env::temp_dir().join(format!("scl-rt-dst-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    let opts = ExportOptions { to: &dst, ref_name: "refs/heads/main", include_encrypted: false };
    export_branch(&mut store, snap, &opts).unwrap();

    // Re-import our export; the tree must reconstruct the same files.
    let mut store2 = Store::new(StoreConfig::default());
    let snap2 = crate::import_head(&mut store2, &dst).unwrap();
    let root = store2.get_snapshot(&snap2).unwrap().root;
    let t = store2.get_tree(&root).unwrap();
    assert!(t.get("top.txt").is_some() && t.get("sub").is_some());

    std::fs::remove_dir_all(&src).unwrap();
    std::fs::remove_dir_all(&dst).unwrap();
}
```
Note: `import_head` resolves `HEAD`; `export_branch` writes `refs/heads/main` **and** (because it created the repo) points `HEAD` at it via `set_head`, so `import_head` resolves the exported commit regardless of gix's default HEAD name. If this test fails at `import_head`, the bug is that `set_head` didn't run or didn't take — fix the export, do NOT paper over it by hardcoding a different `ref_name`.

Run: `cargo test -p scl-gitio git_import_export_reimport_roundtrip`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/gitio/src/export.rs crates/gitio/src/lib.rs
git commit -m "feat(gitio): export_branch — post-order DAG walk, memoized, idempotent"
```

---

## Task 4: Fail-closed encrypted-content policy

Refuse to export when protected content or registry secrets are present, unless `include_encrypted` is set. No Git repo is created and no object is written on refusal. With the flag, protected blobs export as ciphertext and secrets are dropped, both counted in the report.

**Files:**
- Modify: `crates/gitio/src/export.rs`
- Test: `crates/gitio/src/export.rs` tests

**Interfaces:**
- Consumes: Task 3 `export_branch` internals; `scl_core::{Store, Object, ObjectId, Snapshot, PROTECTED}`.
- Produces: refusal behavior + populated `ExportReport.secrets_dropped`.

- [ ] **Step 1: Write the failing tests (refuse without flag; succeed with flag)**

```rust
// Helper: a snapshot with one PROTECTED entry and one registry secret.
#[cfg(test)]
fn encrypted_snapshot(store: &mut scl_core::Store) -> scl_core::ObjectId {
    use scl_core::{Object, Tree, TreeEntry, EntryKind, FileMode, Snapshot, Secret, PROTECTED};
    use std::collections::BTreeMap;
    let ct = store.put(Object::blob(b"ciphertext-bytes".to_vec())).unwrap();
    let root = store.put(Object::Tree(Tree::new(vec![
        TreeEntry { name: "secret.txt".into(), kind: EntryKind::Blob, id: ct, mode: FileMode::FILE, perms: PROTECTED },
    ]))).unwrap();
    let sid = store.put(Object::Secret(Secret { name: "DB_URL".into(), nonce: vec![0;24], ciphertext: vec![1,2,3], wrapped_keys: vec![] })).unwrap();
    let mut secrets = BTreeMap::new();
    secrets.insert("DB_URL".to_string(), sid);
    store.put(Object::Snapshot(Snapshot { root, parents: vec![], author: "t".into(), timestamp: 1, message: "enc".into(), secrets, protection: Default::default() })).unwrap()
}

#[test]
fn refuses_encrypted_without_flag() {
    let mut store = scl_core::Store::new(scl_core::StoreConfig::default());
    let snap = encrypted_snapshot(&mut store);
    let dir = std::env::temp_dir().join(format!("scl-refuse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false };
    let err = export_branch(&mut store, snap, &opts).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("secret.txt") || msg.contains("DB_URL"), "error must name the content: {msg}");
    assert!(!dir.exists(), "no git repo should be created on refusal");
}

#[test]
fn exports_encrypted_with_flag_drops_secrets() {
    let mut store = scl_core::Store::new(scl_core::StoreConfig::default());
    let snap = encrypted_snapshot(&mut store);
    let dir = std::env::temp_dir().join(format!("scl-allow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: true };
    let report = export_branch(&mut store, snap, &opts).unwrap();
    assert_eq!(report.protected_blobs_as_ciphertext, 1);
    assert_eq!(report.secrets_dropped, 1);
    // The protected file exists in git as its ciphertext; no secret file exists.
    let out = std::process::Command::new("git").args(["--git-dir", dir.to_str().unwrap(), "ls-tree", "main"]).output().unwrap();
    let listing = String::from_utf8(out.stdout).unwrap();
    assert!(listing.contains("secret.txt"));
    assert!(!listing.contains("DB_URL"));
    std::fs::remove_dir_all(&dir).unwrap();
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-gitio refuses_encrypted_without_flag exports_encrypted_with_flag_drops_secrets`
Expected: FAIL (`refuses_encrypted_without_flag` fails — export currently succeeds and creates the repo; the with-flag test fails on `secrets_dropped == 1`).

- [ ] **Step 3: Implement the pre-flight scan + secret count**

Add a scan function to `crates/gitio/src/export.rs`:

```rust
/// Read-only pre-flight scan of the DAG rooted at `tip`: collect the paths of
/// PROTECTED tree entries and the names of registry secrets, without writing
/// anything. Used to fail closed before any Git repo is created.
fn scan_encrypted(store: &mut Store, tip: ObjectId) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let mut protected_paths = Vec::new();
    let mut secret_names = Vec::new();
    let mut seen_snaps: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();
    let mut snaps = vec![tip];
    while let Some(sid) = snaps.pop() {
        if !seen_snaps.insert(sid) {
            continue;
        }
        let snap = store.get_snapshot(&sid)?;
        for name in snap.secrets.keys() {
            secret_names.push(name.clone());
        }
        scan_tree(store, snap.root, String::new(), &mut protected_paths)?;
        for p in &snap.parents {
            snaps.push(*p);
        }
    }
    Ok((protected_paths, secret_names))
}

/// Record PROTECTED entry paths under `prefix`, recursing into subtrees. Uses an
/// explicit stack so deep trees can't overflow.
fn scan_tree(store: &mut Store, root: ObjectId, prefix: String, out: &mut Vec<String>) -> anyhow::Result<()> {
    let mut stack = vec![(root, prefix)];
    while let Some((id, pre)) = stack.pop() {
        let tree = store.get_tree(&id)?;
        for e in &tree.entries {
            let path = if pre.is_empty() { e.name.clone() } else { format!("{pre}/{}", e.name) };
            if e.perms & PROTECTED != 0 {
                out.push(path.clone());
            }
            if let EntryKind::Tree = e.kind {
                stack.push((e.id, path));
            }
        }
    }
    Ok(())
}
```

In `export_branch`, before `GitTarget::open_or_init_bare`, insert the fail-closed gate and capture the secret count:

```rust
pub fn export_branch(store: &mut Store, tip: ObjectId, opts: &ExportOptions) -> anyhow::Result<ExportReport> {
    // Fail closed BEFORE creating or writing anything.
    let (protected_paths, secret_names) = scan_encrypted(store, tip)?;
    if !opts.include_encrypted && (!protected_paths.is_empty() || !secret_names.is_empty()) {
        anyhow::bail!(
            "refusing to export encrypted content without --include-encrypted:\n  protected paths: {:?}\n  secrets: {:?}",
            protected_paths, secret_names
        );
    }
    let secrets_dropped = secret_names.len();

    let target = GitTarget::open_or_init_bare(opts.to)?;
    // ... existing DAG walk unchanged ...
```

And set the report's `secrets_dropped` field (replace the `secrets_dropped: 0`):
```rust
        secrets_dropped,
```

- [ ] **Step 4: Run the tests + full gitio suite**

Run: `cargo test -p scl-gitio`
Expected: PASS (refusal creates no repo; with-flag exports ciphertext, drops secret, counts both; all prior tests still green).

- [ ] **Step 5: Commit**

```bash
git add crates/gitio/src/export.rs
git commit -m "feat(gitio): fail closed on protected/secret content unless --include-encrypted"
```

---

## Task 5: CLI `sc export` command + wiring

Wire `sc export --to <path> [--ref <name>] [--include-encrypted]` into the persistent repo, resolving the branch tip and passing it to `gitio`.

**Files:**
- Modify: `crates/cli/src/main.rs`
- Test: `crates/cli/src/main.rs` (or a gitio-level integration test) — plus a manual smoke check.

**Interfaces:**
- Consumes: `scl_repo::Repo`, `scl_repo::refs::{current_branch, head_tip}`, `scl_gitio::{export_branch, ExportOptions}`.
- Produces: the `sc export` command.

- [ ] **Step 1: Add the command + handler**

In `crates/cli/src/main.rs`, add a variant to the `Cmd` enum (match the existing style, e.g. near `Import`):
```rust
    /// Export the current branch's history into a Git repository.
    Export {
        /// Target Git repo path (created bare if absent).
        #[arg(long)]
        to: PathBuf,
        /// Ref to update (default: refs/heads/<current-branch>).
        #[arg(long)]
        r#ref: Option<String>,
        /// Allow exporting protected ciphertext and dropping secrets.
        #[arg(long)]
        include_encrypted: bool,
    },
```
Add the dispatch arm alongside the others in `main`:
```rust
        Cmd::Export { to, r#ref, include_encrypted } => run_export(to, r#ref, include_encrypted),
```
Add the handler (use the project's `open_repo()` helper, as other handlers do):
```rust
fn run_export(to: PathBuf, ref_name: Option<String>, include_encrypted: bool) -> Result<()> {
    let repo = open_repo()?;
    let branch = scl_repo::refs::current_branch(repo.layout())?;
    let tip = repo.head_tip()?.ok_or_else(|| anyhow::anyhow!("branch is unborn — nothing to export"))?;
    let ref_name = ref_name.unwrap_or_else(|| format!("refs/heads/{branch}"));

    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();
    let opts = scl_gitio::ExportOptions { to: &to, ref_name: &ref_name, include_encrypted };
    let report = scl_gitio::export_branch(&mut store, tip, &opts)?;

    println!(
        "exported {} commit(s) to {} at {} ({})",
        report.commits_written, to.display(), ref_name, &report.git_commit[..12.min(report.git_commit.len())]
    );
    if report.protected_blobs_as_ciphertext > 0 || report.secrets_dropped > 0 {
        println!(
            "  warning: {} protected file(s) exported as ciphertext; {} secret(s) dropped (Git cannot enforce confidentiality)",
            report.protected_blobs_as_ciphertext, report.secrets_dropped
        );
    }
    Ok(())
}
```
These accessors all exist and are confirmed: `repo.layout() -> &Layout`, `repo.head_tip() -> Result<Option<ObjectId>>`, `repo.vfs() -> &VfsRepo` (so the store handle is `repo.vfs().store()`, an `Arc<Mutex<Store>>` — same as `Repo::gc` uses). `scl_repo::refs` is a `pub mod`, so `scl_repo::refs::current_branch(repo.layout())` is reachable. `open_repo()` already exists in `main.rs`, and `cli` already depends on `scl-gitio`. There is no `repo.store()` — use `repo.vfs().store()`.

- [ ] **Step 2: Build + a focused compile/behavior check**

Run: `cargo build -p scl-cli`
Expected: clean build.

- [ ] **Step 3: Manual smoke check (end to end)**

Run:
```bash
cd "$(mktemp -d)" && cargo run --quiet --bin sc -- init && echo hi > a.txt && cargo run --quiet --bin sc -- commit -m c1 --author me && \
cargo run --quiet --bin sc -- export --to ./mirror.git && \
git --git-dir ./mirror.git log --oneline && cd - >/dev/null
```
Expected: `sc export` prints `exported 1 commit(s) …`; `git log` shows the `c1` commit.

- [ ] **Step 4: Run the whole workspace**

Run: `cargo test`
Expected: PASS across all crates.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/main.rs
git commit -m "feat(cli): sc export — write current branch history to a git repo"
```

---

## Task 6: Accept ADR-0016 + sync ARCHITECTURE/CLAUDE + demo

Record the shipped feature per the project's ADR/ARCHITECTURE-in-sync convention, and extend the demo to prove round-trip interop.

**Files:**
- Modify: `docs/adr/0016-git-export.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `demo/run_repo_demo.sh`

- [ ] **Step 1: Flip the ADR**

In `docs/adr/0016-git-export.md`, change `- **Status:** Proposed` to `- **Status:** Accepted`. Add a short note recording the shipped policy: export is **fail-closed** on protected/secret content (refuse unless `--include-encrypted`), secrets are dropped rather than materialized as sidecar files, the target ref is **overwritten** (mirror semantics), an absent `--to` path is `git init --bare`-ed, and re-export is idempotent via deterministic signature synthesis.

- [ ] **Step 2: Update CLAUDE.md**

Add to the persistent-repo command block in `CLAUDE.md`:
```sh
cargo run --bin sc -- export --to <git-repo>            # write current branch history to Git
cargo run --bin sc -- export --to <git-repo> --include-encrypted  # allow protected ciphertext
```
Update the "Phase 8 is built" follow-ons line: git-export is now built, so remove it from any remaining-work list (leave genuinely-pending items like break-glass escrow).

- [ ] **Step 3: Update ARCHITECTURE.md**

Add a "Phase 9 — Git export (built)" section consistent with the "Phase 8 …" section: `sc export` maps our object DAG to Git objects (blob/tree/commit), keeps `gix` quarantined in `gitio`, walks the current branch's full history, fails closed on encrypted content, and is idempotent. Note the lossy points (secrets registry, protection policy, per-entry `perms`) that Git trees cannot carry.

- [ ] **Step 4: Extend the demo**

Append an export section to `demo/run_repo_demo.sh` (match the script's `$SC`/`$WORK` conventions and its EXIT-trap cleanup — add a `$MIRROR` temp path to the trap):
```bash
echo
echo "== Git export =="
MIRROR="$(mktemp -d)/mirror.git"
"$SC" export --to "$MIRROR"
echo "git sees the exported history:"
git --git-dir "$MIRROR" log --oneline | sed 's/^/  /'
```
(Add `"$(dirname "$MIRROR")"` to the trap's `rm -rf` list so no residue remains.)

- [ ] **Step 5: Run the demo + full suite**

Run: `bash demo/run_repo_demo.sh && cargo test`
Expected: demo runs to completion and prints the exported `git log`; workspace green.

- [ ] **Step 6: Commit**

```bash
git add docs/adr/0016-git-export.md ARCHITECTURE.md CLAUDE.md demo/run_repo_demo.sh
git commit -m "docs: accept ADR-0016 and record P9 git-export as built"
```

---

## Self-review notes (already reconciled)

- **Spec coverage:** object mapping (blob/tree/commit) → Task 2; canonical tree order → Task 1 (gating); full-history DAG walk + idempotency → Task 3; fail-closed encrypted policy (refuse / ciphertext / drop secrets) → Task 4; deterministic signature synthesis → Task 2; auto-init bare + overwrite ref → Task 1 (`open_or_init_bare`, `set_ref_force`) used by Task 3; CLI + wiring (repo stays git-agnostic) → Task 5; round-trip test → Task 3; ADR/docs/demo → Task 6. No spec section unmapped.
- **Quarantine:** all `gix` usage is confined to `crates/gitio/src/export.rs`; the public API (`ExportReport.git_commit: String`) exposes no `gix` type, so `cli` links `gitio` without referencing `gix`.
- **Type consistency:** `GitTarget`, `GitTreeEntry`, `GitMode{File,Exec,Link,Tree}`, `GitSig{name,email,time_secs}`, `map_blob`/`map_tree`/`map_commit`/`synth_sig`/`scan_encrypted`, `ExportOptions{to,ref_name,include_encrypted}`, `ExportReport{git_commit,commits_written,protected_blobs_as_ciphertext,secrets_dropped}`, and `export_branch(store, tip, opts)` are used identically across tasks.
- **Open verification for the implementer (Task 1):** the exact `gix` 0.85 type/field names (`gix::objs::Tree`/`tree::Entry`/`tree::EntryKind`, `gix::actor::Signature`, `gix::date::Time::new`, `gix::objs::Commit`, `write_object`/`write_blob`/`reference`, `Id::detach`, `ObjectId::to_hex`) must be confirmed against the compiler; the canonical-order test is the real acceptance gate. If a field/type differs, fix it inside `export.rs` — the helper *signatures* (our terms) must not change.
- **HEAD is set on create (Task 1 `set_head`, wired in Task 3):** export points a newly-created repo's `HEAD` at the exported ref, so the three HEAD-resolving checks (round-trip `import_head`, the Task 5 smoke `git log`, the Task 6 demo `git log`) work regardless of gix's default HEAD name. HEAD is never touched on a pre-existing target repo.
