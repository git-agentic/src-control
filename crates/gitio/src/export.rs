//! Git *export* — the write half of the `gix` interop boundary (import is in
//! `lib.rs`). This is the only place, besides import, that touches `gix`.
//!
//! All `gix` types are confined to this file behind `GitTarget` and the small
//! `GitTreeEntry`/`GitMode`/`GitSig` value types, so the rest of export (and the
//! whole rest of the workspace) stays Git-agnostic.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use scl_core::{EntryKind, FileMode, Object, ObjectId, Snapshot, Store, PROTECTED};

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
                    log: LogChange {
                        mode: RefLog::AndReference,
                        force_create_reflog: false,
                        message: "sc export".into(),
                    },
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

    #[test]
    fn synth_sig_parses_name_email_and_falls_back() {
        let a = synth_sig("Ada <ada@x>", 42);
        assert_eq!((a.name.as_str(), a.email.as_str(), a.time_secs), ("Ada", "ada@x", 42));
        let b = synth_sig("bare-name", 7);
        assert_eq!((b.name.as_str(), b.email.as_str(), b.time_secs), ("bare-name", "", 7));
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
