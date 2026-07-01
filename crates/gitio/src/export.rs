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
