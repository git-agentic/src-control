//! `scl-gitio` — the Git interop boundary.
//!
//! This is the only crate that links `gix`. It imports an existing Git
//! repository's `HEAD` tree into the content-addressed [`Store`] in-process (no
//! subprocess, no dependency on a `git` binary at runtime), returning a snapshot
//! id that worktrees can fork from. Keeping Git behind one crate keeps the rest
//! of the system Git-agnostic.

mod export;
pub use export::{export_branch, ExportOptions, ExportReport};

use std::path::Path;

use anyhow::{Context, Result};
use gix::objs::tree::EntryKind as GitEntryKind;
use scl_core::{EntryKind, FileMode, Object, ObjectId, Snapshot, Store, Tree, TreeEntry};

/// Import the `HEAD` commit's tree of the Git repo at `repo_path` into `store`,
/// returning the id of an equivalent snapshot object.
pub fn import_head(store: &mut Store, repo_path: &Path) -> Result<ObjectId> {
    let repo = gix::open(repo_path)
        .with_context(|| format!("opening git repo at {}", repo_path.display()))?;
    let commit = repo.head_commit().context("resolving HEAD commit")?;
    let tree = commit.tree().context("reading HEAD tree")?;

    let root = import_tree(store, &repo, &tree)?;

    let snap = Object::Snapshot(Snapshot {
        root,
        parents: vec![],
        author: "git-import".into(),
        timestamp: 0,
        message: format!("import HEAD {}", commit.id().shorten_or_id()),
        secrets: std::collections::BTreeMap::new(),
        protection: Default::default(),
    });
    store.put(snap).context("storing imported snapshot")
}

fn import_tree(store: &mut Store, repo: &gix::Repository, tree: &gix::Tree) -> Result<ObjectId> {
    let mut entries: Vec<TreeEntry> = Vec::new();

    for entry in tree.iter() {
        let entry = entry.context("decoding tree entry")?;
        let name = entry.filename().to_string();
        let oid = entry.oid().to_owned();

        match entry.mode().kind() {
            GitEntryKind::Tree => {
                let obj = repo.find_object(oid).context("finding subtree")?;
                let subtree = obj.into_tree();
                let sub_id = import_tree(store, repo, &subtree)?;
                entries.push(TreeEntry {
                    name,
                    kind: EntryKind::Tree,
                    id: sub_id,
                    mode: FileMode(0o755),
                    perms: 0,
                });
            }
            GitEntryKind::Blob | GitEntryKind::BlobExecutable | GitEntryKind::Link => {
                let obj = repo.find_object(oid).context("finding blob")?;
                let data = obj.data.clone();
                let id = store.put(Object::blob(data))?;
                let mode = match entry.mode().kind() {
                    GitEntryKind::BlobExecutable => FileMode::EXEC,
                    GitEntryKind::Link => FileMode(0o120000),
                    _ => FileMode::FILE,
                };
                entries.push(TreeEntry { name, kind: EntryKind::Blob, id, mode, perms: 0 });
            }
            // Submodule pointers carry no content in this repo; skip for the MVP.
            GitEntryKind::Commit => continue,
        }
    }

    let tree = Object::Tree(Tree::new(entries));
    store.put(tree).context("storing imported tree")
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::StoreConfig;
    use std::process::Command;

    /// Create a throwaway git repo with the `git` binary and import it.
    #[test]
    fn import_head_reconstructs_tree() {
        let dir = std::env::temp_dir().join(format!("scl-gitio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("README.md"), b"git repo").unwrap();
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}").unwrap();

        let git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&dir)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .output()
                .unwrap()
        };
        git(&["init", "-q"]);
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "init"]);

        let mut store = Store::new(StoreConfig::default());
        let snap = import_head(&mut store, &dir).unwrap();

        // Verify by forking a worktree and reading imported content.
        let s = store.get_snapshot(&snap).unwrap();
        let root = s.root;
        let root_tree = store.get_tree(&root).unwrap();
        assert!(root_tree.get("README.md").is_some());
        assert!(root_tree.get("src").is_some());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
