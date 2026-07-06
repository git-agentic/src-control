//! Agent workspace sessions (P13): fork N in-RAM workspaces from a persistent
//! repo's HEAD, materialize each to an ephemeral checkout, run agent commands,
//! and harvest changed workspaces back as branches. The repo's budget-bounded
//! persistent store is the backing tier — forks share one Arc'd blob cache and
//! eviction is always safe (every object is reconstructible from `.sc/objects`).

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
