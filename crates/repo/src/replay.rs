//! Replay core (P14): cherry-pick is a three-way merge whose base is the
//! replayed commit's first parent (empty base for a root commit). Consumed by
//! the cherry-pick/rebase CLI surface (Tasks 8-9) to apply one commit onto an
//! arbitrary target tree without requiring a full branch merge.

use scl_core::{FileMode, ObjectId};

use crate::error::{Error, Result};
use crate::merge;
use crate::repo::Repo;
use crate::worktree;

/// Result of replaying one commit onto a target tree.
#[derive(Debug)]
pub(crate) enum ReplayOutcome {
    /// Merged tree written to the CAS.
    Clean { root: ObjectId },
    /// Replayed tree equals the target — change already present.
    Empty,
    /// Conflicting paths, with the merged working set (markers included)
    /// and sidecars, ready to materialize.
    Conflicts {
        files: Vec<(String, FileMode, Vec<u8>)>,
        sidecars: Vec<(String, Vec<u8>)>,
        paths: Vec<String>,
    },
}

/// Replay (cherry-pick) `commit_id` onto `onto_root`.
///
/// This is a three-way merge: base = `commit_id`'s first parent's root tree
/// (`None`, i.e. the empty tree, if `commit_id` is a root commit), ours =
/// `onto_root`, theirs = `commit_id`'s own root tree. Merge commits (2+
/// parents) are refused — mainline selection is not supported — as is any
/// replay that would touch `PROTECTED` content, since flattening trees for a
/// three-way merge drops the `perms` byte and would corrupt encrypted files.
pub(crate) fn replay_commit(repo: &Repo, commit_id: ObjectId, onto_root: ObjectId) -> Result<ReplayOutcome> {
    let snap = repo.snapshot(&commit_id)?;
    if snap.parents.len() >= 2 {
        return Err(Error::CannotReplayMerge(commit_id));
    }
    let base_root = match snap.parents.first() {
        Some(p) => Some(repo.snapshot(p)?.root),
        None => None,
    };
    let theirs_root = snap.root;

    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();

    // Fail closed on protected content (same rationale as `Repo::merge`'s
    // guard at repo.rs ~585): `three_way_files` flattens trees without the
    // `perms` byte, which would push raw ciphertext into the working tree as
    // an ordinary unprotected blob. Pure read + early return: nothing is
    // written before this guard fires.
    for root in [base_root, Some(onto_root), Some(theirs_root)].into_iter().flatten() {
        let entries = worktree::tree_file_entries_with_perms(&mut store, root)?;
        if entries.values().any(|(_, _, perms)| perms & scl_core::PROTECTED != 0) {
            return Err(Error::ReplayProtected(commit_id.to_string()));
        }
    }

    let fm = merge::three_way_files(&mut store, base_root, onto_root, theirs_root)?;
    drop(store);

    if !fm.conflicts.is_empty() {
        return Ok(ReplayOutcome::Conflicts {
            files: fm.files,
            sidecars: fm.sidecars,
            paths: fm.conflicts,
        });
    }

    let write_set: Vec<(String, Vec<u8>, FileMode)> =
        fm.files.iter().map(|(p, m, b)| (p.clone(), b.clone(), *m)).collect();
    let root = repo.vfs().write_tree(&write_set)?;

    if root == onto_root {
        Ok(ReplayOutcome::Empty)
    } else {
        Ok(ReplayOutcome::Clean { root })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::tree_file_ids;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-replay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn clean_replay_produces_merged_root() {
        let root = tmp_root("clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"base\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        // main separately edits Y.
        std::fs::write(root.join("y.txt"), b"y\n").unwrap();
        let main_tip = repo.commit("me", "main edits y").unwrap();

        // branch b edits X.
        repo.switch("b").unwrap();
        std::fs::write(root.join("x.txt"), b"x\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip));

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let outcome = replay_commit(&repo, b_tip, onto_root).unwrap();
        match outcome {
            ReplayOutcome::Clean { root: merged_root } => {
                let store_arc = repo.vfs().store();
                let mut store = store_arc.lock().unwrap();
                let ids = tree_file_ids(&mut store, merged_root).unwrap();
                assert!(ids.contains_key("x.txt"), "b's edit must be present");
                assert!(ids.contains_key("y.txt"), "main's edit must be present");
                assert!(ids.contains_key("shared.txt"));
            }
            _ => panic!("expected Clean, got a different outcome"),
        }
        let _ = base;
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn conflicting_replay_reports_paths_with_markers() {
        let root = tmp_root("conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        let main_tip = repo.commit("me", "main edits x").unwrap();

        repo.switch("b").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();
        repo.switch("main").unwrap();

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let outcome = replay_commit(&repo, b_tip, onto_root).unwrap();
        match outcome {
            ReplayOutcome::Conflicts { files, paths, .. } => {
                assert_eq!(paths, vec!["x.txt".to_string()]);
                let x = &files.iter().find(|(p, _, _)| p == "x.txt").unwrap().2;
                assert!(String::from_utf8_lossy(x).contains("<<<<<<<"));
            }
            _ => panic!("expected Conflicts"),
        }
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn already_applied_replay_is_empty() {
        let root = tmp_root("empty");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();

        // main independently makes the exact same edit.
        repo.switch("main").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        let main_tip = repo.commit("me", "main makes same edit").unwrap();

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let outcome = replay_commit(&repo, b_tip, onto_root).unwrap();
        assert!(matches!(outcome, ReplayOutcome::Empty));
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn root_commit_replays_against_empty_base() {
        let root_a = tmp_root("root-a");
        let repo_a = Repo::init(&root_a).unwrap();
        std::fs::write(root_a.join("new.txt"), b"new\n").unwrap();
        let a_root_commit = repo_a.commit("me", "lineage a root").unwrap();
        assert!(repo_a.snapshot(&a_root_commit).unwrap().parents.is_empty());

        let root_b = tmp_root("root-b");
        let repo_b = Repo::init(&root_b).unwrap();
        std::fs::write(root_b.join("existing.txt"), b"existing\n").unwrap();
        let b_tip = repo_b.commit("me", "lineage b tip").unwrap();

        // Reconstruct lineage a's root commit inside repo_b's store so
        // `replay_commit` can read it — copy the commit's tree/blob objects.
        let a_snap = repo_a.snapshot(&a_root_commit).unwrap();
        let store_a_arc = repo_a.vfs().store();
        let store_b_arc = repo_b.vfs().store();
        {
            let mut store_a = store_a_arc.lock().unwrap();
            let ids = tree_file_ids(&mut store_a, a_snap.root).unwrap();
            let mut files = Vec::new();
            for (path, id) in ids {
                let bytes = match store_a.get(&id).unwrap() {
                    scl_core::Object::Blob(b) => b.to_vec(),
                    _ => panic!("expected blob"),
                };
                files.push((path, bytes, FileMode::FILE));
            }
            drop(store_a);
            let copied_root = repo_b.vfs().write_tree(&files).unwrap();
            let mut store_b = store_b_arc.lock().unwrap();
            let copied_commit = store_b
                .put(scl_core::Object::Snapshot(scl_core::Snapshot {
                    root: copied_root,
                    parents: vec![],
                    author: "me".into(),
                    timestamp: 0,
                    message: "lineage a root (copied)".into(),
                    secrets: Default::default(),
                    protection: Default::default(),
                }))
                .unwrap();
            drop(store_b);

            let onto_root = repo_b.snapshot(&b_tip).unwrap().root;
            let outcome = replay_commit(&repo_b, copied_commit, onto_root).unwrap();
            match outcome {
                ReplayOutcome::Clean { root: merged_root } => {
                    let mut store_b = store_b_arc.lock().unwrap();
                    let ids = tree_file_ids(&mut store_b, merged_root).unwrap();
                    assert!(ids.contains_key("new.txt"));
                    assert!(ids.contains_key("existing.txt"));
                }
                _ => panic!("expected Clean"),
            }
        }
        drop(repo_a);
        drop(repo_b);
        std::fs::remove_dir_all(&root_a).ok();
        std::fs::remove_dir_all(&root_b).ok();
    }

    #[test]
    fn merge_commit_and_protected_content_are_refused() {
        let root = tmp_root("refused");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        let main_tip = repo.commit("me", "main adds a").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"f\n").unwrap();
        repo.commit("me", "feature adds f").unwrap();
        let merged = repo.merge("main", "me").unwrap();
        assert!(repo.snapshot(&merged).unwrap().parents.len() >= 2);

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let err = replay_commit(&repo, merged, onto_root).unwrap_err();
        assert!(matches!(err, Error::CannotReplayMerge(id) if id == merged), "got {err:?}");
        let _ = base;

        // Protected content: any replay involving a protected snapshot is refused.
        let proot = tmp_root("refused-protected");
        let prepo = Repo::init(&proot).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        prepo.test_set_protected_prefix("secret/", &[pk]).unwrap();
        std::fs::create_dir_all(proot.join("secret")).unwrap();
        std::fs::write(proot.join("secret/db.txt"), b"hunter2").unwrap();
        let pbase = prepo.commit("me", "base").unwrap();
        std::fs::write(proot.join("other.txt"), b"o\n").unwrap();
        let ptip = prepo.commit("me", "adds other").unwrap();

        let onto_root = prepo.snapshot(&pbase).unwrap().root;
        let err = replay_commit(&prepo, ptip, onto_root).unwrap_err();
        assert!(matches!(err, Error::ReplayProtected(_)), "got {err:?}");

        drop(repo);
        drop(prepo);
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&proot).ok();
    }
}
