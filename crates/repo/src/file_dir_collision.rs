//! #278: a snapshot may never hold a path as both a file and the parent
//! directory of another path. The absent-path carry (protected content the
//! committer cannot read, paths outside the sparse view) used to be able to put
//! a stale file next to a directory the user or agent created at the same path.
//! Every commit path ends in the one tree builder, which now refuses; nothing
//! moves a ref when it does.

use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::repo::Repo;
use crate::worktree;

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("scl-fdc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn put(root: &Path, rel: &str, body: &str) {
    let full = root.join(rel);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, body).unwrap();
}

/// The error names both the file and the path that needs it to be a directory.
fn assert_collision(err: &Error, file: &str, child: &str) {
    let msg = err.to_string();
    assert!(
        matches!(err, Error::Vfs(scl_vfs::Error::FileDirCollision { .. })),
        "wanted a file/directory collision, got {err:?}"
    );
    assert!(
        msg.contains(file) && msg.contains(child),
        "message must name both paths: {msg}"
    );
}

/// A repo whose `main` holds a protected file `secret` (and `keep.txt`), plus
/// a checkout where `secret` is absent: the state of a committer with no key.
/// Returns the repo, its root and the tip, with the working tree clean.
fn keyless_checkout(tag: &str) -> (Repo, PathBuf, scl_core::ObjectId) {
    let root = tmp_root(tag);
    let repo = Repo::init(&root).unwrap();
    let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
    let (mallory_sk, _) = scl_crypto::generate_keypair();
    repo.test_set_protected_prefix("secret/", &[alice_pk])
        .unwrap();
    repo.branch("other").unwrap();
    put(&root, "secret", "hunter2");
    put(&root, "keep.txt", "k\n");
    let c1 = repo.commit("me", "base").unwrap();
    repo.switch_with_identity("other", Some(&mallory_sk))
        .unwrap();
    let skipped = repo
        .switch_with_identity("main", Some(&mallory_sk))
        .unwrap();
    assert_eq!(skipped, vec!["secret".to_string()]);
    assert!(!root.join("secret").exists());
    (repo, root, c1)
}

fn cleanup(repo: Repo, root: &Path) {
    drop(repo);
    std::fs::remove_dir_all(root).unwrap();
    assert!(!root.exists(), "test root must be removed");
}

#[test]
fn commit_refuses_a_directory_over_an_absent_protected_file() {
    let (repo, root, c1) = keyless_checkout("commit-dir");
    put(&root, "secret/notes.txt", "mine\n");
    let err = repo.commit("mallory", "dir").unwrap_err();
    assert_collision(&err, "secret", "secret/notes.txt");
    assert_eq!(repo.head_tip().unwrap(), Some(c1), "no ref moved");
    cleanup(repo, &root);
}

#[test]
fn commit_refuses_a_file_over_an_absent_protected_directory() {
    let root = tmp_root("commit-file");
    let repo = Repo::init(&root).unwrap();
    let (_sk, alice_pk) = scl_crypto::generate_keypair();
    let (mallory_sk, _) = scl_crypto::generate_keypair();
    repo.test_set_protected_prefix("vault/", &[alice_pk])
        .unwrap();
    repo.branch("other").unwrap();
    put(&root, "vault/sub/a.txt", "a");
    let c1 = repo.commit("me", "base").unwrap();
    repo.switch_with_identity("other", Some(&mallory_sk))
        .unwrap();
    repo.switch_with_identity("main", Some(&mallory_sk))
        .unwrap();
    // `vault/sub` is absent for mallory, who creates a plain *file* of that name.
    let _ = std::fs::remove_dir_all(root.join("vault"));
    put(&root, "vault/sub", "not a dir\n");
    let err = repo.commit("mallory", "file").unwrap_err();
    assert_collision(&err, "vault/sub", "vault/sub/a.txt");
    assert_eq!(repo.head_tip().unwrap(), Some(c1));
    cleanup(repo, &root);
}

#[test]
fn commit_refuses_a_directory_over_an_out_of_sparse_file() {
    let root = tmp_root("sparse");
    let repo = Repo::init(&root).unwrap();
    put(&root, "src/a.txt", "a");
    put(&root, "docs", "a file\n");
    let c1 = repo.commit("me", "base").unwrap();
    repo.set_sparse(&["src/".to_string()], None).unwrap();
    assert!(!root.join("docs").exists());
    put(&root, "docs/x.txt", "x\n");
    let err = repo.commit("me", "dir").unwrap_err();
    assert_collision(&err, "docs", "docs/x.txt");
    assert_eq!(repo.head_tip().unwrap(), Some(c1));
    cleanup(repo, &root);
}

#[test]
fn a_real_file_to_directory_transition_still_commits() {
    // #247: across commits a path may change kind; only one snapshot may not
    // hold both.
    let root = tmp_root("transition");
    let repo = Repo::init(&root).unwrap();
    put(&root, "x", "file\n");
    repo.commit("me", "file").unwrap();
    std::fs::remove_file(root.join("x")).unwrap();
    put(&root, "x/inner.txt", "dir\n");
    let c2 = repo.commit("me", "dir").unwrap();
    let root_id = repo.snapshot(&c2).unwrap().root;
    let files = {
        let a = repo.vfs_handle().store();
        let mut s = a.lock().unwrap();
        worktree::tree_file_entries_with_perms(&mut s, root_id).unwrap()
    };
    assert_eq!(files.keys().collect::<Vec<_>>(), vec!["x/inner.txt"]);
    cleanup(repo, &root);
}

#[test]
fn merge_completion_refuses_a_directory_over_a_carried_protected_file() {
    let (repo, root, _c1) = keyless_checkout("merge");
    // Both sides edit keep.txt, so the merge stops; `secret` is carried absent.
    repo.branch("feature").unwrap();
    put(&root, "keep.txt", "ours\n");
    let ours = repo.commit("mallory", "ours").unwrap();
    let (mallory_sk, _) = scl_crypto::generate_keypair();
    repo.switch_with_identity("feature", Some(&mallory_sk))
        .unwrap();
    put(&root, "keep.txt", "theirs\n");
    repo.commit("mallory", "theirs").unwrap();
    repo.switch_with_identity("main", Some(&mallory_sk))
        .unwrap();
    assert!(matches!(
        repo.merge_with_identity("feature", "mallory", None),
        Err(Error::MergeConflicts(1))
    ));
    put(&root, "keep.txt", "resolved\n");
    put(&root, "secret/notes.txt", "mine\n");
    let err = repo.commit("mallory", "merge").unwrap_err();
    assert_collision(&err, "secret", "secret/notes.txt");
    assert_eq!(repo.head_tip().unwrap(), Some(ours), "no ref moved");
    cleanup(repo, &root);
}

#[test]
fn ws_harvest_refuses_a_directory_over_an_absent_protected_file() {
    let (repo, root, c1) = keyless_checkout("ws");
    // Forked without a key, so `secret` is absent from the workspace.
    let s = repo.ws_fork(None, 1, "t", None).unwrap();
    let dir = s.workspaces[0].dir.clone();
    assert!(!dir.join("secret").exists());
    put(&dir, "secret/agent.txt", "agent\n");
    let err = repo.ws_harvest(None, None, Some("t"), None).unwrap_err();
    assert_collision(&err, "secret", "secret/agent.txt");
    assert_eq!(repo.head_tip().unwrap(), Some(c1), "no ref moved");
    assert!(
        crate::refs::resolve_tip(repo.layout(), "ws-1")
            .unwrap()
            .is_none(),
        "no candidate branch left behind"
    );
    // The session is still open: removing the directory lets it harvest.
    std::fs::remove_dir_all(dir.join("secret")).unwrap();
    put(&dir, "other.txt", "ok\n");
    let out = repo.ws_harvest(None, None, Some("t"), None).unwrap();
    assert_eq!(out.len(), 1);
    cleanup(repo, &root);
}

#[test]
fn ws_refresh_refuses_before_any_write() {
    let (repo, root, c1) = keyless_checkout("refresh");
    let s = repo.ws_fork(None, 1, "t", None).unwrap();
    let dir = s.workspaces[0].dir.clone();
    put(&dir, "secret/agent.txt", "agent\n");
    put(&root, "host.txt", "h\n");
    repo.commit("me", "host moves on").unwrap();
    let err = repo.ws_refresh(None, None, None).unwrap_err();
    assert_collision(&err, "secret", "secret/agent.txt");
    let after = repo.ws_session(None).unwrap().unwrap();
    assert_eq!(after.base_snapshot, c1, "base not moved");
    assert!(
        !dir.join("host.txt").exists(),
        "nothing laid into the checkout"
    );
    assert!(after.pending_refresh.is_none());
    cleanup(repo, &root);
}

#[test]
fn private_commit_refuses_a_directory_over_an_out_of_sparse_file() {
    // A private commit carries out-of-view paths through its own tree builder.
    let root = tmp_root("private");
    let repo = Repo::init(&root).unwrap();
    put(&root, "src/a.txt", "a");
    put(&root, "docs", "a file\n");
    repo.commit("me", "base").unwrap();
    let (sk, _) = scl_crypto::generate_keypair();
    repo.set_sparse(&["src/".to_string()], Some(&sk)).unwrap();
    repo.branch_private("fix", &sk, &[], &[]).unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    assert!(!root.join("docs").exists());
    let before = crate::refs::resolve_tip(repo.layout(), "fix").unwrap();
    put(&root, "docs/x.txt", "x\n");
    let err = repo.commit_private("me", "dir", Some(&sk)).unwrap_err();
    assert_collision(&err, "docs", "docs/x.txt");
    assert_eq!(
        crate::refs::resolve_tip(repo.layout(), "fix").unwrap(),
        before,
        "private ref did not move"
    );
    cleanup(repo, &root);
}
