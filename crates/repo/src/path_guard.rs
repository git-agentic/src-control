//! A tree from a peer may name any path, but a checkout must never write into
//! the `.sc/` control directory (or out of the working tree). These tests plant
//! such a tree through the store API (a commit now refuses it) and check that
//! clone, switch and fast-forward refuse before the first write, and that a
//! failed clone takes itself back out.

use std::path::{Path, PathBuf};

use scl_core::{EntryKind, FileMode, Object, ObjectId, Protection, Snapshot, Tree, TreeEntry};

use crate::error::Error;
use crate::repo::Repo;

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("scl-pg-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn entry(name: &str, kind: EntryKind, id: ObjectId) -> TreeEntry {
    TreeEntry {
        name: name.into(),
        kind,
        id,
        mode: FileMode::FILE,
        perms: 0,
    }
}

/// Store a snapshot whose tree holds `ok.txt` and the planted
/// `.sc/recipients.toml`, either as a real `.sc` directory (`nested`) or as a
/// single entry whose name contains the slash. Returns the snapshot id.
fn plant(repo: &Repo, parent: Option<ObjectId>, nested: bool) -> ObjectId {
    let store = repo.vfs_handle().store();
    let mut s = store.lock().unwrap();
    let blob = s.put(Object::blob(b"planted".to_vec())).unwrap();
    let planted = if nested {
        let sub = s
            .put(Object::Tree(Tree::new(vec![entry(
                "recipients.toml",
                EntryKind::Blob,
                blob,
            )])))
            .unwrap();
        entry(".sc", EntryKind::Tree, sub)
    } else {
        entry(".sc/recipients.toml", EntryKind::Blob, blob)
    };
    let root = s
        .put(Object::Tree(Tree::new(vec![
            planted,
            entry("ok.txt", EntryKind::Blob, blob),
        ])))
        .unwrap();
    s.put(Object::Snapshot(Snapshot {
        root,
        parents: parent.into_iter().collect(),
        author: "t".into(),
        timestamp: 0,
        message: "planted".into(),
        secrets: Default::default(),
        protection: Protection::default(),
    }))
    .unwrap()
}

fn assert_unsafe(err: &Error) {
    assert!(
        matches!(err, Error::Core(scl_core::Error::UnsafePath { .. })),
        "wanted UnsafePath, got {err:?}"
    );
}

/// No file under `root` (the `.sc` dir included) holds the planted bytes.
fn assert_nothing_planted(root: &Path) {
    fn walk(dir: &Path, hits: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, hits);
            } else if std::fs::read(&p).is_ok_and(|b| b == b"planted") {
                hits.push(p);
            }
        }
    }
    let mut hits = Vec::new();
    walk(root, &mut hits);
    assert!(hits.is_empty(), "planted bytes were written: {hits:?}");
    assert!(!root.join(".sc/recipients.toml").exists());
}

fn source_with_planted_tip(tag: &str, nested: bool) -> (Repo, PathBuf) {
    let root = tmp_root(tag);
    let src = Repo::init(&root).unwrap();
    let tip = plant(&src, None, nested);
    crate::refs::write_branch_tip(src.layout(), "main", &tip).unwrap();
    (src, root)
}

fn cleanup(repo: Repo, root: &Path) {
    drop(repo);
    std::fs::remove_dir_all(root).unwrap();
    assert!(!root.exists(), "test root must be removed");
}

#[test]
fn clone_of_a_planted_control_file_fails_and_removes_what_it_created() {
    for nested in [true, false] {
        let (src, src_root) = source_with_planted_tip(&format!("clone-src-{nested}"), nested);
        // A nested destination: the parents the clone made go too.
        let base = tmp_root(&format!("clone-dst-{nested}"));
        let dst = base.join("deep/er/victim");
        let err = Repo::clone_to(&src_root, &dst)
            .err()
            .expect("clone must fail");
        assert_unsafe(&err);
        assert!(
            !base.join("deep").exists(),
            "the destination and the parents the clone created are removed"
        );
        assert!(base.exists(), "the directory that was already there stays");
        std::fs::remove_dir_all(&base).unwrap();
        cleanup(src, &src_root);
    }
}

#[test]
fn failed_clone_into_an_existing_empty_directory_keeps_the_directory() {
    let (src, src_root) = source_with_planted_tip("clone-existing-src", true);
    let dst = tmp_root("clone-existing-dst");
    let err = Repo::clone_to(&src_root, &dst)
        .err()
        .expect("clone must fail");
    assert_unsafe(&err);
    assert!(dst.exists(), "an existing directory is not ours to remove");
    assert_eq!(std::fs::read_dir(&dst).unwrap().count(), 0, "nor to fill");
    std::fs::remove_dir_all(&dst).unwrap();
    cleanup(src, &src_root);
}

#[test]
fn switch_onto_a_planted_tip_refuses_before_writing_anything() {
    let root = tmp_root("switch");
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), "a\n").unwrap();
    let c1 = repo.commit("me", "base").unwrap();
    let evil = plant(&repo, Some(c1), true);
    crate::refs::write_branch_tip(repo.layout(), "evil", &evil).unwrap();
    let err = repo.switch("evil").unwrap_err();
    assert_unsafe(&err);
    assert_eq!(repo.head_tip().unwrap(), Some(c1), "HEAD did not move");
    assert!(!root.join("ok.txt").exists(), "no file was laid");
    assert!(root.join("a.txt").exists(), "the old tree is untouched");
    assert_nothing_planted(&root);
    cleanup(repo, &root);
}

#[test]
fn fast_forward_onto_a_planted_tip_refuses_before_writing_anything() {
    let root = tmp_root("ff");
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), "a\n").unwrap();
    let c1 = repo.commit("me", "base").unwrap();
    let evil = plant(&repo, Some(c1), true);
    crate::refs::write_branch_tip(repo.layout(), "evil", &evil).unwrap();
    let err = repo.merge("evil", "me").unwrap_err();
    assert_unsafe(&err);
    assert_eq!(
        repo.head_tip().unwrap(),
        Some(c1),
        "the branch did not move"
    );
    assert!(!root.join("ok.txt").exists(), "no file was laid");
    assert_nothing_planted(&root);
    cleanup(repo, &root);
}

/// A repo on `main` whose tip is the planted tree (the working tree is stale,
/// which these commands do not read).
fn repo_at_planted_tip(tag: &str) -> (Repo, PathBuf) {
    let root = tmp_root(tag);
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), "a\n").unwrap();
    let c1 = repo.commit("me", "base").unwrap();
    let evil = plant(&repo, Some(c1), true);
    crate::refs::write_branch_tip(repo.layout(), "main", &evil).unwrap();
    (repo, root)
}

#[test]
fn ws_fork_on_a_planted_tip_refuses_before_changing_the_filesystem() {
    let (repo, root) = repo_at_planted_tip("ws-fork");
    // Residue a fork would clear, and the key it would mint.
    let ws = root.join(".sc/ws");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("leftover"), "keep").unwrap();
    // The commit in the setup minted the key; drop it so a new one is visible.
    let _ = std::fs::remove_file(root.join(".sc/local-key"));
    let err = repo.ws_fork(None, 2, "me", None).unwrap_err();
    assert_unsafe(&err);
    assert_eq!(std::fs::read(ws.join("leftover")).unwrap(), b"keep");
    assert!(!ws.join("1").exists() && !ws.join("session.toml").exists());
    assert!(!root.join(".sc/local-key").exists(), "no key was minted");
    cleanup(repo, &root);
}

#[test]
fn sc_work_on_a_planted_tip_refuses_before_creating_the_session() {
    let (repo, root) = repo_at_planted_tip("work");
    let scratch = tmp_root("work-scratch");
    let session = scratch.join("session");
    let err = repo
        .work(crate::workspace::WorkOptions {
            agents: 1,
            base_name: "work".into(),
            cmd: vec!["true".into()],
            author: "t".into(),
            message: None,
            identity: None,
            with_secrets: false,
            session_root: Some(session.clone()),
        })
        .unwrap_err();
    assert_unsafe(&err);
    assert!(!session.exists(), "no session root was created");
    std::fs::remove_dir_all(&scratch).unwrap();
    cleanup(repo, &root);
}

#[test]
fn discard_failed_clone_removes_only_what_the_clone_made() {
    // A missing destination with missing parents is claimed: the destination
    // and every parent the claim made go, the directory that was there stays.
    let parent = tmp_root("discard-parent");
    let created = parent.join("deep/er/dst");
    let claim = crate::sync::claim_clone_dir(&created).unwrap();
    Repo::init(&created).unwrap();
    crate::sync::discard_failed_clone(&claim);
    assert!(!parent.join("deep").exists(), "claimed parents are removed");
    assert!(parent.exists(), "a pre-existing parent is not");
    std::fs::remove_dir_all(&parent).unwrap();

    // A claimed destination that gained a file is left, and so are its parents.
    let parent = tmp_root("discard-nonempty");
    let created = parent.join("deep/dst");
    let claim = crate::sync::claim_clone_dir(&created).unwrap();
    Repo::init(&created).unwrap();
    std::fs::write(created.join("stray"), "x").unwrap();
    crate::sync::discard_failed_clone(&claim);
    assert!(!created.join(".sc").exists());
    assert!(created.join("stray").exists(), "remove_dir only, never all");
    std::fs::remove_dir_all(&parent).unwrap();

    // An existing empty directory is accepted and kept; only its `.sc/` goes.
    let existing = tmp_root("discard-existing");
    let claim = crate::sync::claim_clone_dir(&existing).unwrap();
    Repo::init(&existing).unwrap();
    crate::sync::discard_failed_clone(&claim);
    assert!(existing.exists() && !existing.join(".sc").exists());
    std::fs::remove_dir_all(&existing).unwrap();
    assert!(!existing.exists());
}

#[test]
fn a_repo_exists_race_during_clone_removes_nothing() {
    // The destination is claimed while empty, then another process makes `.sc/`.
    let parent = tmp_root("race");
    let dst = parent.join("deep/dst");
    let claim = crate::sync::claim_clone_dir(&dst).unwrap();
    std::fs::create_dir_all(dst.join(".sc")).unwrap();
    std::fs::write(dst.join(".sc/precious"), "theirs").unwrap();
    let err = Repo::init(&dst).err().expect("init must refuse");
    assert!(matches!(err, Error::RepoExists(_)), "{err:?}");
    crate::sync::discard_after_init_error(&claim, &err);
    assert_eq!(std::fs::read(dst.join(".sc/precious")).unwrap(), b"theirs");
    std::fs::remove_dir_all(&parent).unwrap();
}

#[test]
fn clone_into_a_non_empty_directory_is_refused_and_changes_nothing() {
    let (src, src_root) = source_with_planted_tip("clone-nonempty-src", true);
    let dst = tmp_root("clone-nonempty-dst");
    std::fs::write(dst.join("mine.txt"), "keep me").unwrap();
    let err = Repo::clone_to(&src_root, &dst)
        .err()
        .expect("clone must fail");
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    assert_eq!(std::fs::read(dst.join("mine.txt")).unwrap(), b"keep me");
    assert!(!dst.join(".sc").exists());
    // A symlink already inside the destination could redirect checkout writes.
    #[cfg(unix)]
    {
        std::fs::remove_file(dst.join("mine.txt")).unwrap();
        std::os::unix::fs::symlink("/nonexistent-sc-target", dst.join("link")).unwrap();
        let err = Repo::clone_to(&src_root, &dst)
            .err()
            .expect("clone must fail");
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
        assert!(!dst.join(".sc").exists());
    }
    std::fs::remove_dir_all(&dst).unwrap();
    cleanup(src, &src_root);
}

#[test]
fn commit_refuses_a_control_dir_alias() {
    let root = tmp_root("commit");
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), "a\n").unwrap();
    let c1 = repo.commit("me", "base").unwrap();
    std::fs::create_dir_all(root.join("sub/.SC")).unwrap();
    std::fs::write(root.join("sub/.SC/x"), "x").unwrap();
    let err = repo.commit("me", "alias").unwrap_err();
    assert!(
        matches!(
            &err,
            Error::Vfs(scl_vfs::Error::Core(scl_core::Error::UnsafePath { .. }))
        ),
        "{err:?}"
    );
    assert_eq!(repo.head_tip().unwrap(), Some(c1), "no ref moved");
    cleanup(repo, &root);
}

#[test]
fn private_tree_builder_refuses_a_control_dir_alias() {
    let blob = Object::blob(b"x".to_vec()).id();
    let map = |p: &str| std::iter::once((p.to_string(), (blob, FileMode::FILE, 0u8))).collect();
    for bad in [".sc/x", "a/.Sc/b", "sc~1"] {
        assert!(
            crate::private::build_tree_objects(&map(bad)).is_err(),
            "{bad}"
        );
    }
    assert!(crate::private::build_tree_objects(&map("a/.scignore")).is_ok());
}
