//! A stop's checkout and an abort delete or overwrite a path only when it is
//! the stop's own file: tracked by the tree being replaced with exactly its
//! bytes, or recorded as written by the stop. Anything else is the user's and
//! is left in place (#255, #256). Pinned for merge, cherry-pick and rebase.

use std::path::{Path, PathBuf};

use crate::replay::RebaseResult;
use crate::repo::{AbortReport, Repo};

#[derive(Clone, Copy, Debug)]
enum Op {
    Merge,
    Pick,
    Rebase,
}

const OPS: [Op; 3] = [Op::Merge, Op::Pick, Op::Rebase];

fn root_for(tag: &str, op: Op) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "scl-user-file-safety-{tag}-{op:?}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn put(root: &Path, rel: &str, bytes: &[u8]) {
    let full = root.join(rel);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, bytes).unwrap();
}

fn read(root: &Path, rel: &str) -> Vec<u8> {
    std::fs::read(root.join(rel)).unwrap()
}

fn stop(repo: &Repo, op: Op) {
    match op {
        Op::Merge => {
            repo.merge("feature", "me").unwrap_err();
        }
        Op::Pick => {
            repo.cherry_pick("feature", "me", None, None).unwrap_err();
        }
        Op::Rebase => assert!(matches!(
            repo.rebase("main", "me", None).unwrap(),
            RebaseResult::Stopped { .. }
        )),
    }
}

fn abort(repo: &Repo, op: Op) -> AbortReport {
    match op {
        Op::Merge => repo.merge_abort(),
        Op::Pick => repo.cherry_pick_abort(),
        Op::Rebase => repo.rebase_abort(),
    }
    .unwrap()
}

fn finish(root: &Path, repo: Repo) {
    drop(repo);
    std::fs::remove_dir_all(root).unwrap();
    assert!(!root.exists(), "test repository must leave no residue");
}

/// `x.txt` conflicts as text. `main` deletes `y.txt` and adds `main_only.txt`;
/// `feature` keeps `y.txt` and adds `added.txt`. Merge and pick run on `main`
/// (theirs = feature), rebase runs on `feature` (onto main). `view`, if set,
/// narrows to `src/` (which then holds the conflict as `src/x.txt`) before the
/// stop, which it runs, with `docs/*` tracked outside it.
fn stopped(tag: &str, op: Op, view: bool) -> (PathBuf, Repo) {
    let root = root_for(tag, op);
    let repo = Repo::init(&root).unwrap();
    let x = if view { "src/x.txt" } else { "x.txt" };
    put(&root, x, b"a\nb\nc\n");
    put(&root, "y.txt", b"y\n");
    put(&root, "docs/d.txt", b"d\n");
    put(&root, "docs/e.txt", b"e\n");
    repo.commit("me", "base").unwrap();
    repo.branch("feature").unwrap();
    put(&root, x, b"a\nMAIN\nc\n");
    std::fs::remove_file(root.join("y.txt")).unwrap();
    put(&root, "main_only.txt", b"from main\n");
    repo.commit("me", "main").unwrap();
    repo.switch("feature").unwrap();
    put(&root, x, b"a\nFEATURE\nc\n");
    put(&root, "added.txt", b"from feature\n");
    repo.commit("me", "feature").unwrap();
    if view {
        repo.set_sparse(&["src/".into()], None).unwrap();
        assert!(
            !root.join("docs/d.txt").exists(),
            "setup: docs/ is out of view"
        );
    }
    if !matches!(op, Op::Rebase) {
        repo.switch("main").unwrap();
    }
    stop(&repo, op);
    (root, repo)
}

/// The file the stop lays that the restored tip does not track.
fn laid(op: Op) -> &'static str {
    match op {
        Op::Merge | Op::Pick => "added.txt",
        Op::Rebase => "main_only.txt",
    }
}

#[test]
fn abort_removes_the_files_the_stop_laid() {
    for op in OPS {
        let (root, repo) = stopped("laid", op, false);
        assert!(root.join(laid(op)).exists(), "{op:?}: setup");
        let report = abort(&repo, op);
        assert!(!root.join(laid(op)).exists(), "{op:?}: laid file survived");
        assert!(report.kept.is_empty(), "{op:?}: {report:?}");
        finish(&root, repo);
    }
}

#[test]
fn abort_keeps_a_stop_file_the_user_changed_and_says_so() {
    for op in OPS {
        let (root, repo) = stopped("edited", op, false);
        put(&root, laid(op), b"MINE\n");
        let report = abort(&repo, op);
        assert_eq!(read(&root, laid(op)), b"MINE\n", "{op:?}");
        assert_eq!(report.kept, vec![laid(op).to_string()], "{op:?}");
        finish(&root, repo);
    }
}

#[test]
fn abort_keeps_a_user_file_at_a_path_the_stop_never_laid() {
    // `y.txt` is in theirs' tree (merge, pick) or the restored tip (rebase)
    // but not in the stop's result: the user's new file there is not ours.
    for op in OPS {
        let (root, repo) = stopped("never", op, false);
        assert!(!root.join("y.txt").exists(), "{op:?}: setup");
        put(&root, "y.txt", b"MINE\n");
        let report = abort(&repo, op);
        assert_eq!(read(&root, "y.txt"), b"MINE\n", "{op:?}");
        // Rebase would have restored its own y.txt there; it says it did not.
        let expect: Vec<String> = if matches!(op, Op::Rebase) {
            vec!["y.txt".into()]
        } else {
            vec![]
        };
        assert_eq!(report.kept, expect, "{op:?}");
        finish(&root, repo);
    }
}

#[test]
fn abort_keeps_a_symlink_where_the_stop_laid_a_file() {
    #[cfg(unix)]
    for op in OPS {
        let (root, repo) = stopped("symlink", op, false);
        std::fs::remove_file(root.join(laid(op))).unwrap();
        std::fs::write(root.join("elsewhere"), b"from main\n").unwrap();
        std::os::unix::fs::symlink("elsewhere", root.join(laid(op))).unwrap();
        let report = abort(&repo, op);
        assert!(
            root.join(laid(op)).symlink_metadata().unwrap().is_symlink(),
            "{op:?}"
        );
        assert_eq!(report.kept, vec![laid(op).to_string()], "{op:?}");
        finish(&root, repo);
    }
}

#[test]
fn a_stop_keeps_a_local_copy_of_an_out_of_view_tracked_file() {
    for op in OPS {
        let (root, repo) = {
            // The user restores local copies before the stop: one edited, one
            // identical to the tip. They are tracked, so the stop's guard
            // skips them.
            let root = root_for("oov-stop", op);
            let repo = Repo::init(&root).unwrap();
            put(&root, "src/x.txt", b"a\nb\nc\n");
            put(&root, "docs/d.txt", b"d\n");
            put(&root, "docs/e.txt", b"e\n");
            repo.commit("me", "base").unwrap();
            repo.branch("feature").unwrap();
            put(&root, "src/x.txt", b"a\nMAIN\nc\n");
            repo.commit("me", "main").unwrap();
            repo.switch("feature").unwrap();
            put(&root, "src/x.txt", b"a\nFEATURE\nc\n");
            repo.commit("me", "feature").unwrap();
            repo.set_sparse(&["src/".into()], None).unwrap();
            if !matches!(op, Op::Rebase) {
                repo.switch("main").unwrap();
            }
            put(&root, "docs/d.txt", b"MINE\n");
            put(&root, "docs/e.txt", b"e\n");
            (root, repo)
        };
        stop(&repo, op);
        assert_eq!(read(&root, "docs/d.txt"), b"MINE\n", "{op:?}: stop");
        assert!(
            !root.join("docs/e.txt").exists(),
            "{op:?}: an unchanged copy goes as before"
        );
        let report = abort(&repo, op);
        assert_eq!(read(&root, "docs/d.txt"), b"MINE\n", "{op:?}: abort");
        assert!(
            report.kept.is_empty(),
            "{op:?}: out of view is not reported"
        );
        finish(&root, repo);
    }
}

#[test]
fn an_edited_out_of_view_file_is_committed_as_the_users_edit() {
    // Completion semantics stay (ADR-0034 refinement 5): the user's copy of a
    // tracked out-of-view file is read like any tracked file.
    for op in [Op::Merge, Op::Pick] {
        let (root, repo) = stopped("oov-commit", op, true);
        put(&root, "docs/d.txt", b"MINE\n");
        put(&root, "src/x.txt", b"a\nresolved\nc\n");
        repo.commit("me", "complete").unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let root_id = repo.snapshot(&tip).unwrap().root;
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let files = crate::worktree::tree_file_entries_with_perms(&mut store, root_id).unwrap();
        let (blob, ..) = files["docs/d.txt"];
        assert_eq!(
            store.get(&blob).unwrap(),
            scl_core::Object::blob(b"MINE\n".to_vec()),
            "{op:?}"
        );
        drop(store);
        finish(&root, repo);
    }
}
