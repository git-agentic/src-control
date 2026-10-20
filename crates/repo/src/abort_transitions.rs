//! Tests for #247: aborting (or otherwise leaving) a tree where the other side
//! turned a file into a directory, or the reverse. The restore must replace
//! the stop's layout at that path, never fail with `IsADirectory` /
//! `NotADirectory`, and never delete anything the tree being replaced does not
//! track.

use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::repo::Repo;
use crate::RebaseResult;

/// How the path `x` is laid out on a side.
#[derive(Clone, Copy, Debug)]
enum Shape {
    File,
    Dir,
}

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("scl-repo-abort-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn lay(root: &Path, shape: Shape) {
    let _ = std::fs::remove_file(root.join("x"));
    let _ = std::fs::remove_dir_all(root.join("x"));
    match shape {
        Shape::File => std::fs::write(root.join("x"), b"file\n").unwrap(),
        Shape::Dir => {
            std::fs::create_dir_all(root.join("x")).unwrap();
            std::fs::write(root.join("x/a"), b"a\n").unwrap();
        }
    }
}

fn assert_shape(root: &Path, shape: Shape) {
    match shape {
        Shape::File => assert_eq!(std::fs::read(root.join("x")).unwrap(), b"file\n"),
        Shape::Dir => {
            assert!(root.join("x").is_dir());
            assert_eq!(std::fs::read(root.join("x/a")).unwrap(), b"a\n");
            assert_eq!(std::fs::read_dir(root.join("x")).unwrap().count(), 1);
        }
    }
}

/// `main` keeps `x` as `ours`; branch `other` turns it into `theirs` and both
/// edit `c.txt`'s first line, so combining them stops on a conflict.
fn fixture(tag: &str, ours: Shape, theirs: Shape) -> (PathBuf, Repo) {
    let root = tmp_root(tag);
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("c.txt"), b"1\n2\n3\n").unwrap();
    lay(&root, ours);
    repo.commit("me", "base").unwrap();
    repo.branch("other").unwrap();
    std::fs::write(root.join("c.txt"), b"OURS\n2\n3\n").unwrap();
    repo.commit("me", "main").unwrap();
    repo.switch("other").unwrap();
    lay(&root, theirs);
    std::fs::write(root.join("c.txt"), b"THEIRS\n2\n3\n").unwrap();
    repo.commit("me", "other").unwrap();
    repo.switch("main").unwrap();
    (root, repo)
}

fn assert_restored(root: &Path, repo: &Repo, ours: Shape) {
    assert_shape(root, ours);
    assert_eq!(std::fs::read(root.join("c.txt")).unwrap(), b"OURS\n2\n3\n");
    let st = repo.status().unwrap();
    assert!(st.modified.is_empty() && st.deleted.is_empty(), "{st:?}");
}

fn finish(root: &Path, repo: Repo) {
    drop(repo);
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        !root.exists(),
        "test root {} must be removed",
        root.display()
    );
}

const TRANSITIONS: [(&str, Shape, Shape); 2] = [
    ("f2d", Shape::File, Shape::Dir),
    ("d2f", Shape::Dir, Shape::File),
];

#[test]
fn merge_abort_restores_a_file_dir_transition() {
    for (tag, ours, theirs) in TRANSITIONS {
        let (root, repo) = fixture(&format!("merge-{tag}"), ours, theirs);
        assert!(matches!(
            repo.merge("other", "me").unwrap_err(),
            Error::MergeConflicts(_)
        ));
        assert_shape(&root, theirs);
        repo.merge_abort().unwrap();
        assert_restored(&root, &repo, ours);
        finish(&root, repo);
    }
}

#[test]
fn cherry_pick_abort_restores_a_file_dir_transition() {
    for (tag, ours, theirs) in TRANSITIONS {
        let (root, repo) = fixture(&format!("pick-{tag}"), ours, theirs);
        let r = repo.cherry_pick("other", "me", None, None);
        assert!(matches!(r, Err(Error::PickConflicts(_))), "{r:?}");
        assert_shape(&root, theirs);
        repo.cherry_pick_abort().unwrap();
        assert_restored(&root, &repo, ours);
        finish(&root, repo);
    }
}

#[test]
fn rebase_abort_restores_a_file_dir_transition() {
    for (tag, ours, theirs) in TRANSITIONS {
        let (root, repo) = fixture(&format!("rebase-{tag}"), ours, theirs);
        let r = repo.rebase("other", "me", None).unwrap();
        assert!(matches!(r, RebaseResult::Stopped { .. }), "{r:?}");
        assert_shape(&root, theirs);
        repo.rebase_abort().unwrap();
        assert_restored(&root, &repo, ours);
        finish(&root, repo);
    }
}

/// A stopped merge with `x` a directory the abort must turn back into a
/// file. `add` puts something of the user's under `x/`; the abort must then
/// refuse having changed nothing, and succeed once `remove` takes it away.
fn refused_abort_changes_nothing(tag: &str, add: impl FnOnce(&Path), remove: impl FnOnce(&Path)) {
    let (root, repo) = fixture(tag, Shape::File, Shape::Dir);
    assert!(matches!(
        repo.merge("other", "me").unwrap_err(),
        Error::MergeConflicts(_)
    ));
    let markers = std::fs::read(root.join("c.txt")).unwrap();
    assert!(String::from_utf8_lossy(&markers).contains("<<<<<<<"));
    add(&root.join("x"));
    assert!(repo.merge_abort().is_err());
    assert!(repo.merge_in_progress(), "the merge is still open");
    assert_eq!(std::fs::read(root.join("c.txt")).unwrap(), markers);
    assert_eq!(std::fs::read(root.join("x/a")).unwrap(), b"a\n");
    remove(&root.join("x"));
    repo.merge_abort().unwrap();
    assert_restored(&root, &repo, Shape::File);
    finish(&root, repo);
}

/// An untracked file inside the directory the abort must replace with a file
/// is the user's: the abort refuses before the first write and stays retryable.
#[test]
fn merge_abort_keeps_untracked_content_in_the_obstructing_directory() {
    refused_abort_changes_nothing(
        "merge-untracked",
        |x| std::fs::write(x.join("mine.txt"), b"mine\n").unwrap(),
        |x| std::fs::remove_file(x.join("mine.txt")).unwrap(),
    );
}

#[test]
fn abort_refuses_an_ignored_file_and_a_dotfile_in_the_directory() {
    refused_abort_changes_nothing(
        "merge-ignored",
        |x| {
            std::fs::write(x.join("../.scignore"), b"*.tmp\n").unwrap();
            std::fs::write(x.join("scratch.tmp"), b"t\n").unwrap();
        },
        |x| std::fs::remove_file(x.join("scratch.tmp")).unwrap(),
    );
    refused_abort_changes_nothing(
        "merge-dotfile",
        |x| std::fs::write(x.join(".hidden"), b"h\n").unwrap(),
        |x| std::fs::remove_file(x.join(".hidden")).unwrap(),
    );
}

/// A symlink to a directory outside the repository, directly or nested, is
/// neither followed nor removed.
#[cfg(unix)]
#[test]
fn abort_refuses_a_symlink_to_an_outside_directory() {
    let outside = tmp_root("symlink-outside");
    std::fs::create_dir(outside.join("keep")).unwrap();
    for nested in [false, true] {
        let target = outside.clone();
        refused_abort_changes_nothing(
            &format!("merge-symlink-{nested}"),
            |x| {
                let dir = if nested {
                    std::fs::create_dir(x.join("sub")).unwrap();
                    x.join("sub")
                } else {
                    x.to_path_buf()
                };
                std::os::unix::fs::symlink(&target, dir.join("link")).unwrap();
            },
            |x| {
                let dir = if nested {
                    x.join("sub")
                } else {
                    x.to_path_buf()
                };
                std::fs::remove_file(dir.join("link")).unwrap();
            },
        );
        assert!(outside.join("keep").is_dir(), "the link was followed");
    }
    std::fs::remove_dir_all(&outside).unwrap();
}

/// A subdirectory that cannot be read is treated as holding the user's
/// content (skipped when the process can read it anyway, as root does).
#[cfg(unix)]
#[test]
fn abort_refuses_an_unreadable_subdirectory() {
    use std::os::unix::fs::PermissionsExt;
    let probe = tmp_root("unreadable-probe");
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::read_dir(&probe).is_ok();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(&probe).unwrap();
    if readable {
        return;
    }
    refused_abort_changes_nothing(
        "merge-unreadable",
        |x| {
            std::fs::create_dir(x.join("locked")).unwrap();
            std::fs::set_permissions(x.join("locked"), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        },
        |x| {
            std::fs::set_permissions(x.join("locked"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::fs::remove_dir(x.join("locked")).unwrap();
        },
    );
}

/// `switch` and `undo` across a file/directory change at one path.
#[test]
fn switch_and_undo_cross_a_file_dir_transition() {
    for (tag, ours, theirs) in TRANSITIONS {
        let root = tmp_root(&format!("switch-{tag}"));
        let repo = Repo::init(&root).unwrap();
        lay(&root, ours);
        repo.commit("me", "base").unwrap();
        repo.branch("other").unwrap();
        repo.switch("other").unwrap();
        lay(&root, theirs);
        repo.commit("me", "other").unwrap();
        repo.switch("main").unwrap();
        assert_shape(&root, ours);
        repo.switch("other").unwrap();
        assert_shape(&root, theirs);
        repo.switch("main").unwrap();
        assert_shape(&root, ours);
        lay(&root, theirs);
        repo.commit("me", "flip").unwrap();
        repo.undo().unwrap();
        assert_shape(&root, ours);
        finish(&root, repo);
    }
}

/// `rebase --continue` lays a later commit's file/directory change over the
/// resolved stop.
#[test]
fn rebase_continue_crosses_a_file_dir_transition() {
    for (tag, from, to) in TRANSITIONS {
        let root = tmp_root(&format!("continue-{tag}"));
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("c.txt"), b"1\n2\n3\n").unwrap();
        lay(&root, from);
        repo.commit("me", "base").unwrap();
        repo.branch("other").unwrap();
        std::fs::write(root.join("c.txt"), b"OURS\n2\n3\n").unwrap();
        repo.commit("me", "a").unwrap();
        lay(&root, to);
        repo.commit("me", "b").unwrap();
        repo.switch("other").unwrap();
        std::fs::write(root.join("c.txt"), b"THEIRS\n2\n3\n").unwrap();
        repo.commit("me", "other").unwrap();
        repo.switch("main").unwrap();
        assert!(matches!(
            repo.rebase("other", "me", None).unwrap(),
            RebaseResult::Stopped { .. }
        ));
        std::fs::write(root.join("c.txt"), b"RESOLVED\n2\n3\n").unwrap();
        let r = repo.rebase_continue("me", None).unwrap();
        assert!(matches!(r, RebaseResult::Rebased { .. }), "{r:?}");
        assert_shape(&root, to);
        finish(&root, repo);
    }
}

/// The same abort on a `--filter src/` partial clone, with `src/x` changing
/// between file and directory on the other side.
#[test]
fn merge_abort_restores_a_file_dir_transition_on_a_partial_clone() {
    use crate::partial_merge::{clone_edit_src, Fx};
    for (tag, ours, theirs) in TRANSITIONS {
        let fx = Fx::origin(&format!("abort-fd-{tag}"), |root| {
            lay(&root.join("src"), ours);
        });
        fx.origin.branch("b1").unwrap();
        fx.origin.switch("b1").unwrap();
        lay(&fx.origin_root.join("src"), theirs);
        std::fs::write(fx.origin_root.join("src/a.txt"), b"ONE\ntwo\nthree\n").unwrap();
        fx.origin.commit("t", "b1").unwrap();
        fx.origin.switch("main").unwrap();
        let clone = fx.clone(false);
        clone_edit_src(&fx, &clone, b"uno\ntwo\nthree\n");
        assert!(matches!(
            clone.merge("origin/b1", "t").unwrap_err(),
            Error::MergeConflicts(_)
        ));
        assert_shape(&fx.clone_root.join("src"), theirs);
        clone.merge_abort().unwrap();
        assert_shape(&fx.clone_root.join("src"), ours);
        let st = clone.status().unwrap();
        assert!(st.modified.is_empty() && st.deleted.is_empty(), "{st:?}");
        drop(clone);
        fx.cleanup();
    }
}

/// A forward `switch` onto a file where a directory with an untracked file
/// stands still refuses, and deletes nothing.
#[test]
fn switch_refuses_a_file_over_a_directory_holding_untracked_content() {
    let root = tmp_root("switch-untracked");
    let repo = Repo::init(&root).unwrap();
    lay(&root, Shape::Dir);
    repo.commit("me", "base").unwrap();
    repo.branch("other").unwrap();
    repo.switch("other").unwrap();
    lay(&root, Shape::File);
    repo.commit("me", "other").unwrap();
    repo.switch("main").unwrap();
    std::fs::write(root.join("x/mine.txt"), b"mine\n").unwrap();
    let err = repo.switch("other").unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    assert_eq!(std::fs::read(root.join("x/mine.txt")).unwrap(), b"mine\n");
    assert_eq!(std::fs::read(root.join("x/a")).unwrap(), b"a\n");
    finish(&root, repo);
}

/// A user's empty directory is not evidence of tracked content: a forward
/// `switch` onto a file at its path refuses and keeps it.
#[test]
fn switch_keeps_an_untracked_empty_directory_where_a_file_must_go() {
    let root = tmp_root("switch-empty-dir");
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("c.txt"), b"c\n").unwrap();
    repo.commit("me", "base").unwrap();
    repo.branch("other").unwrap();
    repo.switch("other").unwrap();
    lay(&root, Shape::File);
    repo.commit("me", "other").unwrap();
    repo.switch("main").unwrap();
    std::fs::create_dir(root.join("x")).unwrap();
    assert!(repo.switch("other").is_err());
    assert!(root.join("x").is_dir());
    finish(&root, repo);
}

/// An abort that cannot replace a directory because of an untracked file
/// leaves the user's empty subdirectories alone too.
#[test]
fn merge_abort_refusal_does_not_prune_empty_user_directories() {
    let (root, repo) = fixture("merge-prune", Shape::File, Shape::Dir);
    assert!(repo.merge("other", "me").is_err());
    std::fs::write(root.join("x/mine.txt"), b"mine\n").unwrap();
    std::fs::create_dir(root.join("x/empty")).unwrap();
    assert!(repo.merge_abort().is_err());
    assert!(root.join("x/empty").is_dir());
    assert!(root.join("x/mine.txt").exists());
    finish(&root, repo);
}

/// Switching onto a private branch across a directory-to-file change.
#[test]
fn private_switch_crosses_a_directory_to_file_transition() {
    let root = tmp_root("private");
    let repo = Repo::init(&root).unwrap();
    let (sk, _pk) = scl_crypto::generate_keypair();
    lay(&root, Shape::Dir);
    repo.commit("me", "base").unwrap();
    repo.branch_private("fix", &sk, &[], &[]).unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    lay(&root, Shape::File);
    repo.commit_private("me", "flip", Some(&sk)).unwrap();
    repo.switch_with_identity("main", Some(&sk)).unwrap();
    assert_shape(&root, Shape::Dir);
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    assert_shape(&root, Shape::File);
    finish(&root, repo);
}

/// Adopting a branch into an unborn one has no old tree and no untracked
/// guard: an empty directory of the user's where a file must go is kept, and
/// the merge fails rather than deleting it.
#[test]
fn unborn_adoption_keeps_an_empty_directory_where_a_file_must_go() {
    let src = tmp_root("unborn-src");
    let origin = Repo::init(&src).unwrap();
    std::fs::write(src.join("x"), b"file\n").unwrap();
    origin.commit("me", "base").unwrap();
    let dst = tmp_root("unborn-dst");
    let repo = Repo::init(&dst).unwrap();
    repo.remote_add("origin", src.to_str().unwrap()).unwrap();
    repo.fetch("origin").unwrap();
    std::fs::create_dir(dst.join("x")).unwrap();
    assert!(repo.merge("origin/main", "me").is_err());
    assert!(dst.join("x").is_dir(), "the user's directory must survive");
    finish(&dst, repo);
    finish(&src, origin);
}
