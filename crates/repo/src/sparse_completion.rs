//! A stopped merge, cherry-pick or rebase on a FULL clone must complete from
//! its decided root (#238). With a sparse spec an out-of-view path the other
//! side deleted stays deleted while its clean adds and modifies land and
//! ours-side-only out-of-view changes are kept; a protected path the other
//! side deleted stays deleted too.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{FileMode, Object};

use crate::conflicts::ResolveSide;
use crate::repo::Repo;
use crate::worktree;

#[derive(Clone, Copy, Debug)]
enum Op {
    Merge,
    Pick,
    Rebase,
}

/// A working-tree edit applied before a commit.
enum Edit<'a> {
    Write(&'a str, &'a [u8]),
    Exec(&'a str, &'a [u8]),
    Remove(&'a str),
}

fn apply(root: &Path, edits: &[Edit]) {
    for e in edits {
        match e {
            Edit::Write(p, b) | Edit::Exec(p, b) => {
                let full = root.join(p);
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                std::fs::write(&full, b).unwrap();
                #[cfg(unix)]
                if matches!(e, Edit::Exec(..)) {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
            }
            Edit::Remove(p) => std::fs::remove_file(root.join(p)).unwrap(),
        }
    }
}

/// Stop `op` of `feature` against `main`, resolve `src/a.txt` to the other
/// side, complete, and return the tip's `path -> (content, mode)`. Cleans up.
fn finish(
    root: &Path,
    repo: Repo,
    op: Op,
    identity: Option<&scl_crypto::SecretKey>,
    conflict: &str,
) -> BTreeMap<String, (Vec<u8>, FileMode)> {
    match op {
        Op::Merge => {
            repo.merge_with_identity("feature", "me", identity)
                .unwrap_err();
        }
        Op::Pick => {
            repo.cherry_pick("feature", "me", identity, None)
                .unwrap_err();
        }
        Op::Rebase => {
            let out = repo.rebase("main", "me", identity).unwrap();
            assert!(matches!(out, crate::replay::RebaseResult::Stopped { .. }));
        }
    }
    repo.resolve_path(conflict, ResolveSide::Theirs, identity)
        .unwrap();
    match op {
        Op::Rebase => {
            repo.rebase_continue("me", identity).unwrap();
        }
        _ => {
            repo.commit("me", "complete").unwrap();
        }
    }
    let tip = repo.head_tip().unwrap().unwrap();
    let mut out = BTreeMap::new();
    {
        let store_arc = repo.vfs().store();
        let mut s = store_arc.lock().unwrap();
        let tree = s.get_snapshot(&tip).unwrap().root;
        for (p, (id, mode, _)) in worktree::tree_file_entries_with_perms(&mut s, tree).unwrap() {
            match s.get(&id).unwrap() {
                Object::Blob(b) => out.insert(p, (b.to_vec(), mode)),
                _ => unreachable!(),
            };
        }
    }
    drop(repo);
    std::fs::remove_dir_all(root).unwrap();
    assert!(!root.exists(), "temp repo must be removed");
    out
}

/// base -> `main` edits and `feature` edits (both touch `src/a.txt`, so the
/// operation stops), optionally under sparse `src/`. Everything under
/// `docs/` is outside the view.
fn run(
    tag: &str,
    op: Op,
    sparse: bool,
    base: &[Edit],
    main: &[Edit],
    feature: &[Edit],
) -> BTreeMap<String, (Vec<u8>, FileMode)> {
    let root = std::env::temp_dir().join(format!(
        "scl-sparse-completion-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repo::init(&root).unwrap();
    apply(&root, base);
    repo.commit("me", "base").unwrap();
    repo.branch("feature").unwrap();
    apply(&root, main);
    repo.commit("me", "main").unwrap();
    repo.switch("feature").unwrap();
    apply(&root, feature);
    repo.commit("me", "feature").unwrap();
    // Narrow before leaving `feature`, so its out-of-view files are not left
    // on disk to block the switch (a directory where `main` has a file).
    if sparse {
        repo.set_sparse(&["src/".into()], None).unwrap();
        // Drop what the narrowing left behind: empty directories.
        for d in ["docs/x", "docs"] {
            let _ = std::fs::remove_dir(root.join(d));
        }
        assert!(!root.join("docs").exists(), "setup: docs/ is out of view");
    }
    if !matches!(op, Op::Rebase) {
        repo.switch("main").unwrap();
    }
    finish(&root, repo, op, None, "src/a.txt")
}

fn ops() -> [Op; 3] {
    [Op::Merge, Op::Pick, Op::Rebase]
}

fn tag(op: Op, what: &str) -> String {
    format!("{}-{what}", format!("{op:?}").to_lowercase())
}

const BASE_A: Edit = Edit::Write("src/a.txt", b"a\nb\nc\n");
const MAIN_A: Edit = Edit::Write("src/a.txt", b"a\nMAIN\nc\n");
const FEAT_A: Edit = Edit::Write("src/a.txt", b"a\nFEAT\nc\n");

fn text(m: &BTreeMap<String, (Vec<u8>, FileMode)>) -> BTreeMap<&str, &[u8]> {
    m.iter().map(|(p, (b, _))| (p.as_str(), &b[..])).collect()
}

#[test]
fn a_sparse_completion_keeps_the_other_sides_out_of_view_deletion_and_lands_the_rest() {
    for op in ops() {
        let args = |sparse| {
            run(
                &tag(op, if sparse { "del-sparse" } else { "del-full" }),
                op,
                sparse,
                &[
                    BASE_A,
                    Edit::Write("docs/old.txt", b"v1\n"),
                    Edit::Write("docs/mod.txt", b"v1\n"),
                    Edit::Write("docs/ours.txt", b"v1\n"),
                    Edit::Write("docs/ours_del.txt", b"v1\n"),
                ],
                &[
                    MAIN_A,
                    Edit::Write("docs/ours.txt", b"ours v2\n"),
                    Edit::Remove("docs/ours_del.txt"),
                ],
                &[
                    FEAT_A,
                    Edit::Remove("docs/old.txt"),
                    Edit::Write("docs/mod.txt", b"theirs v2\n"),
                    Edit::Write("docs/new.txt", b"new\n"),
                ],
            )
        };
        let (full, sparse) = (args(false), args(true));
        assert!(!full.contains_key("docs/old.txt"), "reference: deleted");
        assert!(
            !sparse.contains_key("docs/old.txt"),
            "{op:?}: the other side's clean out-of-view deletion must not resurrect"
        );
        let s = text(&sparse);
        assert_eq!(
            s["docs/mod.txt"], b"theirs v2\n",
            "{op:?}: clean modify lands"
        );
        assert_eq!(s["docs/new.txt"], b"new\n", "{op:?}: clean add lands");
        assert_eq!(s["docs/ours.txt"], b"ours v2\n", "{op:?}: ours' edit kept");
        assert!(
            !s.contains_key("docs/ours_del.txt"),
            "{op:?}: ours' delete kept"
        );
        assert_eq!(
            s,
            text(&full),
            "{op:?}: sparse completion equals the full one"
        );
    }
}

/// The other side turns the out-of-view file `docs/x` into a directory. The
/// parents used to carry `docs/x` back beside `docs/x/y`, a corrupt tree.
#[test]
fn a_sparse_completion_accepts_a_file_replaced_by_a_directory_out_of_view() {
    for op in ops() {
        let sparse = run(
            &tag(op, "dir"),
            op,
            true,
            &[BASE_A, Edit::Write("docs/x", b"file\n")],
            &[MAIN_A],
            &[
                FEAT_A,
                Edit::Remove("docs/x"),
                Edit::Write("docs/x/y", b"y\n"),
            ],
        );
        let s = text(&sparse);
        assert!(!s.contains_key("docs/x"), "{op:?}: the file is gone");
        assert_eq!(s["docs/x/y"], b"y\n", "{op:?}: the directory's file landed");
    }
}

/// The other side adds the exec bit to an out-of-view file. Compared apart
/// from the equality check: the non-sparse reference drops exec bits (#237).
#[cfg(unix)]
#[test]
fn a_sparse_completion_lands_an_out_of_view_mode_change() {
    for op in ops() {
        let sparse = run(
            &tag(op, "mode"),
            op,
            true,
            &[BASE_A, Edit::Write("docs/run.sh", b"#!/bin/sh\n")],
            &[MAIN_A],
            &[FEAT_A, Edit::Exec("docs/run.sh", b"#!/bin/sh\n")],
        );
        assert_eq!(sparse["docs/run.sh"].1, FileMode::EXEC, "{op:?}");
    }
}

/// The other side deletes a protected file while an unrelated conflict stops
/// the operation: the decided root dropped it, so completion must too. The
/// deletion is committed as a raw snapshot because a plain commit carries an
/// absent protected path forward.
#[test]
fn a_completion_keeps_the_other_sides_protected_deletion() {
    for op in ops() {
        let root = std::env::temp_dir().join(format!(
            "scl-sparse-completion-{}-{}",
            tag(op, "prot"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = Repo::init(&root).unwrap();
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[pk], None).unwrap();
        apply(&root, &[BASE_A, Edit::Write("secret/a.txt", b"s\n")]);
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        apply(&root, &[MAIN_A]);
        repo.commit("me", "main").unwrap();

        repo.switch_with_identity("feature", Some(&sk)).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let protection = repo.snapshot(&tip).unwrap().protection;
        let tree = repo
            .vfs()
            .write_tree_with_perms(&[(
                "src/a.txt".to_string(),
                b"a\nFEAT\nc\n".to_vec(),
                FileMode::FILE,
                0,
            )])
            .unwrap();
        repo.commit_snapshot(
            tree,
            vec![tip],
            Default::default(),
            protection,
            "me",
            "feature deletes secret/a.txt",
        )
        .unwrap();
        // Match the disk to that tree before leaving the branch.
        apply(&root, &[FEAT_A, Edit::Remove("secret/a.txt")]);
        if !matches!(op, Op::Rebase) {
            repo.switch_with_identity("main", Some(&sk)).unwrap();
        }
        let done = finish(&root, repo, op, Some(&sk), "src/a.txt");
        let s = text(&done);
        assert!(
            !s.contains_key("secret/a.txt"),
            "{op:?}: the protected deletion must not be undone"
        );
        assert_eq!(s["src/a.txt"], b"a\nFEAT\nc\n");
    }
}
