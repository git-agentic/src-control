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
    #[cfg_attr(not(unix), allow(dead_code))] // only unix tests build an executable file
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

/// Set up `op` of `feature` against `main` under sparse `src/` (both touch
/// `src/a.txt`, so it stops) where the other side adds `docs/new.txt`, outside
/// the view: `feature` for a merge or pick, `main` for a rebase (which replays
/// `feature` onto it). The caller gets the repo before the operation starts.
fn collision_setup(tag: &str, op: Op) -> (std::path::PathBuf, Repo) {
    let root =
        std::env::temp_dir().join(format!("scl-sparse-collision-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repo::init(&root).unwrap();
    apply(&root, &[BASE_A, Edit::Write("docs/keep.txt", b"keep\n")]);
    repo.commit("me", "base").unwrap();
    repo.branch("feature").unwrap();
    let added = || Edit::Write("docs/new.txt", b"theirs\n");
    let rebase = matches!(op, Op::Rebase);
    apply(&root, &[MAIN_A]);
    if rebase {
        apply(&root, &[added()]);
    }
    repo.commit("me", "main").unwrap();
    repo.switch("feature").unwrap();
    apply(&root, &[FEAT_A]);
    if !rebase {
        apply(&root, &[added()]);
    }
    repo.commit("me", "feature").unwrap();
    repo.set_sparse(&["src/".into()], None).unwrap();
    if !matches!(op, Op::Rebase) {
        repo.switch("main").unwrap();
    }
    (root, repo)
}

/// Start `op`: it stops on `src/a.txt` (an `Err`), or is refused.
fn start(repo: &Repo, op: Op) -> crate::error::Result<()> {
    match op {
        Op::Merge => repo.merge_with_identity("feature", "me", None).map(drop),
        Op::Pick => repo.cherry_pick("feature", "me", None, None).map(drop),
        Op::Rebase => match repo.rebase("main", "me", None)? {
            crate::replay::RebaseResult::Stopped { .. } => {
                Err(crate::error::Error::MergeConflicts(1))
            }
            _ => Ok(()),
        },
    }
}

fn in_progress(repo: &Repo) -> bool {
    crate::merge_state::in_progress(repo.layout())
        || crate::pick_state::in_progress(repo.layout())
        || crate::rebase_state::in_progress(repo.layout())
}

#[test]
fn a_stop_refuses_an_untracked_file_where_the_other_side_adds_one_out_of_view() {
    for op in ops() {
        let (root, repo) = collision_setup(&tag(op, "collide"), op);
        let mine = root.join("docs/new.txt");
        std::fs::create_dir_all(mine.parent().unwrap()).unwrap();
        std::fs::write(&mine, b"MINE\n").unwrap();
        let before = std::fs::read(root.join("src/a.txt")).unwrap();

        let err = start(&repo, op).unwrap_err().to_string();
        assert!(err.contains("docs/new.txt"), "{op:?}: {err}");
        assert!(err.contains("move it away"), "{op:?}: {err}");
        assert!(!in_progress(&repo), "{op:?}: refusal left state behind");
        assert_eq!(std::fs::read(&mine).unwrap(), b"MINE\n", "{op:?}");
        assert_eq!(
            std::fs::read(root.join("src/a.txt")).unwrap(),
            before,
            "{op:?}: nothing written"
        );

        // Move it away and retry: the other side's file lands, as without sparse.
        std::fs::remove_file(&mine).unwrap();
        start(&repo, op).unwrap_err();
        assert!(in_progress(&repo), "{op:?}: the retry must stop");
        repo.resolve_path("src/a.txt", ResolveSide::Theirs, None)
            .unwrap();
        match op {
            Op::Rebase => drop(repo.rebase_continue("me", None).unwrap()),
            _ => drop(repo.commit("me", "complete").unwrap()),
        }
        let tip = repo.head_tip().unwrap().unwrap();
        let store_arc = repo.vfs().store();
        let mut s = store_arc.lock().unwrap();
        let tree = s.get_snapshot(&tip).unwrap().root;
        let files = worktree::tree_file_entries_with_perms(&mut s, tree).unwrap();
        let id = files["docs/new.txt"].0;
        assert!(
            matches!(s.get(&id).unwrap(), Object::Blob(b) if &b[..] == b"theirs\n"),
            "{op:?}: the addition lands"
        );
        drop(s);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists(), "temp repo must be removed");
    }
}

/// Any directory where the other side adds an out-of-view file is the user's,
/// empty or not: `stop_write_blocker` accepts a directory of tracked files
/// (#247), but nothing out of view is laid out, so none is tracked here.
#[test]
fn a_stop_refuses_any_directory_where_the_other_side_adds_a_file_out_of_view() {
    for op in ops() {
        for with_file in [false, true] {
            let (root, repo) = collision_setup(&tag(op, &format!("dir-{with_file}")), op);
            let dir = root.join("docs/new.txt");
            std::fs::create_dir_all(&dir).unwrap();
            if with_file {
                std::fs::write(dir.join("mine"), b"MINE\n").unwrap();
            }
            let err = start(&repo, op).unwrap_err().to_string();
            assert!(err.contains("docs/new.txt"), "{op:?}: {err}");
            assert!(!in_progress(&repo), "{op:?}: refusal left state behind");
            assert!(dir.is_dir(), "{op:?}: the directory is untouched");
            drop(repo);
            std::fs::remove_dir_all(&root).unwrap();
            assert!(!root.exists(), "temp repo must be removed");
        }
    }
}

/// A file standing where the other side needs a parent directory out of view.
#[test]
fn a_stop_refuses_an_untracked_file_where_an_out_of_view_directory_must_be() {
    for op in ops() {
        let (root, repo) = collision_setup(&tag(op, "parent"), op);
        // The user's `docs` is a file where `docs/new.txt` needs a directory.
        std::fs::remove_dir_all(root.join("docs")).ok();
        std::fs::write(root.join("docs"), b"MINE\n").unwrap();
        let err = start(&repo, op).unwrap_err().to_string();
        assert!(err.contains("docs/new.txt"), "{op:?}: {err}");
        assert!(!in_progress(&repo), "{op:?}");
        assert_eq!(std::fs::read(root.join("docs")).unwrap(), b"MINE\n");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists(), "temp repo must be removed");
    }
}

/// An unrelated untracked file out of view is not in the way, and an abort
/// leaves it alone.
#[test]
fn a_stop_and_abort_leave_an_unrelated_out_of_view_file() {
    for op in ops() {
        let (root, repo) = collision_setup(&tag(op, "abort"), op);
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/mine.txt"), b"MINE\n").unwrap();
        start(&repo, op).unwrap_err();
        assert!(in_progress(&repo), "{op:?}: it stops");
        match op {
            Op::Merge => drop(repo.merge_abort().unwrap()),
            Op::Pick => drop(repo.cherry_pick_abort().unwrap()),
            Op::Rebase => drop(repo.rebase_abort().unwrap()),
        }
        assert_eq!(
            std::fs::read(root.join("docs/mine.txt")).unwrap(),
            b"MINE\n",
            "{op:?}"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists(), "temp repo must be removed");
    }
}

/// The same collision on operations that never stop: the result is exact, but
/// the next commit would read the user's file in its place.
#[test]
fn a_clean_operation_refuses_an_untracked_file_where_it_adds_one_out_of_view() {
    // (name, `main` also moves, then the operation)
    type Run = fn(&Repo) -> crate::error::Result<()>;
    let ops: [(&str, bool, Run); 3] = [
        ("merge", true, |r| {
            r.merge_with_identity("feature", "me", None).map(drop)
        }),
        ("ff", false, |r| {
            r.merge_with_identity("feature", "me", None).map(drop)
        }),
        ("switch", false, |r| r.switch("feature").map(drop)),
    ];
    for (name, main_moves, run) in ops {
        let root =
            std::env::temp_dir().join(format!("scl-sparse-clean-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = Repo::init(&root).unwrap();
        apply(&root, &[BASE_A, Edit::Write("docs/keep.txt", b"keep\n")]);
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        if main_moves {
            apply(&root, &[MAIN_A]);
            repo.commit("me", "main").unwrap();
        }
        repo.switch("feature").unwrap();
        apply(&root, &[Edit::Write("docs/new.txt", b"theirs\n")]);
        repo.commit("me", "feature").unwrap();
        repo.set_sparse(&["src/".into()], None).unwrap();
        repo.switch("main").unwrap();
        apply(&root, &[Edit::Write("docs/new.txt", b"MINE\n")]);
        let before = repo.head_tip().unwrap();

        let err = run(&repo).unwrap_err().to_string();
        assert!(
            err.contains("docs/new.txt") && err.contains("move it away"),
            "{name}: {err}"
        );
        assert_eq!(repo.head_tip().unwrap(), before, "{name}: no ref moved");
        assert_eq!(std::fs::read(root.join("docs/new.txt")).unwrap(), b"MINE\n");

        std::fs::remove_file(root.join("docs/new.txt")).unwrap();
        run(&repo).unwrap();
        assert!(
            repo.status().unwrap().added.is_empty(),
            "{name}: clean after"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists(), "temp repo must be removed");
    }
}
