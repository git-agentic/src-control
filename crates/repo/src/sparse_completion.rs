//! A stopped merge, cherry-pick or rebase on a FULL clone with a sparse spec
//! must complete to the same tree as without sparse (#238): an out-of-view
//! path the other side deleted stays deleted, while its clean adds and
//! modifies land and ours-side-only out-of-view changes are kept.

use std::collections::BTreeMap;

use crate::conflicts::ResolveSide;
use crate::repo::Repo;
use crate::worktree;

#[derive(Clone, Copy, Debug)]
enum Op {
    Merge,
    Pick,
    Rebase,
}

/// Run the scenario and return the completed tip's `path -> content`.
///
/// base: `src/a.txt`, `docs/{old,mod,ours,ours_del}.txt`. `main` edits
/// `src/a.txt`, edits `docs/ours.txt` and deletes `docs/ours_del.txt`;
/// `feature` edits `src/a.txt` (a conflict), deletes `docs/old.txt`, edits
/// `docs/mod.txt` and adds `docs/new.txt`. `docs/` is outside the `src/` view.
fn run(tag: &str, op: Op, sparse: bool) -> BTreeMap<String, Vec<u8>> {
    let root = std::env::temp_dir().join(format!(
        "scl-sparse-completion-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("docs")).unwrap();
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("src/a.txt"), b"a\nb\nc\n").unwrap();
    for f in ["old", "mod", "ours", "ours_del"] {
        std::fs::write(root.join(format!("docs/{f}.txt")), b"v1\n").unwrap();
    }
    repo.commit("me", "base").unwrap();
    repo.branch("feature").unwrap();

    std::fs::write(root.join("src/a.txt"), b"a\nMAIN\nc\n").unwrap();
    std::fs::write(root.join("docs/ours.txt"), b"ours v2\n").unwrap();
    std::fs::remove_file(root.join("docs/ours_del.txt")).unwrap();
    repo.commit("me", "main").unwrap();

    repo.switch("feature").unwrap();
    std::fs::write(root.join("src/a.txt"), b"a\nFEAT\nc\n").unwrap();
    std::fs::remove_file(root.join("docs/old.txt")).unwrap();
    std::fs::write(root.join("docs/mod.txt"), b"theirs v2\n").unwrap();
    std::fs::write(root.join("docs/new.txt"), b"new\n").unwrap();
    repo.commit("me", "feature").unwrap();
    if !matches!(op, Op::Rebase) {
        repo.switch("main").unwrap();
    }

    if sparse {
        repo.set_sparse(&["src/".into()], None).unwrap();
        assert!(
            !root.join("docs/mod.txt").exists(),
            "setup: docs/ is out of view"
        );
    }

    match op {
        Op::Merge => {
            repo.merge("feature", "me").unwrap_err();
        }
        Op::Pick => {
            repo.cherry_pick("feature", "me", None, None).unwrap_err();
        }
        Op::Rebase => {
            let out = repo.rebase("main", "me", None).unwrap();
            assert!(matches!(out, crate::replay::RebaseResult::Stopped { .. }));
        }
    }
    repo.resolve_path("src/a.txt", ResolveSide::Theirs, None)
        .unwrap();
    match op {
        Op::Rebase => {
            repo.rebase_continue("me", None).unwrap();
        }
        _ => {
            repo.commit("me", "complete").unwrap();
        }
    }

    let tip = repo.head_tip().unwrap().unwrap();
    let store_arc = repo.vfs().store();
    let mut s = store_arc.lock().unwrap();
    let tree = s.get_snapshot(&tip).unwrap().root;
    let mut out = BTreeMap::new();
    for (p, (id, _, _)) in worktree::tree_file_entries_with_perms(&mut s, tree).unwrap() {
        match s.get(&id).unwrap() {
            scl_core::Object::Blob(b) => out.insert(p, b.to_vec()),
            _ => unreachable!(),
        };
    }
    drop(s);
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists(), "temp repo must be removed");
    out
}

fn check(op: Op) {
    let tag = format!("{op:?}").to_lowercase();
    let full = run(&format!("{tag}-full"), op, false);
    let sparse = run(&format!("{tag}-sparse"), op, true);
    assert!(!full.contains_key("docs/old.txt"), "reference: deleted");
    assert!(
        !sparse.contains_key("docs/old.txt"),
        "{op:?}: the other side's clean out-of-view deletion must not resurrect"
    );
    assert_eq!(
        sparse["docs/mod.txt"], b"theirs v2\n",
        "{op:?}: clean modify lands"
    );
    assert_eq!(sparse["docs/new.txt"], b"new\n", "{op:?}: clean add lands");
    assert_eq!(
        sparse["docs/ours.txt"], b"ours v2\n",
        "{op:?}: ours' edit kept"
    );
    assert!(
        !sparse.contains_key("docs/ours_del.txt"),
        "{op:?}: ours' delete kept"
    );
    assert_eq!(
        sparse, full,
        "{op:?}: sparse completion equals the full one"
    );
}

#[test]
fn a_sparse_merge_keeps_the_other_sides_out_of_view_deletion() {
    check(Op::Merge);
}

#[test]
fn a_sparse_cherry_pick_keeps_the_picked_commits_out_of_view_deletion() {
    check(Op::Pick);
}

#[test]
fn a_sparse_rebase_continue_keeps_the_replayed_commits_out_of_view_deletion() {
    check(Op::Rebase);
}
