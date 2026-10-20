//! A conflicted merge of a public branch into a private branch under a sparse
//! spec must decide out-of-view paths by the merge, not by the prior private
//! tip (#240): a path the public side deleted stays deleted, its clean adds and
//! modifies land, ours-only private edits survive, and the stop writes nothing
//! outside the view.

use std::collections::BTreeMap;
use std::path::Path;

use scl_crypto::SecretKey;

use crate::error::Error;
use crate::repo::Repo;

fn put(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn docs(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir(root.join("docs")) {
        for e in rd {
            let e = e.unwrap();
            out.insert(
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(e.path()).unwrap(),
            );
        }
    }
    out
}

/// `main` holds src/lib.rs plus docs/{old,mod,ours,lines}.txt; private `fix` edits
/// src/lib.rs, docs/ours.txt and the first line of docs/lines.txt; `main` then edits src/lib.rs, deletes
/// docs/old.txt, edits docs/mod.txt and adds docs/new.txt and edits the last line of docs/lines.txt. With `view` set,
/// the sparse spec `src/` is in force on `main` before switching to `fix`,
/// and `conflict_in_docs` also makes `fix` edit docs/mod.txt (a conflict).
struct Fixture {
    root: std::path::PathBuf,
    repo: Repo,
    sk: SecretKey,
}

fn fixture(tag: &str, view: bool, conflict_in_docs: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!("scl-priv-sparse-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repo::init(&root).unwrap();
    put(&root, "src/lib.rs", "base\n");
    put(&root, "docs/old.txt", "old\n");
    put(&root, "docs/mod.txt", "mod-base\n");
    put(&root, "docs/ours.txt", "ours-base\n");
    put(&root, "docs/lines.txt", "a\nb\nc\nd\ne\n");
    repo.commit("t", "base").unwrap();
    let (sk, _pk) = scl_crypto::generate_keypair();
    repo.branch_private("fix", &sk, &[], &[]).unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    put(&root, "src/lib.rs", "private\n");
    put(&root, "docs/ours.txt", "ours-edit\n");
    put(&root, "docs/lines.txt", "A\nb\nc\nd\ne\n");
    if conflict_in_docs {
        put(&root, "docs/mod.txt", "mod-private\n");
    }
    repo.commit_private("alice", "private work", Some(&sk))
        .unwrap();
    repo.switch_with_identity("main", Some(&sk)).unwrap();
    put(&root, "src/lib.rs", "public\n");
    std::fs::remove_file(root.join("docs/old.txt")).unwrap();
    put(&root, "docs/mod.txt", "mod-public\n");
    put(&root, "docs/new.txt", "new-public\n");
    put(&root, "docs/lines.txt", "a\nb\nc\nd\nE\n");
    repo.commit("t", "main moves").unwrap();
    if view {
        repo.set_sparse(&["src/".to_string()], Some(&sk)).unwrap();
    }
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    Fixture { root, repo, sk }
}

/// Stop the merge, resolve `src/lib.rs`, complete, widen to the whole tree
/// and return the resulting `docs/` listing.
fn run(f: &Fixture, view: bool) -> BTreeMap<String, String> {
    let sk = Some(&f.sk);
    assert!(matches!(
        f.repo.merge_into_private("main", "alice", sk),
        Err(Error::MergeConflicts(1))
    ));
    if view {
        assert!(docs(&f.root).is_empty(), "the stop wrote outside the view");
    }
    put(&f.root, "src/lib.rs", "resolved\n");
    f.repo.commit_private("alice", "resolve", sk).unwrap();
    assert_eq!(
        std::fs::read_to_string(f.root.join("src/lib.rs")).unwrap(),
        "resolved\n"
    );
    if view {
        assert!(docs(&f.root).is_empty(), "completion widened the view");
        f.repo.switch_with_identity("main", sk).unwrap();
        f.repo
            .set_sparse(&["src/".to_string(), "docs/".to_string()], sk)
            .unwrap();
        f.repo.switch_with_identity("fix", sk).unwrap();
    }
    docs(&f.root)
}

#[test]
fn sparse_merge_into_private_equals_the_run_without_sparse() {
    let full = fixture("full", false, false);
    let want = run(&full, false);
    let sparse = fixture("sparse", true, false);
    let got = run(&sparse, true);
    assert!(!got.contains_key("old.txt"), "public deletion resurrected");
    assert_eq!(got["mod.txt"], "mod-public\n");
    assert_eq!(got["new.txt"], "new-public\n");
    assert_eq!(got["ours.txt"], "ours-edit\n", "ours-only edit lost");
    // Both sides edited it, out of view: the merged blob is new and sealed.
    assert_eq!(got["lines.txt"], "A\nb\nc\nd\nE\n");
    assert_eq!(got, want);
    std::fs::remove_dir_all(&full.root).unwrap();
    assert!(!full.root.exists(), "test dir left behind");
    std::fs::remove_dir_all(&sparse.root).unwrap();
    assert!(!sparse.root.exists(), "test dir left behind");
}

#[test]
fn an_out_of_view_conflict_is_refused_before_any_write() {
    let f = fixture("refuse", true, true);
    let (_, before, _) = f.repo.head_private().unwrap().unwrap();
    let err = f
        .repo
        .merge_into_private("main", "alice", Some(&f.sk))
        .unwrap_err();
    assert!(
        err.to_string().contains("sc sparse set"),
        "hint widens the spec: {err}"
    );
    assert!(!crate::merge_state::in_progress(f.repo.layout()));
    assert!(docs(&f.root).is_empty());
    assert_eq!(f.repo.head_private().unwrap().unwrap().1, before);
    std::fs::remove_dir_all(&f.root).unwrap();
    assert!(!f.root.exists(), "test dir left behind");
}

#[test]
fn replay_onto_a_private_branch_stays_refused_under_sparse() {
    let f = fixture("replay", true, false);
    assert!(matches!(
        f.repo.cherry_pick("main", "alice", Some(&f.sk), None),
        Err(Error::PrivateUnsupported(_))
    ));
    assert!(matches!(
        f.repo.rebase("main", "alice", Some(&f.sk)),
        Err(Error::PrivateUnsupported(_))
    ));
    assert!(docs(&f.root).is_empty());
    std::fs::remove_dir_all(&f.root).unwrap();
    assert!(!f.root.exists(), "test dir left behind");
}
