//! Tests for the blob-size clone filter (ADR-0055, `--filter blob:limit=<size>`).
//!
//! The fixture is an origin whose history has large blobs that only an old
//! commit references, so a size-limited clone leaves them out while every ref
//! tip stays complete.

use std::path::PathBuf;
use std::time::Duration;

use scl_core::{Object, ObjectId};

use crate::error::Error;
use crate::promisor::{PackFilter, Scope};
use crate::refs;
use crate::replay::{PickResult, RebaseResult};
use crate::repo::Repo;
use crate::sparse::Sparse;

const LIMIT: u64 = 1024;

fn blob_id(bytes: &[u8]) -> ObjectId {
    Object::blob(bytes.to_vec()).id()
}

fn has(repo: &Repo, id: &ObjectId) -> bool {
    repo.vfs().store().lock().unwrap().contains(id)
}

/// 300 numbered lines (about 2.7 KB, over `LIMIT`) with `edits` replacing
/// lines by index, so two edits to different lines merge cleanly.
fn text(edits: &[(usize, &str)]) -> Vec<u8> {
    let mut out = String::new();
    for n in 0..300 {
        match edits.iter().find(|(i, _)| *i == n) {
            Some((_, replacement)) => out.push_str(&format!("{replacement}\n")),
            None => out.push_str(&format!("line {n}\n")),
        }
    }
    out.into_bytes()
}

/// Remove fixture directories and assert they are gone.
fn remove_all(dirs: &[&std::path::Path]) {
    for d in dirs {
        if d.exists() {
            std::fs::remove_dir_all(d).unwrap();
        }
        assert!(!d.exists(), "fixture {} must be removed", d.display());
    }
}

fn huge(tag: u8) -> Vec<u8> {
    vec![tag; 8192]
}

struct Sz {
    origin_root: PathBuf,
    clone_root: PathBuf,
    origin: Repo,
    c1: ObjectId,
    c2: ObjectId,
}

impl Sz {
    /// An origin with `big.txt` (a text over the limit), `small.txt` and
    /// `src/huge.bin` at `c1`, each rewritten at `c2` (`main`). Everything the
    /// first commit holds that the second replaced is history only.
    fn new(tag: &str) -> Sz {
        let pid = std::process::id();
        let base = std::env::temp_dir();
        let origin_root = base.join(format!("scl-p27sz-{tag}-origin-{pid}"));
        let clone_root = base.join(format!("scl-p27sz-{tag}-clone-{pid}"));
        for r in [&origin_root, &clone_root] {
            let _ = std::fs::remove_dir_all(r);
        }
        std::fs::create_dir_all(origin_root.join("src")).unwrap();
        let origin = Repo::init(&origin_root).unwrap();
        std::fs::write(origin_root.join("big.txt"), text(&[])).unwrap();
        std::fs::write(origin_root.join("small.txt"), b"s1\n").unwrap();
        std::fs::write(origin_root.join("src/huge.bin"), huge(1)).unwrap();
        let c1 = origin.commit("t", "c1").unwrap();
        std::fs::write(origin_root.join("big.txt"), text(&[(0, "ours")])).unwrap();
        std::fs::write(origin_root.join("small.txt"), b"s2\n").unwrap();
        std::fs::write(origin_root.join("src/huge.bin"), huge(2)).unwrap();
        let c2 = origin.commit("t", "c2").unwrap();
        Sz {
            origin_root,
            clone_root,
            origin,
            c1,
            c2,
        }
    }

    fn clone(&self, prefixes: &[&str], limit: u64, lazy: bool) -> Repo {
        let prefixes: Vec<String> = prefixes.iter().map(|s| s.to_string()).collect();
        let clone = Repo::clone_url_limited(
            self.origin_root.to_str().unwrap(),
            &self.clone_root,
            &prefixes,
            Some(limit),
            false,
        )
        .unwrap();
        crate::promisor::set_lazy(clone.layout(), lazy).unwrap();
        clone
    }

    fn cleanup(self) {
        drop(self.origin);
        for r in [&self.origin_root, &self.clone_root] {
            if r.exists() {
                std::fs::remove_dir_all(r).unwrap();
            }
            assert!(!r.exists(), "fixture {} must be removed", r.display());
        }
    }
}

/// The core promise: the history-only large blobs are left out, every tip blob
/// (large or small) is present, the checkout is complete, and the clone knows
/// its scope and limit across a reload.
#[test]
fn size_only_clone_leaves_out_history_blobs_and_keeps_every_tip_complete() {
    let sz = Sz::new("core");
    let clone = sz.clone(&[], LIMIT, false);

    assert!(!has(&clone, &blob_id(&text(&[]))), "old big.txt is a gap");
    assert!(!has(&clone, &blob_id(&huge(1))), "old huge.bin is a gap");
    assert!(has(&clone, &blob_id(&text(&[(0, "ours")]))), "tip big.txt");
    assert!(has(&clone, &blob_id(&huge(2))), "tip huge.bin");
    assert!(has(&clone, &blob_id(b"s1\n")), "small history blob is kept");
    assert_eq!(
        std::fs::read(sz.clone_root.join("big.txt")).unwrap(),
        text(&[(0, "ours")]),
        "the checkout materializes the large tip file"
    );
    assert_eq!(
        std::fs::read(sz.clone_root.join("src/huge.bin")).unwrap(),
        huge(2)
    );

    let promisor = clone.promisor().unwrap().unwrap();
    assert!(promisor.is_all_paths());
    assert_eq!(promisor.blob_limit(), Some(LIMIT));
    assert!(promisor.prefixes().is_empty());
    assert_eq!(promisor.describe(), format!("blob:limit={LIMIT}"));
    assert_eq!(
        std::fs::read_to_string(clone.layout().promisor_blob_limit_path()).unwrap(),
        "limit 1024\nscope all-paths\n"
    );
    assert!(clone.sparse_spec().unwrap().is_full(), "the view is full");
    // verify counts the two large old blobs as the gap frontier.
    assert_eq!(clone.partial_gap_count(&[sz.c2]).unwrap(), Some(2));
    drop(clone);
    sz.cleanup();
}

/// A blob of exactly `limit` bytes is left out (size >= limit, like git); one
/// byte less is kept. `blob:limit=0` leaves out every blob no tip reaches.
#[test]
fn boundary_is_inclusive_and_zero_keeps_only_tip_blobs() {
    let pid = std::process::id();
    let base = std::env::temp_dir();
    let origin_root = base.join(format!("scl-p27sz-edge-origin-{pid}"));
    let clone_root = base.join(format!("scl-p27sz-edge-clone-{pid}"));
    let zero_root = base.join(format!("scl-p27sz-edge-zero-{pid}"));
    for r in [&origin_root, &clone_root, &zero_root] {
        let _ = std::fs::remove_dir_all(r);
    }
    std::fs::create_dir_all(&origin_root).unwrap();
    let origin = Repo::init(&origin_root).unwrap();
    let eq = vec![b'e'; LIMIT as usize];
    let lt = vec![b'l'; LIMIT as usize - 1];
    std::fs::write(origin_root.join("eq.bin"), &eq).unwrap();
    std::fs::write(origin_root.join("lt.bin"), &lt).unwrap();
    origin.commit("t", "c1").unwrap();
    std::fs::write(origin_root.join("eq.bin"), b"gone").unwrap();
    std::fs::write(origin_root.join("lt.bin"), b"gone too").unwrap();
    origin.commit("t", "c2").unwrap();

    let clone = Repo::clone_url_limited(
        origin_root.to_str().unwrap(),
        &clone_root,
        &[],
        Some(LIMIT),
        false,
    )
    .unwrap();
    assert!(!has(&clone, &blob_id(&eq)), "size == limit is left out");
    assert!(has(&clone, &blob_id(&lt)), "size == limit - 1 is kept");
    drop(clone);

    let zero = Repo::clone_url_limited(
        origin_root.to_str().unwrap(),
        &zero_root,
        &[],
        Some(0),
        false,
    )
    .unwrap();
    assert!(
        !has(&zero, &blob_id(&lt)),
        "limit 0 leaves out every old blob"
    );
    assert!(has(&zero, &blob_id(b"gone")), "but every tip blob is kept");
    assert_eq!(
        std::fs::read(zero_root.join("eq.bin")).unwrap(),
        b"gone",
        "the checkout is complete"
    );
    drop(zero);
    drop(origin);
    remove_all(&[&origin_root, &clone_root, &zero_root]);
}

/// A clone that combines a prefix with a limit: the prefix decides scope, the
/// limit prunes inside it, and the promisor keeps both.
#[test]
fn prefix_plus_limit_scopes_first_then_prunes() {
    let sz = Sz::new("combo");
    let clone = sz.clone(&["src/"], LIMIT, false);
    assert!(
        !has(&clone, &blob_id(&huge(1))),
        "in scope, over limit, old"
    );
    assert!(has(&clone, &blob_id(&huge(2))), "in scope, over limit, tip");
    assert!(
        !has(&clone, &blob_id(&text(&[(0, "ours")]))),
        "outside the prefix, even at the tip"
    );
    let promisor = clone.promisor().unwrap().unwrap();
    assert!(!promisor.is_all_paths());
    assert_eq!(promisor.prefixes(), &["src/".to_string()]);
    assert_eq!(promisor.blob_limit(), Some(LIMIT));
    assert_eq!(
        promisor.describe(),
        format!("src/, blob:limit={LIMIT}"),
        "verify names both"
    );
    assert_eq!(
        std::fs::read_to_string(clone.layout().promisor_blob_limit_path()).unwrap(),
        "limit 1024\nscope prefixes\n"
    );
    assert!(!sz.clone_root.join("big.txt").exists());
    assert_eq!(
        std::fs::read(sz.clone_root.join("src/huge.bin")).unwrap(),
        huge(2)
    );
    drop(clone);
    sz.cleanup();
}

/// `sc backfill <path>` on a size-only clone fetches every version of the path,
/// and the whole-tree scope and the limit survive it and a reload (B1).
#[test]
fn backfill_keeps_the_whole_tree_scope_and_limit() {
    let sz = Sz::new("backfill");
    let clone = sz.clone(&[], LIMIT, false);
    clone.backfill(&["src/huge.bin".to_string()]).unwrap();
    assert!(has(&clone, &blob_id(&huge(1))), "the old version arrived");
    assert!(
        !has(&clone, &blob_id(&text(&[]))),
        "an unrelated path is untouched"
    );
    let promisor = clone.promisor().unwrap().unwrap();
    assert_eq!(promisor.blob_limit(), Some(LIMIT));
    assert!(promisor.is_all_paths(), "still every path");
    assert!(promisor.prefixes().is_empty(), "widen did not add a prefix");
    assert!(matches!(
        crate::promisor::load(clone.layout()).unwrap().unwrap(),
        p if p == promisor
    ));
    // The gap count falls by the repaired blob.
    assert_eq!(clone.partial_gap_count(&[sz.c2]).unwrap(), Some(1));

    clone.backfill_all().unwrap();
    assert!(clone.promisor().unwrap().is_none(), "now a full clone");
    assert!(
        !clone.layout().promisor_blob_limit_path().exists(),
        "the limit marker went with it"
    );
    assert!(has(&clone, &blob_id(&text(&[]))));
    drop(clone);
    sz.cleanup();
}

/// Marker persistence: the explicit scope round-trips, a stray limit file with
/// no `.sc/promisor` is ignored, and a prefix scope with a limit reloads as such.
#[test]
fn scope_and_limit_round_trip_through_the_markers() {
    let root = std::env::temp_dir().join(format!("scl-p27sz-marker-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let layout = crate::layout::Layout::at(&root);
    std::fs::create_dir_all(&layout.dot_sc).unwrap();

    let all = crate::Promisor::with_blob_limit("o", vec![], 5);
    crate::promisor::store(&layout, &all).unwrap();
    assert_eq!(crate::promisor::load(&layout).unwrap(), Some(all));

    let pref = crate::Promisor::with_blob_limit("o", vec!["a/".into(), "b".into()], 7);
    crate::promisor::store(&layout, &pref).unwrap();
    let back = crate::promisor::load(&layout).unwrap().unwrap();
    assert_eq!(back, pref);
    assert!(matches!(back.prefixes(), [a, b] if a == "a/" && b == "b"));

    // Storing a limit-less marker removes the limit file.
    crate::promisor::store(&layout, &crate::Promisor::new("o", vec!["a/".into()])).unwrap();
    assert!(!layout.promisor_blob_limit_path().exists());

    // A limit file without `.sc/promisor` is leftover state: a full clone.
    std::fs::write(
        layout.promisor_blob_limit_path(),
        "limit 9\nscope all-paths\n",
    )
    .unwrap();
    std::fs::remove_file(layout.promisor_path()).unwrap();
    assert_eq!(crate::promisor::load(&layout).unwrap(), None);

    // Malformed limit file is an error, not a silent unlimited clone.
    crate::promisor::store(&layout, &crate::Promisor::new("o", vec![])).unwrap();
    std::fs::write(layout.promisor_blob_limit_path(), "limit nope\n").unwrap();
    assert!(crate::promisor::load(&layout).is_err());
    remove_all(&[&root]);
}

/// Widening an all-paths scope is a no-op, and widening a prefix scope keeps
/// its limit.
#[test]
fn widen_cannot_narrow_an_all_paths_scope() {
    let mut p = crate::Promisor::with_blob_limit("o", vec![], 5);
    p.widen(&["x/".into()]);
    assert!(p.is_all_paths());
    assert!(p.matches("anything/at/all"));
    assert!(p.should_descend("a/b"));
    assert!(matches!(
        Scope::AllPaths,
        ref s if *s == Scope::AllPaths
    ));
    let mut q = crate::Promisor::with_blob_limit("o", vec!["a/".into()], 5);
    q.widen(&["b/".into()]);
    assert_eq!(q.prefixes(), &["a/".to_string(), "b/".to_string()]);
    assert_eq!(q.blob_limit(), Some(5));
}

/// `PackFilter` is the one definition of "filter active": a limit alone counts.
#[test]
fn pack_filter_is_active_for_a_prefix_or_a_limit() {
    assert!(PackFilter::new(&[], None).is_none());
    assert!(PackFilter::new(&["a/".to_string()], None).is_some());
    let f = PackFilter::new(&[], Some(0)).expect("a limit of zero is still a filter");
    assert_eq!(f.blob_limit(), Some(0));
    assert!(f.prefixes().is_empty());
}

/// `--filter` grammar (decision 1): one limit, no `blob:none`, `blob:` reserved.
#[test]
fn filter_grammar_rejects_duplicates_and_unknown_blob_forms() {
    use crate::promisor::parse_clone_filters as parse;
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        parse(&v(&["src/", "blob:limit=1MiB"])).unwrap(),
        (vec!["src/".to_string()], Some(1 << 20))
    );
    assert_eq!(parse(&v(&["blob:limit=0"])).unwrap(), (vec![], Some(0)));
    assert_eq!(
        parse(&v(&["blob:limit=512KiB"])).unwrap().1,
        Some(512 << 10)
    );
    assert_eq!(parse(&v(&["blob:limit=2048"])).unwrap().1, Some(2048));
    let dup = parse(&v(&["blob:limit=1", "blob:limit=2"])).unwrap_err();
    assert!(dup.to_string().contains("more than once"), "{dup}");
    let none = parse(&v(&["blob:none"])).unwrap_err();
    assert!(none.to_string().contains("blob:limit=0"), "{none}");
    let other = parse(&v(&["blob:oops"])).unwrap_err();
    assert!(other.to_string().contains("reserved"), "{other}");
    assert!(parse(&v(&["blob:limit=lots"])).is_err());
    assert!(parse(&v(&["blob:limit="])).is_err());

    // The reserved grammar is matched case-insensitively and untrimmed, so a
    // variant spelling is the size filter or an error, never a path prefix.
    for spelling in ["Blob:limit=1KiB", " blob:limit=1KiB", "BLOB:LIMIT=1KiB"] {
        assert_eq!(
            parse(&v(&[spelling])).unwrap(),
            (vec![], Some(1024)),
            "{spelling:?}"
        );
    }
    for bad in ["Blob:none", " blob:oops", "BLOB:", "Blob:limit"] {
        let e = parse(&v(&[bad])).unwrap_err();
        assert!(e.to_string().contains("blob:"), "{bad:?}: {e}");
    }
    // Names that merely start with `blob` stay ordinary prefixes.
    assert_eq!(
        parse(&v(&["blobs/", "blob"])).unwrap(),
        (vec!["blobs/".to_string(), "blob".to_string()], None)
    );

    // A limit above the largest transferable object filters nothing.
    for huge in ["18446744073709551615", "2GiB", "1073741825"] {
        let e = parse(&v(&[&format!("blob:limit={huge}")])).unwrap_err();
        assert!(
            e.to_string().contains("would filter nothing"),
            "{huge}: {e}"
        );
    }
    assert_eq!(parse(&v(&["blob:limit=1GiB"])).unwrap().1, Some(1 << 30));
}

/// A size limit with no path filter is a caller bug: the walk refuses instead
/// of silently ignoring the limit.
#[test]
fn limited_walk_without_a_filter_is_refused() {
    let sz = Sz::new("nofilter");
    let arc = sz.origin.vfs().store();
    let mut store = arc.lock().unwrap();
    let err = crate::reachable::reachable_objects_limited(
        &mut *store,
        &[sz.c2],
        None,
        Some(1),
        &Default::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    drop(store);
    drop(arc);
    sz.cleanup();
}

/// `promisor::remove` deletes `.sc/promisor` before the limit marker, so an
/// interrupted removal leaves a stray limit file that `load` ignores.
#[test]
fn remove_deletes_the_marker_before_the_limit_file() {
    let root = std::env::temp_dir().join(format!("scl-p27sz-rm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let layout = crate::layout::Layout::at(&root);
    std::fs::create_dir_all(&layout.dot_sc).unwrap();
    crate::promisor::store(&layout, &crate::Promisor::with_blob_limit("o", vec![], 5)).unwrap();
    crate::promisor::remove(&layout).unwrap();
    assert!(!layout.promisor_path().exists());
    assert!(!layout.promisor_blob_limit_path().exists());
    // The state a crash between the two removals leaves: only the stray file.
    std::fs::write(
        layout.promisor_blob_limit_path(),
        "limit 5\nscope all-paths\n",
    )
    .unwrap();
    assert_eq!(crate::promisor::load(&layout).unwrap(), None);
    remove_all(&[&root]);
}

/// A missing directory (a fetch left it out) is not blamed on the blob limit
/// and is named by its path; a missing root tree points at `--all`, not at an
/// empty `sc backfill `.
#[test]
fn directory_and_root_gaps_do_not_blame_the_limit() {
    let sz = Sz::new("dirgap");
    let clone = sz.clone(&[], LIMIT, false);
    let src_tree = {
        let arc = clone.vfs().store();
        let mut s = arc.lock().unwrap();
        let root = s.get_snapshot(&sz.c2).unwrap().root;
        s.get_tree(&root).unwrap().get("src").unwrap().id
    };
    let root = {
        let arc = clone.vfs().store();
        let mut s = arc.lock().unwrap();
        s.delete(&src_tree).unwrap();
        s.get_snapshot(&sz.c2).unwrap().root
    };
    let err = {
        let arc = clone.vfs().store();
        let mut s = arc.lock().unwrap();
        crate::worktree::preflight_view(clone.layout(), &mut s, root, &Sparse::default())
            .unwrap_err()
    };
    match &err {
        Error::GapInView {
            path,
            prefix,
            blob_limit,
        } => {
            assert_eq!(path, "src");
            assert_eq!(prefix, "src", "names the path");
            assert_eq!(*blob_limit, None, "a directory is not a size gap");
        }
        other => panic!("expected GapInView, got {other:?}"),
    }
    assert!(!err.to_string().contains("blob:limit"), "{err}");

    let root_gap = Error::GapInView {
        path: "(root tree)".into(),
        prefix: String::new(),
        blob_limit: None,
    };
    assert!(
        root_gap
            .to_string()
            .ends_with("Run `sc backfill --all` to repair it"),
        "{root_gap}"
    );
    drop(clone);
    sz.cleanup();
}

/// gc, verify and push on a size-limited clone (presence-based, ADR-0048).
#[test]
fn gc_verify_and_push_work_on_a_size_limited_clone() {
    let sz = Sz::new("gcpush");
    let clone = sz.clone(&[], LIMIT, false);
    let old_big = blob_id(&text(&[]));

    clone.gc(Duration::from_secs(0)).unwrap();
    assert!(has(&clone, &blob_id(&huge(2))), "gc keeps the tip");
    assert!(!has(&clone, &old_big), "and does not invent the gap");
    assert_eq!(clone.partial_gap_count(&[sz.c2]).unwrap(), Some(2));

    // A commit on the clone carries the gapped history by id and pushes.
    std::fs::write(sz.clone_root.join("small.txt"), b"s3\n").unwrap();
    let tip = clone.commit("t", "local").unwrap();
    // The origin handle holds the repo lock; release it for the push.
    let Sz {
        origin_root,
        clone_root,
        origin,
        ..
    } = sz;
    drop(origin);
    assert_eq!(clone.push("origin").unwrap(), tip);
    drop(clone);
    let origin = Repo::open(&origin_root).unwrap();
    assert!(has(&origin, &old_big), "the origin still holds the history");
    assert_eq!(origin.head_tip().unwrap(), Some(tip));
    assert!(origin.snapshot(&tip).is_ok());
    drop(origin);
    remove_all(&[&origin_root, &clone_root]);
}

/// A destination that is not a mirror lacks the gapped history, so the push is
/// refused before sending a snapshot that points at it.
#[test]
fn push_to_a_non_mirror_refuses_on_a_size_gap() {
    let sz = Sz::new("pushother");
    let clone = sz.clone(&[], LIMIT, false);
    let other_root = std::env::temp_dir().join(format!("scl-p27sz-other-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&other_root);
    std::fs::create_dir_all(&other_root).unwrap();
    drop(Repo::init(&other_root).unwrap());
    clone
        .remote_add("other", other_root.to_str().unwrap())
        .unwrap();
    std::fs::write(sz.clone_root.join("small.txt"), b"s3\n").unwrap();
    clone.commit("t", "local").unwrap();
    let err = clone.push("other").unwrap_err();
    match err {
        Error::PushGap { id, .. } => {
            assert!(id == blob_id(&text(&[])) || id == blob_id(&huge(1)), "{id}")
        }
        other => panic!("expected PushGap, got {other:?}"),
    }
    drop(clone);
    remove_all(&[&other_root]);
    sz.cleanup();
}

/// Tip-exemption ordering (D7): a tip that is an ancestor of another tip keeps
/// its own blobs, so switching to it works on a non-lazy clone.
#[test]
fn an_ancestor_tip_is_exempt_even_though_another_tip_reaches_it() {
    let sz = Sz::new("anc");
    // `old` is a ref at c1, which is also main's parent.
    sz.origin.branch("old").unwrap();
    refs::write_branch_tip(sz.origin.layout(), "old", &sz.c1).unwrap();
    let clone = sz.clone(&[], LIMIT, false);
    assert!(
        has(&clone, &blob_id(&text(&[]))),
        "old tip's big.txt is kept"
    );
    assert!(has(&clone, &blob_id(&huge(1))));
    clone.fetch("origin").unwrap();
    refs::write_branch_tip(clone.layout(), "old", &sz.c1).unwrap();
    clone.switch("old").unwrap();
    assert_eq!(
        std::fs::read(sz.clone_root.join("src/huge.bin")).unwrap(),
        huge(1)
    );
    drop(clone);
    sz.cleanup();
}

/// A tip whose root tree equals an older subtree: `side` is the first commit
/// (root R), and `main` moved everything into `x/` and then deleted it, so R
/// also appears at `x` in a non-tip. The tip's blob must be kept.
#[test]
fn a_tip_root_equal_to_an_older_subtree_is_still_expanded() {
    let pid = std::process::id();
    let base = std::env::temp_dir();
    let origin_root = base.join(format!("scl-p27sz-eq-origin-{pid}"));
    let clone_root = base.join(format!("scl-p27sz-eq-clone-{pid}"));
    for r in [&origin_root, &clone_root] {
        let _ = std::fs::remove_dir_all(r);
    }
    std::fs::create_dir_all(&origin_root).unwrap();
    let origin = Repo::init(&origin_root).unwrap();
    std::fs::write(origin_root.join("big.bin"), huge(7)).unwrap();
    let c1 = origin.commit("t", "c1").unwrap();
    std::fs::create_dir_all(origin_root.join("x")).unwrap();
    std::fs::rename(origin_root.join("big.bin"), origin_root.join("x/big.bin")).unwrap();
    origin.commit("t", "move").unwrap();
    std::fs::remove_dir_all(origin_root.join("x")).unwrap();
    std::fs::write(origin_root.join("tiny.txt"), b"t").unwrap();
    origin.commit("t", "drop").unwrap();
    refs::write_branch_tip(origin.layout(), "side", &c1).unwrap();

    let clone = Repo::clone_url_limited(
        origin_root.to_str().unwrap(),
        &clone_root,
        &[],
        Some(LIMIT),
        false,
    )
    .unwrap();
    assert!(
        has(&clone, &blob_id(&huge(7))),
        "side's tip reaches the blob; the older x/ copy must not hide it"
    );
    drop(clone);
    drop(origin);
    remove_all(&[&origin_root, &clone_root]);
}

/// The walk itself: limit semantics at the `reachable` level, both orderings of
/// the wants, and `None` equals the unlimited walk.
#[test]
fn limited_walk_orders_and_none_match_the_unlimited_walk() {
    let sz = Sz::new("walk");
    let arc = sz.origin.vfs().store();
    let mut store = arc.lock().unwrap();
    let all = crate::promisor::Promisor::with_blob_limit("", vec![], LIMIT);
    let f: &dyn crate::reachable::PrefixFilter = &all;
    let full = crate::reachable::reachable_objects(&mut *store, &[sz.c2]).unwrap();

    let none = crate::reachable::reachable_objects_limited(
        &mut *store,
        &[sz.c2],
        Some(f),
        None,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(none.included, full, "no limit keeps everything");
    assert!(none.gaps.is_empty());

    for tips in [vec![sz.c2], vec![sz.c2, sz.c1], vec![sz.c1, sz.c2]] {
        let r = crate::reachable::reachable_objects_limited(
            &mut *store,
            &tips,
            Some(f),
            Some(LIMIT),
            &Default::default(),
        )
        .unwrap();
        let old_in_tips = tips.contains(&sz.c1);
        assert_eq!(
            r.included.contains(&blob_id(&huge(1))),
            old_in_tips,
            "old huge.bin is kept exactly when c1 is itself a tip ({tips:?})"
        );
        assert!(r.included.contains(&blob_id(&huge(2))));
        assert!(r.included.is_disjoint(&r.gaps));
    }
    drop(store);
    drop(arc);
    sz.cleanup();
}

/// B3: a lazy size-only clone has a full view, and a switch to a revision with
/// a gap must still fill (the `is_full()` guard used to skip it). Undo has its
/// own test below.
#[test]
fn lazy_full_view_switch_fills_the_gapped_revision() {
    let sz = Sz::new("b3");
    let clone = sz.clone(&[], LIMIT, false);
    refs::write_branch_tip(clone.layout(), "old", &sz.c1).unwrap();

    // Non-lazy: refused before writing, naming the file.
    let err = clone.switch("old").unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert_eq!(refs::current_branch(clone.layout()).unwrap(), "main");

    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.switch("old").unwrap();
    assert_eq!(refs::current_branch(clone.layout()).unwrap(), "old");
    assert_eq!(
        std::fs::read(sz.clone_root.join("big.txt")).unwrap(),
        text(&[])
    );
    assert!(has(&clone, &blob_id(&huge(1))), "filled by id");

    // gc keeps the filled blobs (reachable from `old`).
    clone.switch("main").unwrap();
    clone.gc(Duration::from_secs(0)).unwrap();
    assert!(has(&clone, &blob_id(&huge(1))));
    drop(clone);
    sz.cleanup();
}

/// D2: tips are complete at clone time only. A fetch can bring a tip that
/// points at a gapped old blob; the non-lazy ff fails before writing with the
/// new clause and the file's own path, `backfill <file>` repairs it, and a
/// lazy clone heals it by id.
#[test]
fn a_fetch_that_reintroduces_a_gapped_blob_is_a_gap_in_view() {
    for lazy in [false, true] {
        let sz = Sz::new(if lazy { "d2-lazy" } else { "d2" });
        let clone = sz.clone(&[], LIMIT, lazy);
        // Revert big.txt to its c1 content: the blob the clone left out.
        std::fs::write(sz.origin_root.join("big.txt"), text(&[])).unwrap();
        sz.origin.commit("t", "revert").unwrap();
        clone.fetch("origin").unwrap();
        assert!(
            !has(&clone, &blob_id(&text(&[]))),
            "the fetch did not send it"
        );

        if lazy {
            clone.merge("origin/main", "t").unwrap();
            assert_eq!(
                std::fs::read(sz.clone_root.join("big.txt")).unwrap(),
                text(&[])
            );
        } else {
            let err = clone.merge("origin/main", "t").unwrap_err();
            match &err {
                Error::GapInView {
                    path,
                    prefix,
                    blob_limit,
                } => {
                    assert_eq!(path, "big.txt");
                    assert_eq!(prefix, "big.txt", "the file's own path");
                    assert_eq!(*blob_limit, Some(LIMIT));
                }
                other => panic!("expected GapInView, got {other:?}"),
            }
            let msg = err.to_string();
            assert!(msg.contains("blob:limit=1024"), "{msg}");
            assert!(msg.contains("`sc backfill big.txt`"), "{msg}");
            assert_eq!(
                std::fs::read(sz.clone_root.join("big.txt")).unwrap(),
                text(&[(0, "ours")]),
                "nothing was written"
            );
            clone.backfill(&["big.txt".to_string()]).unwrap();
            clone.merge("origin/main", "t").unwrap();
            assert_eq!(
                std::fs::read(sz.clone_root.join("big.txt")).unwrap(),
                text(&[])
            );
        }
        drop(clone);
        sz.cleanup();
    }
}

/// D3 on a prefix + limit clone: the error names the file, not the covering
/// prefix `src/`.
#[test]
fn gap_error_names_the_file_on_a_prefix_plus_limit_clone() {
    let sz = Sz::new("d3");
    let clone = sz.clone(&["src/"], LIMIT, false);
    std::fs::write(sz.origin_root.join("src/huge.bin"), huge(1)).unwrap();
    sz.origin.commit("t", "revert").unwrap();
    clone.fetch("origin").unwrap();
    let err = clone.merge("origin/main", "t").unwrap_err();
    match &err {
        Error::GapInView { path, prefix, .. } => {
            assert_eq!(path, "src/huge.bin");
            assert_eq!(prefix, "src/huge.bin", "not the covering prefix");
        }
        other => panic!("expected GapInView, got {other:?}"),
    }
    assert!(
        err.to_string().contains("`sc backfill src/huge.bin`"),
        "{err}"
    );
    drop(clone);
    sz.cleanup();
}

/// A prefix-only partial clone keeps its old error text (no limit clause).
#[test]
fn prefix_only_gap_error_is_unchanged() {
    let err = Error::GapInView {
        path: "src/a.txt".into(),
        prefix: "src/".into(),
        blob_limit: None,
    };
    assert_eq!(
        err.to_string(),
        "src/a.txt is missing from this partial clone's local objects (an earlier fetch left a gap inside the checked-out view); nothing was changed. Run `sc backfill src/` to repair it"
    );
}

/// Merge / cherry-pick / rebase with a size gap as the merge base (D3 + the
/// ADR-0049 engine): a non-lazy clone is refused before any write with the
/// file's own path, a lazy one fills the base by id and lands the merge.
#[test]
fn replay_and_merge_with_a_size_gap_as_base() {
    struct Case(&'static str);
    for case in [Case("merge"), Case("pick"), Case("rebase")] {
        for lazy in [false, true] {
            let sz = Sz::new(&format!("base-{}-{lazy}", case.0));
            // `b1` forks at c1 and edits another line of big.txt, so the base
            // (c1's big.txt) is reachable from no tip and is a gap.
            refs::write_branch_tip(sz.origin.layout(), "b1", &sz.c1).unwrap();
            sz.origin.switch("b1").unwrap();
            std::fs::write(sz.origin_root.join("big.txt"), text(&[(299, "theirs")])).unwrap();
            std::fs::write(sz.origin_root.join("src/huge.bin"), huge(1)).unwrap();
            sz.origin.commit("t", "b1 edit").unwrap();
            sz.origin.switch("main").unwrap();

            let clone = sz.clone(&[], LIMIT, lazy);
            clone.fetch("origin").unwrap();
            let base_blob = blob_id(&text(&[]));
            assert!(!has(&clone, &base_blob), "premise: the base is a gap");
            let before = refs::read_branch_tip(clone.layout(), "main").unwrap();

            let run = |c: &Repo| -> Result<(), Error> {
                match case.0 {
                    "merge" => c.merge("origin/b1", "t").map(|_| ()),
                    "pick" => c
                        .cherry_pick("origin/b1", "t", None, None)
                        .map(|r| assert!(matches!(r, PickResult::Picked(_)))),
                    _ => c.rebase("origin/b1", "t", None).map(|r| {
                        assert!(matches!(
                            r,
                            RebaseResult::Rebased { .. } | RebaseResult::FastForwarded(_)
                        ))
                    }),
                }
            };
            if lazy {
                run(&clone).unwrap_or_else(|e| panic!("{} lazy: {e:?}", case.0));
                assert!(has(&clone, &base_blob), "the base was filled by id");
                let merged = std::fs::read(sz.clone_root.join("big.txt")).unwrap();
                let merged = String::from_utf8(merged).unwrap();
                if case.0 != "rebase" {
                    assert!(merged.starts_with("ours\n"), "{}", &merged[..20]);
                    assert!(merged.contains("theirs\n"));
                }
            } else {
                let err = run(&clone)
                    .err()
                    .unwrap_or_else(|| panic!("{}: non-lazy run succeeded", case.0));
                match &err {
                    Error::GapBySize { path, limit } => {
                        assert_eq!(path, "big.txt", "{} names the file", case.0);
                        assert_eq!(*limit, LIMIT);
                    }
                    Error::GapInView { prefix, .. } => {
                        assert_eq!(prefix, "big.txt", "{} names the file", case.0)
                    }
                    other => panic!("{}: unexpected {other:?}", case.0),
                }
                assert!(
                    err.to_string().contains("sc backfill big.txt"),
                    "{}: {err}",
                    case.0
                );
                assert_eq!(
                    refs::read_branch_tip(clone.layout(), "main").unwrap(),
                    before,
                    "refused before any ref moved"
                );
                assert!(!clone.merge_in_progress() && !clone.pick_in_progress());
                // The repair the message names makes the retry succeed.
                clone.backfill(&["big.txt".to_string()]).unwrap();
                run(&clone).unwrap();
            }
            drop(clone);
            sz.cleanup();
        }
    }
}

/// Sessions on a size-only clone: a non-lazy workspace forks the complete tip
/// view and harvests a clean merge, and a lazy clone's fork after a healed
/// fast-forward does too.
#[test]
fn workspace_session_on_a_size_limited_clone_lands() {
    use crate::ws::WsHarvestOutcome;
    for (lazy, name) in [(false, None), (true, None), (false, Some("named"))] {
        let sz = Sz::new(&format!("ws-{lazy}-{}", name.unwrap_or("default")));
        let clone = sz.clone(&[], LIMIT, lazy);
        let session = clone.ws_fork(name, 1, "t", None).unwrap();
        let ws = &session.workspaces[0].dir;
        assert_eq!(
            std::fs::read(ws.join("src/huge.bin")).unwrap(),
            huge(2),
            "the large tip file is laid out in the workspace"
        );
        std::fs::write(ws.join("big.txt"), text(&[(0, "ours"), (150, "ws")])).unwrap();
        std::fs::write(
            sz.clone_root.join("big.txt"),
            text(&[(0, "ours"), (299, "host")]),
        )
        .unwrap();
        clone.commit("t", "host edit").unwrap();
        let outcomes = clone.ws_harvest(name, None, "t", None).unwrap();
        assert!(
            matches!(outcomes.as_slice(), [WsHarvestOutcome::Landed { .. }]),
            "got {outcomes:?}"
        );
        let landed =
            String::from_utf8(std::fs::read(sz.clone_root.join("big.txt")).unwrap()).unwrap();
        assert!(landed.contains("ws\n") && landed.contains("host\n"));
        drop(clone);
        sz.cleanup();
    }
}

/// `--lazy` works when the only filter is `blob:`: the marker is set after a
/// size-only clone and `sc cat` fills an old version by id.
#[test]
fn lazy_works_when_the_only_filter_is_a_size_limit() {
    let sz = Sz::new("lazycat");
    let clone = sz.clone(&[], LIMIT, true);
    assert!(crate::promisor::is_lazy(clone.layout()));
    refs::write_branch_tip(clone.layout(), "old", &sz.c1).unwrap();
    let bytes = clone.cat_at("old", "src/huge.bin").unwrap();
    assert_eq!(&bytes[..], &huge(1)[..]);
    assert!(has(&clone, &blob_id(&huge(1))));
    drop(clone);
    sz.cleanup();
}

/// A non-lazy clone's `sc cat` of an old version gets the size-aware error.
#[test]
fn cat_of_a_gapped_blob_names_the_limit_when_not_lazy() {
    let sz = Sz::new("catgap");
    let clone = sz.clone(&[], LIMIT, false);
    refs::write_branch_tip(clone.layout(), "old", &sz.c1).unwrap();
    let err = clone.cat_at("old", "src/huge.bin").unwrap_err();
    assert!(matches!(err, Error::GapBySize { .. }), "got {err:?}");
    assert!(err.to_string().contains("blob:limit=1024"), "{err}");
    assert!(
        err.to_string().contains("sc backfill src/huge.bin"),
        "{err}"
    );
    drop(clone);
    sz.cleanup();
}

/// The partial-clone refusals apply to a size-only clone exactly as before.
#[test]
fn partial_refusals_are_unchanged_on_a_size_limited_clone() {
    let sz = Sz::new("refuse");
    let clone = sz.clone(&[], LIMIT, false);
    let (sk, pk) = scl_crypto::generate_keypair();
    let rid = pk.recipient_id();
    assert!(matches!(
        clone.rewrap(&sk, &[], &[], false),
        Err(Error::PartialCloneUnsupported(_))
    ));
    assert!(matches!(
        clone.grant("src/", &sk, &pk),
        Err(Error::PartialCloneUnsupported(_))
    ));
    assert!(matches!(
        clone.revoke("src/", &rid),
        Err(Error::PartialCloneUnsupported(_))
    ));
    drop(clone);
    sz.cleanup();

    // A prefix + limit clone keeps the sparse refusals and names both filters.
    let sz = Sz::new("refuse-prefix");
    let clone = sz.clone(&["src/"], LIMIT, false);
    let err = clone.set_sparse(&[], None).unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument(ref m) if m.contains("empty sparse spec")),
        "got {err:?}"
    );
    assert!(
        err.to_string()
            .contains(&format!("src/, blob:limit={LIMIT}")),
        "{err}"
    );
    assert!(
        clone.disable_sparse(None).is_err(),
        "sparse disable stays refused"
    );
    drop(clone);
    sz.cleanup();
}

/// A size-only clone can narrow its view and return to the full one it started
/// with: `sparse set` with no prefixes and `sparse disable` are allowed on an
/// `AllPaths` scope (the closure is filled when lazy, `GapInView` otherwise).
#[test]
fn a_size_only_clone_can_narrow_and_restore_its_full_view() {
    let sz = Sz::new("restore");
    let clone = sz.clone(&[], LIMIT, false);
    clone.set_sparse(&["src/".to_string()], None).unwrap();
    assert!(!sz.clone_root.join("big.txt").exists(), "narrowed");
    clone.set_sparse(&[], None).unwrap();
    assert!(clone.sparse_spec().unwrap().is_full());
    assert_eq!(
        std::fs::read(sz.clone_root.join("big.txt")).unwrap(),
        text(&[(0, "ours")]),
        "restored"
    );
    clone.set_sparse(&["src/".to_string()], None).unwrap();
    clone.disable_sparse(None).unwrap();
    assert!(clone.sparse_spec().unwrap().is_full());
    assert!(sz.clone_root.join("big.txt").exists());
    assert!(clone.promisor().unwrap().unwrap().is_all_paths());
    drop(clone);
    sz.cleanup();
}

/// B3 for undo: restoring a ref to a revision with a size gap fills it first on
/// a lazy full-view clone, and refuses before moving anything otherwise.
#[test]
fn undo_to_a_gapped_revision_fills_when_lazy_and_refuses_otherwise() {
    for lazy in [false, true] {
        let sz = Sz::new(if lazy { "undo-lazy" } else { "undo" });
        let clone = sz.clone(&[], LIMIT, lazy);
        let head = refs::current_branch(clone.layout()).unwrap();
        crate::oplog::record(
            clone.layout(),
            "synthetic",
            &head,
            &head,
            &[("main".to_string(), Some(sz.c1), Some(sz.c2))],
        )
        .unwrap();
        if lazy {
            clone.undo().unwrap();
            assert_eq!(
                refs::read_branch_tip(clone.layout(), "main").unwrap(),
                Some(sz.c1)
            );
            assert!(
                has(&clone, &blob_id(&huge(1))),
                "filled before the ref moved"
            );
            assert_eq!(
                std::fs::read(sz.clone_root.join("src/huge.bin")).unwrap(),
                huge(1)
            );
        } else {
            let err = clone.undo().unwrap_err();
            assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
            assert_eq!(
                refs::read_branch_tip(clone.layout(), "main").unwrap(),
                Some(sz.c2),
                "no ref moved"
            );
        }
        drop(clone);
        sz.cleanup();
    }
}

/// Named, concurrent sessions (ADR-0056) on a size-only clone: each records the
/// host's full view at fork, lays out the large tip file, and lands on its own;
/// the second harvest merges over the first. A fork always starts at a ref tip,
/// which is complete, so a size gap cannot be in a new session's base.
#[test]
fn named_sessions_on_a_size_limited_clone() {
    use crate::ws::WsHarvestOutcome;
    let sz = Sz::new("named-ws");
    let clone = sz.clone(&[], LIMIT, false);
    let a = clone.ws_fork(Some("a"), 1, "t", None).unwrap();
    let b = clone.ws_fork(Some("b"), 1, "t", None).unwrap();
    assert!(
        a.sparse.is_empty() && b.sparse.is_empty(),
        "full view recorded"
    );
    for sess in [&a, &b] {
        assert_eq!(
            std::fs::read(sess.workspaces[0].dir.join("src/huge.bin")).unwrap(),
            huge(2)
        );
    }
    std::fs::write(
        a.workspaces[0].dir.join("big.txt"),
        text(&[(0, "ours"), (100, "from a")]),
    )
    .unwrap();
    std::fs::write(
        b.workspaces[0].dir.join("big.txt"),
        text(&[(0, "ours"), (200, "from b")]),
    )
    .unwrap();
    for name in ["a", "b"] {
        let out = clone.ws_harvest(Some(name), None, "t", None).unwrap();
        assert!(
            matches!(out.as_slice(), [WsHarvestOutcome::Landed { .. }]),
            "{name}: {out:?}"
        );
    }
    let landed = String::from_utf8(std::fs::read(sz.clone_root.join("big.txt")).unwrap()).unwrap();
    assert!(landed.contains("from a\n") && landed.contains("from b\n"));

    assert!(
        clone.ws_sessions().unwrap().is_empty(),
        "both sessions ended"
    );
    drop(clone);
    sz.cleanup();
}

impl Sz {
    /// Two more origin commits on top of `c2`: `c3` adds `extra.bin` (over the
    /// limit), `c4` (the new tip) replaces it. `extra.bin` v1 is history only;
    /// v2 is the tip's.
    fn grow(&self) -> ObjectId {
        std::fs::write(self.origin_root.join("extra.bin"), huge(3)).unwrap();
        self.origin.commit("t", "c3").unwrap();
        std::fs::write(self.origin_root.join("extra.bin"), huge(4)).unwrap();
        self.origin.commit("t", "c4").unwrap()
    }
}

/// ADR-0055 addendum (#217): a fetch from the promisor origin sends the
/// recorded limit, so a history-only large blob that arrives later is a gap
/// while the new tip stays complete.
#[test]
fn fetch_sends_the_recorded_limit_and_keeps_the_new_tip_complete() {
    let sz = Sz::new("fetch");
    let clone = sz.clone(&[], LIMIT, false);
    let c4 = sz.grow();

    let refs = clone.fetch("origin").unwrap();
    assert_eq!(refs, vec![("main".to_string(), c4)]);
    assert_eq!(
        refs::read_remote_tip(clone.layout(), "origin", "main").unwrap(),
        Some(c4)
    );
    assert!(
        has(&clone, &blob_id(&huge(4))),
        "the new tip's blob is whole"
    );
    assert!(
        !has(&clone, &blob_id(&huge(3))),
        "history-only blob is a gap"
    );
    assert_eq!(
        clone.partial_gap_count(&[c4]).unwrap(),
        Some(3),
        "the two earlier gaps plus the new one"
    );
    // The tip is complete: fast-forwarding to it lays out the large file.
    clone.merge("origin/main", "t").unwrap();
    assert_eq!(
        std::fs::read(sz.clone_root.join("extra.bin")).unwrap(),
        huge(4)
    );
    drop(clone);
    sz.cleanup();
}

/// `fetch_limited(.., true)` (`sc fetch --no-blob-limit`) sends no limit for
/// that fetch and leaves the recorded limit alone.
#[test]
fn no_blob_limit_fetches_history_in_full_and_keeps_the_marker() {
    let sz = Sz::new("nolimit");
    let clone = sz.clone(&[], LIMIT, false);
    let c4 = sz.grow();

    clone.fetch_limited("origin", false, true).unwrap();
    assert!(has(&clone, &blob_id(&huge(3))), "full history arrived");
    assert!(has(&clone, &blob_id(&huge(4))));
    assert!(
        !has(&clone, &blob_id(&huge(1))),
        "older gaps stay gaps: subtraction trusts what the clone already has"
    );
    assert_eq!(
        clone.promisor().unwrap().unwrap().blob_limit(),
        Some(LIMIT),
        "the recorded limit is untouched"
    );
    assert_eq!(
        refs::read_remote_tip(clone.layout(), "origin", "main").unwrap(),
        Some(c4)
    );
    drop(clone);
    sz.cleanup();
}

/// A prefix+limit clone sends only its limit on fetch (a fetch is
/// path-unfiltered, ADR-0048), so out-of-prefix tip blobs arrive whole and
/// history-only large blobs anywhere are gaps.
#[test]
fn fetch_on_a_prefix_plus_limit_clone_applies_the_limit_to_every_path() {
    let sz = Sz::new("fetch-prefix");
    let clone = sz.clone(&["src/"], LIMIT, false);
    let c4 = sz.grow();

    clone.fetch("origin").unwrap();
    assert!(
        has(&clone, &blob_id(&huge(4))),
        "an out-of-prefix tip blob arrives (fetch is not path-filtered)"
    );
    assert!(!has(&clone, &blob_id(&huge(3))), "the limit still applies");
    assert_eq!(
        refs::read_remote_tip(clone.layout(), "origin", "main").unwrap(),
        Some(c4)
    );
    let p = clone.promisor().unwrap().unwrap();
    assert_eq!(p.prefixes(), &["src/".to_string()], "scope unchanged");
    drop(clone);
    sz.cleanup();
}

/// Clones without a limit are unaffected: a prefix-only clone and a full clone
/// still fetch history in full, and `--no-blob-limit` is a no-op for them.
#[test]
fn fetch_without_a_recorded_limit_is_unchanged() {
    let sz = Sz::new("fetch-plain");
    let full_root =
        std::env::temp_dir().join(format!("scl-p27sz-plain-full-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&full_root);
    let full = Repo::clone_to(&sz.origin_root, &full_root).unwrap();
    let prefix_root =
        std::env::temp_dir().join(format!("scl-p27sz-plain-prefix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&prefix_root);
    let prefix = Repo::clone_url_filtered(
        sz.origin_root.to_str().unwrap(),
        &prefix_root,
        Some(&["src/".to_string()]),
    )
    .unwrap();
    sz.grow();
    let (sk, pk) = scl_crypto::generate_keypair();
    sz.origin
        .branch_private("embargo", &sk, std::slice::from_ref(&pk), &[])
        .unwrap();
    sz.origin.switch_with_identity("main", Some(&sk)).unwrap();

    // A plain fetch on the full clone and the opt-out on the prefix clone: both
    // are the old unfiltered fetch.
    full.fetch("origin").unwrap();
    prefix.fetch_limited("origin", false, true).unwrap();
    for repo in [&full, &prefix] {
        assert!(
            repo.layout().remote_ref_path("origin", "embargo").exists(),
            "an unfiltered fetch still records the private remote ref"
        );
    }
    for repo in [&full, &prefix] {
        assert!(has(repo, &blob_id(&huge(3))), "history arrives whole");
        assert!(has(repo, &blob_id(&huge(4))));
    }
    drop((full, prefix));
    remove_all(&[&full_root, &prefix_root]);
    sz.cleanup();
}

/// A limit-bearing fetch skips a ref whose tip did not arrive (a private
/// branch's manifest, dropped under any active filter) instead of recording a
/// dangling remote-tracking ref.
#[test]
fn fetch_with_a_limit_skips_private_refs_it_did_not_receive() {
    let sz = Sz::new("fetch-private");
    let clone = sz.clone(&[], LIMIT, false);
    let (sk, pk) = scl_crypto::generate_keypair();
    sz.origin
        .branch_private("embargo", &sk, std::slice::from_ref(&pk), &[])
        .unwrap();
    // `branch_private` switches the origin to the private branch; go back.
    sz.origin.switch_with_identity("main", Some(&sk)).unwrap();

    assert!(
        sz.origin
            .branches()
            .unwrap()
            .iter()
            .any(|(n, _)| n == "embargo"),
        "the origin serves the private ref"
    );
    let refs = clone.fetch("origin").unwrap();
    assert_eq!(refs.len(), 1, "{refs:?}");
    assert_eq!(refs[0].0, "main");
    assert!(!clone.layout().remote_ref_path("origin", "embargo").exists());
    drop(clone);
    sz.cleanup();
}

/// Counts `blob_size` calls, to prove which blobs the limit measures.
struct Counting<'a> {
    store: &'a mut scl_core::Store,
    measured: usize,
}

impl crate::reachable::ObjectSource for Counting<'_> {
    fn get(&mut self, id: &ObjectId) -> crate::error::Result<Object> {
        crate::reachable::ObjectSource::get(self.store, id)
    }
    fn blob_size(&mut self, id: &ObjectId) -> crate::error::Result<u64> {
        self.measured += 1;
        crate::reachable::ObjectSource::blob_size(self.store, id)
    }
}

/// A fetch measures only blobs the receiver lacks: with the whole closure held
/// (a no-op fetch) nothing is measured, and the result is the same as without.
#[test]
fn the_limited_walk_does_not_measure_blobs_the_receiver_holds() {
    let sz = Sz::new("held");
    let arc = sz.origin.vfs().store();
    let mut store = arc.lock().unwrap();
    let all = crate::promisor::Promisor::with_blob_limit("", vec![], LIMIT);
    let f: &dyn crate::reachable::PrefixFilter = &all;
    let held = crate::reachable::reachable_objects(&mut *store, &[sz.c2]).unwrap();

    let mut cold = Counting {
        store: &mut store,
        measured: 0,
    };
    let r_cold = crate::reachable::reachable_objects_limited(
        &mut cold,
        &[sz.c2],
        Some(f),
        Some(LIMIT),
        &Default::default(),
    )
    .unwrap();
    assert!(cold.measured > 0, "control: a clone measures history blobs");

    let mut warm = Counting {
        store: &mut store,
        measured: 0,
    };
    let r_warm = crate::reachable::reachable_objects_limited(
        &mut warm,
        &[sz.c2],
        Some(f),
        Some(LIMIT),
        &held,
    )
    .unwrap();
    assert_eq!(warm.measured, 0, "a no-op fetch measures nothing");
    // Held blobs are kept instead of gapped; subtracting `held` leaves the
    // same pack either way.
    let pack = |r: &crate::reachable::Reachable| -> Vec<ObjectId> {
        r.included
            .iter()
            .filter(|id| !held.contains(id))
            .copied()
            .collect()
    };
    assert_eq!(pack(&r_cold), pack(&r_warm));
    drop(store);
    sz.cleanup();
}
