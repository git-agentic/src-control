//! Tests for the presence-based partial-clone engine (ADR-0048, P37b-i).
//!
//! These cover behavior that spans modules (fetch, gc, push, materialize,
//! switch, undo, sparse, commit) on a partial clone whose store no longer
//! matches its fetch filter. The shared fixture reproduces the way that
//! happens on an ordinary `sc fetch`: the origin adds a file inside the
//! filter whose bytes equal an object that is only reachable at an
//! out-of-filter path, so the origin's `haves` subtraction leaves the new
//! in-filter blob out of the reply.

use std::path::PathBuf;
use std::time::Duration;

use scl_core::{Object, ObjectId};

use crate::error::Error;
use crate::refs;
use crate::repo::Repo;
use crate::sparse::Sparse;

/// Bytes shared by `docs/readme.txt` (out of filter) and, in commit two,
/// `src/readme.txt` (in filter).
const SHARED: &[u8] = b"identical bytes that live at two paths\n";

struct Fx {
    origin_root: PathBuf,
    clone_root: PathBuf,
    /// Second native repo used as a non-origin remote.
    other_root: PathBuf,
    /// The origin's second snapshot (the one the clone has not fetched).
    c2: ObjectId,
    /// The blob that `src/readme.txt` and `docs/readme.txt` share.
    shared_blob: ObjectId,
    /// The origin's `docs` subtree (a gap on the clone).
    docs_tree: ObjectId,
}

impl Fx {
    /// An origin with `src/a.txt` and `docs/readme.txt` (commit one), a
    /// `--filter src/` clone of it, and then a second origin commit that adds
    /// `src/aaa.txt` (fetched normally) and `src/readme.txt` (omitted by the
    /// fetch). The clone has NOT fetched yet.
    fn new(tag: &str) -> (Fx, Repo) {
        Fx::build(tag, true)
    }

    /// Like [`Fx::new`], but the origin stays at its first commit, so the
    /// clone can push without a fast-forward conflict.
    fn new_in_sync(tag: &str) -> (Fx, Repo) {
        Fx::build(tag, false)
    }

    fn build(tag: &str, advance: bool) -> (Fx, Repo) {
        let pid = std::process::id();
        let base = std::env::temp_dir();
        let origin_root = base.join(format!("scl-p37b-{tag}-origin-{pid}"));
        let clone_root = base.join(format!("scl-p37b-{tag}-clone-{pid}"));
        let other_root = base.join(format!("scl-p37b-{tag}-other-{pid}"));
        for r in [&origin_root, &clone_root, &other_root] {
            let _ = std::fs::remove_dir_all(r);
        }
        std::fs::create_dir_all(origin_root.join("src")).unwrap();
        std::fs::create_dir_all(origin_root.join("docs")).unwrap();
        let origin = Repo::init(&origin_root).unwrap();
        std::fs::write(origin_root.join("src/a.txt"), b"src-one").unwrap();
        std::fs::write(origin_root.join("docs/readme.txt"), SHARED).unwrap();
        let c1 = origin.commit("t", "c1").unwrap();
        let docs_tree = {
            let arc = origin.vfs().store();
            let mut s = arc.lock().unwrap();
            let root = s.get_snapshot(&c1).unwrap().root;
            s.get_tree(&root).unwrap().get("docs").unwrap().id
        };
        let shared_blob = Object::blob(SHARED.to_vec()).id();

        let clone = Repo::clone_url_filtered(
            origin_root.to_str().unwrap(),
            &clone_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        let c2 = if advance {
            std::fs::write(origin_root.join("src/aaa.txt"), b"fetched normally").unwrap();
            std::fs::write(origin_root.join("src/readme.txt"), SHARED).unwrap();
            origin.commit("t", "c2").unwrap()
        } else {
            c1
        };
        drop(origin);

        std::fs::create_dir_all(&other_root).unwrap();
        let other = Repo::init(&other_root).unwrap();
        drop(other);

        (
            Fx {
                origin_root,
                clone_root,
                other_root,
                c2,
                shared_blob,
                docs_tree,
            },
            clone,
        )
    }

    fn has(repo: &Repo, id: &ObjectId) -> bool {
        repo.vfs().store().lock().unwrap().contains(id)
    }

    fn cleanup(self) {
        for r in [&self.origin_root, &self.clone_root, &self.other_root] {
            if r.exists() {
                std::fs::remove_dir_all(r).unwrap();
            }
            assert!(!r.exists(), "fixture {} must be removed", r.display());
        }
    }
}

/// The ADR-0048 repro. After an ordinary fetch the new in-filter blob is
/// absent; `sc gc` must still work, the gap must be counted, and a
/// fast-forward must fail cleanly (before writing anything) instead of
/// failing in `materialize` after it had rewritten part of the tree.
#[test]
fn fetch_leaves_in_filter_gap_gc_works_and_ff_fails_before_writing() {
    let (fx, clone) = Fx::new("repro");
    clone.fetch("origin").unwrap();
    assert!(
        !Fx::has(&clone, &fx.shared_blob),
        "premise: the fetch omitted the blob (it is reachable from a have at docs/)"
    );

    // gc used to fail with `object ... not found` here.
    clone.gc(Duration::from_secs(0)).unwrap();

    // The gap is counted: the never-fetched docs tree, plus the new blob.
    assert_eq!(clone.partial_gap_count(&[fx.c2]).unwrap(), Some(2));

    let head_before = refs::read_branch_tip(clone.layout(), "main").unwrap();
    let err = clone.merge("origin/main", "t").unwrap_err();
    match &err {
        Error::GapInView { path, prefix, .. } => {
            assert_eq!(path, "src/readme.txt");
            assert_eq!(prefix, "src/");
        }
        other => panic!("expected GapInView, got {other:?}"),
    }
    assert!(
        err.to_string().contains("sc backfill src/"),
        "the error names the repair: {err}"
    );
    // Nothing moved: the ref is unchanged and no file was written, not even
    // `src/aaa.txt`, which sorts before the missing `src/readme.txt`.
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        head_before
    );
    assert!(!fx.clone_root.join("src/aaa.txt").exists());
    assert!(!fx.clone_root.join("src/readme.txt").exists());

    // `sc backfill src/` repairs it, and the fast-forward then works.
    clone.backfill(&["src/".to_string()]).unwrap();
    assert!(Fx::has(&clone, &fx.shared_blob));
    clone.merge("origin/main", "t").unwrap();
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/readme.txt")).unwrap(),
        SHARED
    );
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/aaa.txt")).unwrap(),
        b"fetched normally"
    );
    drop(clone);
    fx.cleanup();
}

/// `switch` preflights the target before it removes or writes anything.
#[test]
fn switch_to_a_gapped_branch_fails_before_writing() {
    let (fx, clone) = Fx::new("switch");
    clone.fetch("origin").unwrap();
    refs::write_branch_tip(clone.layout(), "feat", &fx.c2).unwrap();

    let err = clone.switch("feat").unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert_eq!(refs::current_branch(clone.layout()).unwrap(), "main");
    assert!(!fx.clone_root.join("src/aaa.txt").exists());
    assert!(fx.clone_root.join("src/a.txt").exists());
    drop(clone);
    fx.cleanup();
}

/// `sc undo` preflights the snapshot it will restore, before any ref moves.
#[test]
fn undo_to_a_gapped_snapshot_fails_before_moving_refs() {
    let (fx, clone) = Fx::new("undo");
    clone.fetch("origin").unwrap();
    // Record an operation whose undo would restore `main` to the gapped c2.
    let head = refs::current_branch(clone.layout()).unwrap();
    let cur = refs::read_branch_tip(clone.layout(), "main").unwrap();
    crate::oplog::record(
        clone.layout(),
        "synthetic",
        &head,
        &head,
        &[("main".to_string(), Some(fx.c2), cur)],
    )
    .unwrap();

    let err = clone.undo().unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert_eq!(refs::read_branch_tip(clone.layout(), "main").unwrap(), cur);
    assert!(!fx.clone_root.join("src/aaa.txt").exists());
    drop(clone);
    fx.cleanup();
}

/// `sparse set` checks the proposed view before it stores the new spec.
#[test]
fn sparse_set_with_a_gapped_head_keeps_the_old_spec() {
    let (fx, clone) = Fx::new_in_sync("sparse-gap");
    // Lose an in-view blob from the store (the working tree still has the
    // file, so the tree is clean and `sparse set` reaches the preflight).
    let lost = Object::blob(b"src-one".to_vec()).id();
    clone.vfs().store().lock().unwrap().delete(&lost).unwrap();
    let before = clone.sparse_spec().unwrap();

    let err = clone.set_sparse(&["src/".to_string()], None).unwrap_err();
    assert!(
        matches!(err, Error::GapInView { ref path, .. } if path == "src/a.txt"),
        "got {err:?}"
    );
    assert_eq!(clone.sparse_spec().unwrap(), before, "spec untouched");
    drop(clone);
    fx.cleanup();
}

/// An empty spec is a full checkout, which a partial clone cannot have.
#[test]
fn sparse_set_with_no_prefixes_is_refused_on_a_partial_clone() {
    let (fx, clone) = Fx::new("sparse-empty");
    let before = clone.sparse_spec().unwrap();
    let err = clone.set_sparse(&[], None).unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument(ref m) if m.contains("empty sparse spec")),
        "got {err:?}"
    );
    assert_eq!(clone.sparse_spec().unwrap(), before);
    drop(clone);
    fx.cleanup();
}

/// A fill brings in objects outside the filter; gc keeps them because they
/// are reachable, not because the filter says so.
#[test]
fn gc_keeps_filled_objects_outside_the_filter() {
    let (fx, clone) = Fx::new("gc-fill");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    let bytes = clone.cat_at("main", "docs/readme.txt").unwrap();
    assert_eq!(&bytes[..], SHARED);
    assert!(Fx::has(&clone, &fx.docs_tree));
    assert!(Fx::has(&clone, &fx.shared_blob));

    clone.gc(Duration::from_secs(0)).unwrap();
    assert!(Fx::has(&clone, &fx.docs_tree), "filled tree survives gc");
    assert!(Fx::has(&clone, &fx.shared_blob), "filled blob survives gc");
    // And a fresh `cat` still works without refetching anything it holds.
    assert_eq!(
        &clone.cat_at("main", "docs/readme.txt").unwrap()[..],
        SHARED
    );
    drop(clone);
    fx.cleanup();
}

/// A locally created object that is later lost must stop the push, not ship
/// a tree that names it.
#[test]
fn push_refuses_when_a_local_object_is_lost() {
    let (fx, clone) = Fx::new_in_sync("push-lost");
    std::fs::write(fx.clone_root.join("src/a.txt"), b"edited locally").unwrap();
    let tip = clone.commit("t", "local edit").unwrap();
    let lost = Object::blob(b"edited locally".to_vec()).id();
    clone.vfs().store().lock().unwrap().delete(&lost).unwrap();
    assert!(!Fx::has(&clone, &lost));

    let err = clone.push("origin").unwrap_err();
    match err {
        Error::PushGap { id, .. } => assert_eq!(id, lost),
        other => panic!("expected PushGap, got {other:?}"),
    }
    // The origin was not touched.
    drop(clone);
    let origin = Repo::open(&fx.origin_root).unwrap();
    assert!(!Fx::has(&origin, &tip));
    assert_eq!(
        origin.head_tip().unwrap(),
        Some(fx.c2),
        "origin tip unchanged"
    );
    drop(origin);
    fx.cleanup();
}

/// A destination that is not a mirror of the origin lacks the gap objects, so
/// the push is refused instead of writing a snapshot with dangling children.
#[test]
fn push_to_a_non_mirror_remote_is_refused() {
    let (fx, clone) = Fx::new_in_sync("push-other");
    clone
        .remote_add("other", fx.other_root.to_str().unwrap())
        .unwrap();
    std::fs::write(fx.clone_root.join("src/a.txt"), b"edited locally").unwrap();
    let tip = clone.commit("t", "local edit").unwrap();

    let err = clone.push("other").unwrap_err();
    match err {
        Error::PushGap { id, .. } => assert_eq!(id, fx.docs_tree),
        other => panic!("expected PushGap, got {other:?}"),
    }
    drop(clone);
    let other = Repo::open(&fx.other_root).unwrap();
    assert!(!Fx::has(&other, &tip), "nothing was sent");
    drop(other);
    fx.cleanup();
}

/// A partial clone fetches from its promisor origin only.
#[test]
fn fetch_from_a_non_origin_remote_is_refused() {
    let (fx, clone) = Fx::new("fetch-other");
    clone
        .remote_add("other", fx.other_root.to_str().unwrap())
        .unwrap();
    let err = clone.fetch("other").unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument(ref m) if m.contains("promisor origin")),
        "got {err:?}"
    );
    // The origin itself is fine.
    clone.fetch("origin").unwrap();
    drop(clone);
    fx.cleanup();
}

/// Commands that flatten whole trees refuse explicitly on a partial clone.
#[test]
fn whole_tree_commands_refuse_on_a_partial_clone() {
    let (fx, clone) = Fx::new("refuse");
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
    fx.cleanup();
}

/// The commit graft refuses a brand-new top-level directory only when it
/// lies outside BOTH the promisor filter and the sparse view. A view that
/// was widened past the filter (37b-ii) therefore stops being refused.
#[test]
fn graft_new_name_check_uses_filter_union_sparse() {
    let (fx, clone) = Fx::new("graft");
    std::fs::create_dir_all(fx.clone_root.join("tools")).unwrap();
    std::fs::write(fx.clone_root.join("tools/x.txt"), b"tool").unwrap();
    let err = clone.commit("t", "tools").unwrap_err();
    assert!(
        matches!(err, Error::GappedPathContent(ref p) if p.contains("tools")),
        "outside both: refused, got {err:?}"
    );

    // Widen the view to cover `tools/` (the filter still says `src/`).
    crate::sparse::store(
        clone.layout(),
        &Sparse::new(vec!["src/".to_string(), "tools/".to_string()]),
    )
    .unwrap();
    clone.commit("t", "tools").unwrap();
    drop(clone);
    fx.cleanup();
}

/// A fetch can leave a tree inside the filter but outside the (narrower)
/// sparse view absent. A later switch or undo then lays out from a root that
/// has that gap as its OLD root; the removal walk must skip it (nothing of it
/// is on disk) instead of failing with a raw `NotFound` after refs moved.
#[test]
fn old_root_gap_outside_the_view_does_not_break_switch_or_undo() {
    let pid = std::process::id();
    let base = std::env::temp_dir();
    let origin_root = base.join(format!("scl-p37b-oldroot-origin-{pid}"));
    let clone_root = base.join(format!("scl-p37b-oldroot-clone-{pid}"));
    for r in [&origin_root, &clone_root] {
        let _ = std::fs::remove_dir_all(r);
    }
    std::fs::create_dir_all(origin_root.join("src/a")).unwrap();
    std::fs::create_dir_all(origin_root.join("docs")).unwrap();
    let origin = Repo::init(&origin_root).unwrap();
    std::fs::write(origin_root.join("src/a/x.txt"), b"x").unwrap();
    std::fs::write(origin_root.join("docs/d.txt"), SHARED).unwrap();
    let c1 = origin.commit("t", "c1").unwrap();
    let clone = Repo::clone_url_filtered(
        origin_root.to_str().unwrap(),
        &clone_root,
        Some(&["src/".to_string()]),
    )
    .unwrap();
    clone.set_sparse(&["src/a/".to_string()], None).unwrap();
    // `src/b` is byte-identical to `docs`, so its tree id is reachable from a
    // have and the fetch leaves it out: inside the filter, outside the view.
    std::fs::create_dir_all(origin_root.join("src/b")).unwrap();
    std::fs::write(origin_root.join("src/b/d.txt"), SHARED).unwrap();
    origin.commit("t", "c2").unwrap();
    drop(origin);

    refs::write_branch_tip(clone.layout(), "old", &c1).unwrap();
    clone.fetch("origin").unwrap();
    clone.merge("origin/main", "t").unwrap();

    clone.switch("old").unwrap();
    let tip_old = refs::read_branch_tip(clone.layout(), "main").unwrap();
    clone.switch("main").unwrap();
    // Undo the second switch, then the first: each lays out across the gap.
    clone.undo().unwrap();
    assert_eq!(refs::current_branch(clone.layout()).unwrap(), "old");
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        tip_old
    );
    drop(clone);
    for r in [&origin_root, &clone_root] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

/// On a lazy clone the fast-forward that 37b-i refuses with `GapInView` now
/// heals itself: the missing blob is fetched by id before anything is written.
#[test]
fn lazy_clone_heals_the_fetch_gap_on_fast_forward() {
    let (fx, clone) = Fx::new("lazy-ff");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.fetch("origin").unwrap();
    assert!(!Fx::has(&clone, &fx.shared_blob));

    clone.merge("origin/main", "t").unwrap();
    assert!(Fx::has(&clone, &fx.shared_blob));
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/readme.txt")).unwrap(),
        SHARED
    );
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/aaa.txt")).unwrap(),
        b"fetched normally"
    );
    drop(clone);
    fx.cleanup();
}

#[test]
fn lazy_switch_and_undo_fill_the_target_view_first() {
    let (fx, clone) = Fx::new("lazy-switch");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.fetch("origin").unwrap();
    refs::write_branch_tip(clone.layout(), "feat", &fx.c2).unwrap();
    clone.switch("feat").unwrap();
    assert!(Fx::has(&clone, &fx.shared_blob));
    assert!(fx.clone_root.join("src/readme.txt").exists());

    // Undo back to main (a switch) then forward again: both present already.
    clone.undo().unwrap();
    assert_eq!(refs::current_branch(clone.layout()).unwrap(), "main");
    drop(clone);
    fx.cleanup();
}

/// A fill that cannot reach the origin fails the operation before it changes
/// anything: no ref move, no spec change, no file written.
#[test]
fn a_failed_fill_leaves_refs_spec_and_files_untouched() {
    let (fx, clone) = Fx::new("lazy-offline");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.fetch("origin").unwrap();
    refs::write_branch_tip(clone.layout(), "feat", &fx.c2).unwrap();
    // The origin goes away.
    std::fs::remove_dir_all(&fx.origin_root).unwrap();

    let spec_before = clone.sparse_spec().unwrap();
    assert!(clone.switch("feat").is_err());
    assert_eq!(refs::current_branch(clone.layout()).unwrap(), "main");
    assert!(!fx.clone_root.join("src/aaa.txt").exists());

    assert!(clone.merge("origin/main", "t").is_err());
    assert!(!fx.clone_root.join("src/aaa.txt").exists());

    assert!(clone.set_sparse(&["docs/".to_string()], None).is_err());
    assert_eq!(clone.sparse_spec().unwrap(), spec_before);
    assert!(fx.clone_root.join("src/a.txt").exists());
    drop(clone);
    fx.cleanup();
}

/// Fast-forward rebase is a materializer site too: a lazy clone heals the gap.
#[test]
fn lazy_clone_heals_the_fetch_gap_on_fast_forward_rebase() {
    let (fx, clone) = Fx::new("lazy-rebase");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.fetch("origin").unwrap();
    assert!(!Fx::has(&clone, &fx.shared_blob));
    let r = clone.rebase("origin/main", "t", None).unwrap();
    assert!(
        matches!(r, crate::replay::RebaseResult::FastForwarded(_)),
        "got {r:?}"
    );
    assert!(Fx::has(&clone, &fx.shared_blob));
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/readme.txt")).unwrap(),
        SHARED
    );
    drop(clone);
    fx.cleanup();
}

/// A non-lazy clone still refuses the fast-forward rebase before writing.
#[test]
fn non_lazy_fast_forward_rebase_fails_before_writing() {
    let (fx, clone) = Fx::new("rebase-gap");
    clone.fetch("origin").unwrap();
    let err = clone.rebase("origin/main", "t", None).unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert!(!fx.clone_root.join("src/aaa.txt").exists());
    drop(clone);
    fx.cleanup();
}

/// The unborn-branch adopt path fills the view first on a lazy clone.
#[test]
fn lazy_adopt_into_an_unborn_branch_fills_first() {
    let (fx, clone) = Fx::new("lazy-adopt");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.fetch("origin").unwrap();
    refs::write_head(clone.layout(), "fresh").unwrap();
    assert!(clone.head_tip().unwrap().is_none());
    clone.merge("origin/main", "t").unwrap();
    assert!(Fx::has(&clone, &fx.shared_blob));
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/readme.txt")).unwrap(),
        SHARED
    );
    drop(clone);
    fx.cleanup();
}

/// Undo on a lazy clone fills the snapshot it restores before moving any ref.
#[test]
fn lazy_undo_fills_the_restored_view_before_moving_refs() {
    let (fx, clone) = Fx::new("lazy-undo");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.fetch("origin").unwrap();
    let head = refs::current_branch(clone.layout()).unwrap();
    let cur = refs::read_branch_tip(clone.layout(), "main").unwrap();
    crate::oplog::record(
        clone.layout(),
        "synthetic",
        &head,
        &head,
        &[("main".to_string(), Some(fx.c2), cur)],
    )
    .unwrap();
    clone.undo().unwrap();
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        Some(fx.c2)
    );
    assert!(Fx::has(&clone, &fx.shared_blob), "the gap was filled");
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/readme.txt")).unwrap(),
        SHARED
    );
    drop(clone);
    fx.cleanup();
}

/// A crash between storing the new sparse spec and re-laying the tree must not
/// strand files the new spec no longer names: the pending marker keeps the old
/// view in the removal walk's bound until a later materialize finishes.
#[test]
fn an_interrupted_sparse_set_is_finished_by_the_next_materialize() {
    let (fx, clone) = Fx::new_in_sync("sparse-crash");
    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone
        .set_sparse(&["src/".to_string(), "docs/".to_string()], None)
        .unwrap();
    assert!(fx.clone_root.join("docs/readme.txt").exists());
    // Simulate the crash window of `sparse set src/`: the previous spec is
    // recorded and the new one stored, but the tree was never re-laid.
    let prev = clone.sparse_spec().unwrap();
    crate::sparse::store_prev(clone.layout(), &prev).unwrap();
    crate::sparse::store(clone.layout(), &Sparse::new(vec!["src/".to_string()])).unwrap();
    assert!(
        fx.clone_root.join("docs/readme.txt").exists(),
        "still on disk"
    );

    // The next operation that lays the tree out removes the stranded files.
    clone.set_sparse(&["src/".to_string()], None).unwrap();
    assert!(!fx.clone_root.join("docs/readme.txt").exists());
    assert!(
        !fx.clone_root.join("docs").exists() || !fx.clone_root.join("docs/readme.txt").exists()
    );
    assert!(
        !clone.layout().sparse_prev_path().exists(),
        "the marker is cleared once the re-lay completes"
    );

    // A marker left by a crash is also cleared by any other materialize (here
    // a switch), so it cannot widen later removal walks forever.
    crate::sparse::store_prev(
        clone.layout(),
        &Sparse::new(vec!["src/".to_string(), "docs/".to_string()]),
    )
    .unwrap();
    refs::write_branch_tip(clone.layout(), "other", &fx.c2).unwrap();
    clone.switch("other").unwrap();
    assert!(!clone.layout().sparse_prev_path().exists());
    // ...and a file the user creates outside the view afterwards survives the
    // next switch (it is not in the old root, and the bound is back to normal).
    std::fs::create_dir_all(fx.clone_root.join("docs")).unwrap();
    std::fs::write(fx.clone_root.join("docs/mine.txt"), b"mine").unwrap();
    clone.switch("main").unwrap();
    assert!(fx.clone_root.join("docs/mine.txt").exists());
    drop(clone);
    fx.cleanup();
}

/// Every non-test call of the materializer either fills the view's closure
/// first (`ensure_view`) or carries an `ensure-view-exempt` note saying why it
/// cannot run on a partial clone. A new call site cannot be added silently.
#[test]
fn every_materializer_call_site_fills_or_is_exempt() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name == "worktree.rs" || name == "partial_walks.rs" {
            continue; // the definition, and this test
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let body = text
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or(&text);
        let lines: Vec<&str> = body.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("///") {
                continue;
            }
            let call = t.contains("worktree::materialize(")
                || t.contains("worktree::materialize_with_old_view(");
            if !call {
                continue;
            }
            checked += 1;
            let window = lines[i.saturating_sub(60)..i].join("\n");
            assert!(
                window.contains("ensure_view(") || window.contains("ensure-view-exempt"),
                "{name}:{}: materializer call without ensure_view or an ensure-view-exempt note",
                i + 1
            );
        }
    }
    assert!(checked >= 15, "the scan found only {checked} call sites");
}

/// A private branch cannot be checked out on a partial clone (sealing and
/// opening flatten whole trees), so creating or switching to one is refused
/// explicitly instead of failing with a raw `NotFound` mid-switch.
#[test]
fn private_branches_are_refused_on_a_partial_clone() {
    let (fx, clone) = Fx::new_in_sync("private");
    let (sk, pk) = scl_crypto::generate_keypair();
    let err = clone
        .branch_private("secret-work", &sk, std::slice::from_ref(&pk), &[])
        .unwrap_err();
    assert!(
        matches!(err, Error::PartialCloneUnsupported(_)),
        "got {err:?}"
    );
    assert!(!clone.layout().ref_path("secret-work").exists());

    // A private ref that reached the clone some other way (a manifest tip) is
    // refused at switch time, before anything is touched.
    let full_root =
        std::env::temp_dir().join(format!("scl-p37b-private-full-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&full_root);
    let full = Repo::clone_to(&fx.origin_root, &full_root).unwrap();
    let mid = full
        .branch_private("secret-work", &sk, std::slice::from_ref(&pk), &[])
        .unwrap();
    {
        let src = full.vfs().store();
        let dst = clone.vfs().store();
        let m = src.lock().unwrap().get(&mid).unwrap();
        dst.lock().unwrap().put(m).unwrap();
    }
    refs::write_branch_tip(clone.layout(), "secret-work", &mid).unwrap();
    let err = clone
        .switch_with_identity("secret-work", Some(&sk))
        .unwrap_err();
    assert!(
        matches!(err, Error::PartialCloneUnsupported(_)),
        "got {err:?}"
    );
    assert_eq!(refs::current_branch(clone.layout()).unwrap(), "main");
    assert!(fx.clone_root.join("src/a.txt").exists());
    drop(full);
    std::fs::remove_dir_all(&full_root).unwrap();
    drop(clone);
    fx.cleanup();
}
