//! Tests for cherry-pick and rebase on a partial clone (ADR-0049, P37c-iv).
//!
//! They reuse the merge fixture: an origin with `src/`, `docs/`, `docs/api/`
//! and `lib/`, a `--filter src/` clone, and origin branches cut from the first
//! commit. Each result is compared, by root tree id, with the same operation
//! done on the origin, which is a full repository.

use scl_core::ObjectId;

use crate::conflicts::ResolveSide;
use crate::error::Error;
use crate::partial_merge::{clone_edit_src, dir_id, has, protected_origin, Fx, SRC_A};
use crate::refs;
use crate::replay::{PickResult, RebaseResult};
use crate::repo::Repo;

const SRC_UNO: &[u8] = b"uno\ntwo\nthree\n";
const SRC_ONE: &[u8] = b"ONE\ntwo\nthree\n";

fn root_of(repo: &Repo, tip: &ObjectId) -> ObjectId {
    repo.snapshot(tip).unwrap().root
}

/// The origin cherry-picks `pick` onto a side branch that first commits
/// `ours_edit`, and returns the resulting root: what a partial clone's pick
/// must equal.
fn full_pick_root(fx: &Fx, pick: &str, ours_edit: &[(&str, &[u8])], resolve: &[&str]) -> ObjectId {
    fx.origin.branch("expect").unwrap();
    fx.origin.switch("expect").unwrap();
    for (p, bytes) in ours_edit {
        std::fs::write(fx.origin_root.join(p), bytes).unwrap();
    }
    fx.origin.commit("t", "ours").unwrap();
    let tip = match fx.origin.cherry_pick(pick, "t", None, None) {
        Ok(PickResult::Picked(id)) => id,
        Err(Error::PickConflicts(_)) => {
            for p in resolve {
                fx.origin.resolve_path(p, ResolveSide::Ours, None).unwrap();
            }
            fx.origin.commit("t", "pick").unwrap()
        }
        other => panic!("unexpected {other:?}"),
    };
    let root = root_of(&fx.origin, &tip);
    fx.origin.switch("main").unwrap();
    root
}

/// A pick whose commit touched only a subtree outside the view carries that
/// subtree by id: nothing is read, nothing is fetched, on a clone that could
/// not fetch.
#[test]
fn a_pick_carries_a_subtree_outside_the_view_without_a_fetch() {
    let fx = Fx::origin("pick-carry", |_| {});
    let b1 = fx.origin_branch("b1", &[("docs/api/guide.md", b"g changed\n")]);
    let theirs_docs = dir_id(&fx.origin, &b1, "docs");
    let expect = full_pick_root(&fx, "b1", &[("src/a.txt", SRC_UNO)], &[]);
    let clone = fx.clone(false);
    assert!(!has(&clone, &theirs_docs), "premise: docs is a gap");
    clone_edit_src(&fx, &clone, SRC_UNO);

    let PickResult::Picked(id) = clone.cherry_pick("origin/b1", "t", None, None).unwrap() else {
        panic!("expected a pick");
    };
    let snap = clone.snapshot(&id).unwrap();
    assert_eq!(snap.parents.len(), 1);
    assert_eq!(snap.root, expect, "same tree as the full pick");
    assert_eq!(dir_id(&clone, &id, "docs"), theirs_docs);
    assert!(!has(&clone, &theirs_docs), "never read or fetched");
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        SRC_UNO
    );
    assert!(!fx.clone_root.join("docs").exists());
    clone.gc(std::time::Duration::from_secs(0)).unwrap();
    assert!(has(&clone, &id));
    drop(clone);
    fx.cleanup();
}

/// Both sides changed `docs/`: a lazy clone fills it by id, a non-lazy one is
/// refused before any write, naming the path.
#[test]
fn a_pick_over_a_region_outside_the_view_fills_when_lazy_and_is_refused_otherwise() {
    let fx = Fx::origin("pick-fill", |_| {});
    fx.origin_branch("o", &[("docs/b.md", b"b2\n")]);
    fx.origin_branch("b1", &[("docs/a.md", b"a1\n")]);
    let expect = full_pick_root(&fx, "b1", &[("docs/b.md", b"b2\n")], &[]);
    let clone = fx.clone(false);
    clone.merge("origin/o", "t").unwrap(); // fast-forward
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();

    let err = clone.cherry_pick("origin/b1", "t", None, None).unwrap_err();
    assert!(
        matches!(&err, Error::GapOutsideFilter(p) if p == "docs"),
        "got {err:?}"
    );
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );
    assert!(!clone.pick_in_progress());
    assert!(!fx.clone_root.join("docs").exists());

    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    let PickResult::Picked(id) = clone.cherry_pick("origin/b1", "t", None, None).unwrap() else {
        panic!("expected a pick");
    };
    assert_eq!(root_of(&clone, &id), expect);
    assert!(!fx.clone_root.join("docs").exists());
    drop(clone);
    fx.cleanup();
}

/// A conflict inside the view stops the pick with markers and a decided root
/// that holds the carried subtree. Resolving and committing completes it to
/// the tree a full pick gives.
#[test]
fn a_pick_conflict_in_the_view_completes_like_a_full_pick() {
    let fx = Fx::origin("pick-conflict", |_| {});
    let b1 = fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", SRC_ONE),
            ("docs/api/guide.md", b"g changed\n"),
        ],
    );
    let theirs_docs = dir_id(&fx.origin, &b1, "docs");
    let expect = full_pick_root(&fx, "b1", &[("src/a.txt", SRC_UNO)], &["src/a.txt"]);
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, SRC_UNO);
    let ours = refs::read_branch_tip(clone.layout(), "main").unwrap();

    let err = clone.cherry_pick("origin/b1", "t", None, None).unwrap_err();
    assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
    assert!(clone.pick_in_progress());
    let marked = std::fs::read_to_string(fx.clone_root.join("src/a.txt")).unwrap();
    assert!(marked.contains("<<<<<<<"), "{marked}");
    assert!(!fx.clone_root.join("docs").exists());
    assert_eq!(refs::read_branch_tip(clone.layout(), "main").unwrap(), ours);

    clone
        .resolve_path("src/a.txt", ResolveSide::Ours, None)
        .unwrap();
    let id = clone.commit("t", "pick").unwrap();
    assert!(!clone.pick_in_progress());
    let snap = clone.snapshot(&id).unwrap();
    assert_eq!(Some(snap.parents[0]), ours);
    assert_eq!(snap.root, expect, "same tree as the full pick");
    assert_eq!(dir_id(&clone, &id, "docs"), theirs_docs);
    assert!(!has(&clone, &theirs_docs), "never fetched");
    drop(clone);
    fx.cleanup();
}

/// Abort restores ours; an abort that hits a gap in the view changes nothing.
#[test]
fn aborting_a_stopped_pick_restores_ours_and_a_view_gap_changes_nothing() {
    let fx = Fx::origin("pick-abort", |_| {});
    fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", b"\xff\xfeTHEIRS\n"),
            ("docs/api/guide.md", b"g changed\n"),
        ],
    );
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"\xff\xfeOURS\n");
    let ours = refs::read_branch_tip(clone.layout(), "main")
        .unwrap()
        .unwrap();
    let sidecar = fx.clone_root.join("src/a.txt.theirs");

    assert!(matches!(
        clone.cherry_pick("origin/b1", "t", None, None).unwrap_err(),
        Error::PickConflicts(1)
    ));
    assert!(sidecar.exists());
    let src = dir_id(&clone, &ours, "src");
    clone.vfs().store().lock().unwrap().delete(&src).unwrap();
    let err = clone.cherry_pick_abort().unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert!(clone.pick_in_progress(), "still open");
    assert!(sidecar.exists(), "sidecar still there");
    drop(clone);
    fx.cleanup();

    let fx = Fx::origin("pick-abort2", |_| {});
    fx.origin_branch("b1", &[("src/a.txt", SRC_ONE)]);
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, SRC_UNO);
    assert!(matches!(
        clone.cherry_pick("origin/b1", "t", None, None).unwrap_err(),
        Error::PickConflicts(1)
    ));
    clone.cherry_pick_abort().unwrap();
    assert!(!clone.pick_in_progress());
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        SRC_UNO
    );
    drop(clone);
    fx.cleanup();
}

/// A protected subtree no commit touched is carried through a pick, so its
/// blobs were never enumerated: the picked snapshot must keep every wrap.
#[test]
fn a_pick_keeps_the_wraps_of_a_carried_protected_subtree() {
    let (sk, pk) = scl_crypto::generate_keypair();
    let fx = protected_origin("pick-wraps", &pk);
    let base = fx.origin.head_tip().unwrap().unwrap();
    let base_snap = fx.origin.snapshot(&base).unwrap();
    let vault = dir_id(&fx.origin, &base, "vault");
    fx.origin_branch("b1", &[("docs/a.md", b"a1\n")]);
    let clone = fx.clone(false);
    assert!(!has(&clone, &vault));
    clone_edit_src(&fx, &clone, SRC_UNO);

    let PickResult::Picked(id) = clone.cherry_pick("origin/b1", "t", None, None).unwrap() else {
        panic!("expected a pick");
    };
    let snap = clone.snapshot(&id).unwrap();
    assert_eq!(dir_id(&clone, &id, "vault"), vault);
    assert!(!has(&clone, &vault));
    for (blob, wraps) in &base_snap.protection.wrapped {
        assert_eq!(snap.protection.wrapped.get(blob), Some(wraps));
    }
    let (cipher_id, _) = base_snap.protection.wrapped.iter().next().unwrap();
    let cipher = {
        let arc = fx.origin.vfs().store();
        let mut s = arc.lock().unwrap();
        match s.get(cipher_id).unwrap() {
            scl_core::Object::Blob(b) => b,
            other => panic!("expected a blob, got {}", other.kind_name()),
        }
    };
    let plain =
        crate::protect::decrypt_with(&cipher, cipher_id, &[&snap.protection], &sk, "vault/s.txt")
            .unwrap();
    assert_eq!(&plain[..], b"l1\nl2\nl3\n");
    drop(clone);
    fx.cleanup();
}

/// Two local commits replayed onto a target that changed `docs/` carry the
/// target's subtree through both steps and end at the full rebase's tree.
#[test]
fn a_rebase_carries_the_targets_subtree_through_every_step() {
    let fx = Fx::origin("rebase-carry", |_| {});
    let b1 = fx.origin_branch("b1", &[("docs/api/guide.md", b"g changed\n")]);
    let theirs_docs = dir_id(&fx.origin, &b1, "docs");
    let two = b"one\nTWO\nthree\n";
    fx.origin.branch("loc").unwrap();
    fx.origin.switch("loc").unwrap();
    std::fs::write(fx.origin_root.join("src/a.txt"), two).unwrap();
    fx.origin.commit("t", "local 1").unwrap();
    std::fs::write(fx.origin_root.join("src/n.txt"), b"n\n").unwrap();
    fx.origin.commit("t", "local 2").unwrap();
    let RebaseResult::Rebased { new_tip, .. } = fx.origin.rebase("b1", "t", None).unwrap() else {
        panic!("expected a rebase");
    };
    let expect = root_of(&fx.origin, &new_tip);
    fx.origin.switch("main").unwrap();

    let clone = fx.clone(false);
    std::fs::write(fx.clone_root.join("src/a.txt"), two).unwrap();
    clone.commit("t", "local 1").unwrap();
    std::fs::write(fx.clone_root.join("src/n.txt"), b"n\n").unwrap();
    clone.commit("t", "local 2").unwrap();

    let RebaseResult::Rebased {
        new_tip,
        replayed,
        skipped,
    } = clone.rebase("origin/b1", "t", None).unwrap()
    else {
        panic!("expected a rebase");
    };
    assert_eq!((replayed, skipped), (2, 0));
    assert_eq!(
        root_of(&clone, &new_tip),
        expect,
        "same tree as the full rebase"
    );
    assert_eq!(dir_id(&clone, &new_tip, "docs"), theirs_docs);
    assert!(!has(&clone, &theirs_docs), "never read or fetched");
    assert!(!fx.clone_root.join("docs").exists());
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/n.txt")).unwrap(),
        b"n\n"
    );
    drop(clone);
    fx.cleanup();
}

/// A rebase stops on a conflict in the view, can be aborted, and when resolved
/// and continued ends at the tree the full rebase gives.
#[test]
fn a_rebase_stops_on_a_conflict_in_the_view_and_continues() {
    let fx = Fx::origin("rebase-conflict", |_| {});
    fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", SRC_ONE),
            ("docs/api/guide.md", b"g changed\n"),
        ],
    );
    let two = b"one\nTWO\nthree\n";
    // Commit 1 edits line 2; commit 2 edits line 1 and so conflicts with b1.
    let local2 = b"uno\nTWO\nthree\n";
    fx.origin.branch("loc").unwrap();
    fx.origin.switch("loc").unwrap();
    std::fs::write(fx.origin_root.join("src/a.txt"), two).unwrap();
    fx.origin.commit("t", "local 1").unwrap();
    std::fs::write(fx.origin_root.join("src/a.txt"), local2).unwrap();
    fx.origin.commit("t", "local 2").unwrap();
    assert!(matches!(
        fx.origin.rebase("b1", "t", None).unwrap(),
        RebaseResult::Stopped { .. }
    ));
    fx.origin
        .resolve_path("src/a.txt", ResolveSide::Ours, None)
        .unwrap();
    let RebaseResult::Rebased { new_tip, .. } = fx.origin.rebase_continue("t", None).unwrap()
    else {
        panic!("expected a rebase");
    };
    let expect = root_of(&fx.origin, &new_tip);
    fx.origin.switch("main").unwrap();

    let clone = fx.clone(false);
    std::fs::write(fx.clone_root.join("src/a.txt"), two).unwrap();
    clone.commit("t", "local 1").unwrap();
    std::fs::write(fx.clone_root.join("src/a.txt"), local2).unwrap();
    clone.commit("t", "local 2").unwrap();
    let original = refs::read_branch_tip(clone.layout(), "main").unwrap();

    let RebaseResult::Stopped {
        paths, done, total, ..
    } = clone.rebase("origin/b1", "t", None).unwrap()
    else {
        panic!("expected a stop");
    };
    assert_eq!((paths, done, total), (vec!["src/a.txt".to_string()], 1, 2));
    assert!(clone.rebase_in_progress());
    assert!(std::fs::read_to_string(fx.clone_root.join("src/a.txt"))
        .unwrap()
        .contains("<<<<<<<"));
    assert!(!fx.clone_root.join("docs").exists());
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        original,
        "no ref moved"
    );

    clone.rebase_abort().unwrap();
    assert!(!clone.rebase_in_progress());
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        local2
    );

    assert!(matches!(
        clone.rebase("origin/b1", "t", None).unwrap(),
        RebaseResult::Stopped { .. }
    ));
    clone
        .resolve_path("src/a.txt", ResolveSide::Ours, None)
        .unwrap();
    let RebaseResult::Rebased { new_tip, .. } = clone.rebase_continue("t", None).unwrap() else {
        panic!("expected a rebase");
    };
    assert_eq!(
        root_of(&clone, &new_tip),
        expect,
        "same tree as the full rebase"
    );
    assert!(!clone.rebase_in_progress());
    drop(clone);
    fx.cleanup();
}

/// SRC_A is the first commit's content: a pick that changes nothing there is
/// already applied.
#[test]
fn a_pick_already_applied_is_a_noop_on_a_partial_clone() {
    let fx = Fx::origin("pick-noop", |_| {});
    fx.origin_branch("b1", &[("src/a.txt", SRC_UNO)]);
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, SRC_UNO);
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();
    assert_eq!(
        clone.cherry_pick("origin/b1", "t", None, None).unwrap(),
        PickResult::AlreadyApplied
    );
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );
    let _ = SRC_A;
    drop(clone);
    fx.cleanup();
}

/// A carried subtree that lies inside the view is filled before the pick or
/// the rebase lays anything out: a lazy clone fetches it, a non-lazy one fails
/// with the view-gap error and changes nothing.
#[test]
fn a_carried_subtree_inside_the_view_is_filled_before_a_pick_or_rebase_writes() {
    let fx = Fx::origin("replay-view", |_| {});
    fx.origin_branch("b1", &[("docs/api/guide.md", b"g changed\n")]);
    let clone = fx.clone(true);
    clone
        .set_sparse(&["src/".to_string(), "docs/".to_string()], None)
        .unwrap();
    clone_edit_src(&fx, &clone, SRC_UNO);
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();

    crate::promisor::set_lazy(clone.layout(), false).unwrap();
    let err = clone.cherry_pick("origin/b1", "t", None, None).unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );
    assert_eq!(
        std::fs::read(fx.clone_root.join("docs/api/guide.md")).unwrap(),
        b"g\n",
        "nothing was laid out"
    );
    let err = clone.rebase("origin/b1", "t", None).unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );

    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.cherry_pick("origin/b1", "t", None, None).unwrap();
    assert_eq!(
        std::fs::read(fx.clone_root.join("docs/api/guide.md")).unwrap(),
        b"g changed\n"
    );
    drop(clone);
    fx.cleanup();
}

/// The same on a lazy clone for a rebase: the carried in-view subtree is
/// fetched and laid out.
#[test]
fn a_rebase_fills_a_carried_subtree_inside_the_view() {
    let fx = Fx::origin("rebase-view", |_| {});
    fx.origin_branch("b1", &[("docs/api/guide.md", b"g changed\n")]);
    let clone = fx.clone(true);
    clone
        .set_sparse(&["src/".to_string(), "docs/".to_string()], None)
        .unwrap();
    clone_edit_src(&fx, &clone, SRC_UNO);
    assert!(matches!(
        clone.rebase("origin/b1", "t", None).unwrap(),
        RebaseResult::Rebased { .. }
    ));
    assert_eq!(
        std::fs::read(fx.clone_root.join("docs/api/guide.md")).unwrap(),
        b"g changed\n"
    );
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        SRC_UNO
    );
    drop(clone);
    fx.cleanup();
}
