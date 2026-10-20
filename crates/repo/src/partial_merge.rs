//! Tests for clean merges on a partial clone (ADR-0049, P37c-ii).
//!
//! The fixture is an origin with `src/`, `docs/`, `docs/api/` and `lib/`, a
//! `--filter src/` clone of it, and two origin branches `b1` and `b2` cut from
//! the first commit. The clone's view is `src/`, so everything the tests touch
//! under `docs/` is outside it.

use std::path::{Path, PathBuf};

use scl_core::{Object, ObjectId};

use crate::error::Error;
use crate::refs;
use crate::repo::Repo;

pub(crate) const SRC_A: &[u8] = b"one\ntwo\nthree\n";

pub(crate) struct Fx {
    pub(crate) origin_root: PathBuf,
    pub(crate) clone_root: PathBuf,
    pub(crate) origin: Repo,
}

impl Fx {
    /// An origin on `main` at one commit, with `extra` written into that first
    /// commit by the caller-supplied closure.
    pub(crate) fn origin(tag: &str, extra: impl FnOnce(&Path)) -> Fx {
        let pid = std::process::id();
        let base = std::env::temp_dir();
        let origin_root = base.join(format!("scl-p37c-{tag}-origin-{pid}"));
        let clone_root = base.join(format!("scl-p37c-{tag}-clone-{pid}"));
        for r in [&origin_root, &clone_root] {
            let _ = std::fs::remove_dir_all(r);
        }
        for d in ["src", "docs/api", "lib"] {
            std::fs::create_dir_all(origin_root.join(d)).unwrap();
        }
        let origin = Repo::init(&origin_root).unwrap();
        std::fs::write(origin_root.join("src/a.txt"), SRC_A).unwrap();
        std::fs::write(origin_root.join("docs/a.md"), b"a\n").unwrap();
        std::fs::write(origin_root.join("docs/b.md"), b"b\n").unwrap();
        std::fs::write(origin_root.join("docs/api/guide.md"), b"g\n").unwrap();
        std::fs::write(origin_root.join("lib/x.txt"), b"x\n").unwrap();
        extra(&origin_root);
        origin.commit("t", "c1").unwrap();
        Fx {
            origin_root,
            clone_root,
            origin,
        }
    }

    /// Cut `name` from the origin's `main`, write `files` on it, commit, and
    /// return to `main`. Returns the new tip.
    pub(crate) fn origin_branch(&self, name: &str, files: &[(&str, &[u8])]) -> ObjectId {
        self.origin.branch(name).unwrap();
        self.origin.switch(name).unwrap();
        for (p, bytes) in files {
            std::fs::write(self.origin_root.join(p), bytes).unwrap();
        }
        let tip = self.origin.commit("t", &format!("edit on {name}")).unwrap();
        self.origin.switch("main").unwrap();
        tip
    }

    /// A `--filter src/` clone, lazy or not, that has fetched every origin branch.
    pub(crate) fn clone(&self, lazy: bool) -> Repo {
        let clone = Repo::clone_url_filtered(
            self.origin_root.to_str().unwrap(),
            &self.clone_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();
        crate::promisor::set_lazy(clone.layout(), lazy).unwrap();
        clone.fetch("origin").unwrap();
        clone
    }

    pub(crate) fn cleanup(self) {
        drop(self.origin);
        for r in [&self.origin_root, &self.clone_root] {
            if r.exists() {
                std::fs::remove_dir_all(r).unwrap();
            }
            assert!(!r.exists(), "fixture {} must be removed", r.display());
        }
    }
}

pub(crate) fn has(repo: &Repo, id: &ObjectId) -> bool {
    repo.vfs().store().lock().unwrap().contains(id)
}

pub(crate) fn blob_id(bytes: &[u8]) -> ObjectId {
    Object::blob(bytes.to_vec()).id()
}

/// The tree id of directory `name` directly under `snap`'s root.
pub(crate) fn dir_id(repo: &Repo, snap: &ObjectId, name: &str) -> ObjectId {
    let arc = repo.vfs().store();
    let mut s = arc.lock().unwrap();
    let root = s.get_snapshot(snap).unwrap().root;
    s.get_tree(&root).unwrap().get(name).unwrap().id
}

/// Commit an edit to `src/a.txt` on the clone's `main`.
pub(crate) fn clone_edit_src(fx: &Fx, clone: &Repo, bytes: &[u8]) {
    std::fs::write(fx.clone_root.join("src/a.txt"), bytes).unwrap();
    clone.commit("t", "ours").unwrap();
}

/// Disjoint edits merge without reading, or fetching, the other side's region.
/// The clone is not lazy, so a merge that needed the network could not succeed.
#[test]
fn disjoint_merge_carries_the_other_sides_subtree_without_a_fetch() {
    let fx = Fx::origin("carry", |_| {});
    let b1 = fx.origin_branch("b1", &[("docs/api/guide.md", b"g changed\n")]);
    let theirs_docs = dir_id(&fx.origin, &b1, "docs");
    let clone = fx.clone(false);
    assert!(
        !has(&clone, &theirs_docs),
        "premise: the docs tree is a gap"
    );

    clone_edit_src(&fx, &clone, b"one\nTWO\nthree\n");
    let ours = refs::read_branch_tip(clone.layout(), "main").unwrap();
    let (merged, _) = clone.merge_with_identity("origin/b1", "t", None).unwrap();

    let snap = clone.snapshot(&merged).unwrap();
    assert_eq!(snap.parents.len(), 2);
    assert_eq!(Some(snap.parents[0]), ours);
    assert_eq!(
        dir_id(&clone, &merged, "docs"),
        theirs_docs,
        "their docs tree is carried by id"
    );
    assert!(!has(&clone, &theirs_docs), "and never read or fetched");
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        b"one\nTWO\nthree\n"
    );
    assert!(!fx.clone_root.join("docs").exists());
    assert!(!clone.merge_in_progress());
    // The merged snapshot references a subtree the store does not hold: gc and
    // push must walk what is present and cope (ADR-0048).
    clone.gc(std::time::Duration::from_secs(0)).unwrap();
    assert!(has(&clone, &merged), "gc keeps the merge");
    assert!(!has(&clone, &theirs_docs), "and does not invent the gap");
    drop(clone);
    fx.cleanup();
}

/// A region both sides changed is outside the view: a lazy clone fetches it by
/// id (trees only, the blobs are decided by id) and a non-lazy one is refused
/// before it writes anything.
#[test]
fn differing_region_outside_the_view_fills_when_lazy_and_is_refused_otherwise() {
    let fx = Fx::origin("fill", |_| {});
    let b1 = fx.origin_branch("b1", &[("docs/a.md", b"a1\n")]);
    let b2 = fx.origin_branch("b2", &[("docs/b.md", b"b2\n")]);
    let clone = fx.clone(false);
    clone.merge("origin/b1", "t").unwrap(); // fast-forward
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        Some(b1)
    );

    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();
    let err = clone.merge("origin/b2", "t").unwrap_err();
    assert!(
        matches!(&err, Error::GapOutsideFilter(p) if p == "docs"),
        "got {err:?}"
    );
    assert!(err.to_string().contains("sc backfill docs"), "{err}");
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before,
        "refused before any write"
    );
    assert!(!clone.merge_in_progress());
    assert!(!fx.clone_root.join("docs").exists());

    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    let (merged, _) = clone.merge_with_identity("origin/b2", "t", None).unwrap();
    let snap = clone.snapshot(&merged).unwrap();
    assert_eq!(snap.parents, vec![b1, b2]);
    // The differing region was read: its trees and the two changed blobs
    // arrived. The untouched `docs/api` subtree is identical on all three sides,
    // so it was carried and never fetched. Nothing is on disk: docs/ is outside
    // the view.
    assert!(has(&clone, &blob_id(b"a1\n")));
    assert!(has(&clone, &blob_id(b"b2\n")));
    let api = dir_id(&clone, &b1, "docs");
    let api = {
        let arc = clone.vfs().store();
        let mut s = arc.lock().unwrap();
        s.get_tree(&api).unwrap().get("api").unwrap().id
    };
    assert!(!has(&clone, &api), "the identical subtree stays a gap");
    assert!(!fx.clone_root.join("docs").exists());
    let docs = dir_id(&clone, &merged, "docs");
    let arc = clone.vfs().store();
    let mut s = arc.lock().unwrap();
    let docs = s.get_tree(&docs).unwrap();
    assert_eq!(docs.get("a.md").unwrap().id, blob_id(b"a1\n"));
    assert_eq!(docs.get("b.md").unwrap().id, blob_id(b"b2\n"));
    assert_eq!(docs.get("api").unwrap().id, api);
    drop(s);
    drop(clone);
    fx.cleanup();
}

/// The same edits as the clone's conflicting merge, done on a full repo: the
/// origin commits `ours` on a side branch and merges `theirs` into it. The
/// result is what a partial clone's completed merge must equal, by tree id.
fn full_merge_root(
    fx: &Fx,
    theirs: &str,
    ours_edit: &[(&str, &[u8])],
    resolve: &[&str],
) -> ObjectId {
    fx.origin.branch("expect").unwrap();
    fx.origin.switch("expect").unwrap();
    for (p, bytes) in ours_edit {
        std::fs::write(fx.origin_root.join(p), bytes).unwrap();
    }
    fx.origin.commit("t", "ours").unwrap();
    assert!(matches!(
        fx.origin.merge(theirs, "t").unwrap_err(),
        Error::MergeConflicts(_)
    ));
    for p in resolve {
        fx.origin
            .resolve_path(p, crate::conflicts::ResolveSide::Ours, None)
            .unwrap();
    }
    let id = fx.origin.commit("t", "merge").unwrap();
    let root = fx.origin.snapshot(&id).unwrap().root;
    fx.origin.switch("main").unwrap();
    root
}

/// A conflict inside the view is marked on disk; the subtree only theirs
/// changed is carried by id and never fetched, on a clone that cannot fetch.
/// Resolving and committing completes the merge, and the result is the tree a
/// full clone produces from the same edits (ADR-0049 decision 8).
#[test]
fn a_conflict_in_the_view_completes_with_the_carried_subtree_grafted_from_the_decided_root() {
    let fx = Fx::origin("conflict", |_| {});
    let b1 = fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", b"ONE\ntwo\nthree\n"),
            ("docs/api/guide.md", b"g changed\n"),
        ],
    );
    let theirs_docs = dir_id(&fx.origin, &b1, "docs");
    let expect = full_merge_root(
        &fx,
        "b1",
        &[("src/a.txt", b"uno\ntwo\nthree\n")],
        &["src/a.txt"],
    );
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"uno\ntwo\nthree\n");
    let ours = refs::read_branch_tip(clone.layout(), "main").unwrap();
    assert!(!has(&clone, &theirs_docs), "premise: theirs' docs is a gap");

    let err = clone.merge("origin/b1", "t").unwrap_err();
    assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
    assert!(clone.merge_in_progress());
    assert_eq!(clone.active_conflicts().unwrap(), vec!["src/a.txt"]);
    let marked = std::fs::read_to_string(fx.clone_root.join("src/a.txt")).unwrap();
    assert!(marked.contains("<<<<<<<"), "markers on disk: {marked}");
    assert!(!fx.clone_root.join("docs").exists());
    assert!(!has(&clone, &theirs_docs), "carried, never fetched");
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        ours,
        "no ref moved"
    );

    // `sc conflicts` / `sc resolve` look a path up by descending it.
    let v = clone.conflict_versions("src/a.txt", None).unwrap();
    assert!(matches!(&v.ours, crate::conflicts::Side::Present(b) if b == b"uno\ntwo\nthree\n"));
    assert!(matches!(&v.theirs, crate::conflicts::Side::Present(b) if b == b"ONE\ntwo\nthree\n"));
    assert!(matches!(&v.base, crate::conflicts::Side::Present(b) if b == SRC_A));
    // A path under a gap is a gap error, never an absent side.
    let gap = clone
        .conflict_versions("docs/api/guide.md", None)
        .unwrap_err();
    assert!(matches!(gap, Error::GapOutsideFilter(_)), "got {gap:?}");

    clone
        .resolve_path("src/a.txt", crate::conflicts::ResolveSide::Ours, None)
        .unwrap();
    let merged = clone.commit("t", "merge").unwrap();
    assert!(!clone.merge_in_progress());
    let snap = clone.snapshot(&merged).unwrap();
    assert_eq!(snap.parents.len(), 2);
    assert_eq!(Some(snap.parents[0]), ours);
    assert_eq!(snap.root, expect, "same tree as the full merge");
    assert_eq!(dir_id(&clone, &merged, "docs"), theirs_docs);
    assert!(!has(&clone, &theirs_docs), "and still never fetched");
    clone.gc(std::time::Duration::from_secs(0)).unwrap();
    assert!(has(&clone, &merged));
    drop(clone);
    fx.cleanup();
}

/// A stopped merge on a lazy clone can be widened past its filter: the carried
/// subtree that comes into view is filled by id, laid out from the decided
/// root, and the completion equals the full merge (#224). A clone that cannot
/// fetch refuses the widen with the gap error and changes nothing.
#[test]
fn widening_a_stopped_partial_merge_fills_and_lays_out_the_carried_subtree() {
    let fx = Fx::origin("widen-stopped", |_| {});
    fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", b"ONE\ntwo\nthree\n"),
            ("docs/a.md", b"a changed\n"),
        ],
    );
    let expect = full_merge_root(
        &fx,
        "b1",
        &[("src/a.txt", b"uno\ntwo\nthree\n")],
        &["src/a.txt"],
    );
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"uno\ntwo\nthree\n");
    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    let wide = ["src/".to_string(), "docs/".to_string()];
    // Sideways and narrowing keep the old refusal; a widen past the filter on
    // a clone that cannot fetch is the gap error, with nothing changed.
    assert!(matches!(
        clone.set_sparse(&["docs/".to_string()], None),
        Err(Error::MergeInProgress)
    ));
    assert!(matches!(
        clone.set_sparse(&wide, None),
        Err(Error::GapOutsideFilter(_))
    ));
    assert_eq!(
        clone.sparse_spec().unwrap().prefixes(),
        ["src/".to_string()]
    );
    assert!(!fx.clone_root.join("docs").exists());

    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.set_sparse(&wide, None).unwrap();
    assert_eq!(
        std::fs::read(fx.clone_root.join("docs/a.md")).unwrap(),
        b"a changed\n",
        "theirs' content, from the decided root"
    );
    assert!(std::fs::read_to_string(fx.clone_root.join("src/a.txt"))
        .unwrap()
        .contains("<<<<<<<"));
    clone
        .resolve_path("src/a.txt", crate::conflicts::ResolveSide::Ours, None)
        .unwrap();
    let merged = clone.commit("t", "merge").unwrap();
    assert_eq!(clone.snapshot(&merged).unwrap().root, expect);
    assert!(clone.status().unwrap().modified.is_empty());
    drop(clone);
    fx.cleanup();
}

/// Aborting restores ours and removes the markers; the carried subtree was
/// never on disk and the ref never moved.
#[test]
fn aborting_a_partial_conflict_restores_ours() {
    let fx = Fx::origin("abort", |_| {});
    fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", b"ONE\ntwo\nthree\n"),
            ("docs/api/guide.md", b"g changed\n"),
        ],
    );
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"uno\ntwo\nthree\n");
    let ours = refs::read_branch_tip(clone.layout(), "main").unwrap();
    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    clone.merge_abort().unwrap();
    assert!(!clone.merge_in_progress());
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        b"uno\ntwo\nthree\n"
    );
    assert!(!fx.clone_root.join("docs").exists());
    assert_eq!(refs::read_branch_tip(clone.layout(), "main").unwrap(), ours);
    assert!(clone.status().unwrap().modified.is_empty());
    drop(clone);
    fx.cleanup();
}

/// Abort checks the view before it removes anything: when ours' view is
/// missing an object, it fails with `GapInView` and the conflicted state, the
/// markers and the sidecar are all still there to retry.
#[test]
fn an_abort_that_hits_a_view_gap_changes_nothing() {
    let fx = Fx::origin("abort-gap", |_| {});
    fx.origin_branch("b1", &[("src/a.txt", b"\xff\xfeTHEIRS\n")]);
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"\xff\xfeOURS\n");
    let ours = refs::read_branch_tip(clone.layout(), "main")
        .unwrap()
        .unwrap();
    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    let sidecar = fx.clone_root.join("src/a.txt.theirs");
    assert!(sidecar.exists(), "a binary conflict writes a sidecar");

    let src = dir_id(&clone, &ours, "src");
    clone.vfs().store().lock().unwrap().delete(&src).unwrap();
    let err = clone.merge_abort().unwrap_err();
    assert!(matches!(err, Error::GapInView { .. }), "got {err:?}");
    assert!(clone.merge_in_progress(), "the merge is still open");
    assert!(sidecar.exists(), "the sidecar is still there");
    drop(clone);
    fx.cleanup();
}

/// A file the user tracks under the name of a sidecar (`a.txt.theirs`) is not
/// this system's scratch: abort restores it and must not delete it.
#[test]
fn abort_keeps_a_tracked_file_that_is_named_like_a_sidecar() {
    let fx = Fx::origin("abort-tracked", |root| {
        std::fs::write(root.join("src/a.txt.theirs"), b"mine\n").unwrap();
    });
    fx.origin_branch("b1", &[("src/a.txt", b"ONE\ntwo\nthree\n")]);
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"uno\ntwo\nthree\n");
    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    clone.merge_abort().unwrap();
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt.theirs")).unwrap(),
        b"mine\n",
        "the tracked file survives the abort"
    );
    drop(clone);
    fx.cleanup();
}

/// A conflict outside the view is refused before any write, with the widen
/// hint; nothing is marked and no state is recorded.
#[test]
fn a_conflict_outside_the_view_is_refused_before_any_write() {
    let fx = Fx::origin("conflict-out", |_| {});
    fx.origin_branch("b1", &[("docs/a.md", b"a1\n")]);
    fx.origin_branch("b2", &[("docs/a.md", b"a2\n")]);
    let clone = fx.clone(true);
    clone.merge("origin/b1", "t").unwrap(); // fast-forward
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();

    let err = clone.merge("origin/b2", "t").unwrap_err();
    assert!(
        matches!(&err, Error::InvalidArgument(m) if m.contains("outside your sparse checkout")),
        "got {err:?}"
    );
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );
    assert!(!clone.merge_in_progress());
    assert!(!fx.clone_root.join("docs").exists());
    drop(clone);
    fx.cleanup();
}

/// An origin whose `vault/` is protected for `pk` (rule plus ciphertext).
pub(crate) fn protected_origin(tag: &str, pk: &scl_crypto::PublicKey) -> Fx {
    let fx = Fx::origin(tag, |root| {
        std::fs::create_dir_all(root.join("vault")).unwrap();
        std::fs::write(root.join("vault/s.txt"), b"l1\nl2\nl3\n").unwrap();
    });
    fx.origin
        .protect("vault/", std::slice::from_ref(pk), None)
        .unwrap();
    fx
}

/// A protected subtree no side touched is carried, so its blobs were never
/// enumerated: the merged snapshot must keep every wrap, or no recipient could
/// decrypt the carried files again (ADR-0049 decision 4).
#[test]
fn a_carried_protected_subtree_keeps_its_wraps() {
    let (sk, pk) = scl_crypto::generate_keypair();
    let fx = protected_origin("wraps", &pk);
    let base = fx.origin.head_tip().unwrap().unwrap();
    let base_snap = fx.origin.snapshot(&base).unwrap();
    assert!(!base_snap.protection.wrapped.is_empty(), "premise: sealed");
    let vault = dir_id(&fx.origin, &base, "vault");
    fx.origin_branch("b1", &[("docs/a.md", b"a1\n")]);
    let clone = fx.clone(false);
    assert!(!has(&clone, &vault), "premise: vault is outside the filter");

    clone_edit_src(&fx, &clone, b"one\nTWO\nthree\n");
    let (merged, _) = clone.merge_with_identity("origin/b1", "t", None).unwrap();
    let snap = clone.snapshot(&merged).unwrap();
    assert_eq!(dir_id(&clone, &merged, "vault"), vault, "carried by id");
    assert!(!has(&clone, &vault), "and never fetched");
    for (id, wraps) in &base_snap.protection.wrapped {
        assert_eq!(
            snap.protection.wrapped.get(id),
            Some(wraps),
            "the wraps of {id} survive the merge byte for byte"
        );
    }
    // And they still open the carried ciphertext: the recipient decrypts the
    // blob (read from the origin, which holds it) under the MERGED policy.
    let (cipher_id, _) = base_snap.protection.wrapped.iter().next().unwrap();
    let cipher = {
        let arc = fx.origin.vfs().store();
        let mut s = arc.lock().unwrap();
        match s.get(cipher_id).unwrap() {
            Object::Blob(b) => b,
            other => panic!("expected a blob, got {}", other.kind_name()),
        }
    };
    let plain =
        crate::protect::decrypt_with(&cipher, cipher_id, &[&snap.protection], &sk, "vault/s.txt")
            .unwrap();
    assert_eq!(&plain[..], b"l1\nl2\nl3\n");
    assert_eq!(snap.protection.prefixes, base_snap.protection.prefixes);
    drop(clone);
    fx.cleanup();
}

/// A keyless merge of a protected path both sides changed refuses without
/// fetching its ciphertext; with the identity it merges the content.
#[test]
fn keyless_protected_merge_refuses_before_fetching_the_ciphertext() {
    let (sk, pk) = scl_crypto::generate_keypair();
    let fx = protected_origin("identity", &pk);
    // The origin materialized `vault/s.txt` as plaintext at its protect commit;
    // each branch rewrites it, so the edit is committed under the rule.
    let b1 = fx.origin_branch("b1", &[("vault/s.txt", b"L1\nl2\nl3\n")]);
    let b2 = fx.origin_branch("b2", &[("vault/s.txt", b"l1\nl2\nL3\n")]);
    let cipher = |tip: &ObjectId| {
        let arc = fx.origin.vfs().store();
        let mut s = arc.lock().unwrap();
        let root = s.get_snapshot(tip).unwrap().root;
        let vault = s.get_tree(&root).unwrap().get("vault").unwrap().id;
        s.get_tree(&vault).unwrap().get("s.txt").unwrap().id
    };
    let (c1, c2) = (cipher(&b1), cipher(&b2));
    assert_ne!(c1, c2);

    let clone = fx.clone(true);
    clone.merge("origin/b1", "t").unwrap(); // fast-forward
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();
    let err = clone.merge("origin/b2", "t").unwrap_err();
    assert!(
        matches!(&err, Error::ProtectedMergeNeedsIdentity(p) if p == "vault/s.txt"),
        "got {err:?}"
    );
    assert!(!has(&clone, &c1), "ciphertext not fetched for a refusal");
    assert!(!has(&clone, &c2), "ciphertext not fetched for a refusal");
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );

    let (merged, _) = clone
        .merge_with_identity("origin/b2", "t", Some(&sk))
        .unwrap();
    let snap = clone.snapshot(&merged).unwrap();
    let arc = clone.vfs().store();
    let mut s = arc.lock().unwrap();
    let vault = s.get_tree(&snap.root).unwrap().get("vault").unwrap().id;
    let entry = s.get_tree(&vault).unwrap().get("s.txt").unwrap().clone();
    assert_ne!(entry.perms & scl_core::PROTECTED, 0, "sealed again");
    assert!(
        snap.protection.wrapped.contains_key(&entry.id),
        "with fresh wraps for the merged content"
    );
    // The merged plaintext reaches neither the store nor the disk; the sealed
    // blob decrypts for the recipient to the clean three-way result.
    assert!(
        !s.contains(&blob_id(b"L1\nl2\nL3\n")),
        "no plaintext in the CAS"
    );
    let sealed = match s.get(&entry.id).unwrap() {
        Object::Blob(b) => b,
        other => panic!("expected a blob, got {}", other.kind_name()),
    };
    let plain =
        crate::protect::decrypt_with(&sealed, &entry.id, &[&snap.protection], &sk, "vault/s.txt")
            .unwrap();
    assert_eq!(&plain[..], b"L1\nl2\nL3\n");
    assert!(!fx.clone_root.join("vault").exists(), "outside the view");
    drop(s);
    drop(clone);
    fx.cleanup();
}

/// The merged tree carries a subtree that is absent inside the sparse view:
/// the view's closure is filled before anything is written, on a lazy clone,
/// and a non-lazy one fails with the view-gap error and changes nothing.
#[test]
fn a_carried_subtree_inside_the_view_is_filled_before_materializing() {
    let fx = Fx::origin("view", |_| {});
    fx.origin_branch("b1", &[("docs/api/guide.md", b"g changed\n")]);
    let clone = fx.clone(true);
    clone
        .set_sparse(&["src/".to_string(), "docs/".to_string()], None)
        .unwrap();
    assert!(fx.clone_root.join("docs/api/guide.md").exists());
    clone_edit_src(&fx, &clone, b"one\nTWO\nthree\n");
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();

    // Their docs subtree is carried, so it is not read, yet it lies in the view.
    crate::promisor::set_lazy(clone.layout(), false).unwrap();
    let err = clone.merge("origin/b1", "t").unwrap_err();
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
    assert!(!clone.merge_in_progress());

    crate::promisor::set_lazy(clone.layout(), true).unwrap();
    clone.merge("origin/b1", "t").unwrap();
    assert_eq!(
        std::fs::read(fx.clone_root.join("docs/api/guide.md")).unwrap(),
        b"g changed\n"
    );
    drop(clone);
    fx.cleanup();
}

/// A fill interrupted partway leaves its objects behind and nothing else; the
/// retry resumes from what is present and succeeds.
#[test]
fn an_interrupted_fill_changes_nothing_and_the_retry_succeeds() {
    let fx = Fx::origin("retry", |_| {});
    let b1 = fx.origin_branch("b1", &[("docs/a.md", b"a1\n")]);
    let b2 = fx.origin_branch("b2", &[("docs/b.md", b"b2\n")]);
    let clone = fx.clone(true);
    clone.merge("origin/b1", "t").unwrap(); // fast-forward
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();

    // Round one by hand: fetch the docs trees of both sides, then lose the origin
    // before the blobs arrive.
    let docs = [&b1, &b2].map(|tip| dir_id(&fx.origin, tip, "docs"));
    let needs: Vec<(ObjectId, String)> = docs.iter().map(|id| (*id, "docs".to_string())).collect();
    clone.needs_filler().unwrap().fill(&needs).unwrap();
    assert!(docs.iter().all(|id| has(&clone, id)), "trees arrived");
    let gone = fx.origin_root.with_extension("gone");
    std::fs::rename(&fx.origin_root, &gone).unwrap();
    let err = clone.merge("origin/b2", "t").unwrap_err();
    assert!(
        !matches!(err, Error::MergeConflicts(_) | Error::UpToDate),
        "got {err:?}"
    );
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );
    assert!(!clone.merge_in_progress());
    assert!(!fx.clone_root.join("docs").exists());
    assert!(docs.iter().all(|id| has(&clone, id)), "progress is kept");

    std::fs::rename(&gone, &fx.origin_root).unwrap();
    let (merged, _) = clone.merge_with_identity("origin/b2", "t", None).unwrap();
    assert_eq!(clone.snapshot(&merged).unwrap().parents, vec![b1, b2]);
    drop(clone);
    fx.cleanup();
}

/// A conflict in the view while a protected subtree is carried: the decided
/// root holds the subtree by id, and the completion keeps its wraps, so the
/// recipient can still decrypt it afterwards.
#[test]
fn a_carried_protected_subtree_survives_a_conflicted_merge_and_its_completion() {
    let (sk, pk) = scl_crypto::generate_keypair();
    let fx = protected_origin("conflict-wraps", &pk);
    let base = fx.origin.head_tip().unwrap().unwrap();
    let base_snap = fx.origin.snapshot(&base).unwrap();
    let vault = dir_id(&fx.origin, &base, "vault");
    fx.origin_branch("b1", &[("src/a.txt", b"ONE\ntwo\nthree\n")]);
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"uno\ntwo\nthree\n");
    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    clone
        .resolve_path("src/a.txt", crate::conflicts::ResolveSide::Theirs, None)
        .unwrap();
    let merged = clone.commit("t", "merge").unwrap();
    let snap = clone.snapshot(&merged).unwrap();
    assert_eq!(dir_id(&clone, &merged, "vault"), vault, "carried by id");
    assert!(!has(&clone, &vault), "never fetched");
    for (id, wraps) in &base_snap.protection.wrapped {
        assert_eq!(
            snap.protection.wrapped.get(id),
            Some(wraps),
            "wraps of {id}"
        );
    }
    let (cipher_id, _) = base_snap.protection.wrapped.iter().next().unwrap();
    let cipher = {
        let arc = fx.origin.vfs().store();
        let mut s = arc.lock().unwrap();
        match s.get(cipher_id).unwrap() {
            Object::Blob(b) => b,
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

/// A conflict in the view together with a clean protected merge outside it:
/// completion could not seal the outside plaintext, so the merge is refused
/// before any write and names the path.
#[test]
fn a_conflict_with_sealing_outside_the_view_is_refused_before_any_write() {
    let (sk, pk) = scl_crypto::generate_keypair();
    let fx = protected_origin("conflict-seal", &pk);
    fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", b"ONE\ntwo\nthree\n"),
            ("vault/s.txt", b"L1\nl2\nl3\n"),
        ],
    );
    fx.origin_branch(
        "b2",
        &[
            ("src/a.txt", b"uno\ntwo\nthree\n"),
            ("vault/s.txt", b"l1\nl2\nL3\n"),
        ],
    );
    let clone = fx.clone(true);
    clone.merge("origin/b1", "t").unwrap(); // fast-forward
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();
    let on_disk = std::fs::read(fx.clone_root.join("src/a.txt")).unwrap();

    let err = clone
        .merge_with_identity("origin/b2", "t", Some(&sk))
        .unwrap_err();
    assert!(
        matches!(&err, Error::InvalidArgument(m) if m.contains("vault/s.txt") && m.contains("sealing")),
        "got {err:?}"
    );
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );
    assert!(!clone.merge_in_progress());
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        on_disk
    );
    assert!(!fx.clone_root.join("vault").exists());
    drop(clone);
    fx.cleanup();
}

/// Out-of-view entries the merge READ and resolved cleanly (both sides edited
/// different `docs/` files) ride through a conflicted completion too: the
/// decided root holds enumerated entries there, not just carried subtrees, and
/// the graft must put them all back. Same tree as the full merge.
#[test]
fn a_conflict_completion_grafts_enumerated_out_of_view_entries() {
    let fx = Fx::origin("conflict-enum", |_| {});
    fx.origin_branch(
        "o",
        &[("src/a.txt", b"uno\ntwo\nthree\n"), ("docs/b.md", b"b2\n")],
    );
    fx.origin_branch(
        "b1",
        &[("src/a.txt", b"ONE\ntwo\nthree\n"), ("docs/a.md", b"a1\n")],
    );
    let expect = full_merge_root(
        &fx,
        "b1",
        &[("src/a.txt", b"uno\ntwo\nthree\n"), ("docs/b.md", b"b2\n")],
        &["src/a.txt"],
    );
    let clone = fx.clone(true);
    clone.merge("origin/o", "t").unwrap(); // fast-forward
    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    assert!(!fx.clone_root.join("docs").exists());
    clone
        .resolve_path("src/a.txt", crate::conflicts::ResolveSide::Ours, None)
        .unwrap();
    let merged = clone.commit("t", "merge").unwrap();
    assert_eq!(clone.snapshot(&merged).unwrap().root, expect);
    drop(clone);
    fx.cleanup();
}

/// A carried subtree that lies inside the view is filled before the conflict
/// is laid out: its file reaches the disk next to the markers.
#[test]
fn a_conflict_fills_a_carried_subtree_inside_the_view() {
    let fx = Fx::origin("conflict-view", |_| {});
    fx.origin_branch(
        "b1",
        &[
            ("src/a.txt", b"ONE\ntwo\nthree\n"),
            ("docs/api/guide.md", b"g changed\n"),
        ],
    );
    let clone = fx.clone(true);
    clone
        .set_sparse(&["src/".to_string(), "docs/".to_string()], None)
        .unwrap();
    clone_edit_src(&fx, &clone, b"uno\ntwo\nthree\n");
    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    assert_eq!(
        std::fs::read(fx.clone_root.join("docs/api/guide.md")).unwrap(),
        b"g changed\n",
        "the carried subtree was filled and laid out"
    );
    clone.merge_abort().unwrap();
    assert_eq!(
        std::fs::read(fx.clone_root.join("docs/api/guide.md")).unwrap(),
        b"g\n",
        "abort puts the view back"
    );
    drop(clone);
    fx.cleanup();
}

/// A protected path in the view conflicts: the markers are plaintext on disk
/// only, resolution and completion seal the result for the recipient, and no
/// plaintext reaches the store.
#[test]
fn a_protected_conflict_in_the_view_seals_at_completion() {
    let (sk, pk) = scl_crypto::generate_keypair();
    let fx = protected_origin("conflict-protected", &pk);
    fx.origin_branch("b1", &[("vault/s.txt", b"X\nl2\nl3\n")]);
    fx.origin_branch("b2", &[("vault/s.txt", b"Y\nl2\nl3\n")]);
    let clone = fx.clone(true);
    clone
        .set_sparse(&["src/".to_string(), "vault/".to_string()], Some(&sk))
        .unwrap();
    clone
        .merge_with_identity("origin/b1", "t", Some(&sk))
        .unwrap(); // fast-forward
    let err = clone
        .merge_with_identity("origin/b2", "t", Some(&sk))
        .unwrap_err();
    assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
    let marked = std::fs::read(fx.clone_root.join("vault/s.txt")).unwrap();
    assert!(String::from_utf8_lossy(&marked).contains("<<<<<<<"));
    assert!(
        !has(&clone, &blob_id(&marked)),
        "marker plaintext never reaches the store"
    );

    clone
        .resolve_path(
            "vault/s.txt",
            crate::conflicts::ResolveSide::Ours,
            Some(&sk),
        )
        .unwrap();
    let merged = clone.commit("t", "merge").unwrap();
    let snap = clone.snapshot(&merged).unwrap();
    let arc = clone.vfs().store();
    let mut s = arc.lock().unwrap();
    let vault = s.get_tree(&snap.root).unwrap().get("vault").unwrap().id;
    let entry = s.get_tree(&vault).unwrap().get("s.txt").unwrap().clone();
    assert_ne!(entry.perms & scl_core::PROTECTED, 0, "sealed again");
    let sealed = match s.get(&entry.id).unwrap() {
        Object::Blob(b) => b,
        other => panic!("expected a blob, got {}", other.kind_name()),
    };
    let plain =
        crate::protect::decrypt_with(&sealed, &entry.id, &[&snap.protection], &sk, "vault/s.txt")
            .unwrap();
    assert_eq!(&plain[..], b"X\nl2\nl3\n");
    assert!(
        !s.contains(&blob_id(b"X\nl2\nl3\n")),
        "no plaintext in the CAS"
    );
    drop(s);
    drop(clone);
    fx.cleanup();
}

/// A binary conflict writes `<path>.theirs` beside the file. When the view is
/// the file itself the sidecar does not match the spec, yet it sits beside an
/// in-view conflict: the stop writes it, abort removes it, and completion
/// leaves it out of the tree (#224).
#[test]
fn a_sidecar_beside_an_in_view_conflict_is_written_and_removed_under_a_file_exact_view() {
    let fx = Fx::origin("sidecar-exact", |_| {});
    fx.origin_branch("b1", &[("src/a.txt", b"\xff\xfeTHEIRS\n")]);
    let clone = fx.clone(false);
    clone.set_sparse(&["src/a.txt".to_string()], None).unwrap();
    clone_edit_src(&fx, &clone, b"\xff\xfeOURS\n");
    let sidecar = fx.clone_root.join("src/a.txt.theirs");

    let err = clone.merge("origin/b1", "t").unwrap_err();
    assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
    assert_eq!(std::fs::read(&sidecar).unwrap(), b"\xff\xfeTHEIRS\n");
    assert!(!fx.clone_root.join("docs").exists());
    clone.merge_abort().unwrap();
    assert!(!sidecar.exists(), "abort removes the sidecar");
    assert!(!fx.clone_root.join(".sc/CONFLICT_SIDECARS").exists());

    assert!(matches!(
        clone.merge("origin/b1", "t").unwrap_err(),
        Error::MergeConflicts(1)
    ));
    std::fs::write(fx.clone_root.join("src/a.txt"), b"\xff\xferesolved\n").unwrap();
    let merged = clone.commit("t", "merge").unwrap();
    assert!(!sidecar.exists(), "completion removes the sidecar");
    assert!(!clone.tracked_paths().unwrap().contains("src/a.txt.theirs"));
    assert_eq!(clone.snapshot(&merged).unwrap().parents.len(), 2);
    drop(clone);
    fx.cleanup();
}

/// A binary conflict's `<path>.theirs` sidecar must not overwrite a tracked
/// file of that name: the merge is refused before any write.
#[test]
fn a_sidecar_that_would_overwrite_a_tracked_file_is_refused() {
    let fx = Fx::origin("sidecar-tracked", |root| {
        std::fs::write(root.join("src/a.txt.theirs"), b"mine\n").unwrap();
    });
    fx.origin_branch("b1", &[("src/a.txt", b"\xff\xfeTHEIRS\n")]);
    let clone = fx.clone(false);
    clone_edit_src(&fx, &clone, b"\xff\xfeOURS\n");
    let before = refs::read_branch_tip(clone.layout(), "main").unwrap();
    let err = clone.merge("origin/b1", "t").unwrap_err();
    assert!(
        matches!(&err, Error::InvalidArgument(m) if m.contains("overwrite a tracked file")),
        "got {err:?}"
    );
    assert!(!clone.merge_in_progress());
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt.theirs")).unwrap(),
        b"mine\n"
    );
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        before
    );
    drop(clone);
    fx.cleanup();
}
