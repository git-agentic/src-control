//! Helpers for tests that run worker threads: a failure must end the test
//! with a diagnostic, never leave the scope or the harness waiting forever.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Stops a concurrency test from hanging: a worker that panics raises the flag
/// (and a guard built with `true` always does, on exit), so one failure
/// releases every loop instead of leaving the scope waiting on workers that
/// never see `done`.
pub(crate) struct Stop<'a>(pub &'a AtomicBool, pub bool);
impl Drop for Stop<'_> {
    fn drop(&mut self) {
        if self.1 || std::thread::panicking() {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

/// Last-known step per worker, shown by [`watchdog`] when it fires.
pub(crate) type Status = Mutex<BTreeMap<String, String>>;

/// Record `what` as `who`'s current step.
pub(crate) fn note(status: &Status, who: String, what: String) {
    status.lock().unwrap().insert(who, what);
}

/// Aborts the process with each worker's last-known step if the test is still
/// running at `limit`: a worker stuck inside a call (a lock, a bucket op, a
/// barrier whose peer panicked) can not be unwound, so the hang becomes a
/// diagnosed failure. Written straight to stderr because the harness captures
/// `eprintln!` until the test ends. Raise `finished` (see [`Stop`]) to stand
/// the watchdog down.
pub(crate) fn watchdog<'a>(
    s: &'a std::thread::Scope<'a, '_>,
    finished: &'a AtomicBool,
    status: &'a Status,
    limit: Duration,
) {
    s.spawn(move || {
        let start = std::time::Instant::now();
        while !finished.load(Ordering::SeqCst) {
            if start.elapsed() > limit {
                use std::io::Write;
                let _ = writeln!(
                    std::io::stderr(),
                    "WATCHDOG: test still running after {limit:?}; last steps: {:#?}",
                    status.lock().map(|m| m.clone()).unwrap_or_default()
                );
                std::process::abort();
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    });
}

/// The root tree of every [`fake_commit`].
pub(crate) fn empty_tree() -> scl_core::Object {
    scl_core::Object::Tree(scl_core::Tree::default())
}

/// Store a [`fake_commit`] with its root tree, so the ref rule finds it connected.
pub(crate) fn put_fake<T: crate::transport::Transport>(t: &T, commit: &scl_core::Object) {
    for o in [empty_tree(), commit.clone()] {
        t.put_object(&o.id(), &o.encode()).unwrap();
    }
}

/// A tiny snapshot over the empty tree, distinct per `tag`: a stand-in tip
/// for transport tests that move refs without building a repository. A
/// `parent` makes it a descendant, so a move to it is a fast-forward.
pub(crate) fn fake_commit(tag: &str, parent: Option<scl_core::ObjectId>) -> scl_core::Object {
    scl_core::Object::Snapshot(scl_core::Snapshot {
        root: empty_tree().id(),
        parents: parent.into_iter().collect(),
        author: "t".into(),
        timestamp: 0,
        message: tag.into(),
        secrets: Default::default(),
        protection: Default::default(),
    })
}

/// The server-side ref rule (`ref_guard`) from the outside, for any transport:
/// every refusal leaves the ref where it was, every legitimate move lands.
/// Each attempt stores the objects it needs right before `update_ref`, since a
/// refused call may discard what was staged for it.
pub(crate) fn ref_rules_hold<T: crate::transport::Transport>(t: &T) {
    use scl_core::{
        BranchManifest, EntryKind, FileMode, Object, ObjectId, SealedObj, Snapshot, Tree, TreeEntry,
    };

    let tree = |entries: &[(&str, EntryKind, ObjectId)]| {
        Object::Tree(Tree::new(
            entries
                .iter()
                .map(|(name, kind, id)| TreeEntry {
                    name: name.to_string(),
                    kind: *kind,
                    id: *id,
                    mode: FileMode::FILE,
                    perms: 0,
                })
                .collect(),
        ))
    };
    let snap = |root: ObjectId, parents: &[ObjectId], msg: &str| {
        Object::Snapshot(Snapshot {
            root,
            parents: parents.to_vec(),
            author: "t".into(),
            timestamp: 0,
            message: msg.into(),
            secrets: Default::default(),
            protection: Default::default(),
        })
    };
    let manifest = |base: ObjectId, prev: Option<ObjectId>, closure: &[ObjectId]| {
        Object::Manifest(BranchManifest {
            base,
            prev,
            anchors: vec![],
            closure: closure.to_vec(),
            index_ct: vec![1],
            kek_wraps: vec![],
        })
    };
    // Store `objs` and `new`, then try to move `branch` from `old` to `new`.
    let mv = |objs: &[&Object], branch: &str, new: &Object, old: Option<&Object>| {
        for o in objs.iter().copied().chain([new]) {
            t.put_object(&o.id(), &o.encode()).unwrap();
        }
        t.update_ref(branch, &new.id(), old.map(|o| o.id()).as_ref())
    };
    let tip_of = |branch: &str| {
        t.list_refs()
            .unwrap()
            .into_iter()
            .find(|(b, _)| b == branch)
            .map(|(_, id)| id)
    };

    let (b1, b2) = (Object::blob(b"one".to_vec()), Object::blob(b"two".to_vec()));
    let absent_blob = Object::blob(b"never stored".to_vec());
    let absent_tree = tree(&[("x", EntryKind::Blob, absent_blob.id())]);
    // Stored by some cases, but never connected: its root tree is absent.
    let absent_snap = snap(absent_tree.id(), &[], "unconnected");
    // An id nothing ever stores.
    let ghost = ObjectId::of(b"ghost");
    let dir1 = tree(&[("f", EntryKind::Blob, b1.id())]);
    let root1 = tree(&[("a", EntryKind::Tree, dir1.id())]);
    let c1 = snap(root1.id(), &[], "c1");
    let dir2 = tree(&[
        ("f", EntryKind::Blob, b1.id()),
        ("g", EntryKind::Blob, b2.id()),
    ]);
    let root2 = tree(&[("a", EntryKind::Tree, dir2.id())]);
    let c2 = snap(root2.id(), &[c1.id()], "c2");

    // Creation, then a fast-forward that changes one subtree.
    mv(&[&b1, &dir1, &root1], "main", &c1, None).unwrap();
    mv(&[&b2, &dir2, &root2], "main", &c2, Some(&c1)).unwrap();
    assert_eq!(tip_of("main"), Some(c2.id()));

    // Public branch: each of these is refused and `main` does not move.
    let dir3 = tree(&[
        ("f", EntryKind::Blob, b1.id()),
        ("g", EntryKind::Blob, b2.id()),
        ("h", EntryKind::Blob, absent_blob.id()),
    ]);
    let root3 = tree(&[("a", EntryKind::Tree, dir3.id())]);
    let sealed = Object::Sealed(SealedObj {
        payload: std::sync::Arc::from(b"ciphertext".to_vec().into_boxed_slice()),
    });
    let m_over_main = manifest(c2.id(), None, &[]);
    let cases: Vec<(&str, Vec<&Object>, Object)> = vec![
        // a fast-forward whose changed subtree names an absent blob
        (
            "absent nested blob",
            vec![&dir3, &root3],
            snap(root3.id(), &[c2.id()], "x1"),
        ),
        // an absent root tree
        (
            "absent root",
            vec![],
            snap(absent_tree.id(), &[c2.id()], "x2"),
        ),
        // the current tip is a parent, but so is something absent
        (
            "absent second parent",
            vec![&root2],
            snap(root2.id(), &[c2.id(), ghost], "x3"),
        ),
        // ... or something that is not a snapshot
        (
            "blob as second parent",
            vec![&root2, &b1],
            snap(root2.id(), &[c2.id(), b1.id()], "x4"),
        ),
        // a new tip whose parent is a manifest
        (
            "manifest as parent",
            vec![&root2, &m_over_main],
            snap(root2.id(), &[c2.id(), m_over_main.id()], "x5"),
        ),
        // rewind, and a sideways move to an unrelated history
        ("rewind", vec![], c1.clone()),
        ("sideways", vec![&root1], snap(root1.id(), &[], "unrelated")),
        // not a snapshot at all
        ("blob target", vec![], b1.clone()),
        // public `main` turned into a private branch over its own tip
        ("kind flip", vec![], m_over_main.clone()),
    ];
    for (what, objs, new) in cases {
        let r = mv(&objs, "main", &new, Some(&c2));
        assert!(r.is_err(), "{what} must be refused");
        assert_eq!(tip_of("main"), Some(c2.id()), "{what} moved the ref");
    }
    // An entry id reused across kinds. `dirx` is a tree whose own file is
    // absent; naming it as a file in one entry must not make the tree entry
    // that follows look verified, and a tree entry naming a blob is wrong too.
    let dirx = tree(&[("gone", EntryKind::Blob, absent_blob.id())]);
    let reuse = tree(&[
        ("a", EntryKind::Blob, dirx.id()),
        ("b", EntryKind::Tree, dirx.id()),
    ]);
    let tree_over_blob = tree(&[("a", EntryKind::Tree, b1.id())]);
    let file_over_tree = tree(&[("a", EntryKind::Blob, dir1.id())]);
    for (what, objs, root) in [
        ("file and tree entry share an id", vec![&dirx], &reuse),
        ("tree entry names a blob", vec![&b1], &tree_over_blob),
        ("file entry names a tree", vec![&dir1, &b1], &file_over_tree),
    ] {
        let c = snap(root.id(), &[c2.id()], what);
        let mut objs = objs;
        objs.push(root);
        assert!(mv(&objs, "main", &c, Some(&c2)).is_err(), "{what}");
        assert_eq!(tip_of("main"), Some(c2.id()), "{what} moved the ref");
    }
    // The kind rule answers for the flip itself (the ancestry rules would
    // refuse it too, but as a different error).
    let flip = mv(&[], "main", &m_over_main, Some(&c2)).unwrap_err();
    assert!(flip.to_string().contains("change kind"), "{flip}");
    assert!(t.update_ref("main", &ghost, Some(&c2.id())).is_err());
    // New branches: an unconnected commit, and one with an absent parent.
    assert!(mv(&[], "fresh", &absent_snap, None).is_err());
    assert!(mv(&[&root2], "fresh", &snap(root2.id(), &[ghost], "y"), None).is_err());
    assert_eq!(tip_of("fresh"), None);

    // Private branch: a manifest's `prev` chain is its ancestry.
    let m1 = manifest(c1.id(), None, &[sealed.id()]);
    let m2 = manifest(c1.id(), Some(m1.id()), &[sealed.id()]);
    let cases: Vec<(&str, Vec<&Object>, Object, Option<&Object>)> = vec![
        (
            "absent closure entry",
            vec![],
            manifest(c1.id(), None, &[absent_blob.id()]),
            None,
        ),
        ("absent base", vec![], manifest(ghost, None, &[]), None),
    ];
    for (what, objs, new, old) in cases {
        assert!(mv(&objs, "priv", &new, old).is_err(), "{what}");
        assert_eq!(tip_of("priv"), None, "{what} created the ref");
    }
    mv(&[&sealed], "priv", &m1, None).unwrap();
    mv(&[&sealed], "priv", &m2, Some(&m1)).unwrap();
    let cases: Vec<(&str, Object)> = vec![
        ("manifest rewind", m1.clone()),
        ("manifest sideways", manifest(c2.id(), None, &[sealed.id()])),
        (
            "manifest absent closure",
            manifest(c1.id(), Some(m2.id()), &[absent_blob.id()]),
        ),
        ("manifest absent base", manifest(ghost, Some(m2.id()), &[])),
        ("snapshot over manifest", snap(root2.id(), &[m2.id()], "z")),
        ("snapshot target", c2.clone()),
    ];
    for (what, new) in cases {
        assert!(
            mv(&[&sealed, &root2], "priv", &new, Some(&m2)).is_err(),
            "{what} must be refused"
        );
        assert_eq!(tip_of("priv"), Some(m2.id()), "{what} moved the ref");
    }
    let m3 = manifest(c1.id(), Some(m2.id()), &[sealed.id()]);
    mv(&[&sealed], "priv", &m3, Some(&m2)).unwrap();
}

/// Windows: assert `path` carries exactly one explicit, non-inherited
/// full-control ACE for the current user, read back with `icacls`.
#[cfg(windows)]
pub(crate) fn assert_owner_only_dacl(path: &std::path::Path) {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success(), "icacls failed: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let acl = text.replace(path.to_str().unwrap(), "");
    let aces: Vec<&str> = acl.lines().filter(|l| l.contains(":(")).collect();
    let user = std::env::var("USERNAME").unwrap().to_lowercase();
    assert_eq!(aces.len(), 1, "exactly one ACE expected:\n{text}");
    let ace = aces[0].trim().to_lowercase();
    assert!(
        ace.contains(&format!("\\{user}:(")) && ace.contains("(f)") && !ace.contains("(i)"),
        "ACE must be an explicit full-control grant to {user}:\n{text}"
    );
}
