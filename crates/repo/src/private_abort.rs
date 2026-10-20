//! Aborting or completing a stopped merge into a private branch (#246). The
//! branch tip is a manifest, so abort restores through the private checkout
//! path and needs an identity; the stop's `<path>.theirs` sidecars are
//! recorded like the public stop's, so completion leaves them out of the
//! sealed tree and both endings remove them.

use std::path::{Path, PathBuf};

use scl_core::Object;
use scl_crypto::SecretKey;

use crate::error::Error;
use crate::repo::Repo;

const BIN_PRIVATE: &[u8] = &[0, 1, 2, 0xff];
const BIN_PUBLIC: &[u8] = &[0, 9, 8, 0xfe];

fn put(root: &Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap()
}

struct Fixture {
    root: PathBuf,
    repo: Repo,
    sk: SecretKey,
}

impl Fixture {
    fn id(&self) -> Option<&SecretKey> {
        Some(&self.sk)
    }
    fn tip(&self) -> scl_core::ObjectId {
        self.repo.head_private().unwrap().unwrap().1
    }
    fn paths(&self) -> Vec<String> {
        let (b, mid, m) = self.repo.head_private().unwrap().unwrap();
        let ctx = self.repo.open_private(&b, mid, m, self.id()).unwrap();
        let store_arc = self.repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let tip = ctx.inner_tip().unwrap();
        let root = self
            .repo
            .get_inner_snapshot(&mut store, &ctx, &tip)
            .unwrap()
            .root;
        self.repo
            .inner_tree_files(&mut store, &ctx, root)
            .unwrap()
            .into_keys()
            .collect()
    }
    fn assert_no_state(&self) {
        assert!(!crate::merge_state::in_progress(self.repo.layout()));
        for f in [
            "MERGE_HEAD",
            "MERGE_CONFLICTS",
            "CONFLICT_PLAINTEXT",
            "CONFLICT_SIDECARS",
        ] {
            assert!(!self.root.join(".sc").join(f).exists(), "{f} left behind");
        }
    }
    fn finish(self) {
        drop(self.repo);
        std::fs::remove_dir_all(&self.root).unwrap();
        assert!(!self.root.exists(), "test dir left behind");
    }
}

/// `main` holds a.txt, bin.dat and src/lib.rs; private `fix` edits a.txt (text),
/// bin.dat (binary), src/lib.rs (only with `view`) and adds p.txt; `main` then edits a.txt, bin.dat
/// and src/lib.rs and adds m.txt. `text` and `bin` pick which of the two files
/// both sides edit (a conflict); the other is left alone on the private side.
/// With `view`, the sparse spec `src/` is in force.
fn fixture(tag: &str, text: bool, bin: bool, view: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!("scl-priv-abort-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repo::init(&root).unwrap();
    put(&root, "a.txt", b"base\n");
    put(&root, "bin.dat", &[0, 0, 0]);
    put(&root, "src/lib.rs", b"base\n");
    repo.commit("t", "base").unwrap();
    let (sk, _) = scl_crypto::generate_keypair();
    repo.branch_private("fix", &sk, &[], &[]).unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    if text {
        put(&root, "a.txt", b"private edit\n");
    }
    if bin {
        put(&root, "bin.dat", BIN_PRIVATE);
    }
    put(&root, "p.txt", b"private only\n");
    if view {
        put(&root, "src/lib.rs", b"private\n");
    }
    repo.commit_private("alice", "private work", Some(&sk))
        .unwrap();
    repo.switch_with_identity("main", Some(&sk)).unwrap();
    put(&root, "a.txt", b"public edit\n");
    put(&root, "bin.dat", BIN_PUBLIC);
    put(&root, "src/lib.rs", b"public\n");
    put(&root, "m.txt", b"public only\n");
    repo.commit("t", "main moves").unwrap();
    if view {
        repo.set_sparse(&["src/".to_string()], Some(&sk)).unwrap();
    }
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    Fixture { root, repo, sk }
}

/// No non-sealed object may hold `needle`: abort leaves nothing at rest
/// outside the sealed manifest.
fn assert_opaque(repo: &Repo, needle: &[u8]) {
    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();
    for id in store.all_ids().unwrap() {
        let obj = store.get(&id).unwrap();
        if matches!(obj, Object::Sealed(_) | Object::Manifest(_)) {
            continue;
        }
        assert!(
            !obj.encode().windows(needle.len()).any(|w| w == needle),
            "plaintext leaked into a public {} object",
            obj.kind_name()
        );
    }
}

#[test]
fn abort_after_a_text_conflict_restores_the_private_tip() {
    let f = fixture("text", true, false, false);
    let before = f.tip();
    assert!(matches!(
        f.repo.merge_into_private("main", "alice", f.id()),
        Err(Error::MergeConflicts(1))
    ));
    assert!(read(&f.root, "a.txt").contains("<<<<<<<"));
    assert!(f.root.join("m.txt").exists(), "the stop lays theirs' adds");
    f.repo.merge_abort_with_identity(f.id()).unwrap();
    f.assert_no_state();
    assert_eq!(f.tip(), before, "abort must not move the ref");
    assert_eq!(read(&f.root, "a.txt"), "private edit\n");
    assert_eq!(read(&f.root, "src/lib.rs"), "base\n");
    assert_eq!(read(&f.root, "p.txt"), "private only\n");
    assert!(!f.root.join("m.txt").exists(), "theirs' add survived abort");
    let s = f.repo.status_private(f.id()).unwrap();
    assert!(s.added.is_empty() && s.modified.is_empty() && s.deleted.is_empty());
    assert_opaque(&f.repo, b"private edit");
    f.finish();
}

#[test]
fn abort_after_a_binary_conflict_removes_the_sidecar() {
    let f = fixture("bin", false, true, false);
    let before = f.tip();
    assert!(matches!(
        f.repo.merge_into_private("main", "alice", f.id()),
        Err(Error::MergeConflicts(1))
    ));
    assert_eq!(
        std::fs::read(f.root.join("bin.dat.theirs")).unwrap(),
        BIN_PUBLIC
    );
    assert_eq!(
        crate::conflict_plaintext::read_sidecars(f.repo.layout())
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["bin.dat.theirs"],
        "the stop must record its sidecar"
    );
    f.repo.merge_abort_with_identity(f.id()).unwrap();
    f.assert_no_state();
    assert!(!f.root.join("bin.dat.theirs").exists());
    assert_eq!(std::fs::read(f.root.join("bin.dat")).unwrap(), BIN_PRIVATE);
    assert_eq!(f.tip(), before);
    f.finish();
}

#[test]
fn completion_leaves_the_sidecar_out_of_the_sealed_tree_and_removes_it() {
    let f = fixture("done", false, true, false);
    assert!(matches!(
        f.repo.merge_into_private("main", "alice", f.id()),
        Err(Error::MergeConflicts(1))
    ));
    assert!(f.root.join("bin.dat.theirs").exists());
    f.repo.commit_private("alice", "merge", f.id()).unwrap();
    f.assert_no_state();
    assert!(
        !f.root.join("bin.dat.theirs").exists(),
        "sidecar left on disk"
    );
    let paths = f.paths();
    assert!(
        !paths.iter().any(|p| p.ends_with(".theirs")),
        "sidecar sealed into the tree: {paths:?}"
    );
    assert!(paths.contains(&"bin.dat".to_string()));
    assert!(f.repo.status_private(f.id()).unwrap().added.is_empty());
    f.finish();
}

#[test]
fn a_tracked_theirs_file_refuses_the_stop() {
    // `bin.dat.theirs` is the user's own tracked file on both sides' history:
    // the stop must refuse to overwrite it rather than record it as scratch.
    let root = std::env::temp_dir().join(format!("scl-priv-abort-own-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repo::init(&root).unwrap();
    put(&root, "bin.dat", &[0, 0, 0]);
    repo.commit("t", "base").unwrap();
    let (sk, _) = scl_crypto::generate_keypair();
    repo.branch_private("fix", &sk, &[], &[]).unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    put(&root, "bin.dat", BIN_PRIVATE);
    put(&root, "bin.dat.theirs", b"mine\n");
    repo.commit_private("alice", "private", Some(&sk)).unwrap();
    repo.switch_with_identity("main", Some(&sk)).unwrap();
    put(&root, "bin.dat", BIN_PUBLIC);
    repo.commit("t", "public").unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    let err = repo
        .merge_into_private("main", "alice", Some(&sk))
        .unwrap_err();
    assert!(err.to_string().contains("bin.dat.theirs"), "{err}");
    assert!(!crate::merge_state::in_progress(repo.layout()));
    assert_eq!(read(&root, "bin.dat.theirs"), "mine\n");
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists(), "test dir left behind");
}

#[test]
fn an_untracked_file_at_the_sidecar_path_refuses_the_stop() {
    let f = fixture("occupied", false, true, false);
    put(&f.root, "bin.dat.theirs", b"user's own\n");
    let err = f
        .repo
        .merge_into_private("main", "alice", f.id())
        .unwrap_err();
    assert!(err.to_string().contains("bin.dat.theirs"), "{err}");
    assert!(!crate::merge_state::in_progress(f.repo.layout()));
    assert_eq!(read(&f.root, "bin.dat.theirs"), "user's own\n");
    f.finish();
}

#[test]
fn abort_under_a_sparse_spec_writes_nothing_outside_the_view() {
    let f = fixture("sparse", false, false, true);
    let before = f.tip();
    // Only src/lib.rs is in view, and both sides edited it.
    assert!(matches!(
        f.repo.merge_into_private("main", "alice", f.id()),
        Err(Error::MergeConflicts(1))
    ));
    assert!(read(&f.root, "src/lib.rs").contains("<<<<<<<"));
    f.repo.merge_abort_with_identity(f.id()).unwrap();
    f.assert_no_state();
    assert_eq!(f.tip(), before);
    assert_eq!(read(&f.root, "src/lib.rs"), "private\n");
    for outside in ["a.txt", "bin.dat", "p.txt", "m.txt"] {
        assert!(
            !f.root.join(outside).exists(),
            "{outside} written outside the view"
        );
    }
    assert!(f.repo.sparse_spec().unwrap().matches("src/lib.rs"));
    f.finish();
}

#[test]
fn abort_refuses_without_the_identity_and_keeps_the_stop_intact() {
    let f = fixture("noaccess", true, false, false);
    assert!(matches!(
        f.repo.merge_into_private("main", "alice", f.id()),
        Err(Error::MergeConflicts(1))
    ));
    let marked = read(&f.root, "a.txt");
    let (outsider, _) = scl_crypto::generate_keypair();
    for who in [None, Some(&outsider)] {
        let err = f.repo.merge_abort_with_identity(who).unwrap_err();
        assert!(matches!(err, Error::PrivateNoAccess(_)), "{err}");
        assert!(crate::merge_state::in_progress(f.repo.layout()));
        assert_eq!(read(&f.root, "a.txt"), marked, "a refused abort wrote");
    }
    // The keyless entry point is the one the public tests use.
    assert!(matches!(
        f.repo.merge_abort(),
        Err(Error::PrivateNoAccess(_))
    ));
    f.repo.merge_abort_with_identity(f.id()).unwrap();
    f.assert_no_state();
    f.finish();
}

#[test]
fn a_protected_conflict_is_recorded_aborted_and_honors_a_deletion() {
    for finish_by_delete in [false, true] {
        let root = std::env::temp_dir().join(format!(
            "scl-priv-abort-prot-{finish_by_delete}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = Repo::init(&root).unwrap();
        let (sk, pk) = scl_crypto::generate_keypair();
        put(&root, "readme.txt", b"hi\n");
        repo.commit("t", "base").unwrap();
        repo.protect("vault/", std::slice::from_ref(&pk), None)
            .unwrap();
        put(&root, "vault/key.pem", b"PEM-V1\n");
        repo.commit("t", "add protected").unwrap();
        repo.branch_private("fix", &sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&sk)).unwrap();
        put(&root, "vault/key.pem", b"PEM-PRIVATE\n");
        repo.commit_private("alice", "private", Some(&sk)).unwrap();
        repo.switch_with_identity("main", Some(&sk)).unwrap();
        put(&root, "vault/key.pem", b"PEM-PUBLIC\n");
        repo.commit("t", "public").unwrap();
        repo.switch_with_identity("fix", Some(&sk)).unwrap();
        let before = repo.head_private().unwrap().unwrap().1;
        assert!(matches!(
            repo.merge_into_private("main", "alice", Some(&sk)),
            Err(Error::MergeConflicts(1))
        ));
        assert_eq!(
            crate::conflict_plaintext::read(repo.layout())
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["vault/key.pem"],
            "the stop must record the plaintext it wrote"
        );
        if finish_by_delete {
            std::fs::remove_file(root.join("vault/key.pem")).unwrap();
            repo.commit_private("alice", "drop it", Some(&sk)).unwrap();
            let (b, mid, m) = repo.head_private().unwrap().unwrap();
            let ctx = repo.open_private(&b, mid, m, Some(&sk)).unwrap();
            let store_arc = repo.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let tip = ctx.inner_tip().unwrap();
            let r = repo
                .get_inner_snapshot(&mut store, &ctx, &tip)
                .unwrap()
                .root;
            let files = repo.inner_tree_files(&mut store, &ctx, r).unwrap();
            assert!(
                !files.contains_key("vault/key.pem"),
                "a deleted conflict file was carried back"
            );
        } else {
            repo.merge_abort_with_identity(Some(&sk)).unwrap();
            assert_eq!(read(&root, "vault/key.pem"), "PEM-PRIVATE\n");
            assert_eq!(repo.head_private().unwrap().unwrap().1, before);
            assert_opaque(&repo, b"PEM-PRIVATE");
        }
        assert!(!root.join(".sc/CONFLICT_PLAINTEXT").exists());
        assert!(!crate::merge_state::in_progress(repo.layout()));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists(), "test dir left behind");
    }
}

#[test]
fn a_decrypted_carried_protected_file_the_user_deletes_stays_deleted() {
    let root = std::env::temp_dir().join(format!("scl-priv-abort-carry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repo::init(&root).unwrap();
    let (sk, pk) = scl_crypto::generate_keypair();
    put(&root, "a.txt", b"base\n");
    repo.commit("t", "base").unwrap();
    repo.protect("vault/", std::slice::from_ref(&pk), None)
        .unwrap();
    put(&root, "vault/key.pem", b"PEM-V1\n");
    repo.commit("t", "add protected").unwrap();
    repo.branch_private("fix", &sk, &[], &[]).unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    put(&root, "a.txt", b"private\n");
    repo.commit_private("alice", "private", Some(&sk)).unwrap();
    repo.switch_with_identity("main", Some(&sk)).unwrap();
    put(&root, "a.txt", b"public\n");
    put(&root, "vault/key.pem", b"PEM-V2\n");
    repo.commit("t", "public").unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    assert!(matches!(
        repo.merge_into_private("main", "alice", Some(&sk)),
        Err(Error::MergeConflicts(1))
    ));
    // The public rotation was clean and carried: laid out decrypted.
    assert_eq!(read(&root, "vault/key.pem"), "PEM-V2\n");
    assert!(crate::conflict_plaintext::read(repo.layout())
        .unwrap()
        .contains("vault/key.pem"));
    std::fs::remove_file(root.join("vault/key.pem")).unwrap();
    put(&root, "a.txt", b"resolved\n");
    repo.commit_private("alice", "resolve", Some(&sk)).unwrap();
    let (b, mid, m) = repo.head_private().unwrap().unwrap();
    let ctx = repo.open_private(&b, mid, m, Some(&sk)).unwrap();
    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();
    let tip = ctx.inner_tip().unwrap();
    let r = repo
        .get_inner_snapshot(&mut store, &ctx, &tip)
        .unwrap()
        .root;
    assert!(!repo
        .inner_tree_files(&mut store, &ctx, r)
        .unwrap()
        .contains_key("vault/key.pem"));
    drop(store);
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists(), "test dir left behind");
}
