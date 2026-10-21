//! #237: every checkout-style write restores the recorded executable bit and
//! clears a stale one, so `read_worktree` (which reads the mode back from the
//! filesystem) round-trips EXEC and FILE through switch, merge, rebase,
//! sparse set, clone and `sc ws` checkouts.
#![cfg(unix)]

use scl_core::FileMode;
use scl_repo::{worktree, Repo};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A scratch directory removed (and checked gone) when the test ends.
struct Tmp(PathBuf);

impl std::ops::Deref for Tmp {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Tmp {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        if !std::thread::panicking() {
            assert!(!self.0.exists());
        }
    }
}

fn tmp(tag: &str) -> Tmp {
    let p = std::env::temp_dir().join(format!("scl-exec-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    Tmp(p)
}

fn put(root: &Path, rel: &str, body: &str, exec: bool) {
    let full = root.join(rel);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(&full, body).unwrap();
    let mode = if exec { 0o755 } else { 0o644 };
    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn on_disk_exec(root: &Path, rel: &str) -> bool {
    std::fs::metadata(root.join(rel))
        .unwrap()
        .permissions()
        .mode()
        & 0o111
        != 0
}

/// The mode the current tip records for `rel`.
fn committed(repo: &Repo, rel: &str) -> FileMode {
    let tip = repo.head_tip().unwrap().unwrap();
    let store = repo.vfs().store();
    let mut store = store.lock().unwrap();
    let root = store.get_snapshot(&tip).unwrap().root;
    worktree::tree_file_entries(&mut store, root).unwrap()[rel].1
}

/// Status is clean, and a follow-up commit (touching `touch`) keeps `rel` EXEC/FILE.
fn assert_round_trips(repo: &Repo, root: &Path, rel: &str, exec: bool, touch: &str) {
    assert_eq!(on_disk_exec(root, rel), exec, "{rel} on disk");
    let st = repo.status().unwrap();
    assert!(
        st.added.is_empty() && st.modified.is_empty() && st.deleted.is_empty(),
        "status not clean: {st:?}"
    );
    std::fs::write(root.join(touch), format!("touch-{}", rand_tag(repo))).unwrap();
    repo.commit("t", "touch").unwrap();
    let want = if exec { FileMode::EXEC } else { FileMode::FILE };
    assert_eq!(committed(repo, rel), want, "{rel} committed");
}

fn rand_tag(repo: &Repo) -> String {
    repo.head_tip().unwrap().unwrap().short().to_string()
}

fn base(tag: &str) -> (Repo, Tmp) {
    let root = tmp(tag);
    let repo = Repo::init(&root).unwrap();
    put(&root, "seed.txt", "seed", false);
    repo.commit("t", "seed").unwrap();
    (repo, root)
}

#[test]
fn switch_restores_exec_and_clears_it_for_plain_files() {
    let (repo, root) = base("switch");
    put(&root, "run.sh", "#!/bin/sh\n", true);
    put(&root, "data.txt", "d", false);
    repo.commit("t", "add").unwrap();
    repo.branch("plain").unwrap();
    repo.switch("plain").unwrap();
    // On `plain` the same path is an ordinary file (content differs).
    put(&root, "run.sh", "not a script\n", false);
    repo.commit("t", "demote").unwrap();

    repo.switch("main").unwrap();
    assert_round_trips(&repo, &root, "run.sh", true, "data.txt");
    assert_round_trips(&repo, &root, "data.txt", false, "seed.txt");
    // EXEC -> FILE: the stale bit is cleared on the existing file.
    repo.switch("plain").unwrap();
    assert_round_trips(&repo, &root, "run.sh", false, "data.txt");
    // And back again.
    repo.switch("main").unwrap();
    assert_round_trips(&repo, &root, "run.sh", true, "data.txt");
}

#[test]
fn merge_creates_exec_file_with_its_bit() {
    let (repo, root) = base("merge");
    repo.branch("feat").unwrap();
    repo.switch("feat").unwrap();
    put(&root, "run.sh", "#!/bin/sh\n", true);
    repo.commit("t", "script").unwrap();
    repo.switch("main").unwrap();
    put(&root, "m.txt", "m", false);
    repo.commit("t", "m").unwrap();
    assert!(!root.join("run.sh").exists());

    repo.merge("feat", "t").unwrap();
    assert_round_trips(&repo, &root, "run.sh", true, "m.txt");
}

#[test]
fn rebase_creates_exec_file_with_its_bit() {
    let (repo, root) = base("rebase");
    repo.branch("feat").unwrap();
    repo.switch("feat").unwrap();
    put(&root, "f.txt", "f", false);
    repo.commit("t", "f").unwrap();
    repo.switch("main").unwrap();
    put(&root, "run.sh", "#!/bin/sh\n", true);
    repo.commit("t", "script").unwrap();
    repo.switch("feat").unwrap();
    assert!(!root.join("run.sh").exists());

    repo.rebase("main", "t", None).unwrap();
    assert_round_trips(&repo, &root, "run.sh", true, "f.txt");
}

#[test]
fn sparse_set_lays_out_exec_files_with_their_bit() {
    let (repo, root) = base("sparse");
    put(&root, "a/run.sh", "#!/bin/sh\n", true);
    put(&root, "b/x.txt", "x", false);
    repo.commit("t", "tree").unwrap();

    repo.set_sparse(&["b".to_string()], None).unwrap();
    assert!(!root.join("a/run.sh").exists());
    // Widening lays a/run.sh out afresh.
    repo.set_sparse(&["a".to_string(), "b".to_string()], None)
        .unwrap();
    assert_round_trips(&repo, &root, "a/run.sh", true, "b/x.txt");
}

/// A stopped merge widened mid-stop (#224): the executable that comes into
/// view keeps its bit, and the completing commit still records EXEC.
#[test]
fn stopped_merge_widen_lays_out_exec_files_with_their_bit() {
    let (repo, root) = base("widen");
    put(&root, "seed.txt", "l1\nl2\nl3\n", false);
    repo.commit("t", "base").unwrap();
    repo.branch("feat").unwrap();
    put(&root, "seed.txt", "MAIN\nl2\nl3\n", false);
    repo.commit("t", "main").unwrap();
    repo.switch("feat").unwrap();
    put(&root, "seed.txt", "FEAT\nl2\nl3\n", false);
    put(&root, "bin/run.sh", "#!/bin/sh\n", true);
    repo.commit("t", "feat").unwrap();
    repo.switch("main").unwrap();
    repo.set_sparse(&["seed.txt".to_string()], None).unwrap();
    assert!(repo.merge("feat", "t").is_err(), "conflict on seed.txt");
    assert!(!root.join("bin/run.sh").exists());

    repo.set_sparse(&["seed.txt".to_string(), "bin".to_string()], None)
        .unwrap();
    assert!(on_disk_exec(&root, "bin/run.sh"), "bit laid by the widen");
    put(&root, "seed.txt", "MERGED\nl2\nl3\n", false);
    repo.commit("t", "merge").unwrap();
    assert_eq!(committed(&repo, "bin/run.sh"), FileMode::EXEC);
    assert!(on_disk_exec(&root, "bin/run.sh"));
}

#[test]
fn clone_keeps_exec_bit() {
    let (repo, root) = base("clone-src");
    put(&root, "run.sh", "#!/bin/sh\n", true);
    put(&root, "plain.txt", "p", false);
    repo.commit("t", "add").unwrap();

    let dst = tmp("clone-dst");
    let cloned = Repo::clone_to(&root, &dst).unwrap();
    assert_round_trips(&cloned, &dst, "run.sh", true, "plain.txt");
    assert!(!on_disk_exec(&dst, "seed.txt"));
}

#[test]
fn ws_checkout_keeps_exec_bit() {
    let (repo, root) = base("ws");
    put(&root, "run.sh", "#!/bin/sh\n", true);
    put(&root, "plain.txt", "p", false);
    repo.commit("t", "add").unwrap();

    let session = repo.ws_fork(None, 1, "t", None).unwrap();
    let dir = &session.workspaces[0].dir;
    assert!(on_disk_exec(dir, "run.sh"));
    assert!(!on_disk_exec(dir, "plain.txt"));
    // Harvesting an edit of another file must not demote the script.
    std::fs::write(dir.join("plain.txt"), "edited").unwrap();
    repo.ws_harvest(None, None, Some("t"), None).unwrap();
    assert_eq!(committed(&repo, "run.sh"), FileMode::EXEC);
    assert_eq!(committed(&repo, "plain.txt"), FileMode::FILE);
}

/// Set the on-disk permission bits exactly (a stale or restrictive mode).
fn chmod(root: &Path, rel: &str, mode: u32) {
    std::fs::set_permissions(root.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
}

fn disk_mode(root: &Path, rel: &str) -> u32 {
    std::fs::metadata(root.join(rel))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// The decrypted-protected-plaintext path of `materialize` keeps the recorded
/// bit, clears a stale one, and never widens read bits.
#[test]
fn protected_switch_keeps_and_clears_exec_without_widening_reads() {
    let (repo, root) = base("prot-switch");
    let (sk, pk) = scl_crypto::generate_keypair();
    repo.protect("secret/", &[pk], None).unwrap();
    put(&root, "secret/run.sh", "#!/bin/sh\n", true);
    repo.commit("t", "add").unwrap();
    repo.branch("plain").unwrap();
    repo.switch_with_identity("plain", Some(&sk)).unwrap();
    put(&root, "secret/run.sh", "not a script\n", false);
    repo.commit("t", "demote").unwrap();

    // Owner-only file on disk: EXEC adds only the owner execute bit.
    chmod(&root, "secret/run.sh", 0o600);
    repo.switch_with_identity("main", Some(&sk)).unwrap();
    assert_eq!(disk_mode(&root, "secret/run.sh"), 0o700);
    // EXEC -> FILE clears the stale bits.
    repo.switch_with_identity("plain", Some(&sk)).unwrap();
    assert_eq!(disk_mode(&root, "secret/run.sh") & 0o111, 0);
}

/// The protected conflict write-out lays the recorded bit onto the markers.
#[test]
fn protected_conflict_writeout_keeps_exec_bit() {
    let (repo, root) = base("prot-conflict");
    let (sk, pk) = scl_crypto::generate_keypair();
    repo.protect("secret/", &[pk], None).unwrap();
    put(&root, "secret/run.sh", "l1\nl2\nl3\n", true);
    repo.commit("t", "base").unwrap();
    repo.branch("feat").unwrap();
    put(&root, "secret/run.sh", "MAIN\nl2\nl3\n", true);
    repo.commit("t", "main").unwrap();
    repo.switch_with_identity("feat", Some(&sk)).unwrap();
    put(&root, "secret/run.sh", "FEAT\nl2\nl3\n", true);
    repo.commit("t", "feat").unwrap();
    repo.switch_with_identity("main", Some(&sk)).unwrap();

    chmod(&root, "secret/run.sh", 0o600);
    assert!(repo.merge_with_identity("feat", "t", Some(&sk)).is_err());
    let text = std::fs::read_to_string(root.join("secret/run.sh")).unwrap();
    assert!(text.contains("<<<<<<<"), "markers: {text}");
    // The write-out may recreate the file (umask-dependent read bits).
    assert!(on_disk_exec(&root, "secret/run.sh"));
}

/// `sc resolve` recreates a conflicted file the user deleted with its mode.
#[test]
fn resolve_after_delete_restores_exec_bit() {
    let (repo, root) = base("resolve-del");
    put(&root, "run.sh", "l1\nl2\nl3\n", true);
    repo.commit("t", "base").unwrap();
    repo.branch("feat").unwrap();
    put(&root, "run.sh", "MAIN\nl2\nl3\n", true);
    repo.commit("t", "main").unwrap();
    repo.switch("feat").unwrap();
    put(&root, "run.sh", "FEAT\nl2\nl3\n", true);
    repo.commit("t", "feat").unwrap();
    repo.switch("main").unwrap();
    assert!(repo.merge("feat", "t").is_err());

    std::fs::remove_file(root.join("run.sh")).unwrap();
    repo.resolve_path("run.sh", scl_repo::ResolveSide::Theirs, None)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("run.sh")).unwrap(),
        "FEAT\nl2\nl3\n"
    );
    assert!(on_disk_exec(&root, "run.sh"));
}

/// Private branches: `materialize_private` (plain and protected-carried
/// paths) and the private-merge conflict write-out keep/clear the bit.
#[test]
fn private_branch_materialize_and_conflict_writeout_keep_exec_bit() {
    let (repo, root) = base("private");
    let (sk, pk) = scl_crypto::generate_keypair();
    repo.protect("secret/", &[pk], None).unwrap();
    for rel in ["run.sh", "secret/tool.sh"] {
        put(&root, rel, "l1\nl2\nl3\n", true);
    }
    repo.commit("t", "base").unwrap();
    repo.branch_private("fix", &sk, &[], &[]).unwrap();

    // Switching in lays both files out executable, from owner-only files.
    for rel in ["run.sh", "secret/tool.sh"] {
        chmod(&root, rel, 0o600);
    }
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    for rel in ["run.sh", "secret/tool.sh"] {
        assert_eq!(disk_mode(&root, rel), 0o700, "{rel} after switch");
    }

    // Conflicting edits on both sides stop the merge with markers.
    for rel in ["run.sh", "secret/tool.sh"] {
        put(&root, rel, "FIX\nl2\nl3\n", true);
    }
    repo.commit_private("t", "private edit", Some(&sk)).unwrap();
    repo.switch_with_identity("main", Some(&sk)).unwrap();
    for rel in ["run.sh", "secret/tool.sh"] {
        put(&root, rel, "MAIN\nl2\nl3\n", true);
    }
    repo.commit("t", "main edit").unwrap();
    repo.switch_with_identity("fix", Some(&sk)).unwrap();
    for rel in ["run.sh", "secret/tool.sh"] {
        chmod(&root, rel, 0o600);
    }
    assert!(repo.merge_into_private("main", "t", Some(&sk)).is_err());
    for rel in ["run.sh", "secret/tool.sh"] {
        let text = std::fs::read_to_string(root.join(rel)).unwrap();
        assert!(text.contains("<<<<<<<"), "{rel} markers: {text}");
        assert_eq!(disk_mode(&root, rel), 0o700, "{rel} after conflict");
    }
}
