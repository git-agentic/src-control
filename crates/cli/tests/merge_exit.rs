//! `sc merge` exit-code discipline: conflicts must exit nonzero so
//! `sc merge x && sc commit` cannot commit conflict markers.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-merge-exit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn merge_with_conflicts_exits_nonzero_and_abort_exits_zero() {
    let root = tmp("conflict");

    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("file.txt"), "base\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "base"]).status.success());
    assert!(sc(&root, &["branch", "feature"]).status.success());

    // Diverge: ours on main, theirs on feature.
    std::fs::write(root.join("file.txt"), "ours\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "ours"]).status.success());
    assert!(sc(&root, &["switch", "feature"]).status.success());
    std::fs::write(root.join("file.txt"), "theirs\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "theirs"]).status.success());
    assert!(sc(&root, &["switch", "main"]).status.success());

    let out = sc(&root, &["merge", "feature"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("conflict"),
        "expected conflict report, got: {stdout}"
    );
    assert_eq!(out.status.code(), Some(1), "conflicted merge must exit 1");

    // A clean abort is a success exit — and must not hit a stale lock.
    let abort = sc(&root, &["merge", "--abort"]);
    assert!(
        abort.status.success(),
        "abort: {}",
        String::from_utf8_lossy(&abort.stderr)
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn abort_on_a_private_branch_needs_the_identity() {
    let root = tmp("private");
    let keys = tmp("private-keys");
    let id = keys.join("alice.id");
    let id_arg = id.to_str().unwrap();
    assert!(sc(&keys, &["keygen", "--out", id_arg]).status.success());

    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("file.txt"), "base\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "base"]).status.success());
    let ok = |args: &[&str]| {
        let out = sc(&root, args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    ok(&["branch", "fix", "--private", "--identity", id_arg]);
    ok(&["switch", "fix", "--identity", id_arg]);
    std::fs::write(root.join("file.txt"), "private\n").unwrap();
    ok(&["commit", "-m", "private", "--identity", id_arg]);
    ok(&["switch", "main", "--identity", id_arg]);
    std::fs::write(root.join("file.txt"), "public\n").unwrap();
    ok(&["commit", "-m", "public"]);
    ok(&["switch", "fix", "--identity", id_arg]);

    let out = sc(&root, &["merge", "main", "--identity", id_arg]);
    assert_eq!(out.status.code(), Some(1), "conflicted merge must exit 1");

    // No key: refused, and the stop is still there to abort.
    let mut keyless = Command::new(env!("CARGO_BIN_EXE_sc"));
    keyless
        .args(["merge", "--abort"])
        .current_dir(&root)
        .env("SC_IDENTITY", keys.join("absent"));
    assert!(!keyless.output().unwrap().status.success());
    assert!(std::fs::read_to_string(root.join("file.txt"))
        .unwrap()
        .contains("<<<<<<<"));

    let abort = sc(&root, &["merge", "--abort", "--identity", id_arg]);
    assert!(
        abort.status.success(),
        "abort: {}",
        String::from_utf8_lossy(&abort.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(root.join("file.txt")).unwrap(),
        "private\n"
    );
    assert!(!root.join(".sc/MERGE_HEAD").exists());

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
    assert!(!root.exists() && !keys.exists(), "test dir left behind");
}
