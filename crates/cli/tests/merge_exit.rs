//! `sc merge` exit-code discipline: conflicts must exit nonzero so
//! `sc merge x && sc commit` cannot commit conflict markers.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc")).args(args).current_dir(dir).output().expect("sc runs")
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
    assert!(stdout.contains("conflict"), "expected conflict report, got: {stdout}");
    assert_eq!(out.status.code(), Some(1), "conflicted merge must exit 1");

    // A clean abort is a success exit — and must not hit a stale lock.
    let abort = sc(&root, &["merge", "--abort"]);
    assert!(abort.status.success(), "abort: {}", String::from_utf8_lossy(&abort.stderr));

    std::fs::remove_dir_all(&root).unwrap();
}
