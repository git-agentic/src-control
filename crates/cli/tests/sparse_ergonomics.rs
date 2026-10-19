//! `sc sparse set` usability guards (P24 follow-ons): a prefix that matches
//! nothing is warned about, and a bare `sparse set` points at `sparse disable`.

use std::process::Command;

fn sc(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn repo(tag: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("scl-cli-sparse-ergo-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("docs")).unwrap();
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("src/a.txt"), "a\n").unwrap();
    std::fs::write(root.join("docs/b.txt"), "b\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "c1"]).status.success());
    root
}

/// A prefix naming nothing empties the tree; the command still succeeds, but
/// says so, and names the way back.
#[test]
fn a_prefix_matching_no_tracked_path_is_warned_about() {
    let root = repo("nomatch");
    let out = sc(&root, &["sparse", "set", "sorc/"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("matches no tracked path"), "{err}");
    assert!(err.contains("sc sparse disable"), "{err}");
    assert!(!root.join("src/a.txt").exists(), "the view really is empty");

    // A real prefix draws no warning, and a mixed set warns only for the miss.
    assert!(sc(&root, &["sparse", "disable"]).status.success());
    let ok = sc(&root, &["sparse", "set", "src/"]);
    assert!(ok.status.success());
    assert!(
        !stderr(&ok).contains("matches no tracked path"),
        "{}",
        stderr(&ok)
    );
    let mixed = sc(&root, &["sparse", "set", "src/", "nope/"]);
    assert!(mixed.status.success());
    let err = stderr(&mixed);
    assert!(err.contains("\"nope/\""), "{err}");
    assert!(!err.contains("\"src/\""), "{err}");
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists());
}

/// With no prefix `sparse set` was a silent `sparse disable`; it now refuses
/// and says which command means that.
#[test]
fn a_bare_sparse_set_points_at_disable() {
    let root = repo("bare");
    assert!(sc(&root, &["sparse", "set", "src/"]).status.success());
    let out = sc(&root, &["sparse", "set"]);
    assert!(!out.status.success(), "a bare `sparse set` must be refused");
    let err = stderr(&out);
    assert!(err.contains("sc sparse disable"), "{err}");
    assert!(!root.join("docs/b.txt").exists(), "nothing was re-laid");
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists());
}
