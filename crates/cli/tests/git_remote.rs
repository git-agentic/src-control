//! End-to-end: sc <-> local git repo fetch/push round-trip.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e")
        .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e")
        .output()
        .expect("git runs")
}
fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-gitremote-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn fetch_from_git_imports_history_into_tracking_ref() {
    let root = tmp("fetch");
    let gitrepo = root.join("upstream"); // a normal (non-bare) git repo with content
    std::fs::create_dir_all(&gitrepo).unwrap();
    git(&gitrepo, &["init", "-q", "-b", "main"]);
    std::fs::write(gitrepo.join("hello.txt"), b"world").unwrap();
    git(&gitrepo, &["add", "."]);
    git(&gitrepo, &["commit", "-q", "-m", "from-git"]);

    let screpo = root.join("work");
    std::fs::create_dir_all(&screpo).unwrap();
    assert!(sc(&screpo, &["init"]).status.success());
    assert!(sc(&screpo, &["remote", "add", "hub", gitrepo.to_str().unwrap(), "--git"]).status.success());

    let out = sc(&screpo, &["fetch", "hub"]);
    assert!(out.status.success(), "fetch failed: {}", String::from_utf8_lossy(&out.stderr));

    // Integrate via existing merge, then the content is present.
    let m = sc(&screpo, &["merge", "hub/main"]);
    assert!(m.status.success(), "merge failed: {}", String::from_utf8_lossy(&m.stderr));
    assert_eq!(std::fs::read(screpo.join("hello.txt")).unwrap(), b"world");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn gc_after_git_fetch_retains_fetched_snapshots() {
    let root = tmp("gcsafe");
    let gitrepo = root.join("upstream");
    std::fs::create_dir_all(&gitrepo).unwrap();
    git(&gitrepo, &["init", "-q", "-b", "main"]);
    std::fs::write(gitrepo.join("keep.txt"), b"data").unwrap();
    git(&gitrepo, &["add", "."]);
    git(&gitrepo, &["commit", "-q", "-m", "keepme"]);

    let screpo = root.join("work");
    std::fs::create_dir_all(&screpo).unwrap();
    sc(&screpo, &["init"]);
    sc(&screpo, &["remote", "add", "hub", gitrepo.to_str().unwrap(), "--git"]);
    sc(&screpo, &["fetch", "hub"]);

    // gc with no local merge: the remote-tracking ref must keep the snapshot alive.
    let g = sc(&screpo, &["gc", "--prune-expire", "0s"]);
    assert!(g.status.success(), "gc failed: {}", String::from_utf8_lossy(&g.stderr));
    // Merge still works => the fetched objects survived gc.
    let m = sc(&screpo, &["merge", "hub/main"]);
    assert!(m.status.success(), "merge after gc failed: {}", String::from_utf8_lossy(&m.stderr));
    assert_eq!(std::fs::read(screpo.join("keep.txt")).unwrap(), b"data");

    std::fs::remove_dir_all(&root).unwrap();
}
