//! P23 Task 3: `sc conflicts`, `sc resolve`, and marker-aware `sc status`.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-conflicts-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Set up a repo with a conflicted merge on `file.txt` (base/ours/theirs all
/// differ) and leave the merge in progress.
fn make_conflicted_merge(root: &Path) {
    assert!(sc(root, &["init"]).status.success());
    std::fs::write(root.join("file.txt"), "base\n").unwrap();
    assert!(sc(root, &["commit", "-m", "base"]).status.success());
    assert!(sc(root, &["branch", "feature"]).status.success());

    std::fs::write(root.join("file.txt"), "ours\n").unwrap();
    assert!(sc(root, &["commit", "-m", "ours"]).status.success());
    assert!(sc(root, &["switch", "feature"]).status.success());
    std::fs::write(root.join("file.txt"), "theirs\n").unwrap();
    assert!(sc(root, &["commit", "-m", "theirs"]).status.success());
    assert!(sc(root, &["switch", "main"]).status.success());

    let out = sc(root, &["merge", "feature"]);
    assert_eq!(out.status.code(), Some(1), "conflicted merge must exit 1");
}

#[test]
fn conflicts_with_no_op_in_progress_reports_none() {
    let root = tmp("none");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("f.txt"), "1\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "c1"]).status.success());

    let out = sc(&root, &["conflicts"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no conflicts (no merge/pick/rebase in progress)"));

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn conflicts_lists_paths_with_kind() {
    let root = tmp("list");
    make_conflicted_merge(&root);

    let out = sc(&root, &["conflicts"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("file.txt"),
        "expected file.txt listed, got: {text}"
    );
    assert!(text.contains("[text]"), "expected [text] kind, got: {text}");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn conflicts_json_lists_path_and_kind() {
    let root = tmp("json");
    make_conflicted_merge(&root);

    let out = sc(&root, &["conflicts", "--json"]);
    assert!(out.status.success());
    let arr: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid json");
    let arr = arr.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["path"], "file.txt");
    assert_eq!(arr[0]["kind"], "text");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn conflicts_shows_base_ours_theirs_for_a_path() {
    let root = tmp("versions");
    make_conflicted_merge(&root);

    let out = sc(&root, &["conflicts", "file.txt"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("--- base ---"));
    assert!(text.contains("base"));
    assert!(text.contains("--- ours ---"));
    assert!(text.contains("ours"));
    assert!(text.contains("--- theirs ---"));
    assert!(text.contains("theirs"));

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn resolve_ours_completes_the_merge_and_hints_commit() {
    let root = tmp("resolve-ours");
    make_conflicted_merge(&root);

    let out = sc(&root, &["resolve", "--ours", "file.txt"]);
    assert!(
        out.status.success(),
        "resolve failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    assert!(text.contains("resolved file.txt (ours)"), "got: {text}");
    assert!(
        text.contains("sc commit"),
        "expected completion hint, got: {text}"
    );

    let content = std::fs::read_to_string(root.join("file.txt")).unwrap();
    assert_eq!(content, "ours\n");

    // The op is still "in progress" (not yet committed) but has zero
    // remaining conflicts, so `sc conflicts` lists none.
    let conflicts_after = sc(&root, &["conflicts"]);
    assert!(conflicts_after.status.success());
    assert!(
        stdout(&conflicts_after).trim().is_empty(),
        "expected no conflicts left, got: {}",
        stdout(&conflicts_after)
    );

    assert!(sc(&root, &["commit", "-m", "merged"]).status.success());

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn resolve_requires_exactly_one_side() {
    let root = tmp("neither");
    make_conflicted_merge(&root);

    let out = sc(&root, &["resolve", "file.txt"]);
    assert!(
        !out.status.success(),
        "resolve with neither --ours nor --theirs must fail"
    );

    let out2 = sc(&root, &["resolve", "--ours", "--theirs", "file.txt"]);
    assert!(
        !out2.status.success(),
        "clap should reject --ours and --theirs together"
    );

    // Abort so the temp dir teardown isn't left with a stale lock/merge.
    let _ = sc(&root, &["merge", "--abort"]);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn resolve_reports_bad_path_but_continues_and_exits_nonzero() {
    let root = tmp("bad-path");
    make_conflicted_merge(&root);

    let out = sc(
        &root,
        &["resolve", "--ours", "does-not-exist.txt", "file.txt"],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a bad path among good ones must exit 1"
    );
    let text = stdout(&out);
    assert!(
        text.contains("resolved file.txt (ours)"),
        "good path must still resolve: {text}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does-not-exist.txt"),
        "bad path must be reported on stderr"
    );

    // The good path's resolution must have gone through despite the bad one.
    let content = std::fs::read_to_string(root.join("file.txt")).unwrap();
    assert_eq!(content, "ours\n");

    assert!(sc(&root, &["commit", "-m", "merged"]).status.success());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn status_shows_per_path_conflict_detail_under_merge_banner() {
    let root = tmp("status-detail");
    make_conflicted_merge(&root);

    let out = sc(&root, &["status"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("merge in progress"),
        "banner must be unchanged, got: {text}"
    );
    assert!(
        text.contains("file.txt"),
        "expected per-path detail, got: {text}"
    );
    assert!(
        text.contains("[text]"),
        "expected kind in detail line, got: {text}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn status_json_includes_conflicts_array() {
    let root = tmp("status-json");
    make_conflicted_merge(&root);

    let out = sc(&root, &["status", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid json");
    let conflicts = v["conflicts"].as_array().expect("conflicts array");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["path"], "file.txt");
    assert_eq!(conflicts[0]["kind"], "text");

    std::fs::remove_dir_all(&root).unwrap();
}
