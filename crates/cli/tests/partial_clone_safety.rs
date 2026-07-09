//! P27 Task 5: CLI-level coverage for the data-safety surfaces of a partial
//! clone — `sc export` refuses, `sc verify` reports gaps as expected (not
//! corrupt), and `sc status`/`sc diff`/`sc gc` all succeed on a fresh
//! partial clone instead of erroring on the out-of-filter gap.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc")).args(args).current_dir(dir).output().expect("sc runs")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-partial-safety-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Build a source repo with `src/a.txt` + `docs/b.txt` in separate
/// subtrees, one commit, then partial-clone it (`--filter src/`) into
/// `dst`. Returns `(src_root, dst_root)`.
fn make_partial_clone(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let src_root = tmp(&format!("{tag}-src"));
    let dst_root = tmp(&format!("{tag}-dst"));
    std::fs::create_dir_all(src_root.join("src")).unwrap();
    std::fs::create_dir_all(src_root.join("docs")).unwrap();
    assert!(sc(&src_root, &["init"]).status.success());
    std::fs::write(src_root.join("src/a.txt"), "src-one\n").unwrap();
    std::fs::write(src_root.join("docs/b.txt"), "docs-one\n").unwrap();
    assert!(sc(&src_root, &["commit", "-m", "c1"]).status.success());

    let out = sc(
        &src_root,
        &["clone", src_root.to_str().unwrap(), dst_root.to_str().unwrap(), "--filter", "src/"],
    );
    assert!(out.status.success(), "partial clone failed: {}", stderr(&out));
    assert!(dst_root.join(".sc/promisor").exists(), "partial clone must write .sc/promisor");
    (src_root, dst_root)
}

#[test]
fn export_refuses_on_partial_clone() {
    let (src_root, dst_root) = make_partial_clone("export");

    let export_to = tmp("export-target");
    let out = sc(&dst_root, &["export", "--to", export_to.to_str().unwrap()]);
    assert!(!out.status.success(), "export must refuse on a partial clone");
    let err = stderr(&out);
    assert!(err.contains("partial"), "error must name the partial clone: {err}");
    assert!(err.contains("backfill"), "error must hint at `sc backfill`: {err}");
    assert!(!export_to.exists(), "export must not have written anything");

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

#[test]
fn verify_reports_partial_not_corrupt() {
    let (src_root, dst_root) = make_partial_clone("verify");

    let out = sc(&dst_root, &["verify"]);
    assert!(out.status.success(), "verify must exit 0 on a healthy partial clone: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("partial:"), "verify must print a partial-clone gap line: {text}");
    assert!(!text.to_lowercase().contains("missing"), "gaps must not be reported as missing: {text}");
    assert!(!text.to_lowercase().contains("corrupt"), "gaps must not be reported as corrupt: {text}");

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

#[test]
fn status_diff_and_gc_succeed_on_fresh_partial_clone() {
    let (src_root, dst_root) = make_partial_clone("status-diff-gc");

    let status = sc(&dst_root, &["status"]);
    assert!(status.status.success(), "status must not error on the out-of-filter gap: {}", stderr(&status));
    let status_text = stdout(&status);
    assert!(!status_text.to_lowercase().contains("deleted"), "no spurious deletion: {status_text}");

    let diff = sc(&dst_root, &["diff"]);
    assert!(diff.status.success(), "diff must not error on the out-of-filter gap: {}", stderr(&diff));
    assert!(stdout(&diff).is_empty(), "a clean partial checkout diffs empty: {}", stdout(&diff));

    let gc = sc(&dst_root, &["gc"]);
    assert!(gc.status.success(), "gc must not error walking the out-of-filter gap: {}", stderr(&gc));

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

#[test]
fn sparse_widen_beyond_partial_filter_is_refused() {
    let (src_root, dst_root) = make_partial_clone("sparse-widen");

    let out = sc(&dst_root, &["sparse", "set", "docs/"]);
    assert!(!out.status.success(), "widening sparse beyond the partial filter must be refused");
    let err = stderr(&out);
    assert!(err.contains("docs/"), "error must name docs/: {err}");
    assert!(err.contains("backfill"), "error must hint at `sc backfill`: {err}");

    let disable = sc(&dst_root, &["sparse", "disable"]);
    assert!(!disable.status.success(), "disabling sparse (full checkout) must be refused on a partial clone");
    assert!(stderr(&disable).contains("backfill"));

    assert!(!dst_root.join("docs/b.txt").exists(), "no partial write happened");

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}
