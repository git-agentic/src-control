//! P27 Task 5: CLI-level coverage for the data-safety surfaces of a partial
//! clone — `sc export` refuses, `sc verify` reports gaps as expected (not
//! corrupt), and `sc status`/`sc diff`/`sc gc` all succeed on a fresh
//! partial clone instead of erroring on the out-of-filter gap.

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
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "scl-cli-partial-safety-{tag}-{}",
        std::process::id()
    ));
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
        &[
            "clone",
            src_root.to_str().unwrap(),
            dst_root.to_str().unwrap(),
            "--filter",
            "src/",
        ],
    );
    assert!(
        out.status.success(),
        "partial clone failed: {}",
        stderr(&out)
    );
    assert!(
        dst_root.join(".sc/promisor").exists(),
        "partial clone must write .sc/promisor"
    );
    (src_root, dst_root)
}

#[test]
fn export_refuses_on_partial_clone() {
    let (src_root, dst_root) = make_partial_clone("export");

    let export_to = tmp("export-target");
    let out = sc(&dst_root, &["export", "--to", export_to.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "export must refuse on a partial clone"
    );
    let err = stderr(&out);
    assert!(
        err.contains("partial"),
        "error must name the partial clone: {err}"
    );
    assert!(
        err.contains("backfill"),
        "error must hint at `sc backfill`: {err}"
    );
    assert!(!export_to.exists(), "export must not have written anything");

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

#[test]
fn verify_reports_partial_not_corrupt() {
    let (src_root, dst_root) = make_partial_clone("verify");

    let out = sc(&dst_root, &["verify"]);
    assert!(
        out.status.success(),
        "verify must exit 0 on a healthy partial clone: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("partial:"),
        "verify must print a partial-clone gap line: {text}"
    );
    assert!(
        !text.to_lowercase().contains("missing"),
        "gaps must not be reported as missing: {text}"
    );
    assert!(
        !text.to_lowercase().contains("corrupt"),
        "gaps must not be reported as corrupt: {text}"
    );

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

#[test]
fn status_diff_and_gc_succeed_on_fresh_partial_clone() {
    let (src_root, dst_root) = make_partial_clone("status-diff-gc");

    let status = sc(&dst_root, &["status"]);
    assert!(
        status.status.success(),
        "status must not error on the out-of-filter gap: {}",
        stderr(&status)
    );
    let status_text = stdout(&status);
    assert!(
        !status_text.to_lowercase().contains("deleted"),
        "no spurious deletion: {status_text}"
    );

    let diff = sc(&dst_root, &["diff"]);
    assert!(
        diff.status.success(),
        "diff must not error on the out-of-filter gap: {}",
        stderr(&diff)
    );
    assert!(
        stdout(&diff).is_empty(),
        "a clean partial checkout diffs empty: {}",
        stdout(&diff)
    );

    let gc = sc(&dst_root, &["gc"]);
    assert!(
        gc.status.success(),
        "gc must not error walking the out-of-filter gap: {}",
        stderr(&gc)
    );

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

/// P27 final review I2: `sc backfill --all` is the real escape hatch —
/// fetches every remaining object and removes `.sc/promisor`, after which
/// a cherry-pick that was refused as unsupported on a partial clone works.
#[test]
fn backfill_all_lifts_partial_clone_refusals() {
    let (src_root, dst_root) = make_partial_clone("backfill-all");

    // Replay is still refused while partial (a merge, clean or conflicting
    // inside the view, works since P37c). Create a clashing branch (same
    // file) for the refusal and a non-conflicting one for the merge after
    // backfill.
    assert!(sc(&dst_root, &["branch", "clash"]).status.success());
    assert!(sc(&dst_root, &["switch", "clash"]).status.success());
    std::fs::write(dst_root.join("src/a.txt"), "clash-edit\n").unwrap();
    assert!(sc(&dst_root, &["commit", "-m", "clash"]).status.success());
    assert!(sc(&dst_root, &["switch", "main"]).status.success());
    assert!(sc(&dst_root, &["branch", "feature"]).status.success());
    assert!(sc(&dst_root, &["switch", "feature"]).status.success());
    std::fs::write(dst_root.join("src/feature.txt"), "feature-only\n").unwrap();
    assert!(sc(&dst_root, &["commit", "-m", "feature"]).status.success());
    assert!(sc(&dst_root, &["switch", "main"]).status.success());
    std::fs::write(dst_root.join("src/a.txt"), "main-edit\n").unwrap();
    assert!(sc(&dst_root, &["commit", "-m", "main"]).status.success());

    let pick_before = sc(&dst_root, &["cherry-pick", "clash"]);
    assert!(
        !pick_before.status.success(),
        "a cherry-pick must still be refused before backfill --all"
    );
    assert!(
        stderr(&pick_before).contains("backfill --all"),
        "refusal must point at `sc backfill --all`: {}",
        stderr(&pick_before)
    );
    assert!(
        !dst_root.join("src/a.txt.theirs").exists(),
        "a refused cherry-pick writes nothing"
    );
    assert_eq!(
        std::fs::read_to_string(dst_root.join("src/a.txt")).unwrap(),
        "main-edit\n"
    );

    let backfill = sc(&dst_root, &["backfill", "--all"]);
    assert!(
        backfill.status.success(),
        "sc backfill --all failed: {}",
        stderr(&backfill)
    );
    assert!(
        !dst_root.join(".sc/promisor").exists(),
        ".sc/promisor must be removed by backfill --all"
    );

    // Widen sparse too (a separate P24 mechanism `--all` doesn't touch) so
    // `docs/` materializes before the merge fast-forward/land needs it.
    let sparse_disable = sc(&dst_root, &["sparse", "disable"]);
    assert!(
        sparse_disable.status.success(),
        "sparse disable must now succeed: {}",
        stderr(&sparse_disable)
    );

    // The cherry-pick is no longer refused: it reaches the ordinary
    // conflict state (markers in the file), which `--abort` undoes.
    let conflict_after = sc(&dst_root, &["cherry-pick", "clash"]);
    assert!(
        !stderr(&conflict_after).contains("partial clone"),
        "a cherry-pick must no longer be refused after backfill --all: {}",
        stderr(&conflict_after)
    );
    assert!(
        std::fs::read_to_string(dst_root.join("src/a.txt"))
            .unwrap()
            .contains("<<<<<<<"),
        "the ordinary conflict markers are written"
    );
    assert!(sc(&dst_root, &["cherry-pick", "--abort"]).status.success());

    let merge_after = sc(&dst_root, &["merge", "feature"]);
    assert!(
        merge_after.status.success(),
        "merge must succeed after backfill --all: {}",
        stderr(&merge_after)
    );

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

/// P37c-iii: a merge with a conflict inside the view works on a partial clone.
/// Markers land, `sc conflicts` and `sc resolve` find the path without
/// flattening a tree, and `sc commit` completes the merge. The untouched
/// `docs/` subtree is never fetched or written.
#[test]
fn conflicting_merge_on_a_partial_clone_resolves_and_commits() {
    let (src_root, dst_root) = make_partial_clone("conflict-merge");
    assert!(sc(&dst_root, &["branch", "clash"]).status.success());
    assert!(sc(&dst_root, &["switch", "clash"]).status.success());
    std::fs::write(dst_root.join("src/a.txt"), "clash-edit\n").unwrap();
    assert!(sc(&dst_root, &["commit", "-m", "clash"]).status.success());
    assert!(sc(&dst_root, &["switch", "main"]).status.success());
    std::fs::write(dst_root.join("src/a.txt"), "main-edit\n").unwrap();
    assert!(sc(&dst_root, &["commit", "-m", "main"]).status.success());

    let merge = sc(&dst_root, &["merge", "clash"]);
    assert!(!merge.status.success(), "a conflicting merge exits nonzero");
    assert!(
        !stderr(&merge).contains("partial clone"),
        "not refused as unsupported: {}",
        stderr(&merge)
    );
    assert!(std::fs::read_to_string(dst_root.join("src/a.txt"))
        .unwrap()
        .contains("<<<<<<<"));
    assert!(
        !dst_root.join("docs").exists(),
        "docs/ stays out of the view"
    );

    let listed = sc(&dst_root, &["conflicts"]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(stdout(&listed).contains("src/a.txt"));
    let shown = sc(&dst_root, &["conflicts", "src/a.txt"]);
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert!(stdout(&shown).contains("main-edit") && stdout(&shown).contains("clash-edit"));

    let resolved = sc(&dst_root, &["resolve", "--theirs", "src/a.txt"]);
    assert!(resolved.status.success(), "{}", stderr(&resolved));
    let commit = sc(&dst_root, &["commit", "-m", "merge clash"]);
    assert!(commit.status.success(), "{}", stderr(&commit));
    assert_eq!(
        std::fs::read_to_string(dst_root.join("src/a.txt")).unwrap(),
        "clash-edit\n"
    );
    assert!(!dst_root.join("docs").exists());
    let verify = sc(&dst_root, &["verify"]);
    assert!(verify.status.success(), "{}", stderr(&verify));

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

#[test]
fn sparse_widen_beyond_partial_filter_is_refused() {
    let (src_root, dst_root) = make_partial_clone("sparse-widen");

    let out = sc(&dst_root, &["sparse", "set", "docs/"]);
    assert!(
        !out.status.success(),
        "widening sparse beyond the partial filter must be refused"
    );
    let err = stderr(&out);
    assert!(err.contains("docs/"), "error must name docs/: {err}");
    assert!(
        err.contains("backfill"),
        "error must hint at `sc backfill`: {err}"
    );

    let disable = sc(&dst_root, &["sparse", "disable"]);
    assert!(
        !disable.status.success(),
        "disabling sparse (full checkout) must be refused on a partial clone"
    );
    assert!(stderr(&disable).contains("backfill"));

    assert!(
        !dst_root.join("docs/b.txt").exists(),
        "no partial write happened"
    );

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

/// ADR-0048: an ordinary `sc fetch` can leave an in-filter object absent
/// (the origin subtracts the closure of every have, and the new file equals
/// one that is only reachable at an out-of-filter path). `sc gc` must keep
/// working, `sc verify` must count the gap, and a fast-forward must fail
/// before it writes anything, with a repair hint that works.
#[test]
fn fetch_then_gc_and_fast_forward_on_a_partial_clone() {
    let src_root = tmp("fetch-gc-src");
    let dst_root = tmp("fetch-gc-dst");
    std::fs::create_dir_all(src_root.join("src")).unwrap();
    std::fs::create_dir_all(src_root.join("docs")).unwrap();
    assert!(sc(&src_root, &["init"]).status.success());
    std::fs::write(src_root.join("src/a.txt"), "src-one\n").unwrap();
    std::fs::write(
        src_root.join("docs/readme.txt"),
        "same bytes at two paths\n",
    )
    .unwrap();
    assert!(sc(&src_root, &["commit", "-m", "c1"]).status.success());
    let out = sc(
        &src_root,
        &[
            "clone",
            src_root.to_str().unwrap(),
            dst_root.to_str().unwrap(),
            "--filter",
            "src/",
        ],
    );
    assert!(out.status.success(), "clone: {}", stderr(&out));

    // The origin adds an in-filter file whose bytes equal docs/readme.txt, and
    // another in-filter file that sorts before it.
    std::fs::write(src_root.join("src/aaa.txt"), "fetched normally\n").unwrap();
    std::fs::write(src_root.join("src/readme.txt"), "same bytes at two paths\n").unwrap();
    assert!(sc(&src_root, &["commit", "-m", "c2"]).status.success());

    let fetch = sc(&dst_root, &["fetch", "origin"]);
    assert!(fetch.status.success(), "fetch: {}", stderr(&fetch));

    let gc = sc(&dst_root, &["gc"]);
    assert!(
        gc.status.success(),
        "gc must work after an ordinary fetch: {}",
        stderr(&gc)
    );
    let verify = sc(&dst_root, &["verify"]);
    assert!(verify.status.success(), "verify: {}", stderr(&verify));

    let merge = sc(&dst_root, &["merge", "origin/main"]);
    assert!(!merge.status.success(), "the fast-forward must be refused");
    let err = stderr(&merge);
    assert!(
        err.contains("sc backfill src/"),
        "error names the repair: {err}"
    );
    assert!(
        !dst_root.join("src/aaa.txt").exists() && !dst_root.join("src/readme.txt").exists(),
        "nothing was written before the refusal"
    );

    let backfill = sc(&dst_root, &["backfill", "src/"]);
    assert!(backfill.status.success(), "backfill: {}", stderr(&backfill));
    let merge = sc(&dst_root, &["merge", "origin/main"]);
    assert!(merge.status.success(), "merge: {}", stderr(&merge));
    assert_eq!(
        std::fs::read_to_string(dst_root.join("src/readme.txt")).unwrap(),
        "same bytes at two paths\n"
    );

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}

/// The git bridge walks the whole history and every blob, so a partial clone
/// refuses `sc push` to a git remote up front, like `sc export`.
#[test]
fn push_to_a_git_remote_is_refused_on_a_partial_clone() {
    let (src_root, dst_root) = make_partial_clone("push-git");
    let bare = tmp("push-git-bare");
    std::fs::create_dir_all(&bare).unwrap();
    let init = Command::new("git")
        .args(["init", "-q", "--bare", "-b", "main"])
        .arg(&bare)
        .output()
        .expect("git runs");
    assert!(init.status.success());
    assert!(sc(
        &dst_root,
        &["remote", "add", "hub", bare.to_str().unwrap(), "--git"]
    )
    .status
    .success());

    let out = sc(&dst_root, &["push", "hub"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("partial clone"), "names the cause: {err}");
    assert!(err.contains("backfill --all"), "names the repair: {err}");

    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
    std::fs::remove_dir_all(&bare).unwrap();
}

/// `sc sparse set` with no prefixes is a full checkout, which is what `sparse
/// disable` is, so it is refused too (otherwise it would bypass that refusal).
#[test]
fn sparse_set_with_no_prefixes_is_refused_on_a_partial_clone() {
    let (src_root, dst_root) = make_partial_clone("sparse-empty");
    let out = sc(&dst_root, &["sparse", "set"]);
    assert!(!out.status.success(), "an empty spec must be refused");
    assert!(stderr(&out).contains("backfill"), "{}", stderr(&out));
    assert!(!dst_root.join("docs/b.txt").exists());
    std::fs::remove_dir_all(&src_root).unwrap();
    std::fs::remove_dir_all(&dst_root).unwrap();
}
