//! ADR-0055: `sc clone --filter blob:limit=<size>` through the real binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sc(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-blob-limit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Remove fixture directories and assert they are gone.
fn remove_all(dirs: &[&Path]) {
    for d in dirs {
        if d.exists() {
            std::fs::remove_dir_all(d).unwrap();
        }
        assert!(!d.exists(), "fixture {} must be removed", d.display());
    }
}

const OLD: &[u8] = &[b'o'; 4096];
const NEW: &[u8] = &[b'n'; 4096];

/// An origin whose first commit holds a 4 KiB `big.bin` that the second
/// replaced, plus a small file.
fn origin(tag: &str) -> PathBuf {
    let root = tmp(&format!("{tag}-origin"));
    std::fs::create_dir_all(&root).unwrap();
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("big.bin"), OLD).unwrap();
    std::fs::write(root.join("small.txt"), "one\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "c1"]).status.success());
    std::fs::write(root.join("big.bin"), NEW).unwrap();
    assert!(sc(&root, &["commit", "-m", "c2"]).status.success());
    root
}

#[test]
fn size_limited_clone_checks_out_complete_and_reports_the_gap() {
    let src = origin("clone");
    let dst = tmp("clone-dst");
    let out = sc(
        &src,
        &[
            "clone",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--filter",
            "blob:limit=1KiB",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("partial: blob:limit=1024"),
        "{}",
        stdout(&out)
    );
    assert_eq!(std::fs::read(dst.join("big.bin")).unwrap(), NEW);
    assert_eq!(
        std::fs::read_to_string(dst.join(".sc/promisor-blob-limit")).unwrap(),
        "limit 1024\nscope all-paths\n"
    );
    let v = sc(&dst, &["verify"]);
    assert!(v.status.success(), "{}", stderr(&v));
    let text = stdout(&v);
    assert!(
        text.contains("partial: 1 object(s) outside filter [blob:limit=1024]"),
        "{text}"
    );
    assert!(sc(&dst, &["gc"]).status.success());
    assert!(sc(&dst, &["status"]).status.success());
    remove_all(&[&src, &dst]);
}

#[test]
fn lazy_and_backfill_repair_a_size_gap() {
    let src = origin("lazy");
    let dst = tmp("lazy-dst");
    let out = sc(
        &src,
        &[
            "clone",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--filter",
            "blob:limit=1KiB",
            "--lazy",
        ],
    );
    assert!(
        out.status.success(),
        "--lazy works with only blob: {}",
        stderr(&out)
    );
    assert!(dst.join(".sc/promisor-lazy").exists());

    // Non-lazy sibling: backfill by the file's own path repairs the gap.
    let dst2 = tmp("lazy-dst2");
    let out = sc(
        &src,
        &[
            "clone",
            src.to_str().unwrap(),
            dst2.to_str().unwrap(),
            "--filter",
            "blob:limit=1KiB",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let b = sc(&dst2, &["backfill", "big.bin"]);
    assert!(b.status.success(), "{}", stderr(&b));
    let v = stdout(&sc(&dst2, &["verify"]));
    assert!(v.contains("partial: 0 object(s)"), "{v}");
    assert!(
        std::fs::read_to_string(dst2.join(".sc/promisor-blob-limit"))
            .unwrap()
            .contains("scope all-paths"),
        "backfill keeps the whole-tree scope"
    );
    let all = sc(&dst2, &["backfill", "--all"]);
    assert!(all.status.success(), "{}", stderr(&all));
    assert!(!dst2.join(".sc/promisor").exists());
    assert!(!dst2.join(".sc/promisor-blob-limit").exists());
    remove_all(&[&src, &dst, &dst2]);
}

#[test]
fn filter_grammar_errors_are_actionable() {
    let src = origin("grammar");
    let dst = tmp("grammar-dst");
    let run = |filters: &[&str]| {
        let mut args = vec!["clone", src.to_str().unwrap(), dst.to_str().unwrap()];
        for f in filters {
            args.push("--filter");
            args.push(f);
        }
        sc(&src, &args)
    };
    let none = run(&["blob:none"]);
    assert!(!none.status.success());
    assert!(stderr(&none).contains("blob:limit=0"), "{}", stderr(&none));
    let dup = run(&["blob:limit=1", "blob:limit=2"]);
    assert!(!dup.status.success());
    assert!(stderr(&dup).contains("more than once"), "{}", stderr(&dup));
    let bad = run(&["blob:limit=lots"]);
    assert!(!bad.status.success());
    assert!(!dst.exists(), "a rejected filter leaves no destination");
    // `sc clone --help` documents the grammar.
    let help = sc(&src, &["clone", "--help"]);
    assert!(
        stdout(&help).contains("blob:limit=<size>"),
        "{}",
        stdout(&help)
    );
    remove_all(&[&src]);
}

#[test]
fn a_bucket_remote_refuses_a_size_only_clone() {
    let src = origin("bucket");
    let bucket = tmp("bucket-wal");
    std::fs::create_dir_all(&bucket).unwrap();
    let url = format!("sc+wal://{}", bucket.display());
    assert!(sc(&src, &["remote", "add", "bk", &url]).status.success());
    assert!(sc(&src, &["push", "bk"]).status.success());
    let dst = tmp("bucket-dst");
    let out = sc(
        &src,
        &[
            "clone",
            &url,
            dst.to_str().unwrap(),
            "--filter",
            "blob:limit=1KiB",
        ],
    );
    assert!(!out.status.success(), "a bucket remote must refuse");
    assert!(
        stderr(&out).contains("partial clone from bucket remotes"),
        "{}",
        stderr(&out)
    );
    remove_all(&[&src, &bucket, &dst]);
}

/// Add a commit to `src` that introduces `extra.bin`, then replaces it, so the
/// first version is history only.
fn grow(src: &Path) {
    std::fs::write(src.join("extra.bin"), [b'x'; 4096]).unwrap();
    assert!(sc(src, &["commit", "-m", "c3"]).status.success());
    std::fs::write(src.join("extra.bin"), [b'y'; 4096]).unwrap();
    assert!(sc(src, &["commit", "-m", "c4"]).status.success());
}

fn clone_limited(src: &Path, dst: &Path) {
    let out = sc(
        src,
        &[
            "clone",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--filter",
            "blob:limit=1KiB",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn fetch_keeps_the_limit_and_no_blob_limit_opts_out() {
    let src = origin("fetch");
    let dst = tmp("fetch-dst");
    clone_limited(&src, &dst);
    let dst2 = tmp("fetch-dst2");
    clone_limited(&src, &dst2);
    grow(&src);

    let f = sc(&dst, &["fetch"]);
    assert!(f.status.success(), "{}", stderr(&f));
    let m = sc(&dst, &["merge", "origin/main"]);
    assert!(m.status.success(), "{}", stderr(&m));
    assert_eq!(std::fs::read(dst.join("extra.bin")).unwrap(), [b'y'; 4096]);
    let v = stdout(&sc(&dst, &["verify"]));
    // The clone-time old big.bin and the history-only extra.bin v1.
    assert!(
        v.contains("partial: 2 object(s) outside filter [blob:limit=1024]"),
        "fetch must leave the history-only extra.bin out: {v}"
    );

    // The opt-out fetches in full for one command and keeps the marker.
    let f = sc(&dst2, &["fetch", "--no-blob-limit"]);
    assert!(f.status.success(), "{}", stderr(&f));
    assert!(sc(&dst2, &["merge", "origin/main"]).status.success());
    let v = stdout(&sc(&dst2, &["verify"]));
    assert!(
        v.contains("partial: 1 object(s) outside filter [blob:limit=1024]"),
        "only the clone-time gap remains: {v}"
    );
    assert!(dst2.join(".sc/promisor-blob-limit").exists());
    let help = stdout(&sc(&src, &["fetch", "--help"]));
    assert!(help.contains("--no-blob-limit"), "{help}");
    remove_all(&[&src, &dst, &dst2]);
}

#[test]
fn a_bucket_origin_refuses_a_limit_bearing_fetch() {
    let src = origin("bucket-fetch");
    let bucket = tmp("bucket-fetch-wal");
    std::fs::create_dir_all(&bucket).unwrap();
    let url = format!("sc+wal://{}", bucket.display());
    assert!(sc(&src, &["remote", "add", "bk", &url]).status.success());
    assert!(sc(&src, &["push", "bk"]).status.success());
    let dst = tmp("bucket-fetch-dst");
    clone_limited(&src, &dst);
    // Point the promisor at the bucket, as if the clone had come from it.
    let promisor = dst.join(".sc/promisor");
    std::fs::write(&promisor, format!("origin {url}\n")).unwrap();
    assert!(sc(&dst, &["remote", "add", "bk", &url]).status.success());
    let out = sc(&dst, &["fetch", "bk"]);
    assert!(!out.status.success(), "a bucket remote must refuse");
    assert!(
        stderr(&out).contains("partial clone from bucket remotes"),
        "{}",
        stderr(&out)
    );
    // Without the limit the same fetch is an ordinary one.
    let ok = sc(&dst, &["fetch", "bk", "--no-blob-limit"]);
    assert!(ok.status.success(), "{}", stderr(&ok));
    remove_all(&[&src, &bucket, &dst]);
}
