//! `sc+wal://` bucket remotes through the real binary. Wire/WAL correctness
//! is proven in scl-repo's bucket_transport tests; this exercises CLI
//! plumbing: remote add validation, push, clone, fetch.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sc(dir: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sc"));
    cmd.args(args).current_dir(dir);
    cmd.output().expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-bucket-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn bucket_clone_push_fetch_round_trip_and_url_validation() {
    let a = tmp("a");
    let bucket = tmp("bucket");
    let url = format!("sc+wal://{}", bucket.display());

    let out = sc(&a, &["init"]);
    assert!(out.status.success(), "{out:?}");
    std::fs::write(a.join("f.txt"), b"via cli").unwrap();
    assert!(sc(&a, &["commit", "-m", "c1"]).status.success());
    // malformed bucket URL is refused at add time
    let bad = sc(&a, &["remote", "add", "borig", "sc+s3://"]);
    assert!(!bad.status.success());
    assert!(sc(&a, &["remote", "add", "origin", &url]).status.success());
    assert!(sc(&a, &["push", "origin"]).status.success());

    let parent = tmp("bparent");
    let b = parent.join("b");
    let out = sc(&parent, &["clone", &url, b.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read(b.join("f.txt")).unwrap(), b"via cli");

    std::fs::write(b.join("g.txt"), b"round trip").unwrap();
    assert!(sc(&b, &["commit", "-m", "c2"]).status.success());
    assert!(sc(&b, &["push", "origin"]).status.success());
    let out = sc(&a, &["fetch", "origin"]);
    assert!(out.status.success(), "{out:?}");

    for d in [&a, &bucket, &parent] {
        std::fs::remove_dir_all(d).unwrap();
        assert!(!d.exists());
    }
}
