//! `sc+wal://` bucket remotes through the real binary. Wire/WAL correctness
//! is proven in scl-repo's bucket_transport tests; this exercises CLI
//! plumbing: remote add validation, push, clone, fetch.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

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

/// Spawn `sc serve --http 127.0.0.1:0 <extra…> <path>` and return the child
/// plus the OS-assigned `host:port` it reports on its first stdout line
/// (`listening on <addr>`). Copied from `crates/cli/tests/http_remote.rs`'s
/// `spawn_http_server` — same readiness contract (the announce line prints
/// only after `TcpListener::bind` returns) — parameterized with `extra` so
/// this file's tests can pass `--store <url>`.
fn spawn_http_server_with(root: &Path, extra: &[&str]) -> (Child, String) {
    let mut args = vec!["serve", "--http", "127.0.0.1:0"];
    args.extend_from_slice(extra);
    args.push(root.to_str().unwrap());
    let mut child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(&args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn sc serve --http");
    let stdout = child.stdout.take().expect("child stdout is piped");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .expect("read serve startup line");
    if n == 0 {
        let status = child.wait().ok();
        panic!("sc serve --http exited before announcing a bound address: {status:?}");
    }
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected serve startup line: {line:?}"))
        .to_string();
    (child, addr)
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

/// `sc serve --http --store <sc+wal://…>` serves a bucket instead of the
/// serve-home's own object store (P36c): a repo pushed straight to the
/// bucket is clonable through the server, and a push through the server is
/// visible to a completely separate server instance pointed at the same
/// bucket (proving durable state lives in the bucket, not the server
/// process). A malformed `--store` URL must be refused before any bind.
#[test]
fn serve_store_serves_a_bucket_and_second_instance_sees_pushes() {
    let bucket = tmp("srv-bucket");
    let home = tmp("srv-home");
    assert!(sc(&home, &["init"]).status.success());
    let store = format!("sc+wal://{}", bucket.display());

    // seed: a repo pushed straight to the bucket
    let seed = tmp("srv-seed");
    assert!(sc(&seed, &["init"]).status.success());
    std::fs::write(seed.join("f.txt"), b"served from bucket").unwrap();
    assert!(sc(&seed, &["commit", "-m", "c1"]).status.success());
    assert!(sc(&seed, &["remote", "add", "origin", &store])
        .status
        .success());
    assert!(sc(&seed, &["push", "origin"]).status.success());

    // malformed store URL refused before binding
    let bad = sc(
        &home,
        &[
            "serve",
            "--http",
            "127.0.0.1:0",
            "--store",
            "sc+s3://",
            home.to_str().unwrap(),
        ],
    );
    assert!(!bad.status.success());

    let (mut child, addr) = spawn_http_server_with(&home, &["--store", &store]);
    let parent = tmp("srv-clone");
    let dst = parent.join("d");
    let url = format!("sc+http://{addr}/repo");
    assert!(sc(&parent, &["clone", &url, dst.to_str().unwrap()])
        .status
        .success());
    assert_eq!(
        std::fs::read(dst.join("f.txt")).unwrap(),
        b"served from bucket"
    );
    // push through the server, then read it back via a SECOND instance
    std::fs::write(dst.join("g.txt"), b"hop").unwrap();
    assert!(sc(&dst, &["commit", "-m", "c2"]).status.success());
    assert!(sc(&dst, &["push", "origin"]).status.success());
    child.kill().ok();
    let (mut child2, addr2) = spawn_http_server_with(&home, &["--store", &store]);
    let parent2 = tmp("srv-clone2");
    let d2 = parent2.join("d2");
    assert!(sc(
        &parent2,
        &[
            "clone",
            &format!("sc+http://{addr2}/repo"),
            d2.to_str().unwrap()
        ]
    )
    .status
    .success());
    assert_eq!(std::fs::read(d2.join("g.txt")).unwrap(), b"hop");
    child2.kill().ok();

    for p in [&bucket, &home, &seed, &parent, &parent2] {
        std::fs::remove_dir_all(p).unwrap();
        assert!(!p.exists());
    }
}
