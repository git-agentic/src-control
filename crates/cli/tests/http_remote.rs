//! CLI-level wiring for `sc serve --http` (P26 Task 4). The wire-protocol
//! correctness (clone/push/fetch/sign round trip through the real
//! `serve_http_listener`) is proven in-crate by
//! `scl_repo::http_transport::tests::real_server_clone_push_fetch_sign_and_404`;
//! this file only exercises the CLI surface: flag validation and that the
//! spawned `sc serve --http` process actually answers on the socket.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

fn sc(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sc")).args(args).current_dir(dir).output().expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-http-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `sc serve` with neither `--stdio` nor `--http` must bail with a message
/// naming both modes, not silently pick one.
#[test]
fn serve_without_a_mode_bails() {
    let root = tmp("no-mode");
    assert!(sc(&root, &["init"]).status.success());
    let out = sc(&root, &["serve", root.to_str().unwrap()]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("--stdio") && stderr.contains("--http"), "wrong error: {stderr}");
}

/// `sc serve --http <addr> <path>` actually listens and answers the HTTP
/// opening/status handshake — a smoke test of the CLI wiring onto
/// `serve_http`, not a re-proof of `wire::serve` correctness (covered
/// in-crate). Polls a fixed high port with a short retry loop for process
/// startup, then confirms the process is killed cleanly afterward.
#[test]
fn serve_http_cli_answers_on_socket() {
    let root = tmp("cli-answers");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("f.txt"), b"v1").unwrap();
    assert!(sc(&root, &["commit", "-m", "c1", "--author", "t"]).status.success());

    // Fixed high port: avoids needing the child to report back an
    // OS-assigned one over a channel this test doesn't otherwise need.
    let port = 18732u16 + (std::process::id() % 1000) as u16;
    let addr = format!("127.0.0.1:{port}");

    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(["serve", "--http", &addr, root.to_str().unwrap()])
        .spawn()
        .expect("spawn sc serve --http");

    // Retry-connect: give the child a moment to bind.
    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(&addr) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stream = stream.expect("sc serve --http bound and accepted a connection");

    // A malformed opening must get a prompt 400, proving the CLI-spawned
    // server is really running `handle_http_connection`, not just accepting
    // and hanging.
    stream.write_all(b"not an http request\r\n\r\n").unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 400"), "expected 400, got: {resp}");

    let _ = child.kill();
    let _ = child.wait();

    std::fs::remove_dir_all(&root).unwrap();
}
