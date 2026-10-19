//! `sc run --secrets-fd N` (ADR-0052): secrets reach the command on a file
//! descriptor instead of in its environment.
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

fn sc_stdin(dir: &Path, args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sc spawns");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().expect("sc runs")
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-secrets-fd-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A repo with `secrets` (name, value) sealed to alice; returns
/// (repo, alice's identity file, keys dir).
fn repo_with(
    tag: &str,
    secrets: &[(&str, Vec<u8>)],
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let root = tmp(tag);
    let keys = tmp(&format!("{tag}-keys"));
    let id = keys.join("alice.id");
    let out = sc(&keys, &["keygen", "--out", id.to_str().unwrap()]);
    assert!(out.status.success());
    let pk = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("public key")
        .to_string();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(
        repo.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{pk}\"\n"),
    )
    .unwrap();
    for (name, value) in secrets {
        let out = sc_stdin(&repo, &["secret", "add", name, "--to", "alice"], value);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    (repo, id, keys)
}

fn run_fd(repo: &Path, id: &Path, fd: &str, shell: &str) -> std::process::Output {
    sc(
        repo,
        &[
            "run",
            "--identity",
            id.to_str().unwrap(),
            "--secrets-fd",
            fd,
            "--",
            "sh",
            "-c",
            shell,
        ],
    )
}

/// The secrets arrive on the descriptor as NUL-terminated NAME=VALUE records
/// and are absent from the environment, which only names the descriptor.
#[test]
fn secrets_arrive_on_the_fd_and_not_in_the_environment() {
    let (repo, id, keys) = repo_with(
        "basic",
        &[
            ("DB_URL", b"postgres://x".to_vec()),
            ("API_KEY", b"k-123".to_vec()),
        ],
    );
    let out = run_fd(
        &repo,
        &id,
        "3",
        r#"test -z "${DB_URL+set}" && test -z "${API_KEY+set}" && test "$SC_SECRETS_FD" = 3 && cat <&3"#,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records: Vec<&[u8]> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .collect();
    let mut got: Vec<String> = records
        .iter()
        .map(|r| String::from_utf8_lossy(r).into_owned())
        .collect();
    got.sort();
    assert_eq!(got, ["API_KEY=k-123", "DB_URL=postgres://x"]);
    assert!(out.stdout.ends_with(&[0]), "every record is NUL-terminated");

    // The environment of a plain run still carries them (unchanged default).
    let plain = sc(
        &repo,
        &[
            "run",
            "--identity",
            id.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "test \"$API_KEY\" = k-123",
        ],
    );
    assert!(plain.status.success());
    std::fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

/// Any descriptor from 3 up works, and 0, 1, 2 and out-of-range numbers are
/// refused before anything runs.
#[test]
fn the_descriptor_number_is_honoured_and_validated() {
    let (repo, id, keys) = repo_with("fdnum", &[("S", b"v".to_vec())]);
    let out = run_fd(&repo, &id, "9", r#"test "$SC_SECRETS_FD" = 9 && cat <&9"#);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"S=v\0");

    for bad in ["0", "1", "2", "-1", "1024"] {
        let out = run_fd(&repo, &id, bad, "echo ran");
        assert!(!out.status.success(), "fd {bad} must be refused");
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("ran"),
            "the command must not run for fd {bad}"
        );
    }
    std::fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

/// A payload larger than the pipe buffer reaches the child whole, and a child
/// that never reads it does not hang the parent.
#[test]
fn a_large_payload_is_delivered_and_an_unread_one_does_not_hang() {
    let big = vec![b'x'; 300_000];
    let (repo, id, keys) = repo_with("big", &[("BIG", big)]);
    let out = run_fd(&repo, &id, "3", "wc -c <&3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let n: usize = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    assert_eq!(n, "BIG=".len() + 300_000 + 1);

    // The child exits without reading: sc must still return.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args([
            "run",
            "--identity",
            id.to_str().unwrap(),
            "--secrets-fd",
            "3",
            "--",
            "true",
        ])
        .current_dir(&repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            panic!("sc run hung with an unread payload");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(status.success());
    std::fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

/// A value that cannot be framed (it holds a NUL byte) is refused, naming the
/// secret, and the command does not run.
#[test]
fn a_secret_holding_a_nul_byte_is_refused() {
    let (repo, id, keys) = repo_with("nul", &[("BAD", b"a\0b".to_vec())]);
    let out = run_fd(&repo, &id, "3", "echo ran");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("BAD") && err.contains("NUL"), "{err}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("ran"));
    std::fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}
