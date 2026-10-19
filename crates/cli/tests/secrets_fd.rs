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

/// Whatever descriptor is asked for, a command that cannot be executed fails
/// with its real error: the requested number must not clobber the descriptor
/// the standard library uses to report an exec failure.
#[test]
fn a_missing_command_reports_its_error_for_every_nearby_descriptor() {
    let (repo, id, keys) = repo_with("noexec", &[("S", b"v".to_vec())]);
    for fd in 3..=12 {
        let out = sc(
            &repo,
            &[
                "run",
                "--identity",
                id.to_str().unwrap(),
                "--secrets-fd",
                &fd.to_string(),
                "--",
                "/definitely/not/a/command",
            ],
        );
        assert!(!out.status.success(), "fd {fd}: must fail");
        let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
        assert!(
            err.contains("no such file") || err.contains("not found"),
            "fd {fd}: expected the exec error, got {err:?}"
        );
    }
    std::fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

/// A descendant that keeps the descriptor open after the command exits cannot
/// keep `sc run` (or the unread payload) alive.
#[test]
fn a_grandchild_holding_the_descriptor_does_not_pin_sc_run() {
    let (repo, id, keys) = repo_with("grandchild", &[("BIG", vec![b'x'; 300_000])]);
    let start = std::time::Instant::now();
    // The shell backgrounds a sleeper that inherits fd 3, never reads it, and exits.
    let out = run_fd(&repo, &id, "3", "sleep 4 >/dev/null 2>&1 & exit 0");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(3),
        "sc run waited on the grandchild: {:?}",
        start.elapsed()
    );
    std::fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

/// A name that cannot be framed (empty, or holding `=`) is refused before the
/// command runs, whether or not `secret add` let it be registered.
#[test]
fn a_secret_name_that_cannot_be_framed_is_refused() {
    let root = tmp("badname");
    let keys = tmp("badname-keys");
    let id = keys.join("alice.id");
    let out = sc(&keys, &["keygen", "--out", id.to_str().unwrap()]);
    let pk = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .unwrap()
        .to_string();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(
        repo.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{pk}\"\n"),
    )
    .unwrap();
    let add = sc_stdin(&repo, &["secret", "add", "TOKEN=x", "--to", "alice"], b"v");
    if add.status.success() {
        let out = run_fd(&repo, &id, "3", "echo ran");
        assert!(!out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("cannot be framed"), "{err}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("ran"));
    } else {
        // Registration already refuses it: nothing to frame, nothing to leak.
        eprintln!("secret add refuses '=' in a name; the framing check is a backstop");
    }
    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}
