//! Secret values can arrive on stdin, so they never appear in process args
//! (`ps`) or shell history.

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

/// Run `sc` with `input` piped to stdin.
fn sc_stdin(dir: &Path, args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sc spawns");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().expect("sc runs")
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-stdin-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// keygen an identity, returning (identity_file_path, public_key_string).
/// Keys live OUTSIDE the work tree (the P5 scanner flags scl-sk- in-tree).
fn keygen(dir: &Path, name: &str) -> (std::path::PathBuf, String) {
    let idfile = dir.join(format!("{name}.id"));
    let out = sc(dir, &["keygen", "--out", idfile.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pk = stdout
        .lines()
        .find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("public key in keygen output")
        .to_string();
    (idfile, pk)
}

#[test]
fn secret_add_and_rotate_read_value_from_stdin() {
    let root = tmp("addrot");
    let keys = tmp("addrot-keys");
    let (alice_id, alice_pk) = keygen(&keys, "alice");

    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(
        repo.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{alice_pk}\"\n"),
    )
    .unwrap();

    // add: no --value → value comes from stdin (trailing newline trimmed).
    let out = sc_stdin(&repo, &["secret", "add", "DB_URL", "--to", "alice"], "v0\n");
    assert!(
        out.status.success(),
        "add: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let code = sc(
        &repo,
        &[
            "run",
            "--identity",
            alice_id.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "test \"$DB_URL\" = v0",
        ],
    )
    .status
    .code()
    .unwrap();
    assert_eq!(code, 0, "run injected the stdin-supplied value");

    // rotate: --value-stdin → new value from stdin, fresh DEK, no argv leak.
    let out = sc_stdin(
        &repo,
        &["secret", "rotate", "DB_URL", "--value-stdin"],
        "v1\n",
    );
    assert!(
        out.status.success(),
        "rotate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let code = sc(
        &repo,
        &[
            "run",
            "--identity",
            alice_id.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "test \"$DB_URL\" = v1",
        ],
    )
    .status
    .code()
    .unwrap();
    assert_eq!(code, 0, "run injected the rotated stdin value");

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}
