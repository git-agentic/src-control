//! P30 Task 5: CLI surface for session transcripts — `sc transcript
//! attach/show/list/sign`, `sc ws harvest --transcript`, and the `sc log`
//! presence marker. Modeled on `provenance.rs`'s keygen/recipients-config
//! pattern.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sc"));
    c.args(args).current_dir(dir);
    c.env_remove("SC_AUTHOR");
    c.output().expect("sc runs")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-transcripts-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// keygen a v2 identity OUTSIDE the working tree (the P5 scanner flags
/// private key material found inside one), returning (identity file path,
/// encryption pubkey string, signing pubkey string).
fn keygen(keys_dir: &Path, name: &str) -> (std::path::PathBuf, String, String) {
    let idfile = keys_dir.join(format!("{name}.id"));
    let out = sc(keys_dir, &["keygen", "--out", idfile.to_str().unwrap()]);
    assert!(out.status.success(), "keygen: {}", String::from_utf8_lossy(&out.stderr));
    let text = stdout(&out);
    let enc_pk = text
        .lines()
        .find_map(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("keygen prints an encryption public key")
        .to_string();
    let sig_pk = text
        .lines()
        .find_map(|l| l.split_whitespace().find(|w| w.starts_with("scl-sig-")))
        .expect("keygen prints a signing public key")
        .to_string();
    (idfile, enc_pk, sig_pk)
}

#[test]
fn attach_list_show_and_log_marker_round_trip() {
    let root = tmp("basic");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();

    let (id, enc_pk, _sig_pk) = keygen(&keys, "alice");

    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(
        repo.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{enc_pk}\"\n"),
    )
    .unwrap();

    std::fs::write(repo.join("a.txt"), "hello\n").unwrap();
    assert!(sc(&repo, &["commit", "-m", "c1"]).status.success());

    // Transcript body lives outside the working tree.
    let body_path = outside.join("session.txt");
    std::fs::write(&body_path, "USER: fix the bug\nAGENT: done\n").unwrap();

    let attach = sc(
        &repo,
        &[
            "transcript",
            "attach",
            "main",
            body_path.to_str().unwrap(),
            "--agent",
            "claude",
            "--sign",
            "--identity",
            id.to_str().unwrap(),
        ],
    );
    assert!(attach.status.success(), "transcript attach: {}", String::from_utf8_lossy(&attach.stderr));
    let attach_out = stdout(&attach);
    assert!(!attach_out.trim().is_empty(), "attach prints the transcript id");

    // list shows the tip carrying a transcript.
    let list = sc(&repo, &["transcript", "list"]);
    assert!(list.status.success(), "transcript list: {}", String::from_utf8_lossy(&list.stderr));
    let list_out = stdout(&list);
    assert!(list_out.contains("claude"), "list names the agent: {list_out}");

    // show decrypts and prints the body.
    let show = sc(&repo, &["transcript", "show", "main", "--identity", id.to_str().unwrap()]);
    assert!(show.status.success(), "transcript show: {}", String::from_utf8_lossy(&show.stderr));
    let show_out = stdout(&show);
    assert!(show_out.contains("USER: fix the bug"), "show prints the plaintext body: {show_out}");

    // sc log carries a transcript presence marker on that commit.
    let log = stdout(&sc(&repo, &["log"]));
    assert!(log.contains("transcript"), "log shows a transcript marker: {log}");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn show_without_identity_errors_clearly() {
    let root = tmp("noidentity");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();

    let (id, enc_pk, _sig_pk) = keygen(&keys, "alice");
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(
        repo.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{enc_pk}\"\n"),
    )
    .unwrap();
    std::fs::write(repo.join("a.txt"), "hello\n").unwrap();
    assert!(sc(&repo, &["commit", "-m", "c1"]).status.success());

    let body_path = outside.join("session.txt");
    std::fs::write(&body_path, "body").unwrap();
    assert!(sc(
        &repo,
        &["transcript", "attach", "main", body_path.to_str().unwrap(), "--identity", id.to_str().unwrap()]
    )
    .status
    .success());

    // No identity resolvable (no ~/.sc/identity, no SC_IDENTITY, no --identity).
    let mut c = Command::new(env!("CARGO_BIN_EXE_sc"));
    c.args(["transcript", "show", "main"]).current_dir(&repo);
    c.env_remove("SC_AUTHOR");
    c.env_remove("SC_IDENTITY");
    c.env("HOME", root.join("no-such-home").to_str().unwrap());
    let show = c.output().expect("sc runs");
    assert!(!show.status.success(), "show without a resolvable identity must fail, not silently print nothing");

    std::fs::remove_dir_all(&root).unwrap();
}
