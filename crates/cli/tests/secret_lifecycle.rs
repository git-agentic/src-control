//! End-to-end: sc secret rotate and escrow.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc")).args(args).current_dir(dir).output().expect("sc runs")
}
fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-lifecycle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
/// keygen an identity, returning (identity_file_path, public_key_string).
fn keygen(dir: &Path, name: &str) -> (std::path::PathBuf, String) {
    let idfile = dir.join(format!("{name}.id"));
    let out = sc(dir, &["keygen", "--out", idfile.to_str().unwrap()]);
    assert!(out.status.success(), "keygen: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pk = stdout.lines().find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("public key in keygen output").to_string();
    (idfile, pk)
}

#[test]
fn secret_rotate_new_value_changes_what_run_injects() {
    let root = tmp("rotate");
    // keys live OUTSIDE the work tree (P5 scanner would flag scl-sk- in-tree).
    let keys = tmp("rotate-keys");
    let (alice_id, alice_pk) = keygen(&keys, "alice");

    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(repo.join(".sc/recipients.toml"), format!("[recipients]\nalice = \"{alice_pk}\"\n")).unwrap();

    assert!(sc(&repo, &["secret", "add", "DB_URL", "--to", "alice", "--value", "v0"]).status.success());
    // Rotate to a new value; recipients default to the current set (alice).
    let out = sc(&repo, &["secret", "rotate", "DB_URL", "--value", "v1"]);
    assert!(out.status.success(), "rotate: {}", String::from_utf8_lossy(&out.stderr));

    // run injects the NEW value.
    let code = sc(&repo, &["run", "--identity", alice_id.to_str().unwrap(),
        "--", "sh", "-c", "test \"$DB_URL\" = v1"]).status.code().unwrap();
    assert_eq!(code, 0, "run injected the rotated value");

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

#[test]
fn escrow_set_and_show_roundtrip() {
    let root = tmp("escrow-cfg");
    let keys = tmp("escrow-cfg-keys");
    let (_e_id, escrow_pk) = keygen(&keys, "escrow");

    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(repo.join(".sc/recipients.toml"), "[recipients]\n").unwrap();

    // show with none set
    let none = sc(&repo, &["escrow", "show"]);
    assert!(none.status.success());
    assert!(String::from_utf8_lossy(&none.stdout).to_lowercase().contains("no escrow"));

    // set by raw pubkey, then show it back + the non-guarantee note
    assert!(sc(&repo, &["escrow", "set", &escrow_pk]).status.success());
    let shown = sc(&repo, &["escrow", "show"]);
    let out = String::from_utf8_lossy(&shown.stdout);
    assert!(out.contains(&escrow_pk), "escrow show prints the key");
    assert!(out.to_lowercase().contains("policy") || out.to_lowercase().contains("not enforce"),
        "escrow show states the non-guarantee");

    // recipients section preserved after the rewrite
    let cfg = std::fs::read_to_string(repo.join(".sc/recipients.toml")).unwrap();
    assert!(cfg.contains("[recipients]"));
    assert!(cfg.contains("[escrow]"));

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

#[test]
fn escrow_is_auto_included_on_add_and_recoverable() {
    let root = tmp("escrow-auto");
    let keys = tmp("escrow-auto-keys");
    let (_a_id, alice_pk) = keygen(&keys, "alice");
    let (escrow_id, escrow_pk) = keygen(&keys, "escrow");

    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(repo.join(".sc/recipients.toml"), format!("[recipients]\nalice = \"{alice_pk}\"\n")).unwrap();
    assert!(sc(&repo, &["escrow", "set", &escrow_pk]).status.success());

    // add a secret only to alice; escrow must be auto-included → 2 recipients.
    assert!(sc(&repo, &["secret", "add", "DB_URL", "--to", "alice", "--value", "topsecret"]).status.success());
    let list = sc(&repo, &["secret", "list"]);
    let out = String::from_utf8_lossy(&list.stdout);
    assert!(out.contains("DB_URL") && out.contains("2 recipient"), "escrow auto-included: {out}");

    // the escrow identity can recover the value.
    let code = sc(&repo, &["run", "--identity", escrow_id.to_str().unwrap(),
        "--", "sh", "-c", "test \"$DB_URL\" = topsecret"]).status.code().unwrap();
    assert_eq!(code, 0, "escrow identity recovers the secret");

    // rotating (default recipients) keeps escrow (still 2, still recoverable).
    assert!(sc(&repo, &["secret", "rotate", "DB_URL", "--value", "rotated"]).status.success());
    let list2 = sc(&repo, &["secret", "list"]);
    assert!(String::from_utf8_lossy(&list2.stdout).contains("2 recipient"), "escrow retained on rotate");
    let code2 = sc(&repo, &["run", "--identity", escrow_id.to_str().unwrap(),
        "--", "sh", "-c", "test \"$DB_URL\" = rotated"]).status.code().unwrap();
    assert_eq!(code2, 0, "escrow recovers the rotated value");

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}
