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
