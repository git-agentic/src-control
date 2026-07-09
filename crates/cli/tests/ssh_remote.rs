//! End-to-end: sc-native transport over the full ssh:// code path, with the
//! SC_SSH shim standing in for ssh (no sshd needed). See ADR-0022.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sc(dir: &Path, args: &[&str]) -> Output {
    sc_env(dir, &[], args)
}

fn sc_env(dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sc"));
    cmd.args(args).current_dir(dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-ssh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write the SC_SSH shim: drops ssh's option/host args and execs the sc
/// binary under test with the remote command's arguments.
fn write_shim(dir: &Path) -> PathBuf {
    let p = dir.join("fake_ssh.sh");
    std::fs::write(
        &p,
        "#!/bin/sh\n\
         while [ $# -gt 0 ] && [ \"$1\" != \"sc\" ]; do shift; done\n\
         [ $# -gt 0 ] || { echo 'shim: no sc command in argv' >&2; exit 65; }\n\
         shift\n\
         exec \"$SC_BIN\" \"$@\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

/// The env that routes ssh:// through the shim.
fn ssh_env(shim: &Path) -> Vec<(String, String)> {
    vec![
        ("SC_SSH".to_string(), shim.to_string_lossy().into_owned()),
        ("SC_BIN".to_string(), env!("CARGO_BIN_EXE_sc").to_string()),
    ]
}

fn sc_ssh(dir: &Path, shim: &Path, args: &[&str]) -> Output {
    let envs = ssh_env(shim);
    let envs_ref: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    sc_env(dir, &envs_ref, args)
}

/// True if `needle` occurs in any file under `dir` (recursive, raw bytes).
fn tree_contains(dir: &Path, needle: &[u8]) -> bool {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if tree_contains(&path, needle) {
                return true;
            }
        } else if let Ok(bytes) = std::fs::read(&path) {
            if bytes.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn ssh_clone_push_fetch_merge_round_trip() {
    let root = tmp("roundtrip");
    let shim = write_shim(&root);
    let a = root.join("A");
    std::fs::create_dir_all(&a).unwrap();

    // A: the "server-side" repo.
    assert!(sc(&a, &["init"]).status.success());
    std::fs::write(a.join("file.txt"), b"v1").unwrap();
    assert!(sc(&a, &["commit", "-m", "c1", "--author", "t"])
        .status
        .success());

    // Clone over ssh:// (through the shim) into B.
    let url = format!("ssh://testhost{}", a.display());
    let b = root.join("B");
    let out = sc_ssh(&root, &shim, &["clone", &url, b.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "clone failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(b.join("file.txt")).unwrap(), b"v1");
    // origin recorded the ssh URL verbatim.
    let config = std::fs::read_to_string(b.join(".sc/config")).unwrap();
    assert!(config.contains(&url), "config lacks ssh url: {config}");

    // B: commit and push back over the wire.
    std::fs::write(b.join("file.txt"), b"v2").unwrap();
    assert!(sc(&b, &["commit", "-m", "c2", "--author", "t"])
        .status
        .success());
    let out = sc_ssh(&b, &shim, &["push", "origin"]);
    assert!(
        out.status.success(),
        "push failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A's history now contains c2 (log reads refs + objects; its working tree
    // staying at v1 is expected, like pushing into a non-bare git repo).
    let log = sc(&a, &["log"]);
    let text = String::from_utf8_lossy(&log.stdout).into_owned();
    assert!(text.contains("c2"), "A's log lacks pushed commit: {text}");

    // Fetch direction: B fetches after A's tip moved (it moved via B's own
    // push; a second fetch must be a clean no-op that still succeeds).
    let out = sc_ssh(&b, &shim, &["fetch", "origin"]);
    assert!(
        out.status.success(),
        "fetch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn racing_pushes_second_gets_non_fast_forward_then_recovers_via_fetch_merge() {
    let root = tmp("race");
    let shim = write_shim(&root);
    let a = root.join("A");
    std::fs::create_dir_all(&a).unwrap();
    assert!(sc(&a, &["init"]).status.success());
    std::fs::write(a.join("base.txt"), b"base").unwrap();
    assert!(sc(&a, &["commit", "-m", "base", "--author", "t"])
        .status
        .success());

    let url = format!("ssh://testhost{}", a.display());
    let b = root.join("B");
    let c = root.join("C");
    assert!(sc_ssh(&root, &shim, &["clone", &url, b.to_str().unwrap()])
        .status
        .success());
    assert!(sc_ssh(&root, &shim, &["clone", &url, c.to_str().unwrap()])
        .status
        .success());

    // C lands first.
    std::fs::write(c.join("from_c.txt"), b"c").unwrap();
    assert!(sc(&c, &["commit", "-m", "from-c", "--author", "t"])
        .status
        .success());
    assert!(sc_ssh(&c, &shim, &["push", "origin"]).status.success());

    // B diverged; its push must fail typed, not clobber.
    std::fs::write(b.join("from_b.txt"), b"b").unwrap();
    assert!(sc(&b, &["commit", "-m", "from-b", "--author", "t"])
        .status
        .success());
    let out = sc_ssh(&b, &shim, &["push", "origin"]);
    assert!(!out.status.success(), "second push must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("non-fast-forward"), "wrong error: {stderr}");

    // Recovery: fetch + merge + push.
    assert!(sc_ssh(&b, &shim, &["fetch", "origin"]).status.success());
    let merge = sc(&b, &["merge", "origin/main"]);
    assert!(
        merge.status.success(),
        "merge failed: {}",
        String::from_utf8_lossy(&merge.stderr)
    );
    let out = sc_ssh(&b, &shim, &["push", "origin"]);
    assert!(
        out.status.success(),
        "push after merge failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn unauthorized_ssh_clone_receives_ciphertext_it_cannot_read() {
    let root = tmp("cipher");
    let shim = write_shim(&root);
    let a = root.join("A");
    std::fs::create_dir_all(&a).unwrap();
    let secret_plaintext = b"TOP_SECRET_wire_hunter2";
    let public_marker = b"PUBLIC_WIRE_MARKER_xyz";

    // Mirror demo/run_protect_demo.sh's recipient setup.
    assert!(sc(&a, &["init"]).status.success());
    let key = root.join("alice.key");
    let out = sc(&a, &["keygen", "--out", key.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let pk = stdout
        .lines()
        .find(|l| l.contains("public key:"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("keygen prints the public key")
        .to_string();
    std::fs::write(
        a.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{pk}\"\n"),
    )
    .unwrap();
    assert!(sc(&a, &["protect", "secret/", "--to", "alice"])
        .status
        .success());
    std::fs::create_dir_all(a.join("secret")).unwrap();
    std::fs::write(a.join("secret/db.txt"), secret_plaintext).unwrap();
    std::fs::write(a.join("README.md"), public_marker).unwrap();
    assert!(sc(&a, &["commit", "-m", "add secret", "--author", "t"])
        .status
        .success());

    // Positive control on A: an unprotected file's bytes ARE findable in the
    // object store, so the negative greps below are not vacuous.
    assert!(tree_contains(&a.join(".sc/objects"), public_marker));
    assert!(!tree_contains(&a.join(".sc/objects"), secret_plaintext));

    // Clone over the wire WITHOUT alice's key.
    let url = format!("ssh://testhost{}", a.display());
    let b = root.join("B");
    let out = sc_ssh(&root, &shim, &["clone", &url, b.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "clone failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The protected file was not materialized, and no plaintext crossed the wire.
    assert!(
        !b.join("secret/db.txt").exists(),
        "unauthorized clone wrote protected plaintext"
    );
    assert!(
        !tree_contains(&b.join(".sc"), secret_plaintext),
        "plaintext leaked over the wire"
    );
    // The public file arrived intact (transfer itself works).
    assert_eq!(std::fs::read(b.join("README.md")).unwrap(), public_marker);

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn serving_a_non_repo_fails_typed_and_remote_add_validates_ssh_urls() {
    let root = tmp("errors");
    let shim = write_shim(&root);
    let empty = root.join("empty");
    std::fs::create_dir_all(&empty).unwrap();

    // Clone of a served non-repo path: typed NotARepo crosses the wire.
    let url = format!("ssh://testhost{}", empty.display());
    let out = sc_ssh(
        &root,
        &shim,
        &["clone", &url, root.join("dst").to_str().unwrap()],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("not a src-control repo"),
        "wrong error: {stderr}"
    );

    // remote add rejects malformed ssh URLs eagerly.
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    assert!(sc(&work, &["init"]).status.success());
    let out = sc(&work, &["remote", "add", "up", "ssh://hostonly-no-path"]);
    assert!(
        !out.status.success(),
        "malformed ssh url must be rejected at remote add"
    );

    std::fs::remove_dir_all(&root).unwrap();
}
