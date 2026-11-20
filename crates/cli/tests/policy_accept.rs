//! ADR-0059: `sc policy accept|forget` and the refusals they answer.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-policy-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// keygen an identity, returning (identity file, public key string).
fn keygen(dir: &Path, name: &str) -> (std::path::PathBuf, String) {
    let idfile = dir.join(format!("{name}.id"));
    let out = sc(dir, &["keygen", "--out", idfile.to_str().unwrap()]);
    assert!(out.status.success(), "keygen: {}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let pk = text
        .lines()
        .find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("public key in keygen output")
        .to_string();
    (idfile, pk)
}

fn record(repo: &Path) -> String {
    std::fs::read_to_string(repo.join(".sc/accepted-recipients")).unwrap_or_default()
}

#[test]
fn accept_checks_the_key_is_known_and_forget_removes_it() {
    let root = tmp("accept");
    let keys = tmp("accept-keys");
    let (_, alice_pk) = keygen(&keys, "alice");
    let (_, stranger_pk) = keygen(&keys, "stranger");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(
        root.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{alice_pk}\"\n"),
    )
    .unwrap();

    // A key from the local recipients file is accepted as is.
    let out = sc(&root, &["policy", "accept", "secret:X", "--key", &alice_pk]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(record(&root).starts_with("secret:X\t"), "{}", record(&root));

    // One the clone has never heard of needs the explicit flag.
    let out = sc(
        &root,
        &["policy", "accept", "path:a/", "--key", &stranger_pk],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--allow-unknown"), "{}", stderr(&out));
    assert!(!record(&root).contains("path:a/"));
    let out = sc(
        &root,
        &[
            "policy",
            "accept",
            "path:a/",
            "--key",
            &stranger_pk,
            "--allow-unknown",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(record(&root).contains("path:a/\t"));

    // A scope has a kind.
    let out = sc(&root, &["policy", "accept", "a/", "--key", &alice_pk]);
    assert!(!out.status.success());

    let out = sc(&root, &["policy", "forget", "path:a/", &stranger_pk]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!record(&root).contains("path:a/"));
    assert!(record(&root).contains("secret:X\t"), "other pairs stay");

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

#[test]
fn accept_works_while_a_merge_is_stopped() {
    let root = tmp("stopped");
    let keys = tmp("stopped-keys");
    let (_, pk) = keygen(&keys, "k");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("file.txt"), "base\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "base"]).status.success());
    assert!(sc(&root, &["branch", "feature"]).status.success());
    std::fs::write(root.join("file.txt"), "ours\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "ours"]).status.success());
    assert!(sc(&root, &["switch", "feature"]).status.success());
    std::fs::write(root.join("file.txt"), "theirs\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "theirs"]).status.success());
    assert!(sc(&root, &["switch", "main"]).status.success());
    assert_eq!(sc(&root, &["merge", "feature"]).status.code(), Some(1));

    let out = sc(
        &root,
        &[
            "policy",
            "accept",
            "path:docs/",
            "--key",
            &pk,
            "--allow-unknown",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(record(&root).contains("path:docs/\t"));
    let out = sc(&root, &["policy", "forget", "path:docs/", &pk]);
    assert!(out.status.success(), "{}", stderr(&out));
    // The stop is still there.
    assert!(String::from_utf8_lossy(&sc(&root, &["conflicts"]).stdout).contains("file.txt"));

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}

/// A repo with `alice` in recipients.toml, `secret/` protected for her and a
/// secret `DB` added for her, and a fresh clone of it with the same
/// recipients file (the record is never copied).
fn origin_and_clone(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, String, String) {
    let root = tmp(tag);
    // Keys live beside the working trees, not in them (the scanner flags them).
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let (alice_id, alice_pk) = keygen(&keys, "alice");
    let a = root.join("a");
    std::fs::create_dir_all(&a).unwrap();
    assert!(sc(&a, &["init"]).status.success());
    let toml = format!("[recipients]\nalice = \"{alice_pk}\"\n");
    std::fs::write(a.join(".sc/recipients.toml"), &toml).unwrap();
    std::fs::create_dir_all(a.join("secret")).unwrap();
    std::fs::write(a.join("secret/a.txt"), "data\n").unwrap();
    let out = sc(&a, &["protect", "secret/", "--to", "alice"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = sc(
        &a,
        &["secret", "add", "DB", "--to", "alice", "--value", "v0"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    // The origin never needed an accept: it named alice itself.
    let out = sc(
        &a,
        &[
            "secret",
            "rotate",
            "DB",
            "--identity",
            alice_id.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    let b = root.join("b");
    let out = sc(&root, &["clone", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    std::fs::write(b.join(".sc/recipients.toml"), &toml).unwrap();
    assert!(!b.join(".sc/accepted-recipients").exists());
    (root, b, alice_pk, alice_id.to_str().unwrap().to_string())
}

#[test]
fn a_fresh_clone_refuses_a_rule_seal_until_the_key_is_accepted() {
    let (root, b, alice_pk, _) = origin_and_clone("clone-commit");
    std::fs::create_dir_all(b.join("secret")).unwrap();
    std::fs::write(b.join("secret/b.txt"), "more\n").unwrap();

    let out = sc(&b, &["commit", "-m", "seal"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    for want in [
        "path:secret/ grants a recipient you have not accepted",
        "(alice)",
        "sc policy accept path:secret/ --key",
        "sc revoke secret/ --recipient-id",
        "Nothing was written.",
    ] {
        assert!(err.contains(want), "missing {want:?} in: {err}");
    }

    let out = sc(
        &b,
        &["policy", "accept", "path:secret/", "--key", &alice_pk],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let out = sc(&b, &["commit", "-m", "seal"]);
    assert!(out.status.success(), "{}", stderr(&out));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_fresh_clone_refuses_a_default_secret_rotate_until_accepted() {
    let (root, b, alice_pk, alice_id) = origin_and_clone("clone-rotate");
    let rotate = |dir: &Path| sc(dir, &["secret", "rotate", "DB", "--identity", &alice_id]);

    let out = rotate(&b);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("secret:DB grants a recipient you have not accepted")
            && err.contains("sc policy accept secret:DB --key")
            && err.contains("sc secret revoke DB --recipient-id"),
        "{err}"
    );

    // Naming the key on the command line accepts it, like add does.
    let out = sc(
        &b,
        &[
            "secret",
            "rotate",
            "DB",
            "--to",
            "alice",
            "--identity",
            &alice_id,
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(record(&b).contains("secret:DB\t"));
    assert!(rotate(&b).status.success(), "default set now accepted");

    let _ = alice_pk;
    std::fs::remove_dir_all(&root).unwrap();
}
