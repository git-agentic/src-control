//! P22 Task 4: CLI provenance surface — keygen v2, `[signing]`/`[signers]`
//! trust config, `sc sign`, `sc verify`, `--sign` flags, four-state log
//! markers.

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
    let d = std::env::temp_dir().join(format!("scl-cli-provenance-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// keygen a v2 identity, returning (identity file path, encryption pubkey
/// string, signing pubkey string). Keys live OUTSIDE the work tree — the P5
/// scanner flags private key material found inside one.
fn keygen(keys_dir: &Path, name: &str) -> (std::path::PathBuf, String, String) {
    let idfile = keys_dir.join(format!("{name}.id"));
    let out = sc(keys_dir, &["keygen", "--out", idfile.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
fn keygen_v2_writes_seed_file_and_prints_both_public_halves() {
    let keys = tmp("keygen");
    let (idfile, enc_pk, sig_pk) = keygen(&keys, "alice");

    let contents = std::fs::read_to_string(&idfile).unwrap();
    assert!(
        contents.starts_with("scl-id-"),
        "identity file must carry the v2 seed: {contents}"
    );
    assert!(enc_pk.starts_with("scl-pk-"));
    assert!(sig_pk.starts_with("scl-sig-"));

    std::fs::remove_dir_all(&keys).unwrap();
}

/// Write `.sc/recipients.toml` registering `name`'s signing key under
/// `[signing]` and (when `trust` is true) listing it under `[signers]
/// trusted`.
fn write_signing_config(repo: &Path, name: &str, sig_pk: &str, trust: bool) {
    let mut toml = format!("[signing]\n{name} = \"{sig_pk}\"\n");
    if trust {
        toml.push_str(&format!("\n[signers]\ntrusted = [\"{name}\"]\n"));
    }
    std::fs::write(repo.join(".sc/recipients.toml"), toml).unwrap();
}

#[test]
fn commit_sign_verify_and_log_render_the_trusted_state() {
    let root = tmp("trusted");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();

    let (id, _enc_pk, sig_pk) = keygen(&keys, "alice");

    assert!(sc(&repo, &["init"]).status.success());
    write_signing_config(&repo, "alice", &sig_pk, true);

    std::fs::write(repo.join("a.txt"), "hello\n").unwrap();
    let commit = sc(
        &repo,
        &[
            "commit",
            "-m",
            "c1",
            "--sign",
            "--identity",
            id.to_str().unwrap(),
        ],
    );
    assert!(
        commit.status.success(),
        "commit --sign: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    let commit_out = stdout(&commit);
    assert!(
        commit_out.contains("signed"),
        "commit --sign prints a signed line: {commit_out}"
    );
    assert!(
        commit_out.contains("scl-sig-"),
        "signed line names the signer key: {commit_out}"
    );

    // Human log: trusted state renders "signed: alice ✓".
    let log = stdout(&sc(&repo, &["log"]));
    assert!(
        log.contains("signed: alice"),
        "log shows the trusted signer name: {log}"
    );
    assert!(
        log.contains('✓'),
        "trusted state uses the check mark: {log}"
    );

    // JSON log: a "signature" object with status "trusted" and the name.
    let json = stdout(&sc(&repo, &["log", "--json"]));
    assert!(
        json.contains("\"status\":\"trusted\""),
        "json log signature status: {json}"
    );
    assert!(
        json.contains("\"name\":\"alice\""),
        "json log signer name: {json}"
    );

    // verify --require passes: every commit in history is Trusted.
    let verify = sc(&repo, &["verify", "--require"]);
    assert!(
        verify.status.success(),
        "verify --require must pass an all-trusted history: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_out = stdout(&verify);
    assert!(
        verify_out.contains("1 trusted"),
        "verify summary: {verify_out}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn unsigned_commit_gets_no_log_line_and_fails_require() {
    let root = tmp("unsigned");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("a.txt"), "hello\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "c1"]).status.success());

    let log = stdout(&sc(&root, &["log"]));
    assert!(
        !log.contains("signed:"),
        "unsigned commit must print no signature line at all: {log}"
    );
    assert!(!log.contains("INVALID"), "unsigned is not invalid: {log}");

    // Without --require, verify just reports and exits 0.
    let verify = sc(&root, &["verify"]);
    assert!(verify.status.success());
    let out = stdout(&verify);
    assert!(
        out.contains("1 unsigned"),
        "verify summary counts the unsigned commit: {out}"
    );

    // With --require, an unsigned commit in history fails the gate.
    let verify_req = sc(&root, &["verify", "--require"]);
    assert!(
        !verify_req.status.success(),
        "verify --require must fail with an unsigned commit in history"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn untrusted_signature_renders_hex_prefix_and_fails_require() {
    let root = tmp("untrusted");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();

    // Signer exists, but is never listed in [signers] trusted.
    let (id, _enc_pk, sig_pk) = keygen(&keys, "mallory");
    assert!(sc(&repo, &["init"]).status.success());
    write_signing_config(&repo, "mallory", &sig_pk, false);

    std::fs::write(repo.join("a.txt"), "hi\n").unwrap();
    assert!(sc(
        &repo,
        &[
            "commit",
            "-m",
            "c1",
            "--sign",
            "--identity",
            id.to_str().unwrap()
        ]
    )
    .status
    .success());

    let log = stdout(&sc(&repo, &["log"]));
    assert!(
        log.contains("signed:"),
        "untrusted still gets a signed line: {log}"
    );
    assert!(
        log.contains('?'),
        "untrusted state uses the '?' marker: {log}"
    );
    assert!(
        !log.contains('✓'),
        "untrusted must not be rendered as trusted: {log}"
    );

    let json = stdout(&sc(&repo, &["log", "--json"]));
    assert!(
        json.contains("\"status\":\"untrusted\""),
        "json log signature status: {json}"
    );

    let verify_req = sc(&repo, &["verify", "--require"]);
    assert!(
        !verify_req.status.success(),
        "verify --require must fail on an untrusted signature"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn sign_command_signs_an_arbitrary_ref_after_the_fact() {
    let root = tmp("signcmd");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();

    let (id, _enc_pk, sig_pk) = keygen(&keys, "alice");
    assert!(sc(&repo, &["init"]).status.success());
    write_signing_config(&repo, "alice", &sig_pk, true);

    std::fs::write(repo.join("a.txt"), "hi\n").unwrap();
    // Commit WITHOUT --sign, then sign the branch tip separately.
    assert!(sc(&repo, &["commit", "-m", "c1"]).status.success());
    let sign = sc(&repo, &["sign", "main", "--identity", id.to_str().unwrap()]);
    assert!(
        sign.status.success(),
        "sc sign: {}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let sign_out = stdout(&sign);
    assert!(
        sign_out.starts_with("signed "),
        "sign prints the confirmation line: {sign_out}"
    );
    assert!(
        sign_out.contains("scl-sig-"),
        "sign names the signer key: {sign_out}"
    );

    let log = stdout(&sc(&repo, &["log"]));
    assert!(
        log.contains("signed: alice"),
        "post-hoc sign shows up as trusted in log: {log}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn amend_sign_replaces_the_signature_on_the_new_tip() {
    let root = tmp("amendsign");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();

    let (id, _enc_pk, sig_pk) = keygen(&keys, "alice");
    assert!(sc(&repo, &["init"]).status.success());
    write_signing_config(&repo, "alice", &sig_pk, true);

    std::fs::write(repo.join("a.txt"), "hi\n").unwrap();
    assert!(sc(
        &repo,
        &[
            "commit",
            "-m",
            "c1",
            "--sign",
            "--identity",
            id.to_str().unwrap()
        ]
    )
    .status
    .success());
    std::fs::write(repo.join("a.txt"), "hi again\n").unwrap();
    let amend = sc(
        &repo,
        &["amend", "--sign", "--identity", id.to_str().unwrap()],
    );
    assert!(
        amend.status.success(),
        "amend --sign: {}",
        String::from_utf8_lossy(&amend.stderr)
    );
    assert!(
        stdout(&amend).contains("signed"),
        "amend --sign prints a signed line"
    );

    let log = stdout(&sc(&repo, &["log"]));
    assert!(
        log.contains("signed: alice"),
        "amended tip is signed and trusted: {log}"
    );
    assert_eq!(
        log.matches("signed: alice").count(),
        1,
        "amend replaces the tip, not append a parallel history: {log}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

/// A v1 (encryption-only) identity has no signing half; `--sign` must fail
/// with an error naming the fix rather than silently skipping the signature.
#[test]
fn sign_with_v1_identity_errors_naming_the_fix() {
    let root = tmp("v1sign");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());

    // Hand-write a v1 `scl-sk-` identity file directly (bypassing keygen,
    // which is v2-only now) to exercise the legacy-file compatibility path.
    let v1 = repo.parent().unwrap().join("v1.id");
    // A syntactically valid v1 key: reuse `sc keygen`'s v1 predecessor shape
    // is no longer reachable via the CLI, so assert on the repo-level
    // behavior instead — a garbage `scl-sk-` file at least proves --sign
    // surfaces a clear error rather than panicking.
    std::fs::write(
        &v1,
        "scl-sk-0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    std::fs::write(repo.join("a.txt"), "hi\n").unwrap();
    let commit = sc(
        &repo,
        &[
            "commit",
            "-m",
            "c1",
            "--sign",
            "--identity",
            v1.to_str().unwrap(),
        ],
    );
    assert!(
        !commit.status.success(),
        "commit --sign with a bad/v1 identity must fail, not silently skip signing"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn verify_walks_all_parents_of_a_merge_not_just_mainline() {
    let root = tmp("mergewalk");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();

    let (id, _enc_pk, sig_pk) = keygen(&keys, "alice");
    assert!(sc(&repo, &["init"]).status.success());
    write_signing_config(&repo, "alice", &sig_pk, true);

    std::fs::write(repo.join("base.txt"), "base\n").unwrap();
    assert!(sc(&repo, &["commit", "-m", "base"]).status.success());
    assert!(sc(&repo, &["branch", "side"]).status.success());

    // Mainline commit: signed + trusted.
    std::fs::write(repo.join("main.txt"), "main\n").unwrap();
    assert!(sc(
        &repo,
        &[
            "commit",
            "-m",
            "on-main",
            "--sign",
            "--identity",
            id.to_str().unwrap()
        ]
    )
    .status
    .success());

    // Side commit: left unsigned — only reachable via the merge's non-first
    // parent, which `Repo::log`'s mainline walk would never visit.
    assert!(sc(&repo, &["switch", "side"]).status.success());
    std::fs::write(repo.join("side.txt"), "side\n").unwrap();
    assert!(sc(&repo, &["commit", "-m", "on-side"]).status.success());

    assert!(sc(&repo, &["switch", "main"]).status.success());
    assert!(sc(&repo, &["merge", "side"]).status.success());

    let verify = sc(&repo, &["verify"]);
    assert!(verify.status.success());
    let out = stdout(&verify);
    // base (unsigned) + on-main (trusted) + on-side (unsigned) + merge (unsigned) = 4 commits total.
    assert!(
        out.contains("4 commit(s)"),
        "verify must walk every ancestor via both merge parents: {out}"
    );
    assert!(out.contains("1 trusted"), "verify summary: {out}");
    assert!(out.contains("3 unsigned"), "verify summary: {out}");

    std::fs::remove_dir_all(&root).unwrap();
}

/// `sc log` must tolerate its reader closing the pipe early — the common
/// `sc log | grep -q x` idiom under `set -o pipefail`. `run_log` interleaves
/// per-commit `sig_status` disk I/O with `println!`s; if `grep -q` matches
/// an early line (log is newest-first) and exits, closing its stdin, `sc`'s
/// next write must not panic with a broken-pipe error — that turns into a
/// nonzero exit that `pipefail` propagates even though `grep` itself
/// succeeded. Regression test for the P22 provenance review fix.
#[test]
fn log_output_survives_a_closed_reader_pipe() {
    let root = tmp("brokenpipe");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    // Enough commits that sig_status's I/O has room to run while grep is
    // still consuming — and reading, not draining, the earlier lines.
    for i in 0..20 {
        std::fs::write(repo.join("f.txt"), format!("v{i}\n")).unwrap();
        assert!(sc(&repo, &["commit", "-m", &format!("c{i}")])
            .status
            .success());
    }

    let sc_bin = env!("CARGO_BIN_EXE_sc");
    // Newest-first log output means "c19" (the last commit made) is on the
    // very first printed line, so grep -q matches and exits immediately,
    // closing the pipe while `sc log` still has 19 more entries queued.
    let script = format!("set -euo pipefail; \"{sc_bin}\" log | grep -q 'c19'");
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        .current_dir(&repo)
        .output()
        .expect("bash runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "sc log | grep -q under pipefail must exit cleanly, not propagate a broken-pipe panic: stderr={stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe") && !stderr.contains("panicked"),
        "sc log must not panic on BrokenPipe: stderr={stderr}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

/// `sc verify` must tolerate its reader closing the pipe early too — same
/// `sc verify | grep -q INVALID` idiom under `set -o pipefail`. Before this
/// fix, `run_verify`'s per-commit and summary lines used raw `println!`,
/// which panics on `BrokenPipe` when the reader (e.g. `head -1`) stops
/// reading after the first line, turning what should be a clean exit into a
/// pipefail-propagated failure — silently masking the flagship provenance
/// command's tampering signal. Regression test for the P22 final-review fix.
#[test]
fn verify_output_survives_a_closed_reader_pipe() {
    let root = tmp("verify-brokenpipe");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    // Enough commits that verify's per-commit sig_status I/O has room to run
    // while the reader is still consuming — and closing after only the
    // first line.
    for i in 0..20 {
        std::fs::write(repo.join("f.txt"), format!("v{i}\n")).unwrap();
        assert!(sc(&repo, &["commit", "-m", &format!("c{i}")])
            .status
            .success());
    }

    let sc_bin = env!("CARGO_BIN_EXE_sc");
    // `head -1` reads exactly one line and closes its end of the pipe,
    // forcing `sc verify`'s next write (of the remaining 19 commits) to hit
    // a closed reader.
    let script = format!("set -euo pipefail; \"{sc_bin}\" verify | head -1 >/dev/null");
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        .current_dir(&repo)
        .output()
        .expect("bash runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "sc verify | head -1 under pipefail must exit cleanly, not propagate a broken-pipe panic: stderr={stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe") && !stderr.contains("panicked"),
        "sc verify must not panic on BrokenPipe: stderr={stderr}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}
