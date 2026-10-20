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
    assert!(
        attach.status.success(),
        "transcript attach: {}",
        String::from_utf8_lossy(&attach.stderr)
    );
    let attach_out = stdout(&attach);
    assert!(
        !attach_out.trim().is_empty(),
        "attach prints the transcript id"
    );

    // list shows the tip carrying a transcript.
    let list = sc(&repo, &["transcript", "list"]);
    assert!(
        list.status.success(),
        "transcript list: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_out = stdout(&list);
    assert!(
        list_out.contains("claude"),
        "list names the agent: {list_out}"
    );

    // show decrypts and prints the body.
    let show = sc(
        &repo,
        &[
            "transcript",
            "show",
            "main",
            "--identity",
            id.to_str().unwrap(),
        ],
    );
    assert!(
        show.status.success(),
        "transcript show: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    let show_out = stdout(&show);
    assert!(
        show_out.contains("USER: fix the bug"),
        "show prints the plaintext body: {show_out}"
    );

    // sc log carries a transcript presence marker on that commit.
    let log = stdout(&sc(&repo, &["log"]));
    assert!(
        log.contains("transcript"),
        "log shows a transcript marker: {log}"
    );

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
        &[
            "transcript",
            "attach",
            "main",
            body_path.to_str().unwrap(),
            "--identity",
            id.to_str().unwrap()
        ]
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
    assert!(
        !show.status.success(),
        "show without a resolvable identity must fail, not silently print nothing"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

/// P30 t5 review (Important): `sc ws harvest` has already moved the landing
/// refs by the time the `--transcript` attach step runs. If the attach fails
/// for a workspace (here: an empty `[recipients]` set, so
/// `attach_transcript`'s `require_recipients` guard refuses to seal an
/// unreadable transcript), the command must still report that the workspace
/// landed — not abort silently with the ref already moved and nothing
/// printed. This reproduces the ordering bug end to end: fork a workspace,
/// edit it, harvest with `--transcript` in a repo whose recipients set is
/// empty, and assert the landing line is on stdout while the attach warning
/// is on stderr, in that order.
#[test]
fn ws_harvest_transcript_prints_landing_before_reporting_attach_failure() {
    let root = tmp("ws-harvest-attach-fail");
    let repo = root.join("work");
    std::fs::create_dir_all(&repo).unwrap();
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();

    assert!(sc(&repo, &["init"]).status.success());
    // Present but empty: no recipients, no escrow. `transcript_recipients`
    // succeeds with an empty Vec (the file exists, so `load_recipients`
    // doesn't hard-error) — the failure surfaces per-workspace inside
    // `attach_transcript`'s `require_recipients` guard instead.
    std::fs::write(repo.join(".sc/recipients.toml"), "[recipients]\n").unwrap();

    std::fs::write(repo.join("base.txt"), "base\n").unwrap();
    assert!(sc(&repo, &["commit", "-m", "base", "--author", "demo"])
        .status
        .success());

    let fork = sc(&repo, &["ws", "fork", "--agents", "1", "--author", "demo"]);
    assert!(
        fork.status.success(),
        "ws fork: {}",
        String::from_utf8_lossy(&fork.stderr)
    );
    let fork_out = stdout(&fork);
    let ws_dir = fork_out
        .lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().nth(1))
        .expect("fork output names workspace 1's dir");
    std::fs::write(std::path::Path::new(ws_dir).join("new.txt"), "edited\n").unwrap();

    let body_path = outside.join("session.txt");
    std::fs::write(&body_path, "USER: hi\nAGENT: done\n").unwrap();

    let harvest = sc(
        &repo,
        &[
            "ws",
            "harvest",
            "--author",
            "demo",
            "--transcript",
            body_path.to_str().unwrap(),
        ],
    );
    let harvest_stdout = stdout(&harvest);
    let harvest_stderr = String::from_utf8_lossy(&harvest.stderr).into_owned();

    assert!(
        !harvest.status.success(),
        "attach failure must be reported via a non-zero exit, not swallowed: stdout={harvest_stdout} stderr={harvest_stderr}"
    );
    assert!(
        harvest_stdout.contains("1   landed @")
            || harvest_stdout
                .lines()
                .any(|l| l.trim_start().starts_with('1') && l.contains("landed @")),
        "landing status for workspace 1 must still be printed even though the transcript \
         attach failed (the ref already moved by the time attach runs): stdout={harvest_stdout}"
    );
    assert!(
        harvest_stderr.contains("could not be attached"),
        "expected a per-workspace attach-failure warning on stderr: stderr={harvest_stderr}"
    );

    // Ordering: the landing line's position in stdout must not depend on
    // the attach step ever running — assert it unconditionally exists
    // rather than trying to interleave stdout/stderr (separate streams).
    let landed_line = harvest_stdout
        .lines()
        .find(|l| l.contains("landed @"))
        .expect("a landed line must be present in stdout");
    assert!(
        landed_line.trim_start().starts_with('1'),
        "landed line should be for workspace 1: {landed_line}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

/// `--no-transcripts` (#211) fixture: an `origin` repo with a signed commit
/// carrying a signed transcript. Returns (root, origin dir, identity file).
fn origin_with_transcript(
    tag: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let root = tmp(tag);
    let origin = root.join("origin");
    std::fs::create_dir_all(&origin).unwrap();
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let (id, enc_pk, sig_pk) = keygen(&keys, "alice");
    assert!(sc(&origin, &["init"]).status.success());
    std::fs::write(
        origin.join(".sc/recipients.toml"),
        format!(
            "[recipients]\nalice = \"{enc_pk}\"\n\n[signing]\nalice = \"{sig_pk}\"\n\n\
             [signers]\ntrusted = [\"alice\"]\n"
        ),
    )
    .unwrap();
    std::fs::write(origin.join("a.txt"), "hello\n").unwrap();
    assert!(sc(&origin, &["commit", "-m", "c1"]).status.success());
    let idp = id.to_str().unwrap();
    assert!(sc(&origin, &["sign", "main", "--identity", idp])
        .status
        .success());
    let body = keys.join("session.txt");
    std::fs::write(&body, "USER: fix\nAGENT: done\n").unwrap();
    let attach = sc(
        &origin,
        &[
            "transcript",
            "attach",
            "main",
            body.to_str().unwrap(),
            "--agent",
            "claude",
            "--sign",
            "--identity",
            idp,
        ],
    );
    assert!(
        attach.status.success(),
        "{}",
        String::from_utf8_lossy(&attach.stderr)
    );
    (root, origin, id)
}

/// recipients.toml is local config, not cloned: copy it so `sc verify
/// --require` can resolve the trusted signer in `dst`.
fn share_config(origin: &Path, dst: &Path) {
    std::fs::copy(
        origin.join(".sc/recipients.toml"),
        dst.join(".sc/recipients.toml"),
    )
    .unwrap();
}

/// Number of lines in a repo's `.sc/transcripts` index (0 if absent).
fn transcript_index_len(repo: &Path) -> usize {
    std::fs::read_to_string(repo.join(".sc/transcripts"))
        .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

/// The snapshot is intact and verifiable, and the repo shows no transcript.
fn assert_snapshot_ok_and_no_transcript(repo: &Path, refname: &str, file: &str) {
    let cat = sc(repo, &["cat", &format!("{refname}:{file}")]);
    assert!(
        cat.status.success(),
        "snapshot content transfers: {}",
        String::from_utf8_lossy(&cat.stderr)
    );
    let verify = sc(repo, &["verify", "--require", refname]);
    assert!(
        verify.status.success(),
        "snapshot signature verifies: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(transcript_index_len(repo), 0, "no transcript index entry");
    let log = sc(repo, &["log"]);
    assert!(
        log.status.success(),
        "log: {}",
        String::from_utf8_lossy(&log.stderr)
    );
    assert!(
        !stdout(&log).contains("transcript:"),
        "log shows no transcript marker"
    );
}

#[test]
fn clone_no_transcripts_leaves_transcripts_out_and_plain_fetch_brings_them() {
    let (root, origin, id) = origin_with_transcript("nt-clone");
    let dst = root.join("clone");
    let out = sc(
        &root,
        &[
            "clone",
            origin.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--no-transcripts",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    share_config(&origin, &dst);
    assert_snapshot_ok_and_no_transcript(&dst, "main", "a.txt");

    // Per command: a later plain fetch brings the sealed transcript in.
    assert!(sc(&dst, &["fetch"]).status.success());
    assert_eq!(transcript_index_len(&dst), 1);
    let show = sc(
        &dst,
        &[
            "transcript",
            "show",
            "main",
            "--identity",
            id.to_str().unwrap(),
        ],
    );
    assert!(show.status.success());
    assert!(stdout(&show).contains("USER: fix"));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn fetch_no_transcripts_leaves_transcripts_out() {
    let (root, origin, id) = origin_with_transcript("nt-fetch");
    let dst = root.join("clone");
    assert!(sc(
        &root,
        &[
            "clone",
            origin.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--no-transcripts"
        ],
    )
    .status
    .success());
    share_config(&origin, &dst);
    // Origin moves on with a second commit; the clone fetches it opted out.
    std::fs::write(origin.join("b.txt"), "two\n").unwrap();
    assert!(sc(&origin, &["commit", "-m", "c2"]).status.success());
    assert!(sc(
        &origin,
        &["sign", "main", "--identity", id.to_str().unwrap()]
    )
    .status
    .success());
    let out = sc(&dst, &["fetch", "--no-transcripts"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_snapshot_ok_and_no_transcript(&dst, "origin/main", "b.txt");
    assert_eq!(transcript_index_len(&dst), 0);

    assert!(sc(&dst, &["fetch"]).status.success());
    assert_eq!(transcript_index_len(&dst), 1);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn push_no_transcripts_sends_snapshot_but_not_transcript() {
    let (root, origin, id) = origin_with_transcript("nt-push");
    let dst = root.join("clone");
    assert!(sc(
        &root,
        &["clone", origin.to_str().unwrap(), dst.to_str().unwrap()]
    )
    .status
    .success());
    // The clone commits, signs and attaches a transcript, then pushes opted out.
    let idp = id.to_str().unwrap();
    share_config(&origin, &dst);
    std::fs::write(dst.join("b.txt"), "two\n").unwrap();
    assert!(sc(&dst, &["commit", "-m", "c2"]).status.success());
    assert!(sc(&dst, &["sign", "main", "--identity", idp])
        .status
        .success());
    let body = root.join("keys/s2.txt");
    std::fs::write(&body, "second session\n").unwrap();
    assert!(sc(
        &dst,
        &[
            "transcript",
            "attach",
            "main",
            body.to_str().unwrap(),
            "--identity",
            idp
        ],
    )
    .status
    .success());
    let before = transcript_index_len(&origin);
    let out = sc(&dst, &["push", "--no-transcripts"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Origin got the new snapshot (verifiable) and no new transcript.
    assert!(sc(&origin, &["cat", "main:b.txt"]).status.success());
    assert!(sc(&origin, &["verify", "--require", "main"])
        .status
        .success());
    assert_eq!(transcript_index_len(&origin), before);
    std::fs::remove_dir_all(&root).unwrap();
}
