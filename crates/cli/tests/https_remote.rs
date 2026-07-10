//! CLI acceptance for sc+https:// (P32): flag validation, `sc serve
//! fingerprint`, and the spec's round-trip criterion — clone + push + fetch
//! over TLS with a signed ~1 MiB blob under forced SC_PACK_CHUNK,
//! byte-for-byte, zero .sc/tmp residue. Env knobs (SC_HTTPS_*) are safe here
//! because every command is a SUBPROCESS with its own env (Command::env),
//! not a racy in-process set_var.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

fn sc(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

/// `sc()` variant that sets extra env vars on the subprocess — safe because
/// each `Command` gets its own environment (unlike `std::env::set_var`,
/// which is process-global and races under parallel tests).
fn sc_env(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sc"));
    c.args(args).current_dir(dir);
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output().expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-https-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Spawn `sc serve --http 127.0.0.1:0 --tls <extra…> <path>` and return the
/// child, the OS-assigned `host:port` (line 1: `listening on <addr>`), and
/// the TLS fingerprint the server banners on startup (line 2: `tls
/// fingerprint: sha256:<hex>`). Mirrors `http_remote.rs`'s
/// `spawn_http_server`, extended to also read the second announce line.
fn spawn_tls_http_server(root: &Path, extra: &[&str]) -> (Child, String, String) {
    let mut args = vec!["serve", "--http", "127.0.0.1:0", "--tls"];
    args.extend_from_slice(extra);
    args.push(root.to_str().unwrap());
    let mut child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(&args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn sc serve --http --tls");
    let stdout = child.stdout.take().expect("child stdout is piped");
    let mut reader = std::io::BufReader::new(stdout);

    let mut line1 = String::new();
    let n1 = reader
        .read_line(&mut line1)
        .expect("read serve startup line 1");
    if n1 == 0 {
        let status = child.wait().ok();
        panic!("sc serve --http --tls exited before announcing a bound address: {status:?}");
    }
    let addr = line1
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected serve startup line 1: {line1:?}"))
        .to_string();

    let mut line2 = String::new();
    let n2 = reader
        .read_line(&mut line2)
        .expect("read serve startup line 2");
    if n2 == 0 {
        let status = child.wait().ok();
        panic!("sc serve --http --tls exited before announcing a fingerprint: {status:?}");
    }
    let fpr = line2
        .trim()
        .strip_prefix("tls fingerprint: ")
        .unwrap_or_else(|| panic!("unexpected serve startup line 2: {line2:?}"))
        .to_string();

    (child, addr, fpr)
}

/// keygen a v2 identity OUTSIDE the working tree (the P5 scanner flags
/// `scl-id-` files found inside one), mirroring `provenance.rs`'s `keygen`
/// helper, returning the identity file path.
fn keygen(keys_dir: &Path, name: &str) -> PathBuf {
    let idfile = keys_dir.join(format!("{name}.id"));
    let out = sc(keys_dir, &["keygen", "--out", idfile.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    idfile
}

/// Deterministic ~1 MiB of hex-text "random" bytes (splitmix64-seeded),
/// mirroring `demo/run_http_remote_demo.sh`'s `head -c 1048576 /dev/urandom
/// | od -An -tx1` — hex text keeps per-character entropy under the P5
/// scanner's threshold (16 symbols, ≤4 bits/char) while raw high-entropy
/// binary of the same size trips it as a false-positive secret.
fn hex_blob(byte_len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };
    let mut out = Vec::with_capacity(byte_len);
    while out.len() < byte_len {
        let v = next();
        out.extend_from_slice(format!("{v:016x}").as_bytes());
    }
    out.truncate(byte_len);
    out
}

/// Write a known_hosts file pinning `addr` (`host:port`) to `fpr`
/// (`sha256:<hex>`), in the same `host:port sha256:<hex>` line format
/// `tls_pins::record` writes — used to simulate "this address used to be
/// the old server" for the key-swap mismatch scenario.
fn mismatch_kh(dir: &Path, addr: &str, fpr: &str) -> PathBuf {
    let kh = dir.join("mismatch_known_hosts");
    let mut f = std::fs::File::create(&kh).unwrap();
    writeln!(f, "{addr} {fpr}").unwrap();
    kh
}

#[test]
fn tls_flags_validated() {
    let root = tmp("flags");
    assert!(sc(&root, &["init"]).status.success());
    // --tls-cert without --tls
    let out = sc(
        &root,
        &[
            "serve",
            "--http",
            "127.0.0.1:0",
            "--tls-cert",
            "x.pem",
            root.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--tls"));
    // --tls with --stdio
    let out = sc(
        &root,
        &["serve", "--stdio", "--tls", root.to_str().unwrap()],
    );
    assert!(!out.status.success());
    // --tls-cert without --tls-key
    let out = sc(
        &root,
        &[
            "serve",
            "--http",
            "127.0.0.1:0",
            "--tls",
            "--tls-cert",
            "x.pem",
            root.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
}

#[test]
fn serve_fingerprint_mints_and_matches_banner() {
    let root = tmp("fpr");
    assert!(sc(&root, &["init"]).status.success());
    let out = sc(&root, &["serve", "fingerprint", root.to_str().unwrap()]);
    assert!(out.status.success());
    let fpr = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(fpr.starts_with("sha256:"));
    // The identity persisted; a TLS serve now banners the SAME fingerprint.
    let (mut child, _addr, banner_fpr) = spawn_tls_http_server(&root, &[]);
    assert_eq!(banner_fpr, fpr);
    child.kill().ok();
}

#[test]
fn https_clone_push_fetch_round_trip_with_signed_chunked_blob() {
    let w = tmp("rt");
    let origin = w.join("origin");
    std::fs::create_dir_all(&origin).unwrap();
    assert!(sc(&origin, &["init"]).status.success());

    // Identity OUTSIDE the working tree (P5 scanner flags scl-id files).
    let identity = keygen(&w, "alice");

    // ~1 MiB deterministic blob + a signed commit. Hex text, not raw random
    // bytes: see `hex_blob`'s doc comment for why (P5 scanner false positive).
    let blob = hex_blob(1_048_576);
    std::fs::write(origin.join("big.bin"), &blob).unwrap();
    assert!(sc(
        &origin,
        &[
            "commit",
            "-m",
            "big",
            "--sign",
            "--identity",
            identity.to_str().unwrap(),
        ],
    )
    .status
    .success());

    // rw token; capture the raw value from stdout (auth demo pattern).
    let tok_out = sc(
        &origin,
        &["serve", "token", "add", "--label", "ci", "--scope", "rw"],
    );
    assert!(tok_out.status.success());
    let token = String::from_utf8_lossy(&tok_out.stdout).trim().to_string();

    let (mut child, addr, fpr) = spawn_tls_http_server(&origin, &[]);
    let url = format!("sc+https://{addr}/");
    let kh = w.join("known_hosts");

    // Clone with forced tiny chunks; env is per-subprocess, race-free.
    let clone_dir = w.join("clone");
    let out = sc_env(
        &w,
        &["clone", &url, clone_dir.to_str().unwrap()],
        &[
            ("SC_HTTP_TOKEN", token.as_str()),
            ("SC_HTTPS_KNOWN_HOSTS", kh.to_str().unwrap()),
            ("SC_PACK_CHUNK", "4096"),
        ],
    );
    assert!(
        out.status.success(),
        "clone failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // First-connect TOFU announced + pinned.
    assert!(String::from_utf8_lossy(&out.stderr).contains("pinned"));
    assert!(kh.exists());
    // Byte-for-byte.
    assert_eq!(std::fs::read(clone_dir.join("big.bin")).unwrap(), blob);
    // Signature rode the chunked TLS stream.
    let log = sc(&clone_dir, &["log"]);
    assert!(String::from_utf8_lossy(&log.stdout).contains("signed:"));

    // Push an edit back over TLS (second connect: pin known → NO "pinned").
    std::fs::write(clone_dir.join("new.txt"), "from clone").unwrap();
    assert!(sc(&clone_dir, &["commit", "-m", "edit"]).status.success());
    let out = sc_env(
        &clone_dir,
        &["push", "origin"],
        &[
            ("SC_HTTP_TOKEN", token.as_str()),
            ("SC_HTTPS_KNOWN_HOSTS", kh.to_str().unwrap()),
        ],
    );
    assert!(
        out.status.success(),
        "push failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("pinned"),
        "second connect must be quiet"
    );

    // Fetch from a second clone sees the edit.
    let clone2 = w.join("clone2");
    assert!(sc_env(
        &w,
        &["clone", &url, clone2.to_str().unwrap()],
        &[
            ("SC_HTTP_TOKEN", token.as_str()),
            ("SC_HTTPS_KNOWN_HOSTS", kh.to_str().unwrap()),
        ],
    )
    .status
    .success());
    assert_eq!(
        std::fs::read_to_string(clone2.join("new.txt")).unwrap(),
        "from clone"
    );

    // Zero .sc/tmp residue on every end.
    for repo in [&origin, &clone_dir, &clone2] {
        let tmp_dir = repo.join(".sc").join("tmp");
        let empty =
            !tmp_dir.exists() || std::fs::read_dir(&tmp_dir).unwrap().next().is_none();
        assert!(empty, ".sc/tmp residue in {}", repo.display());
    }

    // Key swap → pin mismatch hard-fails.
    child.kill().ok();
    child.wait().ok();
    std::fs::remove_dir_all(origin.join(".sc").join("serve-tls")).unwrap();
    let (mut child2, addr2, _f) = spawn_tls_http_server(&origin, &[]);
    let url2 = format!("sc+https://{addr2}/");
    let clone3 = w.join("clone3");
    // Re-pin the OLD server's fingerprint under the NEW address first, so
    // the lookup hits: write a kh containing addr2 mapped to the OLD
    // fingerprint captured earlier.
    let out = sc_env(
        &w,
        &["clone", &url2, clone3.to_str().unwrap()],
        &[
            ("SC_HTTP_TOKEN", token.as_str()),
            (
                "SC_HTTPS_KNOWN_HOSTS",
                mismatch_kh(&w, &addr2, &fpr).to_str().unwrap(),
            ),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("does not match the pinned fingerprint"),
        "got: {err}"
    );
    child2.kill().ok();
}
