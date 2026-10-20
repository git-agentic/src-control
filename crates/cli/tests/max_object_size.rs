//! `SC_MAX_OBJECT_SIZE` / `sc serve --max-object-size` (#213, ADR-0039
//! addendum): bounds are enforced at startup, and the cap is honoured by a
//! real object transfer.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

fn sc(dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sc"));
    c.args(args)
        .current_dir(dir)
        .env_remove("SC_MAX_OBJECT_SIZE");
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output().expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-maxobj-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A repo at `dir` with one committed `big.bin` of `len` incompressible bytes.
fn repo_with_big_file(dir: &Path, len: usize) -> Vec<u8> {
    assert!(sc(dir, &[], &["init"]).status.success());
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let big: Vec<u8> = (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(dir.join("big.bin"), &big).unwrap();
    let o = sc(dir, &[("SC_AUTHOR", "t")], &["commit", "-m", "big"]);
    assert!(o.status.success(), "commit is not capped: {}", stderr(&o));
    big
}

#[test]
fn out_of_range_env_is_rejected_at_startup_not_clamped() {
    let root = tmp("env-bounds");
    for bad in [
        "0",
        "2097151",
        "1MiB",
        "2047KiB",
        "1025MiB",
        "2GiB",
        "junk",
        "99999999999999GiB",
    ] {
        let o = sc(&root, &[("SC_MAX_OBJECT_SIZE", bad)], &["init"]);
        assert!(!o.status.success(), "{bad} must be rejected");
        assert!(
            stderr(&o).contains("SC_MAX_OBJECT_SIZE"),
            "{bad}: {}",
            stderr(&o)
        );
        assert!(
            !root.join(".sc").exists(),
            "{bad}: rejected before any work"
        );
    }
    for good in ["2097152", "2MiB", "256mib", "1GiB", "", "  "] {
        let o = sc(&root, &[("SC_MAX_OBJECT_SIZE", good)], &["init"]);
        assert!(o.status.success(), "{good:?}: {}", stderr(&o));
        std::fs::remove_dir_all(root.join(".sc")).unwrap();
    }
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn serve_flag_is_bounds_checked_and_overrides_env() {
    let root = tmp("serve-flag");
    assert!(sc(&root, &[], &["init"]).status.success());
    for bad in ["512", "1MiB", "2GiB", "x"] {
        let o = sc(
            &root,
            &[],
            &["serve", "--stdio", "--max-object-size", bad, "."],
        );
        assert!(!o.status.success(), "{bad} must be rejected");
        assert!(
            stderr(&o).contains("--max-object-size"),
            "{bad}: {}",
            stderr(&o)
        );
    }
    // The flag wins over a bad env value (the env is never consulted); the
    // pack-size floor then reports the flag's cap.
    let o = sc(
        &root,
        &[("SC_MAX_OBJECT_SIZE", "junk")],
        &[
            "serve",
            "--stdio",
            "--max-object-size",
            "2MiB",
            "--max-pack-size",
            "1024",
            ".",
        ],
    );
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("below the max object size (2097152)"),
        "the pack floor uses the flag's cap: {}",
        stderr(&o)
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn serve_honours_the_env_when_the_flag_is_absent() {
    let root = tmp("serve-env");
    assert!(sc(&root, &[], &["init"]).status.success());
    let o = sc(
        &root,
        &[("SC_MAX_OBJECT_SIZE", "4MiB")],
        &["serve", "--stdio", "--max-pack-size", "1024", "."],
    );
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("below the max object size (4194304)"),
        "the pack floor uses the env's cap: {}",
        stderr(&o)
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_lowered_cap_refuses_a_transfer_a_raised_one_allows() {
    let src = tmp("xfer-src");
    // 3 MiB: one object over a 2 MiB cap.
    let big = repo_with_big_file(&src, 3 * 1024 * 1024);

    let parent = tmp("xfer-dst");
    let low = parent.join("low");
    let o = sc(
        &parent,
        &[("SC_MAX_OBJECT_SIZE", "2MiB")],
        &["clone", src.to_str().unwrap(), low.to_str().unwrap()],
    );
    assert!(!o.status.success(), "a 2 MiB cap must refuse a 3 MiB blob");
    assert!(
        stderr(&o).contains("2097152-byte object size limit"),
        "refused by the object cap, not something else: {}",
        stderr(&o)
    );

    let high = parent.join("high");
    let o = sc(
        &parent,
        &[("SC_MAX_OBJECT_SIZE", "4MiB")],
        &["clone", src.to_str().unwrap(), high.to_str().unwrap()],
    );
    assert!(o.status.success(), "a 4 MiB cap accepts it: {}", stderr(&o));
    assert_eq!(std::fs::read(high.join("big.bin")).unwrap(), big);

    std::fs::remove_dir_all(&src).unwrap();
    std::fs::remove_dir_all(&parent).unwrap();
}

fn spawn_http_server(root: &Path) -> (Child, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(["serve", "--http", "127.0.0.1:0", root.to_str().unwrap()])
        .env_remove("SC_MAX_OBJECT_SIZE")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn sc serve --http");
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    assert!(reader.read_line(&mut line).unwrap() > 0, "server announced");
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected startup line: {line:?}"))
        .to_string();
    // Keep draining so the server never blocks on a full stdout pipe.
    std::thread::spawn(move || for _ in reader.lines() {});
    (child, addr)
}

#[test]
fn a_client_with_a_lower_cap_than_the_server_fails_with_the_mismatch_hint() {
    let src = tmp("mismatch-src");
    let big = repo_with_big_file(&src, 3 * 1024 * 1024);
    // The server runs at the default cap and serves the 3 MiB blob happily.
    let (mut server, addr) = spawn_http_server(&src);
    let url = format!("sc+http://{addr}");

    let parent = tmp("mismatch-dst");
    let low = parent.join("low");
    let o = sc(
        &parent,
        &[("SC_MAX_OBJECT_SIZE", "2MiB")],
        &["clone", &url, low.to_str().unwrap()],
    );
    assert!(!o.status.success(), "the lowered client must refuse");
    let err = stderr(&o);
    assert!(err.contains("2097152-byte object size limit"), "{err}");
    assert!(err.contains("SC_MAX_OBJECT_SIZE"), "names the knob: {err}");

    let ok = parent.join("ok");
    let o = sc(
        &parent,
        &[("SC_MAX_OBJECT_SIZE", "4MiB")],
        &["clone", &url, ok.to_str().unwrap()],
    );
    assert!(o.status.success(), "an adequate cap passes: {}", stderr(&o));
    assert_eq!(std::fs::read(ok.join("big.bin")).unwrap(), big);

    let _ = server.kill();
    let _ = server.wait();
    std::fs::remove_dir_all(&src).unwrap();
    std::fs::remove_dir_all(&parent).unwrap();
}
