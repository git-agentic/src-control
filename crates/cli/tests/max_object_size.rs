//! `SC_MAX_OBJECT_SIZE` / `sc serve --max-object-size` (#213, ADR-0039
//! addendum): bounds are enforced at startup, and the cap is honoured by a
//! real object transfer.

use std::path::Path;
use std::process::{Command, Output};

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

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-maxobj-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn out_of_range_env_is_rejected_at_startup_not_clamped() {
    let root = tmp("env-bounds");
    for bad in [
        "0",
        "1023KiB",
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
    for good in ["1048576", "1MiB", "256mib", "1GiB"] {
        let o = sc(&root, &[("SC_MAX_OBJECT_SIZE", good)], &["init"]);
        assert!(o.status.success(), "{good}: {}", stderr(&o));
        std::fs::remove_dir_all(root.join(".sc")).unwrap();
    }
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn serve_flag_is_bounds_checked_and_overrides_env() {
    let root = tmp("serve-flag");
    assert!(sc(&root, &[], &["init"]).status.success());
    for bad in ["512", "2GiB", "x"] {
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
    // The flag wins over a bad env value (the env is never consulted).
    let o = sc(
        &root,
        &[("SC_MAX_OBJECT_SIZE", "junk")],
        &[
            "serve",
            "--stdio",
            "--max-object-size",
            "1MiB",
            "--max-pack-size",
            "1024",
            ".",
        ],
    );
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("below the max object size (1048576)"),
        "the pack floor uses the flag's cap: {}",
        stderr(&o)
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_lowered_cap_refuses_a_transfer_a_raised_one_allows() {
    let src = tmp("xfer-src");
    assert!(sc(&src, &[], &["init"]).status.success());
    // 2 MiB of incompressible bytes: one object over a 1 MiB cap.
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let big: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(src.join("big.bin"), &big).unwrap();
    let o = sc(&src, &[("SC_AUTHOR", "t")], &["commit", "-m", "big"]);
    assert!(o.status.success(), "commit is not capped: {}", stderr(&o));

    let parent = tmp("xfer-dst");
    let low = parent.join("low");
    let o = sc(
        &parent,
        &[("SC_MAX_OBJECT_SIZE", "1MiB")],
        &["clone", src.to_str().unwrap(), low.to_str().unwrap()],
    );
    assert!(!o.status.success(), "1 MiB cap must refuse a 2 MiB blob");

    let high = parent.join("high");
    let o = sc(
        &parent,
        &[("SC_MAX_OBJECT_SIZE", "4MiB")],
        &["clone", src.to_str().unwrap(), high.to_str().unwrap()],
    );
    assert!(o.status.success(), "4 MiB cap accepts it: {}", stderr(&o));
    assert_eq!(std::fs::read(high.join("big.bin")).unwrap(), big);

    std::fs::remove_dir_all(&src).unwrap();
    std::fs::remove_dir_all(&parent).unwrap();
}
