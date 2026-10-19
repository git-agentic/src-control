//! `sc remote add` parse-validates the native network URL schemes at add time,
//! so a typo fails here and not at the first fetch (P32 follow-on).

use std::process::Command;

fn sc(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}

fn repo(tag: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("scl-cli-remote-add-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    assert!(sc(&root, &["init"]).status.success());
    root
}

#[test]
fn malformed_http_urls_are_refused_at_add_time_and_good_ones_recorded() {
    let root = repo("http");
    for bad in [
        "sc+http://",
        "sc+http:///repo",
        "sc+https://host:notaport/repo",
        "sc+http://host:99999/repo",
        "sc+https:/host/repo", // near-miss scheme: one slash
        "sc+http:host/repo",
    ] {
        let out = sc(&root, &["remote", "add", "origin", bad]);
        assert!(!out.status.success(), "{bad} should be refused");
        let list = sc(&root, &["remote", "list"]);
        assert!(
            String::from_utf8_lossy(&list.stdout).trim().is_empty(),
            "{bad} must not be recorded"
        );
    }

    for (name, good) in [
        ("plain", "sc+http://127.0.0.1:7777/repo"),
        ("secure", "sc+https://example.com/repo"),
    ] {
        let out = sc(&root, &["remote", "add", name, good]);
        assert!(
            out.status.success(),
            "{good}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let list = String::from_utf8_lossy(&sc(&root, &["remote", "list"]).stdout).into_owned();
    assert!(list.contains("sc+http://127.0.0.1:7777/repo"), "{list}");
    assert!(list.contains("sc+https://example.com/repo"), "{list}");

    std::fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists(), "test must leave no residue");
}

/// With no path, `sc serve fingerprint` finds the repo from a subdirectory,
/// and outside any repo it refuses instead of minting.
#[test]
fn serve_fingerprint_discovers_the_repo_and_refuses_outside_one() {
    let root = repo("fingerprint");
    let sub = root.join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    let out = sc(&sub, &["serve", "fingerprint"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("sha256:"));
    assert!(
        root.join(".sc/serve-tls").is_dir(),
        "minted in the repo root"
    );
    assert!(!sub.join(".sc").exists(), "never in the subdirectory");

    let bare =
        std::env::temp_dir().join(format!("scl-cli-fingerprint-bare-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&bare);
    std::fs::create_dir_all(&bare).unwrap();
    let out = sc(&bare, &["serve", "fingerprint"]);
    assert!(!out.status.success());
    assert!(!bare.join(".sc").exists(), "nothing may be created");

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&bare).unwrap();
    assert!(
        !root.exists() && !bare.exists(),
        "test must leave no residue"
    );
}
