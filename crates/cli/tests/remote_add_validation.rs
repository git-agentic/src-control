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
