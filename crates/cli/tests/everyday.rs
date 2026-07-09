//! Everyday-VCS polish: author resolution, enriched log, `sc diff`, `--json`.

use std::path::Path;
use std::process::Command;

fn sc_env(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sc"));
    c.args(args).current_dir(dir);
    // Isolate from the developer's real environment.
    c.env_remove("SC_AUTHOR");
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output().expect("sc runs")
}

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    sc_env(dir, args, &[])
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-everyday-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn author_resolves_from_flag_env_then_os_user() {
    let root = tmp("author");
    assert!(sc(&root, &["init"]).status.success());

    std::fs::write(root.join("f.txt"), "1\n").unwrap();
    assert!(
        sc_env(&root, &["commit", "-m", "c1"], &[("SC_AUTHOR", "Envy")])
            .status
            .success()
    );
    std::fs::write(root.join("f.txt"), "2\n").unwrap();
    assert!(sc_env(
        &root,
        &["commit", "-m", "c2", "--author", "Flaggy"],
        &[("SC_AUTHOR", "Envy")]
    )
    .status
    .success());

    let log = stdout(&sc(&root, &["log"]));
    assert!(log.contains("Envy"), "env author used: {log}");
    assert!(log.contains("Flaggy"), "flag overrides env: {log}");
    assert!(!log.contains("you"), "the 'you' placeholder is gone: {log}");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn log_shows_date_and_merge_marker() {
    let root = tmp("log");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("a.txt"), "base\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "base"]).status.success());
    assert!(sc(&root, &["branch", "side"]).status.success());
    std::fs::write(root.join("b.txt"), "main\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "on-main"]).status.success());
    assert!(sc(&root, &["switch", "side"]).status.success());
    std::fs::write(root.join("c.txt"), "side\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "on-side"]).status.success());
    assert!(sc(&root, &["switch", "main"]).status.success());
    assert!(sc(&root, &["merge", "side"]).status.success());

    let log = stdout(&sc(&root, &["log"]));
    // Every line carries an ISO date (the year at minimum).
    assert!(log.contains("20"), "log shows a date: {log}");
    let merge_lines: Vec<&str> = log.lines().filter(|l| l.contains("(merge)")).collect();
    assert_eq!(
        merge_lines.len(),
        1,
        "exactly the merge commit is marked: {log}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn diff_shows_unified_hunks_for_modified_added_deleted() {
    let root = tmp("diff");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("mod.txt"), "one\ntwo\nthree\n").unwrap();
    std::fs::write(root.join("gone.txt"), "bye\n").unwrap();
    assert!(sc(&root, &["commit", "-m", "base"]).status.success());

    std::fs::write(root.join("mod.txt"), "one\nTWO\nthree\n").unwrap();
    std::fs::write(root.join("new.txt"), "hello\n").unwrap();
    std::fs::remove_file(root.join("gone.txt")).unwrap();

    let out = sc(&root, &["diff"]);
    assert!(out.status.success());
    let d = stdout(&out);
    assert!(
        d.contains("--- a/mod.txt") && d.contains("+++ b/mod.txt"),
        "headers: {d}"
    );
    assert!(
        d.contains("-two") && d.contains("+TWO"),
        "changed line: {d}"
    );
    assert!(d.contains("+hello"), "added file content: {d}");
    assert!(d.contains("-bye"), "deleted file content: {d}");

    // Clean tree → empty diff, exit 0.
    std::fs::write(root.join("mod.txt"), "one\ntwo\nthree\n").unwrap();
    std::fs::write(root.join("gone.txt"), "bye\n").unwrap();
    std::fs::remove_file(root.join("new.txt")).unwrap();
    let clean = sc(&root, &["diff"]);
    assert!(clean.status.success());
    assert_eq!(stdout(&clean).trim(), "", "clean tree diffs empty");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn json_output_for_status_log_and_secret_list() {
    let root = tmp("json");
    assert!(sc(&root, &["init"]).status.success());
    std::fs::write(root.join("f.txt"), "1\n").unwrap();

    // status --json before any commit: f.txt is added.
    let st: serde_json::Value =
        serde_json::from_str(&stdout(&sc(&root, &["status", "--json"]))).expect("valid json");
    assert_eq!(st["added"], serde_json::json!(["f.txt"]));
    assert_eq!(st["modified"], serde_json::json!([]));

    assert!(
        sc_env(&root, &["commit", "-m", "c1"], &[("SC_AUTHOR", "J")])
            .status
            .success()
    );

    let log: serde_json::Value =
        serde_json::from_str(&stdout(&sc(&root, &["log", "--json"]))).expect("valid json");
    let entries = log.as_array().expect("log is an array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["author"], "J");
    assert_eq!(entries[0]["message"], "c1");
    assert!(entries[0]["id"].as_str().unwrap().len() >= 12);
    assert!(entries[0]["timestamp"].as_u64().is_some());
    assert_eq!(entries[0]["parents"], serde_json::json!([]));

    let secrets: serde_json::Value =
        serde_json::from_str(&stdout(&sc(&root, &["secret", "list", "--json"])))
            .expect("valid json");
    assert_eq!(secrets, serde_json::json!([]));

    std::fs::remove_dir_all(&root).unwrap();
}
