//! Named, concurrently open `sc ws` sessions through the real binary
//! (ADR-0055): addressing by `--session`, independent harvests with first-wins
//! ordering, and `sc ws run` not holding the repo lock while its command runs.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SC: &str = env!("CARGO_BIN_EXE_sc");

fn sc(dir: &Path, args: &[&str]) -> Output {
    Command::new(SC)
        .args(args)
        .current_dir(dir)
        .env_remove("SC_AUTHOR")
        .output()
        .expect("sc runs")
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let out = sc(dir, args);
    assert!(
        out.status.success(),
        "sc {args:?} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The checkout dir of the single workspace `sc ws fork` printed.
fn forked_dir(fork_out: &str) -> PathBuf {
    let line = fork_out.lines().nth(1).expect("one workspace line");
    PathBuf::from(line.split_whitespace().nth(1).expect("dir column"))
}

fn setup(tag: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("scl-cli-ws-sessions-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    ok(&root, &["init"]);
    std::fs::write(root.join("shared.txt"), "base\n").unwrap();
    ok(&root, &["commit", "-m", "base", "--author", "t"]);
    root
}

#[test]
fn two_named_sessions_fork_list_run_and_harvest_independently() {
    let root = setup("two");
    let a = forked_dir(&ok(&root, &["ws", "fork", "--agents", "1", "--name", "a"]));
    let b = forked_dir(&ok(&root, &["ws", "fork", "--agents", "1", "--name", "b"]));
    assert!(a.ends_with(".sc/ws-a/1") && b.ends_with(".sc/ws-b/1"));

    // A second session of the same name is refused; the first is untouched.
    let dup = sc(&root, &["ws", "fork", "--name", "a"]);
    assert!(!dup.status.success());
    assert!(String::from_utf8_lossy(&dup.stderr).contains("session 'a' is already open"));

    // `list` shows every session, or just the one asked for.
    let list = ok(&root, &["ws", "list"]);
    assert!(
        list.contains("session a base:") && list.contains("session b base:"),
        "{list}"
    );
    let only_b = ok(&root, &["ws", "list", "--session", "b"]);
    assert!(
        only_b.contains("session b base:") && !only_b.contains("session a"),
        "{only_b}"
    );

    // With no unnamed session, the default does not guess.
    let guess = sc(&root, &["ws", "harvest"]);
    assert!(!guess.status.success());
    let err = String::from_utf8_lossy(&guess.stderr);
    assert!(
        err.contains("open: a, b") && err.contains("--session"),
        "{err}"
    );

    // Run labels the workspace with the session name.
    let label = ok(
        &root,
        &[
            "ws",
            "run",
            "--session",
            "a",
            "1",
            "--",
            "sh",
            "-c",
            "printf %s \"$SC_WORKSPACE\"",
        ],
    );
    assert_eq!(label, "a-1");

    // Both edit the same file: the first harvest wins, the second falls back.
    std::fs::write(a.join("shared.txt"), "from a\n").unwrap();
    std::fs::write(b.join("shared.txt"), "from b\n").unwrap();
    let first = ok(&root, &["ws", "harvest", "--session", "b", "--author", "t"]);
    assert!(first.contains("landed"), "{first}");
    let second = sc(&root, &["ws", "harvest", "--session", "a", "--author", "t"]);
    assert_eq!(second.status.code(), Some(1));
    let second = String::from_utf8_lossy(&second.stdout);
    assert!(second.contains("fallback: branch a-1"), "{second}");
    assert_eq!(
        std::fs::read_to_string(root.join("shared.txt")).unwrap(),
        "from b\n"
    );

    assert!(!root.join(".sc/ws-a").exists() && !root.join(".sc/ws-b").exists());
    assert!(ok(&root, &["ws", "list"]).contains("no workspace session open"));
    std::fs::remove_dir_all(&root).unwrap();
}

/// While one session's command runs, the repo is free: another `sc` can list,
/// harvest or abandon the other session. (Before ADR-0055 the run held the
/// single-writer lock for the child's whole life and these failed with `Locked`.)
#[test]
fn a_running_session_does_not_block_the_others() {
    let root = setup("run");
    ok(&root, &["ws", "fork", "--agents", "1", "--name", "a"]);
    let b = forked_dir(&ok(&root, &["ws", "fork", "--agents", "1", "--name", "b"]));
    std::fs::write(b.join("from-b.txt"), "b\n").unwrap();

    let inside = |args: &[&str]| -> Vec<String> {
        ["ws", "run", "--session", "a", "1", "--", SC]
            .iter()
            .chain(args)
            .map(|s| s.to_string())
            .collect()
    };
    // The child is `sc` itself, run from inside a's workspace dir.
    for args in [
        &["ws", "list", "--session", "b"][..],
        &["ws", "harvest", "--session", "b", "--author", "t"][..],
    ] {
        let argv = inside(args);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let out = ok(&root, &argv);
        assert!(!out.is_empty(), "{args:?}");
    }
    assert!(
        root.join("from-b.txt").exists(),
        "b landed while a was running"
    );

    // Once its command has finished, a is abandoned like any session.
    ok(&root, &["ws", "abandon", "--session", "a"]);
    assert!(!root.join(".sc/ws-a").exists());
    std::fs::remove_dir_all(&root).unwrap();
}
