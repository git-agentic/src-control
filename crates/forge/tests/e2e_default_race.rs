//! #316: a default-branch change racing a push that deletes the new default. Its own test binary,
//! because the hook hold knob is read from the process environment.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn git(home: &Path, cwd: &Path, auth: Option<&str>, args: &[&str]) -> (bool, String) {
    let mut cmd = Command::new("git");
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .current_dir(cwd);
    if let Some(h) = auth {
        cmd.arg("-c")
            .arg(format!("http.extraHeader=Authorization: {h}"));
    }
    let out = cmd.args(args).output().expect("run git");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_push_in_flight_keeps_the_default_branch_off_a_branch_it_deletes() {
    let s = Srv::start();
    let auth = token(&s.admin);
    let r = s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "race", "default_branch": "main"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let url = format!("{}/siteadmin/race.git", s.base);
    let tmp = Dir(std::env::temp_dir().join(format!("scl-forge-race-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&tmp.0);
    let work = tmp.0.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let ok = |args: &[&str]| {
        let (ok, text) = git(&tmp.0, &work, Some(&auth), args);
        assert!(ok, "git {args:?}: {text}");
    };
    ok(&["init", "-q", "-b", "main"]);
    std::fs::write(work.join("a.txt"), "a\n").unwrap();
    ok(&["add", "."]);
    ok(&["commit", "-q", "-m", "a"]);
    ok(&["push", "-q", &url, "main", "main:refs/heads/dev"]);

    // From here on every push holds in its hook after reading the row, until the marker goes.
    let marker = tmp.0.join("hook-held");
    std::env::set_var("SC_FORGE_HOOK_HOLD", &marker);
    let push = std::thread::spawn({
        let (home, work, auth, url) = (tmp.0.clone(), work.clone(), auth.clone(), url.clone());
        move || {
            git(
                &home,
                &work,
                Some(&auth),
                &["push", &url, ":refs/heads/dev"],
            )
        }
    });
    wait_for("the push's hook to have read the default branch", || {
        marker.exists()
    });

    // The hook read `main`, so it lets the delete of `dev` through: moving the default onto
    // `dev` now would leave it naming a branch the push is about to delete.
    let patch = json!({"default_branch": "dev"});
    let r = s.send(
        "PATCH",
        "/api/v1/repos/siteadmin/race",
        Some(&auth),
        Some(&patch),
    );
    assert_eq!(r.status, 503, "{}", r.msg());

    std::fs::remove_file(&marker).unwrap();
    let (pushed, text) = push.join().unwrap();
    assert!(pushed, "the delete goes through: {text}");
    std::env::remove_var("SC_FORGE_HOOK_HOLD");

    let r = s.get("/api/v1/repos/siteadmin/race", &auth);
    assert_eq!(r.json()["default_branch"], "main");
    assert_eq!(r.json()["empty"], false);
    // Now that no push is in flight the change is decided against the refs: `dev` is gone.
    let r = s.send(
        "PATCH",
        "/api/v1/repos/siteadmin/race",
        Some(&auth),
        Some(&patch),
    );
    assert_eq!(r.status, 422, "{}", r.msg());
}
