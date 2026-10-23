//! F2b: the smart-HTTP git transport, driven by the real `git` client against an in-process server.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Client {
    dir: PathBuf,
}

impl Client {
    fn new(tag: &str) -> Client {
        let dir =
            std::env::temp_dir().join(format!("scl-forge-client-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Client { dir }
    }

    /// Run the client's git with a scrubbed environment; `header` is the Authorization value.
    fn git_in(&self, cwd: &Path, header: Option<&str>, args: &[&str]) -> (bool, String) {
        let mut cmd = Command::new("git");
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("HOME", &self.dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "T")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "T")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .current_dir(cwd);
        if let Some(h) = header {
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

    fn ok(&self, cwd: &Path, header: Option<&str>, args: &[&str]) -> String {
        let (ok, text) = self.git_in(cwd, header, args);
        assert!(ok, "git {args:?}: {text}");
        text
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn repo(s: &Srv, name: &str) -> String {
    let r = s.post(
        "/api/v1/user/repos",
        &token(&s.admin),
        json!({"name": name, "default_branch": "main"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    format!("{}/siteadmin/{name}.git", s.base)
}

#[test]
fn push_then_clone_round_trips() {
    let s = Srv::start();
    let c = Client::new("rt");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    let work = c.dir.join("work");
    c.ok(
        &c.dir,
        None,
        &["init", "-q", "-b", "main", work.to_str().unwrap()],
    );
    std::fs::write(work.join("a.txt"), "hello\n").unwrap();
    c.ok(&work, None, &["add", "."]);
    c.ok(&work, None, &["commit", "-q", "-m", "one"]);
    c.ok(&work, Some(&auth), &["push", &url, "main"]);
    let clone = c.dir.join("clone");
    c.ok(
        &c.dir,
        Some(&auth),
        &["clone", "-q", &url, clone.to_str().unwrap()],
    );
    assert_eq!(
        std::fs::read_to_string(clone.join("a.txt")).unwrap(),
        "hello\n"
    );
}
