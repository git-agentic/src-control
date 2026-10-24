//! F4a: branch protection and commit statuses, checked with the real `git` client and the HTTP API.
//! Delete and force-push cases use a protected branch that is **not** the default: on the default
//! branch the default-branch rule answers first and would hide a missing protection check.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Client {
    dir: PathBuf,
}

impl Client {
    fn new(tag: &str) -> Client {
        let dir = std::env::temp_dir().join(format!("scl-forge-prot-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Client { dir }
    }

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

    fn commit(&self, work: &Path, file: &str, text: &str) {
        std::fs::write(work.join(file), text).unwrap();
        self.ok(work, None, &["add", "."]);
        self.ok(work, None, &["commit", "-q", "-m", file]);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct W {
    s: Srv,
    auth: String,
    id: i64,
}

/// `siteadmin/w` with the README commit on `main`.
fn world() -> W {
    let s = Srv::start();
    let auth = token(&s.admin);
    let r = s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "w", "default_branch": "main", "auto_init": true}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let id = r.json()["id"].as_i64().unwrap();
    W { s, auth, id }
}

impl W {
    fn api(&self, method: &str, path: &str, body: Option<Value>) -> Resp {
        self.s.send(
            method,
            &format!("/api/v1/repos/siteadmin/w{path}"),
            Some(&self.auth),
            body.as_ref(),
        )
    }
    fn git(&self, args: &[&str]) -> String {
        self.s.git(self.id, args, None)
    }
    fn url(&self) -> String {
        format!("{}/siteadmin/w.git", self.s.base)
    }
    fn rule(&self, branch: &str, push: bool) {
        let r = self.api(
            "POST",
            "/branch_protections",
            Some(json!({"branch_name": branch, "enable_push": push})),
        );
        assert_eq!(r.status, 201, "{}", r.msg());
    }
    /// A working copy cloned from `main` with `rel` created from it and pushed.
    fn clone_with_rel(&self, c: &Client) -> PathBuf {
        let work = c.dir.join("work");
        c.ok(
            &c.dir,
            Some(&self.auth),
            &["clone", "-q", &self.url(), work.to_str().unwrap()],
        );
        c.ok(&work, None, &["checkout", "-q", "-b", "rel"]);
        c.ok(&work, Some(&self.auth), &["push", "-q", "origin", "rel"]);
        work
    }
}

fn b64s(s: &str) -> String {
    b64(s)
}

#[test]
fn rule_crud_validation_and_the_branch_object() {
    let w = world();
    let r = w.api(
        "POST",
        "/branch_protections",
        Some(json!({
            "branch_name": "rel", "enable_push": false,
            "enable_status_check": true, "status_check_contexts": ["ci/test"]
        })),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let j = r.json();
    assert_eq!(j["branch_name"], "rel");
    assert_eq!(j["rule_name"], "rel");
    assert_eq!(j["status_check_contexts"], json!(["ci/test"]));
    assert_eq!(j["required_approvals"], 0);

    for (name, body, status, text) in [
        (
            "duplicate",
            json!({"branch_name": "rel", "enable_push": true}),
            403,
            "Branch protection already exist",
        ),
        (
            "case alias",
            json!({"branch_name": "REL"}),
            403,
            "Branch protection already exist",
        ),
        (
            "glob",
            json!({"branch_name": "release/*"}),
            422,
            "patterns are not supported",
        ),
        (
            "approvals",
            json!({"branch_name": "x", "required_approvals": 2}),
            422,
            "unsupported branch protection setting: required_approvals",
        ),
        (
            "checks without contexts",
            json!({"branch_name": "x", "enable_status_check": true}),
            422,
            "status_check_contexts is required",
        ),
        (
            "context pattern",
            json!({"branch_name": "x", "status_check_contexts": ["ci/*"]}),
            422,
            "patterns are not supported",
        ),
        (
            "two names",
            json!({"branch_name": "a", "rule_name": "b"}),
            422,
            "must be the same",
        ),
        ("no name", json!({}), 422, "Required"),
    ] {
        let r = w.api("POST", "/branch_protections", Some(body));
        assert_eq!(
            (r.status, r.msg().contains(text)),
            (status, true),
            "{name}: {}",
            r.msg()
        );
    }

    // the branch object reports the rule
    let b = w.api("GET", "/branches/main", None).json();
    assert_eq!(b["protected"], false);
    w.git(&["update-ref", "refs/heads/rel", "refs/heads/main"]);
    let b = w.api("GET", "/branches/rel", None).json();
    assert_eq!(b["protected"], true);
    assert_eq!(b["user_can_push"], false);
    assert_eq!(b["enable_status_check"], true);
    assert_eq!(b["status_check_contexts"], json!(["ci/test"]));
    assert_eq!(b["effective_branch_protection_name"], "rel");

    let p = w.api(
        "PATCH",
        "/branch_protections/rel",
        Some(json!({"enable_push": true})),
    );
    assert_eq!(p.status, 200);
    assert_eq!(p.json()["enable_push"], true);
    assert_eq!(p.json()["status_check_contexts"], json!(["ci/test"]));
    let bad = w.api(
        "PATCH",
        "/branch_protections/rel",
        Some(json!({"status_check_contexts": []})),
    );
    assert_eq!(
        bad.status, 422,
        "checks stay on, so contexts cannot be emptied"
    );
    assert_eq!(
        w.api("GET", "/branch_protections", None)
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(w.api("GET", "/branch_protections/REL", None).status, 200);
    assert_eq!(w.api("DELETE", "/branch_protections/rel", None).status, 204);
    assert_eq!(w.api("GET", "/branch_protections/rel", None).status, 404);
    assert_eq!(w.api("DELETE", "/branch_protections/rel", None).status, 404);
}

#[test]
fn only_a_repository_admin_manages_rules() {
    let w = world();
    let pw = w.s.mk_user("alice");
    let t = w.s.mk_token("alice", &pw, "t", &["all"]);
    let put = w.api(
        "PUT",
        "/collaborators/alice",
        Some(json!({"permission": "write"})),
    );
    assert_eq!(put.status, 204);
    let tok = token(&t);
    let try_ = |m: &str, p: &str, b: Option<Value>| {
        w.s.send(
            m,
            &format!("/api/v1/repos/siteadmin/w{p}"),
            Some(&tok),
            b.as_ref(),
        )
    };
    let r = try_(
        "POST",
        "/branch_protections",
        Some(json!({"branch_name": "x"})),
    );
    assert_eq!(r.status, 403);
    assert!(
        r.msg().contains("owner or a collaborator with admin"),
        "{}",
        r.msg()
    );
    assert_eq!(
        try_("GET", "/branch_protections", None).status,
        200,
        "a writer may read"
    );
    w.rule("rel", false);
    assert_eq!(
        try_(
            "PATCH",
            "/branch_protections/rel",
            Some(json!({"enable_push": true}))
        )
        .status,
        403
    );
    assert_eq!(try_("DELETE", "/branch_protections/rel", None).status, 403);
    assert_eq!(
        w.api("GET", "/branch_protections/rel", None).json()["enable_push"],
        false
    );
}

#[test]
fn pushes_under_a_rule() {
    let w = world();
    let c = Client::new("push");
    let work = w.clone_with_rel(&c);
    w.rule("rel", false);

    // enable_push=false: nothing moves the branch, administrators included
    c.commit(&work, "a.txt", "a\n");
    let (ok, out) = c.git_in(&work, Some(&w.auth), &["push", "origin", "rel"]);
    assert!(
        !ok && out.contains("direct pushes are not allowed"),
        "{out}"
    );
    let (ok, out) = c.git_in(
        &work,
        Some(&w.auth),
        &["push", "origin", "rel:refs/heads/Rel"],
    );
    assert!(
        !ok && out.contains("protected branch Rel"),
        "a case alias is the same rule: {out}"
    );
    let (ok, out) = c.git_in(&work, Some(&w.auth), &["push", "origin", ":rel"]);
    assert!(!ok && out.contains("protected branch rel"), "{out}");

    // enable_push=true: fast-forwards (carrying new objects, which sit in git's quarantine) pass
    let p = w.api(
        "PATCH",
        "/branch_protections/rel",
        Some(json!({"enable_push": true})),
    );
    assert_eq!(p.status, 200);
    let ff = c.ok(&work, Some(&w.auth), &["push", "origin", "rel"]);
    assert!(ff.contains("rel -> rel"), "{ff}");
    // a forced rewrite and a deletion are refused for everyone
    let tip = w.git(&["rev-parse", "refs/heads/rel"]);
    c.ok(&work, None, &["reset", "-q", "--hard", "HEAD~1"]);
    c.commit(&work, "b.txt", "b\n");
    let (ok, out) = c.git_in(&work, Some(&w.auth), &["push", "-f", "origin", "rel"]);
    assert!(
        !ok && out.contains("force-push protected branch rel"),
        "{out}"
    );
    let (ok, out) = c.git_in(&work, Some(&w.auth), &["push", "origin", ":rel"]);
    assert!(!ok && out.contains("delete protected branch rel"), "{out}");
    assert_eq!(
        w.git(&["rev-parse", "refs/heads/rel"]),
        tip,
        "neither attempt moved the branch"
    );

    // an unruled branch is unaffected, including force pushes and deletion
    c.ok(
        &work,
        Some(&w.auth),
        &["push", "-q", "origin", "HEAD:refs/heads/free"],
    );
    c.ok(&work, None, &["commit", "-q", "--amend", "-m", "rewritten"]);
    c.ok(
        &work,
        Some(&w.auth),
        &["push", "-q", "-f", "origin", "HEAD:refs/heads/free"],
    );
    c.ok(&work, Some(&w.auth), &["push", "-q", "origin", ":free"]);

    // removing the rule lifts it
    assert_eq!(w.api("DELETE", "/branch_protections/rel", None).status, 204);
    c.ok(&work, Some(&w.auth), &["push", "-q", "-f", "origin", "rel"]);
}

#[test]
fn a_rule_reserves_its_branch_name_for_a_push_that_creates_it() {
    let w = world();
    let c = Client::new("create");
    let work = c.dir.join("work");
    c.ok(
        &c.dir,
        Some(&w.auth),
        &["clone", "-q", &w.url(), work.to_str().unwrap()],
    );
    w.rule("future", false);
    let (ok, out) = c.git_in(
        &work,
        Some(&w.auth),
        &["push", "origin", "HEAD:refs/heads/future"],
    );
    assert!(!ok && out.contains("protected branch future"), "{out}");
    let r = w.api("GET", "/branches/future", None);
    assert_eq!(r.status, 404);
}

#[test]
fn contents_writes_under_a_rule() {
    let w = world();
    w.git(&["update-ref", "refs/heads/rel", "refs/heads/main"]);
    w.rule("rel", false);
    let write = |body: Value| w.api("POST", "/contents/f.txt", Some(body));
    let denied = write(json!({"content": b64s("x\n"), "message": "m", "branch": "rel"}));
    assert_eq!(denied.status, 403);
    assert!(
        denied.msg().contains("user cannot commit to repo"),
        "{}",
        denied.msg()
    );
    // a new branch cut from a protected base is fine (the rule covers the target), the name of a ruled branch is not
    let ok = write(
        json!({"content": b64s("x\n"), "message": "m", "branch": "rel", "new_branch": "topic"}),
    );
    assert_eq!(ok.status, 201, "{}", ok.msg());
    w.rule("reserved", false);
    let r = w.api(
        "POST",
        "/contents/g.txt",
        Some(json!({"content": b64s("x\n"), "message": "m", "branch": "main", "new_branch": "reserved"})),
    );
    assert_eq!(r.status, 403, "{}", r.msg());
    assert_eq!(w.api("GET", "/branches/reserved", None).status, 404);
    // enable_push=true allows the write
    w.api(
        "PATCH",
        "/branch_protections/rel",
        Some(json!({"enable_push": true})),
    );
    let ok = write(json!({"content": b64s("y\n"), "message": "m", "branch": "rel"}));
    assert_eq!(ok.status, 201, "{}", ok.msg());
}

#[test]
fn deleting_a_protected_branch_through_the_api_is_refused() {
    let w = world();
    w.git(&["update-ref", "refs/heads/rel", "refs/heads/main"]);
    w.git(&["update-ref", "refs/heads/loose", "refs/heads/main"]);
    w.rule("rel", true);
    let r = w.api("DELETE", "/branches/rel", None);
    assert_eq!(r.status, 403);
    assert!(r.msg().contains("protected"), "{}", r.msg());
    assert_eq!(w.api("GET", "/branches/rel", None).status, 200);
    assert_eq!(w.api("DELETE", "/branches/loose", None).status, 204);
    assert_eq!(
        w.api("DELETE", "/branches/main", None).msg(),
        "can not delete default branch"
    );
}

#[test]
fn a_rule_change_is_ordered_against_contents_writes() {
    let w = world();
    w.git(&["update-ref", "refs/heads/rel", "refs/heads/main"]);
    w.rule("rel", true);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (tip_after_change, ok_count) = std::thread::scope(|sc| {
        let writer = sc.spawn(|| {
            let mut ok = 0;
            let mut i = 0;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                i += 1;
                let r = w.api(
                    "POST",
                    &format!("/contents/n{i}.txt"),
                    Some(json!({"content": b64s("x\n"), "message": "m", "branch": "rel"})),
                );
                match r.status {
                    201 => ok += 1,
                    403 | 409 | 503 => {}
                    s => panic!("unexpected {s}: {}", r.msg()),
                }
            }
            ok
        });
        std::thread::sleep(std::time::Duration::from_millis(400));
        let p = w.api(
            "PATCH",
            "/branch_protections/rel",
            Some(json!({"enable_push": false})),
        );
        assert_eq!(p.status, 200, "{}", p.msg());
        let tip = w.git(&["rev-parse", "refs/heads/rel"]);
        // a write attempted after the change returned is refused (and the writer keeps trying)
        let after = w.api(
            "POST",
            "/contents/after.txt",
            Some(json!({"content": b64s("x\n"), "message": "m", "branch": "rel"})),
        );
        assert_eq!(after.status, 403, "{}", after.msg());
        std::thread::sleep(std::time::Duration::from_millis(400));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        (tip, writer.join().unwrap())
    });
    assert!(ok_count > 0, "the writer made progress before the change");
    assert_eq!(
        w.git(&["rev-parse", "refs/heads/rel"]),
        tip_after_change,
        "no write lands after the rule change returned"
    );
}

#[test]
fn statuses_round_trip_and_their_limits() {
    let w = world();
    let sha = w.git(&["rev-parse", "refs/heads/main"]);
    let post = |p: &str, b: Value| w.api("POST", p, Some(b));
    let r = post(
        &format!("/statuses/{sha}"),
        json!({"state": "success", "context": "ci/test", "description": "ok", "target_url": "https://ci.example/1"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let j = r.json();
    assert_eq!(j["status"], "success");
    assert_eq!(j["creator"]["login"], "siteadmin");
    assert_eq!(
        j["creator"]["email"], "siteadmin@noreply.localhost",
        "the stored address is never shown"
    );
    assert_eq!(j["creator"]["is_admin"], false);
    post(
        &format!("/statuses/{sha}"),
        json!({"state": "failure", "context": "ci/lint"}),
    );
    post(
        "/statuses/main",
        json!({"state": "pending", "context": "ci/test"}),
    );
    let c = w.api("GET", &format!("/commits/{sha}/status"), None).json();
    assert_eq!(c["state"], "failure");
    assert_eq!(c["sha"], sha.as_str());
    assert_eq!(
        c["statuses"].as_array().unwrap().len(),
        2,
        "latest per context"
    );
    assert_eq!(
        c["statuses"][0]["context"], "ci/lint",
        "oldest latest first"
    );
    let h = w.api("GET", &format!("/commits/{sha}/statuses"), None);
    assert_eq!(h.json().as_array().unwrap().len(), 3);
    assert_eq!(h.json()[0]["status"], "pending", "newest first");
    assert_eq!(
        w.api("GET", &format!("/statuses/{sha}?limit=2&page=2"), None)
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );

    for (name, body, status) in [
        ("unknown state", json!({"state": "bogus"}), 422),
        ("missing state", json!({"context": "x"}), 422),
        (
            "script url",
            json!({"state": "success", "target_url": "javascript:alert(1)"}),
            422,
        ),
        (
            "long context",
            json!({"state": "success", "context": "x".repeat(1025)}),
            422,
        ),
        (
            "bad type",
            json!({"state": "success", "description": 5}),
            422,
        ),
    ] {
        let r = post(&format!("/statuses/{sha}"), body);
        assert_eq!(r.status, status, "{name}: {}", r.msg());
    }
    let nope = post("/statuses/nope", json!({"state": "success"}));
    assert_eq!(nope.status, 404);
    let unknown = post(
        &format!("/statuses/{}", "0".repeat(40)),
        json!({"state": "success"}),
    );
    assert_eq!(unknown.status, 404);
    assert_eq!(
        w.api("GET", &format!("/commits/{}/status", "0".repeat(40)), None)
            .status,
        404
    );

    // a read-only collaborator cannot post
    let pw = w.s.mk_user("carol");
    let t = token(&w.s.mk_token("carol", &pw, "t", &["all"]));
    w.api(
        "PUT",
        "/collaborators/carol",
        Some(json!({"permission": "read"})),
    );
    let r = w.s.send(
        "POST",
        &format!("/api/v1/repos/siteadmin/w/statuses/{sha}"),
        Some(&t),
        Some(&json!({"state": "success"})),
    );
    assert_eq!(r.status, 403);
    assert!(r.msg().contains("permission to write"), "{}", r.msg());
}

#[test]
fn combined_status_does_not_deadlock_against_exclusive_repository_operations() {
    // The combined status reads the repository twice (the revision, then the repository object);
    // an exclusive operation (branch delete) queued between the two must not wedge either.
    let w = world();
    let sha = w.git(&["rev-parse", "refs/heads/main"]);
    let r = w.api(
        "POST",
        &format!("/statuses/{sha}"),
        Some(json!({"state": "success", "context": "c"})),
    );
    assert_eq!(r.status, 201);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|sc| {
        for _ in 0..3 {
            sc.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let r = w.api("GET", &format!("/commits/{sha}/status"), None);
                    assert_eq!(r.status, 200, "{}", r.msg());
                }
            });
        }
        let (wr, shar, stopr) = (&w, &sha, &stop);
        sc.spawn(move || {
            for i in 0..40 {
                wr.git(&["update-ref", &format!("refs/heads/t{i}"), shar]);
                let r = wr.api("DELETE", &format!("/branches/t{i}"), None);
                assert_eq!(r.status, 204, "{}", r.msg());
            }
            stopr.store(true, std::sync::atomic::Ordering::SeqCst);
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(60)).is_ok(),
            "the deletes finished: no reader wedged the exclusive lock"
        );
    });
}

// ---- the bypass matrix: every write path against every rule setting and role ----

impl W {
    fn as_(&self, auth: &str, method: &str, path: &str, body: Option<Value>) -> Resp {
        self.s.send(
            method,
            &format!("/api/v1/repos/siteadmin/w{path}"),
            Some(auth),
            body.as_ref(),
        )
    }
}

/// One cell group of the matrix: a protected non-default branch `rel` with `enable_push = push`,
/// and `who` (an administrator or a write collaborator) trying each way to move or remove it.
fn matrix(push: bool, who: &str) {
    let w = world();
    let c = Client::new(&format!("matrix-{push}-{who}"));
    let auth = if who == "admin" {
        w.auth.clone()
    } else {
        let pw = w.s.mk_user("writer");
        let t = token(&w.s.mk_token("writer", &pw, "t", &["all"]));
        let r = w.api(
            "PUT",
            "/collaborators/writer",
            Some(json!({"permission": "write"})),
        );
        assert_eq!(r.status, 204);
        t
    };
    let work = c.dir.join("work");
    c.ok(
        &c.dir,
        Some(&w.auth),
        &["clone", "-q", &w.url(), work.to_str().unwrap()],
    );
    c.ok(&work, None, &["checkout", "-q", "-b", "rel"]);
    c.ok(&work, Some(&w.auth), &["push", "-q", "origin", "rel"]);
    w.rule("rel", push);
    let tag = format!("[push={push} who={who}]");

    // a pull request into `rel`, opened before any of the attempts
    let r = w.api(
        "POST",
        "/contents/t.txt",
        Some(
            json!({"content": b64s("t\n"), "message": "m", "branch": "rel", "new_branch": "topic"}),
        ),
    );
    assert_eq!(r.status, 201, "{tag} {}", r.msg());
    let pr = w.as_(
        &auth,
        "POST",
        "/pulls",
        Some(json!({"title": "t", "head": "topic", "base": "rel"})),
    );
    assert_eq!(pr.status, 201, "{tag} {}", pr.msg());
    let n = pr.json()["number"].as_i64().unwrap();

    let write = |path: &str| {
        w.as_(
            &auth,
            "POST",
            &format!("/contents/{path}"),
            Some(json!({"content": b64s("x\n"), "message": "m", "branch": "rel"})),
        )
        .status
    };
    // direct pushes
    c.commit(&work, "a.txt", "a\n");
    let (ff_ok, _) = c.git_in(&work, Some(&auth), &["push", "origin", "rel"]);
    assert_eq!(ff_ok, push, "{tag} fast-forward push");
    let tip = w.git(&["rev-parse", "refs/heads/rel"]);
    if push {
        assert_ne!(tip, w.git(&["rev-parse", "refs/heads/main"]));
    }
    c.ok(&work, None, &["reset", "-q", "--hard", "HEAD~1"]);
    c.commit(&work, "b.txt", "b\n");
    let (force_ok, _) = c.git_in(&work, Some(&auth), &["push", "-f", "origin", "rel"]);
    assert!(!force_ok, "{tag} force push");
    let (del_ok, _) = c.git_in(&work, Some(&auth), &["push", "origin", ":rel"]);
    assert!(!del_ok, "{tag} push delete");
    assert_eq!(
        w.git(&["rev-parse", "refs/heads/rel"]),
        tip,
        "{tag} neither refused push moved rel"
    );
    // the API
    assert_eq!(write("c.txt") == 201, push, "{tag} contents write");
    assert_eq!(
        w.as_(&auth, "DELETE", "/branches/rel", None).status,
        403,
        "{tag} branch delete"
    );
    let nb = w.as_(&auth, "POST", "/contents/d.txt", Some(json!({"content": b64s("d\n"), "message": "m", "branch": "rel", "new_branch": "off-rel"})));
    assert_eq!(
        nb.status,
        201,
        "{tag} a new branch cut from a protected one is allowed: {}",
        nb.msg()
    );
    // a merge is the one way in when pushes are off; it works for both settings
    let m = w.as_(
        &auth,
        "POST",
        &format!("/pulls/{n}/merge"),
        Some(json!({"Do": "merge"})),
    );
    assert_eq!(m.status, 200, "{tag} merge: {}", m.msg());
    assert_ne!(
        w.git(&["rev-parse", "refs/heads/rel"]),
        tip,
        "{tag} the merge moved rel"
    );
    assert_eq!(w.git(&["for-each-ref", "refs/forge/merge"]), "", "{tag}");
}

#[test]
fn bypass_matrix_pushes_off_administrator() {
    matrix(false, "admin");
}

#[test]
fn bypass_matrix_pushes_off_writer() {
    matrix(false, "writer");
}

#[test]
fn bypass_matrix_pushes_on_administrator() {
    matrix(true, "admin");
}

#[test]
fn bypass_matrix_pushes_on_writer() {
    matrix(true, "writer");
}
