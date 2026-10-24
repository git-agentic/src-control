//! F4b: pull requests, reviews and comments, with real git where refs matter.
//! Branches are made through the contents API (a commit per file) so each test reads as a story.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::{json, Value};

struct W {
    s: Srv,
    auth: String,
    id: i64,
}

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
        self.as_(&self.auth, method, path, body)
    }
    fn as_(&self, auth: &str, method: &str, path: &str, body: Option<Value>) -> Resp {
        self.s.send(
            method,
            &format!("/api/v1/repos/siteadmin/w{path}"),
            Some(auth),
            body.as_ref(),
        )
    }
    fn git(&self, args: &[&str]) -> String {
        self.s.git(self.id, args, None)
    }
    /// One more commit on `branch` (created from `from` when `new`).
    fn commit(&self, branch: &str, file: &str, new_from: Option<&str>) -> String {
        let mut body = json!({"content": b64("x\n"), "message": format!("add {file}"), "branch": new_from.unwrap_or(branch)});
        if new_from.is_some() {
            body["new_branch"] = json!(branch);
        }
        let r = self.api("POST", &format!("/contents/{file}"), Some(body));
        assert_eq!(r.status, 201, "{}", r.msg());
        self.git(&["rev-parse", &format!("refs/heads/{branch}")])
    }
    fn open(&self, head: &str) -> Value {
        let r = self.api(
            "POST",
            "/pulls",
            Some(json!({"title": format!("PR {head}"), "body": "b", "head": head, "base": "main"})),
        );
        assert_eq!(r.status, 201, "{}", r.msg());
        r.json()
    }
    fn retained(&self, n: i64) -> Option<String> {
        self.s.git_try(
            self.id,
            &[
                "rev-parse",
                "--verify",
                "-q",
                &format!("refs/forge/pull/{n}/head"),
            ],
        )
    }
}

#[test]
fn create_validates_and_the_object_has_the_recorded_shape() {
    let w = world();
    let f1 = w.commit("f1", "f1.txt", Some("main"));
    let base = w.git(&["rev-parse", "refs/heads/main"]);
    let pr = w.open("f1");
    assert_eq!(pr["number"], 1);
    assert_eq!(pr["state"], "open");
    assert_eq!(pr["merged"], false);
    assert_eq!(pr["mergeable"], true);
    assert_eq!(pr["changed_files"], 1);
    assert_eq!(pr["additions"], 1);
    assert_eq!(pr["head"]["sha"], f1.as_str());
    assert_eq!(pr["base"]["sha"], base.as_str());
    assert_eq!(pr["merge_base"], base.as_str());
    assert_eq!(pr["head"]["repo"]["full_name"], "siteadmin/w");
    assert_eq!(pr["user"]["login"], "siteadmin");
    assert_eq!(
        w.retained(1).as_deref(),
        Some(f1.as_str()),
        "the head is retained at creation"
    );

    for (name, body, status, text) in [
        (
            "duplicate",
            json!({"title": "t", "head": "f1", "base": "main"}),
            409,
            "pull request already exists",
        ),
        (
            "same branch",
            json!({"title": "t", "head": "main", "base": "main"}),
            422,
            "no changes between the head and the base",
        ),
        (
            "no head",
            json!({"title": "t", "head": "nope", "base": "main"}),
            404,
            "couldn't be found",
        ),
        (
            "no base",
            json!({"title": "t", "head": "f1", "base": "nope"}),
            404,
            "BaseNotExist",
        ),
        (
            "no title",
            json!({"head": "f1", "base": "main"}),
            422,
            "[Title]: Required",
        ),
        (
            "other repository",
            json!({"title": "t", "head": "someone:f1", "base": "main"}),
            404,
            "couldn't be found",
        ),
        (
            "bad branch",
            json!({"title": "t", "head": "a..b", "base": "main"}),
            404,
            "couldn't be found",
        ),
    ] {
        let r = w.api("POST", "/pulls", Some(body));
        assert!(
            r.status == status && r.msg().contains(text),
            "{name}: {} {}",
            r.status,
            r.msg()
        );
    }
    // `owner:branch` naming this repository is the same branch
    w.commit("f2", "f2.txt", Some("main"));
    let r = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "t", "head": "siteadmin:f2", "base": "main"})),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    assert_eq!(r.json()["number"], 2);
}

#[test]
fn the_head_follows_the_branch_and_lists_are_ordered_and_paged() {
    let w = world();
    w.commit("f1", "a.txt", Some("main"));
    w.open("f1");
    let f1b = w.commit("f1", "b.txt", None);
    let got = w.api("GET", "/pulls/1", None).json();
    assert_eq!(got["head"]["sha"], f1b.as_str(), "a push shows immediately");
    assert_eq!(got["changed_files"], 2);
    assert_eq!(
        w.retained(1).as_deref(),
        Some(f1b.as_str()),
        "and is retained"
    );
    w.commit("f2", "c.txt", Some("main"));
    w.open("f2");
    w.commit("f3", "d.txt", Some("main"));
    w.open("f3");
    let list = |q: &str| -> Vec<i64> {
        w.api("GET", &format!("/pulls?{q}"), None)
            .json()
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["number"].as_i64().unwrap())
            .collect()
    };
    assert_eq!(list(""), vec![3, 2, 1]);
    assert_eq!(list("sort=oldest"), vec![1, 2, 3]);
    assert_eq!(list("state=closed"), Vec::<i64>::new());
    assert_eq!(list("limit=2&page=2"), vec![1]);
    let r = w.api("GET", "/pulls?limit=2&state=open", None);
    assert_eq!(r.header("x-total-count").as_deref(), Some("3"));
    assert!(
        r.header("link")
            .unwrap()
            .contains("limit=2&page=2&state=open"),
        "{:?}",
        r.header("link")
    );
    // closing moves it between the lists, and a closed PR keeps the head it had
    let c = w.api("PATCH", "/pulls/2", Some(json!({"state": "closed"})));
    assert_eq!(c.status, 201, "{}", c.msg());
    assert_eq!(c.json()["state"], "closed");
    assert!(c.json()["closed_at"].is_string());
    assert_eq!(list("state=closed"), vec![2]);
    assert_eq!(list("state=all"), vec![3, 2, 1]);
    let r = w.api(
        "PATCH",
        "/pulls/2",
        Some(json!({"state": "open", "title": "renamed"})),
    );
    assert_eq!(
        (r.status, r.json()["title"].as_str().unwrap().to_string()),
        (201, "renamed".to_string())
    );
    assert_eq!(w.api("GET", "/pulls/9", None).status, 404);
    assert_eq!(
        w.api("PATCH", "/pulls/2", Some(json!({"state": "bogus"})))
            .status,
        422
    );
}

#[test]
fn deleting_the_head_branch_closes_the_pull_and_keeps_its_head() {
    let w = world();
    let tip = w.commit("gone", "g.txt", Some("main"));
    w.open("gone");
    let d = w.api("DELETE", "/branches/gone", None);
    assert_eq!(d.status, 204, "{}", d.msg());
    let pr = w.api("GET", "/pulls/1", None).json();
    assert_eq!(
        pr["state"], "closed",
        "recorded: deleting the head closes the PR"
    );
    assert_eq!(pr["head"]["ref"], "refs/pull/1/head");
    assert_eq!(pr["head"]["label"], "gone");
    assert_eq!(pr["head"]["sha"], tip.as_str());
    assert_eq!(w.retained(1).as_deref(), Some(tip.as_str()));
    assert!(
        w.git(&["cat-file", "-t", &tip]).contains("commit"),
        "the commit is still there"
    );
    // diff and commits still work from the retained head
    assert!(w.api("GET", "/pulls/1.diff", None).s_text().contains("+x"));
    assert_eq!(
        w.api("GET", "/pulls/1/commits", None)
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // reopening works without the branch, and a later sync does not close it again
    let re = w.api("PATCH", "/pulls/1", Some(json!({"state": "open"})));
    assert_eq!(re.status, 201);
    assert_eq!(re.json()["state"], "open");
    w.commit("other", "o.txt", Some("main"));
    w.api("DELETE", "/branches/other", None);
    assert_eq!(w.api("GET", "/pulls/1", None).json()["state"], "open");
}

#[test]
fn a_push_that_deletes_or_rewrites_the_head_keeps_it_reachable() {
    use std::process::Command;
    let w = world();
    let c = std::env::temp_dir().join(format!("scl-forge-pulls-push-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&c);
    std::fs::create_dir_all(&c).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("HOME", &c)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "T")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "T")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .arg("-c")
            .arg(format!("http.extraHeader=Authorization: {}", w.auth))
            .args(args)
            .current_dir(&c)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let url = format!("{}/siteadmin/w.git", w.s.base);
    run(&["clone", "-q", &url, "work"]);
    let work = c.join("work");
    let in_work = |args: &[&str]| {
        let out = Command::new("git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("HOME", &c)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "T")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "T")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .arg("-c")
            .arg(format!("http.extraHeader=Authorization: {}", w.auth))
            .args(args)
            .current_dir(&work)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    in_work(&["checkout", "-q", "-b", "pb"]);
    std::fs::write(work.join("p.txt"), "p\n").unwrap();
    in_work(&["add", "."]);
    in_work(&["commit", "-q", "-m", "p1"]);
    in_work(&["push", "-q", "origin", "pb"]);
    w.open("pb");
    let first = in_work(&["rev-parse", "HEAD"]);
    // a forced rewrite moves the PR head and the retention ref
    std::fs::write(work.join("p.txt"), "p2\n").unwrap();
    in_work(&["commit", "-q", "--amend", "-a", "-m", "p1 again"]);
    in_work(&["push", "-q", "-f", "origin", "pb"]);
    let second = in_work(&["rev-parse", "HEAD"]);
    assert_ne!(first, second);
    assert_eq!(
        w.api("GET", "/pulls/1", None).json()["head"]["sha"],
        second.as_str()
    );
    assert_eq!(w.retained(1).as_deref(), Some(second.as_str()));
    // a push that deletes the branch closes the PR on the last head
    in_work(&["push", "-q", "origin", ":pb"]);
    let pr = w.api("GET", "/pulls/1", None).json();
    assert_eq!(pr["state"], "closed");
    assert_eq!(pr["head"]["sha"], second.as_str());
    assert_eq!(w.retained(1).as_deref(), Some(second.as_str()));
    let _ = std::fs::remove_dir_all(&c);
}

#[test]
fn diff_patch_commits_and_files_match_git() {
    let w = world();
    let base = w.git(&["rev-parse", "refs/heads/main"]);
    w.commit("d", "one.txt", Some("main"));
    let head = w.commit("d", "two.txt", None);
    w.open("d");
    let diff = w.api("GET", "/pulls/1.diff", None);
    assert_eq!(diff.status, 200);
    assert_eq!(
        diff.s_text(),
        w.git(&["diff-tree", "-p", "-r", "--no-renames", &base, &head]) + "\n"
    );
    let patch = w.api("GET", "/pulls/1.patch", None).s_text();
    assert!(
        patch.contains("[PATCH 1/2]") && patch.contains("[PATCH 2/2]"),
        "{patch}"
    );
    let commits = w.api("GET", "/pulls/1/commits", None);
    assert_eq!(commits.header("x-total-count").as_deref(), Some("2"));
    assert_eq!(commits.json()[0]["sha"], head.as_str(), "newest first");
    assert_eq!(commits.json()[0]["files"][0]["filename"], "two.txt");
    let files = w.api("GET", "/pulls/1/files", None).json();
    let names: Vec<&str> = files
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["filename"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["one.txt", "two.txt"]);
    assert_eq!(files[0]["status"], "added");
    assert_eq!(files[0]["additions"], 1);
    assert!(files[0]["raw_url"]
        .as_str()
        .unwrap()
        .ends_with(&format!("/raw/commit/{head}/one.txt")));
    assert_eq!(
        w.api("GET", "/pulls/1/merge", None).status,
        404,
        "not merged"
    );
}

#[test]
fn reviews_follow_the_recorded_rules() {
    let w = world();
    w.commit("r", "r.txt", Some("main"));
    // bot opens the PR with write access; alice (write) and carol (read) review
    let mk = |login: &str, perm: &str| {
        let pw = w.s.mk_user(login);
        let t = token(&w.s.mk_token(login, &pw, "t", &["all"]));
        let r = w.api(
            "PUT",
            &format!("/collaborators/{login}"),
            Some(json!({"permission": perm})),
        );
        assert_eq!(r.status, 204);
        t
    };
    let bot = mk("bot", "write");
    let alice = mk("alice", "write");
    let carol = mk("carol", "read");
    let r = w.as_(
        &bot,
        "POST",
        "/pulls",
        Some(json!({"title": "t", "head": "r", "base": "main"})),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let post = |who: &str, ev: &str| {
        w.as_(
            who,
            "POST",
            "/pulls/1/reviews",
            Some(json!({"body": ev, "event": ev})),
        )
    };
    assert_eq!(post(&alice, "REQUEST_CHANGES").json()["official"], true);
    let own = post(&bot, "APPROVED");
    assert_eq!(
        (own.status, own.msg().as_str()),
        (422, "approve your own pull is not allowed")
    );
    assert_eq!(post(&bot, "REQUEST_CHANGES").status, 422);
    assert_eq!(post(&bot, "COMMENT").status, 200, "the author may comment");
    assert_eq!(post(&alice, "APPROVED").json()["official"], true);
    assert_eq!(
        post(&carol, "APPROVED").json()["official"],
        false,
        "no write access"
    );
    let pending = post(&alice, "BOGUS");
    assert_eq!(pending.json()["state"], "PENDING");
    let inline = w.as_(&alice, "POST", "/pulls/1/reviews", Some(json!({"event": "COMMENT", "comments": [{"path": "r.txt", "body": "x", "new_position": 1}]})));
    assert_eq!(
        inline.status, 422,
        "inline comments are refused, not dropped"
    );

    let list = w.as_(&bot, "GET", "/pulls/1/reviews", None);
    let rows = list.json();
    let states: Vec<(String, bool, bool)> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["state"].as_str().unwrap().to_string(),
                r["official"].as_bool().unwrap(),
                r["dismissed"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        states,
        vec![
            ("REQUEST_CHANGES".into(), false, true),
            ("COMMENT".into(), false, false),
            ("APPROVED".into(), true, false),
            ("APPROVED".into(), false, false),
        ],
        "alice's pending review is hidden from bot; her change request was superseded"
    );
    assert_eq!(
        list.header("x-total-count").as_deref(),
        Some("5"),
        "recorded: the total counts the hidden one"
    );
    let mine = w.as_(&alice, "GET", "/pulls/1/reviews", None).json();
    assert_eq!(mine.as_array().unwrap().len(), 5);
    let pid = pending.json()["id"].as_i64().unwrap();
    assert_eq!(
        w.as_(&bot, "GET", &format!("/pulls/1/reviews/{pid}"), None)
            .status,
        404
    );
    assert_eq!(
        w.as_(&alice, "GET", &format!("/pulls/1/reviews/{pid}"), None)
            .status,
        200
    );
    assert_eq!(
        w.as_(
            &alice,
            "GET",
            &format!("/pulls/1/reviews/{pid}/comments"),
            None
        )
        .json(),
        json!([])
    );
    assert_eq!(w.as_(&alice, "GET", "/pulls/7/reviews", None).status, 404);
}

#[test]
fn issue_comments_belong_to_the_pull_and_need_the_issue_scope() {
    let w = world();
    w.commit("c", "c.txt", Some("main"));
    w.open("c");
    let r = w.api("POST", "/issues/1/comments", Some(json!({"body": "hello"})));
    assert_eq!(r.status, 201, "{}", r.msg());
    assert_eq!(r.json()["body"], "hello");
    assert_eq!(r.json()["user"]["email"], "siteadmin@noreply.localhost");
    w.api(
        "POST",
        "/issues/1/comments",
        Some(json!({"body": "second"})),
    );
    let l = w.api("GET", "/issues/1/comments", None);
    assert_eq!(l.header("x-total-count").as_deref(), Some("2"));
    assert_eq!(l.json()[0]["body"], "hello", "oldest first");
    assert_eq!(w.api("GET", "/pulls/1", None).json()["comments"], 2);
    assert_eq!(
        w.api("POST", "/issues/1/comments", Some(json!({"body": " "})))
            .status,
        422
    );
    assert_eq!(
        w.api(
            "POST",
            "/issues/1/comments",
            Some(json!({"body": "x".repeat(70_000)}))
        )
        .status,
        422
    );
    assert_eq!(w.api("GET", "/issues/5/comments", None).status, 404);
    // a token without the issue scope is refused
    let pw = w.s.mk_user("scoped");
    let t = token(&w.s.mk_token("scoped", &pw, "t", &["read:repository", "write:repository"]));
    w.api(
        "PUT",
        "/collaborators/scoped",
        Some(json!({"permission": "write"})),
    );
    assert_eq!(w.as_(&t, "GET", "/issues/1/comments", None).status, 403);
    assert_eq!(
        w.as_(&t, "POST", "/issues/1/comments", Some(json!({"body": "x"})))
            .status,
        403
    );
    assert_eq!(w.as_(&t, "GET", "/pulls/1", None).status, 200);
}

#[test]
fn reads_do_not_deadlock_against_exclusive_repository_operations() {
    let w = world();
    w.commit("s", "s.txt", Some("main"));
    let tip = w.git(&["rev-parse", "refs/heads/s"]);
    w.open("s");
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|sc| {
        for _ in 0..3 {
            sc.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    for p in ["/pulls", "/pulls/1", "/pulls/1/files", "/pulls/1/commits"] {
                        let r = w.api("GET", p, None);
                        assert_eq!(r.status, 200, "{p}: {}", r.msg());
                    }
                }
            });
        }
        let (wr, tipr, stopr) = (&w, &tip, &stop);
        sc.spawn(move || {
            for i in 0..30 {
                wr.git(&["update-ref", &format!("refs/heads/t{i}"), tipr]);
                let r = wr.api("DELETE", &format!("/branches/t{i}"), None);
                assert_eq!(r.status, 204, "{}", r.msg());
            }
            stopr.store(true, std::sync::atomic::Ordering::SeqCst);
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(90)).is_ok(),
            "no reader wedged the exclusive lock"
        );
    });
}

#[test]
fn startup_reconcile_restores_retention_refs_and_closes_vanished_heads() {
    let w = world();
    let tip = w.commit("rc", "rc.txt", Some("main"));
    w.open("rc");
    w.api("PATCH", "/pulls/1", Some(json!({"state": "closed"})));
    // a lost retention ref, a stray one, and a branch removed behind the server's back
    w.git(&["update-ref", "-d", "refs/forge/pull/1/head"]);
    w.git(&["update-ref", "refs/forge/pull/9/head", &tip]);
    w.commit("rc2", "rc2.txt", Some("main"));
    w.open("rc2");
    w.git(&["update-ref", "-d", "refs/heads/rc2"]);
    let conn = scl_forge::db::connect(&w.s.dir).unwrap();
    let git =
        scl_forge::gitproc::Git::new(&w.s.dir, scl_forge::gitproc::find_git().unwrap(), 2).unwrap();
    let dir = w.s.dir.join("repos").join(format!("{}.git", w.id));
    scl_forge::pulls::reconcile_repo(&conn, &git, &dir, w.id, 100).unwrap();
    assert_eq!(
        w.retained(1).as_deref(),
        Some(tip.as_str()),
        "a closed PR gets its ref back"
    );
    assert_eq!(w.retained(9), None, "a ref with no PR is removed");
    assert_eq!(
        w.api("GET", "/pulls/2", None).json()["state"],
        "closed",
        "the vanished head closed it"
    );
    assert!(w.retained(2).is_some());
}

#[test]
fn a_closed_pull_keeps_the_head_it_was_closed_with() {
    let w = world();
    let a = w.commit("k", "k1.txt", Some("main"));
    w.open("k");
    w.api("PATCH", "/pulls/1", Some(json!({"state": "closed"})));
    let b = w.commit("k", "k2.txt", None);
    assert_ne!(a, b);
    let pr = w.api("GET", "/pulls/1", None).json();
    assert_eq!(
        pr["head"]["sha"],
        a.as_str(),
        "the branch moved, the closed PR did not"
    );
    assert_eq!(pr["head"]["ref"], "k");
    assert_eq!(
        w.api("GET", "/pulls/1/commits", None)
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(w.retained(1).as_deref(), Some(a.as_str()));
    // reopening follows the branch again
    let re = w
        .api("PATCH", "/pulls/1", Some(json!({"state": "open"})))
        .json();
    assert_eq!(re["head"]["sha"], b.as_str());
    assert_eq!(
        w.retained(1).as_deref(),
        Some(b.as_str()),
        "sync re-points the ref"
    );
}

#[test]
fn a_stale_sync_never_overwrites_a_newer_retained_head() {
    let w = world();
    let a = w.commit("cas", "c1.txt", Some("main"));
    w.open("cas");
    let git = &w.s.runner;
    let dir = w.s.dir.join("repos").join(format!("{}.git", w.id));
    // someone (the pre-receive hook) recorded a newer tip after the snapshot a sync took
    let b = w.commit("other", "c2.txt", Some("main"));
    assert!(
        !scl_forge::pulls::retain_cas(git, &dir, 1, &b, Some(&"1".repeat(40))).unwrap(),
        "wrong expectation: refused"
    );
    assert_eq!(w.retained(1).as_deref(), Some(a.as_str()), "untouched");
    assert!(scl_forge::pulls::retain_cas(git, &dir, 1, &b, Some(&a)).unwrap());
    assert_eq!(w.retained(1).as_deref(), Some(b.as_str()));
    assert!(
        !scl_forge::pulls::retain_cas(git, &dir, 1, &a, None).unwrap(),
        "create-only refuses an existing ref"
    );
}

#[test]
fn page_links_select_the_rows_the_page_did() {
    let w = world();
    for i in 0..3 {
        w.commit(&format!("p{i}"), &format!("p{i}.txt"), Some("main"));
        w.open(&format!("p{i}"));
    }
    // an encoded name is not `limit` for the server, so it is not for the next page either
    let r = w.api("GET", "/pulls?%6cimit=2&limit=1&sort=oldest", None);
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    let link = r.header("link").unwrap();
    assert!(
        link.contains("limit=1&page=2") && !link.contains("limit=2"),
        "{link}"
    );
    // a bare key is ignored by the server and not repeated
    let r = w.api("GET", "/pulls?sort&sort=oldest&limit=1", None);
    assert_eq!(r.json()[0]["number"], 1);
    assert!(r.header("link").unwrap().contains("sort=oldest"));
    // a hostile query cannot break out of the link target
    let r = w.api("GET", "/pulls?limit=1&x=%3E%2C%3Chttp://evil%3E", None);
    let link = r.header("link").unwrap();
    assert!(
        !link.contains("evil>") && link.matches('<').count() == link.matches("; rel=").count(),
        "{link}"
    );
}

#[test]
fn startup_reconcile_covers_repositories_without_any_pull() {
    let w = world();
    let tip = w.git(&["rev-parse", "refs/heads/main"]);
    w.git(&["update-ref", "refs/forge/pull/1/head", &tip]); // an orphan of a crashed first creation
    let conn = scl_forge::db::connect(&w.s.dir).unwrap();
    scl_forge::pulls::reconcile_all(&w.s.app.life, &conn, 100);
    assert_eq!(w.retained(1), None);
}
