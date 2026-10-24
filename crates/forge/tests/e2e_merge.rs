//! F4c: merging a pull request, its refusals, concurrency and the crash-recovery journal.
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
    fn git_try(&self, args: &[&str]) -> Option<String> {
        self.s.git_try(self.id, args)
    }
    fn tip(&self, branch: &str) -> String {
        self.git(&["rev-parse", &format!("refs/heads/{branch}")])
    }
    /// A commit adding `file` with `text` on `branch` (created from `from` when given).
    fn commit(&self, branch: &str, file: &str, text: &str, from: Option<&str>) -> String {
        let mut body = json!({"content": b64(text), "message": format!("add {file}"), "branch": from.unwrap_or(branch)});
        if from.is_some() {
            body["new_branch"] = json!(branch);
        }
        let r = self.api("POST", &format!("/contents/{file}"), Some(body));
        assert_eq!(r.status, 201, "{}", r.msg());
        self.tip(branch)
    }
    fn open(&self, head: &str, base: &str) -> i64 {
        let r = self.api(
            "POST",
            "/pulls",
            Some(json!({"title": format!("PR {head}"), "head": head, "base": base})),
        );
        assert_eq!(r.status, 201, "{}", r.msg());
        r.json()["number"].as_i64().unwrap()
    }
    fn merge(&self, n: i64, body: Value) -> Resp {
        self.api("POST", &format!("/pulls/{n}/merge"), Some(body))
    }
    fn no_leftovers(&self) {
        let conn = scl_forge::db::connect(&self.s.dir).unwrap();
        assert!(
            !scl_forge::merges::has_pending(&conn, self.id),
            "a pending intent is left"
        );
        assert_eq!(
            self.git(&["for-each-ref", "refs/forge/merge"]),
            "",
            "a receipt is left"
        );
    }
}

#[test]
fn a_clean_merge_makes_a_two_parent_commit_and_a_merged_pull() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let base = w.tip("main");
    let n = w.open("f", "main");
    assert_eq!(w.api("GET", &format!("/pulls/{n}/merge"), None).status, 404);
    let r = w.merge(n, json!({"Do": "merge", "head_commit_id": head}));
    assert_eq!(
        (r.status, r.raw.len()),
        (200, 0),
        "{}",
        String::from_utf8_lossy(&r.raw)
    );
    let m = w.tip("main");
    assert_ne!(m, base);
    let parents = w.git(&["rev-list", "--parents", "-n", "1", &m]);
    assert_eq!(
        parents,
        format!("{m} {base} {head}"),
        "first parent is the base, second the head"
    );
    assert_eq!(
        w.git(&["log", "-1", "--format=%s", &m]),
        "Merge pull request 'PR f' (#1) from f into main"
    );
    assert_eq!(w.git(&["log", "-1", "--format=%an", &m]), "siteadmin");
    assert_eq!(w.git(&["show", &format!("{m}:f.txt")]), "f");
    let pr = w.api("GET", &format!("/pulls/{n}"), None).json();
    assert_eq!(
        (pr["merged"].clone(), pr["state"].clone()),
        (json!(true), json!("closed"))
    );
    assert_eq!(pr["merge_commit_sha"], m.as_str());
    assert_eq!(pr["merged_by"]["login"], "siteadmin");
    assert_eq!(pr["head"]["sha"], head.as_str());
    assert_eq!(pr["mergeable"], false);
    assert!(pr["merged_at"].is_string() && pr["closed_at"].is_string());
    assert_eq!(w.api("GET", &format!("/pulls/{n}/merge"), None).status, 204);
    assert_eq!(
        w.git(&["rev-parse", "refs/forge/pull/1/head"]),
        head,
        "the head stays retained"
    );
    w.no_leftovers();
    // the branch keeps moving; the merged PR does not follow
    w.commit("f", "g.txt", "g\n", None);
    assert_eq!(
        w.api("GET", &format!("/pulls/{n}"), None).json()["head"]["sha"],
        head.as_str()
    );
    let again = w.merge(n, json!({"Do": "merge"}));
    assert_eq!(
        (again.status, again.msg().as_str()),
        (405, "The PR is already merged")
    );
}

#[test]
fn refusals_are_the_recorded_ones() {
    let w = world();
    w.commit("a", "a.txt", "a\n", Some("main"));
    let n = w.open("a", "main");
    let msg = |r: Resp| (r.status, r.msg());
    assert_eq!(
        msg(w.merge(n, json!({"Do": "bogus"}))),
        (422, "[Do]: In".into())
    );
    assert_eq!(msg(w.merge(n, json!({}))), (422, "[Do]: Required".into()));
    for style in ["squash", "rebase", "rebase-merge", "fast-forward-only"] {
        let r = w.merge(n, json!({"Do": style}));
        assert!(
            r.status == 422 && r.msg().contains("merge"),
            "{style}: {}",
            r.msg()
        );
    }
    assert_eq!(
        msg(w.merge(n, json!({"Do": "merge", "head_commit_id": "0".repeat(40)}))),
        (409, "head out of date".into())
    );
    assert_eq!(w.merge(99, json!({"Do": "merge"})).status, 404);
    // a read-only collaborator may not merge
    let pw = w.s.mk_user("reader");
    let t = token(&w.s.mk_token("reader", &pw, "t", &["all"]));
    w.api(
        "PUT",
        "/collaborators/reader",
        Some(json!({"permission": "read"})),
    );
    assert_eq!(
        w.as_(
            &t,
            "POST",
            &format!("/pulls/{n}/merge"),
            Some(json!({"Do": "merge"}))
        )
        .status,
        403
    );
    // a conflict names the paths
    w.commit("c1", "x.txt", "one\n", Some("main"));
    w.commit("c2", "x.txt", "two\n", Some("main"));
    let c1 = w.open("c1", "main");
    let c2 = w.open("c2", "main");
    assert_eq!(w.merge(c1, json!({"Do": "merge"})).status, 200);
    let r = w.merge(c2, json!({"Do": "merge"}));
    assert_eq!((r.status, r.msg()), (409, "Merge conflict: x.txt".into()));
    // a head already contained in the base: nothing to merge
    let tip = w.tip("main");
    w.git(&["update-ref", "refs/heads/inside", &tip]);
    w.commit("tmp", "t.txt", "t\n", Some("main"));
    let r = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "t", "head": "inside", "base": "main"})),
    );
    assert_eq!(r.status, 201, "a contained head may be opened: {}", r.msg());
    let inside = r.json()["number"].as_i64().unwrap();
    let r = w.merge(inside, json!({"Do": "merge"}));
    assert_eq!(
        (r.status, r.msg().as_str()),
        (405, "Please try again later")
    );
    // unrelated histories
    let tree = w.git(&["mktree"]);
    let root = {
        let out = w.s.git(w.id, &["commit-tree", &tree], Some(b"orphan\n"));
        w.git(&["update-ref", "refs/heads/orph", &out]);
        out
    };
    let _ = root;
    let o = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "o", "head": "orph", "base": "main"})),
    );
    assert_eq!(o.status, 201, "{}", o.msg());
    let r = w.merge(o.json()["number"].as_i64().unwrap(), json!({"Do": "merge"}));
    assert_eq!(
        (r.status, r.msg()),
        (409, "Merge conflict: unrelated histories".into())
    );
    // closed and head-deleted pulls are not found
    w.commit("d", "d.txt", "d\n", Some("main"));
    let d = w.open("d", "main");
    w.api(
        "PATCH",
        &format!("/pulls/{d}"),
        Some(json!({"state": "closed"})),
    );
    assert_eq!(w.merge(d, json!({"Do": "merge"})).status, 404);
    w.commit("e", "e.txt", "e\n", Some("main"));
    let e = w.open("e", "main");
    w.api("DELETE", "/branches/e", None);
    assert_eq!(w.merge(e, json!({"Do": "merge"})).status, 404);
    w.no_leftovers();
}

#[test]
fn required_checks_are_read_at_merge_time_and_a_merge_ignores_enable_push() {
    let w = world();
    let head = w.commit("r", "r.txt", "r\n", Some("main"));
    let n = w.open("r", "main");
    // the rule appears after the PR exists: the merge sees it
    let rule = w.api("POST", "/branch_protections", Some(json!({"branch_name": "main", "enable_push": false, "enable_status_check": true, "status_check_contexts": ["ci/test"]})));
    assert_eq!(rule.status, 201);
    let refused = |w: &W| {
        let r = w.merge(n, json!({"Do": "merge"}));
        assert_eq!(r.status, 405, "{}", r.msg());
        assert!(
            r.msg()
                .contains("Not all required status checks successful"),
            "{}",
            r.msg()
        );
    };
    refused(&w);
    for (state, ctx, sha) in [
        ("success", "ci/other", head.clone()),
        ("failure", "ci/test", head.clone()),
        ("pending", "ci/test", head.clone()),
        ("warning", "ci/test", head.clone()),
        ("error", "ci/test", head.clone()),
        ("success", "ci/test", w.tip("main")),
    ] {
        let r = w.api(
            "POST",
            &format!("/statuses/{sha}"),
            Some(json!({"state": state, "context": ctx})),
        );
        assert_eq!(r.status, 201);
        refused(&w);
    }
    w.api(
        "POST",
        &format!("/statuses/{head}"),
        Some(json!({"state": "skipped", "context": "ci/test"})),
    );
    let r = w.merge(n, json!({"Do": "merge"}));
    assert_eq!(
        r.status,
        200,
        "skipped satisfies the check, and enable_push=false does not block a merge: {}",
        r.msg()
    );
    // the protected branch still refuses a direct contents write
    let denied = w.api(
        "POST",
        "/contents/z.txt",
        Some(json!({"content": b64("z"), "message": "m", "branch": "main"})),
    );
    assert_eq!(denied.status, 403);
    w.no_leftovers();
}

#[test]
fn concurrent_merges_into_one_base_all_land_and_nothing_is_left_over() {
    let w = world();
    let n = 6;
    for i in 0..n {
        w.commit(&format!("m{i}"), &format!("m{i}.txt"), "x\n", Some("main"));
        w.open(&format!("m{i}"), "main");
    }
    let results: Vec<(u16, String)> = std::thread::scope(|sc| {
        let hs: Vec<_> = (1..=n)
            .map(|i| {
                let w = &w;
                sc.spawn(move || {
                    let r = w.merge(i, json!({"Do": "merge"}));
                    (r.status, String::from_utf8_lossy(&r.raw).to_string())
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (status, body) in &results {
        assert!(matches!(*status, 200 | 503), "unexpected {status}: {body}");
    }
    // anything the gate timed out on merges afterwards
    for i in 1..=n {
        let p = w.api("GET", &format!("/pulls/{i}"), None).json();
        if p["merged"] != json!(true) {
            assert_eq!(w.merge(i, json!({"Do": "merge"})).status, 200);
        }
    }
    for i in 0..n {
        assert!(
            w.git_try(&["cat-file", "-e", &format!("refs/heads/main:m{i}.txt")])
                .is_some(),
            "m{i}.txt is on main"
        );
    }
    assert_eq!(
        w.git(&["rev-list", "--merges", "--count", "main"]),
        n.to_string()
    );
    w.no_leftovers();
}

#[test]
fn a_writer_moving_the_base_during_merges_loses_nothing() {
    let w = world();
    let n = 4;
    for i in 0..n {
        w.commit(&format!("m{i}"), &format!("m{i}.txt"), "x\n", Some("main"));
        w.open(&format!("m{i}"), "main");
    }
    let landed = std::sync::Mutex::new(Vec::<String>::new());
    std::thread::scope(|sc| {
        // an independent writer advances main with plumbing, compare-and-swap, like a push would
        sc.spawn(|| {
            // twelve moves, spaced so that a merge round (a handful of git processes) can win between two
            for i in 1..=12 {
                let old = w.tip("main");
                let tree = w.git(&["rev-parse", &format!("{old}^{{tree}}")]);
                let c = w.s.git(
                    w.id,
                    &["commit-tree", &tree, "-p", &old],
                    Some(format!("w{i}\n").as_bytes()),
                );
                if w.git_try(&["update-ref", "refs/heads/main", &c, &old])
                    .is_some()
                {
                    landed.lock().unwrap().push(c);
                }
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        });
        for i in 1..=n {
            let mut ok = false;
            for _ in 0..40 {
                let r = w.merge(i, json!({"Do": "merge"}));
                if r.status == 200 {
                    ok = true;
                    break;
                }
                assert!(matches!(r.status, 405 | 503), "{}: {}", r.status, r.msg());
            }
            assert!(ok, "merge {i} never landed");
        }
    });
    let main = w.tip("main");
    for c in landed.lock().unwrap().iter() {
        assert!(
            w.git_try(&["merge-base", "--is-ancestor", c, &main])
                .is_some(),
            "writer commit {c} was lost"
        );
    }
    for i in 0..n {
        assert!(w
            .git_try(&["cat-file", "-e", &format!("{main}:m{i}.txt")])
            .is_some());
    }
    w.no_leftovers();
}

// ---- crash recovery: the journal decides, not guesswork ----

/// How far a hand-built merge got before the "crash".
#[derive(Clone, Copy, PartialEq)]
enum Crash {
    /// The intent row exists; the base never moved.
    NotPublished,
    /// The base moved; the `landed` marker was not written.
    PublishedOnly,
    /// The base moved and the marker exists.
    PublishedMarked,
}

/// Do by hand what the handler does, up to the crash point.
fn crashed_merge(w: &W, n: i64, head: &str, how: Crash) -> (i64, String, String) {
    let base = w.tip("main");
    let tree = w.git(&["merge-tree", "--write-tree", &base, head]);
    let tree = tree.lines().next().unwrap().to_string();
    let merge = w.s.git(
        w.id,
        &["commit-tree", &tree, "-p", &base, "-p", head],
        Some(b"Merge by hand\n"),
    );
    let conn = scl_forge::db::connect(&w.s.dir).unwrap();
    let uid: i64 = conn
        .query_row("SELECT id FROM users WHERE login = 'siteadmin'", [], |r| {
            r.get(0)
        })
        .unwrap();
    conn.execute(
        "INSERT INTO merge_intents (repo_id, pull_number, base_ref, head_ref, base_oid, head_oid, merge_oid, merge_base, changed_files, additions, deletions, merger_id, merged_unix, state, created_unix) \
         VALUES (?1, ?2, 'main', 'f', ?3, ?4, ?5, ?6, 1, 1, 0, ?7, 12345, 'pending', 12345)",
        rusqlite::params![w.id, n, base, head, merge, base, uid],
    )
    .unwrap();
    let id = conn.last_insert_rowid();
    if how != Crash::NotPublished {
        let script = format!(
            "start\nverify refs/heads/f {head}\nupdate refs/heads/main {merge} {base}\nprepare\ncommit\n"
        );
        w.s.git(w.id, &["update-ref", "--stdin"], Some(script.as_bytes()));
    }
    if how == Crash::PublishedMarked {
        let zero = "0".repeat(40);
        w.git(&[
            "update-ref",
            &format!("refs/forge/merge/{id}/landed"),
            &merge,
            &zero,
        ]);
    }
    (id, base, merge)
}

fn recover(w: &W) {
    let conn = scl_forge::db::connect(&w.s.dir).unwrap();
    let dir = w.s.dir.join("repos").join(format!("{}.git", w.id));
    scl_forge::merges::recover_locked(&conn, &w.s.runner, &dir, w.id).unwrap();
    scl_forge::merges::drop_stale_receipts(&conn, &w.s.runner, &dir, w.id).unwrap();
}

fn pull_state(w: &W, n: i64) -> String {
    let conn = scl_forge::db::connect(&w.s.dir).unwrap();
    conn.query_row("SELECT state FROM pulls WHERE number = ?1", [n], |r| {
        r.get(0)
    })
    .unwrap()
}

fn intent_state(w: &W, id: i64) -> String {
    let conn = scl_forge::db::connect(&w.s.dir).unwrap();
    conn.query_row("SELECT state FROM merge_intents WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .unwrap()
}

#[test]
fn a_merge_that_landed_before_the_crash_is_finalized_with_every_field() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    let (_, _, merge) = crashed_merge(&w, n, &head, Crash::PublishedMarked);
    assert_eq!(pull_state(&w, n), "open", "the database does not know yet");
    recover(&w);
    let pr = w.api("GET", &format!("/pulls/{n}"), None).json();
    assert_eq!(pr["merged"], true);
    assert_eq!(pr["merge_commit_sha"], merge.as_str());
    assert_eq!(pr["merged_by"]["login"], "siteadmin");
    assert_eq!(pr["head"]["sha"], head.as_str());
    assert_eq!(pr["changed_files"], 1);
    w.no_leftovers();
    assert_eq!(
        w.merge(n, json!({"Do": "merge"})).status,
        405,
        "and a retry sees the original outcome"
    );
}

#[test]
fn a_crash_between_the_base_moving_and_its_marker_is_recognized_by_the_base_history() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    let (id, _, merge) = crashed_merge(&w, n, &head, Crash::PublishedOnly);
    assert_eq!(w.git(&["for-each-ref", "refs/forge/merge"]), "");
    recover(&w);
    assert_eq!(intent_state(&w, id), "done");
    let pr = w.api("GET", &format!("/pulls/{n}"), None).json();
    assert_eq!(
        (pr["merged"].clone(), pr["merge_commit_sha"].clone()),
        (json!(true), json!(merge))
    );
    w.no_leftovers();
}

#[test]
fn a_landed_merge_with_its_marker_is_still_merged_after_the_base_was_force_pushed_away() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    let (_, base, merge) = crashed_merge(&w, n, &head, Crash::PublishedMarked);
    // an unprotected base may be rewritten before recovery runs: the marker, not ancestry, decides
    w.git(&["update-ref", "refs/heads/main", &base]);
    assert!(w
        .git_try(&["merge-base", "--is-ancestor", &merge, "main"])
        .is_none());
    recover(&w);
    let pr = w.api("GET", &format!("/pulls/{n}"), None).json();
    assert_eq!(pr["merged"], true);
    assert_eq!(pr["merge_commit_sha"], merge.as_str());
    w.no_leftovers();
}

#[test]
fn an_intent_that_never_published_is_aborted_and_the_pull_can_merge_again() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    let (id, base, _) = crashed_merge(&w, n, &head, Crash::NotPublished);
    assert_eq!(w.tip("main"), base, "nothing was published");
    recover(&w);
    assert_eq!(intent_state(&w, id), "aborted");
    assert_eq!(pull_state(&w, n), "open");
    assert_eq!(w.merge(n, json!({"Do": "merge"})).status, 200);
    w.no_leftovers();
}

#[test]
fn a_git_writer_still_holding_the_base_keeps_the_intent_pending() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    let (id, _, _) = crashed_merge(&w, n, &head, Crash::NotPublished);
    // an orphan `update-ref` from before a crash would hold this lock while it finishes
    let lock =
        w.s.dir
            .join("repos")
            .join(format!("{}.git", w.id))
            .join("refs/heads/main.lock");
    std::fs::write(&lock, b"").unwrap();
    recover(&w);
    assert_eq!(
        intent_state(&w, id),
        "pending",
        "not judged while the base is held"
    );
    // and nothing may change the pull request meanwhile
    let r = w.api(
        "PATCH",
        &format!("/pulls/{n}"),
        Some(json!({"state": "closed"})),
    );
    assert_eq!(r.status, 503, "{}", r.msg());
    assert_eq!(pull_state(&w, n), "open");
    std::fs::remove_file(&lock).unwrap();
    recover(&w);
    assert_eq!(intent_state(&w, id), "aborted");
}

#[test]
fn a_close_cannot_overtake_a_landed_merge() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    crashed_merge(&w, n, &head, Crash::PublishedMarked);
    // the pull request is still open in the database; the PATCH settles the merge first
    let r = w.api(
        "PATCH",
        &format!("/pulls/{n}"),
        Some(json!({"state": "closed"})),
    );
    assert_eq!(r.status, 422, "{}", r.msg());
    assert_eq!(pull_state(&w, n), "merged");
    w.no_leftovers();
}

#[test]
fn a_read_settles_an_unfinished_merge() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    let (_, _, merge) = crashed_merge(&w, n, &head, Crash::PublishedOnly);
    // the next read of the pull settles it (the gate is free)
    let pr = w.api("GET", &format!("/pulls/{n}"), None).json();
    assert_eq!(pr["merged"], true, "{pr}");
    assert_eq!(pr["merge_commit_sha"], merge.as_str());
    w.no_leftovers();
}

#[test]
fn stray_markers_are_removed_by_the_startup_repair() {
    let w = world();
    let tip = w.tip("main");
    w.git(&["update-ref", "refs/forge/merge/77/landed", &tip]);
    recover(&w);
    assert_eq!(w.git(&["for-each-ref", "refs/forge/merge"]), "");
}

#[test]
fn a_hostile_title_cannot_add_lines_to_the_merge_commit() {
    let w = world();
    w.commit("t", "t.txt", "t\n", Some("main"));
    let r = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "x\n\nSigned-off-by: Eve <eve@example.invalid>\u{1}", "head": "t", "base": "main"})),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    assert_eq!(w.merge(1, json!({"Do": "merge"})).status, 200);
    let m = w.tip("main");
    let body = w.git(&["log", "-1", "--format=%B", &m]);
    assert_eq!(body.lines().count(), 1, "{body:?}");
    assert!(!body.contains("\n"), "{body:?}");
}

#[test]
fn a_stale_lock_on_the_base_does_not_freeze_recovery() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let n = w.open("f", "main");
    let (id, _, _) = crashed_merge(&w, n, &head, Crash::NotPublished);
    let lock =
        w.s.dir
            .join("repos")
            .join(format!("{}.git", w.id))
            .join("refs/heads/main.lock");
    std::fs::write(&lock, b"").unwrap();
    // a lock that has stood for years belongs to a killed writer
    let touched = std::process::Command::new("touch")
        .args(["-t", "202001010000"])
        .arg(&lock)
        .status()
        .unwrap();
    assert!(touched.success());
    recover(&w);
    assert_eq!(intent_state(&w, id), "aborted");
    assert!(!lock.exists(), "the stale lock was removed");
}
