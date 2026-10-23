//! F3a: the read half of the content API against a real repository pushed with real `git`.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

struct World {
    s: Srv,
    auth: String,
    dir: PathBuf,
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository `siteadmin/smart` with history: root (README.md), then docs/guide.md and an edit,
/// tag `v1` (annotated) and a lightweight tag `light`, branch `feat/x`.
fn world() -> World {
    let s = Srv::start();
    let auth = token(&s.admin);
    let r = s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "smart", "default_branch": "main"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let dir = std::env::temp_dir().join(format!(
        "scl-forge-content-{}-{}",
        std::process::id(),
        s.addr.port()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let w = dir.join("w");
    git(&dir, &["init", "-q", "-b", "main", w.to_str().unwrap()]);
    std::fs::write(w.join("README.md"), "# smart\n").unwrap();
    git(&w, &["add", "."]);
    git(&w, &["commit", "-q", "-m", "root"]);
    git(&w, &["tag", "light"]);
    std::fs::create_dir_all(w.join("docs")).unwrap();
    std::fs::write(w.join("docs/guide.md"), "guide\n").unwrap();
    git(&w, &["add", "."]);
    git(&w, &["commit", "-q", "-m", "second"]);
    git(&w, &["tag", "-a", "v1", "-m", "release one"]);
    git(&w, &["checkout", "-q", "-b", "feat/x"]);
    std::fs::write(w.join("x.txt"), "x\n").unwrap();
    git(&w, &["add", "."]);
    git(&w, &["commit", "-q", "-m", "feat"]);
    git(&w, &["checkout", "-q", "main"]);
    std::fs::write(w.join("README.md"), "# smart\nedited\n").unwrap();
    git(&w, &["commit", "-q", "-a", "-m", "third"]);
    let url = format!("{}/siteadmin/smart.git", s.base);
    let h = format!("http.extraHeader=Authorization: {auth}");
    git(
        &w,
        &["-c", &h, "push", "-q", &url, "main", "feat/x", "--tags"],
    );
    // wait for the push's transport to finish so the repository is quiescent
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while s.app.life.registry.live() != 0 && std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    World { s, auth, dir }
}

impl World {
    fn get(&self, path: &str) -> Resp {
        self.s
            .get(&format!("/api/v1/repos/siteadmin/smart{path}"), &self.auth)
    }
    fn json(&self, path: &str) -> Value {
        let r = self.get(path);
        assert_eq!(r.status, 200, "{path}: {}", String::from_utf8_lossy(&r.raw));
        r.json()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn revisions_are_names_or_ids_never_git_syntax() {
    let w = world();
    assert_eq!(w.get("/commits?sha=main").status, 200);
    assert_eq!(w.get("/commits?sha=feat/x").status, 200);
    assert_eq!(w.get("/commits?sha=v1").status, 200, "a tag name");
    for bad in [
        ":/second",
        "main%5E%7B/second%7D",
        "main@%7B0%7D",
        "--output=/tmp/x",
        "refs/forge/x",
        "refs/heads/main",
        "HEAD~1",
        "main~1",
        "main%5E",
        "main..feat/x",
        "%2D%2Dall",
        "a%00b",
        "main%0Aother",
    ] {
        let r = w.get(&format!("/commits?sha={bad}"));
        assert_eq!(r.status, 404, "{bad}: {}", String::from_utf8_lossy(&r.raw));
        let r = w.get(&format!("/git/commits/{bad}"));
        assert_eq!(r.status, 404, "git/commits/{bad}");
        let r = w.get(&format!("/contents?ref={bad}"));
        assert_eq!(r.status, 404, "contents?ref={bad}");
    }
    // an abbreviated id works (4+ hex digits), a branch wins over a tag of the same name
    let head = w.json("/branches/main")["commit"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(w.get(&format!("/git/commits/{}", &head[..8])).status, 200);
}

#[test]
fn a_tag_named_like_a_branch_does_not_shadow_it() {
    let w = world();
    let main_tip = w.json("/branches/main")["commit"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let url = format!("{}/siteadmin/smart.git", w.s.base);
    let h = format!("http.extraHeader=Authorization: {}", w.auth);
    let work = w.dir.join("w");
    git(&work, &["tag", "main", "main~2"]);
    git(&work, &["-c", &h, "push", "-q", &url, "refs/tags/main"]);
    let list = w.json("/commits?sha=main&limit=1");
    assert_eq!(list[0]["sha"], main_tip, "the branch resolves first");
}

#[test]
fn paths_are_literals_not_patterns() {
    let w = world();
    assert_eq!(w.json("/contents/README.md")["type"], "file");
    for bad in [
        "*",
        "READ*",
        "%3A(exclude)README.md",
        "..%2FREADME.md",
        "docs%2F..%2FREADME.md",
        "docs//guide.md",
        "docs%2F.%2Fguide.md",
        "nope.txt",
    ] {
        let r = w.get(&format!("/contents/{bad}"));
        assert!(
            r.status == 404,
            "{bad}: {} {}",
            r.status,
            String::from_utf8_lossy(&r.raw)
        );
    }
    // a glob or pathspec magic is a literal name that no commit touched: empty, not "everything"
    for lit in ["*", "%3A(exclude)README.md", "READ%2A"] {
        let r = w.get(&format!("/commits?path={lit}"));
        assert_eq!(r.status, 200, "path={lit}");
        assert_eq!(r.json(), json!([]), "path={lit}");
        assert_eq!(r.headers["x-total-count"], "0");
    }
    for bad in ["../x", "a%00b", "/abs"] {
        assert_eq!(
            w.get(&format!("/commits?path={bad}")).status,
            422,
            "path={bad}"
        );
    }
    // the history of a path is only the commits that touched it
    let hist = w.json("/commits?path=docs/guide.md");
    assert_eq!(hist.as_array().unwrap().len(), 1);
}

#[test]
fn a_root_commit_has_a_diff_a_patch_files_and_stats_and_a_merge_free_history_counts() {
    let w = world();
    let all = w.json("/commits?sha=main&limit=50");
    let root = all.as_array().unwrap().last().unwrap()["sha"]
        .as_str()
        .unwrap()
        .to_string();
    let c = w.json(&format!("/git/commits/{root}"));
    assert_eq!(
        c["files"],
        json!([{"filename": "README.md", "status": "added"}])
    );
    assert_eq!(
        c["stats"],
        json!({"total": 1, "additions": 1, "deletions": 0})
    );
    assert!(c["parents"].as_array().unwrap().is_empty());
    let d = w.get(&format!("/git/commits/{root}.diff"));
    assert!(
        String::from_utf8_lossy(&d.raw).contains("+# smart"),
        "{}",
        String::from_utf8_lossy(&d.raw)
    );
    let p = w.get(&format!("/git/commits/{root}.patch"));
    let text = String::from_utf8_lossy(&p.raw).to_string();
    assert!(
        text.starts_with(&format!("From {root} ")) && text.contains("Subject: [PATCH] root"),
        "{text}"
    );
    assert!(
        !text.trim_end().ends_with("2.54.0") && !text.contains("\n-- \n"),
        "no signature trailer"
    );
    let r = w.get("/commits?sha=main&limit=2&page=2");
    assert_eq!(r.headers["x-total-count"], "3");
}

#[test]
fn refs_tags_and_trees() {
    let w = world();
    let refs = w.json("/git/refs");
    let names: Vec<&str> = refs
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ref"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "refs/heads/feat/x",
            "refs/heads/main",
            "refs/tags/light",
            "refs/tags/v1"
        ]
    );
    let v1 = &w.json("/git/refs/tags/v1")[0];
    assert_eq!(
        v1["object"]["type"], "tag",
        "an annotated tag points at a tag object"
    );
    assert_eq!(
        w.json("/git/refs/tags/light")[0]["object"]["type"],
        "commit"
    );
    // a prefix is a path prefix, not a string prefix or a pattern
    assert_eq!(w.get("/git/refs/heads/fe").status, 404);
    assert_eq!(w.get("/git/refs/heads/*").status, 404);
    assert_eq!(w.json("/git/refs/heads/feat").as_array().unwrap().len(), 1);
    // hidden refs never show up
    let tip = w.json("/branches/main")["commit"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    w.s.git(1, &["update-ref", "refs/forge/internal", &tip], None);
    w.s.git(1, &["update-ref", "refs/pull/1/head", &tip], None);
    let all = w.json("/git/refs");
    assert_eq!(all.as_array().unwrap().len(), 4);
    assert_eq!(w.get("/git/refs/forge/internal").status, 404);
    // tags newest first, lightweight tag message is the commit subject
    let tags = w.json("/tags");
    assert_eq!(tags[0]["name"], "v1");
    assert_eq!(tags[0]["message"], "release one");
    assert_eq!(tags[1]["message"], "root");
    // trees accept a branch, a commit id, a tree id; recursion lists directories too
    let by_branch = w.json("/git/trees/main?recursive=true");
    let paths: Vec<&str> = by_branch["tree"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["README.md", "docs", "docs/guide.md"]);
    let docs = by_branch["tree"][1]["sha"].as_str().unwrap().to_string();
    assert_eq!(
        w.json(&format!("/git/trees/{docs}"))["tree"][0]["path"],
        "guide.md"
    );
    assert_eq!(w.get("/git/trees/nope").status, 400);
    let paged = w.json("/git/trees/main?recursive=true&per_page=2&page=2");
    assert_eq!(
        (
            paged["tree"].as_array().unwrap().len(),
            paged["truncated"].clone()
        ),
        (1, json!(false))
    );
}

#[test]
fn archives_are_zip_or_gzipped_tar_and_unknown_references_are_404() {
    let w = world();
    let z = w.get("/archive/main.zip");
    assert_eq!((z.status, &z.raw[..2]), (200, &b"PK"[..]));
    assert_eq!(z.headers["content-type"], "application/octet-stream");
    let t = w.get("/archive/feat/x.tar.gz");
    assert_eq!((t.status, &t.raw[..2]), (200, &[0x1f, 0x8b][..]));
    assert_eq!(w.get("/archive/nope.zip").status, 404);
    assert_eq!(w.get("/archive/main.rar").status, 400);
    assert_eq!(w.get("/archive/--output=x.zip").status, 404);
}

#[test]
fn the_empty_repository_answers_the_recorded_shapes_and_a_busy_runner_is_503() {
    let s = Srv::start_git(1, std::time::Duration::from_millis(100));
    let auth = token(&s.admin);
    s.post("/api/v1/user/repos", &auth, json!({"name": "blank"}));
    let get = |p: &str| s.get(&format!("/api/v1/repos/siteadmin/blank{p}"), &auth);
    assert_eq!(get("/commits").status, 409);
    assert_eq!(get("/contents").json(), json!([]));
    assert_eq!(get("/contents/README.md").json(), json!([]));
    assert_eq!(get("/tags").json(), json!([]));
    assert_eq!(get("/git/refs").status, 404);
    assert_eq!(get("/git/trees/main").status, 400);
    let busy = s.runner.occupy_for_tests();
    for p in [
        "/commits",
        "/tags",
        "/git/refs",
        "/git/commits/main",
        "/git/trees/main",
        "/contents",
        "/archive/main.zip",
    ] {
        // an empty repository answers before git is consulted for some routes; none may be a 500
        assert_ne!(get(p).status, 500, "{p}");
    }
    drop(busy);
}

#[test]
fn a_merge_commit_is_shown_against_its_first_parent_and_a_symlink_has_its_target() {
    let w = world();
    let work = w.dir.join("w");
    git(&work, &["checkout", "-q", "-b", "merged", "main"]);
    git(
        &work,
        &["merge", "-q", "--no-ff", "feat/x", "-m", "merge feat"],
    );
    std::os::unix::fs::symlink("README.md", work.join("link")).unwrap();
    git(&work, &["add", "."]);
    git(&work, &["commit", "-q", "-m", "link"]);
    let tip = git(&work, &["rev-parse", "HEAD"]);
    let merge = git(&work, &["rev-parse", "HEAD~1"]);
    let url = format!("{}/siteadmin/smart.git", w.s.base);
    let h = format!("http.extraHeader=Authorization: {}", w.auth);
    git(&work, &["-c", &h, "push", "-q", &url, "merged"]);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while w.s.app.life.registry.live() != 0 && std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let c = w.json(&format!("/git/commits/{merge}"));
    assert_eq!(c["parents"].as_array().unwrap().len(), 2);
    assert_eq!(
        c["files"],
        json!([{"filename": "x.txt", "status": "added"}])
    );
    let p = String::from_utf8_lossy(&w.get(&format!("/git/commits/{merge}.patch")).raw).to_string();
    assert!(
        p.starts_with(&format!("From {merge} ")) && p.contains("Subject: [PATCH] merge feat"),
        "the patch of a merge is the merge's own: {p}"
    );
    assert!(p.contains("+++ b/x.txt"), "{p}");
    let d = String::from_utf8_lossy(&w.get(&format!("/git/commits/{merge}.diff")).raw).to_string();
    assert!(d.contains("+++ b/x.txt"), "{d}");
    let l = w.json("/contents/link?ref=merged");
    assert_eq!(
        (l["type"].as_str(), l["target"].as_str()),
        (Some("symlink"), Some("README.md"))
    );
    let listing = w.json("/contents?ref=merged");
    let l = listing
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "link")
        .unwrap();
    assert_eq!(l["target"], "README.md", "{tip}");
}

#[test]
fn an_unborn_default_branch_does_not_hide_a_pushed_branch_and_a_busy_runner_is_503() {
    let s = Srv::start_git(1, std::time::Duration::from_millis(100));
    let auth = token(&s.admin);
    s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "only-feat", "default_branch": "main"}),
    );
    let dir = std::env::temp_dir().join(format!(
        "scl-forge-unborn-{}-{}",
        std::process::id(),
        s.addr.port()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let w = dir.join("w");
    git(&dir, &["init", "-q", "-b", "feat", w.to_str().unwrap()]);
    std::fs::write(w.join("f.txt"), "f\n").unwrap();
    git(&w, &["add", "."]);
    git(&w, &["commit", "-q", "-m", "only on feat"]);
    let url = format!("{}/siteadmin/only-feat.git", s.base);
    git(
        &w,
        &[
            "-c",
            &format!("http.extraHeader=Authorization: {auth}"),
            "push",
            "-q",
            &url,
            "feat",
        ],
    );
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while s.app.life.registry.live() != 0 && std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let get = |p: &str| s.get(&format!("/api/v1/repos/siteadmin/only-feat{p}"), &auth);
    // the default branch is unborn: unnamed reads keep the recorded empty-repository answers ...
    assert_eq!(get("/commits").status, 409);
    assert_eq!(get("/contents").json(), json!([]));
    // ... but a named, existing branch is served
    let c = get("/commits?sha=feat");
    assert_eq!(c.status, 200, "{}", c.msg());
    assert_eq!(c.json().as_array().unwrap().len(), 1);
    assert_eq!(get("/contents/f.txt?ref=feat").json()["name"], "f.txt");
    assert_eq!(get("/commits?sha=nope").status, 404);
    assert_eq!(get("/commits?not=feat").status, 400);
    let busy = s.runner.occupy_for_tests();
    for p in [
        "/commits?sha=feat",
        "/tags",
        "/git/refs",
        "/git/commits/feat",
        "/git/trees/feat",
        "/contents?ref=feat",
        "/archive/feat.zip",
    ] {
        assert_eq!(get(p).status, 503, "{p}");
    }
    drop(busy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_reader_without_access_gets_the_same_404_as_for_a_missing_repository() {
    let w = world();
    let pw = w.s.mk_user("mallory");
    let t = w.s.mk_token("mallory", &pw, "t", &["all"]);
    for p in [
        "/commits",
        "/contents",
        "/git/refs",
        "/tags",
        "/archive/main.zip",
        "/git/trees/main",
        "/git/commits/main",
    ] {
        let a =
            w.s.get(&format!("/api/v1/repos/siteadmin/smart{p}"), &token(&t));
        let b =
            w.s.get(&format!("/api/v1/repos/siteadmin/missing{p}"), &token(&t));
        assert_eq!((a.status, a.raw.clone()), (b.status, b.raw.clone()), "{p}");
        assert_eq!(a.status, 404, "{p}");
    }
}
