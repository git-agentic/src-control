//! F3b: contents writes (`POST`/`PUT`/`DELETE`), checked with real git against the bare repository.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::{json, Value};

const ZERO: &str = "0000000000000000000000000000000000000000";

struct W {
    s: Srv,
    auth: String,
    id: i64,
}

/// A repository `siteadmin/w` with the auto-init README commit on `main`.
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
    fn url(&self, path: &str) -> String {
        format!("/api/v1/repos/siteadmin/w/contents/{path}")
    }
    fn write(&self, method: &str, path: &str, body: Value) -> Resp {
        self.s
            .send(method, &self.url(path), Some(&self.auth), Some(&body))
    }
    fn git(&self, args: &[&str]) -> String {
        self.s.git(self.id, args, None)
    }
    fn tip(&self, branch: &str) -> String {
        self.git(&["rev-parse", &format!("refs/heads/{branch}")])
    }
    /// `fsck --strict` finds nothing wrong; unreferenced objects (a refused or lost write leaves some) are fine.
    fn fsck(&self) {
        assert_clean(&self.git(&["fsck", "--strict"]));
    }
    fn blob(&self, spec: &str) -> String {
        self.git(&["rev-parse", spec])
    }
}

fn assert_clean(fsck: &str) {
    let bad: Vec<&str> = fsck
        .lines()
        .filter(|l| !l.starts_with("dangling "))
        .collect();
    assert!(bad.is_empty(), "fsck: {bad:?}");
}

fn enc(s: &str) -> String {
    b64(s)
}

#[test]
fn create_update_delete_round_trip_with_the_recorded_answers() {
    let w = world();
    let before = w.tip("main");
    let r = w.write(
        "POST",
        "new.txt",
        json!({"content": enc("new\n"), "message": "add new.txt", "branch": "main"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let j = r.json();
    let c1 = w.tip("main");
    assert_ne!(c1, before);
    assert_eq!(j["commit"]["sha"], c1.as_str());
    assert_eq!(j["commit"]["message"], "add new.txt\n");
    assert_eq!(j["commit"]["parents"][0]["sha"], before.as_str());
    assert_eq!(
        j["commit"]["tree"]["sha"],
        w.blob("main^{tree}").as_str(),
        "the real tree id"
    );
    assert_eq!(j["content"]["name"], "new.txt");
    assert_eq!(j["content"]["sha"], w.blob("main:new.txt").as_str());
    assert_eq!(j["content"]["last_commit_sha"], c1.as_str());
    assert_eq!(j["content"]["content"], enc("new\n").as_str());
    assert_eq!(
        j["content"]["url"]
            .as_str()
            .unwrap()
            .rsplit_once("?ref=")
            .unwrap()
            .1,
        "main"
    );
    assert_eq!(j["verification"]["verified"], false);
    assert_eq!(j["commit"]["author"]["name"], "siteadmin");
    assert_eq!(
        w.git(&["log", "-1", "--format=%an|%cn|%ae"],),
        format!(
            "siteadmin|siteadmin|{}",
            j["commit"]["author"]["email"].as_str().unwrap()
        )
    );
    // the F3a read sees it
    let got = w.s.get(&w.url("new.txt"), &w.auth);
    assert_eq!(got.json()["sha"], j["content"]["sha"]);

    let dup = w.write(
        "POST",
        "new.txt",
        json!({"content": enc("new\n"), "message": "again", "branch": "main"}),
    );
    assert_eq!(
        (dup.status, dup.msg().as_str()),
        (422, "repository file already exists [path: new.txt]")
    );

    let sha = j["content"]["sha"].as_str().unwrap().to_string();
    let up = w.write(
        "PUT",
        "new.txt",
        json!({"content": enc("two\n"), "message": "update", "sha": sha, "branch": "main"}),
    );
    assert_eq!(up.status, 200, "{}", up.msg());
    let new_sha = up.json()["content"]["sha"].as_str().unwrap().to_string();
    assert_eq!(w.git(&["show", "main:new.txt"]), "two");

    let stale = w.write(
        "PUT",
        "new.txt",
        json!({"content": enc("x\n"), "message": "stale", "sha": sha, "branch": "main"}),
    );
    assert_eq!(stale.status, 422);
    assert_eq!(
        stale.msg(),
        format!("sha does not match [given: {sha}, expected: {new_sha}]")
    );
    let nosha = w.write(
        "PUT",
        "new.txt",
        json!({"content": enc("x\n"), "message": "no sha"}),
    );
    assert_eq!(
        (nosha.status, nosha.msg().as_str()),
        (422, "[SHA]: Required")
    );

    let del = w.write(
        "DELETE",
        "new.txt",
        json!({"message": "rm", "sha": new_sha}),
    );
    assert_eq!(del.status, 200, "{}", del.msg());
    assert_eq!(del.json()["content"], Value::Null);
    assert_eq!(w.s.get(&w.url("new.txt"), &w.auth).status, 404);
    let again = w.write(
        "DELETE",
        "new.txt",
        json!({"message": "rm", "sha": new_sha}),
    );
    assert_eq!(again.status, 404);
    w.fsck();
    assert!(!w.git(&["log", "--format=%s", "main"]).contains("again"));
}

#[test]
fn nested_files_make_directories_and_deleting_the_last_one_removes_them() {
    let w = world();
    let r = w.write(
        "POST",
        "a/b/c.txt",
        json!({"content": enc("c\n"), "message": "nested"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    assert_eq!(
        w.git(&["ls-tree", "-r", "--name-only", "main"]),
        "README.md\na/b/c.txt"
    );
    let sha = r.json()["content"]["sha"].as_str().unwrap().to_string();
    let r = w.write("DELETE", "a/b/c.txt", json!({"sha": sha}));
    assert_eq!(r.status, 200, "{}", r.msg());
    assert_eq!(
        w.git(&["ls-tree", "-r", "--name-only", "main"]),
        "README.md"
    );
    assert_eq!(
        w.git(&["log", "-1", "--format=%s", "main"]),
        "Delete a/b/c.txt",
        "default message"
    );
    w.fsck();
}

#[test]
fn new_branch_leaves_the_base_alone_and_collisions_are_422() {
    let w = world();
    let base = w.tip("main");
    let r = w.write(
        "POST",
        "f.txt",
        json!({"content": enc("f\n"), "message": "to new", "branch": "main", "new_branch": "nb"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    assert_eq!(w.tip("main"), base);
    assert_eq!(w.git(&["rev-parse", "nb~1"]), base);
    assert!(r.json()["content"]["url"]
        .as_str()
        .unwrap()
        .ends_with("?ref=nb"));
    let again = w.write(
        "POST",
        "g.txt",
        json!({"content": enc("g\n"), "branch": "main", "new_branch": "nb"}),
    );
    assert_eq!(
        (again.status, again.msg().as_str()),
        (422, "branch already exists [name: nb]")
    );
    for n in ["nb/x", "feat", "x y", "-bad"] {
        let r = w.write(
            "POST",
            "h.txt",
            json!({"content": enc("h\n"), "branch": "main", "new_branch": n}),
        );
        assert!(
            matches!((n, r.status), ("feat", 201) | (_, 422)),
            "{n}: {} {}",
            r.status,
            r.msg()
        );
    }
    let under = w.write(
        "POST",
        "i.txt",
        json!({"content": enc("i\n"), "branch": "main", "new_branch": "feat/sub"}),
    );
    assert_eq!(
        under.status,
        422,
        "feat exists as a branch: {}",
        under.msg()
    );
    // new_branch equal to branch, or empty, is the branch itself
    let rel = w.write(
        "POST",
        "r.txt",
        json!({"content": enc("r\n"), "branch": "main", "new_branch": "rel/1"}),
    );
    assert_eq!(rel.status, 201, "{}", rel.msg());
    let above = w.write(
        "POST",
        "s.txt",
        json!({"content": enc("s\n"), "branch": "main", "new_branch": "rel"}),
    );
    assert_eq!(
        above.status,
        422,
        "rel is a directory of rel/1: {}",
        above.msg()
    );
    let dflt = w.write(
        "POST",
        "t.txt",
        json!({"content": enc("t\n"), "new_branch": "main"}),
    );
    assert_eq!(
        dflt.status,
        201,
        "new_branch equal to the default is the default: {}",
        dflt.msg()
    );
    let same = w.write(
        "POST",
        "j.txt",
        json!({"content": enc("j\n"), "branch": "main", "new_branch": "main"}),
    );
    assert_eq!(same.status, 201, "{}", same.msg());
    let empty = w.write(
        "POST",
        "k.txt",
        json!({"content": enc("k\n"), "new_branch": ""}),
    );
    assert_eq!(empty.status, 201);
    let missing = w.write(
        "POST",
        "m.txt",
        json!({"content": enc("m\n"), "branch": "nope"}),
    );
    assert_eq!(
        (missing.status, missing.json()["errors"][0].as_str()),
        (404, Some("branch does not exist [name: nope]"))
    );
    w.fsck();
}

#[test]
fn paths_that_a_checkout_could_misread_are_refused() {
    let w = world();
    for p in [
        ".git/config",
        "a/.GIT/x",
        ".gitmodules",
        "x/.git.",
        "git~1/y",
        "a%5Cb",
        "a%2F%2Fb",
    ] {
        let r = w.write("POST", p, json!({"content": enc("x\n"), "message": "m"}));
        assert_eq!(r.status, 422, "{p}: {}", r.msg());
    }
    let tip = w.tip("main");
    assert_eq!(
        w.write("POST", "ok.txt", json!({"content": "!!!", "message": "m"}))
            .status,
        422,
        "base64"
    );
    assert_eq!(
        w.write("POST", "ok.txt", json!({"message": "m"})).status,
        422,
        "content required"
    );
    assert_eq!(
        w.write(
            "POST",
            "ok.txt",
            json!({"content": enc("x"), "message": "a\u{0}b"})
        )
        .status,
        422,
        "NUL"
    );
    assert_eq!(
        w.write(
            "PUT",
            "README.md",
            json!({"content": enc("x"), "sha": "1", "from_path": "old"})
        )
        .status,
        422
    );
    let long = format!("{}\n", "x".repeat(3000));
    assert_eq!(
        w.write("POST", ".gitattributes", json!({"content": enc(&long)}))
            .status,
        422
    );
    assert_eq!(
        w.write("POST", "empty.txt", json!({"content": ""})).status,
        201,
        "an empty file is fine"
    );
    assert_ne!(w.tip("main"), tip);
    w.fsck();
}

#[test]
fn directories_files_and_modes_are_respected() {
    let w = world();
    // build main with an executable, a symlink and a directory, using git directly
    let blob = w.s.git(
        w.id,
        &["hash-object", "-w", "--stdin"],
        Some(b"#!/bin/sh\n"),
    );
    let link =
        w.s.git(w.id, &["hash-object", "-w", "--stdin"], Some(b"run.sh"));
    let sub = w.s.git(
        w.id,
        &["mktree"],
        Some(format!("100644 blob {blob}\tinner\n").as_bytes()),
    );
    let gitlink = "9".repeat(40);
    let tree = w.s.git(
        w.id,
        &["mktree"],
        Some(
            format!(
                "100755 blob {blob}\trun.sh\n120000 blob {link}\tlink\n040000 tree {sub}\tdir\n160000 commit {gitlink}\tsm\n"
            )
            .as_bytes(),
        ),
    );
    let c = w.s.git(
        w.id,
        &["commit-tree", &tree, "-p", &w.tip("main")],
        Some(b"fixture\n"),
    );
    w.git(&["update-ref", "refs/heads/main", &c]);
    // PUT keeps the executable bit
    let r = w.write(
        "PUT",
        "run.sh",
        json!({"content": enc("#!/bin/sh\necho\n"), "sha": blob}),
    );
    assert_eq!(r.status, 200, "{}", r.msg());
    assert!(w.git(&["ls-tree", "main", "run.sh"]).starts_with("100755 "));
    // a symlink, a directory: refused
    let r = w.write("PUT", "link", json!({"content": enc("x"), "sha": link}));
    assert_eq!(r.status, 422, "{}", r.msg());
    let r = w.write("PUT", "dir", json!({"content": enc("x"), "sha": sub}));
    assert_eq!(r.status, 422, "{}", r.msg());
    assert_eq!(w.write("DELETE", "link", json!({"sha": link})).status, 422);
    assert_eq!(
        w.write("PUT", "sm", json!({"content": enc("x"), "sha": gitlink}))
            .status,
        422,
        "submodule"
    );
    assert_eq!(w.write("DELETE", "sm", json!({"sha": gitlink})).status, 422);
    assert_eq!(
        w.write("POST", "sm/x", json!({"content": enc("x")})).status,
        422,
        "under a submodule"
    );
    assert_eq!(
        w.git(&["ls-tree", "main", "sm"]),
        format!("160000 commit {gitlink}\tsm"),
        "gitlink kept"
    );
    // exists as a directory / a file is a parent
    assert_eq!(
        w.write("POST", "dir", json!({"content": enc("x")})).status,
        422
    );
    let r = w.write("POST", "run.sh/child", json!({"content": enc("x")}));
    assert_eq!(r.status, 422, "{}", r.msg());
    assert_eq!(
        w.write("DELETE", "run.sh/child", json!({"sha": blob}))
            .status,
        404
    );
    w.fsck();
}

#[test]
fn untouched_siblings_keep_their_exact_names() {
    let w = world();
    let blob =
        w.s.git(w.id, &["hash-object", "-w", "--stdin"], Some(b"x\n"));
    let mut input = Vec::new();
    for name in [
        &b"bad\xff\x01name"[..],
        &b"tab\tnl\nname"[..],
        &b"edit.txt"[..],
    ] {
        input.extend_from_slice(format!("100644 blob {blob}\t").as_bytes());
        input.extend_from_slice(name);
        input.push(0);
    }
    let sub = w.s.git(w.id, &["mktree", "-z"], Some(&input));
    let tree = w.s.git(
        w.id,
        &["mktree"],
        Some(format!("040000 tree {sub}\td\n").as_bytes()),
    );
    let c = w.s.git(w.id, &["commit-tree", &tree], Some(b"odd names\n"));
    w.git(&["update-ref", "refs/heads/odd", &c]);
    let before = w.git(&["ls-tree", "-z", "odd:d"]);
    let r = w.write(
        "PUT",
        "d/edit.txt",
        json!({"content": enc("new\n"), "sha": blob, "branch": "odd"}),
    );
    assert_eq!(r.status, 200, "{}", r.msg());
    let after = w.git(&["ls-tree", "-z", "odd:d"]);
    // every untouched name is still there with its id; only edit.txt differs
    let strip = |s: &str| {
        s.split('\0')
            .filter(|e| !e.ends_with("edit.txt"))
            .map(String::from)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        strip(&before),
        strip(&after),
        "raw listings of the untouched entries are equal"
    );
    w.fsck();
}

#[test]
fn the_first_commit_of_an_empty_repository_and_an_unborn_default() {
    let s = Srv::start();
    let auth = token(&s.admin);
    let r = s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "e", "default_branch": "main"}),
    );
    let id = r.json()["id"].as_i64().unwrap();
    let put = |p: &str, v: Value| {
        s.send(
            "PUT",
            &format!("/api/v1/repos/siteadmin/e/contents/{p}"),
            Some(&auth),
            Some(&v),
        )
    };
    let post = |p: &str, v: Value| {
        s.send(
            "POST",
            &format!("/api/v1/repos/siteadmin/e/contents/{p}"),
            Some(&auth),
            Some(&v),
        )
    };
    assert_eq!(
        put("a", json!({"content": enc("x"), "sha": "1"})).status,
        404,
        "PUT on an unborn branch"
    );
    assert_eq!(
        post("a", json!({"content": enc("x"), "new_branch": "nb"})).status,
        404,
        "new_branch from an unborn base"
    );
    let r = post(
        "README.md",
        json!({"content": enc("# e\n"), "message": "seed"}),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    assert_eq!(r.json()["commit"]["parents"], json!([]));
    assert_eq!(s.git(id, &["rev-list", "--count", "main"], None), "1");
    assert_clean(&s.git(id, &["fsck", "--strict"], None));
    // an unborn default with another branch present: the seed still lands on the default branch
    let r = s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "f", "default_branch": "main"}),
    );
    let fid = r.json()["id"].as_i64().unwrap();
    let tree = s.git(fid, &["mktree"], Some(b""));
    let c = s.git(fid, &["commit-tree", &tree], Some(b"x\n"));
    s.git(fid, &["update-ref", "refs/heads/feat", &c], None);
    let r = s.send(
        "POST",
        "/api/v1/repos/siteadmin/f/contents/seed.txt",
        Some(&auth),
        Some(&json!({"content": enc("s")})),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    assert_eq!(s.git(fid, &["rev-list", "--count", "main"], None), "1");
    assert_eq!(s.git(fid, &["rev-parse", "feat"], None), c);
}

#[test]
fn access_and_scope_are_checked_before_anything_is_written() {
    let s = Srv::start();
    let auth = token(&s.admin);
    s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "w", "auto_init": true, "default_branch": "main"}),
    );
    let (pr, pw, po) = (
        s.mk_user("reader"),
        s.mk_user("writer"),
        s.mk_user("outsider"),
    );
    for (u, m) in [("reader", "read"), ("writer", "write")] {
        let r = s.send(
            "PUT",
            &format!("/api/v1/repos/siteadmin/w/collaborators/{u}"),
            Some(&auth),
            Some(&json!({"permission": m})),
        );
        assert_eq!(r.status, 204, "{}", r.msg());
    }
    let id = 1;
    let tip = s.git(id, &["rev-parse", "main"], None);
    let post = |tok: &str| {
        s.send(
            "POST",
            "/api/v1/repos/siteadmin/w/contents/x.txt",
            Some(&token(tok)),
            Some(&json!({"content": enc("x")})),
        )
    };
    let reader = s.mk_token("reader", &pr, "t", &["all"]);
    assert_eq!(post(&reader).status, 403, "read collaborator");
    let outsider = s.mk_token("outsider", &po, "t", &["all"]);
    assert_eq!(
        post(&outsider).status,
        404,
        "no access looks like no repository"
    );
    let ro = s.mk_token("writer", &pw, "ro", &["read:repository"]);
    let r = post(&ro);
    assert_eq!(r.status, 403);
    assert!(r.msg().contains("write:repository"), "{}", r.msg());
    assert_eq!(
        s.git(id, &["rev-parse", "main"], None),
        tip,
        "nothing was written"
    );
    let writer = s.mk_token("writer", &pw, "rw", &["all"]);
    assert_eq!(post(&writer).status, 201);
    let anon = s.send(
        "POST",
        "/api/v1/repos/siteadmin/w/contents/y.txt",
        None,
        Some(&json!({"content": enc("y")})),
    );
    assert_eq!(anon.status, 403, "the recorded anonymous answer");
}

#[test]
fn a_busy_runner_is_503_and_the_branch_does_not_move() {
    let s = Srv::start_git(1, std::time::Duration::from_millis(100));
    let auth = token(&s.admin);
    s.post(
        "/api/v1/user/repos",
        &auth,
        json!({"name": "w", "auto_init": true, "default_branch": "main"}),
    );
    let tip = s.git(1, &["rev-parse", "main"], None);
    let busy = s.runner.occupy_for_tests();
    let r = s.send(
        "POST",
        "/api/v1/repos/siteadmin/w/contents/x.txt",
        Some(&auth),
        Some(&json!({"content": enc("x")})),
    );
    assert_eq!(r.status, 503, "{}", r.msg());
    drop(busy);
    assert_eq!(s.git(1, &["rev-parse", "main"], None), tip);
}

#[test]
fn concurrent_api_writers_and_an_independent_ref_writer_lose_nothing() {
    let w = std::sync::Arc::new(world());
    let racer = {
        let w = w.clone();
        std::thread::spawn(move || {
            // an independent writer (a stand-in for a push): adds a file on top of the tip, by CAS
            let mut landed = Vec::new();
            for i in 0..15 {
                let tip = w.tip("main");
                let listing = w.git(&["ls-tree", &format!("{tip}^{{tree}}")]);
                let blob = w.s.git(
                    w.id,
                    &["hash-object", "-w", "--stdin"],
                    Some(format!("ext {i}\n").as_bytes()),
                );
                let tree = w.s.git(
                    w.id,
                    &["mktree"],
                    Some(format!("{listing}\n100644 blob {blob}\text{i}.txt\n").as_bytes()),
                );
                let c = w.s.git(
                    w.id,
                    &["commit-tree", &tree, "-p", &tip],
                    Some(format!("racer {i}\n").as_bytes()),
                );
                let out = std::process::Command::new("git")
                    .args([
                        "--git-dir",
                        w.s.dir
                            .join("repos")
                            .join(format!("{}.git", w.id))
                            .to_str()
                            .unwrap(),
                        "update-ref",
                        "refs/heads/main",
                        &c,
                        &tip,
                    ])
                    .output()
                    .unwrap();
                if out.status.success() {
                    landed.push((c, format!("ext{i}.txt")));
                }
                std::thread::sleep(std::time::Duration::from_millis(3));
            }
            landed
        })
    };
    let writers: Vec<_> = (0..12)
        .map(|i| {
            let w = w.clone();
            std::thread::spawn(move || {
                let r = w.write(
                    "POST",
                    &format!("f{i}.txt"),
                    json!({"content": enc(&format!("{i}\n")), "message": format!("w{i}")}),
                );
                (i, r.status)
            })
        })
        .collect();
    let results: Vec<(i32, u16)> = writers.into_iter().map(|h| h.join().unwrap()).collect();
    let landed = racer.join().unwrap();
    for (i, st) in &results {
        assert!(matches!(st, 201 | 409), "writer {i}: {st}");
    }
    let files = w.git(&["ls-tree", "--name-only", "main"]);
    for (i, st) in &results {
        assert_eq!(
            files.contains(&format!("f{i}.txt")),
            *st == 201,
            "f{i}.txt vs {st}"
        );
    }
    assert!(
        results.iter().filter(|(_, s)| *s == 201).count() >= 6,
        "most writers land: {results:?}"
    );
    assert!(
        !landed.is_empty(),
        "the independent writer landed something"
    );
    for (c, file) in landed {
        assert!(
            files.contains(&file),
            "{file} written outside the API survived the API's rebuilds"
        );
        let out = std::process::Command::new("git")
            .args([
                "--git-dir",
                w.s.dir
                    .join("repos")
                    .join(format!("{}.git", w.id))
                    .to_str()
                    .unwrap(),
                "merge-base",
                "--is-ancestor",
                &c,
                "main",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "racer commit {c} was lost");
    }
    w.fsck();
    let _ = ZERO;
}

#[test]
fn deleting_the_repository_while_writes_are_queued_does_not_hang() {
    let w = std::sync::Arc::new(world());
    let writers: Vec<_> = (0..8)
        .map(|i| {
            let w = w.clone();
            std::thread::spawn(move || {
                w.write("POST", &format!("d{i}.txt"), json!({"content": enc("x\n")}))
                    .status
            })
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let del =
        w.s.send("DELETE", "/api/v1/repos/siteadmin/w", Some(&w.auth), None);
    assert_eq!(del.status, 204, "{}", del.msg());
    for h in writers {
        let st = h.join().unwrap();
        assert!(matches!(st, 201 | 404 | 503), "{st}");
    }
}

#[test]
fn a_directory_cannot_take_a_name_that_must_be_a_blob() {
    let w = world();
    for p in [".gitattributes/x", "d/.GITATTRIBUTES/y", "gitatt~1/z"] {
        let r = w.write("POST", p, json!({"content": enc("x\n")}));
        assert_eq!(r.status, 422, "{p}: {}", r.msg());
    }
    assert_eq!(
        w.write(
            "POST",
            "d/.gitattributes",
            json!({"content": enc("*.rs text\n")})
        )
        .status,
        201
    );
    w.fsck();
}
