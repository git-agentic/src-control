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

// ---- helpers ----

fn put_commit(c: &Client, work: &Path, file: &str, text: &str) {
    std::fs::write(work.join(file), text).unwrap();
    c.ok(work, None, &["add", "."]);
    c.ok(work, None, &["commit", "-q", "-m", file]);
}

/// A working copy with one commit on `main`, pushed to `url` with `auth`.
fn seeded(c: &Client, url: &str, auth: &str) -> PathBuf {
    let work = c.dir.join("work");
    c.ok(
        &c.dir,
        None,
        &["init", "-q", "-b", "main", work.to_str().unwrap()],
    );
    put_commit(c, &work, "a.txt", "hello\n");
    c.ok(&work, Some(auth), &["push", "-q", url, "main"]);
    work
}

fn body_text(r: &Resp) -> String {
    String::from_utf8_lossy(&r.raw).to_string()
}

const UP: &str = "/info/refs?service=git-upload-pack";
const RP: &str = "/info/refs?service=git-receive-pack";

// ---- credentials and answers ----

#[test]
fn every_credential_form_is_accepted_and_each_failure_has_its_recorded_text() {
    let s = Srv::start();
    let t = s.admin.clone();
    repo(&s, "smart");
    let path = format!("/siteadmin/smart.git{UP}");

    let anon = s.send("GET", &path, None, None);
    assert_eq!(
        (anon.status, body_text(&anon).as_str()),
        (401, "Unauthorized\n")
    );
    assert!(anon.headers["www-authenticate"].starts_with("Basic realm="));

    for good in [
        token(&t),
        format!("Bearer {t}"),
        basic("anyone", &t),
        basic("oauth2", &t),
        basic(&t, ""),
    ] {
        let r = s.send("GET", &path, Some(&good), None);
        assert_eq!(r.status, 200, "{good}: {}", body_text(&r));
        assert_eq!(
            r.headers["content-type"],
            "application/x-git-upload-pack-advertisement"
        );
        // (the harness does not decode the chunked framing)
        assert!(
            body_text(&r).contains("001e# service=git-upload-pack\n"),
            "{good}: {:?}",
            body_text(&r)
        );
    }

    for bad in [
        token("nonsense"),
        basic("siteadmin", "nonsense"),
        format!("Bearer {}", "0".repeat(40)),
    ] {
        let r = s.send("GET", &path, Some(&bad), None);
        assert_eq!(
            (r.status, body_text(&r).as_str()),
            (401, "Verify\n"),
            "{bad}"
        );
    }
}

#[test]
fn a_password_is_never_a_git_credential() {
    let s = Srv::start();
    let pw = s.mk_user("alice");
    repo(&s, "smart");
    let r = s.send(
        "GET",
        &format!("/siteadmin/smart.git{UP}"),
        Some(&basic("alice", &pw)),
        None,
    );
    assert_eq!((r.status, body_text(&r).as_str()), (401, "Verify\n"));
}

#[test]
fn missing_and_invisible_repositories_answer_identically() {
    let s = Srv::start();
    let pw = s.mk_user("bob");
    let bob = token(&s.mk_token("bob", &pw, "t", &["all"]));
    let r = s.post(
        "/api/v1/user/repos",
        &token(&s.admin),
        json!({"name": "secret", "private": true}),
    );
    assert_eq!(r.status, 201);
    for repo in ["secret", "nothere"] {
        for q in [UP, RP] {
            let r = s.send(
                "GET",
                &format!("/siteadmin/{repo}.git{q}"),
                Some(&bob),
                None,
            );
            assert_eq!(
                (r.status, body_text(&r).as_str()),
                (404, "Repository not found"),
                "{repo}{q}"
            );
        }
    }
}

#[test]
fn scopes_and_permissions_gate_each_service() {
    let s = Srv::start();
    let (pw_r, pw_w) = (s.mk_user("reader"), s.mk_user("writer"));
    let reader = s.mk_token("reader", &pw_r, "t", &["all"]);
    repo(&s, "smart");
    let put = |user: &str, mode: &str| {
        let r = s.send(
            "PUT",
            &format!("/api/v1/repos/siteadmin/smart/collaborators/{user}"),
            Some(&token(&s.admin)),
            Some(&json!({"permission": mode})),
        );
        assert_eq!(r.status, 204, "{}", r.msg());
    };
    put("reader", "read");
    put("writer", "write");
    let writer = s.mk_token("writer", &pw_w, "t", &["all"]);
    let code = |auth: &str, q: &str| {
        s.send(
            "GET",
            &format!("/siteadmin/smart.git{q}"),
            Some(&token(auth)),
            None,
        )
        .status
    };
    assert_eq!(code(&reader, UP), 200);
    assert_eq!(code(&reader, RP), 403, "read collaborator cannot push");
    assert_eq!(code(&writer, RP), 200);
    // Scope: a read-only token reads but does not push even where the user may write.
    let ro = s.mk_token("writer", &pw_w, "ro", &["read:repository"]);
    assert_eq!(code(&ro, UP), 200);
    assert_eq!(code(&ro, RP), 403);
    let other = s.mk_token("writer", &pw_w, "other", &["read:user"]);
    assert_eq!(code(&other, UP), 403, "no repository scope at all");
    let public = s.mk_token("writer", &pw_w, "pub", &["public-only", "read:repository"]);
    assert_eq!(
        code(&public, UP),
        403,
        "public-only tokens never reach repository transport"
    );
}

#[test]
fn only_the_whitelisted_shapes_and_methods_are_served() {
    let s = Srv::start();
    let a = token(&s.admin);
    repo(&s, "smart");
    let get = |p: &str| {
        s.send("GET", &format!("/siteadmin/smart.git{p}"), Some(&a), None)
            .status
    };
    for p in [
        "/config",
        "/hooks/pre-receive",
        "/refs/heads/main",
        "/objects/../config",
        "/info/refs",
        "/info/refs?service=git-bogus",
        "/objects/info/alternates",
        "/forge",
        "/../x",
    ] {
        assert_eq!(get(p), 404, "{p}");
    }
    assert_eq!(get("/HEAD"), 200);
    let post = |p: &str| {
        s.send("POST", &format!("/siteadmin/smart.git{p}"), Some(&a), None)
            .status
    };
    assert_eq!(post("/info/refs?service=git-upload-pack"), 405);
    assert_eq!(
        get("/git-receive-pack"),
        405,
        "an RPC endpoint is POST only"
    );
    assert_eq!(post("/HEAD"), 405);
    // Encoded path separators and dots cannot name anything else.
    for p in [
        "/siteadmin/%2e%2e.git/info/refs",
        "/siteadmin%2Fsmart.git/info/refs",
        "/siteadmin/smart%2egit/info/refs",
    ] {
        let r = s.send("GET", p, Some(&a), None);
        assert!(r.status == 404, "{p}: {}", r.status);
    }
}

// ---- real client flows ----

#[test]
fn branches_tags_force_and_deletes_by_push() {
    let s = Srv::start();
    let c = Client::new("flows");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    let work = seeded(&c, &url, &auth);
    c.ok(
        &work,
        Some(&auth),
        &["push", "-q", &url, "main:refs/heads/dev"],
    );
    c.ok(&work, None, &["tag", "v1"]);
    c.ok(&work, Some(&auth), &["push", "-q", &url, "v1"]);
    put_commit(&c, &work, "b.txt", "two\n");
    c.ok(&work, Some(&auth), &["push", "-q", &url, "main"]);
    // forced rewind of dev, then a stale lease is refused
    c.ok(
        &work,
        Some(&auth),
        &["push", "-q", "-f", &url, "main:refs/heads/dev"],
    );
    let (ok, _) = c.git_in(
        &work,
        Some(&auth),
        &[
            "push",
            "-q",
            "--force-with-lease=dev:0000000000000000000000000000000000000001",
            &url,
            "main~1:refs/heads/dev",
        ],
    );
    assert!(!ok, "stale lease must be refused");
    c.ok(
        &work,
        Some(&auth),
        &["push", "-q", &url, ":refs/heads/dev", ":refs/tags/v1"],
    );
    let refs = c.ok(&work, Some(&auth), &["ls-remote", &url]);
    assert!(
        refs.contains("refs/heads/main") && !refs.contains("dev") && !refs.contains("v1"),
        "{refs}"
    );
    // the push stamped the repository
    let r = s.get("/api/v1/repos/siteadmin/smart", &auth);
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["empty"], false);
}

#[test]
fn the_ref_policy_is_enforced_for_every_unwritable_namespace_and_the_default_branch() {
    let s = Srv::start();
    let c = Client::new("policy");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    let work = seeded(&c, &url, &auth);
    for refname in [
        "refs/replace/abc",
        "refs/pull/1/head",
        "refs/notes/commits",
        "refs/changes/01/1/1",
        "refs/forge/x",
        "refs/stash",
    ] {
        let (ok, text) = c.git_in(
            &work,
            Some(&auth),
            &["push", &url, &format!("main:{refname}")],
        );
        assert!(!ok, "{refname} must be refused: {text}");
    }
    let (ok, text) = c.git_in(&work, Some(&auth), &["push", &url, ":refs/heads/main"]);
    assert!(
        !ok && text.contains("pre-receive hook declined") || text.contains("default branch"),
        "{text}"
    );
    let refs = c.ok(&work, Some(&auth), &["ls-remote", &url]);
    assert!(
        refs.contains("refs/heads/main"),
        "the default branch survives: {refs}"
    );
    assert!(
        !refs.contains("replace") && !refs.contains("pull") && !refs.contains("notes"),
        "{refs}"
    );
}

#[test]
fn refs_forge_is_hidden_from_both_services_even_when_it_exists() {
    let s = Srv::start();
    let c = Client::new("hidden");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    let work = seeded(&c, &url, &auth);
    let oid = s.git(1, &["rev-parse", "refs/heads/main"], None);
    s.git(1, &["update-ref", "refs/forge/internal", &oid], None);
    for q in [UP, RP] {
        let r = s.send(
            "GET",
            &format!("/siteadmin/smart.git{q}"),
            Some(&auth),
            None,
        );
        assert!(!body_text(&r).contains("refs/forge"), "{q}");
    }
    let (ok, _) = c.git_in(&work, Some(&auth), &["fetch", &url, "refs/forge/internal"]);
    assert!(!ok, "a hidden ref cannot be fetched by name");
}

#[test]
fn fetch_by_sha_filters_shallow_and_both_protocol_versions_work() {
    let s = Srv::start();
    let c = Client::new("fetch");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    let work = seeded(&c, &url, &auth);
    put_commit(&c, &work, "b.txt", "two\n");
    c.ok(&work, Some(&auth), &["push", "-q", &url, "main"]);
    let tip = c.ok(&work, None, &["rev-parse", "HEAD"]).trim().to_string();
    for v in ["0", "2"] {
        let dst = c.dir.join(format!("c{v}"));
        c.ok(
            &c.dir,
            Some(&auth),
            &[
                "-c",
                &format!("protocol.version={v}"),
                "clone",
                "-q",
                &url,
                dst.to_str().unwrap(),
            ],
        );
        assert_eq!(c.ok(&dst, None, &["rev-parse", "HEAD"]).trim(), tip, "v{v}");
    }
    let lite = c.dir.join("lite");
    c.ok(
        &c.dir,
        Some(&auth),
        &[
            "clone",
            "-q",
            "--filter=blob:none",
            &url,
            lite.to_str().unwrap(),
        ],
    );
    assert!(c
        .ok(&lite, None, &["config", "remote.origin.partialclonefilter"])
        .contains("blob:none"));
    let shallow = c.dir.join("shallow");
    c.ok(
        &c.dir,
        Some(&auth),
        &["clone", "-q", "--depth=1", &url, shallow.to_str().unwrap()],
    );
    assert_eq!(
        c.ok(&shallow, None, &["rev-list", "--count", "HEAD"])
            .trim(),
        "1"
    );
    c.ok(&shallow, Some(&auth), &["fetch", "-q", "--unshallow"]);
    assert_eq!(
        c.ok(&shallow, None, &["rev-list", "--count", "HEAD"])
            .trim(),
        "2"
    );
    // fetch an unreferenced-by-branch commit by its id (allowAnySHA1InWant)
    c.ok(
        &work,
        Some(&auth),
        &["push", "-q", &url, "main~1:refs/heads/old"],
    );
    let old = c
        .ok(&work, None, &["rev-parse", "main~1"])
        .trim()
        .to_string();
    c.ok(&work, Some(&auth), &["push", "-q", &url, ":refs/heads/old"]);
    let by = c.dir.join("by");
    c.ok(&c.dir, None, &["init", "-q", by.to_str().unwrap()]);
    c.ok(&by, Some(&auth), &["fetch", "-q", &url, &old]);
}

#[test]
fn gzip_request_bodies_are_inflated_by_the_server_under_a_cap() {
    use std::io::Write;
    let s = Srv::start_transport(scl_forge::cgi::Cfg {
        max_request: 1 << 20,
        ..Default::default()
    });
    let c = Client::new("gzip");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    seeded(&c, &url, &auth);
    let gz = |data: &[u8]| {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    };
    let post = |body: &[u8], enc: &str| {
        let head = format!(
            "POST /siteadmin/smart.git/git-upload-pack HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: {auth}\r\nGit-Protocol: version=2\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Encoding: {enc}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        s.raw(head.as_bytes(), body)
    };
    let ls_refs = b"0014command=ls-refs\n00010009peel\n0000";
    let r = post(&gz(ls_refs), "gzip");
    assert_eq!(r.status, 200, "{}", body_text(&r));
    assert!(body_text(&r).contains("refs/heads/main"));
    // a bomb: tiny on the wire, far over the inflated cap
    let bomb = gz(&vec![b'0'; 64 << 20]);
    assert!(bomb.len() < 200_000);
    assert_eq!(post(&bomb, "gzip").status, 413);
    assert_eq!(post(b"not gzip at all", "gzip").status, 400);
    assert_eq!(post(ls_refs, "br").status, 415);
    // git never gzips a push; the server refuses it rather than guess
    let head = format!(
        "POST /siteadmin/smart.git/git-receive-pack HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: {auth}\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\n"
    );
    assert_eq!(s.raw(head.as_bytes(), b"abc").status, 415);
}

// ---- limits, admission, process control ----

/// Open a push the client never finishes: the transport stays in flight until the socket closes.
fn stalled_push(s: &Srv, auth: &str, repo: &str) -> std::net::TcpStream {
    use std::io::Write;
    let mut sock = std::net::TcpStream::connect(s.addr).unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let head = format!(
        "POST /siteadmin/{repo}.git/git-receive-pack HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 1000\r\n\r\n0000"
    );
    sock.write_all(head.as_bytes()).unwrap();
    sock
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !f() {
        assert!(
            std::time::Instant::now() < end,
            "timed out waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn slots_are_bounded_then_released_when_the_client_disconnects() {
    let s = Srv::start_transport(scl_forge::cgi::Cfg {
        max_transports: 1,
        admission_wait: std::time::Duration::from_millis(200),
        ..Default::default()
    });
    let auth = token(&s.admin);
    repo(&s, "smart");
    let held = stalled_push(&s, &auth, "smart");
    wait_for("the transport to register", || {
        s.app.life.registry.live() == 1
    });
    let r = s.send(
        "GET",
        &format!("/siteadmin/smart.git{UP}"),
        Some(&auth),
        None,
    );
    assert_eq!(r.status, 503, "{}", body_text(&r));
    assert_eq!(r.headers["retry-after"], "5");
    drop(held);
    wait_for("the child to be reaped after the disconnect", || {
        s.app.life.registry.live() == 0
    });
    wait_for("the slot to come back", || {
        s.send(
            "GET",
            &format!("/siteadmin/smart.git{UP}"),
            Some(&auth),
            None,
        )
        .status
            == 200
    });
}

#[test]
fn a_stalled_upload_is_cut_off_by_the_idle_deadline() {
    let s = Srv::start_transport(scl_forge::cgi::Cfg {
        idle: std::time::Duration::from_millis(300),
        ..Default::default()
    });
    let auth = token(&s.admin);
    repo(&s, "smart");
    let mut sock = stalled_push(&s, &auth, "smart");
    let mut buf = Vec::new();
    use std::io::Read;
    let _ = sock.read_to_end(&mut buf);
    // git writes its response head before it reads the request, so the status line is already
    // out; what the client must see is a connection that ends, not a clean finish.
    assert!(
        !String::from_utf8_lossy(&buf).contains("\r\n0\r\n\r\n"),
        "the chunked body must not be terminated cleanly: {}",
        String::from_utf8_lossy(&buf)
    );
    wait_for("cleanup", || s.app.life.registry.live() == 0);
}

#[test]
fn the_wall_clock_limit_ends_a_transport() {
    let s = Srv::start_transport(scl_forge::cgi::Cfg {
        timeout: std::time::Duration::from_millis(400),
        ..Default::default()
    });
    let auth = token(&s.admin);
    repo(&s, "smart");
    let mut sock = stalled_push(&s, &auth, "smart");
    let mut buf = Vec::new();
    use std::io::Read;
    let _ = sock.read_to_end(&mut buf);
    assert!(
        !String::from_utf8_lossy(&buf).contains("\r\n0\r\n\r\n"),
        "{}",
        String::from_utf8_lossy(&buf)
    );
    wait_for("cleanup", || s.app.life.registry.live() == 0);
}

#[test]
fn deleting_a_repository_ends_its_running_transports_first() {
    let s = Srv::start();
    let auth = token(&s.admin);
    repo(&s, "smart");
    let _held = stalled_push(&s, &auth, "smart");
    wait_for("the transport", || s.app.life.registry.live() == 1);
    let r = s.send("DELETE", "/api/v1/repos/siteadmin/smart", Some(&auth), None);
    assert_eq!(r.status, 204, "{}", r.msg());
    assert_eq!(s.app.life.registry.live(), 0);
    assert!(!s.dir.join("repos").join("1.git").exists());
    assert!(!s.dir.join("trash").join("1.git").exists());
    let r = s.send(
        "GET",
        &format!("/siteadmin/smart.git{UP}"),
        Some(&auth),
        None,
    );
    assert_eq!(r.status, 404);
}

#[test]
fn a_push_over_the_size_cap_fails_and_changes_nothing() {
    let s = Srv::start_transport(scl_forge::cgi::Cfg {
        max_pack: 200 << 10,
        ..Default::default()
    });
    let c = Client::new("cap");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    let work = seeded(&c, &url, &auth);
    // incompressible bytes, so the pack really is large
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let blob: Vec<u8> = (0..(1u32 << 20))
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(work.join("big.bin"), &blob).unwrap();
    c.ok(&work, None, &["add", "."]);
    c.ok(&work, None, &["commit", "-q", "-m", "big"]);
    let (ok, _) = c.git_in(&work, Some(&auth), &["push", "-q", &url, "main"]);
    assert!(!ok);
    let before = c.ok(&work, Some(&auth), &["ls-remote", &url, "refs/heads/main"]);
    let local_parent = c.ok(&work, None, &["rev-parse", "HEAD~1"]);
    assert!(
        before.starts_with(local_parent.trim()),
        "{before} vs {local_parent}"
    );
    wait_for("cleanup", || s.app.life.registry.live() == 0);
}

#[test]
fn a_full_disk_reserve_refuses_pushes_with_507_but_not_reads() {
    let s = Srv::start_transport(scl_forge::cgi::Cfg {
        min_free: u64::MAX / 2,
        ..Default::default()
    });
    let auth = token(&s.admin);
    repo(&s, "smart");
    let post = format!(
        "POST /siteadmin/smart.git/git-receive-pack HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: {auth}\r\nContent-Length: 4\r\n\r\n0000"
    );
    assert_eq!(s.raw(post.as_bytes(), b"").status, 507);
    assert_eq!(
        s.send(
            "GET",
            &format!("/siteadmin/smart.git{UP}"),
            Some(&auth),
            None
        )
        .status,
        200
    );
}

#[test]
fn the_hook_binary_fails_closed() {
    let s = Srv::start();
    repo(&s, "smart");
    let hook = s.dir.join("hooks").join("pre-receive");
    let z = "0".repeat(40);
    let one = "1".repeat(40);
    let run = |id: &str, dir: &Path, stdin: &str| {
        use std::io::Write;
        let mut child = Command::new(&hook)
            .env_clear()
            .env("FORGE_DATA_DIR", dir)
            .env("FORGE_REPO_ID", id)
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let ok_line = format!("{z} {one} refs/heads/feature\n");
    assert_eq!(run("1", &s.dir, &ok_line).0, Some(0));
    for (what, id, dir, line) in [
        (
            "replace ref",
            "1",
            &s.dir,
            format!("{z} {one} refs/replace/x\n"),
        ),
        (
            "default delete",
            "1",
            &s.dir,
            format!("{one} {z} refs/heads/main\n"),
        ),
        (
            "default delete, other case",
            "1",
            &s.dir,
            format!("{one} {z} refs/heads/MAIN\n"),
        ),
        ("non-utf8 ref", "1", &s.dir, "x".to_string()),
        ("unknown repo", "999", &s.dir, ok_line.clone()),
        ("missing db", "1", &s.dir.join("nowhere"), ok_line.clone()),
    ] {
        let (code, err) = run(id, dir, &line);
        assert_eq!(code, Some(1), "{what}: {err}");
    }
    assert_eq!(run("x", &s.dir, &ok_line).0, Some(1), "bad id");
}

// ---- streaming and process control, continued ----

/// 20 MiB that does not compress.
fn noise(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

#[test]
fn a_large_push_and_clone_stream_and_a_vanished_client_ends_the_child() {
    use std::io::{Read, Write};
    let s = Srv::start();
    let c = Client::new("big");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    let work = seeded(&c, &url, &auth);
    std::fs::write(work.join("big.bin"), noise(20 << 20)).unwrap();
    c.ok(&work, None, &["add", "."]);
    c.ok(&work, None, &["commit", "-q", "-m", "big"]);
    c.ok(&work, Some(&auth), &["push", "-q", &url, "main"]);
    let tip = c.ok(&work, None, &["rev-parse", "HEAD"]).trim().to_string();
    let dst = c.dir.join("dst");
    c.ok(
        &c.dir,
        Some(&auth),
        &["clone", "-q", &url, dst.to_str().unwrap()],
    );
    assert_eq!(
        std::fs::metadata(dst.join("big.bin")).unwrap().len(),
        20 << 20
    );

    // Ask for the whole pack (protocol v0) and hang up after the first bytes.
    let want = format!("want {tip} ofs-delta\n");
    let body = format!("{:04x}{want}0000{:04x}done\n", want.len() + 4, 9);
    let head = format!(
        "POST /siteadmin/smart.git/git-upload-pack HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut sock = std::net::TcpStream::connect(s.addr).unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    sock.write_all(head.as_bytes()).unwrap();
    sock.write_all(body.as_bytes()).unwrap();
    let mut first = [0u8; 4096];
    let n = sock.read(&mut first).unwrap();
    assert!(String::from_utf8_lossy(&first[..n]).starts_with("HTTP/1.1 200"));
    drop(sock);
    wait_for("the child to be ended after the hang-up", || {
        s.app.life.registry.live() == 0
    });
    // and the server still serves
    assert_eq!(
        s.send(
            "GET",
            &format!("/siteadmin/smart.git{UP}"),
            Some(&auth),
            None
        )
        .status,
        200
    );
}

#[test]
fn concurrent_pushes_to_one_new_branch_let_exactly_one_win() {
    let s = Srv::start();
    let c = Client::new("race");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    seeded(&c, &url, &auth);
    let mk = |name: &str| {
        let w = c.dir.join(name);
        c.ok(
            &c.dir,
            None,
            &["init", "-q", "-b", "x", w.to_str().unwrap()],
        );
        put_commit(&c, &w, &format!("{name}.txt"), name);
        w
    };
    let (a, b) = (mk("a"), mk("b"));
    let results: Vec<bool> = std::thread::scope(|sc| {
        let hs: Vec<_> = [&a, &b]
            .into_iter()
            .map(|w| {
                sc.spawn(|| {
                    c.git_in(w, Some(&auth), &["push", "-q", &url, "x:refs/heads/race"])
                        .0
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|ok| **ok).count(), 1, "{results:?}");
    s.git(1, &["fsck", "--no-progress"], None);
}

#[test]
fn shutdown_ends_a_running_transport() {
    let s = Srv::start();
    let auth = token(&s.admin);
    repo(&s, "smart");
    let held = stalled_push(&s, &auth, "smart");
    wait_for("the transport", || s.app.life.registry.live() == 1);
    let app = s.app.clone();
    drop(s); // stops the server: the drain deadline passes, then stragglers are cancelled
    assert_eq!(app.life.registry.live(), 0);
    drop(held);
}

#[test]
fn authenticated_object_reads_are_never_publicly_cacheable() {
    let s = Srv::start();
    let c = Client::new("cache");
    let url = repo(&s, "smart");
    let auth = token(&s.admin);
    seeded(&c, &url, &auth);
    let oid = s.git(1, &["rev-parse", "HEAD"], None);
    // a loose object (git says `public, max-age=31536000` for these) and the info/refs advertisement
    let loose = format!("/siteadmin/smart.git/objects/{}/{}", &oid[..2], &oid[2..]);
    let r = s.send("GET", &loose, Some(&auth), None);
    assert_eq!(
        r.status,
        200,
        "a small push leaves loose objects: {}",
        body_text(&r)
    );
    let cc = r.headers["cache-control"].to_ascii_lowercase();
    assert!(cc.contains("private") && !cc.contains("public"), "{cc}");
    assert!(!r.headers.contains_key("expires"), "no far-future expiry");
    let r = s.send(
        "GET",
        &format!("/siteadmin/smart.git{UP}"),
        Some(&auth),
        None,
    );
    assert!(!r.headers["cache-control"]
        .to_ascii_lowercase()
        .contains("public"));
}

#[test]
fn a_request_queued_for_a_slot_does_not_start_git_after_shutdown() {
    let s = Srv::start_transport(scl_forge::cgi::Cfg {
        max_transports: 1,
        ..Default::default()
    });
    let auth = token(&s.admin);
    repo(&s, "smart");
    let held = stalled_push(&s, &auth, "smart");
    wait_for("the transport", || s.app.life.registry.live() == 1);
    let app = s.app.clone();
    let addr = s.addr;
    let admin = s.admin.clone();
    let queued = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut sock = std::net::TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        write!(
            sock,
            "GET /siteadmin/smart.git{UP} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: {}\r\n\r\n",
            token(&admin)
        )
        .ok();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).to_string()
    });
    std::thread::sleep(std::time::Duration::from_millis(300)); // let it reach the admission queue
    drop(s);
    let reply = queued.join().unwrap();
    assert!(!reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert_eq!(app.life.registry.live(), 0);
    drop(held);
}
