//! F5a: garbage collection and the cleanup of what killed git writers leave behind.
#![cfg(unix)]

mod common;
use common::*;
use scl_forge::maintenance::{self, Cfg, Outcome};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

static N: AtomicUsize = AtomicUsize::new(0);

/// A git wrapper that logs every invocation and, while `hold` exists, blocks the first
/// invocation that has `sub` among its arguments (touching `started` when it begins to wait).
struct Wrap {
    dir: PathBuf,
}

impl Wrap {
    fn new(sub: &str) -> Wrap {
        let dir = std::env::temp_dir().join(format!(
            "scl-maint-wrap-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let real = scl_forge::gitproc::find_git().expect("git");
        let d = dir.display();
        let script = format!(
            "#!/bin/sh\necho \"$@\" >> {d}/log\nfor a in \"$@\"; do\n  if [ \"$a\" = {sub} ] && [ -e {d}/hold ]; then\n    touch {d}/started\n    while [ -e {d}/hold ]; do sleep 0.05; done\n  fi\ndone\nexec {} \"$@\"\n",
            real.display()
        );
        let bin = dir.join("git");
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        Wrap { dir }
    }
    fn bin(&self) -> PathBuf {
        self.dir.join("git")
    }
    fn hold(&self) {
        std::fs::write(self.dir.join("hold"), "").unwrap();
    }
    fn release(&self) {
        let _ = std::fs::remove_file(self.dir.join("hold"));
    }
    fn wait_started(&self) {
        wait_for("the wrapped git to start waiting", || {
            self.dir.join("started").exists()
        });
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
    }
}

impl Drop for Wrap {
    fn drop(&mut self) {
        self.release();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while !f() {
        assert!(
            std::time::Instant::now() < end,
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn cfg() -> Cfg {
    Cfg {
        interval: Duration::ZERO,
        min_free: 0,
        gate_wait: Duration::from_secs(5),
        ..Cfg::default()
    }
}

struct W {
    s: Srv,
    auth: String,
    id: i64,
}

fn world_with(cfg: Cfg, git_bin: Option<PathBuf>) -> W {
    let s = Srv::start_maint(cfg, git_bin);
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

fn world() -> W {
    world_with(cfg(), None)
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
    fn exists(&self, oid: &str) -> bool {
        self.s.git_try(self.id, &["cat-file", "-e", oid]).is_some()
    }
    fn repo(&self) -> PathBuf {
        self.s.dir.join("repos").join(format!("{}.git", self.id))
    }
    fn tip(&self, branch: &str) -> String {
        self.git(&["rev-parse", &format!("refs/heads/{branch}")])
    }
    /// An unreferenced blob, loose.
    fn loose(&self, text: &str) -> String {
        self.s.git(
            self.id,
            &["hash-object", "-w", "--stdin"],
            Some(text.as_bytes()),
        )
    }
    fn loose_path(&self, oid: &str) -> PathBuf {
        self.repo().join("objects").join(&oid[..2]).join(&oid[2..])
    }
    fn commit(&self, branch: &str, file: &str, text: &str, from: Option<&str>) -> String {
        let mut body = json!({"content": b64(text), "message": format!("add {file}"), "branch": from.unwrap_or(branch)});
        if from.is_some() {
            body["new_branch"] = json!(branch);
        }
        let r = self.api("POST", &format!("/contents/{file}"), Some(body));
        assert_eq!(r.status, 201, "{}", r.msg());
        self.tip(branch)
    }
    /// One pass on request, waited for.
    fn pass(&self) {
        let before = self.s.app.maint.passes();
        let r = self.s.send(
            "POST",
            "/api/v1/admin/cron/git_gc_repos",
            Some(&self.auth),
            None,
        );
        assert_eq!(r.status, 204, "{}", r.s_text());
        wait_for("the maintenance pass", || {
            self.s.app.maint.passes() > before
        });
    }
    /// One repository's maintenance, in this thread.
    fn maintain(&self) -> Outcome {
        let conn = scl_forge::db::connect(&self.s.dir).unwrap();
        maintenance::maintain_repo(&self.s.app, &conn, self.id)
    }
    fn fsck(&self) {
        let out = self
            .s
            .git_try(self.id, &["fsck", "--strict", "--no-dangling"]);
        assert!(out.is_some(), "git fsck failed");
    }
}

fn age(p: &Path, days: u64) {
    // Loose objects are read-only files; setting the time needs only ownership.
    let f = std::fs::File::open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(days * 86_400))
        .unwrap();
}

fn age_dir(p: &Path, days: u64) {
    // A directory cannot be opened for writing: use the std handle on a read-only open.
    let f = std::fs::File::open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(days * 86_400))
        .unwrap();
}

#[test]
fn aged_unreferenced_objects_go_young_and_reachable_ones_stay() {
    let w = world();
    let head = w.commit("f", "f.txt", "f\n", Some("main"));
    let old_loose = w.loose("old loose");
    age(&w.loose_path(&old_loose), 30);
    // An old unreferenced object inside a pack: reach it through a temporary ref while packing
    // (git 2.40 only packs loose unreachable objects next to an existing pack), then drop the ref.
    let old_packed = w.loose("old packed");
    w.git(&["update-ref", "refs/tmp/keep", &old_packed]);
    w.git(&["repack", "-a", "-d", "-l"]);
    w.git(&["update-ref", "-d", "refs/tmp/keep"]);
    for e in std::fs::read_dir(w.repo().join("objects/pack"))
        .unwrap()
        .flatten()
    {
        age(&e.path(), 30);
    }
    assert!(!w.loose_path(&old_packed).exists(), "the object is packed");
    let young_loose = w.loose("young loose");
    assert!(w.exists(&old_packed));
    w.pass();
    assert!(
        !w.exists(&old_loose),
        "an old loose object must be collected"
    );
    assert!(
        !w.exists(&old_packed),
        "an old packed object must be collected"
    );
    assert!(w.exists(&young_loose), "a young object survives the window");
    assert!(w.exists(&head), "a branch tip survives");
    assert_eq!(w.tip("f"), head);
    w.fsck();
    // The data is intact end to end: the file reads back through the API.
    let r = w.api("GET", "/contents/f.txt?ref=f", None);
    assert_eq!(r.status, 200, "{}", r.msg());
}

#[test]
fn a_merged_pull_keeps_its_merge_commit_after_the_base_is_rewritten() {
    let w = world();
    let base = w.tip("main");
    w.commit("f", "f.txt", "f\n", Some("main"));
    let r = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "PR f", "head": "f", "base": "main"})),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let n = r.json()["number"].as_i64().unwrap();
    assert_eq!(
        w.api(
            "POST",
            &format!("/pulls/{n}/merge"),
            Some(json!({"Do": "merge"}))
        )
        .status,
        200
    );
    let m = w.tip("main");
    assert_eq!(
        w.git(&["rev-parse", &format!("refs/forge/pull/{n}/merge")]),
        m
    );
    // The base is rewritten away from the merge and the objects are old.
    w.git(&["update-ref", "refs/heads/main", &base]);
    let tree = w.git(&["rev-parse", &format!("{m}^{{tree}}")]);
    for oid in [&m, &tree] {
        age(&w.loose_path(oid), 30);
    }
    let junk = w.loose("junk");
    age(&w.loose_path(&junk), 30);
    w.pass();
    assert!(w.exists(&m), "the merge commit is kept by its ref");
    assert!(w.exists(&tree));
    assert!(!w.exists(&junk), "the pass really pruned");
    let pr = w.api("GET", &format!("/pulls/{n}"), None).json();
    assert_eq!(pr["merge_commit_sha"], m.as_str());
    // A missing ref is recreated from the database before anything is pruned.
    w.git(&["update-ref", "-d", &format!("refs/forge/pull/{n}/merge")]);
    w.pass();
    assert!(w.exists(&m));
    assert_eq!(
        w.git(&["rev-parse", &format!("refs/forge/pull/{n}/merge")]),
        m
    );
    w.fsck();
}

#[test]
fn a_retention_ref_that_cannot_be_repaired_stops_the_prune() {
    let w = world();
    w.commit("f", "f.txt", "f\n", Some("main"));
    let r = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "PR f", "head": "f", "base": "main"})),
    );
    let n = r.json()["number"].as_i64().unwrap();
    assert_eq!(
        w.api(
            "PATCH",
            &format!("/pulls/{n}"),
            Some(json!({"state": "closed"}))
        )
        .status,
        201
    );
    // Lose the retention ref and make it unwritable with a lock that is not yet stale.
    let head_ref = format!("refs/forge/pull/{n}/head");
    w.git(&["update-ref", "-d", &head_ref]);
    let lock = w.repo().join(format!("{head_ref}.lock"));
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock, "x").unwrap();
    let junk = w.loose("junk");
    age(&w.loose_path(&junk), 30);
    let o = w.maintain();
    assert!(matches!(o, Outcome::Skipped(_)), "{o:?}");
    assert!(
        w.exists(&junk),
        "nothing is pruned while a root is unconfirmed"
    );
    // Once the lock is old it is cleaned first, the ref is repaired and the prune runs.
    age(&lock, 1);
    let o = w.maintain();
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert!(!lock.exists());
    assert!(!w.exists(&junk));
    assert!(w.git_try_ref(&head_ref));
}

impl W {
    fn git_try_ref(&self, r: &str) -> bool {
        self.s
            .git_try(self.id, &["rev-parse", "--verify", "--quiet", r])
            .is_some()
    }
}

#[test]
fn stage_two_excludes_the_api_writers_while_it_prunes() {
    let wrap = Wrap::new("prune");
    let w = world_with(cfg(), Some(wrap.bin()));
    w.commit("f", "f.txt", "f\n", Some("main"));
    wrap.hold();
    let before = w.s.app.maint.passes();
    let r = w.s.send(
        "POST",
        "/api/v1/admin/cron/git_gc_repos",
        Some(&w.auth),
        None,
    );
    assert_eq!(r.status, 204);
    wrap.wait_started();
    let done = AtomicBool::new(false);
    std::thread::scope(|sc| {
        let writer = sc.spawn(|| {
            let r = w.api(
                "POST",
                "/contents/g.txt",
                Some(json!({"content": b64("g\n"), "message": "g", "branch": "f"})),
            );
            done.store(true, Ordering::SeqCst);
            r.status
        });
        std::thread::sleep(Duration::from_millis(700));
        assert!(
            !done.load(Ordering::SeqCst),
            "a contents write must wait for the prune"
        );
        wrap.release();
        assert_eq!(writer.join().unwrap(), 201);
    });
    wait_for("the pass", || w.s.app.maint.passes() > before);
    w.fsck();
}

#[test]
fn deleting_a_repository_cancels_a_gc_in_either_stage() {
    for stage in ["gc", "prune"] {
        let wrap = Wrap::new(stage);
        let w = world_with(cfg(), Some(wrap.bin()));
        wrap.hold();
        let outcome = std::thread::scope(|sc| {
            let run = sc.spawn(|| w.maintain());
            wrap.wait_started();
            let started = std::time::Instant::now();
            let r =
                w.s.send("DELETE", "/api/v1/repos/siteadmin/w", Some(&w.auth), None);
            assert_eq!(r.status, 204, "{stage}: {}", r.s_text());
            assert!(
                started.elapsed() < Duration::from_secs(9),
                "{stage}: the delete must not wait out its limit"
            );
            run.join().unwrap()
        });
        assert_eq!(outcome, Outcome::Gone, "{stage}");
        assert!(!w.repo().exists());
    }
}

#[test]
fn a_running_transport_defers_the_cleanup_and_age_keeps_young_leftovers() {
    let w = world();
    let stale = w.repo().join("refs/heads/zz.lock");
    let young = w.repo().join("refs/heads/yy.lock");
    let quarantine = w.repo().join("objects/tmp_objdir-incoming-abc123");
    std::fs::write(&stale, "x").unwrap();
    std::fs::write(&young, "x").unwrap();
    std::fs::create_dir_all(quarantine.join("pack")).unwrap();
    std::fs::write(quarantine.join("pack/tmp"), "x").unwrap();
    age(&stale, 1);
    age_dir(&quarantine, 1);
    {
        let _transport =
            w.s.app
                .life
                .registry
                .register(w.id, true, || true)
                .expect("registers");
        assert!(matches!(w.maintain(), Outcome::Done { .. }));
        assert!(stale.exists() && quarantine.exists(), "an owner may exist");
    }
    assert!(matches!(w.maintain(), Outcome::Done { .. }));
    assert!(!stale.exists(), "a stale lock goes once no owner can exist");
    assert!(!quarantine.exists(), "so does a stale quarantine directory");
    assert!(young.exists(), "a young lock is left alone");
}

#[test]
fn too_little_free_disk_skips_the_repack_and_so_the_prune() {
    let wrap = Wrap::new("none");
    let w = world_with(
        Cfg {
            min_free: u64::MAX / 2,
            ..cfg()
        },
        Some(wrap.bin()),
    );
    let junk = w.loose("junk");
    age(&w.loose_path(&junk), 30);
    assert!(matches!(w.maintain(), Outcome::Skipped(_)));
    let log = wrap.log();
    assert!(!log.split_whitespace().any(|a| a == "gc"), "gc ran: {log}");
    assert!(
        !log.split_whitespace().any(|a| a == "prune"),
        "pruned without a stage 1: {log}"
    );
    assert!(w.exists(&junk));
}

#[test]
fn the_cron_route_is_for_site_admins_with_the_admin_scope() {
    let w = world();
    let url = "/api/v1/admin/cron/git_gc_repos";
    // Anonymous callers get Gitea's answer for a token-only route.
    assert!([401, 403].contains(&w.s.send("POST", url, None, None).status));
    let pw = w.s.mk_user("bob");
    let bob = token(&w.s.mk_token("bob", &pw, "t", &["write:repository"]));
    assert_eq!(w.s.send("POST", url, Some(&bob), None).status, 403);
    let narrow = scl_forge::admin::generate_access_token(
        &w.s.dir,
        "siteadmin",
        "narrow",
        &["read:repository".to_string()],
    )
    .unwrap();
    assert_eq!(
        w.s.send("POST", url, Some(&token(&narrow)), None).status,
        403,
        "an admin token without the admin scope"
    );
    assert_eq!(
        w.s.send("POST", "/api/v1/admin/cron/nope", Some(&w.auth), None)
            .status,
        404
    );
    assert_eq!(w.s.send("POST", url, Some(&w.auth), None).status, 204);
    wait_for("the queue to drain", || !w.s.app.maint.busy());
}

#[test]
fn requests_during_a_running_pass_start_nothing_more() {
    let wrap = Wrap::new("gc");
    let w = world_with(cfg(), Some(wrap.bin()));
    let before = w.s.app.maint.passes();
    wrap.hold();
    let url = "/api/v1/admin/cron/git_gc_repos";
    assert_eq!(w.s.send("POST", url, Some(&w.auth), None).status, 204);
    wrap.wait_started();
    for _ in 0..3 {
        assert_eq!(w.s.send("POST", url, Some(&w.auth), None).status, 204);
    }
    assert!(
        !w.s.app.maint.request(),
        "a running pass covers the request"
    );
    wrap.release();
    wait_for("the pass", || w.s.app.maint.passes() > before);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(w.s.app.maint.passes(), before + 1, "exactly one pass ran");
}

#[test]
fn a_prune_window_shorter_than_the_safe_minimum_is_refused_at_startup() {
    let dir = std::env::temp_dir().join(format!("scl-maint-flag-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sc-forge"))
        .args(["serve", "--data-dir"])
        .arg(&dir)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--public-url",
            "http://127.0.0.1:1",
            "--gc-prune-expire",
            "60",
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--gc-prune-expire must be at least"), "{err}");
}

#[test]
fn passes_beside_writers_lose_nothing() {
    let w = world();
    w.commit("f", "f.txt", "f\n", Some("main"));
    // Everything that exists is old, so the passes really prune and the writers reuse old objects.
    let junk: Vec<String> = (0..20).map(|i| w.loose(&format!("junk {i}"))).collect();
    let mut stack = vec![w.repo().join("objects")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if d.file_name().is_some_and(|n| n.len() == 2) {
                age(&p, 30);
            }
        }
    }
    let stop = AtomicBool::new(false);
    let acknowledged = std::sync::Mutex::new(Vec::<String>::new());
    std::thread::scope(|sc| {
        let passes = sc.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                w.pass();
            }
        });
        let writers: Vec<_> = (0..3)
            .map(|t| {
                let (w, ack) = (&w, &acknowledged);
                sc.spawn(move || {
                    for i in 0..8 {
                        let file = format!("t{t}-{i}.txt");
                        let r = w.api(
                            "POST",
                            &format!("/contents/{file}"),
                            Some(json!({"content": b64(&format!("{t}{i}\n")), "message": file, "branch": "f"})),
                        );
                        if r.status == 201 {
                            ack.lock().unwrap().push(file);
                        } else {
                            // Contention on one branch is a refusal, never a lost write.
                            assert!([409, 422, 503].contains(&r.status), "{} {}", r.status, r.msg());
                        }
                    }
                })
            })
            .collect();
        for h in writers {
            h.join().unwrap();
        }
        stop.store(true, Ordering::SeqCst);
        passes.join().unwrap();
    });
    assert!(!acknowledged.lock().unwrap().is_empty());
    assert!(
        junk.iter().all(|j| !w.exists(j)),
        "the passes pruned the old junk"
    );
    w.fsck();
    for file in acknowledged.lock().unwrap().iter() {
        let r = w.api("GET", &format!("/contents/{file}?ref=f"), None);
        assert_eq!(r.status, 200, "{file} was acknowledged and must read back");
    }
}

#[test]
fn a_branch_or_default_branch_writer_defers_the_cleanup() {
    let w = world();
    let stale = w.repo().join("refs/heads/zz.lock");
    std::fs::write(&stale, "x").unwrap();
    age(&stale, 1);
    {
        // The exclusive lifecycle lock is what default-branch changes and branch deletes hold.
        let lock = w.s.app.life.lock_for(w.id);
        let _writer = lock.write().unwrap();
        // Neither the cleanup nor the reconcile (a gated writer) runs beside it.
        assert!(matches!(w.maintain(), Outcome::Skipped(_)));
        assert!(stale.exists(), "a lifecycle writer may own that lock");
    }
    assert!(matches!(w.maintain(), Outcome::Done { .. }));
    assert!(!stale.exists());
}

#[test]
fn an_open_pull_with_no_branch_and_no_retention_ref_stops_the_prune() {
    let w = world();
    w.commit("f", "f.txt", "f\n", Some("main"));
    let r = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "PR f", "head": "f", "base": "main"})),
    );
    let n = r.json()["number"].as_i64().unwrap();
    // Lost branch and retention ref, and a fresh lock that keeps the repair from succeeding: the
    // sync logs and skips this pull request, yet the prune must still refuse to run.
    w.git(&["update-ref", "-d", "refs/heads/f"]);
    w.git(&["update-ref", "-d", &format!("refs/forge/pull/{n}/head")]);
    let lock = w.repo().join(format!("refs/forge/pull/{n}/head.lock"));
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock, "x").unwrap();
    let junk = w.loose("junk");
    age(&w.loose_path(&junk), 30);
    let o = w.maintain();
    assert!(matches!(o, Outcome::Skipped(_)), "{o:?}");
    assert!(w.exists(&junk));
}

#[test]
fn a_fetch_does_not_defer_the_cleanup_but_a_push_does() {
    let w = world();
    let stale = w.repo().join("refs/heads/zz.lock");
    std::fs::write(&stale, "x").unwrap();
    age(&stale, 1);
    let reg = &w.s.app.life.registry;
    let push = reg.register(w.id, true, || true).expect("registers");
    assert!(matches!(w.maintain(), Outcome::Done { .. }));
    assert!(stale.exists(), "a push may own the lock");
    drop(push);
    let _fetch = reg.register(w.id, false, || true).expect("registers");
    assert!(matches!(w.maintain(), Outcome::Done { .. }));
    assert!(!stale.exists(), "a read-only run owns no lock");
}

#[test]
fn the_quarantine_name_matches_what_git_really_creates() {
    use scl_forge::orphans::QUARANTINE_PREFIX;
    let w = world();
    let hook = w.repo().join("hooks");
    std::fs::create_dir_all(&hook).unwrap();
    let seen = w.s.dir.join("seen");
    // A pre-receive hook sees the quarantine: record what lives under objects/ at that moment.
    let script = format!("#!/bin/sh\nls \"$GIT_DIR/objects\" > {}\n", seen.display());
    // The server's own hooks directory is configured globally; use a per-repository override.
    let own = w.s.dir.join("own-hooks");
    std::fs::create_dir_all(&own).unwrap();
    std::fs::write(own.join("pre-receive"), script).unwrap();
    std::fs::set_permissions(
        own.join("pre-receive"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let work = w.s.dir.join("work");
    let git = |dir: &Path, args: &[&str]| {
        let o = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    };
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    std::fs::write(work.join("a"), "a").unwrap();
    git(&work, &["add", "a"]);
    git(
        &work,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@x",
            "commit",
            "-qm",
            "m",
        ],
    );
    let bare = w.s.dir.join("q.git");
    git(&w.s.dir, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    git(&bare, &["config", "core.hooksPath", own.to_str().unwrap()]);
    git(&work, &["push", "-q", bare.to_str().unwrap(), "main"]);
    let listing = std::fs::read_to_string(&seen).unwrap();
    assert!(
        listing.lines().any(|l| l.starts_with(QUARANTINE_PREFIX)),
        "git names its quarantine differently now: {listing}"
    );
}

#[test]
fn an_absurd_prune_window_prunes_nothing() {
    let w = world_with(
        Cfg {
            prune_expire: Duration::from_secs(u64::MAX),
            ..cfg()
        },
        None,
    );
    let junk = w.loose("junk");
    age(&w.loose_path(&junk), 30);
    assert!(matches!(w.maintain(), Outcome::Skipped(_)));
    assert!(w.exists(&junk));
}

#[test]
fn duration_flags_beyond_ten_years_are_refused() {
    for (flag, value) in [
        ("--gc-prune-expire", "9999999999"),
        ("--maintenance-interval", "18446744073709551615"),
        ("--gc-timeout", "9999999999"),
    ] {
        let dir = std::env::temp_dir().join(format!("scl-maint-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sc-forge"))
            .args(["serve", "--data-dir"])
            .arg(&dir)
            .args([
                "--listen",
                "127.0.0.1:0",
                "--public-url",
                "http://127.0.0.1:1",
            ])
            .args([flag, value])
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!out.status.success(), "{flag}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("at most"), "{flag}: {err}");
    }
}

#[test]
fn a_base_branch_deleted_under_an_open_pull_keeps_its_last_commit() {
    let w = world();
    let base_tip = w.commit("b", "b.txt", "b\n", Some("main"));
    w.commit("f", "f.txt", "f\n", Some("main"));
    let r = w.api(
        "POST",
        "/pulls",
        Some(json!({"title": "PR f", "head": "f", "base": "b"})),
    );
    assert_eq!(r.status, 201, "{}", r.msg());
    let n = r.json()["number"].as_i64().unwrap();
    w.git(&["update-ref", "-d", "refs/heads/b"]);
    let tree = w.git(&["rev-parse", &format!("{base_tip}^{{tree}}")]);
    for oid in [&base_tip, &tree] {
        age(&w.loose_path(oid), 30);
    }
    w.pass();
    assert!(w.exists(&base_tip), "the stored base must survive");
    assert_eq!(
        w.git(&["rev-parse", &format!("refs/forge/pull/{n}/base")]),
        base_tip
    );
    let r = w.api("GET", &format!("/pulls/{n}"), None);
    assert_eq!(r.status, 200, "{}", r.msg());
}
