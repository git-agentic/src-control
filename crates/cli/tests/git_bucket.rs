//! `sc+git::<git-url>` bucket remotes through the real binary: URL routing,
//! the private-branch opt-in, the deferred-feature refusals, and one end-to-end
//! scenario (private branch + protected path + secret over a Git carrier).
//!
//! The scenario runs twice from one body: over `sc+wal://` as a control that
//! proves the script itself, and over `sc+git::file://<bare repo>`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

thread_local! {
    /// `TMPDIR` for every `sc` this test thread runs (each test owns its thread).
    static SC_TMPDIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-gitbucket-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `sc` in `dir` with a private `HOME` (so no real `~/.sc/identity` is
/// picked up) and, optionally, `SC_IDENTITY`.
fn sc_as(dir: &Path, identity: Option<&Path>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sc"));
    cmd.args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("SC_AUTHOR", "tester")
        .env_remove("SC_IDENTITY");
    if let Some(id) = identity {
        cmd.env("SC_IDENTITY", id);
    }
    if let Some(t) = SC_TMPDIR.with(|t| t.borrow().clone()) {
        cmd.env("TMPDIR", t);
    }
    cmd.output().expect("sc runs")
}

fn sc(dir: &Path, args: &[&str]) -> Output {
    sc_as(dir, None, args)
}

fn ok(out: Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn err_text(out: &Output) -> String {
    assert!(!out.status.success(), "expected failure: {out:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn keygen(dir: &Path, name: &str) -> (PathBuf, String) {
    let idfile = dir.join(format!("{name}.id"));
    let out = ok(sc(dir, &["keygen", "--out", idfile.to_str().unwrap()]));
    let pk = out
        .lines()
        .find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("public key in keygen output")
        .to_string();
    (idfile, pk)
}

fn init_repo(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    ok(sc(dir, &["init"]));
}

// ---- always-on: URL routing and refusals (no GitBucket I/O) ----------------

/// `sc+git:` is a reserved prefix. A near miss is refused by `remote add` and
/// `clone`, never saved and never read as a local path or a Git URL.
#[test]
fn sc_git_near_misses_are_refused_and_never_saved_or_cloned() {
    let a = tmp("nearmiss");
    init_repo(&a);
    for url in [
        "sc+git:/x",
        "sc+git://x",
        "sc+git:x",
        "sc+git:git@h:o/r.git",
    ] {
        let out = sc(&a, &["remote", "add", "x", url]);
        let e = err_text(&out);
        assert!(e.contains("sc+git::"), "{url}: {e}");
    }
    let listed = ok(sc(&a, &["remote", "list"]));
    assert_eq!(listed.trim(), "", "nothing was saved");

    // clone: refused before the destination is created
    let dst = a.join("dst");
    let out = sc(&a, &["clone", "sc+git:/x", dst.to_str().unwrap()]);
    let e = err_text(&out);
    assert!(e.contains("sc+git::"), "{e}");
    assert!(!dst.exists());
    std::fs::remove_dir_all(&a).unwrap();
}

#[test]
fn sc_git_is_never_a_git_bridge_remote_and_the_opt_in_is_sc_git_only() {
    let a = tmp("flags");
    init_repo(&a);
    let carrier = "sc+git::file:///nonexistent/carrier.git";
    let e = err_text(&sc(&a, &["remote", "add", "x", carrier, "--git"]));
    assert!(e.contains("--git cannot be used"), "{e}");
    let e = err_text(&sc(
        &a,
        &[
            "remote",
            "add",
            "x",
            "https://example.com/r.git",
            "--allow-private-branches",
        ],
    ));
    assert!(e.contains("only to sc+git::"), "{e}");
    let dst = a.join("dst");
    let e = err_text(&sc(&a, &["clone", "--git", carrier, dst.to_str().unwrap()]));
    assert!(e.contains("--git cannot be used"), "{e}");
    let e = err_text(&sc(
        &a,
        &[
            "clone",
            "/some/path",
            dst.to_str().unwrap(),
            "--allow-private-branches",
        ],
    ));
    assert!(e.contains("only to sc+git::"), "{e}");
    assert!(!dst.exists());
    assert_eq!(ok(sc(&a, &["remote", "list"])).trim(), "");
    std::fs::remove_dir_all(&a).unwrap();
}

/// Deferred in v1: `sc serve --store` refuses an `sc+git::` store with a clear
/// message, before any I/O.
#[test]
fn serve_store_refuses_sc_git() {
    let a = tmp("deferred");
    init_repo(&a);
    let home = tmp("deferred-home");
    init_repo(&home);
    let e = err_text(&sc(
        &a,
        &[
            "serve",
            "--stdio",
            "--store",
            "sc+git::file:///nonexistent/carrier.git",
            home.to_str().unwrap(),
        ],
    ));
    assert!(e.contains("does not support sc+git::"), "{e}");
    for d in [&a, &home] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

/// The private-branch gate through the binary, with a config written by hand
/// (an old-style entry with no `allow_private_branches` key parses as false).
/// The carrier does not exist: refusing proves it happens before any upload.
#[test]
fn pushing_a_private_branch_to_a_git_carrier_needs_the_opt_in() {
    let a = tmp("gate");
    let keys = tmp("gate-keys");
    init_repo(&a);
    let (id, pk) = keygen(&keys, "alice");
    std::fs::write(
        a.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{pk}\"\n"),
    )
    .unwrap();
    std::fs::write(a.join("f.txt"), "f\n").unwrap();
    ok(sc(&a, &["commit", "-m", "base"]));
    let idp = id.to_str().unwrap();
    ok(sc(
        &a,
        &[
            "branch",
            "hotfix",
            "--private",
            "--to",
            "alice",
            "--identity",
            idp,
        ],
    ));
    ok(sc(&a, &["switch", "hotfix", "--identity", idp]));
    std::fs::write(a.join("embargo.txt"), "secret fix\n").unwrap();
    ok(sc(&a, &["commit", "-m", "embargoed", "--identity", idp]));

    let carrier = a.join("never-created.git");
    std::fs::write(
        a.join(".sc/config"),
        format!(
            "[remote.origin]\nurl = \"sc+git::file://{}\"\n",
            carrier.display()
        ),
    )
    .unwrap();
    let e = err_text(&sc(&a, &["push", "origin"]));
    for needle in [
        "--allow-private-branches",
        "sc remote set <name> --allow-private-branches",
        "readable by everyone who can read the Git repository",
        "after any later revoke",
    ] {
        assert!(e.contains(needle), "missing {needle:?}: {e}");
    }
    assert!(!carrier.exists(), "nothing was uploaded");
    // The suggested command works on the existing remote: the gate is passed
    // (the push now fails later, opening the nonexistent carrier).
    ok(sc(
        &a,
        &["remote", "set", "origin", "--allow-private-branches"],
    ));
    let e = err_text(&sc(&a, &["push", "origin"]));
    assert!(!e.contains("Nothing was uploaded"), "{e}");
    for d in [&a, &keys] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

// ---- end-to-end scenario ----------------------------------------------------

struct Fixture {
    root: PathBuf,
    keys: PathBuf,
    id: PathBuf,
    /// The carrier (`sc+wal://` directory or bare Git repo) and its sc URL.
    carrier: PathBuf,
    url: String,
    a: PathBuf,
}

fn git_carrier(tag: &str) -> Fixture {
    let mut fx = fixture(tag, "git");
    let st = Command::new("git")
        .args(["init", "--bare", "-q", fx.carrier.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(st.success());
    fx.url = format!("sc+git::file://{}", fx.carrier.display());
    fx
}

fn fixture(tag: &str, kind: &str) -> Fixture {
    let root = tmp(&format!("e2e-{kind}-{tag}"));
    let keys = tmp(&format!("e2e-{kind}-{tag}-keys"));
    let (id, pk) = keygen(&keys, "alice");
    let carrier = root.join("carrier");
    let a = root.join("a");
    init_repo(&a);
    std::fs::write(
        a.join(".sc/recipients.toml"),
        format!("[recipients]\nalice = \"{pk}\"\n"),
    )
    .unwrap();
    let idp = id.to_str().unwrap();
    ok(sc(&a, &["protect", "config/", "--to", "alice"]));
    std::fs::create_dir_all(a.join("config")).unwrap();
    std::fs::write(a.join("config/prod.env"), "DB=prod-secret-marker\n").unwrap();
    std::fs::write(a.join("README.md"), "public readme\n").unwrap();
    ok(sc(
        &a,
        &[
            "secret",
            "add",
            "API_TOKEN",
            "--to",
            "alice",
            "--value",
            "s3cret",
        ],
    ));
    ok(sc_as(&a, Some(&id), &["commit", "-m", "main base"]));
    ok(sc(
        &a,
        &[
            "branch",
            "hotfix",
            "--private",
            "--to",
            "alice",
            "--identity",
            idp,
        ],
    ));
    ok(sc(&a, &["switch", "hotfix", "--identity", idp]));
    std::fs::write(a.join("embargo.txt"), "embargoed fix\n").unwrap();
    ok(sc(
        &a,
        &["commit", "-m", "embargoed message", "--identity", idp],
    ));
    ok(sc(&a, &["switch", "main", "--identity", idp]));
    Fixture {
        url: format!("sc+wal://{}", carrier.display()),
        root,
        keys,
        id,
        carrier,
        a,
    }
}

fn clone_into(
    fx: &Fixture,
    name: &str,
    identity: Option<&Path>,
    extra: &[&str],
) -> (PathBuf, Output) {
    let dst = fx.root.join(name);
    let mut args = vec!["clone", fx.url.as_str(), dst.to_str().unwrap()];
    args.extend_from_slice(extra);
    let out = sc_as(&fx.root, identity, &args);
    (dst, out)
}

/// The shared body. `gated` is true for `sc+git::`, where a private branch
/// needs the per-remote opt-in.
fn scenario(fx: Fixture, gated: bool) {
    // Every `sc` runs with its own empty TMPDIR, so the carrier's temporary
    // cache repositories are findable afterwards.
    let tmpdir = fx.root.join("sc-tmpdir");
    std::fs::create_dir_all(&tmpdir).unwrap();
    SC_TMPDIR.with(|t| *t.borrow_mut() = Some(tmpdir.clone()));
    let idp = fx.id.clone();
    let idp = idp.to_str().unwrap();
    let a = &fx.a;

    let notice = |out: &Output| {
        String::from_utf8_lossy(&out.stderr).contains("everyone who can read the Git repository")
    };

    let out = sc(a, &["remote", "add", "origin", &fx.url]);
    assert_eq!(notice(&out), gated, "one notice for sc+git:: only: {out:?}");
    ok(out);
    ok(sc(a, &["push", "origin"])); // public main

    ok(sc(a, &["switch", "hotfix", "--identity", idp]));
    if gated {
        let before = refs_on_carrier(&fx.carrier);
        assert!(!before.is_empty(), "main's push stored refs/sc/*");
        let e = err_text(&sc(a, &["push", "origin"]));
        assert!(e.contains("--allow-private-branches"), "{e}");
        assert_eq!(
            refs_on_carrier(&fx.carrier),
            before,
            "refusal uploaded nothing"
        );
        let out = sc(
            a,
            &[
                "remote",
                "add",
                "opted",
                &fx.url,
                "--allow-private-branches",
            ],
        );
        ok(out);
        ok(sc(a, &["push", "opted"]));
        let cfg = std::fs::read_to_string(a.join(".sc/config")).unwrap();
        assert!(cfg.contains("allow_private_branches = true"), "{cfg}");
    } else {
        ok(sc(a, &["push", "origin"]));
    }
    ok(sc(a, &["switch", "main", "--identity", idp]));

    // Compact the same remote twice, a grace window apart; the clones below then
    // prove everything still reads. On a Git carrier the first run only records
    // when it first saw each object, so it deletes nothing and the second run
    // (past the grace) is the one that removes refs.
    let remote = if gated { "opted" } else { "origin" };
    let compact = [
        "remote",
        "compact",
        remote,
        "--prune-expire",
        "1s",
        "--allow-short-grace",
    ];
    let first = ok(sc(a, &compact));
    let mid = refs_on_carrier(&fx.carrier).lines().count();
    if gated {
        assert!(first.contains("first sighting"), "{first}");
        assert!(
            first.contains("deleted 0 log entries, 0 checkpoint(s), 0 pack(s)"),
            "{first}"
        );
        assert!(
            refs_on_carrier(&fx.carrier).contains("refs/sc/compact/sightings"),
            "the age record is on the host"
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let second = ok(sc(a, &compact));
    if gated {
        assert!(!second.contains("deleted 0 log entries"), "{second}");
        let end = refs_on_carrier(&fx.carrier).lines().count();
        assert!(
            end < mid,
            "compaction removed refs from the host: {mid} -> {end}"
        );
    }

    // Keyless clone: public content and the branch marker only.
    let (keyless, out) = clone_into(&fx, "keyless", None, &[]);
    assert_eq!(notice(&out), gated);
    ok(out);
    let listing = ok(sc(&keyless, &["branch", "list"]));
    assert!(listing.contains("hotfix (private, no access)"), "{listing}");
    assert_eq!(
        std::fs::read_to_string(keyless.join("README.md")).unwrap(),
        "public readme\n"
    );
    assert!(
        !keyless.join("config/prod.env").exists(),
        "protected path is absent"
    );
    assert!(!keyless.join("embargo.txt").exists());
    let cfg = std::fs::read_to_string(keyless.join(".sc/config")).unwrap();
    assert!(!cfg.contains("allow_private_branches"), "{cfg}");
    assert!(ok(sc(&keyless, &["secret", "list"])).contains("API_TOKEN"));

    // Keyed clone: everything reads.
    let extra: &[&str] = if gated {
        &["--allow-private-branches"]
    } else {
        &[]
    };
    let (keyed, out) = clone_into(&fx, "keyed", Some(&fx.id), extra);
    ok(out);
    // Clone materializes HEAD without a key; a keyed switch lays the protected file out.
    ok(sc_as(
        &keyed,
        Some(&fx.id),
        &["switch", "main", "--identity", idp],
    ));
    assert_eq!(
        std::fs::read_to_string(keyed.join("config/prod.env")).unwrap(),
        "DB=prod-secret-marker\n"
    );
    ok(sc_as(
        &keyed,
        Some(&fx.id),
        &[
            "run",
            "--identity",
            idp,
            "--",
            "sh",
            "-c",
            "test \"$API_TOKEN\" = s3cret",
        ],
    ));
    let cfg = std::fs::read_to_string(keyed.join(".sc/config")).unwrap();
    assert_eq!(
        cfg.contains("allow_private_branches = true"),
        gated,
        "{cfg}"
    );
    ok(sc_as(
        &keyed,
        Some(&fx.id),
        &["switch", "hotfix", "--identity", idp],
    ));
    assert_eq!(
        std::fs::read_to_string(keyed.join("embargo.txt")).unwrap(),
        "embargoed fix\n"
    );
    let log = ok(sc_as(&keyed, Some(&fx.id), &["log", "--identity", idp]));
    assert!(log.contains("embargoed message"), "{log}");

    // A partial clone of a bucket remote is refused, as for sc+wal://.
    let (partial, out) = clone_into(&fx, "partial", None, &["--filter", "config/"]);
    let e = err_text(&out);
    assert!(
        e.contains("partial clone from bucket remotes is not supported"),
        "{e}"
    );
    assert!(!partial.exists(), "{e}");

    let left: Vec<_> = std::fs::read_dir(&tmpdir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "temp cache left behind: {left:?}");

    std::fs::remove_dir_all(&fx.root).unwrap();
    std::fs::remove_dir_all(&fx.keys).unwrap();
    assert!(!fx.root.exists());
}

fn refs_on_carrier(carrier: &Path) -> String {
    let out = Command::new("git")
        .args(["-C", carrier.to_str().unwrap(), "for-each-ref", "refs/sc/"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Control: the same script over the existing `sc+wal://` backend.
#[test]
fn scenario_over_a_wal_bucket_is_the_control() {
    scenario(fixture("control", "wal"), false);
}

#[test]
fn private_branch_protected_path_and_secret_round_trip_over_a_git_carrier() {
    scenario(git_carrier("roundtrip"), true);
}

/// Carrier URL forms through the CLI: file://, scp-form, ssh://, https://. No
/// network is touched: `remote add` validates the URL and writes the config.
#[test]
fn remote_add_accepts_scp_form_and_file_carrier_urls_and_notices_once() {
    let a = tmp("forms");
    init_repo(&a);
    for (i, inner) in [
        "file:///srv/hub.git",
        "git@github.com:org/repo.git",
        "ssh://git@host/org/repo.git",
        "https://example.com/org/repo.git",
        "/abs/path/hub.git",
    ]
    .iter()
    .enumerate()
    {
        let url = format!("sc+git::{inner}");
        let out = sc(&a, &["remote", "add", &format!("r{i}"), &url]);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        ok(out);
        assert_eq!(
            stderr
                .matches("everyone who can read the Git repository")
                .count(),
            1,
            "{url}: {stderr}"
        );
    }
    let listed = ok(sc(&a, &["remote", "list"]));
    assert!(
        listed.contains("sc+git::git@github.com:org/repo.git\t[sc]"),
        "{listed}"
    );
    for bad in [
        "relative/path",
        "-oProxyCommand=x",
        "https://u:pw@h/r.git",
        "https://token@h/r.git",
        "",
    ] {
        let url = format!("sc+git::{bad}");
        assert!(
            !sc(&a, &["remote", "add", "bad", &url]).status.success(),
            "{url}"
        );
    }
    std::fs::remove_dir_all(&a).unwrap();
}

/// No message of ours shows a credential from an `sc+git::` URL.
#[test]
fn rejected_urls_and_flag_errors_never_echo_credentials() {
    let a = tmp("redact");
    init_repo(&a);
    let dst = a.join("dst");
    let cred = "sc+git::https://u:hunter2@h/r.git";
    let out = sc(&a, &["remote", "add", "bad", cred]);
    let seen = |o: &Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    };
    assert!(!out.status.success());
    assert!(!seen(&out).contains("hunter2"), "{}", seen(&out));
    // the --git refusals, in both commands
    for url in [cred, "sc+git::git@h:o/r.git"] {
        for args in [
            vec!["remote", "add", "x", url, "--git"],
            vec!["clone", "--git", url, dst.to_str().unwrap()],
        ] {
            let out = sc(&a, &args);
            assert!(seen(&out).contains("--git cannot be used"), "{args:?}");
            assert!(!seen(&out).contains("hunter2"), "{}", seen(&out));
        }
    }
    // a valid URL with an ssh user is echoed without the user part
    let out = sc(&a, &["remote", "add", "ok", "sc+git::ssh://deploy@h/r.git"]);
    assert!(!seen(&out).contains("deploy@"), "{}", seen(&out));
    assert!(out.status.success());
    // near misses in the other letter cases are refused too
    for url in ["SC+GIT::https://u:hunter2@h/r.git", "Sc+Git:x"] {
        let out = sc(&a, &["remote", "add", "y", url]);
        assert!(!out.status.success(), "{url}");
        assert!(!seen(&out).contains("hunter2"), "{}", seen(&out));
    }
    assert_eq!(ok(sc(&a, &["remote", "list"])).lines().count(), 1);
    std::fs::remove_dir_all(&a).unwrap();
}

/// `sc remote set` flips the private-branch opt-in on an existing remote.
#[test]
fn remote_set_changes_the_private_branch_opt_in() {
    let a = tmp("remote-set");
    init_repo(&a);
    ok(sc(
        &a,
        &["remote", "add", "origin", "sc+git::file:///srv/hub.git"],
    ));
    ok(sc(&a, &["remote", "add", "w", "sc+wal:///srv/w"]));
    let cfg = || std::fs::read_to_string(a.join(".sc/config")).unwrap();
    assert!(!cfg().contains("allow_private_branches = true"));
    ok(sc(
        &a,
        &["remote", "set", "origin", "--allow-private-branches"],
    ));
    assert!(cfg().contains("allow_private_branches = true"), "{}", cfg());
    ok(sc(
        &a,
        &["remote", "set", "origin", "--no-allow-private-branches"],
    ));
    assert!(
        !cfg().contains("allow_private_branches = true"),
        "{}",
        cfg()
    );
    // refusals
    let e = err_text(&sc(&a, &["remote", "set", "origin"]));
    assert!(e.contains("nothing to set"), "{e}");
    let e = err_text(&sc(&a, &["remote", "set", "w", "--allow-private-branches"]));
    assert!(e.contains("only to sc+git::"), "{e}");
    let e = err_text(&sc(
        &a,
        &["remote", "set", "nope", "--allow-private-branches"],
    ));
    assert!(e.contains("no such remote"), "{e}");
    let e = err_text(&sc(
        &a,
        &[
            "remote",
            "set",
            "origin",
            "--allow-private-branches",
            "--no-allow-private-branches",
        ],
    ));
    assert!(e.contains("cannot be used with"), "{e}");
    std::fs::remove_dir_all(&a).unwrap();
}
