//! `sc+git::` remote plumbing: URL parsing and the reserved prefix, the
//! private-branch gate. The serve-side gate has its own tests in
//! `git_serve_tests.rs`. Nothing here reaches `GitBucket`'s real I/O except the URL-parse test.

use super::*;
use crate::error::Error;
use crate::repo::Repo;

fn root(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-bt-gitremote-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn invalid<T: std::fmt::Debug>(r: Result<T>) -> String {
    match r {
        Err(Error::InvalidArgument(m)) => m,
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

/// `sc+git:` is a reserved prefix: only `sc+git::<inner>` is accepted, and a
/// near miss is refused before the inner validator runs.
#[test]
fn sc_git_near_misses_are_refused_at_parse() {
    for url in [
        "sc+git:",
        "sc+git:/x",
        "sc+git:x",
        "sc+git://x",
        "sc+git:file:///x",
        "sc+git::file:///x\n",
        "sc+git::file:///x\r",
        // the prefix is case-insensitive: only exact lowercase `sc+git::` parses
        "SC+GIT::file:///x",
        "Sc+Git:x",
        "sc+GIT::file:///x",
        "SC+git:/x",
    ] {
        let msg = invalid(BucketUrl::parse(url));
        assert!(msg.contains("bad bucket url"), "{url}: {msg}");
    }
    // No message echoes a credential from the URL.
    for url in [
        "sc+git::https://u:hunter2@h/r.git",
        "SC+GIT::https://u:hunter2@h/r.git",
        "sc+git:https://u:hunter2@h/r.git",
    ] {
        let msg = invalid(BucketUrl::parse(url));
        assert!(!msg.contains("hunter2"), "{url}: {msg}");
    }
    // Not under the prefix at all: the generic refusal names all three schemes.
    assert!(invalid(BucketUrl::parse("sc+gitx::y")).contains("sc+git::"));
}

#[test]
fn is_bucket_url_recognises_every_bucket_scheme_and_the_reserved_prefix() {
    for url in [
        "sc+wal:///tmp/b",
        "sc+s3://bucket/p",
        "sc+git::file:///srv/r.git",
        "sc+git::git@github.com:org/repo.git",
        // reserved prefix: routed to the bucket transport so parse refuses it
        "sc+git:/x",
        "sc+git://x",
        "SC+GIT::x",
        "Sc+Git:x",
    ] {
        assert!(is_bucket_url(url), "{url}");
    }
    for url in [
        "",
        "/srv/repo",
        "ssh://host/repo",
        "sc+http://h/r",
        "sc+https://h/r",
        "https://github.com/o/r.git",
        "git@github.com:o/r.git",
        "sc+wal:/x",
        "sc+gitx::y",
    ] {
        assert!(!is_bucket_url(url), "{url}");
    }
    assert!(is_git_bucket_url("sc+git:/x") && !is_git_bucket_url("sc+wal:///x"));
}

/// A near miss must not be opened as a local `.sc/` path by `open_transport`.
#[test]
fn a_near_miss_never_opens_as_a_local_path() {
    let d = root("nearmiss");
    // A directory that a path reading of the URL would find.
    std::fs::create_dir_all(d.join(".sc")).unwrap();
    for prefix in ["sc+git:", "SC+GIT::", "Sc+Git:"] {
        let url = format!("{prefix}{}", d.display());
        let Err(err) = crate::stdio_transport::open_transport(&url) else {
            panic!("a near miss is refused: {url}");
        };
        assert!(matches!(err, Error::InvalidArgument(_)), "{err}");
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn the_private_branch_gate_names_the_flag_and_the_exposure() {
    let url = "sc+git::git@github.com:org/repo.git";
    let msg = invalid(check_private_push_allowed(url, false, "hotfix"));
    for needle in [
        "--allow-private-branches",
        "hotfix",
        "branch name, recipient ids and sizes",
        "readable by everyone who can read the Git repository",
        "after any later revoke",
        "Nothing was uploaded",
        "sc remote set <name> --allow-private-branches",
    ] {
        assert!(msg.contains(needle), "missing {needle:?}: {msg}");
    }
    // the message never shows userinfo
    let msg = invalid(check_private_push_allowed(
        "sc+git::https://u:hunter2@h/r.git",
        false,
        "hotfix",
    ));
    assert!(!msg.contains("hunter2"), "{msg}");
    assert!(check_private_push_allowed(url, true, "hotfix").is_ok());
    // Other remote kinds are unchanged.
    for other in ["sc+wal:///tmp/b", "sc+s3://b/p", "ssh://h/r", "/srv/repo"] {
        assert!(check_private_push_allowed(other, false, "hotfix").is_ok());
    }
}

/// The gate runs in `Repo::push` before any bucket I/O: the carrier here does
/// not exist, and a push that got past the gate would try to open it.
#[test]
fn push_of_a_private_branch_to_a_git_carrier_refuses_before_any_io() {
    let d = root("gate-push");
    let repo = Repo::init(&d).unwrap();
    std::fs::write(d.join("a.txt"), "a\n").unwrap();
    repo.commit("me", "base").unwrap();
    let (sk, pk) = scl_crypto::generate_keypair();
    repo.branch_private("emb", &sk, std::slice::from_ref(&pk), &[])
        .unwrap();
    repo.switch_with_identity("emb", Some(&sk)).unwrap();
    assert!(repo.head_private().unwrap().is_some());
    let url = format!("sc+git::file://{}/never-created.git", d.display());
    repo.remote_add("origin", &url).unwrap();

    let msg = invalid(repo.push("origin"));
    assert!(msg.contains("--allow-private-branches"), "{msg}");
    assert!(!d.join("never-created.git").exists());

    // The opt-in is per remote and persisted: a remote without it is still
    // gated, and the flag survives a config reload.
    repo.remote_add_opts("opted", &url, true).unwrap();
    repo.remote_add("plain", &url).unwrap();
    let cfg = crate::remote::RemoteConfig::load(repo.layout()).unwrap();
    assert!(cfg.allow_private_branches("opted"));
    assert!(!cfg.allow_private_branches("plain"));
    assert!(invalid(repo.push("plain")).contains("--allow-private-branches"));
    drop(repo);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn sc_git_urls_parse_with_the_inner_url_verbatim() {
    for inner in [
        "file:///srv/r.git",
        "git@github.com:org/repo.git",
        "https://example.com/org/repo.git",
        "ssh://git@host/org/repo.git",
        "/abs/local/repo.git",
    ] {
        let u = BucketUrl::parse(&format!("sc+git::{inner}")).unwrap();
        assert_eq!(u.scheme, BucketScheme::Git);
        assert_eq!(u.bucket, inner);
        assert_eq!(u.prefix, "");
    }
    // The backend's own validator decides what an inner URL may be.
    for inner in [
        "",
        "-oProxyCommand=x",
        "relative/path",
        "https://u:pw@h/r.git",
        "https://token@h/r.git",
    ] {
        assert!(
            BucketUrl::parse(&format!("sc+git::{inner}")).is_err(),
            "{inner}"
        );
    }
}
