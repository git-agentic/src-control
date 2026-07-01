//! End-to-end: sc <-> local git repo fetch/push round-trip.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("sc runs")
}
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e")
        .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e")
        .output()
        .expect("git runs")
}
fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-gitremote-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn fetch_from_git_imports_history_into_tracking_ref() {
    let root = tmp("fetch");
    let gitrepo = root.join("upstream"); // a normal (non-bare) git repo with content
    std::fs::create_dir_all(&gitrepo).unwrap();
    git(&gitrepo, &["init", "-q", "-b", "main"]);
    std::fs::write(gitrepo.join("hello.txt"), b"world").unwrap();
    git(&gitrepo, &["add", "."]);
    git(&gitrepo, &["commit", "-q", "-m", "from-git"]);

    let screpo = root.join("work");
    std::fs::create_dir_all(&screpo).unwrap();
    assert!(sc(&screpo, &["init"]).status.success());
    assert!(sc(&screpo, &["remote", "add", "hub", gitrepo.to_str().unwrap(), "--git"]).status.success());

    let out = sc(&screpo, &["fetch", "hub"]);
    assert!(out.status.success(), "fetch failed: {}", String::from_utf8_lossy(&out.stderr));

    // Integrate via existing merge, then the content is present.
    let m = sc(&screpo, &["merge", "hub/main"]);
    assert!(m.status.success(), "merge failed: {}", String::from_utf8_lossy(&m.stderr));
    assert_eq!(std::fs::read(screpo.join("hello.txt")).unwrap(), b"world");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn gc_after_git_fetch_retains_fetched_snapshots() {
    let root = tmp("gcsafe");
    let gitrepo = root.join("upstream");
    std::fs::create_dir_all(&gitrepo).unwrap();
    git(&gitrepo, &["init", "-q", "-b", "main"]);
    std::fs::write(gitrepo.join("keep.txt"), b"data").unwrap();
    git(&gitrepo, &["add", "."]);
    git(&gitrepo, &["commit", "-q", "-m", "keepme"]);

    let screpo = root.join("work");
    std::fs::create_dir_all(&screpo).unwrap();
    sc(&screpo, &["init"]);
    sc(&screpo, &["remote", "add", "hub", gitrepo.to_str().unwrap(), "--git"]);
    sc(&screpo, &["fetch", "hub"]);

    // gc with no local merge: the remote-tracking ref must keep the snapshot alive.
    let g = sc(&screpo, &["gc", "--prune-expire", "0s"]);
    assert!(g.status.success(), "gc failed: {}", String::from_utf8_lossy(&g.stderr));
    // Merge still works => the fetched objects survived gc.
    let m = sc(&screpo, &["merge", "hub/main"]);
    assert!(m.status.success(), "merge after gc failed: {}", String::from_utf8_lossy(&m.stderr));
    assert_eq!(std::fs::read(screpo.join("keep.txt")).unwrap(), b"data");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn push_to_git_roundtrips_and_reuses_marks() {
    let root = tmp("push");
    // Author sc history.
    let screpo = root.join("work");
    std::fs::create_dir_all(&screpo).unwrap();
    sc(&screpo, &["init"]);
    std::fs::write(screpo.join("f.txt"), b"v1").unwrap();
    assert!(sc(&screpo, &["commit", "-m", "c1"]).status.success());
    std::fs::write(screpo.join("f.txt"), b"v2").unwrap();
    assert!(sc(&screpo, &["commit", "-m", "c2"]).status.success());

    // A bare git target.
    let bare = root.join("target.git");
    git(&root, &["init", "-q", "--bare", bare.to_str().unwrap()]);

    sc(&screpo, &["remote", "add", "hub", bare.to_str().unwrap(), "--git"]);
    let p = sc(&screpo, &["push", "hub"]);
    assert!(p.status.success(), "push failed: {}", String::from_utf8_lossy(&p.stderr));

    // git log reads back two commits with our messages.
    let log = git(&bare, &["log", "--format=%s", "main"]);
    let subjects = String::from_utf8_lossy(&log.stdout);
    assert!(subjects.contains("c2") && subjects.contains("c1"), "git log: {subjects}");

    // A second push with no new commits is a clean no-op (marks => already there).
    let p2 = sc(&screpo, &["push", "hub"]);
    assert!(p2.status.success());

    // A fresh sc repo can fetch the pushed history back and get identical tip id.
    let screpo2 = root.join("clone");
    std::fs::create_dir_all(&screpo2).unwrap();
    sc(&screpo2, &["init"]);
    sc(&screpo2, &["remote", "add", "hub", bare.to_str().unwrap(), "--git"]);
    assert!(sc(&screpo2, &["fetch", "hub"]).status.success());
    assert!(sc(&screpo2, &["merge", "hub/main"]).status.success());
    assert_eq!(std::fs::read(screpo2.join("f.txt")).unwrap(), b"v2");

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn push_refuses_encrypted_content_without_flag() {
    let root = tmp("pushenc");
    let screpo = root.join("work");
    std::fs::create_dir_all(&screpo).unwrap();
    // Identity file lives OUTSIDE the work tree so the P5 secret scanner never
    // sees the `scl-sk-` private key during commit.
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let id = keys.join("id");

    sc(&screpo, &["init"]);

    // Generate an identity; grab its public key (line: "public key:   scl-pk-…").
    let kg = sc(&screpo, &["keygen", "--out", id.to_str().unwrap()]);
    assert!(kg.status.success(), "keygen failed: {}", String::from_utf8_lossy(&kg.stderr));
    let kg_out = String::from_utf8_lossy(&kg.stdout);
    let pubkey = kg_out
        .lines()
        .find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("keygen prints a public key")
        .to_string();

    // Recipients file lives inside .sc/ (not scanned); the pubkey there is safe.
    std::fs::write(
        screpo.join(".sc/recipients.toml"),
        format!("[recipients]\nme = \"{pubkey}\"\n"),
    )
    .unwrap();

    // Protect a prefix BEFORE committing so the tip snapshot carries an
    // encrypted blob for the confidentiality gate to fire on.
    let pr = Command::new(env!("CARGO_BIN_EXE_sc"))
        .args(["protect", "secret/", "--to", "me"])
        .current_dir(&screpo)
        .env("SC_IDENTITY", id.to_str().unwrap())
        .output()
        .expect("sc runs");
    assert!(pr.status.success(), "protect failed: {}", String::from_utf8_lossy(&pr.stderr));

    std::fs::create_dir_all(screpo.join("secret")).unwrap();
    std::fs::write(screpo.join("secret/creds.txt"), b"top-secret-value").unwrap();
    let c = sc(&screpo, &["commit", "-m", "add protected file"]);
    assert!(c.status.success(), "commit failed: {}", String::from_utf8_lossy(&c.stderr));

    // A bare git target + git remote.
    let bare = root.join("target.git");
    git(&root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    sc(&screpo, &["remote", "add", "hub", bare.to_str().unwrap(), "--git"]);

    // Push without the flag MUST refuse (fail-closed confidentiality gate).
    let refused = sc(&screpo, &["push", "hub"]);
    assert!(!refused.status.success(), "push should refuse encrypted content without --include-encrypted");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("refus"), "expected a refusal on stderr, got: {stderr}");

    // Push WITH the flag MUST succeed (protected files export as ciphertext).
    let allowed = sc(&screpo, &["push", "hub", "--include-encrypted"]);
    assert!(allowed.status.success(), "push --include-encrypted failed: {}", String::from_utf8_lossy(&allowed.stderr));

    std::fs::remove_dir_all(&root).unwrap();
}

// Exercises the ff-gate "remote maps to an ancestor of the local tip" branch:
// after an initial push creates the ref, a fresh local commit pushes as a clean
// fast-forward (the remote's mapped sc id is a strict ancestor of the new tip).
#[test]
fn push_fast_forwards_after_new_commit() {
    let root = tmp("pushff");
    let screpo = root.join("work");
    std::fs::create_dir_all(&screpo).unwrap();
    sc(&screpo, &["init"]);
    std::fs::write(screpo.join("f.txt"), b"v1").unwrap();
    assert!(sc(&screpo, &["commit", "-m", "c1"]).status.success());

    let bare = root.join("target.git");
    git(&root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    sc(&screpo, &["remote", "add", "hub", bare.to_str().unwrap(), "--git"]);

    // First push: absent ref -> creates refs/heads/main at c1.
    assert!(sc(&screpo, &["push", "hub"]).status.success());

    // A new local commit; second push must fast-forward (remote=c1 is an
    // ancestor of the new tip c2), not refuse.
    std::fs::write(screpo.join("f.txt"), b"v2").unwrap();
    assert!(sc(&screpo, &["commit", "-m", "c2"]).status.success());
    let p = sc(&screpo, &["push", "hub"]);
    assert!(p.status.success(), "fast-forward push failed: {}", String::from_utf8_lossy(&p.stderr));

    let log = git(&bare, &["log", "--format=%s", "main"]);
    let subjects = String::from_utf8_lossy(&log.stdout);
    assert!(subjects.contains("c2") && subjects.contains("c1"), "git log: {subjects}");

    std::fs::remove_dir_all(&root).unwrap();
}

// Exercises the ff-gate "remote points at a commit sc has never seen" branch:
// a second, independent sc repo with no marks for the remote tries to push over
// an existing remote ref. It cannot map the remote oid, so it must refuse and
// tell the user to fetch first, rather than clobber the remote history.
#[test]
fn push_refuses_when_remote_has_unseen_commit() {
    let root = tmp("pushunseen");
    let bare = root.join("target.git");
    git(&root, &["init", "-q", "--bare", bare.to_str().unwrap()]);

    // Repo A publishes history to the bare remote.
    let repo_a = root.join("a");
    std::fs::create_dir_all(&repo_a).unwrap();
    sc(&repo_a, &["init"]);
    std::fs::write(repo_a.join("f.txt"), b"from-a").unwrap();
    assert!(sc(&repo_a, &["commit", "-m", "a1"]).status.success());
    sc(&repo_a, &["remote", "add", "hub", bare.to_str().unwrap(), "--git"]);
    assert!(sc(&repo_a, &["push", "hub"]).status.success());

    // Repo B has its own, disjoint history and no marks for the remote.
    let repo_b = root.join("b");
    std::fs::create_dir_all(&repo_b).unwrap();
    sc(&repo_b, &["init"]);
    std::fs::write(repo_b.join("g.txt"), b"from-b").unwrap();
    assert!(sc(&repo_b, &["commit", "-m", "b1"]).status.success());
    sc(&repo_b, &["remote", "add", "hub", bare.to_str().unwrap(), "--git"]);

    // The remote ref maps to a commit B has never seen -> refuse (fetch first).
    let p = sc(&repo_b, &["push", "hub"]);
    assert!(!p.status.success(), "push should refuse when remote has an unseen commit");
    let stderr = String::from_utf8_lossy(&p.stderr);
    assert!(
        stderr.contains("non-fast-forward") && stderr.contains("fetch first"),
        "expected a fetch-first refusal, got: {stderr}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}
