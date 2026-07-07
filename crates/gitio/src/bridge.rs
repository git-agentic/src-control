//! System-git mirror bridge (P18, ADR-0028): the spawned `git` binary is
//! TRANSPORT ONLY — it moves bytes between a local bare mirror and the
//! network. All object translation stays in-process (import/export in this
//! crate). Auth is entirely git's (ssh-agent, credential helpers); its
//! stderr passes through so failures read like git's own.

use std::path::{Path, PathBuf};
use std::process::Command;

/// True for URL forms that need the network bridge: https/http, scp-style
/// (`git@host:path`), ssh://, and file:// (bridged too, so tests and demos
/// drive the real transport code hermetically). Everything else is a local
/// path handled by the existing P10 direct machinery.
pub fn is_network_git_url(url: &str) -> bool {
    if url.starts_with("https://")
        || url.starts_with("http://")
        || url.starts_with("ssh://")
        || url.starts_with("file://")
    {
        return true;
    }
    // scp-style: user@host:path — an '@' and a ':' before any '/'.
    match (url.find('@'), url.find(':'), url.find('/')) {
        (Some(a), Some(c), slash) if a < c && slash.map_or(true, |s| c < s) => true,
        _ => false,
    }
}

fn git_program() -> String {
    std::env::var("SC_GIT").unwrap_or_else(|_| "git".to_string())
}

/// Spawn git with stderr inherited (auth prompts/errors reach the user
/// verbatim). Non-zero exit or a missing binary become clear errors.
fn run_git(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let prog = git_program();
    let status = Command::new(&prog)
        .current_dir(dir)
        .args(args)
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "'{prog}' not found — network Git remotes require the git binary on PATH \
                 (or set SC_GIT to point at one)"
            ),
            _ => anyhow::anyhow!("spawning '{prog}': {e}"),
        })?;
    if !status.success() {
        anyhow::bail!("{prog} {} failed (exit {})", args.join(" "), status.code().unwrap_or(-1));
    }
    Ok(())
}

/// As `run_git`, but captures stdout (for rev-parse / ls-remote parsing).
fn run_git_capture(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let prog = git_program();
    let out = Command::new(&prog)
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "'{prog}' not found — network Git remotes require the git binary on PATH \
                 (or set SC_GIT to point at one)"
            ),
            _ => anyhow::anyhow!("spawning '{prog}': {e}"),
        })?;
    if !out.status.success() {
        std::io::Write::write_all(&mut std::io::stderr(), &out.stderr).ok();
        anyhow::bail!("{prog} {} failed (exit {})", args.join(" "), out.status.code().unwrap_or(-1));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Create (or open) the bare mirror for `url`, (re-)pinning its `origin`.
/// Idempotent; deleting the dir is always safe (next call recreates it).
pub fn ensure_mirror(mirror_dir: &Path, url: &str) -> anyhow::Result<PathBuf> {
    if !mirror_dir.join("HEAD").exists() {
        std::fs::create_dir_all(mirror_dir)?;
        run_git(mirror_dir, &["init", "--bare", "--quiet", "."])?;
        run_git(mirror_dir, &["remote", "add", "origin", url])?;
    } else {
        run_git(mirror_dir, &["remote", "set-url", "origin", url])?;
    }
    Ok(mirror_dir.to_path_buf())
}

/// Sync the mirror's heads from the network. The `+` refspec force-updates:
/// mirror heads are cache (a post-push mirror head that the remote later
/// rejected self-heals here), and `--prune` drops deleted branches.
pub fn mirror_fetch(mirror: &Path) -> anyhow::Result<()> {
    run_git(mirror, &["fetch", "--prune", "--quiet", "origin", "+refs/heads/*:refs/heads/*"])
}

/// Push one branch of the mirror up to the network remote. Non-ff rejections
/// come back as git's own error text.
pub fn mirror_push(mirror: &Path, branch: &str) -> anyhow::Result<()> {
    let spec = format!("refs/heads/{branch}:refs/heads/{branch}");
    run_git(mirror, &["push", "--quiet", "origin", &spec])
}

/// The remote's default branch (`HEAD` symref), e.g. "main".
pub fn remote_default_branch(mirror: &Path) -> anyhow::Result<String> {
    let out = run_git_capture(mirror, &["ls-remote", "--symref", "origin", "HEAD"])?;
    // First line: "ref: refs/heads/<name>\tHEAD"
    out.lines()
        .find_map(|l| l.strip_prefix("ref: refs/heads/"))
        .and_then(|rest| rest.split_whitespace().next())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("could not determine the remote's default branch (ls-remote --symref gave no HEAD symref)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    static GIT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-bridge-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn classifies_network_git_urls() {
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for u in [
            "https://github.com/org/repo.git",
            "http://host/repo.git",
            "git@github.com:org/repo.git",
            "ssh://git@github.com/org/repo.git",
        ] {
            assert!(is_network_git_url(u), "{u} must classify as network");
        }
        for u in ["/abs/path/repo.git", "../rel/repo.git", "repo.git", "C:repo"] {
            assert!(!is_network_git_url(u), "{u} must classify as local");
        }
        // file:// is handled by the bridge (real-git transport) so demos/tests
        // exercise the genuine code path without a network.
        assert!(is_network_git_url("file:///tmp/hub.git"));
    }

    #[test]
    fn ensure_mirror_creates_bare_repo_pinned_to_url() {
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = tmp("ensure");
        // A real local bare repo as the "network" origin, via file://.
        let hub = root.join("hub.git");
        run_git(std::path::Path::new("."), &["init", "--bare", hub.to_str().unwrap()]).unwrap();
        let url = format!("file://{}", hub.display());

        let mirror_dir = root.join("mirror.git");
        let mirror = ensure_mirror(&mirror_dir, &url).unwrap();
        assert!(mirror.join("HEAD").exists(), "must be a bare git repo");
        // Idempotent + re-pins the URL.
        let mirror2 = ensure_mirror(&mirror_dir, &url).unwrap();
        assert_eq!(mirror, mirror2);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fetch_and_push_round_trip_through_mirror() {
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = tmp("roundtrip");
        let hub = root.join("hub.git");
        run_git(std::path::Path::new("."), &["init", "--bare", hub.to_str().unwrap()]).unwrap();
        // Seed the hub with one commit via a scratch worktree.
        let seed = root.join("seed");
        run_git(std::path::Path::new("."), &["init", "-b", "main", seed.to_str().unwrap()]).unwrap();
        std::fs::write(seed.join("a.txt"), "hello").unwrap();
        run_git(&seed, &["add", "."]).unwrap();
        run_git(&seed, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "seed"]).unwrap();
        run_git(&seed, &["push", &format!("file://{}", hub.display()), "main"]).unwrap();

        let url = format!("file://{}", hub.display());
        let mirror = ensure_mirror(&root.join("mirror.git"), &url).unwrap();
        mirror_fetch(&mirror).unwrap();
        // The mirror now has the hub's head.
        let out = run_git_capture(&mirror, &["rev-parse", "refs/heads/main"]).unwrap();
        assert_eq!(out.trim().len(), 40, "mirror must have refs/heads/main");
        assert_eq!(remote_default_branch(&mirror).unwrap(), "main");

        // Write a second commit into the MIRROR's head (simulating P10 export),
        // push it up, and see it on the hub.
        let seed2 = root.join("seed2");
        run_git(std::path::Path::new("."), &["clone", mirror.to_str().unwrap(), seed2.to_str().unwrap()]).unwrap();
        std::fs::write(seed2.join("b.txt"), "world").unwrap();
        run_git(&seed2, &["add", "."]).unwrap();
        run_git(&seed2, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "two"]).unwrap();
        run_git(&seed2, &["push", "origin", "main"]).unwrap();
        mirror_push(&mirror, "main").unwrap();
        let hub_tip = run_git_capture(&hub, &["rev-parse", "refs/heads/main"]).unwrap();
        let mirror_tip = run_git_capture(&mirror, &["rev-parse", "refs/heads/main"]).unwrap();
        assert_eq!(hub_tip, mirror_tip, "push must land the mirror head on the hub");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sc_git_override_and_missing_binary_error() {
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = tmp("scgit");
        // A shim that always fails with a recognizable message.
        let shim = root.join("git-shim.sh");
        std::fs::write(&shim, "#!/bin/sh\necho 'shim: refusing' >&2\nexit 7\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

        // SAFETY-of-test: env is process-global; keep the mutation scoped and
        // restore. (Mirror the SC_SSH test idiom in crates/repo — check
        // sync.rs/wire tests for the exact pattern used there and reuse it.)
        std::env::set_var("SC_GIT", shim.to_str().unwrap());
        let err = mirror_fetch(&root).unwrap_err();
        assert!(format!("{err:#}").contains("exit"), "shim exit must surface: {err:#}");

        std::env::set_var("SC_GIT", root.join("no-such-binary").to_str().unwrap());
        let err = mirror_fetch(&root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("SC_GIT") || msg.contains("not found"), "missing binary must be a clear error: {msg}");
        std::env::remove_var("SC_GIT");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
