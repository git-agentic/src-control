//! Startup cleanup after a crash: git processes the dead server left behind, and the ref locks they
//! held.
//!
//! Git children run in their own process groups, so a SIGKILLed `sc-forge` leaves its `update-ref`
//! or `receive-pack` children running. Left alone they could finish a ref update after startup
//! recovery has judged a merge "not landed". The data directory is exclusively locked by the
//! server (see `lifecycle::DirLock`), so at startup every git process that names a path under this
//! data directory's `repos/` belongs to a dead predecessor; they are killed, and the `*.lock` files
//! a killed git leaves in `refs/` (nothing else holds them now) are removed, before any recovery
//! looks at the repositories. At run time nothing here runs: a live lock then belongs to a live
//! writer.

use std::path::Path;
use std::time::{Duration, Instant};

/// What the cleanup found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub killed: usize,
    pub locks: usize,
}

/// `(pid, argv and environment joined by spaces)` of every process, from `/proc` where it exists,
/// else from BSD `ps` (whose `-E` flag appends the environment of the caller's own processes). The
/// environment matters: the writer behind an HTTP push is `git receive-pack --stateless-rpc .`
/// run in the repository's directory, named by nothing on its command line, but it inherited the
/// `FORGE_DATA_DIR` the transport sets.
fn processes() -> Vec<(i32, String)> {
    if Path::new("/proc/self").exists() {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                    continue;
                };
                let join = |raw: Vec<u8>| {
                    raw.split(|b| *b == 0)
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                if let Ok(raw) = std::fs::read(e.path().join("cmdline")) {
                    let mut cmd = join(raw);
                    if let Ok(env) = std::fs::read(e.path().join("environ")) {
                        cmd.push(' ');
                        cmd.push_str(&join(env));
                    }
                    out.push((pid, cmd));
                }
            }
        }
        return out;
    }
    let ps = ["/bin/ps", "/usr/bin/ps"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    let Some(ps) = ps else {
        return Vec::new();
    };
    let Ok(o) = std::process::Command::new(ps)
        .args(["-axEww", "-o", "pid=,command="])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let (pid, cmd) = l.split_once(' ')?;
            Some((pid.parse().ok()?, cmd.trim_start().to_string()))
        })
        .collect()
}

/// Is `cmd` a git invocation: the configured git executable (`SC_FORGE_GIT` may name it anything),
/// or an executable called `git` or `git-*` (what git itself spawns, `git-receive-pack` and the like)?
fn is_git(cmd: &str, configured: Option<&Path>) -> bool {
    let exe = cmd.split(' ').next().unwrap_or("");
    if configured.is_some_and(|c| c == Path::new(exe)) {
        return true;
    }
    Path::new(exe)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "git" || n.starts_with("git-"))
}

/// Does `cmd` (arguments and environment entries joined by spaces) contain `needle` as a whole token
/// start: preceded by a space, `=` or the start, and, for an environment value (`exact_end`), followed
/// by a space or the end? Another instance's `/srv/forge-secondary` must not match `/srv/forge`, nor
/// `/mnt/srv/forge/repos/` match `/srv/forge/repos/`.
fn mentions(cmd: &str, needle: &str, exact_end: bool) -> bool {
    let mut from = 0;
    while let Some(i) = cmd[from..].find(needle) {
        let at = from + i;
        let end = at + needle.len();
        let before_ok = at == 0 || matches!(cmd.as_bytes()[at - 1], b' ' | b'=');
        let after_ok = !exact_end || end == cmd.len() || cmd.as_bytes()[end] == b' ';
        if before_ok && after_ok {
            return true;
        }
        from = at + cmd[at..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Dead but not yet reaped by its parent (a zombie holds nothing, least of all a lock).
fn is_zombie(pid: i32) -> bool {
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // `pid (comm) S ...`: the state follows the last closing parenthesis.
        return stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            == Some('Z');
    }
    ["/bin/ps", "/usr/bin/ps"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .and_then(|ps| {
            std::process::Command::new(ps)
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .ok()
        })
        .is_some_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim_start()
                .starts_with('Z')
        })
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    let exists = unsafe { libc::kill(pid, 0) == 0 };
    exists && !is_zombie(pid)
}

/// Kill git processes that work on this data directory's repositories (not ours: `me`), then wait
/// briefly for them to be gone. Returns `(killed, survivors)`. The match is on the command line
/// (`--git-dir=<data>/repos/...` for our `update-ref`s, the repository path for `receive-pack` and
/// `upload-pack`), or by the `FORGE_DATA_DIR` they inherited from the HTTP transport: the processes
/// that can move a ref. Helpers that only read or write objects
/// (`index-pack`, `unpack-objects`) are not named by path and are left to finish and exit.
pub fn kill_orphan_git(data_dir: &Path, me: i32, git_bin: Option<&Path>) -> (usize, usize) {
    let needle = format!("{}/repos/", data_dir.display());
    let env_needle = format!("FORGE_DATA_DIR={}", data_dir.display());
    let doomed: Vec<i32> = processes()
        .into_iter()
        .filter(|(pid, cmd)| {
            *pid != me
                && (mentions(cmd, &needle, false) || mentions(cmd, &env_needle, true))
                && is_git(cmd, git_bin)
        })
        .map(|(pid, _)| pid)
        .collect();
    for pid in &doomed {
        // SAFETY: SIGKILL to a process we just found by its command line.
        unsafe { libc::kill(*pid, libc::SIGKILL) };
    }
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && doomed.iter().any(|p| alive(*p)) {
        std::thread::sleep(Duration::from_millis(20));
    }
    (doomed.len(), doomed.iter().filter(|p| alive(**p)).count())
}

fn remove_locks(dir: &Path, depth: usize) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        let p = e.path();
        let Ok(t) = e.file_type() else { continue };
        if t.is_dir() && depth < 32 {
            n += remove_locks(&p, depth + 1);
        } else if t.is_file()
            && p.extension().is_some_and(|x| x == "lock")
            && std::fs::remove_file(&p).is_ok()
        {
            eprintln!(
                "sc-forge: removed the ref lock {} left by a killed git",
                p.display()
            );
            n += 1;
        }
    }
    n
}

/// Remove the leftover ref locks of every repository (`refs/**/*.lock`, `packed-refs.lock`,
/// `HEAD.lock`). Only after [`kill_orphan_git`], and only at startup.
pub fn remove_stale_locks(data_dir: &Path) -> usize {
    let mut n = 0;
    let Ok(rd) = std::fs::read_dir(data_dir.join("repos")) else {
        return 0;
    };
    for e in rd.flatten() {
        let repo = e.path();
        if !repo.is_dir() {
            continue;
        }
        n += remove_locks(&repo.join("refs"), 0);
        for f in ["packed-refs.lock", "HEAD.lock"] {
            if std::fs::remove_file(repo.join(f)).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// The startup cleanup. `data_dir` must be the canonical data directory; `git_bin` is the git
/// executable the server runs. Locks are removed only
/// when no matching process is left alive: a lock of a writer that could not be killed is not ours
/// to take.
pub fn sweep(data_dir: &Path, git_bin: Option<&Path>) -> Swept {
    let (killed, survivors) = kill_orphan_git(data_dir, std::process::id() as i32, git_bin);
    let locks = if survivors == 0 {
        remove_stale_locks(data_dir)
    } else {
        eprintln!(
            "sc-forge: {survivors} orphaned git process(es) would not die; leaving the ref locks in place"
        );
        0
    };
    if killed + locks > 0 {
        eprintln!("sc-forge: startup cleanup killed {killed} orphaned git process(es) and removed {locks} stale lock(s)");
    }
    Swept { killed, locks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_git_executables_count() {
        assert!(is_git(
            "/usr/bin/git --git-dir=/d/repos/1.git update-ref --stdin",
            None
        ));
        assert!(is_git("git-receive-pack /d/repos/1.git", None));
        assert!(!is_git("/bin/sleep 100 /d/repos/1.git", None));
        assert!(!is_git("/usr/bin/gitk /d/repos/1.git", None));
        // a differently named git, configured through SC_FORGE_GIT, counts too
        let custom = Path::new("/opt/vcs/bin/scm");
        assert!(is_git(
            "/opt/vcs/bin/scm --git-dir=/d/repos/1.git update-ref",
            Some(custom)
        ));
        assert!(!is_git(
            "/opt/vcs/bin/scm --git-dir=/d/repos/1.git update-ref",
            None
        ));
    }

    #[test]
    fn locks_under_refs_are_removed_and_nothing_else() {
        let d = std::env::temp_dir().join(format!("scl-forge-orphans-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let repo = d.join("repos").join("1.git");
        std::fs::create_dir_all(repo.join("refs/heads/feat")).unwrap();
        for f in [
            "refs/heads/main.lock",
            "refs/heads/feat/x.lock",
            "refs/heads/main",
            "packed-refs.lock",
            "config.lock",
        ] {
            std::fs::write(repo.join(f), b"").unwrap();
        }
        assert_eq!(remove_stale_locks(&d), 3);
        assert!(repo.join("refs/heads/main").exists() && repo.join("config.lock").exists());
        assert!(
            !repo.join("refs/heads/main.lock").exists() && !repo.join("packed-refs.lock").exists()
        );
        std::fs::remove_dir_all(&d).unwrap();
        assert!(!d.exists());
    }

    #[test]
    fn a_data_directory_matches_only_as_a_whole_token() {
        let env = "FORGE_DATA_DIR=/srv/forge";
        assert!(mentions(
            "git receive-pack . HOME=/h FORGE_DATA_DIR=/srv/forge PATH=/bin",
            env,
            true
        ));
        assert!(mentions("FORGE_DATA_DIR=/srv/forge", env, true));
        assert!(!mentions(
            "git x FORGE_DATA_DIR=/srv/forge-secondary PATH=/bin",
            env,
            true
        ));
        assert!(!mentions("git x XFORGE_DATA_DIR=/srv/forge", env, true));
        let repos = "/srv/forge/repos/";
        assert!(mentions(
            "git --git-dir=/srv/forge/repos/7.git update-ref",
            repos,
            false
        ));
        assert!(!mentions(
            "git --git-dir=/mnt/srv/forge/repos/7.git update-ref",
            repos,
            false
        ));
        assert!(!mentions(
            "git --git-dir=/srv/forge-secondary/repos/7.git x",
            repos,
            false
        ));
    }
}
