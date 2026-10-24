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

/// `(pid, argv joined by spaces)` of every process, from `/proc` where it exists, else `ps`.
fn processes() -> Vec<(i32, String)> {
    if Path::new("/proc/self").exists() {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                    continue;
                };
                if let Ok(raw) = std::fs::read(e.path().join("cmdline")) {
                    let cmd = raw
                        .split(|b| *b == 0)
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
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
        .args(["-axo", "pid=,command="])
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

/// Is `cmd` a git invocation (the executable's file name starts with `git`)?
fn is_git(cmd: &str) -> bool {
    let exe = cmd.split(' ').next().unwrap_or("");
    Path::new(exe)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "git" || n.starts_with("git-"))
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
/// `upload-pack`): the processes that can move a ref. Helpers that only read or write objects
/// (`index-pack`, `unpack-objects`) are not named by path and are left to finish and exit.
pub fn kill_orphan_git(data_dir: &Path, me: i32) -> (usize, usize) {
    let needle = format!("{}/repos/", data_dir.display());
    let doomed: Vec<i32> = processes()
        .into_iter()
        .filter(|(pid, cmd)| *pid != me && cmd.contains(&needle) && is_git(cmd))
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

/// The startup cleanup. `data_dir` must be the canonical data directory. Locks are removed only
/// when no matching process is left alive: a lock of a writer that could not be killed is not ours
/// to take.
pub fn sweep(data_dir: &Path) -> Swept {
    let (killed, survivors) = kill_orphan_git(data_dir, std::process::id() as i32);
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
            "/usr/bin/git --git-dir=/d/repos/1.git update-ref --stdin"
        ));
        assert!(is_git("git-receive-pack /d/repos/1.git"));
        assert!(!is_git("/bin/sleep 100 /d/repos/1.git"));
        assert!(!is_git("/usr/bin/gitk /d/repos/1.git"));
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
}
