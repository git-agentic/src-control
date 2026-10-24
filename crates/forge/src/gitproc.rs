//! The one place a `git` child process is spawned. Every spawn gets an environment built from
//! scratch (nothing inherited), an explicit `--git-dir` (never repository discovery), per-spawn
//! configuration through `GIT_CONFIG_COUNT`, its own process group, a wall-clock deadline that
//! kills the whole group, capped output drained by dedicated threads, and an admission slot
//! acquired with a deadline so a busy server answers 503 instead of queueing.
//!
//! Inputs are the caller's responsibility to validate (branch names through `refname`, identity
//! through [`Identity::new`]); this module never builds a revision from client text.

use crate::limits::Gate;
use crate::registry::Cancel;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Oldest `git` the server supports (`merge-tree --write-tree` needs 2.38; the spec pins 2.40).
pub const MIN_GIT: (u32, u32) = (2, 40);

/// Why a git spawn failed.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// No admission slot within the deadline.
    #[error("too many git operations in flight")]
    Busy,
    /// The deadline passed; the process group was killed. Carries what was captured.
    #[error("git timed out")]
    Timeout { stdout: Vec<u8> },
    /// More output than the cap; the process group was killed.
    #[error("git produced too much output")]
    OutputTooLarge,
    /// The caller's [`Cancel`] was set; the process group was killed.
    #[error("git was cancelled")]
    Cancelled,
    #[error("could not run git: {0}")]
    Spawn(#[from] std::io::Error),
    /// git ran and failed in a way that means "something is wrong", not "not found".
    #[error("git failed: {0}")]
    Failed(String),
}

/// What a finished git run produced.
#[derive(Debug)]
pub struct Out {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Out {
    pub fn ok(&self) -> bool {
        self.status.success()
    }

    /// stdout as text, trimmed.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }
}

/// An author/committer identity for commit-producing spawns. The values reach git through
/// environment variables, so NUL, newline and angle brackets (which would forge another
/// header field) are refused.
#[derive(Clone, Debug)]
pub struct Identity {
    name: String,
    email: String,
    /// Commit time (unix seconds), when the caller needs the commit to match a response it has
    /// already built; otherwise git uses the clock.
    date: Option<i64>,
}

impl Identity {
    /// `None` when either value could not be a safe identity.
    pub fn new(name: &str, email: &str) -> Option<Identity> {
        let safe =
            |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_control() || matches!(c, '<' | '>'));
        (safe(name) && safe(email)).then(|| Identity {
            name: name.into(),
            email: email.into(),
            date: None,
        })
    }

    /// The same identity with both commit dates fixed to `secs` (UTC).
    pub fn at(mut self, secs: i64) -> Identity {
        self.date = Some(secs);
        self
    }
}

/// One git invocation.
#[derive(Default)]
pub struct Spec<'a> {
    /// The bare repository (absolute path built from the integer id), or `None` for commands
    /// that need none (`--version`, `init` takes its path as an argument).
    pub repo: Option<&'a Path>,
    pub args: &'a [&'a str],
    pub stdin: Option<&'a [u8]>,
    pub identity: Option<&'a Identity>,
    /// Larger output cap than the runner's default (archives, diffs, big listings).
    pub max_output: Option<usize>,
    /// Longer deadline than the runner's default.
    pub timeout: Option<Duration>,
    /// Extra environment for this spawn, added after the pinned one (the `pre-receive` hook passes
    /// the object directories of git's quarantine this way).
    pub extra_env: &'a [(&'a str, &'a str)],
    /// Ends the spawn (group killed, [`GitError::Cancelled`]) once set; checked before the spawn
    /// and on every poll.
    pub cancel: Option<&'a Cancel>,
}

/// The runner.
pub struct Git {
    data_dir: PathBuf,
    bin: PathBuf,
    gate: Gate,
    timeout: Duration,
    admission: Duration,
    max_output: usize,
}

impl Git {
    /// Build a runner for `data_dir` using the `git` at `bin`. Creates the empty hook directory
    /// and scratch `HOME` it points git at.
    pub fn new(data_dir: &Path, bin: PathBuf, concurrency: usize) -> std::io::Result<Git> {
        std::fs::create_dir_all(data_dir.join("hooks"))?;
        std::fs::create_dir_all(data_dir.join("tmp").join("home"))?;
        // Absolute, once: the child runs with the data directory as its working directory, so a
        // relative path would resolve against itself and target `data/data/...`.
        let data_dir = std::fs::canonicalize(data_dir)?;
        Ok(Git {
            data_dir,
            bin,
            gate: Gate::new(concurrency),
            timeout: Duration::from_secs(30),
            admission: Duration::from_secs(5),
            max_output: 16 << 20,
        })
    }

    /// The absolute data directory this runner works in.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Hold one admission slot until the returned permit is dropped. For tests that need a
    /// saturated runner (every other spawn waits out its admission deadline and gets `Busy`).
    pub fn occupy_for_tests(&self) -> crate::limits::Permit<'_> {
        self.gate.acquire()
    }

    pub fn with_limits(mut self, timeout: Duration, admission: Duration, max_output: usize) -> Git {
        self.timeout = timeout;
        self.admission = admission;
        self.max_output = max_output;
        self
    }

    /// The environment of every spawn: built from scratch, nothing inherited.
    pub fn env(&self, identity: Option<&Identity>) -> Vec<(String, String)> {
        self.env_with(identity, &[])
    }

    /// Like [`Git::env`], plus per-spawn git config entries (`key`, `value`) appended to the
    /// pinned ones (the transport adds its upload/receive settings this way).
    pub fn env_with(
        &self,
        identity: Option<&Identity>,
        extra: &[(&str, String)],
    ) -> Vec<(String, String)> {
        let d = self.data_dir.display().to_string();
        let mut env: Vec<(String, String)> = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), format!("{d}/tmp/home")),
            ("LC_ALL".into(), "C".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
            ("GIT_ATTR_NOSYSTEM".into(), "1".into()),
            ("GIT_NO_REPLACE_OBJECTS".into(), "1".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("GIT_CEILING_DIRECTORIES".into(), d.clone()),
        ];
        let mut config: Vec<(String, String)> = vec![
            ("core.hooksPath".into(), format!("{d}/hooks")),
            ("core.fsync".into(), "all".into()),
            ("core.fsyncMethod".into(), "fsync".into()),
            ("core.useReplaceRefs".into(), "false".into()),
            ("gc.auto".into(), "0".into()),
            // A maintenance `pack-refs` holds `packed-refs.lock` for a moment; a ref delete waits
            // for it (git's default is one second).
            ("core.packedRefsTimeout".into(), "5000".into()),
            ("receive.fsckObjects".into(), "true".into()),
        ];
        config.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        env.push(("GIT_CONFIG_COUNT".into(), config.len().to_string()));
        for (i, (k, v)) in config.into_iter().enumerate() {
            env.push((format!("GIT_CONFIG_KEY_{i}"), k));
            env.push((format!("GIT_CONFIG_VALUE_{i}"), v));
        }
        if let Some(id) = identity {
            for who in ["AUTHOR", "COMMITTER"] {
                env.push((format!("GIT_{who}_NAME"), id.name.clone()));
                env.push((format!("GIT_{who}_EMAIL"), id.email.clone()));
                if let Some(t) = id.date {
                    env.push((format!("GIT_{who}_DATE"), format!("{t} +0000")));
                }
            }
        }
        env
    }

    /// The git executable (absolute).
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// Run git as described by `spec`.
    pub fn run(&self, spec: &Spec) -> Result<Out, GitError> {
        self.run_program(self.bin.as_os_str(), spec)
    }

    fn run_program(&self, program: &OsStr, spec: &Spec) -> Result<Out, GitError> {
        let _slot = self
            .gate
            .acquire_timeout(self.admission)
            .ok_or(GitError::Busy)?;
        if spec.cancel.is_some_and(Cancel::is_set) {
            return Err(GitError::Cancelled);
        }
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .envs(self.env(spec.identity))
            .envs(spec.extra_env.iter().copied());
        if let Some(repo) = spec.repo {
            cmd.arg(format!("--git-dir={}", repo.display()));
        }
        cmd.args(spec.args)
            .current_dir(&self.data_dir)
            .stdin(if spec.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = cmd.spawn()?;
        let pgid = child.id() as i32;
        let kill_group = move || {
            // SAFETY: killpg only sends a signal; the child leads its own group (process_group(0)).
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
        };

        let over = Arc::new(AtomicBool::new(false));
        let drain = |mut r: Box<dyn Read + Send>, cap: usize, over: Arc<AtomicBool>| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let mut buf = [0u8; 16 * 1024];
                while let Ok(n) = r.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if out.len() + n > cap {
                        over.store(true, Ordering::SeqCst);
                        // Keep draining so a still-running child never blocks on a full pipe.
                        continue;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                out
            })
        };
        let cap = spec.max_output.unwrap_or(self.max_output);
        let t_out = drain(
            Box::new(child.stdout.take().expect("piped")),
            cap,
            over.clone(),
        );
        let t_err = drain(
            Box::new(child.stderr.take().expect("piped")),
            self.max_output,
            over.clone(),
        );
        let t_in = spec.stdin.map(|bytes| {
            let mut w = child.stdin.take().expect("piped");
            let bytes = bytes.to_vec();
            std::thread::spawn(move || {
                let _ = w.write_all(&bytes); // a child that exits early closes the pipe: not an error here
            })
        });

        // Detect the leader's exit without reaping it (`waitid` with WNOWAIT): while the leader is
        // an unreaped zombie its pid, and so the process-group id, cannot be reused, so the group
        // signal below can never reach an unrelated group. Reap only after signalling.
        let deadline = Instant::now() + spec.timeout.unwrap_or(self.timeout);
        let outcome = loop {
            match exited_unreaped(pgid) {
                Ok(true) => break None,
                Ok(false) => {}
                Err(e) => {
                    kill_group();
                    let _ = child.wait();
                    return Err(e.into());
                }
            }
            if over.load(Ordering::SeqCst) {
                break Some(GitError::OutputTooLarge);
            }
            if spec.cancel.is_some_and(Cancel::is_set) {
                break Some(GitError::Cancelled);
            }
            if Instant::now() >= deadline {
                break Some(GitError::Timeout { stdout: Vec::new() });
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        // Whatever the reason we stopped, end the whole group (a hook's background child may
        // outlive the leader) while the leader still holds the group id, then reap it.
        kill_group();
        let status = child.wait()?;
        if let Some(t) = t_in {
            let _ = t.join();
        }
        let (stdout, stderr) = (
            t_out.join().unwrap_or_default(),
            t_err.join().unwrap_or_default(),
        );
        match outcome {
            None if !over.load(Ordering::SeqCst) => Ok(Out {
                status,
                stdout,
                stderr,
            }),
            None | Some(GitError::OutputTooLarge) => Err(GitError::OutputTooLarge),
            Some(GitError::Timeout { .. }) => Err(GitError::Timeout { stdout }),
            Some(e) => Err(e),
        }
    }
}

/// Has child `pid` exited? Uses `waitid(WEXITED | WNOHANG | WNOWAIT)`, which reports exit
/// without reaping, so the pid stays reserved until the caller waits on the child.
pub(crate) fn exited_unreaped(pid: i32) -> std::io::Result<bool> {
    // SAFETY: an all-zero siginfo_t is a valid value for waitid to fill in.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-pointer; the options only observe, never reap.
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // With WNOHANG, si_pid stays 0 when no child has changed state.
    #[cfg(target_os = "linux")]
    // SAFETY: waitid filled the siginfo for a SIGCHLD-class report.
    let pid_set = unsafe { info.si_pid() } != 0;
    #[cfg(not(target_os = "linux"))]
    let pid_set = info.si_pid != 0;
    Ok(pid_set)
}

/// Resolve where `git` is: `configured` (the `SC_FORGE_GIT` value) if given, else `git` on `path`.
/// The result is always absolute: every spawn runs with the data directory as its working
/// directory, so a relative path (or a relative `PATH` entry) would be looked up there instead of
/// where the operator started the server.
pub fn resolve_git(configured: Option<&OsStr>, path: Option<&OsStr>) -> Option<PathBuf> {
    let name: &OsStr = configured.unwrap_or_else(|| OsStr::new("git"));
    if Path::new(name).components().count() > 1 {
        return std::path::absolute(name).ok().filter(|p| p.is_file());
    }
    std::env::split_paths(path?)
        .filter_map(|d| std::path::absolute(d.join(name)).ok())
        .find(|p| p.is_file())
}

/// Find `git` from the server's own environment (`SC_FORGE_GIT`, then `PATH`), as an absolute path.
pub fn find_git() -> Option<PathBuf> {
    resolve_git(
        std::env::var_os("SC_FORGE_GIT").as_deref(),
        std::env::var_os("PATH").as_deref(),
    )
}

/// `(major, minor)` from `git version 2.54.0 (Apple Git-157)`.
pub fn parse_version(text: &str) -> Option<(u32, u32)> {
    let v = text.split_whitespace().nth(2)?;
    let mut it = v.split('.');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Check the installed git is new enough; returns its version text.
pub fn check_version(git: &Git) -> Result<String, String> {
    let out = git
        .run(&Spec {
            args: &["--version"],
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    let text = out.text();
    match parse_version(&text) {
        Some(v) if v >= MIN_GIT => Ok(text),
        Some(_) => Err(format!(
            "{text}: sc-forge needs git {}.{} or newer",
            MIN_GIT.0, MIN_GIT.1
        )),
        None => Err(format!("cannot read the git version from {text:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scl-forge-git-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn git(tag: &str) -> (Git, PathBuf) {
        let d = tmp(tag);
        (
            Git::new(&d, find_git().expect("git on PATH"), 4).unwrap(),
            d,
        )
    }

    fn init(g: &Git, d: &Path) -> PathBuf {
        let repo = d.join("repos").join("1.git");
        std::fs::create_dir_all(d.join("repos")).unwrap();
        let out = g
            .run(&Spec {
                args: &[
                    "init",
                    "--bare",
                    "--quiet",
                    "--template=",
                    "--initial-branch=main",
                    repo.to_str().unwrap(),
                ],
                ..Default::default()
            })
            .unwrap();
        assert!(out.ok(), "{}", String::from_utf8_lossy(&out.stderr));
        repo
    }

    #[test]
    fn the_installed_git_is_new_enough_and_versions_parse() {
        let (g, d) = git("version");
        assert!(check_version(&g).is_ok());
        assert_eq!(
            parse_version("git version 2.54.0 (Apple Git-157)"),
            Some((2, 54))
        );
        assert_eq!(parse_version("git version 2.39.5"), Some((2, 39)));
        assert!(parse_version("nonsense").is_none());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_environment_is_built_from_scratch() {
        let (g, d) = git("env");
        let id = Identity::new("alice", "alice@example.invalid").unwrap();
        let env = g.env(Some(&id));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for must in [
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_ATTR_NOSYSTEM",
            "GIT_CEILING_DIRECTORIES",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
        ] {
            assert!(keys.contains(&must), "{must}");
        }
        let hooks = env
            .iter()
            .find(|(k, _)| k.starts_with("GIT_CONFIG_VALUE"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(
            hooks,
            format!("{}/hooks", g.data_dir().display()),
            "hooksPath is pinned to the server's directory"
        );
        assert!(
            g.env(None)
                .iter()
                .all(|(k, _)| !k.starts_with("GIT_AUTHOR")),
            "no identity unless asked"
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_relative_data_dir_becomes_absolute_and_repos_land_where_expected() {
        let rel = PathBuf::from(format!("scl-forge-rel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rel);
        let g = Git::new(&rel, find_git().expect("git"), 2).unwrap();
        assert!(g.data_dir().is_absolute());
        let repo = g.data_dir().join("repos").join("1.git");
        std::fs::create_dir_all(g.data_dir().join("repos")).unwrap();
        let out = g
            .run(&Spec {
                args: &[
                    "init",
                    "--bare",
                    "--quiet",
                    "--template=",
                    repo.to_str().unwrap(),
                ],
                ..Default::default()
            })
            .unwrap();
        assert!(out.ok());
        assert!(
            rel.join("repos").join("1.git").join("HEAD").is_file(),
            "created under the path the caller gave, not `rel/rel/...`"
        );
        assert!(!rel.join(&rel).exists());
        let _ = std::fs::remove_dir_all(&rel);
    }

    #[test]
    fn a_child_inherits_nothing_from_the_server_environment() {
        let (g, d) = git("inherit");
        std::env::set_var("SC_FORGE_TEST_SENTINEL", "leaked");
        let out = g
            .run_program(OsStr::new("/usr/bin/env"), &Spec::default())
            .unwrap();
        std::env::remove_var("SC_FORGE_TEST_SENTINEL");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            !text.contains("SC_FORGE_TEST_SENTINEL"),
            "env_clear must hide the parent environment:\n{text}"
        );
        assert!(
            text.contains("GIT_NO_REPLACE_OBJECTS=1") && text.contains("GIT_CEILING_DIRECTORIES=")
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_git_path_is_always_absolute() {
        let d = tmp("resolve-git");
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::write(d.join("bin").join("mygit"), b"#!/bin/sh\n").unwrap();
        let cwd = std::env::current_dir().unwrap();
        // a slash-containing relative value is made absolute against the current directory
        let rel = d
            .strip_prefix(&cwd)
            .map(|p| p.join("bin/mygit"))
            .unwrap_or_else(|_| d.join("bin/mygit"));
        let got = resolve_git(Some(rel.as_os_str()), None).expect("resolved");
        assert!(got.is_absolute() && got.ends_with("bin/mygit"), "{got:?}");
        // a bare name is searched on PATH, and a relative PATH entry is made absolute too
        let path = std::env::join_paths([d.join("bin")]).unwrap();
        assert!(resolve_git(Some(OsStr::new("mygit")), Some(&path))
            .unwrap()
            .is_absolute());
        let rel_dir = d
            .join("bin")
            .strip_prefix(&cwd)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| d.join("bin"));
        let rel_path = std::env::join_paths([rel_dir]).unwrap();
        assert!(resolve_git(Some(OsStr::new("mygit")), Some(&rel_path))
            .unwrap()
            .is_absolute());
        assert!(resolve_git(Some(OsStr::new("nope-not-here")), Some(&path)).is_none());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn identity_refuses_forged_header_characters() {
        assert!(Identity::new("alice", "a@example.invalid").is_some());
        for bad in [
            ("a\nb", "e@x"),
            ("a", "e@x\n"),
            ("a<", "e@x"),
            ("a", "e@x>"),
            ("a\0", "e@x"),
            ("", "e@x"),
            ("a", ""),
        ] {
            assert!(Identity::new(bad.0, bad.1).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn git_runs_against_an_explicit_dir_with_server_config_and_no_user_config() {
        let (g, d) = git("config");
        let repo = init(&g, &d);
        let hooks = g
            .run(&Spec {
                repo: Some(&repo),
                args: &["config", "--get", "core.hooksPath"],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hooks.text(), format!("{}/hooks", g.data_dir().display()));
        let user = g
            .run(&Spec {
                repo: Some(&repo),
                args: &["config", "--get", "user.name"],
                ..Default::default()
            })
            .unwrap();
        assert!(!user.ok(), "no user, global or system config is read");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_corrupt_repo_dir_never_resolves_an_enclosing_repository() {
        let (g, d) = git("discovery");
        let outer = d.join("outer");
        std::fs::create_dir_all(&outer).unwrap();
        assert!(g
            .run(&Spec {
                args: &["init", "--quiet", outer.to_str().unwrap()],
                ..Default::default()
            })
            .unwrap()
            .ok());
        let inner = outer.join("repos").join("2.git"); // a damaged repo: just an empty directory inside another repo
        std::fs::create_dir_all(&inner).unwrap();
        let out = g
            .run(&Spec {
                repo: Some(&inner),
                args: &["rev-parse", "--git-dir"],
                ..Default::default()
            })
            .unwrap();
        assert!(
            !out.ok(),
            "git must not walk up to the enclosing repository: {}",
            out.text()
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn stdin_reaches_git_and_objects_are_content_addressed() {
        let (g, d) = git("stdin");
        let repo = init(&g, &d);
        let out = g
            .run(&Spec {
                repo: Some(&repo),
                args: &["hash-object", "-w", "--no-filters", "--stdin"],
                stdin: Some(b"hello\n"),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(out.text(), "ce013625030ba8dba906f756967f9e9ca394464a");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_timeout_kills_the_whole_process_group() {
        let (g, d) = git("timeout");
        let g = g.with_limits(Duration::from_millis(400), Duration::from_secs(5), 1 << 20);
        // The shell starts a grandchild that would outlive it, prints its pid, then waits.
        let err = g
            .run_program(
                OsStr::new("/bin/sh"),
                &Spec {
                    args: &["-c", "sleep 60 & echo $!; wait"],
                    ..Default::default()
                },
            )
            .unwrap_err();
        let GitError::Timeout { stdout } = err else {
            panic!("expected a timeout, got {err:?}")
        };
        let pid: i32 = String::from_utf8_lossy(&stdout)
            .trim()
            .parse()
            .expect("grandchild pid");
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: signal 0 only probes for existence.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "the grandchild {pid} must be killed with its group");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_cancel_kills_the_group_and_a_set_one_prevents_the_spawn() {
        let (g, d) = git("cancel");
        let cancel = Cancel::default();
        let setter = cancel.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            setter.cancel();
        });
        let started = Instant::now();
        let err = g
            .run_program(
                OsStr::new("/bin/sh"),
                &Spec {
                    args: &["-c", "sleep 60 & echo $!; wait"],
                    cancel: Some(&cancel),
                    ..Default::default()
                },
            )
            .unwrap_err();
        t.join().unwrap();
        assert!(matches!(err, GitError::Cancelled), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        // Already set: nothing starts (the marker file would exist if it had).
        let marker = d.join("started");
        let again = g.run_program(
            OsStr::new("/bin/sh"),
            &Spec {
                args: &["-c", &format!("touch {}", marker.display())],
                cancel: Some(&cancel),
                ..Default::default()
            },
        );
        assert!(matches!(again, Err(GitError::Cancelled)));
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_normal_exit_still_ends_a_lingering_background_child() {
        let (g, d) = git("linger");
        // The leader exits at once, leaving a grandchild that would run for a minute.
        let out = g
            .run_program(
                OsStr::new("/bin/sh"),
                &Spec {
                    args: &["-c", "sleep 60 & echo $!"],
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(out.ok());
        let pid: i32 = out.text().parse().expect("grandchild pid");
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: signal 0 only probes for existence.
        assert!(
            unsafe { libc::kill(pid, 0) } != 0,
            "the grandchild {pid} must not outlive a run"
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn output_over_the_cap_kills_the_child() {
        let (g, d) = git("cap");
        let g = g.with_limits(Duration::from_secs(10), Duration::from_secs(5), 4096);
        let t = Instant::now();
        let err = g
            .run_program(OsStr::new("/usr/bin/yes"), &Spec::default())
            .unwrap_err();
        assert!(matches!(err, GitError::OutputTooLarge), "{err:?}");
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "killed promptly, not at the timeout"
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_busy_runner_answers_busy_after_the_admission_deadline() {
        let (g, d) = git("busy");
        let g = Git::new(&d, g.bin.clone(), 1).unwrap().with_limits(
            Duration::from_secs(10),
            Duration::from_millis(80),
            1 << 20,
        );
        let g = Arc::new(g);
        let g2 = g.clone();
        let hold = std::thread::spawn(move || {
            g2.run_program(
                OsStr::new("/bin/sleep"),
                &Spec {
                    args: &["0.6"],
                    ..Default::default()
                },
            )
        });
        std::thread::sleep(Duration::from_millis(100));
        let err = g
            .run(&Spec {
                args: &["--version"],
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, GitError::Busy), "{err:?}");
        assert!(hold.join().unwrap().is_ok());
        let _ = std::fs::remove_dir_all(d);
    }
}
