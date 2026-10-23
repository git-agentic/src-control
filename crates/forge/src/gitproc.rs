//! The one place a `git` child process is spawned. Every spawn gets an environment built from
//! scratch (nothing inherited), an explicit `--git-dir` (never repository discovery), per-spawn
//! configuration through `GIT_CONFIG_COUNT`, its own process group, a wall-clock deadline that
//! kills the whole group, capped output drained by dedicated threads, and an admission slot
//! acquired with a deadline so a busy server answers 503 instead of queueing.
//!
//! Inputs are the caller's responsibility to validate (branch names through `refname`, identity
//! through [`Identity::new`]); this module never builds a revision from client text.

use crate::limits::Gate;
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
    #[error("could not run git: {0}")]
    Spawn(#[from] std::io::Error),
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
}

impl Identity {
    /// `None` when either value could not be a safe identity.
    pub fn new(name: &str, email: &str) -> Option<Identity> {
        let safe =
            |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_control() || matches!(c, '<' | '>'));
        (safe(name) && safe(email)).then(|| Identity {
            name: name.into(),
            email: email.into(),
        })
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
        Ok(Git {
            data_dir: data_dir.to_path_buf(),
            bin,
            gate: Gate::new(concurrency),
            timeout: Duration::from_secs(30),
            admission: Duration::from_secs(5),
            max_output: 16 << 20,
        })
    }

    pub fn with_limits(mut self, timeout: Duration, admission: Duration, max_output: usize) -> Git {
        self.timeout = timeout;
        self.admission = admission;
        self.max_output = max_output;
        self
    }

    /// The environment of every spawn: built from scratch, nothing inherited.
    pub fn env(&self, identity: Option<&Identity>) -> Vec<(String, String)> {
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
        let config = [
            ("core.hooksPath", format!("{d}/hooks")),
            ("core.fsync", "all".to_string()),
            ("core.fsyncMethod", "fsync".to_string()),
            ("core.useReplaceRefs", "false".to_string()),
            ("gc.auto", "0".to_string()),
            ("receive.fsckObjects", "true".to_string()),
        ];
        env.push(("GIT_CONFIG_COUNT".into(), config.len().to_string()));
        for (i, (k, v)) in config.into_iter().enumerate() {
            env.push((format!("GIT_CONFIG_KEY_{i}"), k.into()));
            env.push((format!("GIT_CONFIG_VALUE_{i}"), v));
        }
        if let Some(id) = identity {
            for who in ["AUTHOR", "COMMITTER"] {
                env.push((format!("GIT_{who}_NAME"), id.name.clone()));
                env.push((format!("GIT_{who}_EMAIL"), id.email.clone()));
            }
        }
        env
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
        let mut cmd = Command::new(program);
        cmd.env_clear().envs(self.env(spec.identity));
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
        let t_out = drain(
            Box::new(child.stdout.take().expect("piped")),
            self.max_output,
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

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break Ok(st);
            }
            if over.load(Ordering::SeqCst) {
                kill_group();
                let _ = child.wait();
                break Err(GitError::OutputTooLarge);
            }
            if Instant::now() >= deadline {
                kill_group();
                let _ = child.wait();
                break Err(GitError::Timeout { stdout: Vec::new() });
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        // The group may outlive the leader (a hook's background child): end it on every path.
        kill_group();
        if let Some(t) = t_in {
            let _ = t.join();
        }
        let (stdout, stderr) = (
            t_out.join().unwrap_or_default(),
            t_err.join().unwrap_or_default(),
        );
        match status {
            Ok(status) if !over.load(Ordering::SeqCst) => Ok(Out {
                status,
                stdout,
                stderr,
            }),
            Ok(_) => Err(GitError::OutputTooLarge),
            Err(GitError::Timeout { .. }) => Err(GitError::Timeout { stdout }),
            Err(e) => Err(e),
        }
    }
}

/// Find `git`: `SC_FORGE_GIT` if set, else the first `git` on the server's own `PATH`.
pub fn find_git() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SC_FORGE_GIT") {
        return Some(PathBuf::from(p));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("git"))
        .find(|p| p.is_file())
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
            format!("{}/hooks", d.display()),
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
        assert_eq!(hooks.text(), format!("{}/hooks", d.display()));
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
