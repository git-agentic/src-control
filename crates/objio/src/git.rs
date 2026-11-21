//! `GitBucket`: a `Bucket` stored as `refs/sc/*` inside any Git repository
//! (the `sc+git::` carrier, P39).
//!
//! Each bucket key `K` lives at the ref `refs/sc/K`. The ref points at a
//! parentless commit whose tree holds the value as chunk blobs `c0000`,
//! `c0001`, ... of at most [`CHUNK`] bytes each; the commit id is the tag.
//! Atomicity comes from `receive-pack` checking the sent old-oid under its ref
//! lock: create-only writes push with an empty lease, CAS writes with the
//! expected oid as the lease, and no `+` refspec is ever used (a `+` makes
//! `--force-with-lease` ineffective).
//!
//! Git is driven through the system `git` binary (`SC_GIT` overrides it), never
//! through `gix`, which stays quarantined in `gitio`. A per-instance temporary
//! bare repository caches fetched objects and is removed on `Drop`; a SIGKILL
//! or a SIGINT (the CLI installs no signal handler, so Ctrl-C skips `Drop`)
//! can leave `sc-git-bucket-<pid>-<random>` behind in the temp directory.
//!
//! Every rejected write is classified by re-reading the exact ref with
//! `ls-remote`, never by the host's wording, so a hook refusal can never look
//! like a lost race.

use crate::{validate_key, Bucket, Error, Fetched, ObjectMeta, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

/// Largest chunk blob a value is split into (GitHub's hard per-blob limit is
/// 100 MB); also the largest chunk accepted on read.
const CHUNK: usize = 32 << 20;
/// Largest value written or read: GitHub's per-push cap and sc-forge's
/// `receive.maxInputSize`. Values are buffered in RAM like on S3.
const MAX_VALUE: u64 = 2 << 30;
/// Cap for every value that is not a `.pack` (manifest, log entries,
/// checkpoints, `.idx`): they are small by construction, so a hostile host
/// cannot make a reader buffer gigabytes of one.
const MAX_SMALL_VALUE: u64 = 256 << 20;
/// Most chunk entries a value tree may hold (names are `c0000`..`c9999`).
const MAX_CHUNKS: usize = 10_000;
/// How long a tag this instance itself observed or wrote is trusted for a
/// conditional read before the network is asked again.
const FRESH: Duration = Duration::from_secs(2);
/// Cap on captured `ls-remote` output (a hostile host cannot fill RAM).
const LS_REMOTE_CAP: usize = 64 << 20;
/// Cap on captured output of every other small git call.
const SMALL_CAP: usize = 1 << 20;
/// Namespace prefix of every bucket ref.
const NS: &str = "refs/sc/";
/// Refspecs per `fetch` call in `list_meta` (keeps the command line short).
const FETCH_BATCH: usize = 256;

/// `-c` overrides on every git call: transport allowlist, no hooks, no signing,
/// no background maintenance, bounded stalls.
const GIT_CONFIG: &[&str] = &[
    "protocol.allow=never",
    "protocol.file.allow=always",
    "protocol.ssh.allow=always",
    "protocol.https.allow=always",
    "protocol.http.allow=always",
    // A user config must not re-enable helper transports a hostile URL could abuse.
    "protocol.ext.allow=never",
    "protocol.fd.allow=never",
    "protocol.git.allow=never",
    "fetch.fsckObjects=true",
    "core.hooksPath=/dev/null",
    "gc.auto=0",
    "maintenance.auto=false",
    "push.gpgSign=false",
    "commit.gpgSign=false",
    "tag.gpgSign=false",
    "core.useReplaceRefs=false",
    "http.lowSpeedLimit=1000",
    "http.lowSpeedTime=60",
];

/// `GIT_*` variables that survive into child git processes: the user's
/// transport and credential setup. Everything else (`GIT_DIR` family, config
/// injection, traces) is removed so the process environment cannot redirect
/// the cache repository or change config.
const KEEP_GIT_ENV: &[&str] = &[
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_ASKPASS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_EXEC_PATH",
    "GIT_PROXY_COMMAND",
    "GIT_SSL_NO_VERIFY",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "GIT_SSL_CERT",
    "GIT_SSL_KEY",
    "GIT_SSL_VERSION",
];

/// Fixed carrier identity so a clean account with no `user.name` can write.
const IDENTITY_ENV: &[(&str, &str)] = &[
    ("GIT_AUTHOR_NAME", "sc"),
    ("GIT_AUTHOR_EMAIL", "sc@invalid"),
    ("GIT_COMMITTER_NAME", "sc"),
    ("GIT_COMMITTER_EMAIL", "sc@invalid"),
];

fn keep_env(name: &str) -> bool {
    // Windows environment names are case-insensitive: `git_dir` is `GIT_DIR`.
    #[cfg(windows)]
    let upper = name.to_ascii_uppercase();
    #[cfg(windows)]
    let name = upper.as_str();
    !name.starts_with("GIT_") || KEEP_GIT_ENV.contains(&name)
}

/// A key family GitBucket knows the WAL layout of: the first cache miss in one
/// fetches the whole family in a single `git fetch` instead of one round trip
/// per entry.
struct Family {
    dir: &'static str,
    suffix: &'static str,
}

const FAMILIES: [Family; 3] = [
    Family {
        dir: "log/",
        suffix: "",
    },
    Family {
        dir: "checkpoints/",
        suffix: "",
    },
    Family {
        dir: "packs/",
        suffix: ".idx",
    },
];

impl Family {
    fn matches(&self, key: &str) -> bool {
        key.len() > self.dir.len() + self.suffix.len()
            && key.starts_with(self.dir)
            && key.ends_with(self.suffix)
    }
    fn glob(&self) -> String {
        format!("{NS}{}*{}", self.dir, self.suffix)
    }
}

fn family_of(key: &str) -> Option<&'static Family> {
    FAMILIES.iter().find(|f| f.matches(key))
}

/// Keys whose value is write-once by the WAL layout: log entries, checkpoints
/// and pack files. Decided by the key alone, never by anything a remote
/// writer controls (a commit message), so a hostile or buggy writer cannot
/// make a mutable key look immutable.
fn create_only_key(key: &str) -> bool {
    key.starts_with("log/")
        || key.starts_with("checkpoints/")
        || (key.starts_with("packs/") && (key.ends_with(".pack") || key.ends_with(".idx")))
}

/// What this instance knows about a key's current remote value.
struct Known {
    oid: String,
    /// [`create_only_key`]: the value never changes, so reads are served from
    /// the local cache with no network call.
    create_only: bool,
    /// When the oid was last observed or written by this instance.
    at: Instant,
}

/// Captured result of one git invocation.
struct Out {
    success: bool,
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

/// Outcome of a push of one ref.
enum Pushed {
    Done,
    /// The host refused or the push failed; carries the captured message.
    Refused(String),
}

/// A bucket stored as `refs/sc/*` in a Git repository reachable at `url`.
/// Intent: let a plain Git host carry a native sc store (P39) without a new
/// server. See the module docs for the value encoding and write protocol.
pub struct GitBucket {
    url: String,
    git: String,
    cache: PathBuf,
    /// Chunk size used for writes (tests shrink it).
    chunk: usize,
    state: Mutex<HashMap<String, Known>>,
}

fn is_oid(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A usable CAS tag: a nonzero full hex oid of the cache's (SHA-1) format.
fn is_tag(s: &str) -> bool {
    is_oid(s) && s.bytes().any(|b| b != b'0')
}

/// Strict ref-safe key check on top of the shared `validate_key`: git ref
/// format rules, so a key can never smuggle ref syntax into a refspec.
fn check_key(key: &str) -> Result<()> {
    validate_key(key)?;
    if key.len() > 1024
        || key.contains("..")
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        || key
            .split('/')
            .any(|c| c.starts_with('.') || c.ends_with('.') || c.ends_with(".lock"))
    {
        return Err(Error::BadKey(format!("{key:?}")));
    }
    Ok(())
}

/// Prefix check for `list`/`list_meta`: the key charset, so no glob character
/// reaches an `ls-remote` pattern. Empty is allowed.
fn check_prefix(prefix: &str) -> Result<()> {
    if prefix.len() > 1024
        || prefix.starts_with('/')
        || prefix.contains("..")
        || prefix.contains("//")
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
    {
        return Err(Error::BadKey(format!("{prefix:?}")));
    }
    Ok(())
}

/// Replace URL userinfo (`user@`) with `***@` in text that is printed, for a
/// bare Git URL or one under the `sc+git::` prefix, `scheme://` and scp forms
/// alike. Any message that shows a remote URL goes through this.
pub fn redact(s: &str) -> String {
    let (lead, inner) = match s.get(..8) {
        Some(p) if p.eq_ignore_ascii_case("sc+git::") => s.split_at(8),
        _ => ("", s),
    };
    if let Some((scheme, rest)) = inner.split_once("://") {
        let end = rest.find('/').unwrap_or(rest.len());
        if let Some((_, host)) = rest[..end].rsplit_once('@') {
            return format!("{lead}{scheme}://***@{host}{}", &rest[end..]);
        }
    } else if let Some((left, path)) = inner.split_once(':') {
        if let Some((_, host)) = left.rsplit_once('@') {
            if !left.contains('/') {
                return format!("{lead}***@{host}:{path}");
            }
        }
    }
    s.to_string()
}

/// The size cap of `key`'s value: pack files may be large, everything else small.
fn value_cap(key: &str) -> u64 {
    if key.ends_with(".pack") {
        MAX_VALUE
    } else {
        MAX_SMALL_VALUE
    }
}

/// Refuse a value over the per-key cap before building or reading anything.
fn check_len(key: &str, len: u64) -> Result<()> {
    let cap = value_cap(key);
    if len > cap {
        return Err(Error::Backend(format!(
            "value of {len} bytes for {key:?} exceeds the {cap}-byte git bucket cap"
        )));
    }
    Ok(())
}

/// How a refused write turned out, judged by re-reading the exact ref.
#[derive(Debug, PartialEq, Eq)]
enum Settled {
    /// The remote holds our new commit: the push landed and only its
    /// acknowledgement was lost.
    Landed,
    /// Someone else's value (or a deletion) beat the lease.
    Lost,
    /// The ref still holds what the lease expected (or a create found
    /// nothing): the host refused for its own reasons (hook, permissions).
    Genuine,
}

/// Classify a refused push of `ours` under `lease` (`""` = create-only) from
/// the ref's current remote value.
fn classify_refusal(ours: &str, lease: &str, remote: Option<&str>) -> Settled {
    match remote {
        Some(cur) if cur == ours => Settled::Landed,
        Some(cur) if cur != lease => Settled::Lost,
        None if !lease.is_empty() => Settled::Lost,
        _ => Settled::Genuine,
    }
}

/// Result of [`GitBucket::put`].
enum Written {
    Landed(String),
    Lost,
    Failed(Error),
}

fn corrupt(why: impl std::fmt::Display) -> Error {
    Error::Backend(format!("corrupt git bucket value: {why}"))
}

/// A host (optionally `:port`, or a bracketed IPv6 literal) that cannot be read
/// as an option or smuggle URL/shell syntax.
fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'))
}

impl GitBucket {
    /// Validate an inner Git URL (the part after `sc+git::`) without touching
    /// the network. Accepts `https://`, `http://`, `ssh://`, `file:///abs`,
    /// scp-form `user@host:path` and absolute local paths; refuses everything
    /// else (leading `-`, control characters, `::` transport helpers, `git://`,
    /// relative paths, a password in the URL, and any userinfo at all on
    /// `http(s)://`: credentials go through git's credential helper, never into
    /// a URL that is stored in `.sc/config` and echoed).
    pub fn validate_url(url: &str) -> Result<()> {
        let bad = |why: &str| {
            Err(Error::Backend(format!(
                "unsupported git url ({why}): {:?}",
                redact(url)
            )))
        };
        if url.is_empty() || url.len() > 4096 {
            return bad("empty or too long");
        }
        if url.starts_with('-') {
            return bad("starts with '-'");
        }
        if url.chars().any(|c| c.is_control()) {
            return bad("control character");
        }
        if url.contains("::") {
            return bad("'::' transport helper");
        }
        if let Some((scheme, rest)) = url.split_once("://") {
            match scheme {
                "file" => {
                    if !rest.starts_with('/') {
                        return bad("file:// needs an absolute path (file:///...)");
                    }
                }
                "https" | "http" | "ssh" => {
                    let end = rest.find('/').unwrap_or(rest.len());
                    let (authority, path) = rest.split_at(end);
                    if path.len() < 2 {
                        return bad("missing repository path");
                    }
                    let host = match authority.rsplit_once('@') {
                        Some((userinfo, host)) => {
                            if scheme != "ssh" {
                                return bad("credentials in url; use a credential helper");
                            }
                            if userinfo.contains(':') {
                                return bad("password in url; use a credential helper");
                            }
                            if userinfo.starts_with('-') {
                                return bad("user starts with '-'");
                            }
                            host
                        }
                        None => authority,
                    };
                    if !host_ok(host) {
                        return bad("bad host");
                    }
                }
                _ => return bad("scheme not allowed"),
            }
            return Ok(());
        }
        if std::path::Path::new(url).is_absolute() {
            return Ok(());
        }
        // scp form: user@host:path
        if let Some((left, path)) = url.split_once(':') {
            if let Some((user, host)) = left.split_once('@') {
                let user_ok = !user.is_empty()
                    && !user.starts_with('-')
                    && user
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
                if user_ok && host_ok(host) && !left.contains('/') && !path.is_empty() {
                    return Ok(());
                }
            }
        }
        bad("relative path or unrecognized form")
    }

    /// Open a bucket stored as `refs/sc/*` in the Git repository at `url`
    /// (validates first). Spawns `$SC_GIT` (default `git`). Creates a private
    /// temporary cache repository (local only); no network call happens until
    /// the first method call.
    pub fn open(url: &str) -> Result<GitBucket> {
        let git = std::env::var("SC_GIT").unwrap_or_else(|_| "git".to_string());
        Self::open_with(url, git, CHUNK)
    }

    fn open_with(url: &str, git: String, chunk: usize) -> Result<GitBucket> {
        Self::validate_url(url)?;
        let b = GitBucket {
            url: url.to_string(),
            git,
            cache: new_cache_dir()?,
            chunk: chunk.max(1),
            state: Mutex::new(HashMap::new()),
        };
        // An early `?` drops `b`, which removes the cache dir.
        b.run_ok(
            &["init", "--bare", "--quiet", "--template=", "."],
            None,
            &[],
            SMALL_CAP,
        )?;
        Ok(b)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Known>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Run git in the cache repository with the hardened environment.
    fn run(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        env: &[(&str, &str)],
        max_out: usize,
    ) -> Result<Out> {
        let mut cmd = Command::new(&self.git);
        for c in GIT_CONFIG {
            cmd.arg("-c").arg(c);
        }
        cmd.args(args).current_dir(&self.cache);
        for (k, _) in std::env::vars_os() {
            if !keep_env(&k.to_string_lossy()) {
                cmd.env_remove(&k);
            }
        }
        cmd.env("GIT_DIR", &self.cache)
            .env("LC_ALL", "C")
            .env("GIT_TERMINAL_PROMPT", "0");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| {
            Error::Backend(format!(
                "cannot run git ({}): {e} (install git or set SC_GIT)",
                self.git
            ))
        })?;
        let sin = child.stdin.take();
        let mut sout = child.stdout.take().expect("piped");
        let mut serr = child.stderr.take().expect("piped");
        let (stdout, stderr, over) = std::thread::scope(|s| {
            if let (Some(mut w), Some(data)) = (sin, stdin) {
                // A write error means the child already exited; its status says why.
                s.spawn(move || {
                    let _ = w.write_all(data);
                });
            }
            let eh = s.spawn(move || {
                let mut buf = Vec::new();
                let _ = (&mut serr).take(SMALL_CAP as u64).read_to_end(&mut buf);
                let _ = std::io::copy(&mut serr, &mut std::io::sink());
                buf
            });
            let mut out = Vec::new();
            let _ = (&mut sout).take(max_out as u64 + 1).read_to_end(&mut out);
            let over = out.len() > max_out;
            if over {
                let _ = child.kill();
            }
            (out, eh.join().unwrap_or_default(), over)
        });
        let status = child.wait()?;
        if over {
            return Err(Error::Backend(format!(
                "git output exceeded {max_out} bytes (hostile or corrupt remote)"
            )));
        }
        Ok(Out {
            success: status.success(),
            code: status.code(),
            stdout,
            stderr: self.scrub(&String::from_utf8_lossy(&stderr)),
        })
    }

    fn run_ok(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        env: &[(&str, &str)],
        max_out: usize,
    ) -> Result<Out> {
        let out = self.run(args, stdin, env, max_out)?;
        if out.success {
            Ok(out)
        } else {
            Err(self.fail(args.first().copied().unwrap_or("git"), &out))
        }
    }

    /// Error text safe to print: URL userinfo redacted, control bytes (ESC
    /// from a hostile hook message) dropped, length bounded.
    fn scrub(&self, text: &str) -> String {
        let t = text.replace(&self.url, &redact(&self.url));
        t.chars()
            .filter(|c| !c.is_control() || *c == '\n')
            .take(4096)
            .collect::<String>()
            .trim()
            .to_string()
    }

    fn fail(&self, what: &str, out: &Out) -> Error {
        Error::Backend(format!(
            "git {what} failed (exit {}): {}",
            out.code.map_or("signal".to_string(), |c| c.to_string()),
            out.stderr
        ))
    }

    fn out_oid(out: &Out) -> Result<String> {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if is_oid(&s) {
            Ok(s)
        } else {
            Err(Error::Backend(format!(
                "git returned a bad object id: {s:?}"
            )))
        }
    }

    /// `ls-remote` lines `(oid, refname)` for `pattern`. Patterns tail-match, so
    /// callers must compare full refnames themselves.
    fn ls_remote(&self, pattern: &str) -> Result<Vec<(String, String)>> {
        let out = self.run(
            &[
                "ls-remote",
                "--refs",
                "--end-of-options",
                &self.url,
                pattern,
            ],
            None,
            &[],
            LS_REMOTE_CAP,
        )?;
        if !out.success {
            return Err(self.fail("ls-remote", &out));
        }
        let mut v = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            match line.split_once('\t') {
                Some((oid, name)) if is_oid(oid) => v.push((oid.to_string(), name.to_string())),
                _ => return Err(Error::Backend(format!("bad ls-remote line: {line:?}"))),
            }
        }
        Ok(v)
    }

    /// The remote oid of exactly `refs/sc/<key>`.
    fn remote_ref(&self, key: &str) -> Result<Option<String>> {
        let full = format!("{NS}{key}");
        Ok(self
            .ls_remote(&full)?
            .into_iter()
            .find(|(_, name)| *name == full)
            .map(|(oid, _)| oid))
    }

    /// Remote `(key, oid)` pairs whose key starts with the raw `prefix`, sorted.
    fn remote_list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let mut v: Vec<(String, String)> = self
            .ls_remote(&format!("{NS}{prefix}*"))?
            .into_iter()
            .filter_map(|(oid, name)| {
                let key = name.strip_prefix(NS)?.to_string();
                (key.starts_with(prefix) && check_key(&key).is_ok()).then_some((key, oid))
            })
            .collect();
        v.sort();
        Ok(v)
    }

    /// Fetch `refspecs`, always shallow so a hostile commit's parents are never
    /// downloaded. `family` = a glob fetch of a whole key family, which also
    /// prunes stale local refs. A shallow glob fetch that matches no ref exits 1
    /// with no error text; [`Self::get_family`] tells that apart by listing.
    fn fetch(&self, refspecs: &[String], family: bool) -> Result<Out> {
        let mut a = vec![
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
        ];
        a.push("--depth=1");
        if family {
            a.push("--prune");
        }
        a.extend(["--end-of-options", &self.url]);
        a.extend(refspecs.iter().map(String::as_str));
        self.run(&a, None, &[], SMALL_CAP)
    }

    /// Push `oid` to `refs/sc/<key>` (or delete it when `oid` is `None`) under
    /// a lease: `Some("")` = must not exist, `Some(oid)` = must equal `oid`.
    /// Never a `+` refspec.
    fn push(&self, key: &str, oid: Option<&str>, lease: Option<&str>) -> Result<Pushed> {
        let full = format!("{NS}{key}");
        let refspec = format!("{}:{full}", oid.unwrap_or(""));
        let lease_arg = lease.map(|l| format!("--force-with-lease={full}:{l}"));
        let mut a = vec!["push", "--porcelain", "--no-verify"];
        if let Some(l) = &lease_arg {
            a.push(l);
        }
        a.extend(["--end-of-options", &self.url, &refspec]);
        let out = self.run(&a, None, &[], SMALL_CAP)?;
        let landed = out.success
            && (oid.is_none()
                || String::from_utf8_lossy(&out.stdout).lines().any(|line| {
                    let mut f = line.split('\t');
                    let flag = f.next().unwrap_or("");
                    let to = f.next().and_then(|r| r.rsplit_once(':')).map(|(_, t)| t);
                    to == Some(full.as_str()) && matches!(flag, " " | "+" | "*")
                }));
        if landed {
            Ok(Pushed::Done)
        } else {
            let first = out
                .stdout
                .split(|b| *b == b'\n')
                .find(|l| l.first() == Some(&b'!'))
                .map(|l| self.scrub(&String::from_utf8_lossy(l)))
                .unwrap_or_default();
            Ok(Pushed::Refused(format!(
                "git push failed (exit {}): {} {}",
                out.code.map_or("signal".to_string(), |c| c.to_string()),
                out.stderr,
                first
            )))
        }
    }

    /// Build the value commit locally: chunk blobs, tree, parentless commit
    /// with a unique nonce so a fresh write can never be "up to date".
    fn make_commit(&self, key: &str, bytes: &[u8], kind: &str) -> Result<String> {
        check_len(key, bytes.len() as u64)?;
        let mut tree = String::new();
        for (i, c) in bytes.chunks(self.chunk).enumerate() {
            let o = self.run_ok(
                &["hash-object", "-w", "--no-filters", "--stdin"],
                Some(c),
                &[],
                SMALL_CAP,
            )?;
            tree.push_str(&format!("100644 blob {}\tc{i:04}\n", Self::out_oid(&o)?));
        }
        let t = Self::out_oid(&self.run_ok(&["mktree"], Some(tree.as_bytes()), &[], SMALL_CAP)?)?;
        let msg = format!("sc-bucket {kind} {}", nonce(&self.cache));
        let c = self.run_ok(
            &["commit-tree", "--no-gpg-sign", "-m", &msg, &t],
            None,
            IDENTITY_ENV,
            SMALL_CAP,
        )?;
        Self::out_oid(&c)
    }

    /// Tree id of a cached value commit; refuses parents.
    fn commit_info(&self, oid: &str) -> Result<String> {
        let out = self.run_ok(&["cat-file", "commit", oid], None, &[], SMALL_CAP)?;
        let text = String::from_utf8_lossy(&out.stdout);
        let head = text.split_once("\n\n").map_or(&*text, |(h, _)| h);
        let mut tree = None;
        for line in head.lines() {
            if line.starts_with("parent ") {
                return Err(corrupt("commit has a parent"));
            }
            if let Some(t) = line.strip_prefix("tree ") {
                tree.get_or_insert(t.to_string());
            }
        }
        match tree {
            Some(t) if is_oid(&t) => Ok(t),
            _ => Err(corrupt("commit has no tree")),
        }
    }

    /// Validate a cached value's shape and sizes (against `key`'s cap) without
    /// reading any content.
    fn inspect(&self, key: &str, oid: &str) -> Result<Vec<(String, u64)>> {
        let tree = self.commit_info(oid)?;
        let raw = self
            .run_ok(&["cat-file", "tree", &tree], None, &[], SMALL_CAP)?
            .stdout;
        let mut oids = Vec::new();
        let mut pos = 0;
        while pos < raw.len() {
            let sp = raw[pos..].iter().position(|b| *b == b' ');
            let nul = raw[pos..].iter().position(|b| *b == 0);
            let (Some(sp), Some(nul)) = (sp, nul) else {
                return Err(corrupt("malformed tree"));
            };
            if sp > nul || raw.len() < pos + nul + 21 {
                return Err(corrupt("malformed tree"));
            }
            let mode = &raw[pos..pos + sp];
            let name = &raw[pos + sp + 1..pos + nul];
            let i = oids.len();
            if i >= MAX_CHUNKS {
                return Err(corrupt("too many chunks"));
            }
            if mode != b"100644" || name != format!("c{i:04}").as_bytes() {
                return Err(corrupt("tree is not contiguous regular chunk blobs"));
            }
            oids.push(hex::encode(&raw[pos + nul + 1..pos + nul + 21]));
            pos += nul + 21;
        }
        let input: String = oids.iter().map(|o| format!("{o}\n")).collect();
        let out = self.run_ok(
            &["cat-file", "--batch-check"],
            Some(input.as_bytes()),
            &[],
            SMALL_CAP * 4,
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut chunks = Vec::new();
        let mut total = 0u64;
        for (o, line) in oids.iter().zip(text.lines()) {
            let f: Vec<&str> = line.split(' ').collect();
            let size: u64 = match f.as_slice() {
                [_, "blob", size] => size.parse().map_err(|_| corrupt("bad chunk size"))?,
                _ => return Err(corrupt("chunk is not a present blob")),
            };
            if size > CHUNK as u64 {
                return Err(corrupt(format!("chunk of {size} bytes exceeds {CHUNK}")));
            }
            total += size;
            if total > value_cap(key) {
                return Err(corrupt(format!(
                    "value exceeds the {}-byte cap",
                    value_cap(key)
                )));
            }
            chunks.push((o.clone(), size));
        }
        if chunks.len() != oids.len() {
            return Err(corrupt("chunk listing incomplete"));
        }
        Ok(chunks)
    }

    fn read_chunks(&self, chunks: &[(String, u64)]) -> Result<Vec<u8>> {
        let total: u64 = chunks.iter().map(|c| c.1).sum();
        let mut bytes = Vec::with_capacity(total as usize);
        for (o, size) in chunks {
            let out = self.run_ok(&["cat-file", "blob", o], None, &[], CHUNK + 1)?;
            if out.stdout.len() as u64 != *size {
                return Err(corrupt("chunk size changed"));
            }
            bytes.extend_from_slice(&out.stdout);
        }
        Ok(bytes)
    }

    /// Answer a read for `oid` already present in the cache; records it as known.
    fn finish_read(
        &self,
        st: &mut HashMap<String, Known>,
        key: &str,
        oid: &str,
        cached: Option<&str>,
    ) -> Result<Fetched> {
        let chunks = self.inspect(key, oid)?;
        st.insert(
            key.to_string(),
            Known {
                oid: oid.to_string(),
                create_only: create_only_key(key),
                at: Instant::now(),
            },
        );
        if cached == Some(oid) {
            return Ok(Fetched::Unchanged);
        }
        Ok(Fetched::New {
            bytes: self.read_chunks(&chunks)?,
            tag: oid.to_string(),
        })
    }

    /// Local refs under `prefix` as `(key, oid, objecttype)`.
    fn local_refs(&self, prefix: &str) -> Result<Vec<(String, String, String)>> {
        let out = self.run_ok(
            &[
                "for-each-ref",
                "--format=%(objectname) %(objecttype) %(refname)",
                prefix,
            ],
            None,
            &[],
            LS_REMOTE_CAP,
        )?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let mut f = l.splitn(3, ' ');
                let (oid, ty, name) = (f.next()?, f.next()?, f.next()?);
                Some((name.strip_prefix(NS)?.to_string(), oid.into(), ty.into()))
            })
            .collect())
    }

    fn get_family(
        &self,
        st: &mut HashMap<String, Known>,
        key: &str,
        cached: Option<&str>,
        fam: &Family,
    ) -> Result<Fetched> {
        let pat = fam.glob();
        let out = self.fetch(&[format!("+{pat}:{pat}")], true)?;
        if !out.success {
            // A shallow glob fetch that matches nothing fails too: an empty
            // family is absence, anything else is a real failure.
            if self
                .remote_list(fam.dir)?
                .iter()
                .any(|(k, _)| fam.matches(k))
            {
                return Err(self.fail("fetch", &out));
            }
            st.retain(|k, _| !fam.matches(k));
            return Ok(Fetched::Absent);
        }
        let local: Vec<_> = self
            .local_refs(&format!("{NS}{}", fam.dir))?
            .into_iter()
            .filter(|(k, _, _)| fam.matches(k) && check_key(k).is_ok())
            .collect();
        st.retain(|k, _| !fam.matches(k) || local.iter().any(|(l, _, _)| l == k));
        for (k, oid, ty) in &local {
            if k == key && ty != "commit" {
                return Err(corrupt("ref does not point at a commit"));
            }
            if ty != "commit" {
                continue;
            }
            match st.get_mut(k) {
                Some(known) if known.oid == *oid => known.at = Instant::now(),
                _ => {
                    self.commit_info(oid)?;
                    st.insert(
                        k.clone(),
                        Known {
                            oid: oid.clone(),
                            create_only: create_only_key(k),
                            at: Instant::now(),
                        },
                    );
                }
            }
        }
        match st.get(key) {
            None => Ok(Fetched::Absent),
            Some(k) => {
                let oid = k.oid.clone();
                self.answer(key, &oid, cached)
            }
        }
    }

    fn answer(&self, key: &str, oid: &str, cached: Option<&str>) -> Result<Fetched> {
        if cached == Some(oid) {
            return Ok(Fetched::Unchanged);
        }
        let chunks = self.inspect(key, oid)?;
        Ok(Fetched::New {
            bytes: self.read_chunks(&chunks)?,
            tag: oid.to_string(),
        })
    }

    /// Write `bytes` under `lease` (`""` = create-only). Any outcome but a
    /// landed write drops the key's cached tag, so the freshness window can
    /// never vouch for a tag that just lost. A refusal is settled by
    /// re-reading the exact ref (see [`classify_refusal`]).
    fn put(&self, key: &str, bytes: &[u8], kind: &str, lease: &str) -> Result<Written> {
        let oid = self.make_commit(key, bytes, kind)?;
        let refusal = match self.push(key, Some(&oid), Some(lease)) {
            Ok(Pushed::Done) => None,
            Ok(Pushed::Refused(msg)) => Some(Error::Backend(msg)),
            Err(e) => Some(e),
        };
        if let Some(refusal) = refusal {
            self.lock().remove(key);
            let settled = match self.remote_ref(key) {
                Ok(remote) => classify_refusal(&oid, lease, remote.as_deref()),
                Err(_) => Settled::Genuine,
            };
            match settled {
                Settled::Lost => return Ok(Written::Lost),
                Settled::Genuine => return Ok(Written::Failed(refusal)),
                Settled::Landed => {}
            }
        }
        self.lock().insert(
            key.to_string(),
            Known {
                oid: oid.clone(),
                create_only: create_only_key(key),
                at: Instant::now(),
            },
        );
        Ok(Written::Landed(oid))
    }
}

impl Drop for GitBucket {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.cache);
    }
}

/// Fresh private temp directory `sc-git-bucket-<pid>-<random>` (mode 0700).
fn new_cache_dir() -> Result<PathBuf> {
    for attempt in 0u64..16 {
        let name = format!(
            "sc-git-bucket-{}-{}",
            std::process::id(),
            &nonce_seed(attempt)[..16]
        );
        let p = std::env::temp_dir().join(name);
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        match b.create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::Backend(
        "cannot create a unique cache directory".into(),
    ))
}

fn nonce_seed(extra: u64) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut h = blake3::Hasher::new();
    h.update(&nanos.to_le_bytes());
    h.update(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    h.update(&std::process::id().to_le_bytes());
    h.update(&extra.to_le_bytes());
    // Address entropy separates threads racing within one clock tick.
    let local = 0u8;
    h.update(&(std::ptr::addr_of!(local) as usize).to_le_bytes());
    hex::encode(h.finalize().as_bytes())
}

fn nonce(cache: &std::path::Path) -> String {
    let mut h = blake3::Hasher::new();
    h.update(nonce_seed(0).as_bytes());
    h.update(cache.as_os_str().as_encoded_bytes());
    hex::encode(&h.finalize().as_bytes()[..16])
}

impl Bucket for GitBucket {
    fn get(&self, key: &str, cached_tag: Option<&str>) -> Result<Fetched> {
        check_key(key)?;
        let mut st = self.lock();
        if let Some(k) = st.get(key) {
            if k.create_only {
                let oid = k.oid.clone();
                return self.answer(key, &oid, cached_tag);
            }
            if cached_tag == Some(k.oid.as_str()) && k.at.elapsed() < FRESH {
                return Ok(Fetched::Unchanged);
            }
        }
        if let Some(fam) = family_of(key) {
            return self.get_family(&mut st, key, cached_tag, fam);
        }
        let Some(remote) = self.remote_ref(key)? else {
            st.remove(key);
            return Ok(Fetched::Absent);
        };
        if cached_tag == Some(remote.as_str()) {
            st.entry(key.to_string())
                .and_modify(|k| k.at = Instant::now())
                .or_insert(Known {
                    oid: remote,
                    create_only: false,
                    at: Instant::now(),
                });
            return Ok(Fetched::Unchanged);
        }
        let full = format!("{NS}{key}");
        let out = self.fetch(&[format!("+{full}:{full}")], false)?;
        if !out.success {
            // The ref may have vanished between ls-remote and fetch; only the
            // exact full refname decides (patterns tail-match).
            return match self.remote_ref(key)? {
                None => {
                    st.remove(key);
                    Ok(Fetched::Absent)
                }
                Some(_) => Err(self.fail("fetch", &out)),
            };
        }
        // The ref must point directly at a commit: no peeling of tag objects.
        let Some((_, oid, ty)) = self
            .local_refs(&full)?
            .into_iter()
            .find(|(k, _, _)| k == key)
        else {
            return Err(corrupt("fetched ref is missing"));
        };
        if ty != "commit" {
            return Err(corrupt("ref does not point at a commit"));
        }
        self.finish_read(&mut st, key, &oid, cached_tag)
    }

    fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        check_key(key)?;
        match self.put(key, bytes, "new", "")? {
            Written::Landed(_) => Ok(true),
            Written::Lost => Ok(false),
            Written::Failed(refusal) => Err(refusal),
        }
    }

    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        expected_tag: Option<&str>,
    ) -> Result<Option<String>> {
        check_key(key)?;
        let lease = match expected_tag {
            None => "",
            Some(t) if is_tag(t) => t,
            Some(_) => return Ok(None),
        };
        match self.put(key, bytes, "cas", lease)? {
            Written::Landed(oid) => Ok(Some(oid)),
            Written::Lost => Ok(None),
            Written::Failed(refusal) => Err(refusal),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        check_prefix(prefix)?;
        Ok(self
            .remote_list(prefix)?
            .into_iter()
            .map(|(k, _)| k)
            .collect())
    }

    // shortcut: downloads every listed value to read its size; only compaction
    // (refused on git remotes in v1) and tests call it. Upgrade to a filtered
    // fetch if listing large stores becomes slow.
    fn list_meta(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        check_prefix(prefix)?;
        let listed = self.remote_list(prefix)?;
        let mut st = self.lock();
        let missing: Vec<String> = listed
            .iter()
            .filter(|(k, oid)| st.get(k).is_none_or(|known| known.oid != *oid))
            .map(|(k, _)| format!("+{NS}{k}:{NS}{k}"))
            .collect();
        for group in missing.chunks(FETCH_BATCH) {
            let out = self.fetch(group, false)?;
            if !out.success {
                return Err(self.fail("fetch", &out));
            }
        }
        let now = SystemTime::now();
        let mut metas = Vec::new();
        for (key, oid) in listed {
            let chunks = self.inspect(&key, &oid)?;
            st.insert(
                key.clone(),
                Known {
                    oid,
                    create_only: create_only_key(&key),
                    at: Instant::now(),
                },
            );
            metas.push(ObjectMeta {
                key,
                size: chunks.iter().map(|c| c.1).sum(),
                // Committer time is writer-controlled, so the observation time
                // stands in: compaction never prunes on it (ADR-0060).
                modified: now,
            });
        }
        Ok(metas)
    }

    fn exists(&self, key: &str) -> Result<bool> {
        check_key(key)?;
        Ok(self.remote_ref(key)?.is_some())
    }

    fn delete(&self, key: &str) -> Result<()> {
        check_key(key)?;
        let mut st = self.lock();
        st.remove(key);
        match self.push(key, None, None)? {
            Pushed::Done => Ok(()),
            Pushed::Refused(msg) => match self.remote_ref(key) {
                Ok(None) => Ok(()),
                _ => Err(Error::Backend(msg)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_suite;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn have_git() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    macro_rules! need_git {
        () => {
            if !have_git() {
                eprintln!("git not available; skipping");
                return;
            }
        };
    }

    /// A scratch directory removed on drop, asserting it is gone.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "scl-objio-git-{}-{tag}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
            if !std::thread::panicking() {
                assert!(!self.0.exists(), "scratch dir must be removed");
            }
        }
    }

    /// Run real git (isolated config, fixed identity); returns trimmed stdout.
    fn git(dir: &Path, args: &[&str], stdin: &str) -> String {
        let mut c = Command::new("git");
        c.args(args)
            .current_dir(dir)
            .env_remove("GIT_DIR")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@invalid")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A bare hub repository; returns (path, file:// url).
    fn hub(t: &Tmp) -> (PathBuf, String) {
        let p = t.0.join("hub.git");
        git(&t.0, &["init", "--bare", "-q", p.to_str().unwrap()], "");
        let url = format!("file://{}", p.display());
        (p, url)
    }

    fn open(url: &str) -> GitBucket {
        GitBucket::open(url).unwrap()
    }

    #[cfg(unix)]
    fn shim(t: &Tmp, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = t.0.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\nexec git \"$@\"\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_str().unwrap().to_string()
    }

    fn open_git(url: &str, git: &str) -> GitBucket {
        GitBucket::open_with(url, git.to_string(), CHUNK).unwrap()
    }

    fn tag_of(b: &GitBucket, key: &str) -> String {
        let Fetched::New { tag, .. } = b.get(key, None).unwrap() else {
            panic!("expected New")
        };
        tag
    }

    #[test]
    fn git_bucket_passes_contract() {
        need_git!();
        let t = Tmp::new("contract");
        let (_, url) = hub(&t);
        contract_suite(&open(&url));
    }

    #[test]
    fn racing_cas_has_exactly_one_winner() {
        need_git!();
        let t = Tmp::new("racecas");
        let (_, url) = hub(&t);
        for round in 0..4 {
            let key = format!("manifest{round}");
            let base = open(&url);
            let tag = base.put_if_tag(&key, b"v0", None).unwrap().unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let hs: Vec<_> = (0..2)
                .map(|i| {
                    let (url, key, tag, barrier) =
                        (url.clone(), key.clone(), tag.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let b = GitBucket::open(&url).unwrap();
                        barrier.wait();
                        b.put_if_tag(&key, format!("w{i}").as_bytes(), Some(&tag))
                            .unwrap()
                    })
                })
                .collect();
            let wins = hs
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(Option::is_some)
                .count();
            assert_eq!(wins, 1, "round {round}");
        }
    }

    #[test]
    fn racing_create_has_exactly_one_winner() {
        need_git!();
        let t = Tmp::new("racenew");
        let (_, url) = hub(&t);
        for round in 0..4 {
            let key = format!("log/{round}");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let hs: Vec<_> = (0..2)
                .map(|i| {
                    let (url, key, barrier) = (url.clone(), key.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let b = GitBucket::open(&url).unwrap();
                        barrier.wait();
                        b.put_new(&key, format!("w{i}").as_bytes()).unwrap()
                    })
                })
                .collect();
            let wins = hs
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|w| *w)
                .count();
            assert_eq!(wins, 1, "round {round}");
        }
    }

    #[test]
    fn stale_and_malformed_tags_lose() {
        need_git!();
        let t = Tmp::new("tags");
        let (_, url) = hub(&t);
        let b = open(&url);
        b.put_if_tag("manifest", b"v1", None).unwrap().unwrap();
        let stale = "1".repeat(40);
        assert!(b
            .put_if_tag("manifest", b"x", Some(&stale))
            .unwrap()
            .is_none());
        assert!(b
            .put_if_tag("manifest", b"x", Some("zz-not-hex"))
            .unwrap()
            .is_none());
        assert!(b
            .put_if_tag("manifest", b"x", Some(&"0".repeat(40)))
            .unwrap()
            .is_none());
        assert!(b
            .put_if_tag("manifest", b"x", Some(&"A".repeat(40)))
            .unwrap()
            .is_none());
        let Fetched::New { bytes, .. } = b.get("manifest", None).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"v1");
        // a deleted key with a stale tag also loses rather than erroring
        b.delete("manifest").unwrap();
        assert!(b
            .put_if_tag("manifest", b"x", Some(&stale))
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rejecting_hook_is_an_error_not_a_lost_race() {
        use std::os::unix::fs::PermissionsExt;
        need_git!();
        let t = Tmp::new("hook");
        let (hubdir, url) = hub(&t);
        let b = open(&url);
        let tag = b.put_if_tag("manifest", b"v1", None).unwrap().unwrap();
        let hook = hubdir.join("hooks/pre-receive");
        std::fs::write(
            &hook,
            "#!/bin/sh\nprintf 'nope \\033[31mred\\n' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let start = Instant::now();
        let e1 = b.put_new("log/1", b"x").unwrap_err().to_string();
        let e2 = b
            .put_if_tag("manifest", b"v2", Some(&tag))
            .unwrap_err()
            .to_string();
        assert!(start.elapsed() < Duration::from_secs(30));
        assert!(e1.contains("nope"), "{e1}");
        assert!(
            !e1.contains('\u{1b}') && !e2.contains('\u{1b}'),
            "ESC leaked"
        );
        // the refused write left the store untouched
        assert!(!b.exists("log/1").unwrap());
        assert_eq!(tag_of(&open(&url), "manifest"), tag);
        // delete is refused too, and is not mistaken for idempotent success
        assert!(b.delete("manifest").is_err());
    }

    #[test]
    fn decoy_branch_does_not_confuse_reads() {
        need_git!();
        let t = Tmp::new("decoy");
        let (hubdir, url) = hub(&t);
        let b = open(&url);
        b.put_new("other", b"o").unwrap();
        let oid = git(&hubdir, &["rev-parse", "refs/sc/other"], "");
        git(
            &hubdir,
            &["update-ref", "refs/heads/x/refs/sc/manifest", &oid],
            "",
        );
        git(
            &hubdir,
            &["update-ref", "refs/heads/x/refs/sc/log/1", &oid],
            "",
        );
        let r = open(&url);
        assert!(matches!(r.get("manifest", None).unwrap(), Fetched::Absent));
        assert!(matches!(r.get("log/1", None).unwrap(), Fetched::Absent));
        assert!(!r.exists("manifest").unwrap());
        assert_eq!(r.list("").unwrap(), vec!["other".to_string()]);
        assert_eq!(r.list("log/").unwrap(), Vec::<String>::new());
        assert!(r.list_meta("").unwrap().len() == 1);
        // a real manifest next to the decoy is the one read
        assert!(r.put_new("manifest", b"real").unwrap());
        let Fetched::New { bytes, .. } = open(&url).get("manifest", None).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"real");
    }

    #[test]
    fn values_larger_than_a_chunk_round_trip() {
        need_git!();
        let t = Tmp::new("chunks");
        let (hubdir, url) = hub(&t);
        let small = GitBucket::open_with(&url, "git".into(), 4).unwrap();
        let big: Vec<u8> = (0..26u8).collect(); // 7 chunks of at most 4 bytes
        assert!(small.put_new("packs/big.pack", &big).unwrap());
        assert!(small.put_new("exact", &big[..8]).unwrap()); // exact multiple
        assert!(small.put_new("empty", b"").unwrap());
        let tree = git(&hubdir, &["ls-tree", "refs/sc/packs/big.pack"], "");
        assert_eq!(tree.lines().count(), 7);
        let r = open(&url); // fresh cache: exercises the fetch path
        for (k, v) in [
            ("packs/big.pack", &big[..]),
            ("exact", &big[..8]),
            ("empty", &b""[..]),
        ] {
            let Fetched::New { bytes, .. } = r.get(k, None).unwrap() else {
                panic!("{k}")
            };
            assert_eq!(bytes, v, "{k}");
        }
        let metas = r.list_meta("").unwrap();
        let sizes: Vec<(&str, u64)> = metas.iter().map(|m| (m.key.as_str(), m.size)).collect();
        assert_eq!(
            sizes,
            vec![("empty", 0), ("exact", 8), ("packs/big.pack", 26)]
        );
    }

    /// Plant a value commit straight into the hub, bypassing GitBucket.
    fn plant(hubdir: &Path, key: &str, parent: bool, entries: &[(&str, &str, &str)]) {
        plant_msg(hubdir, key, parent, entries, "planted");
    }

    fn plant_msg(
        hubdir: &Path,
        key: &str,
        parent: bool,
        entries: &[(&str, &str, &str)],
        msg: &str,
    ) {
        let blob = git(hubdir, &["hash-object", "-w", "--stdin"], "data");
        let empty = git(hubdir, &["mktree"], "");
        let lines: String = entries
            .iter()
            .map(|(mode, ty, name)| {
                let oid = if *ty == "tree" { &empty } else { &blob };
                format!("{mode} {ty} {oid}\t{name}\n")
            })
            .collect();
        let tree = git(hubdir, &["mktree"], &lines);
        let mut args = vec!["commit-tree", &tree, "-m", msg];
        let base;
        if parent {
            base = git(hubdir, &["commit-tree", &empty, "-m", "base"], "");
            args.extend(["-p", &base]);
        }
        let c = git(hubdir, &args, "");
        git(hubdir, &["update-ref", &format!("refs/sc/{key}"), &c], "");
    }

    #[test]
    fn corrupt_value_shapes_are_refused() {
        need_git!();
        let t = Tmp::new("corrupt");
        let (hubdir, url) = hub(&t);
        let ok = [("100644", "blob", "c0000")];
        for (key, parent, entries) in [
            ("k-parent", true, &ok[..]),
            ("k-subtree", false, &[("040000", "tree", "c0000")][..]),
            (
                "k-gap",
                false,
                &[("100644", "blob", "c0000"), ("100644", "blob", "c0002")][..],
            ),
            ("k-name", false, &[("100644", "blob", "evil")][..]),
            ("k-exec", false, &[("100755", "blob", "c0000")][..]),
            // family keys take the batched path
            ("log/1", true, &ok[..]),
            (
                "log/2",
                false,
                &[("100644", "blob", "c0000"), ("100644", "blob", "c0002")][..],
            ),
        ] {
            plant(&hubdir, key, parent, entries);
            let err = open(&url).get(key, None);
            assert!(
                matches!(&err, Err(Error::Backend(m)) if m.contains("corrupt")),
                "{key}: {:?}",
                err.err()
            );
        }
        // sanity: a well-formed planted value reads fine
        plant(&hubdir, "k-ok", false, &ok);
        assert!(matches!(
            open(&url).get("k-ok", None).unwrap(),
            Fetched::New { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ref_vanishing_between_ls_remote_and_fetch_is_absent() {
        need_git!();
        let t = Tmp::new("vanish");
        let (hubdir, url) = hub(&t);
        open(&url).put_new("k", b"v").unwrap();
        // The shim deletes the ref in the hub just before the fetch runs.
        let body = format!(
            "for a in \"$@\"; do if [ \"$a\" = fetch ]; then git --git-dir={} update-ref -d refs/sc/k; fi; done",
            hubdir.display()
        );
        let sh = shim(&t, "vanish.sh", &body);
        let r = open_git(&url, &sh);
        assert!(matches!(r.get("k", None).unwrap(), Fetched::Absent));
        assert!(!r.exists("k").unwrap());
    }

    #[test]
    fn url_validation() {
        for bad in [
            "",
            "-oProxyCommand=x",
            "--upload-pack=x",
            "https://h/x\n",
            "https://h/x\r",
            "https://h/x\0",
            "https://h/x\u{1b}",
            "ext::sh -c id",
            "https://h/a::b",
            "git://host/x.git",
            "ftp://host/x",
            "relative/path",
            "./x",
            "host:path",
            "https://user:pass@host/x",
            "ssh://user:pw@host/x",
            "https://user@host/x.git",
            "http://token@host/x.git",
            "https://@host/x.git",
            "ssh://-oProxyCommand=x@host/x",
            "ssh://host%2e/x",
            "ssh://ho$t/x",
            "ssh://ho;st/x",
            "git@ho$t:x",
            "https://-evil/x",
            "ssh://git@-evil/x",
            "git@-evil:x",
            "https://host",
            "file://host/x",
            "file://rel",
            "git@host:",
            "@host:x",
            "us er@host:x",
            "foo/bar@host:x",
        ] {
            assert!(GitBucket::validate_url(bad).is_err(), "{bad:?}");
        }
        for good in [
            "https://host/x.git",
            "http://127.0.0.1:8080/x.git",
            "ssh://git@host/x",
            "ssh://git@host:2222/org/x.git",
            "git@host:org/x.git",
            "git@github.com:org/repo.git",
            "file:///abs/path/x.git",
            "/abs/path/x.git",
            "/abs/with space/x.git",
        ] {
            GitBucket::validate_url(good).unwrap_or_else(|e| panic!("{good:?}: {e}"));
        }
        // a password never appears in the error text
        let e = GitBucket::validate_url("https://u:hunter2@host/x")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("hunter2"), "{e}");
        assert_eq!(redact("https://u:pw@h/x"), "https://***@h/x");
        assert_eq!(
            redact("sc+git::https://u:hunter2@h/r.git"),
            "sc+git::https://***@h/r.git"
        );
        assert_eq!(redact("SC+GIT::git@h:o/r.git"), "SC+GIT::***@h:o/r.git");
        assert_eq!(redact("git@h:o/r.git"), "***@h:o/r.git");
        assert_eq!(redact("/abs/a@b/x.git"), "/abs/a@b/x.git");
        assert_eq!(redact("https://h/x@y"), "https://h/x@y");
    }

    #[test]
    fn keys_are_validated_on_every_method() {
        need_git!();
        let t = Tmp::new("keys");
        let (_, url) = hub(&t);
        let b = open(&url);
        for bad in [
            "a.lock", ".x", "a..b", "*", "a b", "a/.x", "a.", "x.lock/y", "a?b", "a[b", "a:b",
            "a~b", "a^b", "a\\b", "", "/a", "a//b", "é", "a@{b",
        ] {
            let is_bad = |r: Result<()>| matches!(r, Err(Error::BadKey(_)));
            assert!(is_bad(b.get(bad, None).map(drop)), "get {bad:?}");
            assert!(is_bad(b.put_new(bad, b"x").map(drop)), "put_new {bad:?}");
            assert!(
                is_bad(b.put_if_tag(bad, b"x", None).map(drop)),
                "put_if_tag {bad:?}"
            );
            assert!(is_bad(b.exists(bad).map(drop)), "exists {bad:?}");
            assert!(is_bad(b.delete(bad)), "delete {bad:?}");
        }
        for bad in ["*", "a b", "a?", "/a", "a..b", "log//"] {
            assert!(matches!(b.list(bad), Err(Error::BadKey(_))), "list {bad:?}");
            assert!(
                matches!(b.list_meta(bad), Err(Error::BadKey(_))),
                "list_meta {bad:?}"
            );
        }
        assert!(b.list("").unwrap().is_empty());
    }

    #[test]
    fn list_is_a_raw_string_prefix() {
        need_git!();
        let t = Tmp::new("list");
        let (_, url) = hub(&t);
        let b = open(&url);
        for k in ["log/1", "logger/x", "manifest", "packs/a.pack"] {
            b.put_new(k, b"x").unwrap();
        }
        assert_eq!(b.list("log").unwrap(), vec!["log/1", "logger/x"]);
        assert_eq!(b.list("log/").unwrap(), vec!["log/1"]);
        assert_eq!(b.list("").unwrap().len(), 4);
    }

    #[cfg(unix)]
    #[test]
    fn puts_survive_hostile_user_git_config() {
        need_git!();
        let t = Tmp::new("cfg");
        let (_, url) = hub(&t);
        // no config at all, so no identity either
        let none = shim(&t, "none.sh", "export GIT_CONFIG_GLOBAL=/dev/null");
        let b = open_git(&url, &none);
        assert!(b.put_new("a", b"1").unwrap());
        // signing on and an unusable gpg program, a hooks dir, and a bad identity
        let cfg = t.0.join("gitconfig");
        std::fs::write(
            &cfg,
            "[commit]\n\tgpgSign = true\n[tag]\n\tgpgSign = true\n[push]\n\tgpgSign = true\n[gpg]\n\tprogram = /nonexistent/gpg\n[user]\n\tname = X\n\temail = x@x\n[core]\n\thooksPath = /nonexistent/hooks\n",
        )
        .unwrap();
        let signing = shim(
            &t,
            "sign.sh",
            &format!("export GIT_CONFIG_GLOBAL={}", cfg.display()),
        );
        let b = open_git(&url, &signing);
        assert!(b.put_new("b", b"2").unwrap());
        let tag = b.put_if_tag("m", b"1", None).unwrap().unwrap();
        assert!(b.put_if_tag("m", b"2", Some(&tag)).unwrap().is_some());
        assert_eq!(b.list("").unwrap(), vec!["a", "b", "m"]);
    }

    #[test]
    fn env_scrub_keeps_transport_and_drops_redirects() {
        for keep in [
            "PATH",
            "HOME",
            "SSH_AUTH_SOCK",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_GLOBAL",
        ] {
            assert!(keep_env(keep), "{keep}");
        }
        for drop in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_NAMESPACE",
            "GIT_COMMON_DIR",
            "GIT_PREFIX",
            "GIT_ALLOW_PROTOCOL",
            "GIT_TRACE",
        ] {
            assert!(!keep_env(drop), "{drop}");
        }
    }

    #[test]
    fn cache_dir_is_private_and_removed_on_drop() {
        need_git!();
        let t = Tmp::new("drop");
        let (_, url) = hub(&t);
        let b = open(&url);
        b.put_new("k", b"v").unwrap();
        let cache = b.cache.clone();
        assert!(cache.is_dir());
        assert!(cache
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(&format!("sc-git-bucket-{}-", std::process::id())));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                cache.metadata().unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        drop(b);
        assert!(!cache.exists());
        // a missing git binary is a clear error at open
        let e = GitBucket::open_with(&url, "/no/such/git".into(), CHUNK).err();
        assert!(e.is_some_and(|e| e.to_string().contains("SC_GIT")));
    }

    #[test]
    fn plain_local_path_urls_work() {
        need_git!();
        let t = Tmp::new("path");
        let (hubdir, _) = hub(&t);
        let b = open(hubdir.to_str().unwrap());
        contract_suite(&b);
    }

    #[test]
    fn value_cap_is_enforced_per_key_kind() {
        assert!(check_len("packs/a.pack", MAX_VALUE).is_ok());
        let e = check_len("packs/a.pack", MAX_VALUE + 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("cap"), "{e}");
        // everything that is not a pack is held to the small cap
        for k in ["manifest", "log/1", "checkpoints/1", "packs/a.idx"] {
            assert!(check_len(k, MAX_SMALL_VALUE).is_ok(), "{k}");
            assert!(check_len(k, MAX_SMALL_VALUE + 1).is_err(), "{k}");
        }
    }

    #[test]
    fn create_only_is_decided_by_key_layout() {
        for k in ["log/1", "checkpoints/9", "packs/a.pack", "packs/a.idx"] {
            assert!(create_only_key(k), "{k}");
        }
        for k in ["manifest", "other", "packs/a.txt", "logger/x", "x/log/1"] {
            assert!(!create_only_key(k), "{k}");
        }
    }

    #[test]
    fn refusal_classification() {
        let (ours, old, other) = ("a".repeat(40), "b".repeat(40), "c".repeat(40));
        let c = |lease: &str, remote: Option<&str>| classify_refusal(&ours, lease, remote);
        // the remote holds our new commit: a lost ack is a success
        assert_eq!(c("", Some(&ours)), Settled::Landed);
        assert_eq!(c(&old, Some(&ours)), Settled::Landed);
        // someone else's value or a deletion beat the lease
        assert_eq!(c("", Some(&other)), Settled::Lost);
        assert_eq!(c(&old, Some(&other)), Settled::Lost);
        assert_eq!(c(&old, None), Settled::Lost);
        // the ref is as the lease expected (or a create found nothing): the host refused
        assert_eq!(c(&old, Some(&old)), Settled::Genuine);
        assert_eq!(c("", None), Settled::Genuine);
    }

    #[cfg(unix)]
    #[test]
    fn lost_push_ack_is_success_when_the_remote_holds_our_commit() {
        need_git!();
        let t = Tmp::new("lostack");
        let (_, url) = hub(&t);
        // The push really lands, but git reports failure.
        let sh = shim(
            &t,
            "ack.sh",
            "for a in \"$@\"; do if [ \"$a\" = push ]; then git \"$@\" >/dev/null 2>&1; exit 1; fi; done",
        );
        let b = open_git(&url, &sh);
        assert!(b.put_new("log/1", b"x").unwrap());
        let tag = b.put_if_tag("manifest", b"v1", None).unwrap().unwrap();
        let tag2 = b
            .put_if_tag("manifest", b"v2", Some(&tag))
            .unwrap()
            .unwrap();
        let Fetched::New { bytes, tag: seen } = open(&url).get("manifest", None).unwrap() else {
            panic!()
        };
        assert_eq!((bytes, seen), (b"v2".to_vec(), tag2));
    }

    #[test]
    fn a_lost_cas_forgets_the_tag_it_lost_with() {
        need_git!();
        let t = Tmp::new("lostcas");
        let (_, url) = hub(&t);
        let (a, b) = (open(&url), open(&url));
        let old = a.put_if_tag("manifest", b"v1", None).unwrap().unwrap();
        let new = b
            .put_if_tag("manifest", b"v2", Some(&old))
            .unwrap()
            .unwrap();
        // A still trusts `old` inside the freshness window, but its CAS loses...
        assert!(a
            .put_if_tag("manifest", b"v3", Some(&old))
            .unwrap()
            .is_none());
        // ...so the window must no longer vouch for it.
        let Fetched::New { tag, .. } = a.get("manifest", Some(&old)).unwrap() else {
            panic!("a lost tag must not read as unchanged")
        };
        assert_eq!(tag, new);
        // a refused create-only write forgets its key too
        assert!(a.put_new("log/1", b"x").unwrap());
        assert!(!b.put_new("log/1", b"y").unwrap());
        assert!(!a.put_new("log/1", b"z").unwrap());
        assert!(!a.lock().contains_key("log/1"));
    }

    #[test]
    fn a_writer_cannot_make_a_mutable_key_immutable_with_its_commit_message() {
        need_git!();
        let t = Tmp::new("newmsg");
        let (hubdir, url) = hub(&t);
        plant_msg(
            &hubdir,
            "manifest",
            false,
            &[("100644", "blob", "c0000")],
            "sc-bucket new decoy",
        );
        let a = open(&url);
        let Fetched::New { bytes, tag } = a.get("manifest", None).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"data");
        let b = open(&url);
        let tag2 = b
            .put_if_tag("manifest", b"v2", Some(&tag))
            .unwrap()
            .unwrap();
        std::thread::sleep(FRESH + Duration::from_millis(200));
        let Fetched::New { bytes, tag: seen } = a.get("manifest", Some(&tag)).unwrap() else {
            panic!("a mutable key must be re-read from the network")
        };
        assert_eq!((bytes, seen), (b"v2".to_vec(), tag2));
    }

    #[test]
    fn a_ref_at_an_annotated_tag_is_corrupt_not_peeled() {
        need_git!();
        let t = Tmp::new("atag");
        let (hubdir, url) = hub(&t);
        plant(&hubdir, "tmp", false, &[("100644", "blob", "c0000")]);
        let c = git(&hubdir, &["rev-parse", "refs/sc/tmp"], "");
        let tag = git(
            &hubdir,
            &["mktag"],
            &format!("object {c}\ntype commit\ntag t\ntagger t <t@invalid> 0 +0000\n\nm\n"),
        );
        git(&hubdir, &["update-ref", "refs/sc/atag", &tag], "");
        let err = open(&url).get("atag", None);
        assert!(
            matches!(&err, Err(Error::Backend(m)) if m.contains("corrupt")),
            "{:?}",
            err.err()
        );
        // the same ref under a family key is refused too
        git(&hubdir, &["update-ref", "refs/sc/log/1", &tag], "");
        assert!(open(&url).get("log/1", None).is_err());
    }

    #[test]
    fn family_ref_names_are_checked_before_they_enter_state() {
        need_git!();
        let t = Tmp::new("famname");
        let (hubdir, url) = hub(&t);
        let ok = [("100644", "blob", "c0000")];
        plant(&hubdir, "log/1", false, &ok);
        plant(&hubdir, "log/a@b", false, &ok);
        let r = open(&url);
        assert!(matches!(r.get("log/1", None).unwrap(), Fetched::New { .. }));
        let st = r.lock();
        assert!(st.contains_key("log/1"));
        assert!(!st.contains_key("log/a@b"));
    }

    #[cfg(unix)]
    #[test]
    fn user_config_cannot_reenable_helper_transports() {
        need_git!();
        let t = Tmp::new("ext");
        let (_, url) = hub(&t);
        let cfg = t.0.join("gitconfig");
        std::fs::write(&cfg, "[protocol \"ext\"]\n\tallow = always\n").unwrap();
        // control: with that config alone, git does run the ext helper
        let control = t.0.join("control");
        let _ = Command::new("git")
            .args(["ls-remote", &format!("ext::touch {}", control.display())])
            .env("GIT_CONFIG_GLOBAL", &cfg)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            control.exists(),
            "control: ext should be enabled by the config"
        );
        let marker = t.0.join("marker");
        let sh = shim(
            &t,
            "ext.sh",
            &format!("export GIT_CONFIG_GLOBAL={}", cfg.display()),
        );
        let b = open_git(&url, &sh);
        let out = b
            .run(
                &[
                    "ls-remote",
                    "--end-of-options",
                    &format!("ext::touch {}", marker.display()),
                ],
                None,
                &[],
                SMALL_CAP,
            )
            .unwrap();
        assert!(!out.success);
        assert!(!marker.exists(), "ext transport ran");
    }

    #[cfg(unix)]
    #[test]
    fn cold_reads_cost_a_bounded_number_of_network_calls() {
        need_git!();
        let mut measured = Vec::new();
        for n in [4usize, 24] {
            let t = Tmp::new("count");
            let (_, url) = hub(&t);
            let wlog = t.0.join("wcalls.log");
            let wsh = shim(
                &t,
                "wcount.sh",
                &format!(
                    "s=; k=0; for x in \"$@\"; do if [ $k = 1 ]; then k=0; continue; fi; if [ \"$x\" = -c ]; then k=1; continue; fi; s=$x; break; done; echo \"$s\" >> {}",
                    wlog.display()
                ),
            );
            let w = open_git(&url, &wsh);
            for i in 1..=n {
                assert!(w.put_new(&format!("log/{i:020}"), b"entry").unwrap());
                assert!(w.put_new(&format!("packs/h{i}.idx"), b"idx").unwrap());
            }
            let m = w.put_if_tag("manifest", b"m", None).unwrap().unwrap();
            let count = |log: &Path| -> usize {
                std::fs::read_to_string(log)
                    .unwrap_or_default()
                    .lines()
                    .filter(|l| matches!(*l, "fetch" | "ls-remote" | "push"))
                    .count()
            };
            // a create-only key just written is served locally, a freshly
            // written CAS tag is trusted inside the window: zero network calls
            let wbefore = count(&wlog);
            assert!(matches!(
                w.get("manifest", Some(&m)).unwrap(),
                Fetched::Unchanged
            ));
            assert!(matches!(
                w.get(&format!("log/{:020}", 1), None).unwrap(),
                Fetched::New { .. }
            ));
            assert!(wbefore > 0, "the writer's shim must see its own calls");
            assert_eq!(count(&wlog), wbefore, "writer re-read its own writes");
            let log = t.0.join("calls.log");
            let sh = shim(
                &t,
                "count.sh",
                &format!(
                    "s=; k=0; for x in \"$@\"; do if [ $k = 1 ]; then k=0; continue; fi; if [ \"$x\" = -c ]; then k=1; continue; fi; s=$x; break; done; echo \"$s\" >> {}",
                    log.display()
                ),
            );
            let calls = || count(&log);
            let r = open_git(&url, &sh);
            // cold read of the manifest, every log entry and every idx
            assert!(matches!(
                r.get("manifest", None).unwrap(),
                Fetched::New { .. }
            ));
            for i in 1..=n {
                assert!(matches!(
                    r.get(&format!("log/{i:020}"), None).unwrap(),
                    Fetched::New { .. }
                ));
                assert!(matches!(
                    r.get(&format!("packs/h{i}.idx"), None).unwrap(),
                    Fetched::New { .. }
                ));
            }
            // probing the first absent log slot
            assert!(matches!(
                r.get(&format!("log/{:020}", n + 1), None).unwrap(),
                Fetched::Absent
            ));
            let cold = calls();
            // incremental: one new log entry + idx written elsewhere, then polled
            assert!(w.put_new(&format!("log/{:020}", n + 1), b"new").unwrap());
            assert!(w.put_new("packs/hnew.idx", b"idx").unwrap());
            let before = calls();
            assert!(matches!(
                r.get(&format!("log/{:020}", n + 1), None).unwrap(),
                Fetched::New { .. }
            ));
            assert!(matches!(
                r.get("packs/hnew.idx", None).unwrap(),
                Fetched::New { .. }
            ));
            let incremental = calls() - before;
            measured.push((n, cold, incremental));
        }
        eprintln!("git network calls (n, cold, incremental): {measured:?}");
        assert_eq!(measured[0].1, measured[1].1, "cold cost independent of N");
        assert_eq!(measured[0].2, measured[1].2);
        assert!(measured[1].1 <= 6, "{measured:?}");
        assert!(measured[1].2 <= 4, "{measured:?}");
    }
}
