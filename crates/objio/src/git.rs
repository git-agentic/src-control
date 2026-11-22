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
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Mutex, MutexGuard};
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
/// Most refs one leased delete push carries, and the most command-line bytes it
/// may use (a lease plus a refspec per key; Windows caps a command line near
/// 32 KiB, so the budget stays well under it).
const DELETE_BATCH: usize = 128;
const DELETE_ARG_BUDGET: usize = 24 << 10;
/// Most value bytes one batched create push carries (an item larger than this
/// goes in a push of its own). The item and command-line bounds of the leased
/// delete apply too, so a batch never outgrows what a host accepts in one push.
const PUSH_VALUE_BUDGET: u64 = 64 << 20;
/// How long a fetch may neither grow `objects/pack` nor exit before the
/// watchdog kills it (a served store depends on its git child, so a silent
/// host must not park a session forever).
const IDLE: Duration = Duration::from_secs(120);
/// Download budget of a fetch of a whole key family or a batch of keys.
const FAMILY_BUDGET: u64 = MAX_VALUE;
/// How long a terminated fetch is watched for a surviving helper (pipes still
/// open, pack directory still changing) before its download is discarded anyway.
const SETTLE: Duration = Duration::from_secs(5);

/// `-c` overrides on every git call: transport allowlist, no hooks, no signing,
/// no background maintenance, bounded stalls. `protocol.version=2` makes a
/// fetch send `ref-prefix`, so the host filters its ref advertisement down to
/// what is asked for; `fetch.unpackLimit=1` keeps every incoming object in one
/// `objects/pack/tmp_pack_*` file (never loose objects), which is what the
/// fetch watchdog measures; `fetch.uriProtocols=` and `transfer.bundleURI=false`
/// stop a host from redirecting the download to packfile or bundle URLs the
/// watchdog could not see.
const GIT_CONFIG: &[&str] = &[
    "protocol.version=2",
    "fetch.unpackLimit=1",
    "fetch.uriProtocols=",
    "transfer.bundleURI=false",
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

/// Fetch watchdog limits: what one fetch may cost before it is killed.
#[derive(Clone, Copy)]
struct Tuning {
    /// Replaces the computed download budget of every fetch (tests only).
    budget: Option<u64>,
    /// Replaces the budget of a family or batched fetch only, so a test can make a
    /// family "too big" while every single key stays within its own cap.
    family_budget: Option<u64>,
    /// A fetch that neither grows `objects/pack` nor exits for this long is killed.
    idle: Duration,
    /// Fixed polling interval; `None` polls after 2 ms and backs off to 50 ms
    /// (tests fix it to make a fetch finish between two polls).
    poll: Option<Duration>,
    /// The program that signals a process group in serve mode (tests point it
    /// at a missing one).
    #[cfg(unix)]
    kill: &'static str,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            budget: None,
            family_budget: None,
            idle: IDLE,
            poll: None,
            #[cfg(unix)]
            kill: "kill",
        }
    }
}

/// The two detached pipe readers of a watched git and what they have delivered.
struct Readers {
    out: mpsc::Receiver<(Vec<u8>, bool)>,
    err: mpsc::Receiver<Vec<u8>>,
    got_out: Option<(Vec<u8>, bool)>,
    got_err: Option<Vec<u8>>,
}

impl Readers {
    /// Collect what the readers deliver until `deadline`; the error names the
    /// first pipe still open then. A reader that died counts as done and empty.
    fn wait(&mut self, deadline: Instant) -> std::result::Result<(), &'static str> {
        if self.got_out.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.out.recv_timeout(left) {
                Ok(v) => self.got_out = Some(v),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.got_out = Some(Default::default())
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return Err("stdout"),
            }
        }
        if self.got_err.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.err.recv_timeout(left) {
                Ok(v) => self.got_err = Some(v),
                Err(mpsc::RecvTimeoutError::Disconnected) => self.got_err = Some(Vec::new()),
                Err(mpsc::RecvTimeoutError::Timeout) => return Err("stderr"),
            }
        }
        Ok(())
    }
}

/// One watched fetch: its download budget and the name of the cap behind it.
struct Watch {
    budget: u64,
    what: String,
    /// Set when the fetch ended by passing `budget` (as opposed to any other
    /// failure), so a caller can tell an oversized family from a broken one.
    over: std::cell::Cell<bool>,
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
    /// Key families (by directory) whose one-fetch read passed the family
    /// budget: this instance reads their keys one fetch each from then on.
    oversized: Mutex<std::collections::HashSet<&'static str>>,
    tune: Tuning,
    /// Serve mode: the lock on `<cache>/.owner.lock`, held for the bucket's whole
    /// life. It is how [`GitBucket::reap_stale`] tells a live cache from one a
    /// killed process left behind (the OS drops the lock with its holder).
    owner: Option<std::fs::File>,
    /// Serve mode: every fetch leads its own process group, so the watchdog
    /// can kill `ssh` and `git-remote-*` along with git. Off for the CLI, where
    /// the terminal's Ctrl-C must still reach git and ssh must still be able to
    /// prompt on the controlling terminal.
    #[cfg(unix)]
    group: bool,
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

/// Download budget of a fetch of exactly one key: its value cap plus the pack
/// overhead (0.1% and 1 MiB; deflate can grow incompressible data a little).
fn single_budget(key: &str) -> u64 {
    let cap = value_cap(key);
    cap + cap / 1024 + (1 << 20)
}

/// Negative refspecs that make `+refs/sc/<key>:refs/sc/<key>` exact. For a
/// refspec without a glob git also accepts a remote ref that merely abbreviates
/// to the name (its rev-parse rules: `refs/heads/refs/sc/<key>`, a tag, a
/// remote-tracking ref, ...), which would let a branch or tag stand in for an
/// absent key. `ls-remote` plus an exact-name compare never had that gap, so
/// the single-key fetch excludes every such spelling.
fn exact_only(full: &str) -> Vec<String> {
    ["refs/", "refs/tags/", "refs/heads/", "refs/remotes/"]
        .iter()
        .map(|p| format!("^{p}{full}"))
        .chain([format!("^refs/remotes/{full}/HEAD")])
        .collect()
}

/// Name and size of every regular file directly in `dir` (empty when it cannot
/// be read).
fn dir_files(dir: &Path) -> HashMap<OsString, u64> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file().then(|| (e.file_name(), m.len()))
        })
        .collect()
}

/// Total size of the regular files directly in `dir`.
fn dir_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()).map(|m| m.len()))
        .sum()
}

/// Remove the `*.lock` files under `dir` (the cache root and its `refs/`, not
/// `objects/`): only a killed git can have left one, because nothing else uses
/// the cache while its fetch is being undone.
fn remove_stale_locks(dir: &Path, depth: u32) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let (path, kind) = (e.path(), e.file_type());
        match kind {
            Ok(t) if t.is_dir() && depth < 8 && e.file_name() != "objects" => {
                remove_stale_locks(&path, depth + 1);
            }
            Ok(t)
                if t.is_file()
                    && e.file_name() != OWNER_LOCK
                    && path.extension().is_some_and(|x| x == "lock") =>
            {
                let _ = std::fs::remove_file(&path);
            }
            _ => {}
        }
    }
}

/// Whether a watched git's process group may be signalled: only while the leader
/// is unreaped. Its pid pins the group id then, so the signal can only reach our
/// own group. Once the leader is reaped, the group's id is free to be reused by
/// an unrelated process group of the same user, and nothing observable can show
/// it has not been: an open pipe proves a live member only at the instant it is
/// looked at, and the external `kill` runs later. Holding the pid without
/// reaping it needs `waitid(WNOWAIT)`, which is `unsafe`, so after the reap the
/// group is never signalled, whatever the pipes say.
///
/// The cost: a helper that outlives git's exit (a smart-HTTP v0/v1 helper chain,
/// an ssh `ControlPersist` master, a hostile process) is not killed and can keep
/// writing after the download was discarded, until it exits. The watchdog then
/// only settles for a bounded time and discards what the fetch added.
fn may_signal_group(leader_reaped: bool) -> bool {
    !leader_reaped
}

/// Signal every process of group `pgid` with SIGKILL through the system `kill`.
/// False only when that program cannot be run; a non-zero exit (the group is
/// already gone) is fine.
#[cfg(unix)]
fn kill_group(program: &str, pgid: u32) -> bool {
    Command::new(program)
        .args(["-s", "KILL", "--"])
        .arg(format!("-{pgid}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Set once a missing `kill` has been reported.
#[cfg(unix)]
static KILL_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Print `msg` to stderr unless `flag` says it was already printed; true when it
/// printed.
#[cfg(unix)]
fn warn_once(flag: &std::sync::atomic::AtomicBool, msg: &str) -> bool {
    let first = !flag.swap(true, std::sync::atomic::Ordering::Relaxed);
    if first {
        eprintln!("{msg}");
    }
    first
}

/// Read up to `cap` bytes from `r` and discard the rest, so the writer never
/// blocks on a full pipe. The flag says more than `cap` bytes came.
fn drain(r: &mut impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let _ = r.by_ref().take(cap as u64 + 1).read_to_end(&mut buf);
    let over = buf.len() > cap;
    buf.truncate(cap);
    let _ = std::io::copy(r, &mut std::io::sink());
    (buf, over)
}

fn over_budget(watch: &Watch) -> Error {
    watch.over.set(true);
    Error::Backend(format!(
        "git fetch downloaded more than {} bytes ({}); it was stopped and its download \
         discarded (hostile or corrupt remote)",
        watch.budget, watch.what
    ))
}

fn stalled(idle: Duration) -> Error {
    Error::Backend(format!(
        "git fetch made no progress for {idle:?}; it was stopped (unreachable or hostile remote)"
    ))
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

/// How many leading items of `rest` go in one batched git call: the first
/// always does, and more join while the item count stays within
/// [`DELETE_BATCH`], their summed command-line cost within [`DELETE_ARG_BUDGET`]
/// and their summed value bytes within [`PUSH_VALUE_BUDGET`]. `cost` gives an
/// item's `(command-line bytes, value bytes)`.
fn batch_len<T>(rest: &[T], cost: impl Fn(&T) -> (usize, u64)) -> usize {
    let (mut n, mut args, mut value) = (0, 0usize, 0u64);
    while let Some(item) = rest.get(n) {
        let (a, v) = cost(item);
        if n > 0
            && (n >= DELETE_BATCH || args + a > DELETE_ARG_BUDGET || value + v > PUSH_VALUE_BUDGET)
        {
            break;
        }
        args += a;
        value += v;
        n += 1;
    }
    n
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

    /// [`GitBucket::open`] for a long-running server (`sc serve --store`): the
    /// cache directory is made under `parent` (the serve home's `.sc/tmp/`, created
    /// if missing) instead of the system temp directory, and every fetch
    /// leads its own process group so the watchdog, when it kills one, takes `ssh` or
    /// `git-remote-https` with it (which needs a `kill` program on the PATH). The
    /// bucket holds a lock on `<cache>/.owner.lock` until it is dropped. A killed
    /// server can leave the cache behind; [`GitBucket::reap_stale`] removes such
    /// leftovers at the next start.
    pub fn open_in(url: &str, parent: &Path) -> Result<GitBucket> {
        let git = std::env::var("SC_GIT").unwrap_or_else(|_| "git".to_string());
        Self::open_full(url, git, CHUNK, Some(parent), true)
    }

    /// Test hook for other crates: lower the download budget of a whole-family
    /// fetch to `bytes`, so a store counts as "over the family budget" without
    /// planting gigabytes. Reads then degrade to one fetch per key, as for a
    /// really oversized family. Not for production use.
    #[doc(hidden)]
    pub fn cap_family_fetches_at(&mut self, bytes: u64) {
        self.tune.family_budget = Some(bytes);
    }

    /// Test hook for other crates: [`GitBucket::open`] running `program` instead
    /// of `git` (a shim that logs the calls it passes through), without touching
    /// the process environment. Not for production use.
    #[doc(hidden)]
    pub fn open_with_program(url: &str, program: &str) -> Result<GitBucket> {
        Self::open_with(url, program.to_string(), CHUNK)
    }

    fn open_with(url: &str, git: String, chunk: usize) -> Result<GitBucket> {
        Self::open_full(url, git, chunk, None, false)
    }

    fn open_full(
        url: &str,
        git: String,
        chunk: usize,
        parent: Option<&Path>,
        group: bool,
    ) -> Result<GitBucket> {
        Self::validate_url(url)?;
        #[cfg(not(unix))]
        let _ = group; // process groups are unix-only; the watchdog kills the child alone
                       // The cache path must be absolute: git runs with the cache as its working
                       // directory and `GIT_DIR` set to the same path, and a relative one (a serve
                       // home given as `.`, a relative `TMPDIR`) would be resolved from inside it.
        let (cache, owner) = match parent {
            Some(p) => {
                let p = std::path::absolute(p)?;
                std::fs::create_dir_all(&p)?;
                let (cache, owner) = new_owned_cache_dir_in(&p)?;
                (cache, Some(owner))
            }
            None => (
                new_cache_dir_in(&std::path::absolute(std::env::temp_dir())?)?,
                None,
            ),
        };
        let b = GitBucket {
            url: url.to_string(),
            git,
            cache,
            chunk: chunk.max(1),
            state: Mutex::new(HashMap::new()),
            oversized: Mutex::new(std::collections::HashSet::new()),
            tune: Tuning::default(),
            owner,
            #[cfg(unix)]
            group,
        };
        // An early `?` drops `b`, which removes the cache dir. The cache is
        // pinned to sha1 whatever the user's `init.defaultObjectFormat`: values
        // and tags are sha1 ids (shortcut: sha256 carriers are unsupported in v1).
        b.run_ok(
            &[
                "init",
                "--bare",
                "--quiet",
                "--template=",
                "--object-format=sha1",
                ".",
            ],
            None,
            &[],
            SMALL_CAP,
        )?;
        Ok(b)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Known>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The git command line in the cache repository with the hardened
    /// environment, stdout and stderr piped.
    fn command(&self, args: &[&str], env: &[(&str, &str)], piped_stdin: bool) -> Command {
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
        cmd.stdin(if piped_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        cmd
    }

    fn spawn(&self, cmd: &mut Command) -> Result<Child> {
        cmd.spawn().map_err(|e| {
            Error::Backend(format!(
                "cannot run git ({}): {e} (install git or set SC_GIT)",
                self.git
            ))
        })
    }

    /// Run git in the cache repository with the hardened environment.
    fn run(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        env: &[(&str, &str)],
        max_out: usize,
    ) -> Result<Out> {
        let mut cmd = self.command(args, env, stdin.is_some());
        let mut child = self.spawn(&mut cmd)?;
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

    /// Run `git fetch` under the download watchdog. Instead of blocking on the
    /// pipes like [`Self::run`], this polls the growth of `objects/pack` (every
    /// download lands in one `tmp_pack_*` file, see [`GIT_CONFIG`]) while
    /// detached threads drain the pipes, and kills git when the growth passes
    /// `watch.budget` or when nothing grows and nothing exits for `idle`. A
    /// check after a normal exit catches a fetch that finished between two
    /// polls. A breach removes what the fetch added and returns an error
    /// naming the cap.
    ///
    /// The bound is disk per fetch. It is not RAM inside `index-pack` and not
    /// the total size of the cache, which grows by what each fetch keeps.
    fn run_watched(&self, args: &[&str], max_out: usize, watch: &Watch) -> Result<Out> {
        let pack_dir = self.cache.join("objects").join("pack");
        let before = dir_files(&pack_dir);
        let base: u64 = before.values().sum();
        let mut cmd = self.command(args, &[], false);
        #[cfg(unix)]
        if self.group {
            std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        }
        let mut child = self.spawn(&mut cmd)?;
        let mut sout = child.stdout.take().expect("piped");
        let mut serr = child.stderr.take().expect("piped");
        // Detached readers: a descendant that outlives a killed git and keeps a
        // pipe open must never be able to block this call.
        let (otx, orx) = mpsc::channel();
        let (etx, erx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = otx.send(drain(&mut sout, max_out));
        });
        std::thread::spawn(move || {
            let _ = etx.send(drain(&mut serr, SMALL_CAP).0);
        });

        let (mut last, mut moved) = (0u64, Instant::now());
        let mut pause = self.tune.poll.unwrap_or(Duration::from_millis(2));
        let mut breach = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) => {}
                Err(e) => {
                    // Whether the leader is reaped is unknown: no group signal.
                    self.stop(&mut child, false);
                    let _ = child.wait();
                    return Err(e.into());
                }
            }
            let grown = dir_bytes(&pack_dir).saturating_sub(base);
            if grown > watch.budget {
                breach = Some(over_budget(watch));
                break None;
            }
            if grown != last {
                (last, moved) = (grown, Instant::now());
            } else if moved.elapsed() >= self.tune.idle {
                breach = Some(stalled(self.tune.idle));
                break None;
            }
            std::thread::sleep(pause);
            if self.tune.poll.is_none() {
                pause = (pause * 2).min(Duration::from_millis(50));
            }
        };
        let mut readers = Readers {
            out: orx,
            err: erx,
            got_out: None,
            got_err: None,
        };
        // Every breach ends in `terminate_and_discard`: the budget during the
        // run, the budget after git exited, no progress, a pipe that stays open.
        let Some(status) = status else {
            self.terminate_and_discard(&mut child, &mut readers, &pack_dir, &before, false);
            return Err(breach.expect("only a breach leaves the loop without a status"));
        };
        // Git has exited and is reaped. A helper that outlived it may still be
        // writing while it holds the pipes (in serve mode it is in git's group),
        // so keep measuring `objects/pack` for the one deadline both pipes share,
        // and once more after both have closed, before calling the fetch good.
        let deadline = Instant::now() + self.tune.idle;
        let held = loop {
            let step = (Instant::now() + Duration::from_millis(20)).min(deadline);
            let pending = readers.wait(step);
            if dir_bytes(&pack_dir).saturating_sub(base) > watch.budget {
                self.terminate_and_discard(&mut child, &mut readers, &pack_dir, &before, true);
                return Err(over_budget(watch));
            }
            match pending {
                Ok(()) => break None,
                Err(what) if Instant::now() >= deadline => break Some(what),
                Err(_) => {}
            }
        };
        if let Some(what) = held {
            self.terminate_and_discard(&mut child, &mut readers, &pack_dir, &before, true);
            return Err(Error::Backend(format!(
                "git exited but left its {what} open for {:?} (a helper outlived it)",
                self.tune.idle
            )));
        }
        let (stdout, over) = readers.got_out.take().unwrap_or_default();
        let stderr = readers.got_err.take().unwrap_or_default();
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

    /// The one end of every breach. Stop git (its whole group in serve mode, but
    /// only while the leader is unreaped: [`may_signal_group`]), reap it, then
    /// keep watching until the pipes have closed and the pack directory has
    /// stopped changing, or a short settle deadline passes, and only then discard
    /// what the fetch added. Discarding first would let a surviving helper write
    /// into the directory after it was cleaned. `reaped` says whether the leader
    /// was already reaped when the breach was found. A helper that outlives that
    /// reap is not killed and may write again after the discard.
    fn terminate_and_discard(
        &self,
        child: &mut Child,
        readers: &mut Readers,
        pack_dir: &Path,
        before: &HashMap<OsString, u64>,
        reaped: bool,
    ) {
        self.stop(child, may_signal_group(reaped));
        let _ = child.wait();
        let settle = Instant::now() + self.tune.idle.min(SETTLE);
        let mut last = dir_bytes(pack_dir);
        loop {
            std::thread::sleep(Duration::from_millis(20));
            let closed = readers.wait(Instant::now()).is_ok();
            let now = dir_bytes(pack_dir);
            if (closed && now == last) || Instant::now() >= settle {
                break;
            }
            last = now;
        }
        self.discard_download(pack_dir, before);
    }

    /// Kill a watched git, and with `signal_group` (see [`may_signal_group`]) its
    /// whole process group in serve mode, where the child leads its own, so `ssh`
    /// and `git-remote-*` die with it. The system `kill` keeps this std-only, with
    /// no `unsafe`, and serve mode on unix therefore needs a `kill` on the PATH.
    /// Without one only git itself is killed, and a warning says so once.
    fn stop(&self, child: &mut Child, signal_group: bool) {
        #[cfg(not(unix))]
        let _ = signal_group; // no process groups: only the child is killed
        #[cfg(unix)]
        if self.group && signal_group && !kill_group(self.tune.kill, child.id()) {
            warn_once(
                &KILL_WARNED,
                &format!(
                    "sc: cannot run `{}` to stop a fetch's process group; only git itself is \
                     killed, so ssh or git-remote-https may keep running (put a `kill` \
                     program on the PATH)",
                    self.tune.kill
                ),
            );
        }
        let _ = child.kill();
    }

    /// Undo a fetch that went over budget: remove every file it added to
    /// `objects/pack` and every ref under `refs/sc/`. A fetch that finished
    /// before the check had already pointed refs at what is deleted here; the
    /// cache is only a copy of the host, so the next read fetches again.
    fn discard_download(&self, pack_dir: &Path, before: &HashMap<OsString, u64>) {
        // A killed git cannot release its locks (`shallow.lock`, ref locks), and
        // a lock that stays would fail every later fetch into this cache.
        remove_stale_locks(&self.cache, 0);
        // Names first, while the objects still exist: a ref to a missing
        // object is skipped by `for-each-ref`.
        let refs: Vec<String> = self
            .local_refs(NS)
            .map(|v| v.into_iter().map(|(k, _, _)| format!("{NS}{k}")).collect())
            .unwrap_or_default();
        for e in std::fs::read_dir(pack_dir).into_iter().flatten().flatten() {
            if !before.contains_key(&e.file_name()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        if !refs.is_empty() {
            let cmds: String = refs.iter().map(|r| format!("delete {r}\n")).collect();
            let _ = self.run(
                &["update-ref", "--stdin"],
                Some(cmds.as_bytes()),
                &[],
                SMALL_CAP,
            );
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
        self.ls_remote_all(&[pattern])
    }

    /// [`Self::ls_remote`] for several patterns in one call.
    fn ls_remote_all(&self, patterns: &[&str]) -> Result<Vec<(String, String)>> {
        let mut a = vec!["ls-remote", "--refs", "--end-of-options", self.url.as_str()];
        a.extend(patterns);
        let out = self.run(&a, None, &[], LS_REMOTE_CAP)?;
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
    /// The download budget is [`FAMILY_BUDGET`]; a fetch of exactly one key
    /// goes through [`Self::fetch_one`] and gets that key's own, tighter one.
    fn fetch(&self, refspecs: &[String], family: bool) -> Result<Out> {
        self.fetch_family(refspecs, family).0
    }

    /// [`Self::fetch`], plus whether the fetch ended by passing its budget. A
    /// family over its budget is not an error to [`Self::get_family`]: it falls
    /// back to one fetch per key.
    fn fetch_family(&self, refspecs: &[String], family: bool) -> (Result<Out>, bool) {
        let what = "the 2 GiB budget of a family or batched fetch".to_string();
        let budget = self.tune.family_budget.unwrap_or(FAMILY_BUDGET);
        self.fetch_flagged(refspecs, family, budget, what)
    }

    /// Fetch exactly `refs/sc/<key>` in one call, which both reads the ref and
    /// updates the cache (a v2 host answers with just that ref, see
    /// [`GIT_CONFIG`]). Exact by name: see [`exact_only`]. A failure does not
    /// say whether the ref is absent; the caller asks `ls-remote` for that.
    fn fetch_one(&self, key: &str) -> Result<Out> {
        let full = format!("{NS}{key}");
        let mut specs = vec![format!("+{full}:{full}")];
        specs.extend(exact_only(&full));
        let what = format!("the value cap of {key:?}");
        self.fetch_flagged(&specs, false, single_budget(key), what)
            .0
    }

    fn fetch_flagged(
        &self,
        refspecs: &[String],
        family: bool,
        budget: u64,
        what: String,
    ) -> (Result<Out>, bool) {
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
        let watch = Watch {
            budget: self.tune.budget.unwrap_or(budget),
            what,
            over: std::cell::Cell::new(false),
        };
        let out = self.run_watched(&a, SMALL_CAP, &watch);
        (out, watch.over.get())
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
        let out = match self.fetch_family(&[format!("+{pat}:{pat}")], true) {
            (Ok(out), _) => out,
            // The family is over its download budget (the fetch is already killed
            // and discarded). A store can legitimately be that big before it is
            // compacted, and compaction itself has to read it, so degrade instead
            // of failing: each key is its own fetch with its own value cap, and
            // so are the rest of this family's keys for this instance.
            (Err(_), true) => {
                let first = self
                    .oversized
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(fam.dir);
                if first {
                    eprintln!(
                        "sc: the {} entries of this Git store exceed the family download \
                         budget; reading them one by one (compacting the store shrinks them)",
                        fam.dir
                    );
                }
                return self.get_single(st, key, cached);
            }
            (Err(e), false) => return Err(e),
        };
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

    /// Read one key with a fetch of exactly that ref (see [`Self::fetch_one`]).
    /// This is the path of every key outside a family and of the keys of a
    /// family that passed its budget.
    fn get_single(
        &self,
        st: &mut HashMap<String, Known>,
        key: &str,
        cached_tag: Option<&str>,
    ) -> Result<Fetched> {
        // One fetch both reads the ref and tells whether it changed: a v2 host
        // filters its advertisement to this ref, where `ls-remote` followed by
        // `fetch` cost two calls (and the whole advertisement on a v0 host).
        let full = format!("{NS}{key}");
        let out = self.fetch_one(key)?;
        if !out.success {
            // The fetch fails for an absent ref and for a real error alike;
            // only the exact full refname decides (patterns tail-match).
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
        if cached_tag == Some(oid.as_str()) {
            // Refresh only a cache entry for this very value; an entry for an
            // older value would otherwise look fresh. A cold hit stays uncached.
            match st.get_mut(key) {
                Some(k) if k.oid == oid => k.at = Instant::now(),
                _ => {
                    st.remove(key);
                }
            }
            return Ok(Fetched::Unchanged);
        }
        self.finish_read(st, key, &oid, cached_tag)
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
        self.lock().insert(key.to_string(), Self::known(key, &oid));
        Ok(Written::Landed(oid))
    }

    /// The cached state of a key this instance just wrote at `oid`.
    fn known(key: &str, oid: &str) -> Known {
        Known {
            oid: oid.to_string(),
            create_only: create_only_key(key),
            at: Instant::now(),
        }
    }

    /// The remote oid of each exactly named `refs/sc/<key>` among `keys`, from
    /// one `ls-remote` per command-line-bounded chunk. Patterns tail-match, so
    /// each line is compared by its full refname.
    fn remote_refs(&self, keys: &[&str]) -> Result<HashMap<String, String>> {
        let mut found = HashMap::new();
        let mut rest = keys;
        while !rest.is_empty() {
            let (chunk, tail) = rest.split_at(batch_len(rest, |k| (NS.len() + k.len() + 1, 0)));
            rest = tail;
            let patterns: Vec<String> = chunk.iter().map(|k| format!("{NS}{k}")).collect();
            let pats: Vec<&str> = patterns.iter().map(String::as_str).collect();
            for (oid, name) in self.ls_remote_all(&pats)? {
                if patterns.contains(&name) {
                    found.insert(name, oid);
                }
            }
        }
        Ok(found)
    }

    /// One create-only push of `chunk` (`(key, commit)` pairs): a
    /// `--force-with-lease=refs/sc/K:` and an `oid:refs/sc/K` refspec per key,
    /// never `+`, never `--atomic` (the keys are independent). Which keys landed
    /// is read from git's per-ref porcelain lines whatever its exit status: a
    /// push where the host refused some refs exits non-zero yet applied the rest.
    /// Returns the landed flags and, when any key did not land, the refusal text.
    fn push_new_chunk(&self, chunk: &[(&str, &str)]) -> Result<(Vec<bool>, Option<String>)> {
        let leases: Vec<String> = chunk
            .iter()
            .map(|(k, _)| format!("--force-with-lease={NS}{k}:"))
            .collect();
        let specs: Vec<String> = chunk
            .iter()
            .map(|(k, oid)| format!("{oid}:{NS}{k}"))
            .collect();
        let mut a = vec!["push", "--porcelain", "--no-verify"];
        a.extend(leases.iter().map(String::as_str));
        a.extend(["--end-of-options", &self.url]);
        a.extend(specs.iter().map(String::as_str));
        let out = self.run(&a, None, &[], SMALL_CAP)?;
        let mut accepted = std::collections::HashSet::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut f = line.split('\t');
            let flag = f.next().unwrap_or("");
            let to = f.next().and_then(|r| r.rsplit_once(':')).map(|(_, t)| t);
            if let (Some(to), " " | "+" | "*") = (to, flag) {
                accepted.insert(to.to_string());
            }
        }
        let landed: Vec<bool> = chunk
            .iter()
            .map(|(k, _)| accepted.contains(&format!("{NS}{k}")))
            .collect();
        let refusal = (!landed.iter().all(|l| *l)).then(|| {
            // Every rejected ref: a retry can see one key's "stale info" before
            // the host's own refusal of another.
            let rejected: Vec<String> = out
                .stdout
                .split(|b| *b == b'\n')
                .filter(|l| l.first() == Some(&b'!'))
                .map(|l| self.scrub(&String::from_utf8_lossy(l)))
                .collect();
            format!(
                "git push failed (exit {}): {} {}",
                out.code.map_or("signal".to_string(), |c| c.to_string()),
                out.stderr,
                rejected.join("; ")
            )
        });
        Ok((landed, refusal))
    }
}

impl Drop for GitBucket {
    fn drop(&mut self) {
        // Release the lock first: an open file keeps a directory from being
        // removed on Windows.
        drop(self.owner.take());
        let _ = std::fs::remove_dir_all(&self.cache);
    }
}

/// Prefix of every cache directory name: `sc-git-bucket-<pid>-<random>`.
const CACHE_PREFIX: &str = "sc-git-bucket-";

/// Name of the file whose lock marks a cache directory as owned by a live
/// [`GitBucket::open_in`] bucket.
const OWNER_LOCK: &str = ".owner.lock";

impl GitBucket {
    /// Remove cache directories a killed process left under `parent`, and return
    /// how many were removed. A `sc-git-bucket-*` directory is removed only when
    /// its `.owner.lock` can be locked, which means no live bucket holds it: the
    /// OS drops a lock with its holder, so liveness does not depend on pid
    /// numbers (pid reuse, containers where every server is pid 1, several pid
    /// namespaces on one host) or on any helper program. Several `sc serve
    /// --stdio` processes can share one `parent`, and a live one's cache
    /// survives. A directory with no lock file, a symlink, and any other name
    /// are kept. The lock is an advisory file lock on one host: it is not
    /// reliable over NFS and similar (as for `DirBucket`). Unix only; on other
    /// platforms it removes nothing.
    pub fn reap_stale(parent: &Path) -> usize {
        #[cfg(unix)]
        {
            let mut removed = 0;
            for e in std::fs::read_dir(parent).into_iter().flatten().flatten() {
                // `file_type` does not follow a symlink, so only a real directory goes.
                if !e.file_name().to_string_lossy().starts_with(CACHE_PREFIX)
                    || !e.file_type().is_ok_and(|t| t.is_dir())
                {
                    continue;
                }
                let lock = e.path().join(OWNER_LOCK);
                if !std::fs::symlink_metadata(&lock).is_ok_and(|m| m.is_file()) {
                    continue;
                }
                let Ok(held) = std::fs::OpenOptions::new().write(true).open(&lock) else {
                    continue;
                };
                // Hold the lock through the removal: an owner that is just being
                // created blocks on it, then sees its lock file gone and starts over.
                if held.try_lock().is_ok() && std::fs::remove_dir_all(e.path()).is_ok() {
                    removed += 1;
                }
            }
            removed
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            0
        }
    }
}

/// A fresh cache directory under `parent` with its owner lock taken. A sweep
/// ([`GitBucket::reap_stale`]) that raced the creation either blocks the lock
/// until it has removed the directory or removes it before the lock exists; both
/// show as a missing lock file, and the next attempt starts over.
fn new_owned_cache_dir_in(parent: &Path) -> Result<(PathBuf, std::fs::File)> {
    for _ in 0..8 {
        let dir = new_cache_dir_in(parent)?;
        let lock = dir.join(OWNER_LOCK);
        let held = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
            .and_then(|f| f.lock().map(|()| f));
        match held {
            Ok(f) if std::fs::symlink_metadata(&lock).is_ok() => return Ok((dir, f)),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e.into());
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    Err(Error::Backend(
        "cannot create a locked cache directory".into(),
    ))
}

/// Fresh private directory `sc-git-bucket-<pid>-<random>` (mode 0700) under `parent`.
fn new_cache_dir_in(parent: &Path) -> Result<PathBuf> {
    for attempt in 0u64..16 {
        let name = format!(
            "{CACHE_PREFIX}{}-{}",
            std::process::id(),
            &nonce_seed(attempt)[..16]
        );
        let p = parent.join(name);
        #[cfg_attr(not(unix), allow(unused_mut))] // `mut` only for the unix mode
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
            let too_big = self
                .oversized
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(fam.dir);
            if !too_big {
                return self.get_family(&mut st, key, cached_tag, fam);
            }
        }
        self.get_single(&mut st, key, cached_tag)
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

    // shortcut: downloads every listed value to read its size; only tests and
    // callers that opened a carrier as a plain bucket call it (compaction on a
    // carrier lists with `list_tags` and sizes packs from their idx). Upgrade to
    // a filtered fetch if listing large stores becomes slow.
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

    /// One `ls-remote` per command-line-bounded chunk, every `refs/sc/<key>` a
    /// pattern, compared by exact refname. Never answered from the local state:
    /// a key another writer deleted must read as absent.
    fn exists_batch(&self, keys: &[&str]) -> Result<Vec<bool>> {
        for k in keys {
            check_key(k)?;
        }
        let found = self.remote_refs(keys)?;
        Ok(keys
            .iter()
            .map(|k| found.contains_key(&format!("{NS}{k}")))
            .collect())
    }

    /// Builds every value commit locally, then pushes in chunks (see
    /// [`batch_len`]): one `git push` per chunk instead of one per key. A key the
    /// push did not report as landed drops its cached state, and all such keys are
    /// classified together by one `ls-remote` of their exact refs with
    /// [`classify_refusal`], as [`GitBucket::put`] does for one key: our commit
    /// there is a lost ack (landed), another value is a lost race (`false`),
    /// nothing is a refusal by the host (an error). If the re-read itself fails
    /// the push refusal is returned, never `false`. An error may leave any subset
    /// of the keys created: orphans a compaction sweeps.
    fn put_new_batch(&self, items: &[(&str, &[u8])]) -> Result<Vec<bool>> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        for (k, _) in items {
            check_key(k)?;
        }
        crate::check_batch(items.iter().map(|(k, _)| *k))?;
        let oids = items
            .iter()
            .map(|(k, v)| self.make_commit(k, v, "new"))
            .collect::<Result<Vec<String>>>()?;
        let mut landed = vec![false; items.len()];
        let mut refusal: Option<Error> = None;
        let mut start = 0;
        while start < items.len() {
            let n = batch_len(&items[start..], |(k, v)| {
                (2 * (NS.len() + k.len()) + 64, v.len() as u64)
            });
            let chunk: Vec<(&str, &str)> = (start..start + n)
                .map(|i| (items[i].0, oids[i].as_str()))
                .collect();
            match self.push_new_chunk(&chunk) {
                Ok((flags, msg)) => {
                    landed[start..start + n].copy_from_slice(&flags);
                    if refusal.is_none() {
                        refusal = msg.map(Error::Backend);
                    }
                }
                Err(e) => {
                    refusal.get_or_insert(e);
                    break;
                }
            }
            start += n;
        }
        {
            let mut st = self.lock();
            for (i, (k, _)) in items.iter().enumerate() {
                if landed[i] {
                    st.insert(k.to_string(), Self::known(k, &oids[i]));
                } else {
                    st.remove(*k);
                }
            }
        }
        let unlanded: Vec<usize> = (0..items.len()).filter(|i| !landed[*i]).collect();
        if unlanded.is_empty() {
            return Ok(landed);
        }
        let refusal =
            refusal.unwrap_or_else(|| Error::Backend("git push did not report the refs".into()));
        let keys: Vec<&str> = unlanded.iter().map(|i| items[*i].0).collect();
        // Cannot re-read (network): report the push failure itself.
        let Ok(remote) = self.remote_refs(&keys) else {
            return Err(refusal);
        };
        let mut genuine = false;
        for i in unlanded {
            let key = items[i].0;
            let cur = remote.get(&format!("{NS}{key}")).map(String::as_str);
            match classify_refusal(&oids[i], "", cur) {
                Settled::Landed => {
                    landed[i] = true;
                    self.lock()
                        .insert(key.to_string(), Self::known(key, &oids[i]));
                }
                Settled::Lost => {}
                Settled::Genuine => genuine = true,
            }
        }
        if genuine {
            return Err(refusal);
        }
        Ok(landed)
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

    fn list_tags(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        check_prefix(prefix)?;
        self.remote_list(prefix)
    }

    /// One `git push --porcelain` per chunk, a `--force-with-lease=refs/sc/K:<oid>`
    /// and a `:refs/sc/K` refspec per key (never `+`, never `--atomic`): the
    /// host checks each lease under that ref's lock, so a key someone re-created
    /// since the caller's listing survives. A refused push is settled by
    /// re-reading every ref of the chunk: gone or at another value is fine, still
    /// at its lease means the host refused it (hook, permissions) and is an error.
    fn delete_leased(&self, items: &[(String, String)]) -> Result<()> {
        for (key, tag) in items {
            check_key(key)?;
            if !is_tag(tag) {
                return Err(Error::Backend(format!(
                    "lease for {key:?} is not a full object id"
                )));
            }
        }
        let mut rest = items;
        while !rest.is_empty() {
            let mut n = 0;
            let mut bytes = 0;
            while let Some((key, _)) = rest.get(n) {
                let cost = 2 * (NS.len() + key.len()) + 64;
                if n > 0 && (n >= DELETE_BATCH || bytes + cost > DELETE_ARG_BUDGET) {
                    break;
                }
                bytes += cost;
                n += 1;
            }
            let (chunk, tail) = rest.split_at(n);
            rest = tail;
            {
                let mut st = self.lock();
                for (key, _) in chunk {
                    st.remove(key);
                }
            }
            let leases: Vec<String> = chunk
                .iter()
                .map(|(k, t)| format!("--force-with-lease={NS}{k}:{t}"))
                .collect();
            let specs: Vec<String> = chunk.iter().map(|(k, _)| format!(":{NS}{k}")).collect();
            let mut a = vec!["push", "--porcelain", "--no-verify"];
            a.extend(leases.iter().map(String::as_str));
            a.extend(["--end-of-options", &self.url]);
            a.extend(specs.iter().map(String::as_str));
            let out = self.run(&a, None, &[], SMALL_CAP)?;
            if out.success {
                continue;
            }
            let first = out
                .stdout
                .split(|b| *b == b'\n')
                .find(|l| l.first() == Some(&b'!'))
                .map(|l| self.scrub(&String::from_utf8_lossy(l)))
                .unwrap_or_default();
            let refusal = format!(
                "git push failed (exit {}): {} {}",
                out.code.map_or("signal".to_string(), |c| c.to_string()),
                out.stderr,
                first
            );
            // Cannot re-read (network): report the push failure itself.
            let now: HashMap<String, String> = self
                .remote_list("")
                .map_err(|_| Error::Backend(refusal.clone()))?
                .into_iter()
                .collect();
            if chunk.iter().any(|(k, t)| now.get(k) == Some(t)) {
                return Err(Error::Backend(refusal));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{contract_suite, leased_delete_suite};
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
        shim_script(t, name, &format!("{body}\nexec git \"$@\"\n"))
    }

    /// An executable `/bin/sh` script with exactly `body`.
    #[cfg(unix)]
    fn shim_script(t: &Tmp, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = t.0.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[cfg(unix)]
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
        let b = open(&url);
        contract_suite(&b);
        leased_delete_suite(&b);
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
        // signing on and an unusable gpg program, a hooks dir, a bad identity and
        // a sha256 default object format (the cache must stay sha1)
        let cfg = t.0.join("gitconfig");
        std::fs::write(
            &cfg,
            "[commit]\n\tgpgSign = true\n[tag]\n\tgpgSign = true\n[push]\n\tgpgSign = true\n[gpg]\n\tprogram = /nonexistent/gpg\n[user]\n\tname = X\n\temail = x@x\n[core]\n\thooksPath = /nonexistent/hooks\n[init]\n\tdefaultObjectFormat = sha256\n",
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
    fn confirming_a_newer_tag_does_not_refresh_an_older_cached_value() {
        need_git!();
        let t = Tmp::new("stale");
        let (_, url) = hub(&t);
        let a = GitBucket::open(&url).unwrap();
        let b = GitBucket::open(&url).unwrap();
        let t1 = a.put_if_tag("manifest", b"v1", None).unwrap().unwrap();
        let t2 = b.put_if_tag("manifest", b"v2", Some(&t1)).unwrap().unwrap();
        // `a` caches t1; a caller that already knows t2 asks `a` to confirm it.
        assert!(matches!(
            a.get("manifest", Some(&t2)).unwrap(),
            Fetched::Unchanged
        ));
        // Asking about the stale t1 right after must not be answered from the cache.
        let Fetched::New { bytes, tag } = a.get("manifest", Some(&t1)).unwrap() else {
            panic!("stale tag answered as unchanged")
        };
        assert_eq!((bytes.as_slice(), tag.as_str()), (&b"v2"[..], t2.as_str()));
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

    /// Keys of a listing, in order.
    fn names(v: &[(String, String)]) -> Vec<&str> {
        v.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn list_tags_reports_the_tag_get_reports_without_downloading() {
        need_git!();
        let t = Tmp::new("tags-list");
        let (_, url) = hub(&t);
        let b = open(&url);
        for k in ["log/1", "logger/x", "manifest", "packs/a.pack"] {
            b.put_new(k, k.as_bytes()).unwrap();
        }
        let r = open(&url); // fresh cache: nothing is downloaded to list
        let tags = r.list_tags("log").unwrap();
        assert_eq!(names(&tags), ["log/1", "logger/x"]);
        for (k, tag) in &r.list_tags("").unwrap() {
            assert_eq!(*tag, tag_of(&b, k), "{k}");
        }
        assert!(r.lock().is_empty(), "a listing must not fetch values");
        assert!(matches!(r.list_tags("a b"), Err(Error::BadKey(_))));
        // a CAS moves the tag the listing reports
        let old = tag_of(&b, "manifest");
        let new = b
            .put_if_tag("manifest", b"v2", Some(&old))
            .unwrap()
            .unwrap();
        let tags = r.list_tags("manifest").unwrap();
        assert_eq!(tags, vec![("manifest".to_string(), new)]);
    }

    #[test]
    fn delete_leased_removes_only_keys_still_at_their_lease() {
        need_git!();
        let t = Tmp::new("leased");
        let (hubdir, url) = hub(&t);
        let b = open(&url);
        for k in ["keep", "log/1", "log/2", "log/3"] {
            assert!(b.put_new(k, k.as_bytes()).unwrap());
        }
        let listed = b.list_tags("").unwrap();
        // After the listing someone else replaces log/2 and re-creates log/3.
        let other = open(&url);
        let lease = |k: &str| listed.iter().find(|(n, _)| n == k).unwrap().1.clone();
        let new2 = other
            .put_if_tag("log/2", b"theirs", Some(&lease("log/2")))
            .unwrap()
            .unwrap();
        other.delete("log/3").unwrap();
        assert!(other.put_new("log/3", b"recreated").unwrap());
        let new3 = tag_of(&other, "log/3");
        // A key that was never there, with a plausible lease, is not an error.
        let mut items: Vec<(String, String)> = listed
            .iter()
            .filter(|(k, _)| k.starts_with("log/"))
            .cloned()
            .collect();
        items.push(("log/9".into(), "1".repeat(40)));
        b.delete_leased(&items).unwrap();

        let now = open(&url).list_tags("").unwrap();
        assert_eq!(
            now,
            vec![
                ("keep".to_string(), lease("keep")),
                ("log/2".to_string(), new2),
                ("log/3".to_string(), new3),
            ]
        );
        let Fetched::New { bytes, .. } = open(&url).get("log/3", None).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"recreated");
        assert!(!git(&hubdir, &["for-each-ref", "refs/sc/log/1"], "").contains("log/1"));
        // Replaying the same call is idempotent.
        b.delete_leased(&items).unwrap();
        assert_eq!(b.list("").unwrap(), vec!["keep", "log/2", "log/3"]);
        b.delete_leased(&[]).unwrap();
    }

    #[test]
    fn delete_leased_refuses_a_bad_key_or_lease_before_any_push() {
        need_git!();
        let t = Tmp::new("leased-bad");
        let (_, url) = hub(&t);
        let b = open(&url);
        b.put_new("log/1", b"x").unwrap();
        let good = tag_of(&b, "log/1");
        for lease in ["", "zz", "A".repeat(40).as_str(), "0".repeat(41).as_str()] {
            let r = b.delete_leased(&[("log/1".into(), lease.into())]);
            assert!(matches!(r, Err(Error::Backend(_))), "{lease:?}");
        }
        for key in ["a..b", "a b", "", "x.lock", "/a", "log/*"] {
            let r = b.delete_leased(&[(key.into(), good.clone())]);
            assert!(matches!(r, Err(Error::BadKey(_))), "{key:?}");
        }
        // One bad item anywhere refuses the whole call: nothing was deleted.
        let r = b.delete_leased(&[("log/1".into(), good.clone()), ("a..b".into(), good)]);
        assert!(r.is_err());
        assert_eq!(b.list("").unwrap(), vec!["log/1"]);
    }

    #[cfg(unix)]
    #[test]
    fn delete_leased_reports_a_ref_the_host_refuses_and_still_removes_the_rest() {
        use std::os::unix::fs::PermissionsExt;
        need_git!();
        let t = Tmp::new("leased-hook");
        let (hubdir, url) = hub(&t);
        let b = open(&url);
        for k in ["log/1", "log/2", "log/3"] {
            b.put_new(k, k.as_bytes()).unwrap();
        }
        let items = b.list_tags("log/").unwrap();
        // An `update` hook judges each ref on its own: it refuses log/2 only.
        let hook = hubdir.join("hooks/update");
        std::fs::write(
            &hook,
            "#!/bin/sh\ncase \"$1\" in refs/sc/log/2) echo 'keep log two' >&2; exit 1;; esac\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = b.delete_leased(&items).unwrap_err().to_string();
        assert!(e.contains("keep log two"), "{e}");
        // Not mistaken for a lost race: log/2 is still at its lease, the others went.
        assert_eq!(names(&open(&url).list_tags("").unwrap()), ["log/2"]);
        // Once the host allows it, the same call finishes the job.
        std::fs::remove_file(&hook).unwrap();
        b.delete_leased(&items).unwrap();
        assert!(b.list("").unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn delete_leased_batches_with_one_lease_per_ref_and_never_plus_or_atomic() {
        need_git!();
        let t = Tmp::new("leased-batch");
        let (hubdir, url) = hub(&t);
        plant(&hubdir, "seed", false, &[("100644", "blob", "c0000")]);
        let c = git(&hubdir, &["rev-parse", "refs/sc/seed"], "");
        const N: usize = 300;
        let cmds: String = (0..N)
            .map(|i| format!("create refs/sc/log/{i:04} {c}\n"))
            .collect();
        git(&hubdir, &["update-ref", "--stdin"], &cmds);
        let log = t.0.join("pushes.log");
        let sh = shim(
            &t,
            "pushes.sh",
            &format!(
                "for x in \"$@\"; do if [ \"$x\" = push ]; then echo \"$*\" >> {}; break; fi; done",
                log.display()
            ),
        );
        let b = open_git(&url, &sh);
        let items: Vec<(String, String)> = b
            .list_tags("log/")
            .unwrap()
            .into_iter()
            .map(|(k, _)| (k, c.clone()))
            .collect();
        assert_eq!(items.len(), N);
        b.delete_leased(&items).unwrap();
        assert!(b.list("log/").unwrap().is_empty());
        let text = std::fs::read_to_string(&log).unwrap();
        let pushes: Vec<&str> = text.lines().collect();
        assert!(pushes.len() >= N.div_ceil(DELETE_BATCH), "{}", pushes.len());
        let mut leases = 0;
        for p in &pushes {
            assert!(p.len() < 32 * 1024, "command line of {} bytes", p.len());
            assert!(!p.contains("--atomic"), "{p}");
            for tok in p.split(' ') {
                assert!(!tok.starts_with('+'), "plus refspec: {tok}");
                if let Some(l) = tok.strip_prefix("--force-with-lease=refs/sc/log/") {
                    assert!(l.ends_with(&format!(":{c}")), "{tok}");
                    leases += 1;
                }
            }
        }
        assert_eq!(leases, N, "one lease per ref");
    }

    /// [`Bucket::put_new_batch`] over string values.
    fn batch(b: &GitBucket, items: &[(&str, &str)]) -> Result<Vec<bool>> {
        let v: Vec<(&str, &[u8])> = items.iter().map(|(k, v)| (*k, v.as_bytes())).collect();
        b.put_new_batch(&v)
    }

    fn value_of(b: &GitBucket, key: &str) -> String {
        let Fetched::New { bytes, .. } = b.get(key, None).unwrap() else {
            panic!("{key} should exist")
        };
        String::from_utf8(bytes).unwrap()
    }

    /// Shell that sets `s` to the git subcommand (skipping `-c <x>` pairs).
    #[cfg(unix)]
    const SUBCOMMAND: &str = "s=; k=0; for x in \"$@\"; do if [ $k = 1 ]; then k=0; continue; fi; if [ \"$x\" = -c ]; then k=1; continue; fi; s=$x; break; done";

    /// A shim that logs the full command line of every push and the subcommand
    /// of every other network call.
    #[cfg(unix)]
    fn call_log_shim(t: &Tmp, log: &Path) -> String {
        shim(
            t,
            "calls.sh",
            &format!(
                "{SUBCOMMAND}; case \"$s\" in push) echo \"push $*\" >> {l};; fetch) echo \"$s\" >> {l};; ls-remote) echo \"ls-remote $*\" >> {l};; esac",
                l = log.display()
            ),
        )
    }

    #[cfg(unix)]
    fn logged(log: &Path, prefix: &str) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with(prefix))
            .map(String::from)
            .collect()
    }

    #[test]
    fn put_new_batch_reports_each_key_and_leaves_an_existing_one_alone() {
        need_git!();
        let t = Tmp::new("batch-mixed");
        let (_, url) = hub(&t);
        assert!(open(&url).put_new("log/2", b"theirs").unwrap());
        // this instance has never seen log/2
        let b = open(&url);
        let out = batch(
            &b,
            &[("log/1", "one"), ("log/2", "mine"), ("log/3", "three")],
        )
        .unwrap();
        assert_eq!(out, [true, false, true]);
        let r = open(&url);
        assert_eq!(value_of(&r, "log/1"), "one");
        assert_eq!(value_of(&r, "log/2"), "theirs");
        assert_eq!(value_of(&r, "log/3"), "three");
        // the lost key was not cached as ours, the landed ones are
        assert_eq!(value_of(&b, "log/2"), "theirs");
        assert_eq!(value_of(&b, "log/1"), "one");
    }

    #[cfg(unix)]
    #[test]
    fn put_new_batch_reports_a_ref_the_host_refuses_and_a_retry_finishes() {
        use std::os::unix::fs::PermissionsExt;
        need_git!();
        let t = Tmp::new("batch-hook");
        let (hubdir, url) = hub(&t);
        let log = t.0.join("calls.log");
        let b = open_git(&url, &call_log_shim(&t, &log));
        // An `update` hook judges each ref on its own: it refuses log/2 only.
        let hook = hubdir.join("hooks/update");
        std::fs::write(
            &hook,
            "#!/bin/sh\ncase \"$1\" in refs/sc/log/2) echo 'keep log two' >&2; exit 1;; esac\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let items = [("log/1", "one"), ("log/2", "two"), ("log/3", "three")];
        let e = batch(&b, &items).unwrap_err().to_string();
        assert!(e.contains("keep log two"), "{e}");
        // the push exits non-zero but its per-ref lines say log/1 and log/3
        // landed, so only log/2 is re-read
        let reads = logged(&log, "ls-remote");
        assert_eq!(reads.len(), 1, "{reads:?}");
        assert!(reads[0].contains("refs/sc/log/2"), "{reads:?}");
        assert!(
            !reads[0].contains("refs/sc/log/1") && !reads[0].contains("refs/sc/log/3"),
            "{reads:?}"
        );
        // not mistaken for a lost race, and the other keys landed
        assert_eq!(
            names(&open(&url).list_tags("").unwrap()),
            ["log/1", "log/3"]
        );
        // once the host allows it, the same call finishes the job: the keys that
        // landed report false, the refused one true
        std::fs::remove_file(&hook).unwrap();
        assert_eq!(batch(&b, &items).unwrap(), [false, true, false]);
        let r = open(&url);
        assert_eq!(value_of(&r, "log/2"), "two");
        assert_eq!(
            names(&r.list_tags("").unwrap()),
            ["log/1", "log/2", "log/3"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn put_new_batch_never_reports_false_when_it_cannot_tell() {
        need_git!();
        // push and the re-read both fail: an error carrying the push refusal
        let t = Tmp::new("batch-blind");
        let (_, url) = hub(&t);
        let sh = shim(
            &t,
            "blind.sh",
            &format!("{SUBCOMMAND}; case \"$s\" in push|ls-remote) echo boom >&2; exit 1;; esac"),
        );
        let b = open_git(&url, &sh);
        let e = batch(&b, &[("log/1", "one")]).unwrap_err().to_string();
        assert!(e.contains("git push failed") && e.contains("boom"), "{e}");
        // push fails, the re-read works and finds nothing: the host refused
        let sh = shim(
            &t,
            "refuse.sh",
            &format!("{SUBCOMMAND}; case \"$s\" in push) echo boom >&2; exit 1;; esac"),
        );
        let b = open_git(&url, &sh);
        let e = batch(&b, &[("log/1", "one")]).unwrap_err().to_string();
        assert!(e.contains("boom"), "{e}");
        assert!(!open(&url).exists("log/1").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_lost_batch_acknowledgement_is_success_when_the_remote_holds_our_commits() {
        need_git!();
        let t = Tmp::new("batch-ack");
        let (_, url) = hub(&t);
        // the push lands but its answer (exit status and per-ref lines) is lost
        let sh = shim_script(
            &t,
            "ack.sh",
            &format!("{SUBCOMMAND}\ncase \"$s\" in push) git \"$@\" >/dev/null 2>&1; exit 1;; esac\nexec git \"$@\"\n"),
        );
        let b = open_git(&url, &sh);
        assert_eq!(
            batch(&b, &[("log/1", "one"), ("log/2", "two")]).unwrap(),
            [true, true]
        );
        assert_eq!(value_of(&open(&url), "log/2"), "two");
    }

    #[cfg(unix)]
    #[test]
    fn put_new_batch_is_one_push_per_chunk_with_a_lease_per_ref_and_never_plus_or_atomic() {
        need_git!();
        let t = Tmp::new("batch-chunks");
        let (_, url) = hub(&t);
        let log = t.0.join("calls.log");
        let b = open_git(&url, &call_log_shim(&t, &log));
        // a few keys: one push, and no re-read when everything landed
        let few: Vec<String> = (0..5).map(|i| format!("log/{i:04}")).collect();
        let items: Vec<(&str, &str)> = few.iter().map(|k| (k.as_str(), "v")).collect();
        assert_eq!(batch(&b, &items).unwrap(), [true; 5]);
        assert_eq!(logged(&log, "push").len(), 1);
        assert!(logged(&log, "ls-remote").is_empty() && logged(&log, "fetch").is_empty());
        // what landed is cached as ours: a create-only key is read with no call
        assert!(matches!(
            b.get("log/0003", None).unwrap(),
            Fetched::New { .. }
        ));
        assert!(logged(&log, "fetch").is_empty() && logged(&log, "ls-remote").is_empty());
        // more than DELETE_BATCH keys: split, each push within the line budget
        let n = DELETE_BATCH + 2;
        let many: Vec<String> = (0..n).map(|i| format!("packs/h{i:04}.idx")).collect();
        let items: Vec<(&str, &str)> = many.iter().map(|k| (k.as_str(), "v")).collect();
        assert_eq!(batch(&b, &items).unwrap(), vec![true; n]);
        let pushes = logged(&log, "push");
        assert_eq!(pushes.len(), 3, "1 + ceil({n} / {DELETE_BATCH})");
        let mut leases = 0;
        for p in &pushes[1..] {
            assert!(p.len() < 32 * 1024, "command line of {} bytes", p.len());
            assert!(!p.contains("--atomic"), "{p}");
            for tok in p.split(' ') {
                assert!(!tok.starts_with('+'), "plus refspec: {tok}");
                if let Some(l) = tok.strip_prefix("--force-with-lease=refs/sc/packs/") {
                    assert!(l.ends_with(".idx:"), "create-only lease expected: {tok}");
                    leases += 1;
                }
            }
        }
        assert_eq!(leases, n, "one lease per ref");
        assert_eq!(b.list("packs/").unwrap().len(), n);
    }

    #[test]
    fn batch_chunks_respect_the_item_line_and_value_bounds() {
        let mib = 1u64 << 20;
        // value bytes: 40 + 40 would pass 64, so they split; an item over the
        // budget goes alone
        let sizes = [40 * mib, 40 * mib, 100 * mib, 1];
        let mut rest: &[u64] = &sizes;
        let mut chunks = Vec::new();
        while !rest.is_empty() {
            let n = batch_len(rest, |v| (100, *v));
            chunks.push(n);
            rest = &rest[n..];
        }
        assert_eq!(chunks, [1, 1, 1, 1]);
        assert_eq!(batch_len(&[mib; 64], |v| (100, *v)), 64);
        assert_eq!(
            batch_len(&[mib; 65], |v| (100, *v)),
            64,
            "64 MiB fits, 65 do not"
        );
        // item count
        assert_eq!(batch_len(&[0u64; 500], |v| (1, *v)), DELETE_BATCH);
        // command-line bytes: the first item always fits, then the budget bounds
        assert_eq!(batch_len(&[0u64; 10], |_| (DELETE_ARG_BUDGET, 0)), 1);
        assert_eq!(batch_len(&[0u64; 10], |_| (DELETE_ARG_BUDGET / 4, 0)), 4);
    }

    #[cfg(unix)]
    #[test]
    fn batch_calls_validate_before_any_git_call_and_empty_is_free() {
        need_git!();
        let t = Tmp::new("batch-validate");
        let (_, url) = hub(&t);
        let log = t.0.join("calls.log");
        let b = open_git(&url, &call_log_shim(&t, &log));
        assert!(b.put_new_batch(&[]).unwrap().is_empty());
        assert!(b.exists_batch(&[]).unwrap().is_empty());
        assert!(batch(&b, &[("log/1", "x"), ("bad key", "y")]).is_err());
        assert!(batch(&b, &[("log/1", "x"), ("log/2/../3", "y")]).is_err());
        assert!(batch(&b, &[("log/1", "x"), ("log/1", "y")]).is_err());
        // acceptable to the shared key check, not to a refspec
        assert!(batch(&b, &[("log/1", "x"), ("log/a..b", "y")]).is_err());
        assert!(batch(&b, &[("log/1", "x"), ("log/a:b", "y")]).is_err());
        assert!(b.exists_batch(&["log/1", "a b"]).is_err());
        assert!(b.exists_batch(&["log/1", "log/*"]).is_err());
        assert!(
            std::fs::read_to_string(&log).unwrap_or_default().is_empty(),
            "no network call for an empty or invalid batch"
        );
        assert!(!open(&url).exists("log/1").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn exists_batch_compares_exact_refnames_and_never_trusts_the_local_state() {
        need_git!();
        let t = Tmp::new("exists-batch");
        let (hubdir, url) = hub(&t);
        let log = t.0.join("calls.log");
        let b = open_git(&url, &call_log_shim(&t, &log));
        assert!(batch(&b, &[("log/1", "one"), ("packs/a.pack", "p")])
            .unwrap()
            .iter()
            .all(|x| *x));
        let oid = git(&hubdir, &["rev-parse", "refs/sc/log/1"], "");
        // a branch whose tail looks like a bucket key is not that key
        git(
            &hubdir,
            &["update-ref", "refs/heads/x/refs/sc/log/9", &oid],
            "",
        );
        let before = logged(&log, "ls-remote").len();
        assert_eq!(
            b.exists_batch(&["log/9", "log/1", "log/2", "packs/a.pack"])
                .unwrap(),
            [false, true, false, true]
        );
        assert_eq!(logged(&log, "ls-remote").len(), before + 1, "one call");
        // a key another writer deleted reads as absent although we wrote it
        git(&hubdir, &["update-ref", "-d", "refs/sc/log/1"], "");
        assert_eq!(b.exists_batch(&["log/1"]).unwrap(), [false]);
        // a long list is split by command-line bytes, one ls-remote per chunk
        let keys: Vec<String> = (0..300)
            .map(|i| format!("packs/{}{i:04}.pack", "h".repeat(50)))
            .collect();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let before = logged(&log, "ls-remote").len();
        let got = b.exists_batch(&refs).unwrap();
        assert!(got.iter().all(|x| !x));
        assert_eq!(logged(&log, "ls-remote").len() - before, 3);
    }

    /// Shell snippet for a shim that logs the git subcommand of every call.
    #[cfg(unix)]
    fn count_snippet(log: &Path) -> String {
        format!(
            "s=; k=0; for x in \"$@\"; do if [ $k = 1 ]; then k=0; continue; fi; if [ \"$x\" = -c ]; then k=1; continue; fi; s=$x; break; done; echo \"$s\" >> {}",
            log.display()
        )
    }

    /// Network subcommands logged by [`count_snippet`], in order.
    #[cfg(unix)]
    fn network_calls(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| matches!(*l, "fetch" | "ls-remote" | "push"))
            .map(String::from)
            .collect()
    }

    /// Wait for `pid` to be gone (a zombie awaiting its reaper counts as gone).
    #[cfg(unix)]
    fn wait_gone(pid: u32) {
        for _ in 0..400 {
            let out = Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if stat.is_empty() || stat.starts_with('Z') {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("process {pid} survived");
    }

    #[cfg(unix)]
    fn kill_pid(pid: u32) {
        let _ = Command::new("kill")
            .args(["-s", "KILL", &pid.to_string()])
            .status();
    }

    /// The error text of a read that must fail.
    fn get_err(b: &GitBucket, key: &str) -> String {
        match b.get(key, None) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("reading {key:?} must fail"),
        }
    }

    /// Plant a value commit holding one incompressible chunk of `n` bytes, with
    /// a parent commit when `parent` (a hostile shape: a shallow fetch records
    /// it as a shallow boundary).
    fn plant_big(hubdir: &Path, key: &str, n: usize, parent: bool) {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let data: Vec<u8> = (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let f = hubdir.join("big.bin");
        std::fs::write(&f, &data).unwrap();
        let blob = git(hubdir, &["hash-object", "-w", f.to_str().unwrap()], "");
        std::fs::remove_file(&f).unwrap();
        let tree = git(hubdir, &["mktree"], &format!("100644 blob {blob}\tc0000\n"));
        let mut args = vec!["commit-tree", &tree, "-m", "planted"];
        let base;
        if parent {
            let empty = git(hubdir, &["mktree"], "");
            base = git(hubdir, &["commit-tree", &empty, "-m", "base"], "");
            args.extend(["-p", &base]);
        }
        let c = git(hubdir, &args, "");
        git(hubdir, &["update-ref", &format!("refs/sc/{key}"), &c], "");
    }

    /// A hostile value with a parent is recorded in `shallow` by the depth-1
    /// fetch, and a discarded download deletes that very object. The cache must
    /// not be left pointing at it: the next reads, of the same hostile key and
    /// of a good one, still work, in both modes and on both check paths.
    #[test]
    fn a_discarded_value_with_a_parent_leaves_the_cache_usable() {
        need_git!();
        let t = Tmp::new("shallow");
        let (hubdir, url) = hub(&t);
        assert!(open(&url).put_new("good", b"fine").unwrap());
        plant_big(&hubdir, "manifest", 3 << 20, true);
        let late = Some(Duration::from_millis(400));
        for (group, poll) in [(true, None), (true, late), (false, late)] {
            let mut b = GitBucket::open_full(&url, "git".into(), CHUNK, None, group).unwrap();
            b.tune.budget = Some(256 << 10);
            b.tune.poll = poll;
            let e = get_err(&b, "manifest");
            assert!(e.contains("262144 bytes"), "{e}");
            let Fetched::New { bytes, .. } = b.get("good", None).unwrap() else {
                panic!("the cache must still read a good key")
            };
            assert_eq!(bytes, b"fine");
            let again = get_err(&b, "manifest");
            assert!(again.contains("262144 bytes"), "{again}");
        }
    }

    /// A mutable-key read is one `git fetch`, and the host's reply lists that
    /// ref alone: protocol v2 sends `ref-prefix`, so the branch and the other
    /// keys on the host never cross the wire (they used to, in a separate
    /// `ls-remote`).
    #[cfg(unix)]
    #[test]
    fn a_manifest_read_is_one_fetch_with_a_filtered_advertisement() {
        need_git!();
        let t = Tmp::new("filtered");
        let (hubdir, url) = hub(&t);
        let w = open(&url);
        let m = w.put_if_tag("manifest", b"v1", None).unwrap().unwrap();
        w.put_new("log/1", b"entry").unwrap();
        w.put_new("other", b"o").unwrap();
        let oid = git(&hubdir, &["rev-parse", "refs/sc/other"], "");
        git(&hubdir, &["update-ref", "refs/heads/main", &oid], "");

        let (calls, trace) = (t.0.join("calls.log"), t.0.join("trace.log"));
        // GIT_TRACE_PACKET is stripped from the environment `run` passes, so
        // the shim sets it itself.
        let sh = shim(
            &t,
            "trace.sh",
            &format!(
                "{}\nexport GIT_TRACE_PACKET={}",
                count_snippet(&calls),
                trace.display()
            ),
        );
        let r = open_git(&url, &sh);
        let Fetched::New { bytes, tag } = r.get("manifest", None).unwrap() else {
            panic!("cold read")
        };
        assert_eq!((bytes.as_slice(), tag.as_str()), (&b"v1"[..], m.as_str()));
        assert_eq!(network_calls(&calls), ["fetch"], "one call, no ls-remote");

        let text = std::fs::read_to_string(&trace).unwrap();
        assert!(
            text.contains("ref-prefix refs/sc/manifest"),
            "the fetch must ask for the ref by prefix"
        );
        let advertised: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("upload-pack>") && l.contains(" refs/"))
            .filter_map(|l| l.split_whitespace().last())
            .collect();
        assert_eq!(
            advertised,
            ["refs/sc/manifest"],
            "reply must be filtered: {text}"
        );

        // A poll after the freshness window is again one call, and unchanged.
        std::thread::sleep(FRESH + Duration::from_millis(200));
        assert!(matches!(
            r.get("manifest", Some(&m)).unwrap(),
            Fetched::Unchanged
        ));
        assert_eq!(network_calls(&calls), ["fetch", "fetch"]);
    }

    /// Git resolves a refspec source that is absent by its abbreviation rules,
    /// so a branch, tag or remote-tracking ref spelled `refs/sc/<key>` after its
    /// own prefix would stand in for the key. The exact-name reads of v1 never
    /// allowed that; the single-key fetch still must not.
    #[test]
    fn abbreviated_ref_names_never_stand_in_for_an_absent_key() {
        need_git!();
        let t = Tmp::new("abbrev");
        let (hubdir, url) = hub(&t);
        plant(&hubdir, "decoy-src", false, &[("100644", "blob", "c0000")]);
        let c = git(&hubdir, &["rev-parse", "refs/sc/decoy-src"], "");
        let decoys = [
            "refs/refs/sc/manifest",
            "refs/tags/refs/sc/manifest",
            "refs/heads/refs/sc/manifest",
            "refs/remotes/refs/sc/manifest",
            "refs/remotes/refs/sc/manifest/HEAD",
        ];
        for decoy in decoys {
            git(&hubdir, &["update-ref", decoy, &c], "");
            let r = open(&url);
            assert!(
                matches!(r.get("manifest", None).unwrap(), Fetched::Absent),
                "{decoy} stood in for the manifest"
            );
            assert!(!r.exists("manifest").unwrap());
            git(&hubdir, &["update-ref", "-d", decoy], "");
        }
        // With every decoy present, the real key is the one read. (A push to a
        // name some other ref abbreviates to is ambiguous, so the key goes in first.)
        assert!(open(&url)
            .put_if_tag("manifest", b"real", None)
            .unwrap()
            .is_some());
        for decoy in &decoys[..4] {
            git(&hubdir, &["update-ref", decoy, &c], "");
        }
        let Fetched::New { bytes, .. } = open(&url).get("manifest", None).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"real");
    }

    /// A value over its budget is discarded whether the watchdog catches it in
    /// flight or only after git exited between two polls (`poll` fixed longer
    /// than the whole fetch), in serve mode (the group is killed) and in CLI
    /// mode (git alone), and the same instance keeps reading good keys. A git
    /// killed in flight cannot release its `shallow.lock`; the next read must
    /// not trip on it. After a CLI-mode kill a surviving `index-pack` may still
    /// finish its own file, so only the other cases assert an empty pack dir.
    #[test]
    fn an_oversized_value_is_discarded_and_the_instance_keeps_working() {
        need_git!();
        let t = Tmp::new("oversize");
        let (hubdir, url) = hub(&t);
        assert!(open(&url).put_new("good", b"fine").unwrap());
        plant_big(&hubdir, "manifest", 3 << 20, false);
        let late = Some(Duration::from_millis(400));
        for (group, poll) in [(true, None), (true, late), (false, None), (false, late)] {
            let mut b = GitBucket::open_full(&url, "git".into(), CHUNK, None, group).unwrap();
            b.tune.budget = Some(256 << 10);
            b.tune.poll = poll;
            let started = Instant::now();
            let e = get_err(&b, "manifest");
            assert!(
                e.contains("262144 bytes") && e.contains("manifest"),
                "the error must name the cap: {e}"
            );
            if poll.is_some() {
                assert!(
                    started.elapsed() >= Duration::from_millis(400),
                    "final check path"
                );
            }
            if group || poll.is_some() {
                assert!(
                    dir_files(&b.cache.join("objects").join("pack")).is_empty(),
                    "the download must be removed"
                );
            }
            assert!(b.local_refs(NS).unwrap().is_empty(), "no ref may survive");
            let Fetched::New { bytes, .. } = b.get("good", None).unwrap() else {
                panic!("the instance must still read other keys")
            };
            assert_eq!(bytes, b"fine");
            // the hostile key is refused again, not cached as absent or known
            assert!(b.get("manifest", None).is_err());
        }
    }

    /// The fetch is killed in flight, with every descendant, and leaves nothing:
    /// the shim stands in for a git that keeps growing `tmp_pack_*` and has a
    /// helper process (as `ssh` or `git-remote-https` would).
    #[cfg(unix)]
    #[test]
    fn a_runaway_fetch_is_killed_with_its_descendants() {
        need_git!();
        let t = Tmp::new("runaway");
        let (_, url) = hub(&t);
        let pids = t.0.join("pids");
        // Like a git killed mid-fetch, it holds locks it can never release.
        let body = format!(
            "case \" $* \" in *\" fetch \"*) sleep 600 & echo $! > {}; touch \"$GIT_DIR/shallow.lock\"; mkdir -p \"$GIT_DIR/refs/sc\"; touch \"$GIT_DIR/refs/sc/manifest.lock\"; while :; do head -c 65536 /dev/zero >> \"$GIT_DIR/objects/pack/tmp_pack_x\"; sleep 0.01; done;; esac",
            pids.display()
        );
        let sh = shim(&t, "runaway.sh", &body);
        let parent = t.0.join("scratch");
        let mut b = GitBucket::open_full(&url, sh, CHUNK, Some(&parent), true).unwrap();
        assert!(b.cache.starts_with(&parent));
        b.tune.budget = Some(1 << 20);
        let started = Instant::now();
        let e = get_err(&b, "manifest");
        assert!(e.contains("1048576 bytes"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(90));
        let helper: u32 = std::fs::read_to_string(&pids)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        wait_gone(helper);
        let tmp_pack = b.cache.join("objects").join("pack").join("tmp_pack_x");
        assert!(!tmp_pack.exists(), "partial download must be removed");
        for lock in ["shallow.lock", "refs/sc/manifest.lock"] {
            assert!(!b.cache.join(lock).exists(), "{lock} must be removed");
        }
        // The loop that wrote it died too: nothing comes back.
        std::thread::sleep(Duration::from_millis(300));
        assert!(!tmp_pack.exists(), "the fetch kept running");
    }

    /// No growth and no exit for `idle` is a stuck host. Both modes return
    /// promptly; in serve mode the group dies with it.
    #[cfg(unix)]
    #[test]
    fn a_silent_fetch_hits_the_no_progress_deadline() {
        need_git!();
        for group in [false, true] {
            let t = Tmp::new("silent");
            let (_, url) = hub(&t);
            let pids = t.0.join("pids");
            // A little data first (under the budget), so the breach has
            // something to discard.
            let body = format!(
                "case \" $* \" in *\" fetch \"*) head -c 1000 /dev/zero > \"$GIT_DIR/objects/pack/tmp_pack_idle\"; sleep 600 & echo $! > {}; wait;; esac",
                pids.display()
            );
            let sh = shim(&t, "silent.sh", &body);
            let mut b = GitBucket::open_full(&url, sh, CHUNK, None, group).unwrap();
            b.tune.idle = Duration::from_millis(800);
            let started = Instant::now();
            let e = get_err(&b, "manifest");
            let took = started.elapsed();
            assert!(
                dir_files(&b.cache.join("objects").join("pack")).is_empty(),
                "the no-progress breach must discard what the fetch added"
            );
            let helper: u32 = std::fs::read_to_string(&pids)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(e.contains("no progress"), "{e}");
            assert!(took >= Duration::from_millis(800), "{took:?}");
            assert!(
                took < Duration::from_secs(90),
                "a descendant holding the pipes must not park the call: {took:?}"
            );
            if group {
                wait_gone(helper);
            } else {
                // Only the child was killed: the orphan still holds the pipes,
                // which is exactly what must not block the caller.
                kill_pid(helper);
                wait_gone(helper);
            }
        }
    }

    /// A git that exits cleanly while a helper keeps its pipes open is an error
    /// within `idle`, not a hang, and what the fetch added is discarded. git is
    /// already reaped, so the group is not signalled in either mode: the helper
    /// outlives the call (the test kills it), which is the documented cost.
    #[cfg(unix)]
    #[test]
    fn a_helper_holding_the_pipes_after_exit_is_an_error() {
        need_git!();
        for group in [true, false] {
            let t = Tmp::new("held");
            let (_, url) = hub(&t);
            let pids = t.0.join("pids");
            // The fetch "downloads" something small and exits cleanly.
            let body = format!(
                "case \" $* \" in *\" fetch \"*) head -c 1000 /dev/zero > \"$GIT_DIR/objects/pack/tmp_pack_held\"; sleep 600 & echo $! > {}; exit 0;; esac",
                pids.display()
            );
            let sh = shim(&t, "held.sh", &body);
            let mut b = GitBucket::open_full(&url, sh, CHUNK, None, group).unwrap();
            b.tune.idle = Duration::from_millis(800);
            let started = Instant::now();
            let e = get_err(&b, "manifest");
            assert!(e.contains("left its"), "{e}");
            assert!(started.elapsed() < Duration::from_secs(90));
            assert!(
                dir_files(&b.cache.join("objects").join("pack")).is_empty(),
                "the pipe-timeout breach must discard what the fetch added"
            );
            let helper: u32 = std::fs::read_to_string(&pids)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            kill_pid(helper);
            wait_gone(helper);
        }
    }

    /// git exits cleanly with its download over budget while a helper is still
    /// alive (here holding the pipes): the download is discarded like for every
    /// other breach, but the group is not signalled, because git is already
    /// reaped and its id could have been reused. The helper survives (and is
    /// killed here by the test). `poll` is fixed longer than the shim runs, so
    /// git has already exited at the second look.
    #[cfg(unix)]
    #[test]
    fn a_clean_exit_over_budget_discards_but_leaves_the_helper_alone() {
        need_git!();
        for group in [true, false] {
            let t = Tmp::new("finalover");
            let (_, url) = hub(&t);
            let pids = t.0.join("pids");
            let body = format!(
                "case \" $* \" in *\" fetch \"*) sleep 0.4; head -c 2000000 /dev/zero > \"$GIT_DIR/objects/pack/pack-fake.pack\"; sleep 600 & echo $! > {}; exit 0;; esac",
                pids.display()
            );
            let sh = shim(&t, "finalover.sh", &body);
            let mut b = GitBucket::open_full(&url, sh, CHUNK, None, group).unwrap();
            let (kill, killed) = recording_kill(&t);
            b.tune.kill = kill;
            b.tune.budget = Some(64 << 10);
            b.tune.poll = Some(Duration::from_millis(1500));
            b.tune.idle = Duration::from_secs(3);
            let e = get_err(&b, "manifest");
            assert!(e.contains("65536 bytes"), "{e}");
            assert!(
                dir_files(&b.cache.join("objects").join("pack")).is_empty(),
                "the over-budget download must be discarded"
            );
            assert!(!killed.exists(), "no group signal after the leader's reap");
            let helper: u32 = std::fs::read_to_string(&pids)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let alive = Command::new("ps")
                .args(["-o", "stat=", "-p", &helper.to_string()])
                .output()
                .unwrap();
            let stat = String::from_utf8_lossy(&alive.stdout).trim().to_string();
            assert!(!stat.is_empty() && !stat.starts_with('Z'), "stat {stat:?}");
            kill_pid(helper);
            wait_gone(helper);
        }
    }

    /// A `kill` stand-in that records its arguments and then really kills:
    /// returns the program path and the log it appends to.
    #[cfg(unix)]
    fn recording_kill(t: &Tmp) -> (&'static str, PathBuf) {
        let log = t.0.join("kill.log");
        let sh = shim_script(
            t,
            "killrec.sh",
            &format!("echo \"$@\" >> {}\nexec kill \"$@\"\n", log.display()),
        );
        (Box::leak(sh.into_boxed_str()), log)
    }

    /// Once git is reaped the group is never signalled, whether a pipe is still
    /// open (a helper holds it) or both are closed: its id may have been reused,
    /// and an open pipe proves nothing by the time the external `kill` runs. The
    /// fetch is over budget in both cases and is still discarded.
    #[cfg(unix)]
    #[test]
    fn a_reaped_leader_gets_no_group_signal_even_with_a_pipe_open() {
        need_git!();
        for helper_holds_pipes in [true, false] {
            let t = Tmp::new("nosignal");
            let (_, url) = hub(&t);
            let pids = t.0.join("pids");
            let helper = if helper_holds_pipes {
                format!("sleep 600 & echo $! > {};", pids.display())
            } else {
                String::new()
            };
            // The shim writes too much late, then exits; with a helper the pipes stay open.
            let body = format!(
                "case \" $* \" in *\" fetch \"*) sleep 1; head -c 2000000 /dev/zero > \"$GIT_DIR/objects/pack/pack-fake.pack\"; {helper} exit 0;; esac"
            );
            let sh = shim(&t, "nosignal.sh", &body);
            let mut b = GitBucket::open_full(&url, sh, CHUNK, None, true).unwrap();
            let (kill, killed) = recording_kill(&t);
            b.tune.kill = kill;
            b.tune.budget = Some(64 << 10);
            b.tune.idle = Duration::from_secs(3);
            // git has exited at the second look, so the breach comes after the reap.
            b.tune.poll = Some(Duration::from_secs(3));
            let e = get_err(&b, "manifest");
            assert!(e.contains("65536 bytes"), "{e}");
            assert!(
                dir_files(&b.cache.join("objects").join("pack")).is_empty(),
                "the over-budget download must be discarded"
            );
            assert!(!killed.exists(), "no group signal after the reap");
            if helper_holds_pipes {
                let pid: u32 = std::fs::read_to_string(&pids)
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                kill_pid(pid);
                wait_gone(pid);
            }
        }
    }

    /// The signalling decision: only while the leader is unreaped, when its pid
    /// pins the group id. After the reap, never.
    #[test]
    fn the_group_is_signalled_only_while_the_leader_is_unreaped() {
        assert!(may_signal_group(false), "an unreaped leader pins the id");
        assert!(!may_signal_group(true), "a reaped leader pins nothing");
    }

    /// A helper that outlives git can cross the budget after git has exited and
    /// close both pipes before the shared deadline. The watchdog must still
    /// catch it, and must not call the fetch good.
    #[cfg(unix)]
    #[test]
    fn a_helper_that_crosses_the_budget_after_git_exits_is_caught() {
        need_git!();
        for group in [true, false] {
            let t = Tmp::new("late");
            let (_, url) = hub(&t);
            // git exits at once; a helper holds the pipes, then writes too much and exits.
            let body = "case \" $* \" in *\" fetch \"*) ( sleep 0.6; head -c 2000000 /dev/zero > \"$GIT_DIR/objects/pack/pack-late.pack\" ) & exit 0;; esac";
            let sh = shim(&t, "late.sh", body);
            let mut b = GitBucket::open_full(&url, sh, CHUNK, None, group).unwrap();
            b.tune.budget = Some(64 << 10);
            let e = get_err(&b, "manifest");
            assert!(e.contains("65536 bytes"), "{e}");
            assert!(
                dir_files(&b.cache.join("objects").join("pack")).is_empty(),
                "the late download must be discarded"
            );
        }
    }

    /// A relative serve home (`.`) must work: git runs with the cache as its
    /// working directory, so a relative cache path would be resolved from inside
    /// the cache. The path is relative to the current directory without
    /// changing it, by climbing out to the root and down again.
    #[cfg(unix)]
    #[test]
    fn a_relative_cache_parent_works() {
        need_git!();
        let t = Tmp::new("relative");
        let (_, url) = hub(&t);
        let cwd = std::env::current_dir().unwrap();
        let up = "../".repeat(cwd.components().count() - 1);
        let target = t.0.join("home").join(".sc").join("tmp");
        let rel = PathBuf::from(format!(
            "{up}{}",
            target.strip_prefix("/").unwrap().display()
        ));
        assert!(rel.is_relative());
        let b = GitBucket::open_in(&url, &rel).unwrap();
        assert!(b.cache.is_absolute(), "{:?}", b.cache);
        assert!(b.put_new("k", b"v").unwrap());
        let Fetched::New { bytes, .. } = b.get("k", None).unwrap() else {
            panic!("the value just written must read back")
        };
        assert_eq!(bytes, b"v");
        // and a non-create-only key goes through the fetch path too
        let tag = b.put_if_tag("manifest", b"m", None).unwrap().unwrap();
        std::thread::sleep(FRESH + Duration::from_millis(100));
        assert!(matches!(
            b.get("manifest", Some(&tag)).unwrap(),
            Fetched::Unchanged
        ));
    }

    /// Both pipes share one deadline after git exits. Here stdout is held for
    /// half of `idle` and stderr for 1.25 times `idle`: waiting `idle` for each
    /// in turn (the old behavior) would let the second one finish in time.
    #[cfg(unix)]
    #[test]
    fn the_pipe_wait_after_exit_has_one_deadline() {
        need_git!();
        let t = Tmp::new("deadline");
        let (_, url) = hub(&t);
        let body = "case \" $* \" in *\" fetch \"*) sleep 4 2>/dev/null & sleep 10 >/dev/null & exit 0;; esac";
        let sh = shim(&t, "deadline.sh", body);
        let mut b = open_git(&url, &sh);
        b.tune.idle = Duration::from_secs(8);
        let e = get_err(&b, "manifest");
        assert!(e.contains("left its stderr open"), "{e}");
    }

    /// Without a `kill` program serve mode cannot signal the group. It falls back
    /// to killing git alone, returns, and warns once instead of staying silent.
    #[cfg(unix)]
    #[test]
    fn a_missing_kill_program_falls_back_to_killing_git_and_warns_once() {
        need_git!();
        let flag = std::sync::atomic::AtomicBool::new(false);
        assert!(warn_once(&flag, "first"), "the first report prints");
        assert!(!warn_once(&flag, "second"), "later reports stay quiet");
        assert!(
            !kill_group("/no/such/kill", 1),
            "an unrunnable program is reported"
        );

        let t = Tmp::new("nokill");
        let (_, url) = hub(&t);
        let pids = t.0.join("pids");
        let body = format!(
            "case \" $* \" in *\" fetch \"*) sleep 600 & echo $! > {}; wait;; esac",
            pids.display()
        );
        let sh = shim(&t, "nokill.sh", &body);
        let mut b = GitBucket::open_full(&url, sh, CHUNK, None, true).unwrap();
        b.tune.idle = Duration::from_millis(800);
        b.tune.kill = "/no/such/kill";
        let started = Instant::now();
        let e = get_err(&b, "manifest");
        assert!(e.contains("no progress"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(90));
        // Only git was killed: the helper outlives the call, which is the
        // documented cost of a missing `kill`.
        let helper: u32 = std::fs::read_to_string(&pids)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let alive = Command::new("ps")
            .args(["-o", "stat=", "-p", &helper.to_string()])
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&alive.stdout).trim().to_string();
        assert!(!stat.is_empty() && !stat.starts_with('Z'), "stat {stat:?}");
        kill_pid(helper);
        wait_gone(helper);
    }

    /// A store whose `log/`, `checkpoints/` or `packs/*.idx` family passes the
    /// family budget must stay readable, or it could never be compacted. The
    /// family fetch is discarded, the requested key is read with a fetch of its
    /// own (with its own value cap), and the instance remembers: the family's
    /// other keys go straight to single fetches, with no new family attempt. Each
    /// family is judged on its own.
    #[cfg(unix)]
    #[test]
    fn an_oversized_family_degrades_to_one_fetch_per_key() {
        need_git!();
        let t = Tmp::new("bigfamily");
        let (_, url) = hub(&t);
        let w = open(&url);
        let keys = ["log/1", "log/2", "log/3", "packs/a.idx", "packs/b.idx"];
        for k in keys {
            assert!(w.put_new(k, k.as_bytes()).unwrap());
        }
        // `family` for a glob refspec, `single` for an exact one.
        let calls = t.0.join("calls.log");
        let body = format!(
            "case \" $* \" in *\" fetch \"*) case \"$*\" in *'*'*) echo family >> {0};; *) echo single >> {0};; esac;; esac",
            calls.display()
        );
        let sh = shim(&t, "fam.sh", &body);
        let mut r = open_git(&url, &sh);
        r.tune.family_budget = Some(1);
        let count = |what: &str| {
            std::fs::read_to_string(&calls)
                .unwrap_or_default()
                .lines()
                .filter(|l| *l == what)
                .count()
        };
        let read = |k: &str| match r.get(k, None).unwrap() {
            Fetched::New { bytes, .. } => bytes,
            _ => panic!("{k} must read"),
        };
        assert_eq!(read("log/1"), b"log/1");
        assert_eq!((count("family"), count("single")), (1, 1));
        assert_eq!(read("log/2"), b"log/2");
        assert_eq!(read("log/3"), b"log/3");
        assert_eq!(
            (count("family"), count("single")),
            (1, 3),
            "later keys of an oversized family must not retry the family fetch"
        );
        // The idx family is judged on its own: one attempt, then single fetches.
        assert_eq!(read("packs/a.idx"), b"packs/a.idx");
        assert_eq!(read("packs/b.idx"), b"packs/b.idx");
        assert_eq!((count("family"), count("single")), (2, 5));
        // An absent key of an oversized family is absent, not an error.
        assert!(matches!(r.get("log/9", None).unwrap(), Fetched::Absent));
    }

    /// Degrading to single fetches does not lift the per-key cap: a hostile value
    /// in an oversized family is still refused at its own cap.
    #[test]
    fn a_hostile_value_in_an_oversized_family_still_fails_its_own_cap() {
        need_git!();
        let t = Tmp::new("bigfamily-hostile");
        let (hubdir, url) = hub(&t);
        plant_big(&hubdir, "log/1", 3 << 20, false);
        let mut b = open(&url);
        b.tune.budget = Some(256 << 10); // every fetch, family or single
        let e = get_err(&b, "log/1");
        assert!(e.contains("value cap of \"log/1\""), "{e}");
    }

    #[test]
    fn the_forced_config_pins_the_download_redirect_switches() {
        for pinned in [
            "protocol.version=2",
            "fetch.unpackLimit=1",
            "fetch.uriProtocols=",
            "transfer.bundleURI=false",
        ] {
            assert!(GIT_CONFIG.contains(&pinned), "{pinned}");
        }
    }

    /// Serve mode (own cache parent, own process group) is the same store.
    #[cfg(unix)]
    #[test]
    fn a_served_bucket_passes_the_contract_and_cleans_up() {
        need_git!();
        let t = Tmp::new("served");
        let (_, url) = hub(&t);
        let parent = t.0.join("home").join(".sc").join("tmp");
        let b = GitBucket::open_in(&url, &parent).unwrap();
        let cache = b.cache.clone();
        assert_eq!(cache.parent(), Some(parent.as_path()));
        contract_suite(&b);
        drop(b);
        assert!(!cache.exists());
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
    }

    /// The startup sweep goes by the owner lock, not by pid numbers. A cache
    /// whose lock is free goes even when its pid is ours or alive (pid reuse,
    /// every server being pid 1 in a container); one whose lock is held stays
    /// even when its pid looks dead; so do a directory with no lock file, a
    /// symlink, and other names. This process's own live buckets stay too.
    #[cfg(unix)]
    #[test]
    fn reap_stale_goes_by_the_owner_lock_not_by_pid() {
        need_git!();
        let t = Tmp::new("reap");
        let (_, url) = hub(&t);
        let parent = t.0.join("tmp");
        std::fs::create_dir_all(&parent).unwrap();
        let mk = |name: &str, lock: bool| {
            let p = parent.join(name);
            std::fs::create_dir_all(p.join("objects")).unwrap();
            if lock {
                std::fs::write(p.join(OWNER_LOCK), b"").unwrap();
            }
            p
        };
        let mut gone = Command::new("true").spawn().unwrap();
        let dead = gone.id();
        gone.wait().unwrap();
        // Free lock, whatever the pid says: our own pid, a live one, a junk name.
        let stale_own = mk(&format!("{CACHE_PREFIX}{}-aaaa", std::process::id()), true);
        let stale_one = mk(&format!("{CACHE_PREFIX}1-bbbb"), true);
        let stale_junk = mk(&format!("{CACHE_PREFIX}notapid-cccc"), true);
        // Held lock, whatever the pid says: a dead one (another namespace, or a
        // server that is alive under a pid we cannot see).
        let held_dir = mk(&format!("{CACHE_PREFIX}{dead}-dddd"), true);
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(held_dir.join(OWNER_LOCK))
            .unwrap();
        held.lock().unwrap();
        // Never reaped: no lock file, another name, a symlink into a stale-looking dir.
        let no_lock = mk(&format!("{CACHE_PREFIX}{dead}-eeee"), false);
        let other = mk("serve-bucket-1-0", true);
        let link = parent.join(format!("{CACHE_PREFIX}{dead}-link"));
        std::os::unix::fs::symlink(&other, &link).unwrap();
        // Two live buckets of this process.
        let (a, b) = (
            GitBucket::open_in(&url, &parent).unwrap(),
            GitBucket::open_in(&url, &parent).unwrap(),
        );

        assert_eq!(GitBucket::reap_stale(&parent), 3);
        for gone in [&stale_own, &stale_one, &stale_junk] {
            assert!(
                !gone.exists(),
                "{gone:?} has a free lock and must be reaped"
            );
        }
        for kept in [&held_dir, &no_lock, &other, &link, &a.cache, &b.cache] {
            assert!(kept.exists(), "{kept:?} must survive");
        }
        assert!(other.join(OWNER_LOCK).exists(), "a symlink is not followed");
        assert!(a.put_new("k", b"v").unwrap() && b.exists("k").unwrap());

        // The holder going away (a killed server) is what frees the cache.
        drop(held);
        // A child another test thread is forking can hold a copy of the lock's
        // descriptor until its exec closes it, so the lock frees a moment later.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut reaped = GitBucket::reap_stale(&parent);
        while reaped == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            reaped = GitBucket::reap_stale(&parent);
        }
        assert_eq!(reaped, 1);
        assert!(!held_dir.exists());
        // So does dropping a bucket: it removes its own directory.
        let cache = a.cache.clone();
        drop(a);
        assert!(!cache.exists());
        assert_eq!(GitBucket::reap_stale(&parent.join("missing")), 0);
    }

    /// A sweep that runs while buckets are being opened and dropped never takes
    /// a live bucket's cache: the owner lock is taken before the bucket is used,
    /// and a sweep that raced the creation makes the opener start over.
    #[cfg(unix)]
    #[test]
    fn a_sweep_never_removes_a_live_bucket_while_others_open() {
        need_git!();
        let t = Tmp::new("sweep");
        let (_, url) = hub(&t);
        let parent = t.0.join("tmp");
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    GitBucket::reap_stale(&parent);
                }
            });
            for i in 0..12 {
                let b = GitBucket::open_in(&url, &parent).unwrap();
                assert!(
                    b.put_new(&format!("k{i}"), b"v").unwrap(),
                    "cache {i} was swept"
                );
            }
            done.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
    }
}
