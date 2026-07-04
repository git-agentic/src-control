//! `sc` — the src-control CLI.
//!
//! The headline command is `sc demo`, which spins up N in-memory agent
//! worktrees in parallel, has each edit and check out independently, tears
//! everything down, and proves no residual files remain on disk.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use scl_core::{Backend, FileMode, SpillPolicy, Store, StoreConfig};
use scl_crypto::KeyProvider;
use scl_vfs::Repo;

#[derive(Parser)]
#[command(name = "sc", version, about = "src-control: in-memory agent worktrees")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Spin up N parallel in-memory agent worktrees, edit + checkout each, then
    /// tear down and verify zero residual files on disk.
    Demo(DemoArgs),
    /// Import a Git repo's HEAD into the store and print a summary.
    Import {
        /// Path to a Git repository.
        #[arg(long)]
        repo: PathBuf,
    },
    /// Generate an X25519 identity keypair (private key written to disk 0600).
    Keygen {
        /// Where to write the private key (default: ~/.sc/identity).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Phase 2 proof: add a committed secret, deny an unauthorized context,
    /// decrypt + inject in an authorized one, then grant — all in RAM.
    SecretDemo(SecretDemoArgs),
    /// Create a new persistent repo (.sc/) in the current directory.
    Init,
    /// Snapshot the working tree as a commit on the current branch.
    Commit {
        #[arg(short, long)]
        message: String,
        #[arg(long, default_value = "you")]
        author: String,
    },
    /// Show working-tree changes against HEAD.
    Status,
    /// Show commit history from HEAD.
    Log,
    /// Create a new branch at the current tip.
    Branch { name: String },
    /// Switch HEAD to a branch and materialize it. Protected files decrypt when
    /// the resolved identity is a recipient, and are skipped otherwise.
    Switch {
        name: String,
        /// Identity file for decrypting protected files (default
        /// `--identity`/`SC_IDENTITY`/`~/.sc/identity`). Missing file → protected
        /// files are simply skipped.
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Committed-secret operations.
    Secret {
        #[command(subcommand)]
        op: SecretOp,
    },
    /// Merge a branch into the current branch (or fast-forward).
    ///
    /// On conflicts this command prints the conflicted files and exits 0 (not an
    /// error) — the working tree is left with conflict markers and a merge in
    /// progress. Check `sc status` (or scripts should check it) before chaining
    /// further commands, since `sc merge x && sc commit` would otherwise commit
    /// the markers.
    Merge {
        /// Branch to merge in.
        branch: Option<String>,
        /// Abandon an in-progress merge and restore the working tree. When given,
        /// the BRANCH argument is ignored.
        #[arg(long)]
        abort: bool,
        #[arg(long, default_value = "you")]
        author: String,
    },
    /// Scan the working tree for plaintext secrets without committing.
    Scan,
    /// Decrypt authorized secrets, inject them, and run a command.
    Run {
        /// Identity file (default ~/.sc/identity or $SC_IDENTITY).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Command and args after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Clone a local repo into a new directory.
    Clone { src: PathBuf, dst: PathBuf },
    /// Manage remotes.
    Remote {
        #[command(subcommand)]
        op: RemoteOp,
    },
    /// Fetch objects + branch tips from a remote into remote-tracking refs.
    Fetch {
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Push the current branch to a remote (fast-forward-only).
    Push {
        #[arg(default_value = "origin")]
        remote: String,
        /// For git remotes: allow pushing protected ciphertext and dropping secrets.
        #[arg(long)]
        include_encrypted: bool,
    },
    /// Protect a path prefix: files under it are convergently encrypted for the
    /// named recipients on commit. With `--list` (or no prefix), list the rules.
    Protect {
        /// Path prefix to protect (e.g. `secret/`). Omit to list.
        prefix: Option<String>,
        /// Recipient names (from `.sc/recipients.toml`).
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// List protected prefixes instead of adding one.
        #[arg(long)]
        list: bool,
    },
    /// Grant a recipient read access to an already-protected prefix (policy-only;
    /// no file objects change). Requires your identity to re-wrap the DEK.
    Grant {
        /// The protected path prefix.
        prefix: String,
        /// Recipient names to grant (from `.sc/recipients.toml`).
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// Your identity file (must currently be a recipient of the prefix).
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Revoke a recipient's access to a protected prefix (by recipient id).
    Revoke {
        /// The protected path prefix.
        prefix: String,
        /// Recipient id to revoke.
        #[arg(long)]
        recipient_id: String,
    },
    /// Garbage-collect: pack reachable objects, prune unreachable ones.
    Gc {
        /// Prune unreachable loose objects older than this (e.g. 24h, 7d).
        #[arg(long, default_value = "24h")]
        prune_expire: String,
    },
    /// Export the current branch's history into a Git repository.
    Export {
        /// Target Git repo path (created bare if absent).
        #[arg(long)]
        to: PathBuf,
        /// Ref to update (default: refs/heads/<current-branch>).
        #[arg(long)]
        r#ref: Option<String>,
        /// Allow exporting protected ciphertext and dropping secrets.
        #[arg(long)]
        include_encrypted: bool,
    },
    /// Manage the break-glass escrow recipient (auto-included at seal/protect).
    Escrow {
        #[command(subcommand)]
        op: EscrowOp,
    },
}

#[derive(Subcommand)]
enum EscrowOp {
    /// Set the escrow key (a `scl-pk-…` pubkey, or a name from [recipients]).
    Set { key_or_name: String },
    /// Show the configured escrow key (and its recovery non-guarantee).
    Show,
}

#[derive(Subcommand)]
enum RemoteOp {
    /// Add a named remote.
    Add {
        name: String,
        url: String,
        /// Treat the remote URL as a Git repository (translated via gitio).
        #[arg(long)]
        git: bool,
    },
    /// List configured remotes.
    List,
}

#[derive(Subcommand)]
enum SecretOp {
    /// Seal a value (read from --value or stdin) to named recipients.
    Add {
        name: String,
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// The secret value. WARNING: passed on the command line, so it is
        /// visible in process args (e.g. `ps`) and shell history. Reading the
        /// value from stdin instead is a planned follow-up.
        #[arg(long)]
        value: String,
    },
    /// Grant a recipient access by re-wrapping (requires your identity). Each
    /// granted recipient produces one commit (N recipients -> N commits).
    Grant {
        name: String,
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Revoke a recipient (by recipient id).
    Revoke {
        name: String,
        #[arg(long)]
        recipient_id: String,
    },
    /// List committed secrets.
    List,
    /// Rotate a secret's value under a fresh DEK (the cryptographic cutover that
    /// revoke does not perform). With --value, seal a new value (no identity
    /// needed); without, recover the current value with --identity and re-seal it.
    /// Recipients default to the secret's current set; --to overrides.
    Rotate {
        name: String,
        /// New value. Omit to keep the current value (requires --identity).
        #[arg(long)]
        value: Option<String>,
        /// Recipient names (default: the secret's current recipients).
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// Your identity (required when --value is omitted, to recover the value).
        #[arg(long)]
        identity: Option<PathBuf>,
    },
}

#[derive(Parser)]
struct SecretDemoArgs {
    /// Resident blob budget in megabytes.
    #[arg(long, default_value_t = 8)]
    budget_mb: usize,
}

#[derive(Parser)]
struct DemoArgs {
    /// Number of parallel agent worktrees.
    #[arg(long, default_value_t = 4)]
    agents: usize,
    /// Optional Git repo to fork from. Without it, a synthetic repo is generated.
    #[arg(long)]
    repo: Option<PathBuf>,
    /// Resident blob budget in megabytes.
    #[arg(long, default_value_t = 8)]
    budget_mb: usize,
    /// Allow spilling evicted blobs to a session temp dir (removed on teardown).
    #[arg(long, default_value_t = false)]
    spill: bool,
    /// Materialize each agent's worktree to disk (under the session dir) to
    /// exercise the only disk-writing path, then clean it up.
    #[arg(long, default_value_t = true)]
    checkout: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Demo(args) => run_demo(args),
        Cmd::Import { repo } => run_import(repo),
        Cmd::Keygen { out } => run_keygen(out),
        Cmd::SecretDemo(args) => run_secret_demo(args),
        Cmd::Init => run_init(),
        Cmd::Commit { message, author } => run_commit(&author, &message),
        Cmd::Status => run_status(),
        Cmd::Log => run_log(),
        Cmd::Branch { name } => run_branch(&name),
        Cmd::Switch { name, identity } => run_switch(&name, identity),
        Cmd::Scan => run_scan(),
        Cmd::Merge { branch, abort, author } => run_merge(branch, abort, &author),
        Cmd::Secret { op } => run_secret(op),
        Cmd::Run { identity, cmd } => run_run(identity, cmd),
        Cmd::Clone { src, dst } => run_clone(src, dst),
        Cmd::Remote { op } => run_remote(op),
        Cmd::Fetch { remote } => run_fetch(&remote),
        Cmd::Push { remote, include_encrypted } => run_push(&remote, include_encrypted),
        Cmd::Protect { prefix, to, list } => run_protect(prefix, to, list),
        Cmd::Grant { prefix, to, identity } => run_grant(prefix, to, identity),
        Cmd::Revoke { prefix, recipient_id } => run_revoke(prefix, recipient_id),
        Cmd::Gc { prune_expire } => run_gc(&prune_expire),
        Cmd::Export { to, r#ref, include_encrypted } => run_export(to, r#ref, include_encrypted),
        Cmd::Escrow { op } => run_escrow(op),
    }
}

fn run_import(repo_path: PathBuf) -> Result<()> {
    let mut store = Store::new(StoreConfig::default());
    let snap = scl_gitio::import_head(&mut store, &repo_path)?;
    let repo = Repo::new(store);
    let wt = repo.fork(snap, "import-view")?;
    let files = wt.list()?;
    println!("Imported HEAD of {}", repo_path.display());
    println!("  snapshot: {snap}");
    println!("  files:    {}", files.len());
    for f in files.iter().take(20) {
        println!("    {f}");
    }
    if files.len() > 20 {
        println!("    … and {} more", files.len() - 20);
    }
    Ok(())
}

fn run_demo(args: DemoArgs) -> Result<()> {
    let pid = std::process::id();
    let session_root = std::env::temp_dir().join(format!("scl-session-{pid}"));
    let _ = std::fs::remove_dir_all(&session_root);
    std::fs::create_dir_all(&session_root)?;

    let budget_bytes = args.budget_mb * 1024 * 1024;
    let backend = if args.spill {
        Backend::Ephemeral(SpillPolicy::SpillTo(session_root.join("spill")))
    } else {
        Backend::Ephemeral(SpillPolicy::Disallow)
    };

    println!("=== src-control · in-memory agent worktree demo ===");
    println!(
        "agents={}  budget={} MiB  spill={}  checkout={}",
        args.agents, args.budget_mb, args.spill, args.checkout
    );
    println!("session dir: {}", session_root.display());
    println!();

    let repo = Repo::new(Store::new(StoreConfig { budget_bytes, backend }));

    // ---- base snapshot: import a Git repo, or synthesize one in memory. ----
    let base = match &args.repo {
        Some(path) => {
            let store = repo.store();
            let mut guard = store.lock().unwrap();
            let snap = scl_gitio::import_head(&mut guard, path)
                .with_context(|| format!("importing {}", path.display()))?;
            drop(guard);
            let n = repo.fork(snap, "probe")?.list()?.len();
            println!("base: imported {} ({} files)", path.display(), n);
            snap
        }
        None => {
            let snap = synth_repo(&repo)?;
            let n = repo.fork(snap, "probe")?.list()?.len();
            println!("base: synthetic repo ({n} files)");
            snap
        }
    };
    println!("base snapshot: {base}");
    println!("store after base load: {}", fmt_stats(&repo));
    println!();

    // ---- fork N worktrees and run them in parallel threads. ----
    let edits = Arc::new(AtomicU64::new(0));
    let results: Vec<AgentResult> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..args.agents)
            .map(|i| {
                let repo = repo.clone();
                let session_root = session_root.clone();
                let edits = edits.clone();
                scope.spawn(move || run_agent(i, repo, base, &session_root, args.checkout, &edits))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Result<Vec<_>>>()
    })?;

    for r in &results {
        println!(
            "  agent-{:<2} forked={}  edited {} file(s)  new snapshot={}  checkout={}",
            r.id,
            base.short(),
            r.edited,
            r.snapshot.short(),
            r.checked_out
        );
    }
    println!();
    println!("total edits across agents: {}", edits.load(Ordering::Relaxed));
    println!("store after agents ran:    {}", fmt_stats(&repo));

    // Confirm isolation: each agent produced a distinct snapshot from the base.
    let all_distinct = results.iter().all(|r| r.snapshot != base);
    println!("all agent snapshots differ from base (isolation): {all_distinct}");

    // ---- teardown: drop worktrees implicitly (results moved), remove session. ----
    drop(results);
    drop(repo); // drops Store -> removes spill dir
    std::fs::remove_dir_all(&session_root).ok();

    // ---- zero-residue proof. ----
    let residue = session_root.exists();
    println!();
    println!("=== teardown ===");
    println!("session dir still present: {residue}");
    if residue {
        anyhow::bail!("residual files left on disk at {}", session_root.display());
    }
    println!("RESULT: zero residual files on disk after teardown ✔");
    Ok(())
}

struct AgentResult {
    id: usize,
    edited: usize,
    snapshot: scl_core::ObjectId,
    checked_out: bool,
}

/// One agent: fork the base, make isolated edits, optionally checkout to disk,
/// read its files back, and commit a new snapshot.
fn run_agent(
    id: usize,
    repo: Repo,
    base: scl_core::ObjectId,
    session_root: &std::path::Path,
    checkout: bool,
    edits: &AtomicU64,
) -> Result<AgentResult> {
    let mut wt = repo.fork(base, format!("agent-{id}"))?;

    // Each agent edits a distinct set of files, so overlays don't collide.
    wt.write(
        "README.md",
        format!("# edited by agent-{id}\n").into_bytes(),
        FileMode::FILE,
    );
    wt.write(
        &format!("agents/agent-{id}.log"),
        format!("agent {id} was here\n").into_bytes(),
        FileMode::FILE,
    );
    wt.remove("docs/REMOVE_ME.txt");
    edits.fetch_add(3, Ordering::Relaxed);

    // Read-after-write within the worktree.
    let readme = wt.read("README.md")?;
    debug_assert!(readme.starts_with(b"# edited"));

    let checked_out = if checkout {
        let dest = session_root.join(format!("agent-{id}"));
        wt.checkout(&dest)?;
        // Simulate "running against the checkout": read a file back from disk.
        let _ = std::fs::read(dest.join("README.md"))?;
        true
    } else {
        false
    };

    let snapshot = wt.commit(&format!("agent-{id}"), "agent edits")?;
    Ok(AgentResult { id, edited: 3, snapshot, checked_out })
}

/// Generate a synthetic in-memory repo with a mix of small files and a few large
/// blobs, so the memory budget and eviction path get exercised.
fn synth_repo(repo: &Repo) -> Result<scl_core::ObjectId> {
    let mut files: Vec<(String, Vec<u8>, FileMode)> = Vec::new();
    files.push(("README.md".into(), b"# synthetic repo\n".to_vec(), FileMode::FILE));
    files.push(("docs/REMOVE_ME.txt".into(), b"delete me\n".to_vec(), FileMode::FILE));
    for i in 0..40 {
        files.push((
            format!("src/module_{i:02}.rs"),
            format!("// module {i}\npub fn f{i}() -> usize {{ {i} }}\n").into_bytes(),
            FileMode::FILE,
        ));
    }
    // A few "large" blobs (1 MiB each) to push against a small budget.
    for i in 0..6 {
        files.push((
            format!("assets/blob_{i}.bin"),
            vec![b'A' + i as u8; 1024 * 1024],
            FileMode::FILE,
        ));
    }
    Ok(repo.commit_files(&files, "synth", "synthetic base")?)
}

fn fmt_stats(repo: &Repo) -> String {
    let s = repo.stats();
    format!(
        "resident_blob={:.1} MiB / {:.0} MiB budget · objects={} · spilled={} · evictions={} · rehydrations={}",
        s.resident_blob_bytes as f64 / 1048576.0,
        s.budget_bytes as f64 / 1048576.0,
        s.resident_objects,
        s.spilled_blobs,
        s.evictions,
        s.rehydrations,
    )
}

// ---- identity-path helpers --------------------------------

/// Default identity path: `$HOME/.sc/identity`.
fn default_identity_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".sc").join("identity")
}

/// Resolve the identity file: `--identity` > `SC_IDENTITY` > default.
fn resolve_identity_path(flag: Option<PathBuf>) -> PathBuf {
    if let Some(p) = flag {
        return p;
    }
    if let Ok(env) = std::env::var("SC_IDENTITY") {
        return PathBuf::from(env);
    }
    default_identity_path()
}

fn run_keygen(out: Option<PathBuf>) -> Result<()> {
    let path = out.unwrap_or_else(default_identity_path);
    if let Some(parent) = path.parent() {
        // Only tighten a directory we create ourselves: chmod-ing a pre-existing
        // parent (e.g. $HOME for `--out ~/identity`, or CWD for `--out ./key`)
        // would retroactively narrow the user's own dir — a footgun.
        let parent_preexisted = parent.as_os_str().is_empty() || parent.exists();
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        if !parent_preexisted {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let (sk, pk) = scl_crypto::generate_keypair();
    // Create the key file 0600 *atomically* so the private key is never visible
    // group/world-readable through the umask window between write and chmod.
    // `create_new(true)` refuses to clobber an existing identity.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("identity already exists at {} (refusing to overwrite)", path.display()))?;
        f.write_all(sk.to_key_string().as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, sk.to_key_string())?;
    }
    println!("wrote private key: {} (0600)", path.display());
    println!("public key:   {}", pk.to_key_string());
    println!("recipient id: {}", pk.recipient_id());
    println!("\nAdd to .sc/recipients.toml under [recipients]:");
    println!("  <name> = \"{}\"", pk.to_key_string());
    Ok(())
}

// ---- .sc/recipients.toml loader ------------------------------------

/// Parsed `.sc/recipients.toml`: `[recipients] name -> scl-pk-<hex>`, plus an
/// optional `[escrow]` break-glass key auto-included at seal/protect time.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct RecipientsFile {
    #[serde(default)]
    recipients: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    escrow: Option<EscrowEntry>,
}

/// A single break-glass escrow recipient entry: `[escrow] key = "scl-pk-…"`.
#[derive(serde::Serialize, serde::Deserialize)]
struct EscrowEntry {
    key: String,
}

/// Resolve recipient names to public keys from a recipients file.
fn load_recipients(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, scl_crypto::PublicKey>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let parsed: RecipientsFile = toml::from_str(&text)?;
    let mut out = std::collections::BTreeMap::new();
    for (name, key_str) in parsed.recipients {
        let pk = scl_crypto::PublicKey::from_key_string(&key_str)
            .map_err(|_| anyhow::anyhow!("bad public key for recipient '{name}'"))?;
        out.insert(name, pk);
    }
    Ok(out)
}

/// The configured escrow public key, if any. Missing file or missing `[escrow]`
/// section → `None`.
fn load_escrow(path: &std::path::Path) -> Result<Option<scl_crypto::PublicKey>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let parsed: RecipientsFile = toml::from_str(&text)?;
    match parsed.escrow {
        Some(e) => Ok(Some(
            scl_crypto::PublicKey::from_key_string(&e.key)
                .map_err(|_| anyhow::anyhow!("bad escrow public key"))?,
        )),
        None => Ok(None),
    }
}

// ---- sc secret-demo ------------------------------------------------

/// Decrypt `name` from `snapshot` using `identity`, inject it into a child
/// process environment, and return what the child read back. Proves the value
/// reaches a real process env without ever touching disk.
fn run_with_secret(
    repo: &Repo,
    snapshot: scl_core::ObjectId,
    name: &str,
    identity: &scl_crypto::SecretKey,
) -> Result<String> {
    let wt = repo.fork(snapshot, "run")?;
    let sid = wt
        .secret_id(name)
        .ok_or_else(|| anyhow::anyhow!("no secret named {name}"))?;
    let secret = repo.store().lock().unwrap().get_secret(&sid)?;
    // Integrity: the registry pointer must name the same secret it points at, so
    // a registry entry can't be silently relabeled to another (same-recipient)
    // secret. The AEAD already binds `secret.name` as AAD; this checks the
    // pointer too.
    if secret.name != name {
        return Err(anyhow::anyhow!(
            "secret name mismatch: registry entry {name} points at a secret named {}",
            secret.name
        ));
    }
    let plaintext = scl_crypto::open(&secret, identity)?; // Err if unauthorized
    // Inject the raw secret bytes verbatim. On unix the value can be non-UTF-8;
    // pass it as an `OsStr` so a binary secret survives intact rather than being
    // silently replaced by "".
    #[cfg(unix)]
    let cmd_env_val = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(&plaintext)
    };
    #[cfg(not(unix))]
    let cmd_env_val =
        std::str::from_utf8(&plaintext).map_err(|_| anyhow::anyhow!("secret is not valid UTF-8"))?;
    // NOTE: `plaintext` is `Zeroizing` and is wiped when this fn returns. The
    // child's stdout copy below is NOT zeroized; acceptable here because the
    // demo only logs its `.len()`, never the value itself.
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("printf %s \"${name}\""))
        .env(name, cmd_env_val)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_secret_demo(args: SecretDemoArgs) -> Result<()> {
    let pid = std::process::id();
    let session_root = std::env::temp_dir().join(format!("scl-secret-session-{pid}"));
    let _ = std::fs::remove_dir_all(&session_root);
    std::fs::create_dir_all(&session_root)?;

    println!("=== src-control · committed-secrets demo ===");
    let budget_bytes = args.budget_mb * 1024 * 1024;
    let repo = Repo::new(Store::new(StoreConfig {
        budget_bytes,
        backend: Backend::Ephemeral(SpillPolicy::Disallow),
    }));

    // Two identities, generated in RAM (never written to disk in this demo).
    let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
    let (mallory_sk, mallory_pk) = scl_crypto::generate_keypair();
    println!("alice   recipient: {}", alice_pk.recipient_id());
    println!("mallory recipient: {}", mallory_pk.recipient_id());

    // Base snapshot: one file + one secret sealed to ALICE only.
    let secret_value = b"postgres://app:s3cr3t@db.prod/main";
    let base = repo.commit_files(
        &[("README.md".into(), b"# app\n".to_vec(), FileMode::FILE)],
        "seed",
        "init",
    )?;
    let mut setup = repo.fork(base, "setup")?;
    setup.put_secret(scl_crypto::seal("DB_URL", secret_value, std::slice::from_ref(&alice_pk)))?;
    let snap = setup.commit("setup", "commit DB_URL")?;
    println!("\ncommitted secret DB_URL (wrapped to alice) in snapshot {}", snap.short());

    // 1) Unauthorized context: mallory cannot decrypt.
    println!("\n--- unauthorized context (mallory) ---");
    match run_with_secret(&repo, snap, "DB_URL", &mallory_sk) {
        Ok(v) => anyhow::bail!("SECURITY FAILURE: mallory decrypted DB_URL = {v:?}"),
        Err(e) => println!("mallory run -> DENIED ({e})"),
    }
    // The stored object is still ciphertext.
    let stored = {
        let id = repo.fork(snap, "probe")?.secret_id("DB_URL").unwrap();
        repo.store().lock().unwrap().get_secret(&id)?
    };
    assert_ne!(stored.ciphertext, secret_value, "stored value must be ciphertext");
    println!("stored DB_URL is ciphertext ({} bytes), not the plaintext ✔", stored.ciphertext.len());

    // 2) Authorized context: alice decrypts and injects into a child process.
    println!("\n--- authorized context (alice) ---");
    let got = run_with_secret(&repo, snap, "DB_URL", &alice_sk)?;
    assert_eq!(got.as_bytes(), secret_value, "alice's child must see the plaintext");
    println!("alice run -> child process read DB_URL = <{} bytes, matches> ✔", got.len());

    // Materialize alice's worktree to disk (under session_root): the file tree
    // is written, but the secret registry is NOT a file and must never appear.
    // This also makes the zero-residue teardown below non-vacuous: there is real
    // on-disk content to remove and re-verify.
    let checkout_dir = session_root.join("alice-checkout");
    repo.fork(snap, "alice-checkout")?.checkout(&checkout_dir)?;
    assert!(
        checkout_dir.join("README.md").exists(),
        "checkout must materialize the file tree"
    );
    assert!(
        !checkout_dir.join("DB_URL").exists(),
        "the secret must NOT be written as a file by checkout"
    );
    println!("checkout wrote the file tree but no DB_URL secret file ✔");

    // 3) Grant mallory by re-wrapping the DEK (no value rotation).
    println!("\n--- grant mallory (re-wrap DEK) ---");
    let granted = scl_crypto::rewrap_for(&stored, &alice_sk, &mallory_pk)?;
    assert_eq!(granted.ciphertext, stored.ciphertext, "grant must not rotate the value");
    let mut regrant = repo.fork(snap, "grant")?;
    regrant.put_secret(granted)?;
    let snap2 = regrant.commit("admin", "grant mallory")?;
    let got2 = run_with_secret(&repo, snap2, "DB_URL", &mallory_sk)?;
    assert_eq!(got2.as_bytes(), secret_value, "mallory should now decrypt");
    println!("mallory run after grant -> DB_URL decrypted ✔ (value not rotated)");

    // 4) Teardown + zero-residue proof: remove the session dir (which now holds
    // alice's real checkout from step 2) and verify nothing remains on disk.
    drop(setup);
    drop(repo);
    std::fs::remove_dir_all(&session_root).ok();
    let residue = session_root.exists();
    println!("\n=== teardown ===");
    if residue {
        anyhow::bail!("residual files left on disk at {}", session_root.display());
    }
    println!("RESULT: authorize/deny/grant proven; zero residual files on disk ✔");
    Ok(())
}

// ---- Persistent repo subcommand handlers -----------------------------------

fn open_repo() -> Result<scl_repo::Repo> {
    let cwd = std::env::current_dir()?;
    scl_repo::Repo::open(cwd).map_err(Into::into)
}

fn run_init() -> Result<()> {
    let repo = scl_repo::Repo::init(std::env::current_dir()?)?;
    println!("initialized empty src-control repo at {}", repo.layout().dot_sc.display());
    Ok(())
}

fn run_commit(author: &str, message: &str) -> Result<()> {
    let repo = open_repo()?;
    match repo.commit(author, message) {
        Ok(id) => {
            println!("committed {}", id.short());
            Ok(())
        }
        Err(scl_repo::Error::SecretDetected(report)) => {
            // Drop the repo (releases .sc/lock) before process::exit, which
            // skips destructors and would otherwise leave a stale lock file.
            drop(repo);
            eprint!("{report}");
            std::process::exit(1);
        }
        Err(e) => Err(e.into()),
    }
}

fn run_scan() -> Result<()> {
    let repo = open_repo()?;
    let report = repo.scan_worktree()?;
    if report.is_empty() {
        println!("scan clean (no secrets detected)");
        return Ok(());
    }
    // Drop the repo (releases .sc/lock) before process::exit, which skips
    // destructors and would otherwise leave a stale lock file.
    drop(repo);
    print!("{report}");
    std::process::exit(1);
}

fn run_status() -> Result<()> {
    let repo = open_repo()?;
    if repo.merge_in_progress() {
        println!("merge in progress; resolve and `sc commit` (or `sc merge --abort`):");
        let conflicts = repo.merge_conflicts()?;
        if conflicts.is_empty() {
            println!("  (all conflicts resolved — ready to `sc commit`)");
        } else {
            for p in conflicts {
                println!("  conflicted: {p}");
            }
        }
    }
    let s = repo.status()?;
    if s.added.is_empty() && s.modified.is_empty() && s.deleted.is_empty() {
        if !repo.merge_in_progress() {
            println!("clean (working tree matches HEAD)");
        }
        return Ok(());
    }
    for p in &s.added {
        println!("A  {p}");
    }
    for p in &s.modified {
        println!("M  {p}");
    }
    for p in &s.deleted {
        println!("D  {p}");
    }
    Ok(())
}

fn run_merge(branch: Option<String>, abort: bool, author: &str) -> Result<()> {
    let repo = open_repo()?;
    if abort {
        let skipped = repo.merge_abort()?;
        println!("merge aborted; working tree restored");
        for path in &skipped {
            eprintln!("skipped (no key): {path}");
        }
        return Ok(());
    }
    let branch = branch.ok_or_else(|| anyhow::anyhow!("merge: provide a branch or --abort"))?;
    match repo.merge(&branch, author) {
        Ok(id) => {
            println!("merged {branch}: {}", id.short());
            Ok(())
        }
        Err(scl_repo::Error::MergeConflicts(n)) => {
            println!("merge has {n} conflict(s); resolve these files then `sc commit`:");
            for p in repo.merge_conflicts()? {
                println!("  {p}");
            }
            Ok(()) // not an error exit; the user has work to do
        }
        Err(scl_repo::Error::UpToDate) => {
            println!("already up to date");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn run_log() -> Result<()> {
    let repo = open_repo()?;
    for (id, snap) in repo.log()? {
        println!("{} {} — {}", id.short(), snap.author, snap.message);
    }
    Ok(())
}

fn run_branch(name: &str) -> Result<()> {
    open_repo()?.branch(name)?;
    println!("created branch {name}");
    Ok(())
}

fn run_switch(name: &str, identity: Option<PathBuf>) -> Result<()> {
    let sk = resolve_identity_opt(identity)?;
    let skipped = open_repo()?.switch_with_identity(name, sk.as_ref())?;
    println!("switched to branch {name}");
    for path in &skipped {
        eprintln!("skipped (no key): {path}");
    }
    Ok(())
}

fn run_secret(op: SecretOp) -> Result<()> {
    let repo = open_repo()?;
    let recipients_path = repo.layout().dot_sc.join("recipients.toml");
    match op {
        SecretOp::Add { name, to, value } => {
            let dir = load_recipients(&recipients_path)?;
            let pks = resolve_names(&dir, &to)?;
            repo.secret_add(&name, value.as_bytes(), &pks)?;
            println!("added secret {name} for {} recipient(s)", to.len());
        }
        SecretOp::Grant { name, to, identity } => {
            let dir = load_recipients(&recipients_path)?;
            let pks = resolve_names(&dir, &to)?;
            let sk = load_identity(identity)?;
            for pk in &pks {
                repo.secret_grant(&name, &sk, pk)?;
            }
            println!("granted {name} to {} recipient(s)", to.len());
        }
        SecretOp::Revoke { name, recipient_id } => {
            let rid = scl_crypto::RecipientId::from_hex(&recipient_id)
                .map_err(|_| anyhow::anyhow!("bad recipient id"))?;
            repo.secret_revoke(&name, &rid)?;
            println!("revoked {recipient_id} from {name}");
            eprintln!("note: revoke is metadata-only; run `sc secret rotate {name}` for a cryptographic cutover");
        }
        SecretOp::List => {
            for info in repo.secret_list()? {
                println!("{}  ({} recipient(s))", info.name, info.recipients);
            }
        }
        SecretOp::Rotate { name, value, to, identity } => {
            let dir = load_recipients(&recipients_path)?;
            // Recipient set: explicit --to, else the secret's current recipients.
            let pks = if to.is_empty() {
                let ids = repo.secret_recipients(&name)?;
                let pool: Vec<scl_crypto::PublicKey> = dir.values().cloned().collect();
                resolve_ids_to_pubkeys(&ids, &pool)?
            } else {
                resolve_names(&dir, &to)?
            };
            let new_value = value.as_deref().map(|s| s.as_bytes());
            let identity = match &value {
                Some(_) => None, // sealing a new value needs no decryption
                None => Some(load_identity(identity)?),
            };
            repo.secret_rotate(&name, new_value, &pks, identity.as_ref())?;
            println!("rotated secret {name} for {} recipient(s)", pks.len());
            eprintln!("note: rotation cuts off future reads via the current registry; the old \
                       ciphertext stays in history and anyone holding the old DEK keeps it — \
                       rotate the underlying credential too");
        }
    }
    Ok(())
}

/// `sc escrow set/show`: configure (or display) the break-glass escrow
/// recipient in `.sc/recipients.toml`. Config only — auto-including the
/// escrow key at seal/protect time is a separate concern.
fn run_escrow(op: EscrowOp) -> Result<()> {
    let repo = open_repo()?;
    let path = repo.layout().dot_sc.join("recipients.toml");
    match op {
        EscrowOp::Set { key_or_name } => {
            // Accept a raw pubkey, else resolve a [recipients] name.
            let pk = match scl_crypto::PublicKey::from_key_string(&key_or_name) {
                Ok(pk) => pk,
                Err(_) => {
                    let dir = load_recipients(&path)?;
                    dir.get(&key_or_name).cloned().ok_or_else(|| {
                        anyhow::anyhow!("'{key_or_name}' is not a public key or a known recipient")
                    })?
                }
            };
            // Round-trip the file so [recipients] is preserved.
            let mut file: RecipientsFile = match std::fs::read_to_string(&path) {
                Ok(t) => toml::from_str(&t)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => RecipientsFile::default(),
                Err(e) => return Err(e.into()),
            };
            file.escrow = Some(EscrowEntry { key: pk.to_key_string() });
            std::fs::write(&path, toml::to_string(&file)?)?;
            println!("escrow set to {}", pk.recipient_id());
        }
        EscrowOp::Show => match load_escrow(&path)? {
            Some(pk) => {
                println!("escrow key: {}", pk.to_key_string());
                println!("recipient id: {}", pk.recipient_id());
                println!(
                    "note: escrow is a recovery *policy* convenience, not enforcement — a \
                     committer using the raw API can seal without it."
                );
            }
            None => println!("no escrow key set"),
        },
    }
    Ok(())
}

fn run_run(identity: Option<PathBuf>, cmd: Vec<String>) -> Result<()> {
    let repo = open_repo()?;
    let sk = load_identity(identity)?;
    let code = repo.run(&sk, &cmd)?;
    // `process::exit` skips destructors, so the repo's RepoLock would never run
    // its Drop and `.sc/lock` would leak — bricking the next `sc` command with a
    // spurious `Locked` error. Drop the repo (releasing the lock) before exiting.
    drop(repo);
    std::process::exit(code);
}

fn load_identity(flag: Option<PathBuf>) -> Result<scl_crypto::SecretKey> {
    let path = resolve_identity_path(flag);
    scl_crypto::FileKeyProvider::new(path).identity().map_err(Into::into)
}

/// Soft identity resolution for checkout/switch: a holder with no key must still
/// be able to switch (protected files are skipped). Returns `Ok(None)` when the
/// resolved path doesn't exist, `Ok(Some(..))` when it loads, and propagates the
/// error when a present file fails to parse.
fn resolve_identity_opt(flag: Option<PathBuf>) -> Result<Option<scl_crypto::SecretKey>> {
    let path = resolve_identity_path(flag);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(scl_crypto::FileKeyProvider::new(path).identity()?))
}

fn resolve_names(
    dir: &std::collections::BTreeMap<String, scl_crypto::PublicKey>,
    names: &[String],
) -> Result<Vec<scl_crypto::PublicKey>> {
    names
        .iter()
        .map(|n| dir.get(n).cloned().ok_or_else(|| anyhow::anyhow!("unknown recipient: {n}")))
        .collect()
}

/// Map current recipient ids back to public keys drawn from `pool`. Errors,
/// listing the unresolved ids, when a current recipient has no key in `pool`
/// (e.g. missing from `.sc/recipients.toml`) — we cannot re-wrap a key we lack.
fn resolve_ids_to_pubkeys(
    ids: &[scl_crypto::RecipientId],
    pool: &[scl_crypto::PublicKey],
) -> Result<Vec<scl_crypto::PublicKey>> {
    let mut out = Vec::with_capacity(ids.len());
    let mut unresolved = Vec::new();
    for id in ids {
        match pool.iter().find(|pk| pk.recipient_id().as_str() == id.as_str()) {
            Some(pk) => out.push(pk.clone()),
            None => unresolved.push(id.as_str().to_string()),
        }
    }
    if !unresolved.is_empty() {
        anyhow::bail!(
            "cannot rotate: no public key in .sc/recipients.toml for current recipient(s): {}",
            unresolved.join(", ")
        );
    }
    Ok(out)
}

fn run_clone(src: PathBuf, dst: PathBuf) -> Result<()> {
    let repo = scl_repo::Repo::clone_to(&src, &dst)?;
    let n = repo.branches()?.len();
    println!("cloned {} into {} ({} branch(es))", src.display(), dst.display(), n);
    Ok(())
}

fn run_remote(op: RemoteOp) -> Result<()> {
    let repo = open_repo()?;
    match op {
        RemoteOp::Add { name, url, git } => {
            if git {
                repo.remote_add_git(&name, &url)?;
                println!("added git remote {name} -> {url}");
            } else {
                repo.remote_add(&name, &url)?;
                println!("added remote {name} -> {url}");
            }
        }
        RemoteOp::List => {
            let cfg = scl_repo::RemoteConfig::load(repo.layout())?;
            for (name, url) in repo.remotes()? {
                let kind = match cfg.kind(&name) {
                    Some(scl_repo::RemoteKind::Git) => "git",
                    _ => "sc",
                };
                println!("{name}\t{url}\t[{kind}]");
            }
        }
    }
    Ok(())
}

/// Fetch from `remote`, dispatching on its configured kind: a `git`-kind
/// remote gets a full-history import into a remote-tracking ref (see
/// `run_fetch_git`); an `sc`-kind remote (or unconfigured, defaulting to `sc`)
/// uses the existing object-transport fetch.
fn run_fetch(remote: &str) -> Result<()> {
    let repo = open_repo()?;
    let cfg = scl_repo::RemoteConfig::load(repo.layout())?;
    match cfg.kind(remote) {
        Some(scl_repo::RemoteKind::Git) => run_fetch_git(&repo, remote),
        _ => {
            let remote_refs = repo.fetch(remote)?;
            println!("fetched {remote}: {} remote branch(es)", remote_refs.len());
            for (branch, tip) in remote_refs {
                println!("  {remote}/{branch} -> {}", tip.short());
            }
            Ok(())
        }
    }
}

/// Fetch a git-backed remote: import full history for the current branch into
/// `refs/remotes/<remote>/<branch>`, maintaining the marks map.
///
/// Atomicity order: import (object writes) happens first, then new marks are
/// appended, and the remote-tracking ref is written last. The ref is the
/// reachability root for gc, so a crash between marks and ref leaves only
/// gc-collectible orphans rather than a ref pointing at missing objects.
fn run_fetch_git(repo: &scl_repo::Repo, remote: &str) -> Result<()> {
    use std::collections::HashMap;
    let cfg = scl_repo::RemoteConfig::load(repo.layout())?;
    let url = cfg.url(remote).ok_or_else(|| anyhow::anyhow!("no such remote: {remote}"))?.to_string();
    let branch = scl_repo::refs::current_branch(repo.layout())?;

    // Known marks: git-oid-hex -> sc-id.
    let marks = scl_repo::MarksStore::open(repo.layout(), remote)?;
    let mut known: HashMap<String, scl_core::ObjectId> = HashMap::new();
    for (g, s) in marks.load()? {
        let id = s.parse().map_err(|_| anyhow::anyhow!("bad sc id in marks: {s}"))?;
        known.insert(g, id);
    }

    let report = {
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        scl_gitio::import_history(&mut store, std::path::Path::new(&url), &branch, &known)?
    };

    // Persist new marks first, then the reachability root (the tracking ref) last.
    let new: Vec<(String, String)> =
        report.new_marks.iter().map(|(g, s)| (g.clone(), s.to_hex().to_string())).collect();
    marks.append(&new)?;
    scl_repo::refs::write_remote_tip(repo.layout(), remote, &branch, &report.tip)?;

    println!(
        "fetched {remote} (git): {}/{branch} -> {} ({} new commit(s))",
        remote, report.tip.short(), report.new_marks.len()
    );
    Ok(())
}

fn run_push(remote: &str, include_encrypted: bool) -> Result<()> {
    let repo = open_repo()?;
    let cfg = scl_repo::RemoteConfig::load(repo.layout())?;
    match cfg.kind(remote) {
        Some(scl_repo::RemoteKind::Git) => run_push_git(&repo, remote, include_encrypted),
        _ => {
            let tip = repo.push(remote)?;
            println!("pushed to {remote}: {}", tip.short());
            Ok(())
        }
    }
}

/// Push the current branch to a git-backed remote, fast-forward-only. The
/// snapshot↔commit marks map carries identity so already-pushed commits are
/// reused, not rewritten.
///
/// Atomicity order: `export_branch` writes the git objects and advances the git
/// ref, then new marks are appended. A crash between export and `marks.append`
/// leaves git advanced but sc marks missing, so the next push sees a remote
/// commit it can't map and refuses "fetch first" — a safe refuse, not corruption.
fn run_push_git(repo: &scl_repo::Repo, remote: &str, include_encrypted: bool) -> Result<()> {
    use std::collections::HashMap;
    let cfg = scl_repo::RemoteConfig::load(repo.layout())?;
    let url = cfg.url(remote).ok_or_else(|| anyhow::anyhow!("no such remote: {remote}"))?.to_string();
    let branch = scl_repo::refs::current_branch(repo.layout())?;
    let ref_name = format!("refs/heads/{branch}");
    let local_tip = repo.head_tip()?.ok_or_else(|| anyhow::anyhow!("branch is unborn — nothing to push"))?;

    // Load marks both directions.
    let marks = scl_repo::MarksStore::open(repo.layout(), remote)?;
    let pairs = marks.load()?;
    let mut git_to_sc: HashMap<String, scl_core::ObjectId> = HashMap::new();
    let mut known_sc_to_git: HashMap<scl_core::ObjectId, String> = HashMap::new();
    for (g, s) in &pairs {
        let id: scl_core::ObjectId = s.parse().map_err(|_| anyhow::anyhow!("bad sc id in marks: {s}"))?;
        git_to_sc.insert(g.clone(), id);
        known_sc_to_git.insert(id, g.clone());
    }

    // Fast-forward gate against the remote git ref.
    if let Some(remote_git_hex) = scl_gitio::read_ref(std::path::Path::new(&url), &ref_name)? {
        match git_to_sc.get(&remote_git_hex) {
            Some(&remote_sc) if remote_sc == local_tip => {
                println!("push {remote} (git): already up to date");
                return Ok(());
            }
            Some(&remote_sc) => {
                let store_arc = repo.vfs().store();
                let mut store = store_arc.lock().unwrap();
                if !scl_repo::merge::is_ancestor(&mut store, remote_sc, local_tip)? {
                    anyhow::bail!("non-fast-forward: remote {remote}/{branch} has commits not in local history");
                }
            }
            None => {
                anyhow::bail!(
                    "non-fast-forward: remote {remote}/{branch} points at a commit sc has never seen ({}); fetch first",
                    &remote_git_hex[..12.min(remote_git_hex.len())]
                );
            }
        }
    }

    // Export (reusing known commits), then persist newly-written marks.
    let report = {
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let opts = scl_gitio::ExportOptions {
            to: std::path::Path::new(&url),
            ref_name: &ref_name,
            include_encrypted,
            known_git_commits: &known_sc_to_git,
        };
        scl_gitio::export_branch(&mut store, local_tip, &opts)?
    };
    let new: Vec<(String, String)> =
        report.new_marks.iter().map(|(g, s)| (g.clone(), s.to_hex().to_string())).collect();
    marks.append(&new)?;

    println!(
        "pushed {} commit(s) to {remote} (git) at {ref_name}: {}",
        report.new_marks.len(),
        &report.git_commit[..12.min(report.git_commit.len())]
    );
    if report.protected_blobs_as_ciphertext > 0 || report.secrets_dropped > 0 {
        eprintln!(
            "  warning: {} protected file(s) pushed as ciphertext; {} secret(s) dropped (Git cannot enforce confidentiality)",
            report.protected_blobs_as_ciphertext, report.secrets_dropped
        );
    }
    Ok(())
}

fn run_protect(prefix: Option<String>, to: Vec<String>, list: bool) -> Result<()> {
    let repo = open_repo()?;
    if list || prefix.is_none() {
        for (p, recips) in repo.protected_prefixes()? {
            println!("{p}  ({} recipient(s))", recips.len());
        }
        return Ok(());
    }
    let prefix = prefix.unwrap();
    let dir = load_recipients(&repo.layout().dot_sc.join("recipients.toml"))?;
    let pks = resolve_names(&dir, &to)?;
    let id = repo.protect(&prefix, &pks, None)?;
    println!("protected {prefix} for {} recipient(s): {}", to.len(), id.short());
    Ok(())
}

fn run_grant(prefix: String, to: Vec<String>, identity: Option<PathBuf>) -> Result<()> {
    let repo = open_repo()?;
    let dir = load_recipients(&repo.layout().dot_sc.join("recipients.toml"))?;
    let pks = resolve_names(&dir, &to)?;
    let sk = load_identity(identity)?;
    for pk in &pks {
        repo.grant(&prefix, &sk, pk)?;
    }
    println!("granted {prefix} to {} recipient(s)", to.len());
    Ok(())
}

fn run_revoke(prefix: String, recipient_id: String) -> Result<()> {
    let repo = open_repo()?;
    let rid = scl_crypto::RecipientId::from_hex(&recipient_id)
        .map_err(|_| anyhow::anyhow!("bad recipient id"))?;
    repo.revoke(&prefix, &rid)?;
    println!("revoked {recipient_id} from {prefix}");
    Ok(())
}

fn run_export(to: PathBuf, ref_name: Option<String>, include_encrypted: bool) -> Result<()> {
    let repo = open_repo()?;
    let branch = scl_repo::refs::current_branch(repo.layout())?;
    let tip = repo
        .head_tip()?
        .ok_or_else(|| anyhow::anyhow!("branch is unborn — nothing to export"))?;
    let ref_name = ref_name.unwrap_or_else(|| format!("refs/heads/{branch}"));

    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();
    let known: std::collections::HashMap<scl_core::ObjectId, String> = std::collections::HashMap::new();
    let opts = scl_gitio::ExportOptions { to: &to, ref_name: &ref_name, include_encrypted, known_git_commits: &known };
    let report = scl_gitio::export_branch(&mut store, tip, &opts)?;

    println!(
        "exported {} commit(s) to {} at {} ({})",
        report.commits_written,
        to.display(),
        ref_name,
        &report.git_commit[..12.min(report.git_commit.len())]
    );
    if report.protected_blobs_as_ciphertext > 0 || report.secrets_dropped > 0 {
        eprintln!(
            "  warning: {} protected file(s) exported as ciphertext; {} secret(s) dropped (Git cannot enforce confidentiality)",
            report.protected_blobs_as_ciphertext, report.secrets_dropped
        );
    }
    Ok(())
}

/// Parse a duration like `24h`, `30m`, `45s`, `7d` into a `std::time::Duration`.
/// Bare-number (no suffix) is rejected to avoid ambiguity.
fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => anyhow::bail!("duration needs a unit suffix s/m/h/d, got {s:?}"),
    };
    let n: u64 = num.parse().map_err(|_| anyhow::anyhow!("bad duration number: {s:?}"))?;
    let secs = n.checked_mul(mult).ok_or_else(|| anyhow::anyhow!("duration too large: {s:?}"))?;
    Ok(std::time::Duration::from_secs(secs))
}

fn run_gc(prune_expire: &str) -> Result<()> {
    let grace = parse_duration(prune_expire)?;
    let repo = open_repo()?;
    let stats = repo.gc(grace)?;
    println!(
        "gc: packed {} object(s), pruned {} loose, kept {} recent, removed {} old pack(s)",
        stats.packed, stats.loose_pruned, stats.loose_kept, stats.packs_removed
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn parses_suffixed_durations() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(24 * 3600));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(7 * 86400));
        assert!(parse_duration("nope").is_err());
        assert!(parse_duration("7").is_err());
    }

    #[test]
    fn loads_recipients_from_toml() {
        let (_sk, pk) = scl_crypto::generate_keypair();
        let dir = std::env::temp_dir().join(format!("scl-recip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recipients.toml");
        std::fs::write(
            &path,
            format!("[recipients]\nalice = \"{}\"\n", pk.to_key_string()),
        )
        .unwrap();

        let map = load_recipients(&path).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map["alice"].to_bytes(), pk.to_bytes());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_identity_opt_covers_missing_valid_and_corrupt() {
        let dir = std::env::temp_dir().join(format!("scl-ident-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Absent file → None (keyless holders still switch; protected files skip).
        let missing = dir.join("nope");
        assert!(resolve_identity_opt(Some(missing)).unwrap().is_none());

        // Present + valid → Some, round-trips to the same key.
        let (sk, _pk) = scl_crypto::generate_keypair();
        let key_path = dir.join("identity");
        std::fs::write(&key_path, sk.to_key_string()).unwrap();
        let loaded = resolve_identity_opt(Some(key_path)).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().to_key_string(), sk.to_key_string());

        // Present + corrupt → Err. This is the safety property the soft loader
        // exists for: a malformed key must NOT be silently treated as keyless
        // (which would skip protected files for a user who actually holds a key).
        let corrupt = dir.join("corrupt");
        std::fs::write(&corrupt, b"not a real scl-sk- key").unwrap();
        assert!(resolve_identity_opt(Some(corrupt)).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
