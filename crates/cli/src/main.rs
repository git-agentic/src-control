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
        /// Author recorded on the snapshot (default: $SC_AUTHOR, then the OS
        /// username).
        #[arg(long)]
        author: Option<String>,
    },
    /// Replace the tip commit with one built from the current working tree.
    /// Parents are kept from the tip (merge and root commits amend
    /// naturally); the message is kept unless `-m` overrides it. Refuses
    /// while unborn or while a merge/pick/rebase is in progress.
    Amend {
        /// New message; omit to keep the tip's existing message.
        #[arg(short, long)]
        message: Option<String>,
        /// Author recorded on the amended snapshot (default: $SC_AUTHOR,
        /// then the OS username).
        #[arg(long)]
        author: Option<String>,
    },
    /// Show working-tree changes against HEAD.
    Status {
        /// Emit machine-readable JSON instead of the human listing.
        #[arg(long)]
        json: bool,
    },
    /// Show line-level working-tree changes against HEAD (unified diff).
    Diff,
    /// Show commit history from HEAD.
    Log {
        /// Emit machine-readable JSON instead of the human listing.
        #[arg(long)]
        json: bool,
    },
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
    /// On conflicts this command prints the conflicted files and exits 1 — the
    /// working tree is left with conflict markers and a merge in progress, so
    /// `sc merge x && sc commit` cannot commit the markers. Resolve, then
    /// `sc commit` (or `sc merge --abort`).
    Merge {
        /// Branch to merge in.
        branch: Option<String>,
        /// Abandon an in-progress merge and restore the working tree. When given,
        /// the BRANCH argument is ignored.
        #[arg(long)]
        abort: bool,
        /// Author recorded on the merge snapshot (default: $SC_AUTHOR, then the
        /// OS username).
        #[arg(long)]
        author: Option<String>,
        /// Identity key to decrypt protected paths that diverged in content on
        /// both sides (ciphertext-id fast paths need no identity at all).
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Replay one commit from another branch onto the current branch.
    ///
    /// On conflicts this behaves like `sc merge`: markers + a pick in
    /// progress are left on disk (exit 1), resolve then `sc commit`.
    CherryPick {
        /// Branch or remote-tracking ref whose tip commit to pick.
        #[arg(value_name = "ref", conflicts_with = "abort")]
        refname: Option<String>,
        /// Abandon an in-progress cherry-pick and restore the working tree.
        #[arg(long, conflicts_with_all = ["refname", "mainline"])]
        abort: bool,
        /// Replay a merge commit relative to its Nth parent (1-based); required
        /// when the picked commit is a merge, refused otherwise.
        #[arg(long)]
        mainline: Option<u32>,
        /// Commit author (default $SC_AUTHOR, then the OS username).
        #[arg(long)]
        author: Option<String>,
        /// Identity key to decrypt protected paths that diverged in content on
        /// both sides (ciphertext-id fast paths need no identity at all).
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Replay the current branch's commits onto another branch's tip.
    ///
    /// A conflict STOPS the rebase (exit 1): P4-style markers are left on
    /// disk and the branch ref does not move — resolve then
    /// `sc rebase --continue`, or `sc rebase --abort` to give up and restore
    /// the pre-rebase tree. A resumed rebase (any number of stops) still
    /// collapses into a single `sc undo`-able operation.
    Rebase {
        /// Branch or remote-tracking ref to rebase onto.
        target: Option<String>,
        /// Resume a stopped rebase after resolving conflicts.
        #[arg(long, conflicts_with = "target")]
        r#continue: bool,
        /// Abandon a stopped rebase; restores the pre-rebase working tree.
        #[arg(long, conflicts_with_all = ["target", "continue"])]
        abort: bool,
        /// Commit author (default $SC_AUTHOR, then the OS username).
        #[arg(long)]
        author: Option<String>,
        /// Identity key to decrypt protected paths that diverged in content on
        /// both sides (ciphertext-id fast paths need no identity at all).
        #[arg(long)]
        identity: Option<PathBuf>,
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
    /// Fork N agent workspaces from HEAD, run a command in each, and harvest
    /// changed workspaces to `<name>-<i>` branches.
    Work {
        /// Number of workspaces to fork.
        #[arg(long, default_value_t = 2)]
        agents: usize,
        /// Branch/label base name (branches are `<name>-1..N`).
        #[arg(long, default_value = "work")]
        name: String,
        /// Memory budget for the session's shared object cache, in MiB.
        #[arg(long)]
        budget_mb: Option<usize>,
        /// Decrypt registered secrets and inject them into each agent's env.
        #[arg(long)]
        with_secrets: bool,
        /// Identity file (protected-path checkout and --with-secrets;
        /// default ~/.sc/identity or $SC_IDENTITY).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Commit author for harvested branches (default $SC_AUTHOR, then the
        /// OS username).
        #[arg(long)]
        author: Option<String>,
        /// Agent command and args after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Manage a durable `sc ws` session: workspaces forked from HEAD that
    /// survive the process exiting (unlike `sc work`'s one-shot session).
    Ws {
        #[command(subcommand)]
        op: WsOp,
    },
    /// Clone a repo (local path or `ssh://` URL) into a new directory.
    Clone {
        src: String,
        dst: PathBuf,
        /// Force cloning via the system-git mirror bridge. Unambiguous git
        /// URL forms (https/http, scp-style `git@host:path`, file://) are
        /// auto-detected and need no flag; `--git` is only required for
        /// `ssh://` git hosts, because bare `ssh://` already means an
        /// sc-native remote (ADR-0022/ADR-0028).
        #[arg(long)]
        git: bool,
    },
    /// Serve a repo over stdin/stdout to a remote `sc` client (invoked by
    /// `ssh` for ssh:// remotes; not intended for interactive use).
    Serve {
        /// Speak the wire protocol on stdin/stdout (required; the only mode).
        #[arg(long)]
        stdio: bool,
        /// Repo root to serve (the directory containing `.sc/`).
        path: PathBuf,
    },
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
        /// Machine-readable output for --list.
        #[arg(long)]
        json: bool,
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
    /// Re-seal every secret and protected file's wrap list at the tip to the
    /// current recipient + escrow sets, in one undoable commit.
    Rewrap {
        /// Identity able to open the entries being re-wrapped.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Report what would be re-wrapped without committing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Revert the last operation (run again to redo).
    Undo,
    /// List recent operations, newest first.
    Oplog,
}

#[derive(Subcommand)]
enum EscrowOp {
    /// Replace the whole escrow list with this one key (back-compat sugar).
    Set { key_or_name: String },
    /// Append a key to the escrow list (deduped).
    Add { key_or_name: String },
    /// Remove one escrow key by recipient id or [recipients] name.
    Remove { id_or_name: String },
    /// List the configured escrow keys.
    Show,
}

#[derive(Subcommand)]
enum WsOp {
    /// Fork N durable workspaces from HEAD under `.sc/ws/<i>/`.
    Fork {
        /// Number of workspaces to fork.
        #[arg(long, default_value_t = 2)]
        agents: u32,
        /// Identity file to decrypt protected paths at checkout (default
        /// ~/.sc/identity or $SC_IDENTITY; optional — unmatched protected
        /// paths are just skipped).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Author recorded on any commit a later harvest produces (default
        /// $SC_AUTHOR, then the OS username).
        #[arg(long)]
        author: Option<String>,
    },
    /// List the open session's workspaces (changed/unchanged vs base).
    List,
    /// Run a command in one workspace checkout.
    Run {
        /// Workspace index to run in.
        index: u32,
        /// Decrypt and inject registered secrets into the command's environment
        /// (requires --identity to be set).
        #[arg(long)]
        with_secrets: bool,
        /// Identity for --with-secrets decryption.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// The command to run; `--` separates it from flags.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Abandon one workspace (by index) or the whole session.
    Abandon {
        /// Workspace index to abandon. Omit to abandon the whole session.
        index: Option<u32>,
    },
    /// Read-only conflict probe + cumulative auto-merge of every live
    /// workspace onto the landing branch (default: the session's base
    /// branch). Conflicted/rejected workspaces fall back to a `work-<i>`
    /// branch for manual resolution and keep the session open.
    Harvest {
        /// Landing branch; must be the currently-checked-out branch
        /// (default: the session's base branch).
        #[arg(long)]
        into: Option<String>,
        /// Identity key to decrypt protected paths that diverged in content
        /// on both sides (ciphertext-id fast paths need no identity at all).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Author recorded on any landing commit (default $SC_AUTHOR, then
        /// the OS username).
        #[arg(long)]
        author: Option<String>,
    },
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
        /// visible in process args (e.g. `ps`) and shell history. Omit it to
        /// read the value from stdin instead (trailing newline trimmed).
        #[arg(long)]
        value: Option<String>,
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
    List {
        /// Emit machine-readable JSON instead of the human listing.
        #[arg(long)]
        json: bool,
    },
    /// Rotate a secret's value under a fresh DEK (the cryptographic cutover that
    /// revoke does not perform). With --value, seal a new value (no identity
    /// needed); without, recover the current value with --identity and re-seal it.
    /// Recipients default to the secret's current set; --to overrides.
    Rotate {
        name: String,
        /// New value. Omit to keep the current value (requires --identity).
        /// WARNING: visible in process args and shell history — prefer
        /// --value-stdin for a new value.
        #[arg(long)]
        value: Option<String>,
        /// Read the new value from stdin (trailing newline trimmed), keeping
        /// it out of process args and shell history.
        #[arg(long, conflicts_with = "value")]
        value_stdin: bool,
        /// Recipient names (default: the secret's current recipients).
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// Your identity (required when no new value is given, to recover the
        /// current value).
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
        Cmd::Commit { message, author } => run_commit(&resolve_author(author), &message),
        Cmd::Amend { message, author } => run_amend(&resolve_author(author), message),
        Cmd::Status { json } => run_status(json),
        Cmd::Diff => run_diff(),
        Cmd::Log { json } => run_log(json),
        Cmd::Branch { name } => run_branch(&name),
        Cmd::Switch { name, identity } => run_switch(&name, identity),
        Cmd::Scan => run_scan(),
        Cmd::Merge { branch, abort, author, identity } => {
            run_merge(branch, abort, &resolve_author(author), identity)
        }
        Cmd::CherryPick { refname, abort, mainline, author, identity } => {
            run_cherry_pick(refname, abort, mainline, &resolve_author(author), identity)
        }
        Cmd::Rebase { target, r#continue, abort, author, identity } => {
            run_rebase(target, r#continue, abort, &resolve_author(author), identity)
        }
        Cmd::Secret { op } => run_secret(op),
        Cmd::Run { identity, cmd } => run_run(identity, cmd),
        Cmd::Work { agents, name, budget_mb, with_secrets, identity, author, cmd } => {
            run_work(agents, name, budget_mb, with_secrets, identity, author, cmd)
        }
        Cmd::Ws { op } => run_ws(op),
        Cmd::Clone { src, dst, git } => run_clone(src, dst, git),
        Cmd::Serve { stdio, path } => run_serve(stdio, path),
        Cmd::Remote { op } => run_remote(op),
        Cmd::Fetch { remote } => run_fetch(&remote),
        Cmd::Push { remote, include_encrypted } => run_push(&remote, include_encrypted),
        Cmd::Protect { prefix, to, list, json } => run_protect(prefix, to, list, json),
        Cmd::Grant { prefix, to, identity } => run_grant(prefix, to, identity),
        Cmd::Revoke { prefix, recipient_id } => run_revoke(prefix, recipient_id),
        Cmd::Gc { prune_expire } => run_gc(&prune_expire),
        Cmd::Export { to, r#ref, include_encrypted } => run_export(to, r#ref, include_encrypted),
        Cmd::Escrow { op } => run_escrow(op),
        Cmd::Rewrap { identity, dry_run } => run_rewrap(identity, dry_run),
        Cmd::Undo => run_undo(),
        Cmd::Oplog => run_oplog(),
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
/// optional `[escrow]` break-glass keys auto-included at seal/protect time.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct RecipientsFile {
    #[serde(default)]
    recipients: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    escrow: Option<EscrowSection>,
}

/// The `[escrow]` section: historically a single `key = "scl-pk-…"`, now a
/// `keys = […]` list. Both forms parse; writes always emit `keys` (P17).
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct EscrowSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    keys: Vec<String>,
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

/// All configured escrow public keys (old `key` + new `keys`, deduped, in
/// file order). Missing file or section → empty vec.
fn load_escrows(path: &std::path::Path) -> Result<Vec<scl_crypto::PublicKey>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let parsed: RecipientsFile = toml::from_str(&text)?;
    let Some(section) = parsed.escrow else { return Ok(Vec::new()) };
    let mut out: Vec<scl_crypto::PublicKey> = Vec::new();
    for k in section.key.iter().chain(section.keys.iter()) {
        let pk = scl_crypto::PublicKey::from_key_string(k)
            .map_err(|_| anyhow::anyhow!("bad escrow public key"))?;
        if !out.iter().any(|e| e.recipient_id() == pk.recipient_id()) {
            out.push(pk);
        }
    }
    Ok(out)
}

/// Write escrow keys to `.sc/recipients.toml`, normalizing to the `keys` list
/// form (never `key`). Preserves `[recipients]`. Removes `[escrow]` if empty.
fn write_escrow_keys(path: &std::path::Path, keys: Vec<scl_crypto::PublicKey>) -> Result<()> {
    let mut file: RecipientsFile = match std::fs::read_to_string(path) {
        Ok(t) => toml::from_str(&t)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RecipientsFile::default(),
        Err(e) => return Err(e.into()),
    };
    file.escrow = if keys.is_empty() {
        None
    } else {
        Some(EscrowSection {
            key: None,
            keys: keys.iter().map(|k| k.to_key_string()).collect(),
        })
    };
    std::fs::write(path, toml::to_string(&file)?)?;
    Ok(())
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

fn run_amend(author: &str, message: Option<String>) -> Result<()> {
    let repo = open_repo()?;
    let old = repo.head_tip()?;
    match repo.amend(author, message.as_deref()) {
        Ok(id) => {
            let old_short = old.map(|o| o.short()).unwrap_or_else(|| "?".to_string());
            println!("amended {} -> {}", old_short, id.short());
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

fn run_status(json: bool) -> Result<()> {
    let repo = open_repo()?;
    if json {
        let s = repo.status()?;
        println!(
            "{}",
            serde_json::json!({
                "added": s.added,
                "modified": s.modified,
                "deleted": s.deleted,
                "merge_in_progress": repo.merge_in_progress(),
                "conflicts": repo.merge_conflicts()?,
                "pick_in_progress": repo.pick_in_progress(),
                "rebase_in_progress": repo.rebase_in_progress(),
                "rebase_resolved": repo.rebase_resolved()?,
            })
        );
        return Ok(());
    }
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
    if repo.pick_in_progress() {
        if let Some(id) = repo.pick_head()? {
            println!("cherry-pick in progress: {}", id.short());
        }
    }
    if repo.rebase_in_progress() {
        if let Some((conflicted, done, total)) = repo.rebase_progress()? {
            if repo.rebase_resolved()? {
                // P21: the conflicted commit is already completed on disk —
                // a prior `--continue` landed it but the fold over the
                // remaining commits then errored (e.g. a later commit needs
                // `--identity`). Nothing to resolve here; just re-run
                // `--continue`, distinct from the "stopped at X" window
                // below where conflict markers are still on disk.
                println!(
                    "rebase in progress: conflict resolved — run 'sc rebase --continue' ({} of {})",
                    done + 1,
                    total
                );
            } else {
                println!(
                    "rebase in progress: stopped at {} ({} of {}); resolve conflicts then 'sc rebase --continue', or 'sc rebase --abort'",
                    conflicted.short(),
                    done + 1,
                    total
                );
            }
        }
    }
    let s = repo.status()?;
    if s.added.is_empty() && s.modified.is_empty() && s.deleted.is_empty() {
        if !repo.merge_in_progress() && !repo.pick_in_progress() && !repo.rebase_in_progress() {
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

fn run_merge(branch: Option<String>, abort: bool, author: &str, identity: Option<PathBuf>) -> Result<()> {
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
    let sk = resolve_identity_opt(identity)?;
    match repo.merge_with_identity(&branch, author, sk.as_ref()) {
        Ok((id, skipped)) => {
            println!("merged {branch}: {}", id.short());
            for path in &skipped {
                eprintln!("skipped (no key): {path}");
            }
            Ok(())
        }
        Err(scl_repo::Error::MergeConflicts(n)) => {
            println!("merge has {n} conflict(s); resolve these files then `sc commit`:");
            for p in repo.merge_conflicts()? {
                println!("  {p}");
            }
            // Exit 1 so `sc merge x && sc commit` can't commit conflict markers.
            // Drop the repo first (releases .sc/lock) — process::exit skips
            // destructors and would otherwise leave a stale lock file.
            drop(repo);
            std::process::exit(1);
        }
        Err(scl_repo::Error::UpToDate) => {
            println!("already up to date");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn run_cherry_pick(
    refname: Option<String>,
    abort: bool,
    mainline: Option<u32>,
    author: &str,
    identity: Option<PathBuf>,
) -> Result<()> {
    let repo = open_repo()?;
    if abort {
        let skipped = repo.cherry_pick_abort()?;
        println!("cherry-pick aborted; working tree restored");
        for path in &skipped {
            eprintln!("skipped (no key): {path}");
        }
        return Ok(());
    }
    let refname =
        refname.ok_or_else(|| anyhow::anyhow!("cherry-pick needs a ref or --abort"))?;
    // Soft-resolve like `run_merge`: a missing identity file is fine —
    // ciphertext-id fast paths and plain picks need no identity at all.
    let sk = resolve_identity_opt(identity)?;
    match repo.cherry_pick(&refname, author, sk.as_ref(), mainline) {
        Ok(scl_repo::PickResult::Picked(id)) => {
            println!("picked {}", id.short());
            Ok(())
        }
        Ok(scl_repo::PickResult::AlreadyApplied) => {
            println!("already applied — nothing to do");
            Ok(())
        }
        Err(scl_repo::Error::PickConflicts(n)) => {
            println!("cherry-pick has {n} conflict(s); resolve these files then `sc commit`:");
            for p in repo.pick_conflicts()? {
                println!("  {p}");
            }
            // Exit 1 so `sc cherry-pick x && sc commit` can't commit conflict markers.
            // Drop the repo first (releases .sc/lock) — process::exit skips
            // destructors and would otherwise leave a stale lock file.
            drop(repo);
            std::process::exit(1);
        }
        Err(e) => Err(e.into()),
    }
}

fn run_rebase(
    target: Option<String>,
    r#continue: bool,
    abort: bool,
    author: &str,
    identity: Option<PathBuf>,
) -> Result<()> {
    let repo = open_repo()?;
    if abort {
        let skipped = repo.rebase_abort()?;
        println!("rebase aborted; working tree restored");
        for path in &skipped {
            eprintln!("skipped (no key): {path}");
        }
        return Ok(());
    }
    // Soft-resolve like `run_merge`/`run_cherry_pick`: a missing identity file
    // is fine — ciphertext-id fast paths and plain rebases need no identity.
    let sk = resolve_identity_opt(identity)?;
    let outcome = if r#continue {
        repo.rebase_continue(author, sk.as_ref())
    } else {
        let target = target
            .ok_or_else(|| anyhow::anyhow!("rebase needs a target, --continue, or --abort"))?;
        repo.rebase(&target, author, sk.as_ref())
    };
    match outcome {
        Ok(scl_repo::RebaseResult::AlreadyUpToDate) => {
            println!("already up to date");
            Ok(())
        }
        Ok(scl_repo::RebaseResult::FastForwarded(id)) => {
            println!("fast-forwarded to {}", id.short());
            Ok(())
        }
        Ok(scl_repo::RebaseResult::Rebased { new_tip, replayed, skipped }) => {
            println!("rebased: {replayed} replayed, {skipped} skipped, tip {}", new_tip.short());
            Ok(())
        }
        Ok(scl_repo::RebaseResult::Stopped { conflicted, paths, done, total }) => {
            println!(
                "rebase stopped at {} ({} of {}) with {} conflict(s); resolve these files then `sc rebase --continue`:",
                conflicted.short(),
                done + 1,
                total,
                paths.len()
            );
            for p in &paths {
                println!("  {p}");
            }
            // Exit 1 so `sc rebase x && sc commit` can't commit conflict
            // markers — mirrors `run_merge`/`run_cherry_pick`. Drop the repo
            // first (releases .sc/lock) — process::exit skips destructors.
            drop(repo);
            std::process::exit(1);
        }
        Err(e) => Err(e.into()),
    }
}

fn run_log(json: bool) -> Result<()> {
    let repo = open_repo()?;
    let entries = repo.log()?;
    if json {
        let arr: Vec<serde_json::Value> = entries
            .iter()
            .map(|(id, snap)| {
                serde_json::json!({
                    "id": id.to_hex(),
                    "author": snap.author,
                    "timestamp": snap.timestamp,
                    "message": snap.message,
                    "parents": snap.parents.iter().map(|p| p.to_hex()).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
        return Ok(());
    }
    for (id, snap) in entries {
        let merge = if snap.parents.len() > 1 { " (merge)" } else { "" };
        println!(
            "{} {} {} — {}{}",
            id.short(),
            fmt_utc(snap.timestamp),
            snap.author,
            snap.message,
            merge
        );
    }
    Ok(())
}

/// Show line-level working-tree changes against HEAD.
fn run_diff() -> Result<()> {
    let repo = open_repo()?;
    print!("{}", repo.diff_unified()?);
    Ok(())
}

/// Resolve the commit/merge author: explicit `--author`, then `$SC_AUTHOR`,
/// then the OS username, then the historical `"you"` placeholder.
fn resolve_author(flag: Option<String>) -> String {
    flag.or_else(|| std::env::var("SC_AUTHOR").ok().filter(|s| !s.trim().is_empty()))
        .or_else(|| std::env::var("USER").ok().filter(|s| !s.trim().is_empty()))
        .or_else(|| std::env::var("USERNAME").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "you".to_string())
}

/// Unix seconds → `YYYY-MM-DD HH:MM` UTC, no chrono dependency (civil-from-days
/// per Howard Hinnant's algorithm).
fn fmt_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, secs / 3600, (secs % 3600) / 60)
}

fn run_branch(name: &str) -> Result<()> {
    open_repo()?.branch(name)?;
    println!("created branch {name}");
    Ok(())
}

fn run_undo() -> Result<()> {
    let outcome = open_repo()?.undo()?;
    println!("undid: {}", outcome.desc);
    for path in &outcome.skipped {
        eprintln!("skipped (no key): {path}");
    }
    Ok(())
}

fn run_oplog() -> Result<()> {
    let repo = open_repo()?;
    for rec in repo.oplog()?.iter().rev() {
        println!("{:>4}  {}  {}", rec.seq, fmt_utc(rec.ts), rec.desc);
    }
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
            let value = match value {
                Some(v) => v,
                None => read_value_from_stdin()?,
            };
            let dir = load_recipients(&recipients_path)?;
            let mut pks = resolve_names(&dir, &to)?;
            let escrows = load_escrows(&recipients_path)?;
            pks = append_escrow(pks, &escrows);
            repo.secret_add(&name, value.as_bytes(), &pks)?;
            println!("added secret {name} for {} recipient(s)", pks.len());
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
            eprintln!("hint: run `sc secret rotate {name} --identity <key>` for a cryptographic cutover of this secret, or `sc rewrap` to re-seal everything at once");
        }
        SecretOp::List { json } => {
            let infos = repo.secret_list()?;
            if json {
                let arr: Vec<serde_json::Value> = infos
                    .iter()
                    .map(|i| serde_json::json!({"name": i.name, "recipients": i.recipients}))
                    .collect();
                println!("{}", serde_json::Value::Array(arr));
            } else {
                for info in infos {
                    println!("{}  ({} recipient(s))", info.name, info.recipients);
                }
            }
        }
        SecretOp::Rotate { name, value, value_stdin, to, identity } => {
            let value = match (value, value_stdin) {
                (v @ Some(_), _) => v,
                (None, true) => Some(read_value_from_stdin()?),
                (None, false) => None,
            };
            let dir = load_recipients(&recipients_path)?;
            let escrows = load_escrows(&recipients_path)?;
            // Recipient set: explicit --to, else the secret's current recipients.
            let pks = if to.is_empty() {
                let ids = repo.secret_recipients(&name)?;
                // Pool = named recipients + escrow, so an escrow-only id resolves.
                let mut pool: Vec<scl_crypto::PublicKey> = dir.values().cloned().collect();
                pool.extend(escrows.iter().cloned());
                resolve_ids_to_pubkeys(&ids, &pool)?
            } else {
                resolve_names(&dir, &to)?
            };
            let pks = append_escrow(pks, &escrows);
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

/// `sc escrow set/add/remove/show`: manage the break-glass escrow recipient
/// keys in `.sc/recipients.toml`. Config only — auto-including the escrow
/// keys at seal/protect time is a separate concern.
fn run_escrow(op: EscrowOp) -> Result<()> {
    let repo = open_repo()?;
    let path = repo.layout().dot_sc.join("recipients.toml");

    // Helper to resolve a public-key-or-name string to a PublicKey.
    let resolve_pubkey = |s: &str| -> Result<scl_crypto::PublicKey> {
        match scl_crypto::PublicKey::from_key_string(s) {
            Ok(pk) => Ok(pk),
            Err(_) => {
                let dir = load_recipients(&path)?;
                dir.get(s)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("'{s}' is not a public key or a known recipient"))
            }
        }
    };

    match op {
        EscrowOp::Set { key_or_name } => {
            let pk = resolve_pubkey(&key_or_name)?;
            write_escrow_keys(&path, vec![pk.clone()])?;
            println!("escrow set to {}", pk.recipient_id());
        }
        EscrowOp::Add { key_or_name } => {
            let pk = resolve_pubkey(&key_or_name)?;
            let mut keys = load_escrows(&path)?;
            keys = append_escrow(keys, &[pk.clone()]);
            write_escrow_keys(&path, keys.clone())?;
            println!("escrow key added: {} ({} total)", pk.recipient_id(), keys.len());
        }
        EscrowOp::Remove { id_or_name } => {
            // Try parsing as a recipient id; if that fails, look it up in [recipients].
            let target_id = match scl_crypto::RecipientId::from_hex(&id_or_name) {
                Ok(rid) => rid,
                Err(_) => {
                    let dir = load_recipients(&path)?;
                    dir.get(&id_or_name)
                        .ok_or_else(|| anyhow::anyhow!("'{id_or_name}' is not an escrow key"))?
                        .recipient_id()
                }
            };
            let keys = load_escrows(&path)?;
            let before_count = keys.len();
            let keys: Vec<_> = keys
                .into_iter()
                .filter(|k| k.recipient_id() != target_id)
                .collect();
            if keys.len() == before_count {
                return Err(anyhow::anyhow!("'{id_or_name}' is not an escrow key"));
            }
            write_escrow_keys(&path, keys.clone())?;
            println!("escrow key removed: {} ({} remain)", target_id, keys.len());
        }
        EscrowOp::Show => {
            let keys = load_escrows(&path)?;
            if keys.is_empty() {
                println!("no escrow keys set");
            } else {
                for pk in keys {
                    println!("{}: {}", pk.to_key_string(), pk.recipient_id());
                }
            }
            println!(
                "note: escrow is a recovery *policy* convenience, not enforcement — a \
                 committer using the raw API can seal without it."
            );
        }
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

/// `sc work`: one-command agent-workspace session. Prints a per-workspace
/// summary; exits non-zero if any agent failed or any harvest was rejected.
fn run_work(
    agents: usize,
    name: String,
    budget_mb: Option<usize>,
    with_secrets: bool,
    identity: Option<PathBuf>,
    author: Option<String>,
    cmd: Vec<String>,
) -> Result<()> {
    let repo = match budget_mb {
        Some(mb) => scl_repo::Repo::open_with_budget(std::env::current_dir()?, mb * 1024 * 1024)?,
        None => open_repo()?,
    };
    // --with-secrets needs a loadable identity (hard error); otherwise the
    // identity is optional and only decrypts protected paths at checkout.
    let sk = if with_secrets {
        Some(load_identity(identity)?)
    } else {
        resolve_identity_opt(identity)?
    };
    let outcomes = repo.work(scl_repo::WorkOptions {
        agents,
        base_name: name,
        cmd,
        author: resolve_author(author),
        message: None,
        identity: sk,
        with_secrets,
        session_root: None,
    })?;

    let mut failed = false;
    println!("workspace        agent   result");
    for o in &outcomes {
        let agent = match o.agent_exit {
            Some(0) => "ok".to_string(),
            Some(code) => {
                failed = true;
                format!("exit {code}")
            }
            None => {
                failed = true;
                "spawn failed".to_string()
            }
        };
        let result = match &o.harvest {
            Ok(scl_repo::HarvestResult::Committed(id)) => {
                format!("branch {} @ {}", o.label, id.short())
            }
            Ok(scl_repo::HarvestResult::Unchanged) => "unchanged".to_string(),
            Ok(scl_repo::HarvestResult::Rejected(report)) => {
                failed = true;
                format!("REJECTED by secret scanner ({} finding(s))", report.findings.len())
            }
            Err(e) => {
                failed = true;
                format!("harvest error: {e}")
            }
        };
        println!("{:<16} {:<7} {result}", o.label, agent);
    }
    if !failed {
        println!("\nintegrate with: sc merge <branch>");
    }
    // Drop before exit so the RepoLock's Drop runs (process::exit skips
    // destructors — same reasoning as run_run).
    drop(repo);
    std::process::exit(if failed { 1 } else { 0 });
}

/// `sc ws`: durable agent-workspace session (fork/list/abandon/run).
fn run_ws(op: WsOp) -> Result<()> {
    let repo = open_repo()?;
    match op {
        WsOp::Fork { agents, identity, author } => {
            let sk = resolve_identity_opt(identity)?;
            let session = repo.ws_fork(agents, &resolve_author(author), sk.as_ref())?;
            println!(
                "forked {} workspace(s) from branch {} @ {}",
                session.workspaces.len(),
                session.base_branch,
                session.base_snapshot.short()
            );
            for entry in &session.workspaces {
                println!("  {:<3} {}", entry.index, entry.dir.display());
            }
        }
        WsOp::List => match repo.ws_session()? {
            None => println!("no workspace session open"),
            Some(session) => {
                println!(
                    "session base: branch {} @ {}",
                    session.base_branch,
                    session.base_snapshot.short()
                );
                println!("index  status                       dir");
                for entry in &session.workspaces {
                    let status = repo.ws_status_label(&session, entry)?;
                    println!("{:<6} {:<28} {}", entry.index, status, entry.dir.display());
                }
            }
        },
        WsOp::Run { index, with_secrets, identity, cmd } => {
            // Resolve identity: --with-secrets requires it (hard error);
            // otherwise it's optional and only decrypts protected paths.
            let sk = if with_secrets {
                Some(load_identity(identity)?)
            } else {
                resolve_identity_opt(identity)?
            };
            let code = repo.ws_run(index, &cmd, with_secrets, sk.as_ref())?;
            // Drop the repo before process::exit to ensure the RepoLock's Drop
            // runs and releases .sc/lock (process::exit skips destructors).
            drop(repo);
            std::process::exit(code);
        }
        WsOp::Abandon { index } => {
            let remaining = repo.ws_abandon(index)?;
            match index {
                Some(i) => println!("abandoned workspace {i}; {remaining} still live"),
                None => println!("abandoned the session ({remaining} workspace(s) remain)"),
            }
        }
        WsOp::Harvest { into, identity, author } => {
            let sk = resolve_identity_opt(identity)?;
            let outcomes = repo.ws_harvest(into.as_deref(), &resolve_author(author), sk.as_ref())?;
            let mut failed = false;
            for o in &outcomes {
                match o {
                    scl_repo::WsHarvestOutcome::Landed { index, merged_tip } => {
                        println!("{index:<3} landed @ {}", merged_tip.short());
                    }
                    scl_repo::WsHarvestOutcome::FallbackBranch { index, branch } => {
                        failed = true;
                        println!("{index:<3} fallback: branch {branch} — resolve with `sc merge {branch}`");
                    }
                    scl_repo::WsHarvestOutcome::Unchanged { index } => {
                        println!("{index:<3} unchanged");
                    }
                    scl_repo::WsHarvestOutcome::Rejected { index, report } => {
                        failed = true;
                        println!("{index:<3} REJECTED by secret scanner: {report} — fix and re-run `sc ws harvest`");
                    }
                }
            }
            // Drop before exit so the RepoLock's Drop runs (process::exit
            // skips destructors — same reasoning as run_run/run_work).
            drop(repo);
            std::process::exit(if failed { 1 } else { 0 });
        }
    }
    Ok(())
}

fn load_identity(flag: Option<PathBuf>) -> Result<scl_crypto::SecretKey> {
    let path = resolve_identity_path(flag);
    scl_crypto::FileKeyProvider::new(path).identity().map_err(Into::into)
}

/// Read a secret value from stdin (for `secret add` without `--value` and
/// `secret rotate --value-stdin`), so the value never appears in process args
/// or shell history. One trailing newline is trimmed; an empty value is an
/// error (an accidental `< /dev/null` should not seal an empty secret).
fn read_value_from_stdin() -> Result<String> {
    use std::io::Read;
    eprintln!("reading secret value from stdin…");
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let value = buf.strip_suffix('\n').map(|s| s.strip_suffix('\r').unwrap_or(s)).unwrap_or(&buf);
    if value.is_empty() {
        anyhow::bail!("empty secret value on stdin; pass --value or pipe a non-empty value");
    }
    Ok(value.to_string())
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

/// Append every escrow key to a seal recipient set, deduped by recipient id.
fn append_escrow(
    mut pks: Vec<scl_crypto::PublicKey>,
    escrows: &[scl_crypto::PublicKey],
) -> Vec<scl_crypto::PublicKey> {
    for e in escrows {
        if !pks.iter().any(|p| p.recipient_id() == e.recipient_id()) {
            pks.push(e.clone());
        }
    }
    pks
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

fn run_clone(src: String, dst: PathBuf, git: bool) -> Result<()> {
    // Auto-detect unambiguous git URL forms (https/http, scp-style, file://):
    // those can never be sc-native, so no flag is needed. Bare `ssh://` is
    // ambiguous — it means an sc-native remote (ADR-0022) unless `--git`
    // forces the mirror-bridge path (ADR-0028; user-adjudicated).
    let git_shaped =
        scl_gitio::bridge::is_network_git_url(&src) && !src.starts_with("ssh://");
    if git || git_shaped {
        return run_clone_git(&src, &dst);
    }
    let repo = scl_repo::Repo::clone_url(&src, &dst)?;
    let n = repo.branches()?.len();
    println!("cloned {} into {} ({} branch(es))", src, dst.display(), n);
    Ok(())
}

/// Clone from a hosted Git URL: init + remote add origin --git + fetch +
/// adopt the remote's default branch (P10's unborn fast-forward adoption).
/// Reached by auto-detect for unambiguous git URL forms, or by `--git` for
/// `ssh://` git hosts (bare `ssh://` stays sc-native, ADR-0022).
fn run_clone_git(url: &str, dst: &std::path::Path) -> Result<()> {
    // Guard: --git requires a network git URL. For local paths, use
    // `sc remote add <name> <path> --git` + `sc fetch` instead.
    if !scl_gitio::bridge::is_network_git_url(url) {
        anyhow::bail!(
            "clone --git needs a git URL (https://, git@host:path, ssh://, file://); \
             for a local git repo, use `sc remote add <name> <path> --git` + `sc fetch` instead"
        );
    }

    std::fs::create_dir_all(dst)?;
    let repo = scl_repo::Repo::init(dst)?;
    repo.remote_add_git("origin", url)?;

    // Sync the mirror, then point the unborn HEAD at the remote's default
    // branch name BEFORE fetching, so the tracking ref and local branch agree.
    let mirror = git_remote_effective_path(&repo, "origin", url, true)?;
    let default = scl_gitio::bridge::remote_default_branch(&mirror)?;
    scl_repo::refs::write_head(repo.layout(), &default)?;

    run_fetch_git(&repo, "origin")?;
    // Adopt: merge the tracking ref into the unborn branch (ADR-0018's
    // unborn fast-forward). Author resolution mirrors run_merge's.
    let author = resolve_author(None);
    repo.merge(&format!("origin/{default}"), &author)?;
    println!("cloned {url} into {} (branch {default})", dst.display());
    Ok(())
}

/// Serve a repo over the wire protocol on stdin/stdout. Invoked as the
/// remote-side command by `ssh` for `ssh://` remotes.
fn run_serve(stdio: bool, path: PathBuf) -> Result<()> {
    if !stdio {
        anyhow::bail!("sc serve requires --stdio (the only supported mode)");
    }
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    scl_repo::wire::serve(&path, &mut stdin, &mut stdout)?;
    Ok(())
}

/// The local git path P10's import/export machinery should operate on for
/// `remote`: the URL itself when it is a local path, or the synced bare
/// mirror when it is a network URL (ADR-0028 bridge). `sync_from_network`
/// runs `git fetch` into the mirror first — wanted on sc fetch (fresh data)
/// and on clone; NOT on push (export goes into the mirror as-is; a stale
/// mirror head just means git push reports non-ff, verbatim).
fn git_remote_effective_path(
    repo: &scl_repo::Repo,
    remote: &str,
    url: &str,
    sync_from_network: bool,
) -> Result<std::path::PathBuf> {
    if !scl_gitio::bridge::is_network_git_url(url) {
        return Ok(std::path::PathBuf::from(url));
    }
    let mirror_dir = repo.layout().dot_sc.join("git-remotes").join(remote).join("mirror.git");
    let mirror = scl_gitio::bridge::ensure_mirror(&mirror_dir, url)?;
    if sync_from_network {
        scl_gitio::bridge::mirror_fetch(&mirror)?;
    }
    Ok(mirror)
}

fn run_remote(op: RemoteOp) -> Result<()> {
    let repo = open_repo()?;
    match op {
        RemoteOp::Add { name, url, git } => {
            if git {
                if !scl_gitio::bridge::is_network_git_url(&url)
                    && !std::path::Path::new(&url).join("HEAD").exists()
                    && !std::path::Path::new(&url).join(".git").exists()
                {
                    anyhow::bail!("'{url}' is neither a git URL nor a local git repo");
                }
                repo.remote_add_git(&name, &url)?;
                println!("added git remote {name} -> {url}");
                if scl_gitio::bridge::is_network_git_url(&url) {
                    println!("  (network: transport via the system git binary)");
                }
            } else {
                if url.starts_with("ssh://") {
                    scl_repo::SshUrl::parse(&url)?; // fail fast on malformed URLs
                }
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
    let path = git_remote_effective_path(repo, remote, &url, true)?;

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
        scl_gitio::import_history(&mut store, &path, &branch, &known)?
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
    let path = git_remote_effective_path(repo, remote, &url, false)?;

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

    // Fast-forward gate against the remote git ref. For a network remote,
    // `path` is the local mirror, which is advanced by BOTH `sc fetch` and
    // our own `export_branch` below — it is last-known-or-locally-exported
    // state, not confirmed network state. That is exactly why the network
    // leg (`mirror_push`) must always run for network remotes, even when
    // the mirror already matches `local_tip`: a prior `mirror_push` may
    // have failed after `export_branch` had already advanced the mirror,
    // stranding the commit behind this gate. git itself no-ops the push
    // when the network is truly current, and retries it otherwise.
    if let Some(remote_git_hex) = scl_gitio::read_ref(&path, &ref_name)? {
        match git_to_sc.get(&remote_git_hex) {
            Some(&remote_sc) if remote_sc == local_tip => {
                if scl_gitio::bridge::is_network_git_url(&url) {
                    scl_gitio::bridge::mirror_push(&path, &branch)?;
                }
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
            to: &path,
            ref_name: &ref_name,
            include_encrypted,
            known_git_commits: &known_sc_to_git,
        };
        scl_gitio::export_branch(&mut store, local_tip, &opts)?
    };
    let new: Vec<(String, String)> =
        report.new_marks.iter().map(|(g, s)| (g.clone(), s.to_hex().to_string())).collect();
    marks.append(&new)?;

    // Ordering: export + marks precede the network push (mirroring the
    // atomicity comment above) — a crash after export/marks but before
    // `mirror_push` leaves the mirror ahead of the network, and the next
    // `sc push` retries `mirror_push` (via the ff-gate above, which now
    // always attempts the network leg for network remotes). The
    // stale-network-ff case is caught by git itself. This must run BEFORE
    // the success println below — a failed network leg must not print
    // success.
    if scl_gitio::bridge::is_network_git_url(&url) {
        scl_gitio::bridge::mirror_push(&path, &branch)?;
    }

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
    if report.stale_marks > 0 {
        eprintln!(
            "  note: {} mark(s) referenced git commit(s) pruned from the target; re-synthesized with fresh ids",
            report.stale_marks
        );
    }
    if scl_gitio::bridge::is_network_git_url(&url) {
        println!("pushed {remote} -> network ({url})");
    }
    Ok(())
}

fn run_protect(prefix: Option<String>, to: Vec<String>, list: bool, json: bool) -> Result<()> {
    let repo = open_repo()?;
    if list || prefix.is_none() {
        let prefixes = repo.protected_prefixes()?;
        if json {
            let v: Vec<_> = prefixes
                .iter()
                .map(|(p, recips)| {
                    serde_json::json!({
                        "prefix": p,
                        "recipients": recips.iter().map(|r| serde_json::json!({
                            "id": r.id.as_str(),
                            "epoch": r.epoch,
                            "state": if r.granted { "granted" } else { "revoked" },
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        for (p, recips) in prefixes {
            let granted = recips.iter().filter(|r| r.granted).count();
            println!("{p}  ({granted} granted)");
            for r in recips {
                let state = if r.granted { "granted" } else { "REVOKED" };
                println!("  {}  {}@e{}", r.id.as_str(), state, r.epoch);
            }
        }
        return Ok(());
    }
    let prefix = prefix.unwrap();
    let recipients_path = repo.layout().dot_sc.join("recipients.toml");
    let dir = load_recipients(&recipients_path)?;
    let mut pks = resolve_names(&dir, &to)?;
    let escrows = load_escrows(&recipients_path)?;
    pks = append_escrow(pks, &escrows);
    let id = repo.protect(&prefix, &pks, None)?;
    println!("protected {prefix} for {} recipient(s): {}", pks.len(), id.short());
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
    eprintln!(
        "note: the revocation is recorded as a tombstone and holds across merges; \
         it stops FUTURE seals only. Run `sc rewrap --identity <key>` to strip the \
         recipient's wraps from the tip (old history snapshots keep theirs), and \
         rotate the underlying external credential itself for a real cutover"
    );
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
    if report.stale_marks > 0 {
        eprintln!(
            "  note: {} mark(s) referenced git commit(s) pruned from the target; re-synthesized with fresh ids",
            report.stale_marks
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

fn run_rewrap(identity: Option<PathBuf>, dry_run: bool) -> Result<()> {
    let repo = open_repo()?;
    let sk = load_identity(identity)?;
    let recipients_path = repo.layout().dot_sc.join("recipients.toml");
    let escrows = load_escrows(&recipients_path)?;
    // Known-key pool for reverse recipient_id resolution: every [recipients]
    // key + every escrow key + the identity's own public key.
    let mut known: Vec<scl_crypto::PublicKey> = match load_recipients(&recipients_path) {
        Ok(dir) => dir.into_values().collect(),
        Err(_) => Vec::new(), // missing file: pool is escrow + self
    };
    for e in &escrows {
        if !known.iter().any(|k| k.recipient_id() == e.recipient_id()) {
            known.push(e.clone());
        }
    }
    let me = sk.public();
    if !known.iter().any(|k| k.recipient_id() == me.recipient_id()) {
        known.push(me);
    }

    let report = repo.rewrap(&sk, &escrows, &known, dry_run)?;
    let verb = if dry_run { "would rewrap" } else { "rewrapped" };
    println!(
        "{verb} {} secret(s), {} protected blob(s)",
        report.secrets_rewrapped.len(),
        report.blobs_rewrapped
    );
    if let Some(id) = &report.commit {
        println!("commit: {}", id.short());
    }
    if !report.skipped.is_empty() {
        eprintln!("skipped {} entr(ies):", report.skipped.len());
        for (entry, reason) in &report.skipped {
            eprintln!("  {entry}: {reason}");
        }
        eprintln!("re-run `sc rewrap` with an identity that can open them to complete the sweep");
    }
    eprintln!(
        "note: rewrap cuts the live tip only — snapshots already in history keep \
         their old wraps and secret objects (content addressing); rotating the \
         underlying external credential is still the real cutover"
    );
    if !report.skipped.is_empty() {
        drop(repo);
        std::process::exit(1);
    }
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

    #[test]
    fn escrow_toml_reads_old_single_key_form() {
        let dir = std::env::temp_dir().join(format!("scl-escrow-old-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recipients.toml");
        let (_sk, pk) = scl_crypto::generate_keypair();
        std::fs::write(&path, format!("[escrow]\nkey = \"{}\"\n", pk.to_key_string())).unwrap();
        let keys = load_escrows(&path).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].recipient_id(), pk.recipient_id());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn escrow_toml_reads_list_form_and_missing_is_empty() {
        let dir = std::env::temp_dir().join(format!("scl-escrow-list-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recipients.toml");
        let (_s1, p1) = scl_crypto::generate_keypair();
        let (_s2, p2) = scl_crypto::generate_keypair();
        std::fs::write(
            &path,
            format!("[escrow]\nkeys = [\"{}\", \"{}\"]\n", p1.to_key_string(), p2.to_key_string()),
        )
        .unwrap();
        let keys = load_escrows(&path).unwrap();
        assert_eq!(keys.len(), 2);
        // Missing file → empty, not an error.
        assert!(load_escrows(&dir.join("absent.toml")).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn append_escrow_appends_all_deduped() {
        let (_s1, p1) = scl_crypto::generate_keypair();
        let (_s2, p2) = scl_crypto::generate_keypair();
        let out = append_escrow(vec![p1.clone()], &[p1.clone(), p2.clone()]);
        assert_eq!(out.len(), 2, "p1 deduped, p2 appended");
        assert!(out.iter().any(|k| k.recipient_id() == p2.recipient_id()));
    }

    #[test]
    fn escrow_remove_and_empty_list_roundtrip() {
        let dir = std::env::temp_dir().join(format!("scl-escrow-remove-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recipients.toml");

        // Write two escrow keys
        let (_s1, p1) = scl_crypto::generate_keypair();
        let (_s2, p2) = scl_crypto::generate_keypair();
        write_escrow_keys(&path, vec![p1.clone(), p2.clone()]).unwrap();

        // Load and verify 2 keys
        let keys = load_escrows(&path).unwrap();
        assert_eq!(keys.len(), 2);

        // Simulate removal by writing back minus one key
        write_escrow_keys(&path, vec![p1.clone()]).unwrap();

        // Load and verify 1 key and the right one remains
        let keys = load_escrows(&path).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].recipient_id(), p1.recipient_id());

        // Write empty list and assert load_escrows returns empty
        write_escrow_keys(&path, vec![]).unwrap();
        let keys = load_escrows(&path).unwrap();
        assert!(keys.is_empty());

        // Assert the written file no longer contains an [escrow] section
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("[escrow]"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Env mutation (SC_GIT) races parallel tests in this crate that also
    // spawn git for network remotes — serialize with a local lock, mirroring
    // crates/gitio/src/bridge.rs's GIT_ENV_LOCK pattern. Both network tests
    // in this module take it.
    static GIT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn network_git_remote_round_trip_over_file_url() {
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = std::env::temp_dir().join(format!("scl-cli-netgit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // A bare hub reachable only through a file:// URL (network-shaped).
        let hub = root.join("hub.git");
        std::process::Command::new("git")
            .args(["init", "--bare", "-b", "main", hub.to_str().unwrap()])
            .status().unwrap();
        let url = format!("file://{}", hub.display());

        // sc repo with one commit.
        let work = root.join("repo");
        std::fs::create_dir_all(&work).unwrap();
        let repo = scl_repo::Repo::init(&work).unwrap();
        std::fs::write(work.join("readme.txt"), "hello").unwrap();
        repo.commit("me", "first").unwrap();
        repo.remote_add_git("origin", &url).unwrap();

        // Push through the mirror, then verify the HUB (not the mirror) has it.
        run_push_git(&repo, "origin", false).unwrap();
        let out = std::process::Command::new("git")
            .current_dir(&hub).args(["log", "--oneline"]).output().unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("first"),
            "commit must be visible on the hub via git log");

        // Fetch back through the mirror (round trip sanity).
        run_fetch_git(&repo, "origin").unwrap();

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Reproduces the stranded-push bug: if `mirror_push` fails after
    /// `export_branch` has already advanced the mirror ref, the mirror now
    /// matches `local_tip` and the ff-gate's "already up to date" early
    /// return must not skip retrying the network leg — otherwise the commit
    /// is stuck on the mirror forever and never reaches the hub.
    #[test]
    fn network_push_failure_is_retryable() {
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = std::env::temp_dir().join(format!("scl-cli-netgit-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let hub = root.join("hub.git");
        std::process::Command::new("git")
            .args(["init", "--bare", "-b", "main", hub.to_str().unwrap()])
            .status().unwrap();
        let url = format!("file://{}", hub.display());

        let work = root.join("repo");
        std::fs::create_dir_all(&work).unwrap();
        let repo = scl_repo::Repo::init(&work).unwrap();
        std::fs::write(work.join("readme.txt"), "hello").unwrap();
        repo.commit("me", "first").unwrap();
        repo.remote_add_git("origin", &url).unwrap();

        // A shim that execs the real git for everything except `push`,
        // where it fails loudly — simulating a network outage that hits
        // only the mirror_push leg after export_branch has already
        // advanced the mirror ref.
        let shim = root.join("git-shim.sh");
        std::fs::write(
            &shim,
            "#!/bin/sh\ncase \"$*\" in\n  *push*) echo 'shim: network down' >&2; exit 9;;\nesac\nexec git \"$@\"\n",
        ).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        std::env::set_var("SC_GIT", shim.to_str().unwrap());
        let err = run_push_git(&repo, "origin", false);
        std::env::remove_var("SC_GIT");
        assert!(err.is_err(), "first push must fail when the network leg fails");

        // The hub must NOT have the commit yet.
        let out = std::process::Command::new("git")
            .current_dir(&hub).args(["log", "--oneline"]).output().unwrap();
        assert!(!String::from_utf8_lossy(&out.stdout).contains("first"),
            "hub must not have the commit after a failed network push");

        // Retry with the real git — must succeed and land the commit on the
        // hub, proving the ff-gate didn't strand it behind "already up to
        // date" now that the mirror was advanced by the failed attempt's
        // export_branch call.
        run_push_git(&repo, "origin", false).unwrap();
        let out = std::process::Command::new("git")
            .current_dir(&hub).args(["log", "--oneline"]).output().unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("first"),
            "retry must land the commit on the hub");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clone_from_network_git_url_adopts_default_branch() {
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = std::env::temp_dir().join(format!("scl-cli-gitclone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // Hub with default branch "trunk" and one seeded commit.
        let hub = root.join("hub.git");
        std::process::Command::new("git")
            .args(["init", "--bare", "-b", "trunk", hub.to_str().unwrap()]).status().unwrap();
        let seed = root.join("seed");
        std::process::Command::new("git").args(["init", "-b", "trunk", seed.to_str().unwrap()]).status().unwrap();
        std::fs::write(seed.join("a.txt"), "x").unwrap();
        for args in [vec!["add", "."], vec!["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "seed"]] {
            std::process::Command::new("git").current_dir(&seed).args(&args).status().unwrap();
        }
        std::process::Command::new("git").current_dir(&seed)
            .args(["push", &format!("file://{}", hub.display()), "trunk"]).status().unwrap();

        // Route through run_clone WITHOUT --git: file:// is an unambiguous
        // git URL form, so auto-detect must pick the mirror-bridge path.
        let dst = root.join("cloned");
        run_clone(format!("file://{}", hub.display()), dst.clone(), false).unwrap();
        let repo = scl_repo::Repo::open(&dst).unwrap();
        assert_eq!(scl_repo::refs::current_branch(repo.layout()).unwrap(), "trunk",
            "local branch must adopt the remote default name");
        assert!(dst.join("a.txt").exists(), "working tree must be materialized");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clone_bare_ssh_url_without_git_flag_stays_sc_native() {
        // Env mutation (SC_SSH) — serialize with the shared git-env lock.
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = std::env::temp_dir().join(format!("scl-cli-sshclone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Point SC_SSH at a program that cannot exist: if the sc-native
        // transport is taken, the spawn failure names it (stdio_transport's
        // contract). The git-mirror path would spawn `git` instead and fail
        // with a hostname-resolution error that never mentions this path.
        std::env::set_var("SC_SSH", "/nonexistent/sc-native-ssh-probe");
        let err = run_clone(
            "ssh://testhost/srv/repo".to_string(),
            root.join("cloned-ssh"),
            false,
        )
        .unwrap_err();
        std::env::remove_var("SC_SSH");
        assert!(
            err.to_string().contains("sc-native-ssh-probe"),
            "bare ssh:// without --git must reach the sc-native transport \
             (spawn error should name $SC_SSH), got: {err}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clone_git_flag_with_local_path_errors_clearly() {
        // Env mutation (git init) — serialize with the shared git-env lock.
        let _g = GIT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = std::env::temp_dir().join(format!("scl-cli-gitflag-local-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Create a local bare git repo (plain path, no file:// URL scheme).
        let local_git_repo = root.join("local.git");
        std::process::Command::new("git")
            .args(["init", "--bare", "-b", "main", local_git_repo.to_str().unwrap()])
            .status().unwrap();

        // Calling run_clone_git directly with a local path must bail with
        // a clear error message mentioning "git URL", not misroute into
        // ls-remote queries inside the SOURCE repo.
        let dst = root.join("cloned");
        let err = run_clone_git(local_git_repo.to_str().unwrap(), &dst).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("git URL"),
            "error must mention 'git URL' to guide users; got: {msg}"
        );
        assert!(
            msg.contains("sc remote add"),
            "error must suggest the correct workflow; got: {msg}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
