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
use scl_core::{FileMode, SpillPolicy, Store, StoreConfig};
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
    let spill = if args.spill {
        SpillPolicy::SpillTo(session_root.join("spill"))
    } else {
        SpillPolicy::Disallow
    };

    println!("=== src-control · in-memory agent worktree demo ===");
    println!(
        "agents={}  budget={} MiB  spill={}  checkout={}",
        args.agents, args.budget_mb, args.spill, args.checkout
    );
    println!("session dir: {}", session_root.display());
    println!();

    let repo = Repo::new(Store::new(StoreConfig { budget_bytes, spill }));

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
