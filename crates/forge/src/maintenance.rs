//! Maintenance: garbage collection and the cleanup of what killed git writers leave behind.
//!
//! One pass visits every live repository in turn. For each it runs two stages (plan:
//! `docs/superpowers/plans/2026-10-24-p38-f5a-maintenance.md`):
//!
//! 1. `git gc --prune=never`, no gate: packs what refs reach and loosens unreachable packed objects,
//!    deletes nothing, so it runs beside every other operation.
//! 2. Under the repository's write gate: every retention ref is reconciled (a failure skips the
//!    prune), `git prune --expire=<window>` removes the aged loose unreachable objects, and stale
//!    ref locks and quarantine directories go. The gate keeps the API writers (which copy existing,
//!    possibly old, objects into new trees) from referencing an object prune is about to unlink.
//!
//! Both stages run under one registry registration, like a transport: `delete` cancels the run
//! and waits for it before it renames the directory. The run never takes the lifecycle lock.

use crate::gitproc::{GitError, Spec};
use crate::registry::Cancel;
use crate::routes::App;
use crate::{db, merges, orphans, pulls, repos, timefmt, transport};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Settings of the maintenance pass.
#[derive(Clone, Debug)]
pub struct Cfg {
    /// Time between passes; zero means only on request.
    pub interval: Duration,
    /// Unreachable loose objects younger than this survive `prune`.
    pub prune_expire: Duration,
    /// Wall-clock limit of the gc of one repository.
    pub gc_timeout: Duration,
    /// Wall-clock limit of the prune, which holds the write gate (API writers wait on it).
    pub prune_timeout: Duration,
    /// Free disk that must remain beyond what a repack needs.
    pub min_free: u64,
    /// How long stage 2 waits for the repository's write gate before skipping the repository.
    pub gate_wait: Duration,
    /// Leftover locks and quarantine directories younger than this are left alone.
    pub stale_age: Duration,
}

impl Default for Cfg {
    fn default() -> Cfg {
        Cfg {
            interval: Duration::from_secs(86_400),
            prune_expire: Duration::from_secs(14 * 86_400),
            gc_timeout: Duration::from_secs(3_600),
            prune_timeout: Duration::from_secs(600),
            min_free: 1 << 30,
            gate_wait: Duration::from_secs(30),
            stale_age: Duration::from_secs(600),
        }
    }
}

/// The shortest `--gc-prune-expire` that keeps in-flight work safe: twice the longest git
/// operation, and at least an hour.
pub fn min_prune_expire(git_timeout: Duration) -> Duration {
    (git_timeout * 2).max(Duration::from_secs(3_600))
}

#[derive(Default)]
struct State {
    requested: bool,
    running: bool,
}

/// The maintenance schedule: a timer and on-demand requests share one runner thread ([`spawn`]).
pub struct Maintenance {
    pub cfg: Cfg,
    state: Mutex<State>,
    wake: Condvar,
    passes: AtomicU64,
}

impl Maintenance {
    pub fn new(cfg: Cfg) -> Maintenance {
        Maintenance {
            cfg,
            state: Mutex::default(),
            wake: Condvar::new(),
            passes: AtomicU64::new(0),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Ask for a pass now. `false` when one is already queued or running (it covers this request).
    pub fn request(&self) -> bool {
        let mut st = self.state();
        if st.requested || st.running {
            return false;
        }
        st.requested = true;
        self.wake.notify_all();
        true
    }

    /// Passes finished since the server started.
    pub fn passes(&self) -> u64 {
        self.passes.load(Ordering::SeqCst)
    }

    /// Is a pass queued or running?
    pub fn busy(&self) -> bool {
        let st = self.state();
        st.requested || st.running
    }
}

/// How one repository's maintenance ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both stages ran; sizes are disk usage in KiB.
    Done {
        before_kib: u64,
        after_kib: u64,
    },
    /// Stage 2 did not delete anything.
    Skipped(&'static str),
    /// The repository is gone or being deleted, or the server is stopping.
    Gone,
    Failed(String),
}

/// What a pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub repos: usize,
    pub done: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Start the runner thread: a pass every `cfg.interval` (if set) and whenever one is requested,
/// until the server stops. Passes run one at a time.
pub fn spawn(app: Arc<App>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let m = &app.maint;
        let mut next = (!m.cfg.interval.is_zero()).then(|| Instant::now() + m.cfg.interval);
        loop {
            let requested = {
                let mut st = m.state();
                if !st.requested {
                    st = m
                        .wake
                        .wait_timeout(st, Duration::from_secs(1))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                let r = std::mem::take(&mut st.requested);
                st.running = r || next.is_some_and(|t| Instant::now() >= t);
                r
            };
            if app.life.registry.is_stopped() {
                return;
            }
            if !m.state().running {
                continue;
            }
            let pass = run_pass(&app);
            eprintln!("sc-forge: maintenance pass finished: {pass:?} (requested: {requested})");
            // Not running again before the count moves, so a request that follows an observed
            // increment is always accepted.
            m.state().running = false;
            m.passes.fetch_add(1, Ordering::SeqCst);
            next = (!m.cfg.interval.is_zero()).then(|| Instant::now() + m.cfg.interval);
        }
    })
}

/// One pass over every live repository.
pub fn run_pass(app: &App) -> Pass {
    let mut pass = Pass::default();
    let conn = match db::connect(&app.data_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sc-forge: maintenance cannot open the database: {e}");
            return pass;
        }
    };
    let ids: Vec<i64> = match repos::list_in_state(&conn, "live") {
        Ok(r) => r.into_iter().map(|r| r.id).collect(),
        Err(e) => {
            eprintln!("sc-forge: maintenance cannot list the repositories: {e}");
            return pass;
        }
    };
    for id in ids {
        if app.life.registry.is_stopped() {
            break;
        }
        pass.repos += 1;
        match maintain_repo(app, &conn, id) {
            Outcome::Done {
                before_kib,
                after_kib,
            } => {
                pass.done += 1;
                eprintln!(
                    "sc-forge: maintenance of repository {id}: {before_kib} KiB -> {after_kib} KiB"
                );
            }
            Outcome::Skipped(why) => {
                pass.skipped += 1;
                eprintln!("sc-forge: maintenance of repository {id} skipped: {why}");
            }
            Outcome::Gone => {}
            Outcome::Failed(e) => {
                pass.failed += 1;
                eprintln!("sc-forge: maintenance of repository {id} failed: {e}");
            }
        }
    }
    pass
}

fn fail(e: GitError) -> Outcome {
    match e {
        GitError::Cancelled => Outcome::Gone,
        e => Outcome::Failed(e.to_string()),
    }
}

/// Disk usage of a repository in KiB: `size` (loose) plus `size-pack` from `count-objects -v`.
fn usage_kib(app: &App, dir: &std::path::Path, cancel: &Cancel) -> Result<u64, GitError> {
    let out = app.life.git.run(&Spec {
        repo: Some(dir),
        args: &["count-objects", "-v"],
        cancel: Some(cancel),
        ..Default::default()
    })?;
    if !out.ok() {
        return Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(out
        .text()
        .lines()
        .filter_map(|l| l.split_once(": "))
        .filter(|(k, _)| matches!(*k, "size" | "size-pack"))
        .filter_map(|(_, v)| v.trim().parse::<u64>().ok())
        .sum())
}

/// Collect one repository. See the module documentation for the stages and why they are safe.
pub fn maintain_repo(app: &App, conn: &rusqlite::Connection, id: i64) -> Outcome {
    let life = &app.life;
    let cfg = &app.maint.cfg;
    let dir = life.repo_dir(id);
    let live = || matches!(repos::find_by_id(conn, id), Ok(Some(r)) if r.state == "live");
    let Some(reg) = life.registry.register(id, true, live) else {
        return Outcome::Gone;
    };
    let cancel = reg.cancel.clone();
    let run = |args: &[&str], timeout: Option<Duration>| {
        life.git.run(&Spec {
            repo: Some(&dir),
            args,
            timeout,
            cancel: Some(&cancel),
            ..Default::default()
        })
    };
    let check = |r: Result<crate::gitproc::Out, GitError>| match r {
        Ok(o) if o.ok() => Ok(()),
        Ok(o) => Err(Outcome::Failed(
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        )),
        Err(e) => Err(fail(e)),
    };

    // Leftovers of killed writers go first: a stale ref lock would fail the gc and the reconcile
    // below. Owners are excluded: the gate is held and ours is the only registration.
    match in_gate(life, id, &cancel, cfg.gate_wait, || {
        // The gate excludes the API writers and the registry the transports; default-branch and
        // branch-delete writers hold only the exclusive lifecycle lock, so take that too (gate
        // first, as everywhere). Anything still running means the leftovers wait for the next pass.
        life.try_exclusive(id, || {
            life.registry
                .with_only(&reg, || orphans::clean_repo(&dir, Some(cfg.stale_age)))
        })
    }) {
        Ok(_) => {}
        Err(o) => return o,
    }

    let before = match usage_kib(app, &dir, &cancel) {
        Ok(k) => k,
        Err(e) => return fail(e),
    };

    // Stage 1: nothing is deleted. A repack writes the new pack before it drops the old ones.
    let free = transport::free_bytes(&app.data_dir).unwrap_or(0);
    let mut note = None;
    if free < cfg.min_free.saturating_add(before.saturating_mul(1024)) {
        note = Some("not enough free disk for a repack");
    } else if let Err(o) = check(run(
        &[
            "-c",
            "gc.autoDetach=false",
            "-c",
            "gc.cruftPacks=false",
            "-c",
            "pack.threads=2",
            "-c",
            "pack.windowMemory=256m",
            "gc",
            "--prune=never",
            "--force",
            "--quiet",
        ],
        Some(cfg.gc_timeout),
    )) {
        if o == Outcome::Gone {
            return o;
        }
        // Stage 2 does not depend on stage 1: it only removes aged loose objects.
        eprintln!("sc-forge: gc of repository {id} failed: {o:?}");
        note = Some("gc failed");
    }

    // Stage 2, under the write gate.
    let stage2 = || -> Outcome {
        if cancel.is_set() {
            return Outcome::Gone;
        }
        let now = timefmt::now();
        // The reconcile writes refs and rows as a gated writer, so it holds the shared lifecycle
        // lock like every other one (`delete_branch` relies on that); it never waits for it.
        // A sync logs and skips a pull request it cannot repair, so success of the reconcile is not
        // enough: the roots are verified separately.
        let Some(roots) = life.try_shared(id, || {
            pulls::reconcile_repo(conn, &life.git, &dir, id, now)
                .map_err(|e| e.to_string())
                .and_then(|()| pulls::verify_roots(conn, &life.git, &dir, id))
        }) else {
            return Outcome::Skipped("the repository is being changed (delete, default branch)");
        };
        if let Err(e) = roots {
            // Without every retention ref confirmed, deleting could destroy the only copy.
            eprintln!("sc-forge: repository {id}: retention refs could not be reconciled ({e}); nothing pruned");
            return Outcome::Skipped("retention refs could not be reconciled");
        }
        // A merge intent still pending after the reconcile has a commit only the journal names.
        if merges::has_pending(conn, id) {
            return Outcome::Skipped("a merge is still pending");
        }
        // Saturating, and never a cutoff in the future: an absurd window must not prune everything.
        let window = i64::try_from(cfg.prune_expire.as_secs()).unwrap_or(i64::MAX);
        let cutoff = now.saturating_sub(window);
        if cutoff < 1 {
            return Outcome::Skipped("the prune window reaches before the epoch");
        }
        let expire = format!("--expire={cutoff}");
        if let Err(o) = check(run(&["prune", &expire], Some(cfg.prune_timeout))) {
            return o;
        }
        match usage_kib(app, &dir, &cancel) {
            Ok(after_kib) => Outcome::Done {
                before_kib: before,
                after_kib,
            },
            Err(e) => fail(e),
        }
    };
    match in_gate(life, id, &cancel, cfg.gate_wait, stage2) {
        Ok(o) => {
            if let (Outcome::Done { .. }, Some(n)) = (&o, note) {
                eprintln!("sc-forge: repository {id}: stage 1 did not run ({n}); aged loose objects were still pruned");
            }
            o
        }
        Err(o) => o,
    }
}

/// Run `f` under repository `id`'s write gate. The wait is sliced so a cancel (a delete, shutdown)
/// is noticed; `Err` carries the outcome when `f` never ran.
fn in_gate<T>(
    life: &crate::lifecycle::Lifecycle,
    id: i64,
    cancel: &Cancel,
    wait: Duration,
    f: impl FnOnce() -> T,
) -> Result<T, Outcome> {
    let mut once = Some(f);
    let deadline = Instant::now() + wait;
    loop {
        if cancel.is_set() {
            return Err(Outcome::Gone);
        }
        if let Some(r) = life.with_gate(id, Duration::from_millis(250), || (once.take().unwrap())())
        {
            return Ok(r);
        }
        if Instant::now() >= deadline {
            return Err(Outcome::Skipped("the write gate stayed taken"));
        }
    }
}
