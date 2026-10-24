//! Repository lifecycle: create, delete, change the default branch, and the startup reconciler.
//!
//! Directories are named by the immutable repository id (`repos/<id>.git`), so deleting and
//! recreating a name yields a new directory a straggler cannot see. Every multi-step operation
//! is ordered so a crash at any point leaves a state the reconciler resolves:
//!
//! * create: row `creating` -> `git init` -> optional auto-init commit -> fsync the tree -> row `live`
//! * delete: row `deleting` -> rename into `trash/` -> fsync parents -> delete row -> remove trash
//!
//! `serve` holds the [`DirLock`] for its lifetime, so no second process can reconcile or mutate
//! the same directory, and a per-repository mutex serializes the server's own operations on one id.

use crate::gitproc::{Git, GitError, Identity, Spec};
use crate::refname;
use crate::repos::{self, Repo, RepoPatch};
use crate::store::{StoreError, User};
use rusqlite::Connection;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Exclusive hold on the data directory for the life of the process.
pub struct DirLock(#[allow(dead_code)] File);

impl DirLock {
    /// Take the lock, or fail if another process holds it.
    pub fn acquire(data_dir: &Path) -> Result<DirLock, String> {
        std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(data_dir.join(".lock"))
            .map_err(|e| e.to_string())?;
        f.try_lock().map_err(|_| {
            format!(
                "another sc-forge process holds {}; refusing to share the data directory",
                data_dir.display()
            )
        })?;
        Ok(DirLock(f))
    }
}

/// Why a lifecycle operation failed.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Git(#[from] GitError),
    /// The name is taken (any letter case, any state).
    #[error("exists")]
    Exists,
    /// The repository is not `live` any more (deleted or being deleted).
    #[error("gone")]
    Gone,
    /// The branch does not exist.
    #[error("no such branch")]
    NoSuchBranch,
    /// The default branch name is not a valid branch name.
    #[error("invalid branch name")]
    BadBranch,
    /// A git command that must succeed failed.
    #[error("git failed: {0}")]
    GitFailed(String),
    /// A test-injected crash: the operation stopped here and cleaned nothing up.
    #[error("injected crash at {0}")]
    Crash(&'static str),
}

/// What the reconciler did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub creating_rolled_back: usize,
    pub deleting_finished: usize,
    pub trash_removed: usize,
    pub orphans_moved: usize,
    pub head_repaired: usize,
    pub head_repair_failed: usize,
    pub missing_dirs: usize,
}

/// Owns the on-disk layout and the per-repository serialization.
pub struct Lifecycle {
    data_dir: PathBuf,
    pub git: Arc<Git>,
    /// Live git transports by repository, cancelled by `delete` and at shutdown.
    pub registry: Arc<crate::registry::Registry>,
    locks: Mutex<HashMap<i64, Arc<RwLock<()>>>>,
    #[cfg(test)]
    crash_at: Mutex<Option<&'static str>>,
}

impl Lifecycle {
    pub fn new(data_dir: &Path, git: Arc<Git>) -> std::io::Result<Lifecycle> {
        for d in ["repos", "trash", "orphans"] {
            std::fs::create_dir_all(data_dir.join(d))?;
        }
        // Absolute (the git children run with this as their working directory) and durable: the
        // layout directories' own entries must survive a power loss before any row points at them.
        let data_dir = std::fs::canonicalize(data_dir)?;
        for d in ["repos", "trash", "orphans"] {
            fsync_dir(&data_dir.join(d))?;
        }
        fsync_dir(&data_dir)?;
        Ok(Lifecycle {
            data_dir,
            git,
            registry: Arc::default(),
            locks: Mutex::default(),
            #[cfg(test)]
            crash_at: Mutex::default(),
        })
    }

    /// Run `f` (a read of repository `id` on disk) under the shared lock, and only if the
    /// repository is still `live` once the lock is held. `None` means it is gone (deleted or being
    /// deleted): the caller answers as for a missing repository. Without this, a read that
    /// overlapped the delete's rename could see a half-vanished repository as an empty one.
    pub fn with_read<T>(
        &self,
        conn: &Connection,
        id: i64,
        f: impl FnOnce() -> T,
    ) -> Result<Option<T>, rusqlite::Error> {
        let lock = self.lock_for(id);
        let _shared = lock.read().unwrap_or_else(|e| e.into_inner());
        Ok(match repos::find_by_id(conn, id)? {
            Some(r) if r.state == "live" => Some(f()),
            _ => None,
        })
    }

    /// `repos/<id>.git`: always built from the integer id.
    pub fn repo_dir(&self, id: i64) -> PathBuf {
        self.data_dir.join("repos").join(format!("{id}.git"))
    }

    fn trash_dir(&self, id: i64) -> PathBuf {
        self.data_dir.join("trash").join(format!("{id}.git"))
    }

    /// The lock that serializes the server's operations on repository `id`: delete, default-branch
    /// change and branch delete take it exclusively; reads of the repository take it shared (see
    /// [`Lifecycle::with_read`]), so a read can never straddle the delete's rename.
    pub fn lock_for(&self, id: i64) -> Arc<RwLock<()>> {
        self.locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(id)
            .or_default()
            .clone()
    }

    #[cfg(test)]
    fn arm(&self, step: &'static str) {
        *self.crash_at.lock().unwrap() = Some(step);
    }

    /// A crash point: in tests, an armed step stops the operation without cleanup.
    #[allow(unused_variables)]
    fn step(&self, name: &'static str) -> Result<(), LifecycleError> {
        #[cfg(test)]
        {
            let mut armed = self.crash_at.lock().unwrap();
            if *armed == Some(name) {
                *armed = None; // one-shot: a retry after the "restart" runs normally
                return Err(LifecycleError::Crash(name));
            }
        }
        Ok(())
    }

    fn run(
        &self,
        repo: &Path,
        args: &[&str],
        stdin: Option<&[u8]>,
        id: Option<&Identity>,
    ) -> Result<String, LifecycleError> {
        let out = self.git.run(&Spec {
            repo: Some(repo),
            args,
            stdin,
            identity: id,
            ..Default::default()
        })?;
        if out.ok() {
            Ok(out.text())
        } else {
            Err(LifecycleError::GitFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ))
        }
    }

    /// Create a repository owned by `owner` (the caller has already authorized it) and, with
    /// `auto_init`, its first commit authored by `actor`. A failure before the row is `live`
    /// rolls everything back in-process, so a failed create never blocks the name.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        conn: &Connection,
        owner: &User,
        actor: &User,
        name: &str,
        description: &str,
        default_branch: &str,
        auto_init: bool,
        now: i64,
    ) -> Result<Repo, LifecycleError> {
        if !refname::valid_branch(default_branch) {
            return Err(LifecycleError::BadBranch);
        }
        let row =
            repos::insert_creating(conn, owner.id, name, default_branch, description, "", now)
                .map_err(|e| match e {
                    StoreError::Exists => LifecycleError::Exists,
                    StoreError::Db(d) => LifecycleError::Db(d),
                    StoreError::NotFound => LifecycleError::Gone,
                })?;
        match self.build(conn, &row, actor, auto_init, now) {
            Ok(()) => repos::find_by_id(conn, row.id)?.ok_or(LifecycleError::Gone),
            Err(e @ LifecycleError::Crash(_)) => Err(e), // a crash cleans nothing up: the reconciler does
            Err(e) => {
                // An ordinary failure rolls back now; if even that fails the row stays `creating`
                // and the next startup finishes the job.
                match remove_any(&self.repo_dir(row.id)) {
                    Ok(()) => {
                        let _ = repos::delete_row(conn, row.id);
                    }
                    Err(c) => eprintln!(
                        "sc-forge: could not remove {} ({c}); the row stays `creating` for the next startup",
                        self.repo_dir(row.id).display()
                    ),
                }
                Err(e)
            }
        }
    }

    fn build(
        &self,
        conn: &Connection,
        row: &Repo,
        actor: &User,
        auto_init: bool,
        now: i64,
    ) -> Result<(), LifecycleError> {
        self.step("inserted")?;
        let dir = self.repo_dir(row.id);
        let out = self.git.run(&Spec {
            args: &[
                "init",
                "--bare",
                "--quiet",
                "--template=",
                &format!("--initial-branch={}", row.default_branch),
                &dir.display().to_string(),
            ],
            ..Default::default()
        })?;
        if !out.ok() {
            return Err(LifecycleError::GitFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        self.step("initialized")?;
        if auto_init {
            let email = if actor.email.is_empty() {
                format!("{}@noreply.localhost", actor.login)
            } else {
                actor.email.clone()
            };
            let id = Identity::new(&actor.login, &email)
                .ok_or_else(|| LifecycleError::GitFailed("unusable commit identity".into()))?;
            let readme = format!("# {}\n\n", row.name);
            let blob = self.run(
                &dir,
                &["hash-object", "-w", "--no-filters", "--stdin"],
                Some(readme.as_bytes()),
                None,
            )?;
            let tree = self.run(
                &dir,
                &["mktree"],
                Some(format!("100644 blob {blob}\tREADME.md\n").as_bytes()),
                None,
            )?;
            let commit = self.run(
                &dir,
                &["commit-tree", &tree],
                Some(b"Initial commit\n"),
                Some(&id),
            )?;
            let branch_ref = refname::branch_ref(&row.default_branch);
            self.run(
                &dir,
                &[
                    "update-ref",
                    &branch_ref,
                    &commit,
                    "0000000000000000000000000000000000000000",
                ],
                None,
                None,
            )?;
        }
        self.step("committed")?;
        fsync_tree(&dir)?;
        fsync_dir(&self.data_dir.join("repos"))?;
        fsync_dir(&self.data_dir)?;
        self.step("synced")?;
        if !repos::set_state(conn, row.id, "creating", "live", now)? {
            return Err(LifecycleError::Gone);
        }
        Ok(())
    }

    /// Delete a repository: `deleting` -> rename into `trash/` -> fsync -> row delete -> remove trash.
    /// `Gone` when it was not `live` (someone else is already deleting it).
    pub fn delete(&self, conn: &Connection, repo: &Repo, now: i64) -> Result<(), LifecycleError> {
        let lock = self.lock_for(repo.id);
        let _held = lock.write().unwrap_or_else(|e| e.into_inner());
        if !repos::set_state(conn, repo.id, "live", "deleting", now)? {
            return Err(LifecycleError::Gone);
        }
        self.step("marked")?;
        // The row says `deleting`, so no new transport registers; end the ones running and wait for
        // them to let go before the directory moves. One that will not end keeps the repository.
        self.registry.close(repo.id);
        if !self.registry.wait_idle(repo.id, Duration::from_secs(10)) {
            self.registry.reopen(repo.id);
            let _ = repos::set_state(conn, repo.id, "deleting", "live", now);
            return Err(LifecycleError::Git(GitError::Busy));
        }
        let (from, to) = (self.repo_dir(repo.id), self.trash_dir(repo.id));
        if let Err(e) = std::fs::rename(&from, &to) {
            // Nothing moved: put the row back so the repository is usable again.
            self.registry.reopen(repo.id);
            let _ = repos::set_state(conn, repo.id, "deleting", "live", now);
            return Err(e.into());
        }
        self.step("renamed")?;
        fsync_dir(&self.data_dir.join("repos"))?;
        fsync_dir(&self.data_dir.join("trash"))?;
        repos::delete_row(conn, repo.id)?;
        self.step("row-deleted")?;
        if let Err(e) = std::fs::remove_dir_all(&to) {
            eprintln!(
                "sc-forge: could not remove trash/{}.git ({e}); startup reconcile will",
                repo.id
            );
        }
        self.registry.forget(repo.id);
        self.locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&repo.id);
        Ok(())
    }

    /// Does branch ref `full` exist? `show-ref --verify` exits 1 for "no such ref"; any other
    /// failure (128: the directory is missing or corrupt) is the repository's damage and must
    /// not read as bad user input.
    fn branch_exists(&self, dir: &Path, full: &str) -> Result<bool, LifecycleError> {
        let out = self.git.run(&Spec {
            repo: Some(dir),
            args: &["show-ref", "--verify", "--quiet", full],
            ..Default::default()
        })?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(LifecycleError::GitFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            )),
        }
    }

    /// Make `branch` the default: it must exist; bare `HEAD` is written first, then the row.
    pub fn set_default_branch(
        &self,
        conn: &Connection,
        repo: &Repo,
        branch: &str,
        now: i64,
    ) -> Result<(), LifecycleError> {
        let lock = self.lock_for(repo.id);
        let _held = lock.write().unwrap_or_else(|e| e.into_inner());
        let current = repos::find_by_id(conn, repo.id)?
            .filter(|r| r.state == "live")
            .ok_or(LifecycleError::Gone)?;
        if current.default_branch == branch {
            return Ok(()); // decided under the lock: a concurrent PATCH may already have set it
        }
        let dir = self.repo_dir(current.id);
        let full = refname::branch_ref(branch);
        if !self.branch_exists(&dir, &full)? {
            return Err(LifecycleError::NoSuchBranch);
        }
        self.run(&dir, &["symbolic-ref", "HEAD", &full], None, None)?;
        self.step("head-written")?;
        let patch = RepoPatch {
            default_branch: Some(branch.to_string()),
            ..Default::default()
        };
        if !repos::update_live(conn, current.id, &patch, now)? {
            return Err(LifecycleError::Gone);
        }
        Ok(())
    }

    /// Delete a branch (the caller has refused the default branch). `NoSuchBranch` when absent.
    pub fn delete_branch(
        &self,
        conn: &Connection,
        repo: &Repo,
        branch: &str,
    ) -> Result<(), LifecycleError> {
        let lock = self.lock_for(repo.id);
        let _held = lock.write().unwrap_or_else(|e| e.into_inner());
        let current = repos::find_by_id(conn, repo.id)?
            .filter(|r| r.state == "live")
            .ok_or(LifecycleError::Gone)?;
        // Case-insensitive: on a case-insensitive filesystem `MAIN` aliases the loose ref `main`.
        if crate::policy::same_branch_name(&current.default_branch, branch) {
            return Err(LifecycleError::GitFailed(
                "refusing to delete the default branch".into(),
            ));
        }
        let dir = self.repo_dir(current.id);
        let full = refname::branch_ref(branch);
        if !self.branch_exists(&dir, &full)? {
            return Err(LifecycleError::NoSuchBranch);
        }
        self.run(&dir, &["update-ref", "-d", &full], None, None)?;
        Ok(())
    }

    /// Move `p` out of the way into `orphans/` (never deleting it).
    fn to_orphans(&self, p: &Path) -> std::io::Result<PathBuf> {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut to = self.data_dir.join("orphans").join(&name);
        let mut n = 0;
        while to.exists() {
            n += 1;
            to = self.data_dir.join("orphans").join(format!("{name}.{n}"));
        }
        std::fs::rename(p, &to)?;
        fsync_dir(&self.data_dir.join("orphans"))?;
        Ok(to)
    }

    /// Resolve every state a crash can leave. Run once at startup, before the listener is bound
    /// and while holding the [`DirLock`]. Nothing is ever deleted that a live repository might
    /// own: a directory with no row, and the directory of a `creating` row, move to `orphans/`
    /// (a restored database can resurrect either). A database error aborts the pass before any
    /// directory is touched on its account.
    pub fn reconcile(&self, conn: &Connection, now: i64) -> Result<Report, LifecycleError> {
        let mut rep = Report::default();
        // 1. creating: roll back (the row does not record auto_init, so a half-initialized
        //    repository is never promoted; the client never saw a 201 for it). The directory is
        //    kept in orphans/, and the row is deleted only after that succeeded.
        for r in repos::list_in_state(conn, "creating")? {
            let dir = self.repo_dir(r.id);
            if std::fs::symlink_metadata(&dir).is_ok() {
                self.to_orphans(&dir)?;
            }
            repos::delete_row(conn, r.id)?;
            rep.creating_rolled_back += 1;
        }
        // 2. deleting: resume at the rename, then finish.
        for r in repos::list_in_state(conn, "deleting")? {
            let (from, to) = (self.repo_dir(r.id), self.trash_dir(r.id));
            if from.exists() {
                if to.exists() {
                    std::fs::remove_dir_all(&to)?;
                }
                std::fs::rename(&from, &to)?;
                fsync_dir(&self.data_dir.join("repos"))?;
                fsync_dir(&self.data_dir.join("trash"))?;
            }
            repos::delete_row(conn, r.id)?;
            let _ = std::fs::remove_dir_all(&to);
            rep.deleting_finished += 1;
        }
        // 3. trash with no row. A lookup error propagates: it must never read as "no row".
        for e in std::fs::read_dir(self.data_dir.join("trash"))? {
            let p = e?.path();
            let known = match file_id(&p) {
                Some(id) => repos::find_by_id(conn, id)?.is_some(),
                None => false,
            };
            if !known {
                remove_any(&p)?;
                rep.trash_removed += 1;
            }
        }
        // 4. a directory in repos/ with no row at all: keep it, out of the way, never delete it.
        for e in std::fs::read_dir(self.data_dir.join("repos"))? {
            let p = e?.path();
            let known = match file_id(&p) {
                Some(id) => repos::find_by_id(conn, id)?.is_some(),
                None => false,
            };
            if !known {
                let to = self.to_orphans(&p)?;
                eprintln!(
                    "sc-forge: {} has no repository row; moved to {}",
                    p.display(),
                    to.display()
                );
                rep.orphans_moved += 1;
            }
        }
        // 5. live: HEAD follows the row (the row is the authority); a missing directory is
        //    reported, never silently dropped; one repository that cannot be repaired is reported
        //    and does not stop the others (or the server) from starting.
        for r in repos::list_in_state(conn, "live")? {
            let dir = self.repo_dir(r.id);
            if !dir.is_dir() {
                eprintln!(
                    "sc-forge: repository {}/{} (id {}) has no directory",
                    r.owner, r.name, r.id
                );
                rep.missing_dirs += 1;
                continue;
            }
            let want = refname::branch_ref(&r.default_branch);
            let fix = || -> Result<bool, LifecycleError> {
                let head = self.git.run(&Spec {
                    repo: Some(&dir),
                    args: &["symbolic-ref", "-q", "HEAD"],
                    ..Default::default()
                })?;
                if head.text() == want {
                    return Ok(false);
                }
                self.run(&dir, &["symbolic-ref", "HEAD", &want], None, None)?;
                Ok(true)
            };
            match fix() {
                Ok(true) => rep.head_repaired += 1,
                Ok(false) => {}
                Err(e) => {
                    eprintln!(
                        "sc-forge: cannot repair HEAD of {}/{} (id {}): {e}",
                        r.owner, r.name, r.id
                    );
                    rep.head_repair_failed += 1;
                }
            }
        }
        let _ = now;
        Ok(rep)
    }
}

/// Remove a path whether it is a directory or something that is not (a stray file).
fn remove_any(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The id in a `<id>.git` directory name.
fn file_id(p: &Path) -> Option<i64> {
    p.file_name()?.to_str()?.strip_suffix(".git")?.parse().ok()
}

/// fsync a directory (so its entries are durable).
pub fn fsync_dir(p: &Path) -> std::io::Result<()> {
    File::open(p)?.sync_all()
}

/// fsync every file and directory under `p`, depth first, propagating any failure.
pub fn fsync_tree(p: &Path) -> std::io::Result<()> {
    for e in std::fs::read_dir(p)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            fsync_tree(&e.path())?;
        } else {
            File::open(e.path())?.sync_all()?;
        }
    }
    fsync_dir(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::gitproc::find_git;
    use crate::store::{create_account, NewAccount};

    struct Env {
        dir: PathBuf,
        conn: Connection,
        lc: Lifecycle,
        owner: User,
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn env(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("scl-forge-life-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let conn = db::open_for_admin(&dir).unwrap();
        let git = Arc::new(Git::new(&dir, find_git().expect("git"), 4).unwrap());
        let lc = Lifecycle::new(&dir, git).unwrap();
        let owner = create_account(
            &conn,
            &NewAccount {
                login: "owner".into(),
                email: "owner@example.invalid".into(),
                visibility: "public".into(),
                ..Default::default()
            },
            1,
        )
        .unwrap();
        Env {
            dir,
            conn,
            lc,
            owner,
        }
    }

    fn make(e: &Env, name: &str, init: bool) -> Result<Repo, LifecycleError> {
        e.lc.create(&e.conn, &e.owner, &e.owner, name, "", "main", init, 10)
    }

    fn head(e: &Env, r: &Repo) -> String {
        e.lc.git
            .run(&Spec {
                repo: Some(&e.lc.repo_dir(r.id)),
                args: &["symbolic-ref", "HEAD"],
                ..Default::default()
            })
            .unwrap()
            .text()
    }

    fn rev(e: &Env, r: &Repo, what: &str) -> Option<String> {
        let o =
            e.lc.git
                .run(&Spec {
                    repo: Some(&e.lc.repo_dir(r.id)),
                    args: &["rev-parse", "--verify", "-q", what],
                    ..Default::default()
                })
                .unwrap();
        o.ok().then(|| o.text())
    }

    #[test]
    fn create_with_auto_init_makes_a_bare_repo_with_one_commit_by_the_actor() {
        let e = env("autoinit");
        let r = make(&e, "alpha", true).unwrap();
        assert_eq!(r.state, "live");
        let dir = e.lc.repo_dir(r.id);
        assert!(
            dir.join("HEAD").is_file() && !dir.join(".git").exists(),
            "a bare repo named by id"
        );
        assert!(
            !dir.join("hooks").exists()
                || std::fs::read_dir(dir.join("hooks")).unwrap().count() == 0,
            "no template hooks"
        );
        assert_eq!(head(&e, &r), "refs/heads/main");
        let log =
            e.lc.git
                .run(&Spec {
                    repo: Some(&dir),
                    args: &["log", "-1", "--format=%an|%ae|%cn|%s", "main"],
                    ..Default::default()
                })
                .unwrap()
                .text();
        assert_eq!(log, "owner|owner@example.invalid|owner|Initial commit");
        let blob =
            e.lc.git
                .run(&Spec {
                    repo: Some(&dir),
                    args: &["show", "main:README.md"],
                    ..Default::default()
                })
                .unwrap()
                .text();
        assert_eq!(blob, "# alpha", "recorded 8-byte README `# <name>\\n\\n`");
    }

    #[test]
    fn create_without_auto_init_is_empty_and_head_names_the_default_branch() {
        let e = env("empty");
        let r =
            e.lc.create(&e.conn, &e.owner, &e.owner, "blank", "", "trunk", false, 10)
                .unwrap();
        assert_eq!(head(&e, &r), "refs/heads/trunk");
        assert!(rev(&e, &r, "HEAD").is_none(), "unborn: empty");
    }

    #[test]
    fn a_duplicate_name_in_any_case_is_refused_and_a_failed_create_does_not_block_it() {
        let e = env("dup");
        make(&e, "Mixed", false).unwrap();
        assert!(matches!(
            make(&e, "mixed", false),
            Err(LifecycleError::Exists)
        ));
        assert!(matches!(
            e.lc.create(
                &e.conn,
                &e.owner,
                &e.owner,
                "zed",
                "",
                "bad..branch",
                false,
                10
            ),
            Err(LifecycleError::BadBranch)
        ));
        assert!(
            repos::find_row(&e.conn, "owner", "zed").unwrap().is_none(),
            "an invalid branch never inserts a row"
        );
        // A create whose git step fails (the directory is occupied by a file) rolls back
        // in-process and frees the name.
        std::fs::write(e.lc.repo_dir(2), b"in the way").unwrap();
        assert!(matches!(
            make(&e, "zed", false),
            Err(LifecycleError::GitFailed(_))
        ));
        assert!(
            repos::find_row(&e.conn, "owner", "zed").unwrap().is_none(),
            "row rolled back"
        );
        assert!(!e.lc.repo_dir(2).exists(), "the leftover is removed");
        assert!(
            make(&e, "zed", false).is_ok(),
            "the name is reusable at once"
        );
    }

    #[test]
    fn a_crash_at_every_create_step_is_rolled_back_by_the_reconciler() {
        for step in ["inserted", "initialized", "committed", "synced"] {
            let e = env(&format!("crash-create-{step}"));
            e.lc.arm(step);
            let err = make(&e, "doomed", true).unwrap_err();
            assert!(
                matches!(err, LifecycleError::Crash(s) if s == step),
                "{err:?}"
            );
            let row = repos::find_row(&e.conn, "owner", "doomed")
                .unwrap()
                .unwrap();
            assert_eq!(row.state, "creating");
            // "restart": a fresh runner over the same directory
            let rep = e.lc.reconcile(&e.conn, 20).unwrap();
            assert_eq!(rep.creating_rolled_back, 1, "{step}");
            assert!(
                repos::find_row(&e.conn, "owner", "doomed")
                    .unwrap()
                    .is_none(),
                "{step}: row gone"
            );
            assert!(!e.lc.repo_dir(row.id).exists(), "{step}: directory gone");
            assert!(
                make(&e, "doomed", true).is_ok(),
                "{step}: the name is free and a retry gets a full repo"
            );
        }
    }

    #[test]
    fn delete_moves_to_trash_then_removes_and_a_recreated_name_gets_a_new_id() {
        let e = env("delete");
        let r = make(&e, "doomed", true).unwrap();
        e.lc.delete(&e.conn, &r, 20).unwrap();
        assert!(repos::find_by_id(&e.conn, r.id).unwrap().is_none());
        assert!(!e.lc.repo_dir(r.id).exists() && !e.lc.trash_dir(r.id).exists());
        assert!(
            matches!(e.lc.delete(&e.conn, &r, 21), Err(LifecycleError::Gone)),
            "second delete"
        );
        let again = make(&e, "doomed", true).unwrap();
        assert_ne!(
            again.id, r.id,
            "a recreated name is a new repository in a new directory"
        );
    }

    #[test]
    fn a_crash_at_every_delete_step_is_finished_by_the_reconciler() {
        for step in ["marked", "renamed", "row-deleted"] {
            let e = env(&format!("crash-delete-{step}"));
            let r = make(&e, "doomed", true).unwrap();
            e.lc.arm(step);
            assert!(
                matches!(e.lc.delete(&e.conn, &r, 20), Err(LifecycleError::Crash(_))),
                "{step}"
            );
            e.lc.reconcile(&e.conn, 30).unwrap();
            assert!(
                repos::find_by_id(&e.conn, r.id).unwrap().is_none(),
                "{step}: row gone"
            );
            assert!(
                !e.lc.repo_dir(r.id).exists() && !e.lc.trash_dir(r.id).exists(),
                "{step}: no directory left"
            );
            assert!(make(&e, "doomed", false).is_ok(), "{step}: name reusable");
        }
    }

    #[test]
    fn reconcile_handles_the_remaining_table_rows() {
        let e = env("table");
        // a deleting row with neither directory
        let r = make(&e, "ghost", false).unwrap();
        std::fs::remove_dir_all(e.lc.repo_dir(r.id)).unwrap();
        repos::set_state(&e.conn, r.id, "live", "deleting", 5).unwrap();
        // trash with no row, and a directory with no row at all
        std::fs::create_dir_all(e.lc.trash_dir(99).join("objects")).unwrap();
        std::fs::create_dir_all(e.lc.repo_dir(98).join("objects")).unwrap();
        std::fs::write(e.lc.repo_dir(98).join("precious"), b"data").unwrap();
        // a live row whose directory is missing is reported and left
        let lost = make(&e, "lost", false).unwrap();
        std::fs::remove_dir_all(e.lc.repo_dir(lost.id)).unwrap();
        // a live row whose HEAD disagrees with the row is repaired from the row
        let drift =
            e.lc.create(&e.conn, &e.owner, &e.owner, "drift", "", "main", true, 10)
                .unwrap();
        e.lc.git
            .run(&Spec {
                repo: Some(&e.lc.repo_dir(drift.id)),
                args: &["symbolic-ref", "HEAD", "refs/heads/other"],
                ..Default::default()
            })
            .unwrap();

        let rep = e.lc.reconcile(&e.conn, 40).unwrap();
        assert_eq!(
            rep,
            Report {
                creating_rolled_back: 0,
                deleting_finished: 1,
                trash_removed: 1,
                orphans_moved: 1,
                head_repaired: 1,
                head_repair_failed: 0,
                missing_dirs: 1
            }
        );
        assert!(repos::find_by_id(&e.conn, r.id).unwrap().is_none());
        assert!(!e.lc.trash_dir(99).exists());
        assert!(
            !e.lc.repo_dir(98).exists()
                && e.dir
                    .join("orphans")
                    .join("98.git")
                    .join("precious")
                    .is_file(),
            "an unknown directory is moved, never deleted"
        );
        assert!(
            repos::find_by_id(&e.conn, lost.id).unwrap().is_some(),
            "a live row is never dropped"
        );
        assert_eq!(head(&e, &drift), "refs/heads/main");
    }

    #[test]
    fn a_restored_empty_database_never_erases_repositories() {
        let e = env("restore");
        let r = make(&e, "precious", true).unwrap();
        let dir = e.lc.repo_dir(r.id);
        // lose the database: a fresh, empty one over the same directories
        std::fs::remove_file(db::db_path(&e.dir)).unwrap();
        let conn = db::open_for_admin(&e.dir).unwrap();
        let lc = Lifecycle::new(&e.dir, e.lc.git.clone()).unwrap();
        let rep = lc.reconcile(&conn, 50).unwrap();
        assert_eq!(rep.orphans_moved, 1);
        assert!(
            e.dir
                .join("orphans")
                .join(format!("{}.git", r.id))
                .join("HEAD")
                .is_file(),
            "the repository survives in orphans/"
        );
        assert!(!dir.exists());
    }

    #[test]
    fn set_default_branch_requires_an_existing_branch_and_writes_head_then_row() {
        let e = env("default");
        let r = make(&e, "alpha", true).unwrap();
        let dir = e.lc.repo_dir(r.id);
        assert!(matches!(
            e.lc.set_default_branch(&e.conn, &r, "dev", 20),
            Err(LifecycleError::NoSuchBranch)
        ));
        assert!(
            matches!(
                e.lc.set_default_branch(&e.conn, &r, "main~1", 20),
                Err(LifecycleError::NoSuchBranch)
            ),
            "a revision is not a branch"
        );
        let main = rev(&e, &r, "main").unwrap();
        e.lc.run(&dir, &["update-ref", "refs/heads/dev", &main], None, None)
            .unwrap();
        e.lc.set_default_branch(&e.conn, &r, "dev", 20).unwrap();
        assert_eq!(head(&e, &r), "refs/heads/dev");
        assert_eq!(
            repos::find_by_id(&e.conn, r.id)
                .unwrap()
                .unwrap()
                .default_branch,
            "dev"
        );
        // after a crash between HEAD and the row, the row wins at the next startup
        e.lc.arm("head-written");
        let before = repos::find_by_id(&e.conn, r.id).unwrap().unwrap();
        e.lc.run(
            &dir,
            &["update-ref", "refs/heads/feat/x", &main],
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            e.lc.set_default_branch(&e.conn, &before, "feat/x", 21),
            Err(LifecycleError::Crash(_))
        ));
        assert_eq!(head(&e, &r), "refs/heads/feat/x");
        let rep = e.lc.reconcile(&e.conn, 30).unwrap();
        assert_eq!(rep.head_repaired, 1);
        assert_eq!(head(&e, &r), "refs/heads/dev");
    }

    #[test]
    fn branch_delete_refuses_the_default_and_needs_the_branch_to_exist() {
        let e = env("branchdel");
        let r = make(&e, "alpha", true).unwrap();
        let main = rev(&e, &r, "main").unwrap();
        e.lc.run(
            &e.lc.repo_dir(r.id),
            &["update-ref", "refs/heads/dev", &main],
            None,
            None,
        )
        .unwrap();
        assert!(
            e.lc.delete_branch(&e.conn, &r, "main").is_err(),
            "the default branch stays"
        );
        e.lc.delete_branch(&e.conn, &r, "dev").unwrap();
        assert!(rev(&e, &r, "refs/heads/dev").is_none());
        assert!(matches!(
            e.lc.delete_branch(&e.conn, &r, "dev"),
            Err(LifecycleError::NoSuchBranch)
        ));
    }

    #[test]
    fn a_second_process_cannot_share_the_data_directory() {
        let dir = std::env::temp_dir().join(format!("scl-forge-dirlock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = DirLock::acquire(&dir).unwrap();
        // flock is per open file description, so a second open in this process conflicts too
        assert!(DirLock::acquire(&dir).is_err());
        drop(first);
        assert!(DirLock::acquire(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_interrupted_creates_directory_is_kept_in_orphans_not_deleted() {
        let e = env("keep-creating");
        e.lc.arm("committed");
        assert!(matches!(
            make(&e, "half", true),
            Err(LifecycleError::Crash(_))
        ));
        let id = repos::find_row(&e.conn, "owner", "half")
            .unwrap()
            .unwrap()
            .id;
        let rep = e.lc.reconcile(&e.conn, 20).unwrap();
        assert_eq!(rep.creating_rolled_back, 1);
        assert!(!e.lc.repo_dir(id).exists());
        assert!(
            e.dir
                .join("orphans")
                .join(format!("{id}.git"))
                .join("HEAD")
                .is_file(),
            "the data survives, out of service"
        );
        assert!(repos::find_row(&e.conn, "owner", "half").unwrap().is_none());
    }

    #[test]
    fn a_failed_cleanup_keeps_the_creating_row_so_the_name_stays_blocked_until_it_is_done() {
        use std::os::unix::fs::PermissionsExt;
        let e = env("cleanup-fails");
        e.lc.arm("committed");
        assert!(matches!(
            make(&e, "stuck", true),
            Err(LifecycleError::Crash(_))
        ));
        let id = repos::find_row(&e.conn, "owner", "stuck")
            .unwrap()
            .unwrap()
            .id;
        // repos/ becomes read-only: neither removal nor a move out of it can succeed
        let repos_dir = e.dir.join("repos");
        std::fs::set_permissions(&repos_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let blocked = e.lc.reconcile(&e.conn, 20);
        std::fs::set_permissions(&repos_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        if std::fs::metadata(&repos_dir)
            .map(|_| nix_is_root())
            .unwrap_or(false)
        {
            return; // root ignores directory permissions; the scenario cannot be staged
        }
        assert!(blocked.is_err(), "the failed move is reported");
        let row = repos::find_row(&e.conn, "owner", "stuck")
            .unwrap()
            .expect("the journal row survives a failed cleanup");
        assert_eq!(row.state, "creating");
        assert!(e.lc.repo_dir(id).exists(), "nothing was lost");
        assert!(
            matches!(make(&e, "stuck", false), Err(LifecycleError::Exists)),
            "the name stays blocked until the cleanup is done"
        );
        assert_eq!(
            e.lc.reconcile(&e.conn, 30).unwrap().creating_rolled_back,
            1,
            "the next pass finishes it"
        );
        assert!(make(&e, "stuck", false).is_ok());
    }

    fn nix_is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn a_database_error_aborts_the_pass_before_any_directory_moves() {
        let e = env("db-error");
        let live = make(&e, "alive", true).unwrap();
        std::fs::create_dir_all(e.lc.repo_dir(98).join("objects")).unwrap(); // an orphan to be moved
        e.conn
            .execute_batch("ALTER TABLE repos RENAME TO repos_gone")
            .unwrap();
        assert!(e.lc.reconcile(&e.conn, 20).is_err());
        assert!(
            e.lc.repo_dir(live.id).join("HEAD").is_file(),
            "a live repository is never moved on a lookup error"
        );
        assert!(e.lc.repo_dir(98).exists(), "nothing was touched");
    }

    #[test]
    fn one_unrepairable_repository_does_not_stop_the_pass() {
        let e = env("one-bad");
        let bad = make(&e, "bad", true).unwrap();
        let good =
            e.lc.create(&e.conn, &e.owner, &e.owner, "good", "", "main", true, 10)
                .unwrap();
        e.lc.git
            .run(&Spec {
                repo: Some(&e.lc.repo_dir(good.id)),
                args: &["symbolic-ref", "HEAD", "refs/heads/other"],
                ..Default::default()
            })
            .unwrap();
        std::fs::remove_file(e.lc.repo_dir(bad.id).join("HEAD")).unwrap(); // no longer a repository
        let rep = e.lc.reconcile(&e.conn, 20).unwrap();
        assert_eq!((rep.head_repair_failed, rep.head_repaired), (1, 1));
        assert_eq!(head(&e, &good), "refs/heads/main");
    }

    #[test]
    fn naming_the_current_default_branch_is_a_no_op_decided_under_the_lock() {
        let e = env("default-noop");
        let r = make(&e, "alpha", true).unwrap();
        e.lc.set_default_branch(&e.conn, &r, "main", 20).unwrap(); // already main
        assert_eq!(head(&e, &r), "refs/heads/main");
        // a stale snapshot naming another branch as current still resolves against the row
        let stale = Repo {
            default_branch: "dev".into(),
            ..r.clone()
        };
        e.lc.set_default_branch(&e.conn, &stale, "main", 21)
            .unwrap();
        assert_eq!(
            repos::find_by_id(&e.conn, r.id)
                .unwrap()
                .unwrap()
                .default_branch,
            "main"
        );
    }

    #[test]
    fn a_damaged_repository_is_a_failure_not_a_missing_branch() {
        let e = env("damaged-branch");
        let r = make(&e, "alpha", true).unwrap();
        std::fs::remove_file(e.lc.repo_dir(r.id).join("HEAD")).unwrap(); // no longer a repository
        let a = e.lc.set_default_branch(&e.conn, &r, "dev", 20);
        assert!(matches!(a, Err(LifecycleError::GitFailed(_))), "{a:?}");
        let b = e.lc.delete_branch(&e.conn, &r, "dev");
        assert!(matches!(b, Err(LifecycleError::GitFailed(_))), "{b:?}");
    }

    #[test]
    fn the_default_branch_cannot_be_deleted_by_a_case_alias() {
        let e = env("case-alias");
        let r = make(&e, "alpha", true).unwrap();
        assert!(e.lc.delete_branch(&e.conn, &r, "MAIN").is_err());
        assert!(rev(&e, &r, "refs/heads/main").is_some());
    }
}
