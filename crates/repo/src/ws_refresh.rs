//! `sc ws refresh` (ADR-0056, #215): move a live session onto a newer tip while
//! keeping each workspace's edits, committed or not.
//!
//! A workspace has no commits of its own: its state is the checkout. Refresh
//! commits that state to a throwaway candidate (the harvest pipeline, scanner
//! gate included, but no branch), replays the candidate onto the new tip with
//! the ADR-0049 engine (`replay_commit`, which works on trees and not on the
//! host's working tree), and lays the result over the checkout in place. Only
//! the paths whose tracked content differs between the checkout's state and the
//! result are touched, and only if the file is still what was read, so untracked
//! and ignored files, and files that did not change, are left alone.
//!
//! Everything that can refuse (a conflict, a busy workspace, a gap in the view,
//! a file in the way, a protected path without a key) is decided for every
//! workspace before the first write. The manifest, which carries the new base,
//! is written last.

use std::collections::BTreeSet;
use std::path::PathBuf;

use scl_core::{FileMode, Object, ObjectId, Protection, Store, PROTECTED, RANDOMIZED};

use crate::cache::ProtectedCache;
use crate::error::{Error, Result};
use crate::refs;
use crate::replay::ReplayOutcome;
use crate::repo::Repo;
use crate::sparse::Sparse;
use crate::workspace::HarvestResult;
use crate::worktree::{
    apply_file_mode, clear_dir_obstruction, decrypt_protected, dir_clearable, disk_is_blob, lstat,
    preflight_view, refuse_blocked_parents, safe_join, tree_file_entries_with_perms_sparse,
    under_symlink,
};
use crate::ws::{ensure_idle, label_prefix, open_session, write_manifest, WsEntry};

/// What refresh did to one workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsRefreshEntry {
    /// The workspace's index.
    pub index: u32,
    /// Files written (added or changed).
    pub written: usize,
    /// Files removed.
    pub removed: usize,
    /// Protected paths left absent: the new tip changed them and no key opens them.
    pub skipped: Vec<String>,
}

/// The result of [`Repo::ws_refresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsRefresh {
    /// The branch the session is now based on.
    pub branch: String,
    /// The base before the refresh.
    pub from: ObjectId,
    /// The base after it (the branch tip). Equal to `from` when nothing moved.
    pub to: ObjectId,
    /// One entry per live workspace; empty when the session was already there.
    pub workspaces: Vec<WsRefreshEntry>,
}

/// A write the plan decided on: path, new blob, mode and perms, and the
/// candidate's entry at the path (`None` when the checkout does not track it).
type PlannedWrite = (String, ObjectId, FileMode, u8, Option<(ObjectId, u8)>);

/// The writes one workspace needs, decided before anything is touched. Each
/// carries what the candidate recorded at its path, so apply can check again,
/// right before touching the file, that it is still that.
struct Plan {
    removals: Vec<(String, ObjectId, u8)>,
    writes: Vec<PlannedWrite>,
    skipped: Vec<String>,
}

/// One workspace's refresh, ready to apply.
struct Job {
    index: u32,
    dir: PathBuf,
    /// Wrap lists of the tree being laid out, to decrypt protected paths.
    protection: Protection,
    plan: Plan,
    cache: ProtectedCache,
}

#[cfg(test)]
thread_local! {
    /// Test seam: fail the Nth file operation of the apply phase (0 = the first).
    static FAIL_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// Test seam: runs once the plan is final and the pending marker is written,
    /// right before the first file is touched (a stand-in for an editor).
    static BEFORE_APPLY: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test seam for a crash in the middle of the apply phase; a no-op outside tests.
fn injected_failure() -> Result<()> {
    #[cfg(test)]
    FAIL_AFTER.with(|c| match c.get() {
        Some(0) => Err(Error::InvalidArgument("injected failure".into())),
        Some(n) => {
            c.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })?;
    Ok(())
}

fn before_apply_hook() {
    #[cfg(test)]
    BEFORE_APPLY.with(|h| {
        if let Some(f) = h.borrow().as_ref() {
            f();
        }
    });
}

fn changed_since_read(p: &str) -> Error {
    Error::InvalidArgument(format!(
        "{p} changed in the workspace while it was being read; run `sc ws refresh` again"
    ))
}

/// Whether the file at `full` is still exactly what the candidate recorded at
/// `p` (`prior` = blob and perms). A plain file is compared by bytes. A
/// protected file's plaintext is proved the same way commit proves it: a
/// randomized one by the workspace cache, a convergent one by re-encrypting.
/// Anything that is not a regular file reads as changed.
fn still_read(
    full: &std::path::Path,
    p: &str,
    prior: (ObjectId, u8),
    cache: &ProtectedCache,
) -> bool {
    let (blob, perms) = prior;
    if perms & PROTECTED == 0 {
        return disk_is_blob(full, &blob);
    }
    if !full.symlink_metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
    let Ok(bytes) = std::fs::read(full).map(scl_crypto::Zeroizing::new) else {
        return false;
    };
    if perms & RANDOMIZED != 0 {
        cache.unchanged(p, &bytes) == Some(blob)
    } else {
        Object::blob(scl_crypto::encrypt_path(&bytes).0).id() == blob
    }
}

/// The disk state of path `p` against the candidate's record of it: fine to
/// replace or remove (`Ok(())`), or changed since it was read. A tracked plain
/// file that is gone was deleted after the read; a protected one may never have
/// been laid out (no key at fork), which is not a change.
fn check_prior(
    full: &std::path::Path,
    p: &str,
    prior: Option<(ObjectId, u8)>,
    target: Option<ObjectId>,
    cache: &ProtectedCache,
) -> Result<()> {
    let meta = lstat(full)?;
    match (meta, prior) {
        (None, Some((_, perms))) if perms & PROTECTED == 0 => Err(changed_since_read(p)),
        (None, _) => Ok(()),
        (Some(m), _) if m.is_dir() => Ok(()), // judged by the directory rules
        (Some(_), Some(prior)) if still_read(full, p, prior, cache) => Ok(()),
        // Already the target bytes (a plain file): nothing of the user's to lose.
        // Not for a path the candidate did not track: an ignored file with the
        // same bytes is still the user's, and a rewrite would replace its inode.
        (Some(_), Some(_)) if target.is_some_and(|t| disk_is_blob(full, &t)) => Ok(()),
        (Some(_), Some(_)) => Err(changed_since_read(p)),
        (Some(_), None) => Err(Error::InvalidArgument(format!(
            "cannot write {p}: a file of yours (untracked or ignored) stands there; move it \
             away, then retry"
        ))),
    }
}

/// Decide, without writing, how to turn the checkout (laid out from `old_root`)
/// into `new_root` under `sparse`. Refuses if a file it must replace is no longer
/// the tracked bytes, or a user's file stands where one must go.
fn plan_checkout(
    root: &std::path::Path,
    store: &mut Store,
    old_root: ObjectId,
    new_root: ObjectId,
    protection: &Protection,
    identity: Option<&scl_crypto::SecretKey>,
    sparse: &Sparse,
    cache: &ProtectedCache,
) -> Result<Plan> {
    // Bounded by the view on both sides: a partial clone does not hold the rest.
    let old = tree_file_entries_with_perms_sparse(store, old_root, sparse)?;
    let new = tree_file_entries_with_perms_sparse(store, new_root, sparse)?;
    let (mut removals, mut writes, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    for (p, (blob, _, perms)) in old.iter().filter(|(p, _)| !new.contains_key(*p)) {
        let full = safe_join(root, p)?;
        if lstat(&full)?.is_none() || under_symlink(root, p) {
            continue;
        }
        check_prior(&full, p, Some((*blob, *perms)), None, cache)?;
        removals.push((p.clone(), *blob, *perms));
    }
    let removable: BTreeSet<&str> = removals.iter().map(|r| r.0.as_str()).collect();
    for (p, (blob, mode, perms)) in &new {
        let prior = old.get(p);
        if prior.is_some_and(|(b, m, _)| b == blob && m == mode) {
            continue;
        }
        let full = safe_join(root, p)?;
        let meta = lstat(&full)?;
        let protected = perms & PROTECTED != 0;
        if protected {
            let Object::Blob(bytes) = store.get(blob)? else {
                continue;
            };
            if decrypt_protected(&bytes, blob, protection, identity).is_none() {
                // Leaving the old plaintext would pass it off as the new content.
                if meta.is_some() {
                    return Err(Error::InvalidArgument(format!(
                        "{p} is protected and changed on the new tip: pass --identity so \
                         refresh can decrypt it"
                    )));
                }
                skipped.push(p.clone());
                continue;
            }
        }
        let prior = prior.map(|(b, _, op)| (*b, *op));
        if meta.as_ref().is_some_and(|m| m.is_dir()) {
            // Only a directory the removals are about to empty is a husk: an
            // empty one the refresh did not empty is the user's (as in any
            // forward op), whose working directory a process may hold.
            let under = format!("{p}/");
            let emptied = removals.iter().any(|r| r.0.starts_with(&under));
            if !emptied || !dir_clearable(&full, p, &|c| removable.contains(c)) {
                return Err(Error::InvalidArgument(format!(
                    "cannot write {p}: a directory with untracked or ignored content \
                     stands there; move it away, then retry"
                )));
            }
        } else {
            check_prior(&full, p, prior, (!protected).then_some(*blob), cache)?;
        }
        writes.push((p.clone(), *blob, *mode, *perms, prior));
    }
    refuse_blocked_parents(root, writes.iter().map(|w| &w.0), &|c| {
        removable.contains(c)
    })?;
    Ok(Plan {
        removals,
        writes,
        skipped,
    })
}

/// Carry out one workspace's plan. Each file is replaced atomically, so an
/// interruption never leaves a half-written one, and is checked once more right
/// before it is touched: the plan was made earlier, and anything can edit a
/// checkout meanwhile. `done` counts the file operations completed, across
/// workspaces. A removal that empties a directory takes the directory too.
fn apply_plan(
    store: &mut Store,
    job: &mut Job,
    identity: Option<&scl_crypto::SecretKey>,
    done: &mut usize,
) -> Result<()> {
    for (p, blob, perms) in &job.plan.removals {
        injected_failure()?;
        let full = safe_join(&job.dir, p)?;
        if under_symlink(&job.dir, p) {
            return Err(changed_since_read(p));
        }
        check_prior(&full, p, Some((*blob, *perms)), None, &job.cache)?;
        *done += 1; // from here on the checkout may differ from the old state
        match std::fs::remove_file(&full) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    for (p, blob, mode, perms, prior) in &job.plan.writes {
        injected_failure()?;
        let full = safe_join(&job.dir, p)?;
        let Object::Blob(bytes) = store.get(blob)? else {
            continue;
        };
        let protected = perms & PROTECTED != 0;
        // A parent swapped for a symlink since the plan would send the write out
        // of the workspace.
        if under_symlink(&job.dir, p) {
            return Err(changed_since_read(p));
        }
        check_prior(&full, p, *prior, (!protected).then_some(*blob), &job.cache)?;
        *done += 1; // from here on the checkout may differ from the old state
        clear_dir_obstruction(&full, p)?;
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if protected {
            let pt =
                decrypt_protected(&bytes, blob, &job.protection, identity).ok_or_else(|| {
                    Error::InvalidArgument(format!("{p}: the key stopped opening it mid-refresh"))
                })?;
            scl_core::fsutil::atomic_write_durable(&full, &pt[..])?;
            apply_file_mode(&full, *mode)?;
            if perms & RANDOMIZED != 0 {
                job.cache.record(p, &pt[..], *blob);
            }
        } else {
            scl_core::fsutil::atomic_write_durable(&full, &bytes[..])?;
            apply_file_mode(&full, *mode)?;
        }
    }
    // Only directories a removal emptied: `remove_dir` fails on anything else.
    for (p, ..) in &job.plan.removals {
        let mut dir = safe_join(&job.dir, p)?;
        while dir.pop() && dir != job.dir && std::fs::remove_dir(&dir).is_ok() {}
    }
    Ok(())
}

impl Repo {
    /// Move session `name` onto the tip of `onto` (default the checked-out
    /// branch), keeping every live workspace's edits.
    ///
    /// Per workspace: its checkout is committed to a throwaway candidate whose
    /// parent is the session's base, the candidate is replayed onto the new tip
    /// with the ADR-0049 engine, and the result is laid over the checkout in
    /// place. Edits stay edits: the workspace is still "changed" afterwards, now
    /// against the new base, and a later harvest lands them as before. The
    /// host's working tree and refs are not touched.
    ///
    /// The whole refresh refuses, before writing anything, if any workspace is
    /// running a command, trips the secret scanner, conflicts with the new tip
    /// (in or out of the view), needs a protected path decrypted without
    /// `identity`, has a file or directory of the user's where the new tip puts
    /// one, or the view of the new tip cannot be filled (the gap error,
    /// ADR-0050). The write order is a `pending_refresh` marker in the manifest,
    /// each checkout, then the manifest with the new base and no marker. A crash
    /// in between leaves checkouts holding a mix of old and merged files and a
    /// marker that makes harvest refuse until `sc ws refresh` is run again
    /// (abandon still works). Nothing is lost: every file is replaced
    /// atomically, only over the bytes the candidate read.
    pub fn ws_refresh(
        &self,
        name: Option<&str>,
        onto: Option<&str>,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsRefresh> {
        self.refuse_on_private("sc ws refresh")?;
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let session = open_session(self.layout(), name)?;
        let branch = match onto {
            Some(b) => b.to_string(),
            None => refs::current_branch(self.layout())?,
        };
        let to = refs::read_branch_tip(self.layout(), &branch)?.ok_or_else(|| match onto {
            Some(_) => Error::NoSuchBranch(branch.clone()),
            None => Error::Unborn,
        })?;
        if self.manifest_at(&to)?.is_some() {
            return Err(Error::PrivateUnsupported("sc ws refresh".into()));
        }
        // An unfinished refresh left files at the state of its own target. Finish
        // it onto that exact tip first: replayed onto a tip the branch has since
        // moved to, those files would read as the agent's own changes (and would
        // survive a host revert).
        if let Some(pending) = session.pending_refresh.filter(|p| *p != to) {
            self.refresh_onto(name, &session.base_branch, pending, identity)?;
        }
        self.refresh_onto(name, &branch, to, identity)
    }

    /// [`Self::ws_refresh`] onto the snapshot `to`, labelled as `branch`.
    fn refresh_onto(
        &self,
        name: Option<&str>,
        branch: &str,
        to: ObjectId,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsRefresh> {
        let branch = branch.to_string();
        let mut session = open_session(self.layout(), name)?;
        let prior_pending = session.pending_refresh;
        let from = session.base_snapshot;
        if to == from && branch == session.base_branch && session.pending_refresh.is_none() {
            return Ok(WsRefresh {
                branch,
                from,
                to,
                workspaces: Vec::new(),
            });
        }
        let mut live: Vec<WsEntry> = session
            .workspaces
            .iter()
            .filter(|e| e.live)
            .cloned()
            .collect();
        live.sort_by_key(|e| e.index);
        for e in &live {
            ensure_idle(self.layout(), name, e.index)?;
        }

        // The session's own fork-time view, as harvest uses (ADR-0056, 7).
        let sparse = Sparse::new(session.sparse.clone());
        let tip = self.snapshot(&to)?;
        self.ensure_view(tip.root, &sparse)?;
        let base_root = self.snapshot(&from)?.root;
        let key = crate::cache::local_key(self.layout())?;

        let mut refusals: Vec<String> = Vec::new();
        let mut jobs: Vec<Job> = Vec::new();
        for e in &live {
            let mut cache = ProtectedCache::open(
                key,
                e.dir.clone(),
                Some(self.layout().ws_cache_path(name, e.index as usize)),
            );
            let msg = format!("ws {}-{} refresh", label_prefix(name), e.index);
            // A checkout cannot change the secret registry, so the candidate
            // carries the base's and no registry merge is needed.
            let candidate = crate::workspace::workspace_candidate(
                self,
                from,
                &e.dir,
                &session.author,
                &msg,
                &sparse,
                Some(&mut cache),
            )?;
            let (old_root, new_root, protection) = match candidate {
                HarvestResult::Rejected(report) => {
                    refusals.push(format!(
                        "workspace {}: the secret scanner rejected it ({report}); fix it first",
                        e.index
                    ));
                    continue;
                }
                HarvestResult::Unchanged => (base_root, tip.root, tip.protection.clone()),
                HarvestResult::Committed(c) => {
                    let c_root = self.snapshot(&c)?.root;
                    let onto_tip = (tip.root, &tip.protection);
                    match crate::replay::replay_commit(self, c, onto_tip, identity, None) {
                        Ok(ReplayOutcome::Clean { root, protection }) => (c_root, root, protection),
                        Ok(ReplayOutcome::Empty) => (c_root, tip.root, tip.protection.clone()),
                        Ok(ReplayOutcome::Conflicts { paths, .. }) => {
                            refusals.push(format!(
                                "workspace {}: conflicts with {branch} in {}",
                                e.index,
                                paths.join(", ")
                            ));
                            continue;
                        }
                        Err(
                            err @ (Error::ProtectedMergeNeedsIdentity(_)
                            | Error::NotAuthorized(_)
                            | Error::PathCollision(_)),
                        ) => {
                            refusals.push(format!("workspace {}: {err}", e.index));
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            // The replayed tree's view, filled (lazy clone) or reported as a gap.
            self.ensure_view(new_root, &sparse)?;
            let plan = {
                let store_arc = self.vfs().store();
                let mut store = store_arc.lock().unwrap();
                preflight_view(self.layout(), &mut store, new_root, &sparse)?;
                let planned = plan_checkout(
                    &e.dir,
                    &mut store,
                    old_root,
                    new_root,
                    &protection,
                    identity,
                    &sparse,
                    &cache,
                );
                match planned {
                    Ok(plan) => plan,
                    Err(Error::InvalidArgument(msg)) => {
                        refusals.push(format!("workspace {}: {msg}", e.index));
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            };
            jobs.push(Job {
                index: e.index,
                dir: e.dir.clone(),
                protection,
                plan,
                cache,
            });
        }
        if !refusals.is_empty() {
            return Err(Error::InvalidArgument(format!(
                "sc ws refresh refused; nothing was changed:\n  {}",
                refusals.join("\n  ")
            )));
        }

        // From here the checkouts may hold a mix of old and refreshed files, and
        // harvest would read the refreshed ones as the agent's own: mark the
        // session, durably, before the first write (cleared with the new base).
        session.pending_refresh = Some(to);
        write_manifest(self.layout(), &session)?;
        before_apply_hook();
        let mut report = Vec::with_capacity(jobs.len());
        let mut done = 0;
        let applied = {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            jobs.iter_mut().try_for_each(|job| {
                apply_plan(&mut store, job, identity, &mut done)?;
                report.push(WsRefreshEntry {
                    index: job.index,
                    written: job.plan.writes.len(),
                    removed: job.plan.removals.len(),
                    skipped: job.plan.skipped.clone(),
                });
                Ok(())
            })
        };
        if let Err(e) = applied {
            if done == 0 {
                // Refused before the first file was touched: back to what was
                // there (an earlier crash's marker stays, a fresh one goes).
                session.pending_refresh = prior_pending;
                write_manifest(self.layout(), &session)?;
            }
            return Err(e);
        }
        // The new base last: until it lands, the old one is still the truth.
        session.pending_refresh = None;
        session.base_snapshot = to;
        session.base_branch = branch.clone();
        write_manifest(self.layout(), &session)?;
        for job in &jobs {
            job.cache.save_best_effort();
        }
        Ok(WsRefresh {
            branch,
            from,
            to,
            workspaces: report,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree;
    use crate::ws::WsHarvestOutcome;
    use std::path::Path;

    const LINES: &str = "one\ntwo\nthree\nfour\nfive\n";

    fn tmp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("scl-wsr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn init(tag: &str) -> (Repo, PathBuf) {
        let root = tmp_root(tag);
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), LINES).unwrap();
        repo.commit("t", "base").unwrap();
        (repo, root)
    }

    /// Commit `files` on the host (`None` deletes the path).
    fn host_commit(repo: &Repo, root: &Path, files: &[(&str, Option<&str>)]) -> ObjectId {
        for (p, body) in files {
            let full = root.join(p);
            match body {
                Some(b) => {
                    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                    std::fs::write(full, b).unwrap();
                }
                None => std::fs::remove_file(full).unwrap(),
            }
        }
        repo.commit("t", "host").unwrap()
    }

    fn read(dir: &Path, p: &str) -> String {
        std::fs::read_to_string(dir.join(p)).unwrap()
    }

    fn tree_has(repo: &Repo, tip: ObjectId, path: &str) -> Option<Vec<u8>> {
        let a = repo.vfs().store();
        let mut s = a.lock().unwrap();
        let root = s.get_snapshot(&tip).unwrap().root;
        let entries = worktree::tree_file_entries_with_perms(&mut s, root).unwrap();
        let (id, ..) = *entries.get(path)?;
        match s.get(&id).unwrap() {
            Object::Blob(b) => Some(b.to_vec()),
            _ => None,
        }
    }

    fn base_of(repo: &Repo, name: Option<&str>) -> ObjectId {
        repo.ws_session(name).unwrap().unwrap().base_snapshot
    }

    fn cleanup(repo: Repo, root: &Path) {
        drop(repo);
        std::fs::remove_dir_all(root).unwrap();
        assert!(!root.exists());
    }

    /// Clears the before-apply hook however the test ends.
    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            BEFORE_APPLY.with(|h| *h.borrow_mut() = None);
        }
    }

    /// Resets the failure seam however the test ends.
    struct FailGuard;
    impl FailGuard {
        fn after(n: usize) -> FailGuard {
            FAIL_AFTER.with(|c| c.set(Some(n)));
            FailGuard
        }
    }
    impl Drop for FailGuard {
        fn drop(&mut self) {
            FAIL_AFTER.with(|c| c.set(None));
        }
    }

    #[test]
    fn refresh_with_no_edits_lays_out_the_new_tip() {
        let (repo, root) = init("clean");
        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        let tip = host_commit(&repo, &root, &[("b.txt", Some("new\n")), ("a.txt", None)]);

        let r = repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(
            (r.from, r.to, r.branch.as_str()),
            (session.base_snapshot, tip, "main")
        );
        assert_eq!(r.workspaces.len(), 2);
        assert_eq!((r.workspaces[0].written, r.workspaces[0].removed), (1, 1));
        for e in &session.workspaces {
            assert_eq!(read(&e.dir, "b.txt"), "new\n");
            assert!(!e.dir.join("a.txt").exists());
            assert!(!repo.ws_changed(None, e).unwrap(), "no edits, so unchanged");
        }
        assert_eq!(base_of(&repo, None), tip);
        // The listing now shows the new base.
        let s = repo.ws_session(None).unwrap().unwrap();
        assert_eq!((s.base_branch.as_str(), s.base_snapshot), ("main", tip));
        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        assert!(out
            .iter()
            .all(|o| matches!(o, WsHarvestOutcome::Unchanged { .. })));
        assert_eq!(repo.head_tip().unwrap(), Some(tip));
        cleanup(repo, &root);
    }

    #[test]
    fn refresh_when_already_on_the_tip_does_nothing() {
        let (repo, root) = init("noop");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        std::fs::write(s.workspaces[0].dir.join("a.txt"), "edit\n").unwrap();
        let r = repo.ws_refresh(None, None, None).unwrap();
        assert!(r.workspaces.is_empty() && r.from == r.to);
        assert_eq!(read(&s.workspaces[0].dir, "a.txt"), "edit\n");
        cleanup(repo, &root);
    }

    #[test]
    fn refresh_keeps_uncommitted_edits_and_harvest_then_lands_them() {
        let (repo, root) = init("edits");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        std::fs::write(dir.join("a.txt"), "ONE\ntwo\nthree\nfour\nfive\n").unwrap();
        std::fs::write(dir.join("mine.txt"), "mine\n").unwrap();
        let tip = host_commit(
            &repo,
            &root,
            &[
                ("a.txt", Some("one\ntwo\nthree\nfour\nFIVE\n")),
                ("b.txt", Some("host\n")),
            ],
        );

        let r = repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(r.workspaces[0].index, 1);
        // Both sides of the same file, the workspace's new file and the host's.
        assert_eq!(read(&dir, "a.txt"), "ONE\ntwo\nthree\nfour\nFIVE\n");
        assert_eq!(read(&dir, "mine.txt"), "mine\n");
        assert_eq!(read(&dir, "b.txt"), "host\n");
        assert_eq!(base_of(&repo, None), tip);
        let e = &repo.ws_session(None).unwrap().unwrap().workspaces[0];
        assert!(
            repo.ws_changed(None, e).unwrap(),
            "the edits are still edits"
        );

        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        let merged = match out.as_slice() {
            [WsHarvestOutcome::Landed { merged_tip, .. }] => *merged_tip,
            other => panic!("expected a landing, got {other:?}"),
        };
        // Based on the new tip, so it lands as a fast-forward of it.
        assert_eq!(repo.snapshot(&merged).unwrap().parents, vec![tip]);
        assert_eq!(
            tree_has(&repo, merged, "a.txt").unwrap(),
            b"ONE\ntwo\nthree\nfour\nFIVE\n"
        );
        assert!(tree_has(&repo, merged, "mine.txt").is_some());
        assert!(tree_has(&repo, merged, "b.txt").is_some());
        cleanup(repo, &root);
    }

    #[test]
    fn refresh_applies_deletions_both_ways() {
        let root = tmp_root("del");
        let repo = Repo::init(&root).unwrap();
        for f in ["gone.txt", "keep.txt", "stay.txt"] {
            std::fs::write(root.join(f), format!("{f}\n")).unwrap();
        }
        repo.commit("t", "base").unwrap();
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        std::fs::remove_file(dir.join("keep.txt")).unwrap();
        host_commit(&repo, &root, &[("gone.txt", None)]);

        repo.ws_refresh(None, None, None).unwrap();
        assert!(!dir.join("gone.txt").exists(), "the host deleted it");
        assert!(
            !dir.join("keep.txt").exists(),
            "the workspace's deletion stays"
        );
        assert!(dir.join("stay.txt").exists());
        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        let [WsHarvestOutcome::Landed { merged_tip, .. }] = out.as_slice() else {
            panic!("expected a landing, got {out:?}")
        };
        assert!(tree_has(&repo, *merged_tip, "keep.txt").is_none());
        assert!(tree_has(&repo, *merged_tip, "gone.txt").is_none());
        assert!(tree_has(&repo, *merged_tip, "stay.txt").is_some());
        cleanup(repo, &root);
    }

    #[test]
    fn a_conflict_refuses_the_whole_refresh_and_changes_nothing() {
        let (repo, root) = init("conflict");
        let s = repo.ws_fork(None, 2, "t", None).unwrap();
        let (d1, d2) = (s.workspaces[0].dir.clone(), s.workspaces[1].dir.clone());
        std::fs::write(d1.join("a.txt"), "ws one\ntwo\nthree\nfour\nfive\n").unwrap();
        std::fs::write(d2.join("other.txt"), "two\n").unwrap();
        let old_base = base_of(&repo, None);
        host_commit(
            &repo,
            &root,
            &[
                ("a.txt", Some("host one\ntwo\nthree\nfour\nfive\n")),
                ("b.txt", Some("host\n")),
            ],
        );

        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(
            err.contains("nothing was changed")
                && err.contains("workspace 1")
                && err.contains("a.txt"),
            "{err}"
        );
        assert!(!err.contains("workspace 2"), "{err}");
        assert_eq!(base_of(&repo, None), old_base);
        assert_eq!(read(&d1, "a.txt"), "ws one\ntwo\nthree\nfour\nfive\n");
        assert!(!d1.join("b.txt").exists() && !d2.join("b.txt").exists());
        assert_eq!(read(&d2, "other.txt"), "two\n");
        // Harvest still works exactly as before: one falls back, one lands.
        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        assert!(
            matches!(out[0], WsHarvestOutcome::FallbackBranch { .. }),
            "{out:?}"
        );
        assert!(matches!(out[1], WsHarvestOutcome::Landed { .. }), "{out:?}");
        cleanup(repo, &root);
    }

    #[test]
    fn a_workspace_with_a_running_command_refuses_the_refresh() {
        let (repo, root) = init("busy");
        let s = repo.ws_fork(None, 2, "t", None).unwrap();
        host_commit(&repo, &root, &[("b.txt", Some("host\n"))]);
        let plan = repo.ws_run_plan(None, 2, false, None).unwrap();
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(
            err.contains("workspace 2") && err.contains("still running"),
            "{err}"
        );
        assert!(
            !s.workspaces[0].dir.join("b.txt").exists(),
            "workspace 1 untouched too"
        );
        drop(plan);
        repo.ws_refresh(None, None, None).unwrap();
        assert!(s.workspaces[0].dir.join("b.txt").exists());
        cleanup(repo, &root);
    }

    #[test]
    fn named_sessions_refresh_independently() {
        let (repo, root) = init("named");
        let a = repo.ws_fork(Some("a"), 1, "t", None).unwrap();
        let b = repo.ws_fork(Some("b"), 1, "t", None).unwrap();
        let old = a.base_snapshot;
        let tip = host_commit(&repo, &root, &[("b.txt", Some("host\n"))]);

        repo.ws_refresh(Some("a"), None, None).unwrap();
        assert!(a.workspaces[0].dir.join("b.txt").exists());
        assert!(!b.workspaces[0].dir.join("b.txt").exists());
        assert_eq!(base_of(&repo, Some("a")), tip);
        assert_eq!(
            base_of(&repo, Some("b")),
            old,
            "the other session is untouched"
        );
        repo.ws_refresh(Some("b"), None, None).unwrap();
        assert_eq!(base_of(&repo, Some("b")), tip);
        cleanup(repo, &root);
    }

    #[test]
    fn a_user_file_where_the_new_tip_adds_one_refuses() {
        let (repo, root) = init("untracked");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        std::fs::write(dir.join(".scignore"), "scratch/\n").unwrap();
        std::fs::create_dir_all(dir.join("scratch")).unwrap();
        std::fs::write(dir.join("scratch/log"), "agent file\n").unwrap();
        // The host's new tracked file would land on the agent's own ignored one.
        host_commit(
            &repo,
            &root,
            &[("b.txt", Some("host\n")), ("scratch/log", Some("host\n"))],
        );
        let old = base_of(&repo, None);
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(
            err.contains("workspace 1") && err.contains("scratch/log") && err.contains("stands"),
            "{err}"
        );
        assert_eq!(base_of(&repo, None), old);
        assert!(!dir.join("b.txt").exists(), "nothing was written");
        assert_eq!(read(&dir, "scratch/log"), "agent file\n");
        cleanup(repo, &root);
    }

    #[test]
    fn an_ignored_file_with_the_target_bytes_and_an_empty_directory_still_refuse() {
        let (repo, root) = init("in-the-way");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        std::fs::write(dir.join(".scignore"), "scratch/\n").unwrap();
        std::fs::create_dir_all(dir.join("scratch")).unwrap();
        std::fs::write(dir.join("scratch/log"), "host\n").unwrap();
        std::fs::create_dir_all(dir.join("mine")).unwrap();
        host_commit(
            &repo,
            &root,
            &[("scratch/log", Some("host\n")), ("mine", Some("a file\n"))],
        );
        // The empty directory first (it sorts first), then, once moved, the ignored file.
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(err.contains("cannot write mine"), "{err}");
        assert!(dir.join("mine").is_dir());
        std::fs::remove_dir(dir.join("mine")).unwrap();
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(
            err.contains("scratch/log") && err.contains("stands there"),
            "{err}"
        );
        assert_eq!(read(&dir, "scratch/log"), "host\n");
        cleanup(repo, &root);
    }

    #[test]
    fn an_ignored_untracked_file_is_left_alone() {
        let (repo, root) = init("ignored");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        std::fs::write(dir.join(".scignore"), "scratch/\n").unwrap();
        std::fs::create_dir_all(dir.join("scratch")).unwrap();
        std::fs::write(dir.join("scratch/log"), "keep me\n").unwrap();
        host_commit(&repo, &root, &[("b.txt", Some("host\n"))]);
        repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(read(&dir, "scratch/log"), "keep me\n");
        assert_eq!(read(&dir, "b.txt"), "host\n");
        cleanup(repo, &root);
    }

    /// The same fixture for both crash tests: two edited workspaces and a host
    /// that moved on in other files.
    fn crash_fixture(tag: &str) -> (Repo, PathBuf, Vec<PathBuf>, ObjectId, ObjectId) {
        let (repo, root) = init(tag);
        let s = repo.ws_fork(None, 2, "t", None).unwrap();
        let dirs: Vec<PathBuf> = s.workspaces.iter().map(|e| e.dir.clone()).collect();
        std::fs::write(dirs[0].join("a.txt"), "ONE\ntwo\nthree\nfour\nfive\n").unwrap();
        std::fs::write(dirs[1].join("w2.txt"), "w2\n").unwrap();
        let old = s.base_snapshot;
        let tip = host_commit(
            &repo,
            &root,
            &[("b.txt", Some("b\n")), ("c.txt", Some("c\n"))],
        );
        (repo, root, dirs, old, tip)
    }

    #[test]
    fn an_interrupted_refresh_blocks_harvest_until_it_is_finished() {
        let (repo, root, dirs, old, _tip) = crash_fixture("crash-harvest");
        {
            // One file into the first workspace, then the apply phase dies.
            let _g = FailGuard::after(1);
            let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
            assert!(err.contains("injected failure"), "{err}");
        }
        assert_eq!(
            base_of(&repo, None),
            old,
            "the manifest still names the old base"
        );
        assert!(repo
            .ws_session(None)
            .unwrap()
            .unwrap()
            .pending_refresh
            .is_some());
        assert!(dirs[0].join("b.txt").exists() && !dirs[0].join("c.txt").exists());
        assert!(dirs[1].join("w2.txt").exists() && !dirs[1].join("b.txt").exists());

        assert!(repo.ws_run_plan(None, 1, false, None).is_err());
        // Harvest would read the refreshed b.txt as the agent's own change, and
        // re-apply it even after the host reverts it: it refuses instead.
        let err = repo
            .ws_harvest(None, None, "t", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("did not finish") && err.contains("sc ws refresh"),
            "{err}"
        );
        let tip2 = host_commit(&repo, &root, &[("b.txt", None)]);

        let r = repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(r.to, tip2);
        assert!(repo
            .ws_session(None)
            .unwrap()
            .unwrap()
            .pending_refresh
            .is_none());
        assert!(
            !dirs[0].join("b.txt").exists(),
            "the host's revert is honoured"
        );
        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        assert!(
            out.iter()
                .all(|o| matches!(o, WsHarvestOutcome::Landed { .. })),
            "{out:?}"
        );
        let head = repo.head_tip().unwrap().unwrap();
        assert_eq!(
            tree_has(&repo, head, "a.txt").unwrap(),
            b"ONE\ntwo\nthree\nfour\nfive\n"
        );
        assert!(tree_has(&repo, head, "b.txt").is_none(), "not re-applied");
        for p in ["c.txt", "w2.txt"] {
            assert!(tree_has(&repo, head, p).is_some(), "{p} must survive");
        }
        cleanup(repo, &root);
    }

    #[test]
    fn a_refused_retry_keeps_the_marker_of_an_earlier_crash() {
        let (repo, root, dirs, ..) = crash_fixture("crash-retry-refused");
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, None).unwrap_err();
        }
        // The retry's first file is refused: workspace 1 has since gained a c.txt.
        let d = dirs[0].clone();
        BEFORE_APPLY.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::write(d.join("c.txt"), "late\n").unwrap();
            }))
        });
        let _reset = HookGuard;
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(err.contains("c.txt"), "{err}");
        assert!(repo
            .ws_session(None)
            .unwrap()
            .unwrap()
            .pending_refresh
            .is_some());
        cleanup(repo, &root);
    }

    #[cfg(unix)]
    #[test]
    fn a_parent_swapped_for_a_symlink_after_the_plan_is_not_followed() {
        let root = tmp_root("symlink");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/f"), "f\n").unwrap();
        repo.commit("t", "base").unwrap();
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        let outside = tmp_root("symlink-outside");
        std::fs::create_dir_all(&outside).unwrap();
        host_commit(&repo, &root, &[("sub/new", Some("new\n"))]);
        let (d, o) = (dir.clone(), outside.clone());
        BEFORE_APPLY.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_dir_all(d.join("sub")).unwrap();
                std::os::unix::fs::symlink(&o, d.join("sub")).unwrap();
            }))
        });
        let _reset = HookGuard;
        repo.ws_refresh(None, None, None).unwrap_err();
        assert!(!outside.join("new").exists(), "nothing written outside");
        std::fs::remove_dir_all(&outside).unwrap();
        cleanup(repo, &root);
    }

    #[test]
    fn an_interrupted_refresh_can_be_abandoned() {
        let (repo, root, _dirs, ..) = crash_fixture("crash-abandon");
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, None).unwrap_err();
        }
        assert_eq!(repo.ws_abandon(None, None).unwrap(), 0);
        assert!(repo.ws_session(None).unwrap().is_none());
        cleanup(repo, &root);
    }

    #[test]
    fn a_refusal_before_the_first_write_leaves_nothing_pending() {
        let (repo, root) = init("noop-pending");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        host_commit(&repo, &root, &[("a.txt", Some("host\n"))]);
        // An editor changes the file after the plan is made, before the first write.
        let d = dir.clone();
        BEFORE_APPLY.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::write(d.join("a.txt"), "edited late\n").unwrap();
            }))
        });
        let _reset = HookGuard;
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(err.contains("a.txt changed in the workspace"), "{err}");
        assert_eq!(
            read(&dir, "a.txt"),
            "edited late\n",
            "the edit is not overwritten"
        );
        let session = repo.ws_session(None).unwrap().unwrap();
        assert!(session.pending_refresh.is_none() && session.base_snapshot == s.base_snapshot);
        cleanup(repo, &root);
    }

    #[test]
    fn a_protected_file_edited_after_the_plan_is_not_overwritten() {
        let (repo, root) = init("late-protected");
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x"), "secret x\n").unwrap();
        repo.commit("t", "protected").unwrap();
        let s = repo.ws_fork(None, 1, "t", Some(&sk)).unwrap();
        let dir = s.workspaces[0].dir.clone();
        host_commit(&repo, &root, &[("secret/x", Some("secret x v2\n"))]);
        let d = dir.clone();
        BEFORE_APPLY.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::write(d.join("secret/x"), "agent edit\n").unwrap();
            }))
        });
        let _reset = HookGuard;
        let err = repo
            .ws_refresh(None, None, Some(&sk))
            .unwrap_err()
            .to_string();
        assert!(err.contains("secret/x changed in the workspace"), "{err}");
        assert_eq!(read(&dir, "secret/x"), "agent edit\n");
        cleanup(repo, &root);
    }

    #[test]
    fn a_crash_after_a_protected_rewrite_needs_the_key_to_finish() {
        let (repo, root) = init("crash-protected");
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x"), "secret x\n").unwrap();
        repo.commit("t", "protected").unwrap();
        let s = repo.ws_fork(None, 2, "t", Some(&sk)).unwrap();
        let (d1, d2) = (s.workspaces[0].dir.clone(), s.workspaces[1].dir.clone());
        host_commit(&repo, &root, &[("secret/x", Some("secret x v2\n"))]);
        {
            // Workspace 1 is rewritten, workspace 2 is not reached.
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, Some(&sk)).unwrap_err();
        }
        assert_eq!(read(&d1, "secret/x"), "secret x v2\n");
        assert_eq!(read(&d2, "secret/x"), "secret x\n");
        // The rewritten file no longer matches the old base, so finishing needs
        // the key to merge it; without one it refuses and changes nothing.
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(err.contains("nothing was changed"), "{err}");
        repo.ws_refresh(None, None, Some(&sk)).unwrap();
        for d in [&d1, &d2] {
            assert_eq!(read(d, "secret/x"), "secret x v2\n");
        }
        assert!(repo
            .ws_session(None)
            .unwrap()
            .unwrap()
            .pending_refresh
            .is_none());
        cleanup(repo, &root);
    }

    #[test]
    fn directories_a_removal_emptied_go_and_others_stay() {
        let root = tmp_root("prune");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("gone/deep")).unwrap();
        std::fs::create_dir_all(root.join("kept")).unwrap();
        std::fs::write(root.join("gone/deep/f"), "f\n").unwrap();
        std::fs::write(root.join("kept/g"), "g\n").unwrap();
        std::fs::write(root.join("kept/h"), "h\n").unwrap();
        repo.commit("t", "base").unwrap();
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        std::fs::create_dir_all(dir.join("empty-of-mine")).unwrap();
        host_commit(&repo, &root, &[("gone/deep/f", None), ("kept/g", None)]);
        repo.ws_refresh(None, None, None).unwrap();
        assert!(!dir.join("gone").exists(), "emptied by the removal");
        assert!(dir.join("kept/h").exists());
        assert!(dir.join("empty-of-mine").exists(), "not ours to remove");
        cleanup(repo, &root);
    }

    #[test]
    fn an_interrupted_refresh_can_be_run_again() {
        let (repo, root, dirs, _old, tip) = crash_fixture("crash-rerun");
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, None).unwrap_err();
        }
        let r = repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(r.to, tip);
        assert_eq!(base_of(&repo, None), tip);
        for d in &dirs {
            assert_eq!(read(d, "b.txt"), "b\n");
            assert_eq!(read(d, "c.txt"), "c\n");
        }
        assert_eq!(read(&dirs[0], "a.txt"), "ONE\ntwo\nthree\nfour\nfive\n");
        assert_eq!(read(&dirs[1], "w2.txt"), "w2\n");
        cleanup(repo, &root);
    }

    #[test]
    fn onto_another_branch_moves_the_base_branch_too() {
        let (repo, root) = init("onto");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        let feat = host_commit(&repo, &root, &[("f.txt", Some("feature\n"))]);
        repo.switch("main").unwrap();

        let r = repo.ws_refresh(None, Some("feature"), None).unwrap();
        assert_eq!((r.branch.as_str(), r.to), ("feature", feat));
        assert_eq!(read(&s.workspaces[0].dir, "f.txt"), "feature\n");
        let session = repo.ws_session(None).unwrap().unwrap();
        assert_eq!(session.base_branch, "feature");
        assert!(matches!(
            repo.ws_refresh(None, Some("nope"), None),
            Err(Error::NoSuchBranch(_))
        ));
        cleanup(repo, &root);
    }

    #[test]
    fn a_scanner_hit_in_a_workspace_refuses_the_refresh() {
        let (repo, root) = init("scan");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        std::fs::write(
            s.workspaces[0].dir.join("leak.txt"),
            "AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();
        host_commit(&repo, &root, &[("b.txt", Some("host\n"))]);
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(
            err.contains("workspace 1") && err.contains("scanner"),
            "{err}"
        );
        assert!(!s.workspaces[0].dir.join("b.txt").exists());
        cleanup(repo, &root);
    }

    #[test]
    fn protected_paths_need_the_key_and_keep_their_cache() {
        let (repo, root) = init("protected");
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x"), "secret x\n").unwrap();
        std::fs::write(root.join("secret/y"), "secret y\n").unwrap();
        repo.commit("t", "protected").unwrap();
        let s = repo.ws_fork(None, 2, "t", Some(&sk)).unwrap();
        let (d1, d2) = (s.workspaces[0].dir.clone(), s.workspaces[1].dir.clone());
        // Workspace 1 is left alone; workspace 2 edits a protected file.
        std::fs::write(d2.join("secret/y"), "secret y edited\n").unwrap();
        let old = base_of(&repo, None);
        host_commit(&repo, &root, &[("secret/x", Some("secret x v2\n"))]);

        // The new tip changed a protected file the workspace holds in plaintext.
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(err.contains("--identity"), "{err}");
        assert_eq!(base_of(&repo, None), old);
        assert_eq!(read(&d1, "secret/x"), "secret x\n", "nothing was written");

        repo.ws_refresh(None, None, Some(&sk)).unwrap();
        for d in [&d1, &d2] {
            assert_eq!(read(d, "secret/x"), "secret x v2\n");
        }
        assert_eq!(read(&d2, "secret/y"), "secret y edited\n");
        let session = repo.ws_session(None).unwrap().unwrap();
        // Refresh recorded what it wrote in the cache and kept the rest, so the
        // untouched workspace is not spuriously changed; the protected edit is.
        assert!(!repo.ws_changed(None, &session.workspaces[0]).unwrap());
        assert!(repo.ws_changed(None, &session.workspaces[1]).unwrap());
        let out = repo.ws_harvest(None, None, "t", Some(&sk)).unwrap();
        assert!(
            matches!(out[0], WsHarvestOutcome::Unchanged { .. }),
            "{out:?}"
        );
        assert!(matches!(out[1], WsHarvestOutcome::Landed { .. }), "{out:?}");
        cleanup(repo, &root);
    }

    #[test]
    fn a_session_with_a_narrow_view_stays_in_it() {
        let root = tmp_root("sparse");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), "a\n").unwrap();
        std::fs::write(root.join("docs/x.md"), "x\n").unwrap();
        repo.commit("t", "base").unwrap();
        repo.set_sparse(&["src/".into()], None).unwrap();
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        std::fs::write(dir.join("src/mine.txt"), "mine\n").unwrap();
        // The host widens its own view meanwhile; the session keeps its fork-time one.
        repo.disable_sparse(None).unwrap();
        host_commit(
            &repo,
            &root,
            &[("src/b.txt", Some("b\n")), ("docs/x.md", Some("x2\n"))],
        );

        repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(read(&dir, "src/b.txt"), "b\n");
        assert!(!dir.join("docs").exists(), "outside the session's view");
        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        let [WsHarvestOutcome::Landed { merged_tip, .. }] = out.as_slice() else {
            panic!("expected a landing, got {out:?}")
        };
        assert_eq!(tree_has(&repo, *merged_tip, "docs/x.md").unwrap(), b"x2\n");
        assert!(tree_has(&repo, *merged_tip, "src/mine.txt").is_some());
        cleanup(repo, &root);
    }
}
