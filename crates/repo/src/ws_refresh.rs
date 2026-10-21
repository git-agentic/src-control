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
use crate::ws::{
    ensure_idle, label_prefix, open_session, write_manifest, PendingRefresh, PendingWs, WsEntry,
    WsSession,
};

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

/// Whether the file at `full` is exactly the content recorded as `rec` (blob and
/// perms) at `p`. A plain file is compared by bytes. A protected file's plaintext
/// is proved the way commit proves it: a randomized one by the workspace cache, a
/// convergent one by re-encrypting. Anything that is not a regular file reads as
/// not matching.
fn holds(full: &std::path::Path, p: &str, rec: (ObjectId, u8), cache: &ProtectedCache) -> bool {
    let (blob, perms) = rec;
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

/// The disk state of path `p` against the candidate's record of it (`prior`) and,
/// for a write, the content it is about to get (`target`): fine to replace or
/// remove (`Ok(())`), or changed since it was read. A file that already holds the
/// target is fine too (a retry after an interruption finds its own earlier
/// writes), but only for a path the candidate tracked: an ignored file with the
/// same bytes is still the user's. A tracked plain file that is gone was deleted
/// after the read; a protected one may never have been laid out (no key at fork),
/// which is not a change.
fn check_prior(
    full: &std::path::Path,
    p: &str,
    prior: Option<(ObjectId, u8)>,
    target: Option<(ObjectId, u8)>,
    cache: &ProtectedCache,
) -> Result<()> {
    let meta = lstat(full)?;
    match (meta, prior) {
        (None, Some((_, perms))) if perms & PROTECTED == 0 => Err(changed_since_read(p)),
        (None, _) => Ok(()),
        // A directory where a tracked file was is never ours to remove.
        (Some(m), Some(_)) if m.is_dir() && target.is_none() => Err(changed_since_read(p)),
        (Some(m), _) if m.is_dir() => Ok(()), // a write: judged by the directory rules
        (Some(_), Some(prior))
            if holds(full, p, prior, cache) || target.is_some_and(|t| holds(full, p, t, cache)) =>
        {
            Ok(())
        }
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
    resuming: bool,
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
        // Already the result's content, written by an earlier attempt that was
        // interrupted (a path the candidate tracked, and a content change).
        // On a retry that includes a file the first attempt added, which the
        // candidate does not track.
        if (prior.is_some_and(|(b, ..)| b != blob) || (resuming && prior.is_none()))
            && meta.as_ref().is_some_and(|m| m.is_file())
            && holds(&full, p, (*blob, *perms), cache)
        {
            continue;
        }
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
            check_prior(&full, p, prior, Some((*blob, *perms)), cache)?;
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
        check_prior(&full, p, *prior, Some((*blob, *perms)), &job.cache)?;
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

/// A workspace's refresh, before it is planned: the checkout as the refresh read
/// it (`candidate`) and what it becomes (`result`), both snapshots (the pair a
/// pending marker records).
struct Prep {
    index: u32,
    dir: PathBuf,
    candidate: ObjectId,
    result: ObjectId,
    cache: ProtectedCache,
}

/// Remove the `<stem>.<pid>.<n>.tmp` staging files `atomic_write_durable` leaves
/// beside `full` when its writer was killed: one may hold protected plaintext,
/// and a harvest would take it for the agent's own file. Only that exact name
/// with a pid that is provably dead.
fn sweep_stale_temps(full: &std::path::Path) {
    let (Some(parent), Some(stem)) = (full.parent(), full.file_stem().and_then(|s| s.to_str()))
    else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(mid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(stem))
            .and_then(|n| n.strip_prefix('.'))
            .and_then(|n| n.strip_suffix(".tmp"))
        else {
            continue;
        };
        let mut parts = mid.split('.');
        let (Some(pid), Some(n), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let (Ok(pid), Ok(_)) = (pid.parse::<u32>(), n.parse::<u64>()) {
            if crate::lock::pid_is_dead(pid) && e.file_type().is_ok_and(|t| t.is_file()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
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
    /// ADR-0050). The write order is a `pending_refresh` marker in the manifest
    /// (target, branch and, per workspace, the candidate and result snapshots),
    /// each checkout, then the manifest with the new base and no marker. A crash
    /// in between leaves checkouts holding a mix of old and merged files and a
    /// marker that makes harvest and run refuse; running this again resumes from
    /// the recorded snapshots (not from the half-written checkouts), accepting a
    /// file that is either what the candidate read or what the result holds, and
    /// then moves on to the requested tip.
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
        // An unfinished refresh is finished first, onto its own tip and branch.
        let resumed = if session.pending_refresh.is_some() {
            Some(self.resume_refresh(name, identity)?)
        } else {
            None
        };
        let r = self.refresh_onto(name, &branch, to, identity)?;
        Ok(match resumed {
            Some(done) if r.workspaces.is_empty() => done,
            _ => r,
        })
    }

    /// Live workspaces of `session`, ascending, none running a command.
    fn idle_live(&self, name: Option<&str>, session: &WsSession) -> Result<Vec<WsEntry>> {
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
        Ok(live)
    }

    fn ws_cache(&self, name: Option<&str>, e: &WsEntry) -> Result<ProtectedCache> {
        Ok(ProtectedCache::open(
            crate::cache::local_key(self.layout())?,
            e.dir.clone(),
            Some(self.layout().ws_cache_path(name, e.index as usize)),
        ))
    }

    /// Finish an interrupted refresh from the pairs its marker recorded.
    fn resume_refresh(
        &self,
        name: Option<&str>,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsRefresh> {
        let session = open_session(self.layout(), name)?;
        let pending = session
            .pending_refresh
            .clone()
            .expect("the caller checked for a marker");
        let mut preps = Vec::new();
        for e in self.idle_live(name, &session)? {
            let rec = pending
                .workspaces
                .iter()
                .find(|w| w.index == e.index)
                .ok_or_else(|| {
                    Error::InvalidArgument(format!(
                        "the unfinished refresh has no record of workspace {}; abandon it \
                         (`sc ws abandon{} {}`) and run `sc ws refresh` again",
                        e.index,
                        name.map(|n| format!(" --session {n}")).unwrap_or_default(),
                        e.index
                    ))
                })?;
            preps.push(Prep {
                index: e.index,
                cache: self.ws_cache(name, &e)?,
                dir: e.dir,
                candidate: rec.candidate,
                result: rec.result,
            });
        }
        self.drive_refresh(
            session,
            &pending.branch,
            pending.target,
            preps,
            Vec::new(),
            identity,
        )
    }

    /// [`Self::ws_refresh`] onto the snapshot `to`, labelled as `branch`.
    fn refresh_onto(
        &self,
        name: Option<&str>,
        branch: &str,
        to: ObjectId,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsRefresh> {
        let session = open_session(self.layout(), name)?;
        let from = session.base_snapshot;
        if to == from && branch == session.base_branch {
            return Ok(WsRefresh {
                branch: branch.to_string(),
                from,
                to,
                workspaces: Vec::new(),
            });
        }
        let live = self.idle_live(name, &session)?;

        // The session's own fork-time view, as harvest uses (ADR-0056, 7).
        let sparse = Sparse::new(session.sparse.clone());
        let tip = self.snapshot(&to)?;
        self.ensure_view(tip.root, &sparse)?;

        let mut refusals: Vec<String> = Vec::new();
        let mut preps: Vec<Prep> = Vec::new();
        for e in &live {
            let mut cache = self.ws_cache(name, e)?;
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
            let (candidate, result) = match candidate {
                HarvestResult::Rejected(report) => {
                    refusals.push(format!(
                        "workspace {}: the secret scanner rejected it ({report}); fix it first",
                        e.index
                    ));
                    continue;
                }
                // Untouched: the base becomes the tip.
                HarvestResult::Unchanged => (from, to),
                HarvestResult::Committed(c) => {
                    let onto_tip = (tip.root, &tip.protection);
                    match crate::replay::replay_commit(self, c, onto_tip, identity, None) {
                        // The result is a snapshot so it can be recorded, rooted
                        // and, on a retry, read back with its wrap lists.
                        Ok(ReplayOutcome::Clean { root, protection }) => (
                            c,
                            self.build_snapshot(
                                root,
                                vec![to],
                                tip.secrets.clone(),
                                protection,
                                &session.author,
                                &msg,
                            )?,
                        ),
                        Ok(ReplayOutcome::Empty) => (c, to),
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
            preps.push(Prep {
                index: e.index,
                dir: e.dir.clone(),
                candidate,
                result,
                cache,
            });
        }
        self.drive_refresh(session, branch, to, preps, refusals, identity)
    }

    /// Plan every workspace, mark the session, apply, and move the base. The
    /// shared tail of a fresh refresh and a resumed one (`session` then already
    /// holds the marker). `refusals` are what the caller collected so far.
    #[allow(clippy::too_many_arguments)]
    fn drive_refresh(
        &self,
        mut session: WsSession,
        branch: &str,
        to: ObjectId,
        preps: Vec<Prep>,
        mut refusals: Vec<String>,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsRefresh> {
        let sparse = Sparse::new(session.sparse.clone());
        let from = session.base_snapshot;
        let prior_pending = session.pending_refresh.clone();
        let recorded: Vec<PendingWs> = preps
            .iter()
            .map(|p| PendingWs {
                index: p.index,
                candidate: p.candidate,
                result: p.result,
            })
            .collect();
        let mut jobs: Vec<Job> = Vec::new();
        for prep in preps {
            let old_root = self.snapshot(&prep.candidate)?.root;
            let result = self.snapshot(&prep.result)?;
            // The result's view, filled (lazy clone) or reported as a gap.
            self.ensure_view(result.root, &sparse)?;
            let plan = {
                let store_arc = self.vfs().store();
                let mut store = store_arc.lock().unwrap();
                preflight_view(self.layout(), &mut store, result.root, &sparse)?;
                plan_checkout(
                    &prep.dir,
                    &mut store,
                    old_root,
                    result.root,
                    &result.protection,
                    identity,
                    &sparse,
                    &prep.cache,
                    prior_pending.is_some(),
                )
            };
            match plan {
                Ok(plan) => jobs.push(Job {
                    index: prep.index,
                    dir: prep.dir,
                    protection: result.protection,
                    plan,
                    cache: prep.cache,
                }),
                Err(Error::InvalidArgument(msg)) => {
                    refusals.push(format!("workspace {}: {msg}", prep.index));
                }
                Err(err) => return Err(err),
            }
        }
        if !refusals.is_empty() {
            return Err(Error::InvalidArgument(format!(
                "sc ws refresh refused; nothing was changed:\n  {}",
                refusals.join("\n  ")
            )));
        }

        // From here the checkouts may hold a mix of old and refreshed files, and
        // harvest would read the refreshed ones as the agent's own: mark the
        // session, durably, before the first write, with what the retry needs
        // (cleared with the new base).
        if prior_pending.is_none() {
            session.pending_refresh = Some(PendingRefresh {
                target: to,
                branch: branch.to_string(),
                workspaces: recorded,
            });
            write_manifest(self.layout(), &session)?;
        } else {
            // A killed writer may have left staging files with protected plaintext.
            for job in &jobs {
                for (p, ..) in &job.plan.writes {
                    sweep_stale_temps(&safe_join(&job.dir, p)?);
                }
            }
        }
        before_apply_hook();
        let mut report = Vec::with_capacity(jobs.len());
        let mut done = 0;
        let applied = {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            jobs.iter_mut().try_for_each(|job| {
                let r = apply_plan(&mut store, job, identity, &mut done);
                // What was written is recorded either way, so a retry can tell
                // an already-written protected file from an edit.
                job.cache.save_best_effort();
                r?;
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
        session.base_branch = branch.to_string();
        write_manifest(self.layout(), &session)?;
        Ok(WsRefresh {
            branch: branch.to_string(),
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
    fn a_directory_that_replaced_a_tracked_file_after_the_plan_is_not_removed() {
        let root = tmp_root("dir-for-file");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("gone.txt"), "g\n").unwrap();
        std::fs::write(root.join("keep.txt"), "k\n").unwrap();
        repo.commit("t", "base").unwrap();
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = s.workspaces[0].dir.clone();
        host_commit(&repo, &root, &[("gone.txt", None)]);
        let d = dir.clone();
        BEFORE_APPLY.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(d.join("gone.txt")).unwrap();
                std::fs::create_dir(d.join("gone.txt")).unwrap();
                std::fs::write(d.join("gone.txt/mine"), "m\n").unwrap();
            }))
        });
        let _reset = HookGuard;
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(err.contains("gone.txt changed"), "{err}");
        assert_eq!(read(&dir, "gone.txt/mine"), "m\n");
        cleanup(repo, &root);
    }

    /// Agent edits line 4, the host edits the adjacent line 5 of one file: the
    /// merged file is written before the failure.
    fn adjacent_fixture(tag: &str) -> (Repo, PathBuf, Vec<PathBuf>, ObjectId) {
        let (repo, root) = init(tag);
        let s = repo.ws_fork(None, 2, "t", None).unwrap();
        let dirs: Vec<PathBuf> = s.workspaces.iter().map(|e| e.dir.clone()).collect();
        std::fs::write(dirs[0].join("a.txt"), "one\ntwo\nthree\nFOUR\nfive\n").unwrap();
        let tip = host_commit(
            &repo,
            &root,
            &[
                ("a.txt", Some("one\ntwo\nthree\nfour\nFIVE\n")),
                ("b.txt", Some("b\n")),
            ],
        );
        (repo, root, dirs, tip)
    }

    #[test]
    fn a_retry_after_a_merged_file_was_written_succeeds_and_harvest_lands_the_merge() {
        let (repo, root, dirs, tip) = adjacent_fixture("retry-merged");
        {
            // a.txt (the merged file) is written, then the next operation dies.
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, None).unwrap_err();
        }
        assert_eq!(read(&dirs[0], "a.txt"), "one\ntwo\nthree\nFOUR\nFIVE\n");
        let r = repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(r.to, tip);
        assert_eq!(base_of(&repo, None), tip);
        for d in &dirs {
            assert_eq!(read(d, "b.txt"), "b\n");
        }
        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        assert!(matches!(out[0], WsHarvestOutcome::Landed { .. }), "{out:?}");
        let head = repo.head_tip().unwrap().unwrap();
        assert_eq!(
            tree_has(&repo, head, "a.txt").unwrap(),
            b"one\ntwo\nthree\nFOUR\nFIVE\n"
        );
        cleanup(repo, &root);
    }

    #[test]
    fn a_host_revert_after_a_crash_with_a_merged_file_written_is_honoured() {
        let (repo, root, dirs, _tip) = adjacent_fixture("revert-merged");
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, None).unwrap_err();
        }
        assert_eq!(read(&dirs[0], "a.txt"), "one\ntwo\nthree\nFOUR\nFIVE\n");
        // The host takes the whole change back.
        host_commit(&repo, &root, &[("a.txt", Some(LINES)), ("b.txt", None)]);
        repo.ws_refresh(None, None, None).unwrap();
        assert_eq!(read(&dirs[0], "a.txt"), "one\ntwo\nthree\nFOUR\nfive\n");
        assert!(!dirs[0].join("b.txt").exists());
        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        assert!(matches!(out[0], WsHarvestOutcome::Landed { .. }), "{out:?}");
        let head = repo.head_tip().unwrap().unwrap();
        assert_eq!(
            tree_has(&repo, head, "a.txt").unwrap(),
            b"one\ntwo\nthree\nFOUR\nfive\n",
            "the host's reverted line is not re-applied"
        );
        assert!(tree_has(&repo, head, "b.txt").is_none());
        cleanup(repo, &root);
    }

    #[test]
    fn a_retry_still_refuses_an_edit_made_after_the_crash() {
        let (repo, root, dirs, _tip) = adjacent_fixture("edit-after-crash");
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, None).unwrap_err();
        }
        // The agent edits the file the first attempt wrote.
        std::fs::write(dirs[0].join("a.txt"), "mine\n").unwrap();
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(err.contains("a.txt changed in the workspace"), "{err}");
        assert_eq!(read(&dirs[0], "a.txt"), "mine\n");
        assert!(repo
            .ws_session(None)
            .unwrap()
            .unwrap()
            .pending_refresh
            .is_some());
        cleanup(repo, &root);
    }

    #[test]
    fn the_marker_keeps_the_target_branch_for_the_retry() {
        let (repo, root) = init("marker-branch");
        let s = repo.ws_fork(None, 1, "t", None).unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        let feat = host_commit(
            &repo,
            &root,
            &[("f.txt", Some("f\n")), ("g.txt", Some("g\n"))],
        );
        repo.switch("main").unwrap();
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, Some("feature"), None).unwrap_err();
        }
        let p = repo
            .ws_session(None)
            .unwrap()
            .unwrap()
            .pending_refresh
            .unwrap();
        assert_eq!((p.branch.as_str(), p.target), ("feature", feat));
        // A plain retry (the checked-out branch is main) finishes onto feature
        // first, labelled feature, then moves on to main's tip, which is the old base.
        let r = repo.ws_refresh(None, None, None).unwrap();
        assert_eq!((r.branch.as_str(), r.to), ("main", s.base_snapshot));
        assert!(!s.workspaces[0].dir.join("f.txt").exists());
        // And retrying with the same target finishes it as that branch.
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, Some("feature"), None).unwrap_err();
        }
        let r = repo.ws_refresh(None, Some("feature"), None).unwrap();
        assert_eq!((r.branch.as_str(), r.to), ("feature", feat));
        assert_eq!(
            repo.ws_session(None).unwrap().unwrap().base_branch,
            "feature"
        );
        cleanup(repo, &root);
    }

    #[test]
    fn stale_staging_files_of_a_dead_writer_are_swept_on_retry() {
        let (repo, root, dirs, _tip) = adjacent_fixture("stale-tmp");
        {
            let _g = FailGuard::after(1);
            repo.ws_refresh(None, None, None).unwrap_err();
        }
        // b.txt was about to be written: a killed writer left its staging file.
        let stale = dirs[0].join("b.4000000.7.tmp");
        let alive = dirs[0].join(format!("b.{}.7.tmp", std::process::id()));
        let user = dirs[0].join("b.keep.tmp");
        for f in [&stale, &alive, &user] {
            std::fs::write(f, "plaintext\n").unwrap();
        }
        // The first attempt had written a.txt then died; the staging files are
        // beside b.txt, which the retry writes.
        let err = repo.ws_refresh(None, None, None);
        // Untracked files in the workspace would be read as the agent's own by a
        // fresh candidate, but a retry plans from the record and only sweeps.
        err.unwrap();
        assert!(!stale.exists(), "a dead writer's staging file is removed");
        assert!(alive.exists() && user.exists(), "anything else stays");
        cleanup(repo, &root);
    }

    #[test]
    fn a_convergent_protected_file_edited_after_the_plan_is_not_overwritten() {
        let (repo, root) = init("late-convergent");
        let (sk, pk) = scl_crypto::generate_keypair();
        // A pre-P33 snapshot: the protected blob is sealed convergently.
        let seed = |pt: &[u8], parent: ObjectId| {
            let tip = repo.snapshot(&parent).unwrap();
            let mut protection = tip.protection.clone();
            if protection.prefixes.is_empty() {
                protection.prefixes.push(scl_core::ProtectPrefix {
                    prefix: "secret/".into(),
                    recipients: vec![scl_core::RecipientEntry {
                        key: pk.to_bytes(),
                        epoch: 1,
                        state: scl_core::RecipientState::Granted,
                    }],
                });
            }
            let (cipher, dek) = scl_crypto::encrypt_path(pt);
            protection.wrapped.insert(
                Object::blob(cipher.clone()).id(),
                vec![scl_crypto::wrap_dek_for(&dek, &pk)],
            );
            let root = repo
                .vfs()
                .write_tree_with_perms(&[
                    (
                        "a.txt".to_string(),
                        LINES.as_bytes().to_vec(),
                        FileMode::FILE,
                        0,
                    ),
                    ("secret/x".to_string(), cipher, FileMode::FILE, PROTECTED),
                ])
                .unwrap();
            repo.commit_snapshot(
                root,
                vec![parent],
                Default::default(),
                protection,
                "t",
                "seed",
            )
            .unwrap()
        };
        let base = repo.head_tip().unwrap().unwrap();
        seed(b"secret x\n", base);
        repo.switch("main").unwrap();
        let s = repo.ws_fork(None, 1, "t", Some(&sk)).unwrap();
        let dir = s.workspaces[0].dir.clone();
        assert_eq!(read(&dir, "secret/x"), "secret x\n");
        let tip = repo.head_tip().unwrap().unwrap();
        seed(b"secret x v2\n", tip);
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
    fn a_crash_after_a_protected_rewrite_is_recognised_and_finishes_with_the_key() {
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
        // Workspace 1's file is recognised as already written, but workspace 2
        // still needs the key to be decrypted: without one the retry refuses
        // and changes nothing.
        let err = repo.ws_refresh(None, None, None).unwrap_err().to_string();
        assert!(
            err.contains("nothing was changed") && err.contains("workspace 2"),
            "{err}"
        );
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
