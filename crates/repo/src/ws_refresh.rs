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

/// The writes one workspace needs, decided before anything is touched.
struct Plan {
    removals: Vec<String>,
    writes: Vec<(String, ObjectId, FileMode, u8)>,
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

fn changed_since_read(p: &str) -> Error {
    Error::InvalidArgument(format!(
        "{p} changed in the workspace while it was being read; run `sc ws refresh` again"
    ))
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
) -> Result<Plan> {
    // Bounded by the view on both sides: a partial clone does not hold the rest.
    let old = tree_file_entries_with_perms_sparse(store, old_root, sparse)?;
    let new = tree_file_entries_with_perms_sparse(store, new_root, sparse)?;
    let (mut removals, mut writes, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    for (p, (blob, _, perms)) in old.iter().filter(|(p, _)| !new.contains_key(*p)) {
        let full = safe_join(root, p)?;
        let Some(meta) = lstat(&full)? else { continue };
        if under_symlink(root, p) {
            continue;
        }
        // A protected file's plaintext cannot be compared without its key.
        let ours = if perms & PROTECTED != 0 {
            meta.is_file()
        } else {
            disk_is_blob(&full, blob)
        };
        if !ours {
            return Err(changed_since_read(p));
        }
        removals.push(p.clone());
    }
    let removable: BTreeSet<&str> = removals.iter().map(String::as_str).collect();
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
        match &meta {
            None => {}
            Some(m) if m.is_dir() => {
                if !dir_clearable(&full, p, &|c| removable.contains(c)) {
                    return Err(Error::InvalidArgument(format!(
                        "cannot write {p}: a directory with untracked or ignored content \
                         stands there; move it away, then retry"
                    )));
                }
            }
            Some(m) => {
                let was_ours = match prior {
                    Some((_, _, op)) if op & PROTECTED != 0 => m.is_file(),
                    Some((b, ..)) => disk_is_blob(&full, b),
                    None => false,
                };
                if !was_ours && !(!protected && disk_is_blob(&full, blob)) {
                    return Err(if prior.is_some() {
                        changed_since_read(p)
                    } else {
                        Error::InvalidArgument(format!(
                            "cannot write {p}: a file of yours (untracked or ignored) stands \
                             there; move it away, then retry"
                        ))
                    });
                }
            }
        }
        writes.push((p.clone(), *blob, *mode, *perms));
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
/// interruption never leaves a half-written one.
fn apply_plan(
    store: &mut Store,
    job: &mut Job,
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<()> {
    for p in &job.plan.removals {
        injected_failure()?;
        match std::fs::remove_file(safe_join(&job.dir, p)?) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    for (p, blob, mode, perms) in &job.plan.writes {
        injected_failure()?;
        let full = safe_join(&job.dir, p)?;
        let Object::Blob(bytes) = store.get(blob)? else {
            continue;
        };
        clear_dir_obstruction(&full, p)?;
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if perms & PROTECTED != 0 {
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
    /// ADR-0050). The write order is each checkout, then the manifest with the
    /// new base. A crash in between leaves a manifest that still names the old
    /// base and checkouts whose every file is either its old state or its merged
    /// one; a harvest then lands them (the merge sees the new tip's changes on
    /// both sides) or, where the two sides edited the same lines, falls back to a
    /// branch. Nothing is lost, and `sc ws refresh` can be run again.
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
        let mut session = open_session(self.layout(), name)?;
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
        let from = session.base_snapshot;
        if to == from && branch == session.base_branch {
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

        let mut report = Vec::with_capacity(jobs.len());
        {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            for job in &mut jobs {
                apply_plan(&mut store, job, identity)?;
                report.push(WsRefreshEntry {
                    index: job.index,
                    written: job.plan.writes.len(),
                    removed: job.plan.removals.len(),
                    skipped: job.plan.skipped.clone(),
                });
            }
        }
        // The new base last: until it lands, the old one is still the truth.
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
    fn an_interrupted_refresh_leaves_a_workspace_that_still_harvests() {
        let (repo, root, dirs, old, tip) = crash_fixture("crash-harvest");
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
        assert!(dirs[0].join("b.txt").exists() && !dirs[0].join("c.txt").exists());
        assert!(dirs[1].join("w2.txt").exists() && !dirs[1].join("b.txt").exists());

        let out = repo.ws_harvest(None, None, "t", None).unwrap();
        assert!(
            out.iter()
                .all(|o| matches!(o, WsHarvestOutcome::Landed { .. })),
            "{out:?}"
        );
        let head = repo.head_tip().unwrap().unwrap();
        assert_ne!(head, tip);
        assert_eq!(
            tree_has(&repo, head, "a.txt").unwrap(),
            b"ONE\ntwo\nthree\nfour\nfive\n"
        );
        for p in ["b.txt", "c.txt", "w2.txt"] {
            assert!(tree_has(&repo, head, p).is_some(), "{p} must survive");
        }
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
