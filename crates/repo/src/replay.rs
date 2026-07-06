//! Replay core (P14): cherry-pick is a three-way merge whose base is the
//! replayed commit's first parent (empty base for a root commit). Consumed by
//! the cherry-pick/rebase CLI surface (Tasks 8-9) to apply one commit onto an
//! arbitrary target tree without requiring a full branch merge.

use std::collections::BTreeMap;

use scl_core::{FileMode, ObjectId};

use crate::error::{Error, Result};
use crate::merge;
use crate::refs;
use crate::repo::Repo;
use crate::worktree;

/// Does `commit_id`'s secret registry differ from its first parent's (empty
/// registry if it's a root commit)? Replay (`cherry_pick`/`rebase`) always
/// carries the *target*-side registry forward wholesale rather than diffing
/// and reapplying per-commit changes (see module docs) — so a commit that
/// added, rotated, or removed a secret has that change silently dropped by
/// the replay. Callers use this to decide whether to warn.
fn secrets_changed_from_parent(repo: &Repo, commit_id: ObjectId) -> Result<bool> {
    let snap = repo.snapshot(&commit_id)?;
    let parent_secrets = match snap.parents.first() {
        Some(p) => repo.snapshot(p)?.secrets,
        None => BTreeMap::new(),
    };
    Ok(snap.secrets != parent_secrets)
}

/// Result of replaying one commit onto a target tree.
#[derive(Debug)]
pub(crate) enum ReplayOutcome {
    /// Merged tree written to the CAS.
    Clean { root: ObjectId },
    /// Replayed tree equals the target — change already present.
    Empty,
    /// Conflicting paths, with the merged working set (markers included)
    /// and sidecars, ready to materialize.
    Conflicts {
        files: Vec<(String, FileMode, Vec<u8>)>,
        sidecars: Vec<(String, Vec<u8>)>,
        paths: Vec<String>,
    },
}

/// Replay (cherry-pick) `commit_id` onto `onto_root`.
///
/// This is a three-way merge: base = `commit_id`'s first parent's root tree
/// (`None`, i.e. the empty tree, if `commit_id` is a root commit), ours =
/// `onto_root`, theirs = `commit_id`'s own root tree. Merge commits (2+
/// parents) are refused — mainline selection is not supported — as is any
/// replay that would touch `PROTECTED` content, since flattening trees for a
/// three-way merge drops the `perms` byte and would corrupt encrypted files.
pub(crate) fn replay_commit(repo: &Repo, commit_id: ObjectId, onto_root: ObjectId) -> Result<ReplayOutcome> {
    let snap = repo.snapshot(&commit_id)?;
    if snap.parents.len() >= 2 {
        return Err(Error::CannotReplayMerge(commit_id));
    }
    let base_root = match snap.parents.first() {
        Some(p) => Some(repo.snapshot(p)?.root),
        None => None,
    };
    let theirs_root = snap.root;

    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();

    // Fail closed on protected content (same rationale as `Repo::merge`'s
    // guard at repo.rs ~585): `three_way_files` flattens trees without the
    // `perms` byte, which would push raw ciphertext into the working tree as
    // an ordinary unprotected blob. Pure read + early return: nothing is
    // written before this guard fires.
    for root in [base_root, Some(onto_root), Some(theirs_root)].into_iter().flatten() {
        let entries = worktree::tree_file_entries_with_perms(&mut store, root)?;
        if entries.values().any(|(_, _, perms)| perms & scl_core::PROTECTED != 0) {
            return Err(Error::ReplayProtected(commit_id.to_string()));
        }
    }

    // The guard above ensures no side has PROTECTED entries, so the merge
    // never consults a protection policy (empty ones suffice), never needs an
    // identity, and can't produce `needs_encrypt` outputs.
    let no_prot = scl_core::Protection::default();
    let fm = merge::three_way_files(
        &mut store,
        base_root.map(|r| (r, &no_prot)),
        (onto_root, &no_prot),
        (theirs_root, &no_prot),
        None,
    )?;
    drop(store);

    let files: Vec<(String, FileMode, Vec<u8>)> = fm
        .files
        .into_iter()
        .map(|f| {
            debug_assert!(!f.needs_encrypt, "protected guard fired above");
            (f.path, f.mode, f.bytes)
        })
        .collect();

    if !fm.conflicts.is_empty() {
        return Ok(ReplayOutcome::Conflicts {
            files,
            sidecars: fm.sidecars,
            paths: fm.conflicts,
        });
    }

    let write_set: Vec<(String, Vec<u8>, FileMode)> =
        files.iter().map(|(p, m, b)| (p.clone(), b.clone(), *m)).collect();
    let root = repo.vfs().write_tree(&write_set)?;

    if root == onto_root {
        Ok(ReplayOutcome::Empty)
    } else {
        Ok(ReplayOutcome::Clean { root })
    }
}

/// Outcome of [`Repo::cherry_pick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickResult {
    /// The replayed commit was applied as a new single-parent snapshot.
    Picked(ObjectId),
    /// Change already present on the current branch — nothing committed.
    AlreadyApplied,
}

impl Repo {
    /// Replay `refname`'s tip commit onto the current branch (cherry-pick).
    ///
    /// Preflight mirrors `Repo::merge`'s, in the same order, so the two
    /// commands fail identically for identical reasons: merge-in-progress and
    /// pick-in-progress guards, an unborn current branch (`Error::Unborn`),
    /// resolving `refname` (`Error::NoSuchBranch`), then the dirty-working-tree
    /// check. A clean replay advances the current branch with a single-parent
    /// snapshot (`parents: [ours_tip]`) whose message is the picked commit's
    /// first message line plus a `(cherry-picked from <short>)` suffix. The
    /// clean path follows `Repo::merge`'s crash discipline: snapshot to the
    /// CAS, materialize the working tree, *then* move the branch ref (the ref
    /// update is the atomic commit point — a crash before it leaves tip and
    /// tree consistently pre-pick), with the oplog record written last, after
    /// the ref write it describes. A conflicting replay writes conflict markers
    /// + sidecars over the working tree and records pick state
    /// (`PICK_HEAD`/`PICK_CONFLICTS`) — no ref moves, no oplog entry, so the
    /// current branch tip is unchanged until the conflicts are resolved and
    /// committed. An empty replay (the change is already present) is a no-op.
    pub fn cherry_pick(&self, refname: &str, author: &str) -> Result<PickResult> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        let ours_tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let picked_tip = refs::resolve_tip(&self.layout, refname)?
            .ok_or_else(|| Error::NoSuchBranch(refname.to_string()))?;
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before cherry-picking".into(),
            ));
        }

        let head = refs::current_branch(&self.layout)?;
        let before = refs::read_branch_tip(&self.layout, &head)?;
        let ours_snap = self.snapshot(&ours_tip)?;
        let ours_root = ours_snap.root;
        let picked_snap = self.snapshot(&picked_tip)?;
        let secrets_dropped = secrets_changed_from_parent(self, picked_tip)?;

        match replay_commit(self, picked_tip, ours_root)? {
            ReplayOutcome::Empty => {
                // AlreadyApplied means the tree content already matches, but
                // `replay_commit` only compares roots, not secret registries
                // — for a secrets-only commit this is actively misleading:
                // the secret change is neither present nor going to be.
                if secrets_dropped {
                    eprintln!(
                        "warning: secret-registry changes on the cherry-picked commit were not replayed; re-add them or `sc undo`"
                    );
                }
                Ok(PickResult::AlreadyApplied)
            }
            ReplayOutcome::Clean { root } => {
                let msg_first_line = picked_snap.message.lines().next().unwrap_or("");
                let message = format!("{msg_first_line} (cherry-picked from {})", picked_tip.short());
                // Ordering matters for crash safety (same discipline as
                // `Repo::merge`'s ff and three-way paths): build the snapshot
                // (CAS-only, no visible state), materialize the working tree,
                // and only then move the branch ref — the ref update is the
                // atomic commit point, so a crash before it leaves both tip
                // and tree at the pre-pick state. The oplog record goes last,
                // after the ref write it describes.
                let id = self.build_snapshot(
                    root,
                    vec![ours_tip],
                    ours_snap.secrets.clone(),
                    ours_snap.protection.clone(),
                    author,
                    &message,
                )?;
                {
                    let store_arc = self.vfs().store();
                    let mut store = store_arc.lock().unwrap();
                    worktree::materialize(
                        &self.layout,
                        &mut store,
                        root,
                        Some(ours_root),
                        &ours_snap.protection,
                        None,
                    )?;
                }
                refs::write_branch_tip(&self.layout, &head, &id)?;
                crate::oplog::record(
                    &self.layout,
                    &format!("cherry-pick {refname}"),
                    &head,
                    &head,
                    &[(head.clone(), before, Some(id))],
                )?;
                if secrets_dropped {
                    eprintln!(
                        "warning: secret-registry changes on the cherry-picked commit were not replayed; re-add them or `sc undo`"
                    );
                }
                Ok(PickResult::Picked(id))
            }
            ReplayOutcome::Conflicts { files, sidecars, paths } => {
                // Same conflict-materialize pattern as `Repo::merge` (repo.rs
                // ~595-625): build the marker tree, materialize it over ours,
                // then write sidecars. `replay_commit`'s protected guard has
                // already refused any replay touching PROTECTED content, so
                // `Protection::default()` here is sound for the same reason
                // it is in `merge`'s conflict path.
                let write_set: Vec<(String, Vec<u8>, FileMode)> =
                    files.iter().map(|(p, m, b)| (p.clone(), b.clone(), *m)).collect();
                let marker_root = self.vfs().write_tree(&write_set)?;
                {
                    let store_arc = self.vfs().store();
                    let mut store = store_arc.lock().unwrap();
                    worktree::materialize(
                        &self.layout,
                        &mut store,
                        marker_root,
                        Some(ours_root),
                        &scl_core::Protection::default(),
                        None,
                    )?;
                }
                for (rel, bytes) in &sidecars {
                    let full = self.layout.root.join(rel);
                    if let Some(parent) = full.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(full, bytes)?;
                }
                crate::pick_state::write(&self.layout, &picked_tip, &paths)?;
                Err(Error::PickConflicts(paths.len()))
            }
        }
    }

    /// Replay the current branch's commits onto `target`'s tip (rebase).
    ///
    /// Preflight mirrors `cherry_pick`'s exactly (merge/pick-in-progress
    /// guards, unborn HEAD, ref resolution, dirty-working-tree check). Then:
    /// fast paths for already-up-to-date and pure-fast-forward cases (no
    /// oplog record for the former; ref move + materialize + oplog for the
    /// latter), else a real replay over the first-parent range from the
    /// current tip back to the merge-base (exclusive), applied oldest-first
    /// onto target's tip. Any merge commit anywhere in that range refuses the
    /// whole rebase up front (`Error::CannotReplayMerge`) before a single
    /// commit is replayed. The first conflict aborts the entire rebase with
    /// refs and the working tree untouched — nothing outside the CAS is
    /// written until every replayed commit in the range is clean (unlike
    /// `cherry_pick`, which leaves conflict markers for a single commit).
    /// Same crash discipline as `cherry_pick`'s clean path: snapshots land in
    /// the CAS, then the working tree is materialized, then the branch ref is
    /// moved (the atomic commit point), with the oplog record written last.
    pub fn rebase(&self, target: &str, author: &str) -> Result<RebaseResult> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        let ours_tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let target_tip = refs::resolve_tip(&self.layout, target)?
            .ok_or_else(|| Error::NoSuchBranch(target.to_string()))?;
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before rebasing".into(),
            ));
        }

        let head = refs::current_branch(&self.layout)?;
        let before = refs::read_branch_tip(&self.layout, &head)?;
        let ours_snap = self.snapshot(&ours_tip)?;
        let ours_root = ours_snap.root;

        // Fast paths.
        {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            if merge::is_ancestor(&mut store, target_tip, ours_tip)? {
                return Ok(RebaseResult::AlreadyUpToDate);
            }
            if merge::is_ancestor(&mut store, ours_tip, target_tip)? {
                let target_snap = store.get_snapshot(&target_tip)?;
                let target_root = target_snap.root;
                let target_protection = target_snap.protection;
                worktree::materialize(
                    &self.layout,
                    &mut store,
                    target_root,
                    Some(ours_root),
                    &target_protection,
                    None,
                )?;
                drop(store);
                refs::write_branch_tip(&self.layout, &head, &target_tip)?;
                crate::oplog::record(
                    &self.layout,
                    &format!("rebase onto {target} (ff)"),
                    &head,
                    &head,
                    &[(head.clone(), before, Some(target_tip))],
                )?;
                return Ok(RebaseResult::FastForwarded(target_tip));
            }
        }

        // Real replay: collect the first-parent range from ours_tip back to
        // the merge-base (exclusive), oldest-first, then pre-scan for merge
        // commits so a rebase either replays cleanly in full or refuses
        // before touching anything.
        let base = {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            merge::merge_base(&mut store, ours_tip, target_tip)?.ok_or(Error::NoCommonAncestor)?
        };
        let mut range = Vec::new();
        {
            let mut cur = ours_tip;
            while cur != base {
                let snap = self.snapshot(&cur)?;
                if snap.parents.len() >= 2 {
                    return Err(Error::CannotReplayMerge(cur));
                }
                range.push(cur);
                cur = snap.parents.first().copied().ok_or(Error::NoCommonAncestor)?;
            }
        }
        range.reverse();

        let target_snap = self.snapshot(&target_tip)?;
        let mut acc_tip = target_tip;
        let mut acc_root = target_snap.root;
        let mut replayed = 0usize;
        let mut skipped = 0usize;
        // Replay carries `target_snap.secrets` forward wholesale for every
        // replayed commit (see the loop below) rather than diffing and
        // reapplying each commit's own registry changes. Detect whether any
        // commit in the range actually changed its registry from its
        // (original-history) parent, so we can warn once after the rebase —
        // not per commit — including the all-skipped case.
        let mut secrets_dropped_anywhere = false;

        for commit in range {
            let commit_snap = self.snapshot(&commit)?;
            if secrets_changed_from_parent(self, commit)? {
                secrets_dropped_anywhere = true;
            }
            match replay_commit(self, commit, acc_root)? {
                ReplayOutcome::Empty => {
                    skipped += 1;
                }
                ReplayOutcome::Clean { root } => {
                    let id = self.build_snapshot(
                        root,
                        vec![acc_tip],
                        target_snap.secrets.clone(),
                        target_snap.protection.clone(),
                        author,
                        &commit_snap.message,
                    )?;
                    acc_tip = id;
                    acc_root = root;
                    replayed += 1;
                }
                ReplayOutcome::Conflicts { paths, .. } => {
                    // Nothing outside the CAS has been written: no working-tree
                    // markers, no ref moves — the whole rebase aborts cleanly.
                    return Err(Error::RebaseConflicts { commit, paths });
                }
            }
        }

        {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(
                &self.layout,
                &mut store,
                acc_root,
                Some(ours_root),
                &target_snap.protection,
                None,
            )?;
        }
        refs::write_branch_tip(&self.layout, &head, &acc_tip)?;
        crate::oplog::record(
            &self.layout,
            &format!("rebase onto {target} ({replayed} replayed, {skipped} skipped)"),
            &head,
            &head,
            &[(head.clone(), before, Some(acc_tip))],
        )?;
        if secrets_dropped_anywhere {
            eprintln!(
                "warning: secret-registry changes on the rebased range were not replayed; re-add them or `sc undo`"
            );
        }
        Ok(RebaseResult::Rebased { new_tip: acc_tip, replayed, skipped })
    }
}

/// Outcome of [`Repo::rebase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseResult {
    /// Target already reachable from the current tip — nothing to do.
    AlreadyUpToDate,
    /// Current tip was an ancestor of target — ref fast-forwarded.
    FastForwarded(ObjectId),
    /// Commits replayed; branch now points at the last new snapshot.
    Rebased { new_tip: ObjectId, replayed: usize, skipped: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::tree_file_ids;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-replay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn clean_replay_produces_merged_root() {
        let root = tmp_root("clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"base\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        // main separately edits Y.
        std::fs::write(root.join("y.txt"), b"y\n").unwrap();
        let main_tip = repo.commit("me", "main edits y").unwrap();

        // branch b edits X.
        repo.switch("b").unwrap();
        std::fs::write(root.join("x.txt"), b"x\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip));

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let outcome = replay_commit(&repo, b_tip, onto_root).unwrap();
        match outcome {
            ReplayOutcome::Clean { root: merged_root } => {
                let store_arc = repo.vfs().store();
                let mut store = store_arc.lock().unwrap();
                let ids = tree_file_ids(&mut store, merged_root).unwrap();
                assert!(ids.contains_key("x.txt"), "b's edit must be present");
                assert!(ids.contains_key("y.txt"), "main's edit must be present");
                assert!(ids.contains_key("shared.txt"));
            }
            _ => panic!("expected Clean, got a different outcome"),
        }
        let _ = base;
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn conflicting_replay_reports_paths_with_markers() {
        let root = tmp_root("conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        let main_tip = repo.commit("me", "main edits x").unwrap();

        repo.switch("b").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();
        repo.switch("main").unwrap();

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let outcome = replay_commit(&repo, b_tip, onto_root).unwrap();
        match outcome {
            ReplayOutcome::Conflicts { files, paths, .. } => {
                assert_eq!(paths, vec!["x.txt".to_string()]);
                let x = &files.iter().find(|(p, _, _)| p == "x.txt").unwrap().2;
                assert!(String::from_utf8_lossy(x).contains("<<<<<<<"));
            }
            _ => panic!("expected Conflicts"),
        }
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn already_applied_replay_is_empty() {
        let root = tmp_root("empty");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();

        // main independently makes the exact same edit.
        repo.switch("main").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        let main_tip = repo.commit("me", "main makes same edit").unwrap();

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let outcome = replay_commit(&repo, b_tip, onto_root).unwrap();
        assert!(matches!(outcome, ReplayOutcome::Empty));
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn root_commit_replays_against_empty_base() {
        let root_a = tmp_root("root-a");
        let repo_a = Repo::init(&root_a).unwrap();
        std::fs::write(root_a.join("new.txt"), b"new\n").unwrap();
        let a_root_commit = repo_a.commit("me", "lineage a root").unwrap();
        assert!(repo_a.snapshot(&a_root_commit).unwrap().parents.is_empty());

        let root_b = tmp_root("root-b");
        let repo_b = Repo::init(&root_b).unwrap();
        std::fs::write(root_b.join("existing.txt"), b"existing\n").unwrap();
        let b_tip = repo_b.commit("me", "lineage b tip").unwrap();

        // Reconstruct lineage a's root commit inside repo_b's store so
        // `replay_commit` can read it — copy the commit's tree/blob objects.
        let a_snap = repo_a.snapshot(&a_root_commit).unwrap();
        let store_a_arc = repo_a.vfs().store();
        let store_b_arc = repo_b.vfs().store();
        {
            let mut store_a = store_a_arc.lock().unwrap();
            let ids = tree_file_ids(&mut store_a, a_snap.root).unwrap();
            let mut files = Vec::new();
            for (path, id) in ids {
                let bytes = match store_a.get(&id).unwrap() {
                    scl_core::Object::Blob(b) => b.to_vec(),
                    _ => panic!("expected blob"),
                };
                files.push((path, bytes, FileMode::FILE));
            }
            drop(store_a);
            let copied_root = repo_b.vfs().write_tree(&files).unwrap();
            let mut store_b = store_b_arc.lock().unwrap();
            let copied_commit = store_b
                .put(scl_core::Object::Snapshot(scl_core::Snapshot {
                    root: copied_root,
                    parents: vec![],
                    author: "me".into(),
                    timestamp: 0,
                    message: "lineage a root (copied)".into(),
                    secrets: Default::default(),
                    protection: Default::default(),
                }))
                .unwrap();
            drop(store_b);

            let onto_root = repo_b.snapshot(&b_tip).unwrap().root;
            let outcome = replay_commit(&repo_b, copied_commit, onto_root).unwrap();
            match outcome {
                ReplayOutcome::Clean { root: merged_root } => {
                    let mut store_b = store_b_arc.lock().unwrap();
                    let ids = tree_file_ids(&mut store_b, merged_root).unwrap();
                    assert!(ids.contains_key("new.txt"));
                    assert!(ids.contains_key("existing.txt"));
                }
                _ => panic!("expected Clean"),
            }
        }
        drop(repo_a);
        drop(repo_b);
        std::fs::remove_dir_all(&root_a).ok();
        std::fs::remove_dir_all(&root_b).ok();
    }

    #[test]
    fn merge_commit_and_protected_content_are_refused() {
        let root = tmp_root("refused");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        let main_tip = repo.commit("me", "main adds a").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"f\n").unwrap();
        repo.commit("me", "feature adds f").unwrap();
        let merged = repo.merge("main", "me").unwrap();
        assert!(repo.snapshot(&merged).unwrap().parents.len() >= 2);

        let onto_root = repo.snapshot(&main_tip).unwrap().root;
        let err = replay_commit(&repo, merged, onto_root).unwrap_err();
        assert!(matches!(err, Error::CannotReplayMerge(id) if id == merged), "got {err:?}");
        let _ = base;

        // Protected content: any replay involving a protected snapshot is refused.
        let proot = tmp_root("refused-protected");
        let prepo = Repo::init(&proot).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        prepo.test_set_protected_prefix("secret/", &[pk]).unwrap();
        std::fs::create_dir_all(proot.join("secret")).unwrap();
        std::fs::write(proot.join("secret/db.txt"), b"hunter2").unwrap();
        let pbase = prepo.commit("me", "base").unwrap();
        std::fs::write(proot.join("other.txt"), b"o\n").unwrap();
        let ptip = prepo.commit("me", "adds other").unwrap();

        let onto_root = prepo.snapshot(&pbase).unwrap().root;
        let err = replay_commit(&prepo, ptip, onto_root).unwrap_err();
        assert!(matches!(err, Error::ReplayProtected(_)), "got {err:?}");

        drop(repo);
        drop(prepo);
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&proot).ok();
    }

    #[test]
    fn cherry_pick_clean_advances_branch_and_materializes() {
        let root = tmp_root("cp-clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();

        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"x\n").unwrap();
        let picked = repo.commit("me", "add x").unwrap();
        repo.switch("main").unwrap();
        let old_main_tip = repo.head_tip().unwrap().unwrap();

        let outcome = repo.cherry_pick("work-1", "me").unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked, got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(id));

        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![old_main_tip]);
        assert!(
            snap.message.ends_with(&format!("(cherry-picked from {})", picked.short())),
            "got message: {}",
            snap.message
        );
        assert_eq!(std::fs::read_to_string(root.join("x.txt")).unwrap(), "x\n");

        let ops = repo.oplog().unwrap();
        assert_eq!(ops.last().unwrap().desc, "cherry-pick work-1");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_conflicting_writes_markers_and_state_moves_no_refs() {
        let root = tmp_root("cp-conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        let main_tip = repo.commit("me", "main edits x").unwrap();

        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        let picked = repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip));

        let err = repo.cherry_pick("work-1", "me").unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip), "main tip must not move");
        assert_eq!(repo.pick_head().unwrap(), Some(picked));
        let on_disk = std::fs::read_to_string(root.join("x.txt")).unwrap();
        assert!(on_disk.contains("<<<<<<<"), "got: {on_disk}");

        // Resolve + commit: single-parent commit, pick state cleared.
        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();
        let resolved = repo.commit("me", "resolve conflict").unwrap();
        let resolved_snap = repo.snapshot(&resolved).unwrap();
        assert_eq!(resolved_snap.parents, vec![main_tip]);
        assert!(!repo.pick_in_progress());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_already_applied_is_a_noop() {
        let root = tmp_root("cp-empty");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();

        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();

        let merged = repo.merge("work-1", "me").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(merged));
        let ops_before = repo.oplog().unwrap().len();

        let outcome = repo.cherry_pick("work-1", "me").unwrap();
        assert!(matches!(outcome, PickResult::AlreadyApplied), "got {outcome:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(merged), "tip must not move");
        assert_eq!(repo.oplog().unwrap().len(), ops_before, "no new oplog record");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_preflight_guards() {
        let root = tmp_root("cp-guards");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();
        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();

        // Dirty working tree.
        std::fs::write(root.join("x.txt"), b"dirty\n").unwrap();
        let err = repo.cherry_pick("work-1", "me").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();

        // Merge in progress.
        let ours_tip = repo.head_tip().unwrap().unwrap();
        crate::merge_state::write(&repo.layout, &ours_tip, &[], None).unwrap();
        let err = repo.cherry_pick("work-1", "me").unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        crate::merge_state::clear(&repo.layout).unwrap();

        // Pick in progress.
        crate::pick_state::write(&repo.layout, &ours_tip, &[]).unwrap();
        let err = repo.cherry_pick("work-1", "me").unwrap_err();
        assert!(matches!(err, Error::PickInProgress), "got {err:?}");
        crate::pick_state::clear(&repo.layout).unwrap();

        // Unknown ref.
        let err = repo.cherry_pick("no-such-branch", "me").unwrap_err();
        assert!(matches!(err, Error::NoSuchBranch(_)), "got {err:?}");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// From the Task 6 review: cherry-pick must also refuse during an
    /// in-progress merge, as a standalone mutual-exclusion check distinct
    /// from `cherry_pick_preflight_guards`'s combined guard sweep.
    #[test]
    fn cherry_pick_during_merge_is_refused() {
        let root = tmp_root("cp-merge-mutex");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();
        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();

        let ours_tip = repo.head_tip().unwrap().unwrap();
        crate::merge_state::write(&repo.layout, &ours_tip, &[], None).unwrap();
        let err = repo.cherry_pick("work-1", "me").unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(ours_tip), "tip must not move");

        crate::merge_state::clear(&repo.layout).unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_replays_commits_in_order_onto_target() {
        let root = tmp_root("rebase-order");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main gains a commit after the branch point.
        std::fs::write(root.join("main.txt"), b"main\n").unwrap();
        let main_tip = repo.commit("me", "main adds main.txt").unwrap();

        // feature gains two commits from the old base.
        repo.switch("feature").unwrap();
        std::fs::write(root.join("c1.txt"), b"c1\n").unwrap();
        let c1 = repo.commit("me", "feature c1").unwrap();
        std::fs::write(root.join("c2.txt"), b"c2\n").unwrap();
        let c2 = repo.commit("me", "feature c2").unwrap();
        let _ = c2;

        let outcome = repo.rebase("main", "me").unwrap();
        let (new_tip, replayed, skipped) = match outcome {
            RebaseResult::Rebased { new_tip, replayed, skipped } => (new_tip, replayed, skipped),
            other => panic!("expected Rebased, got {other:?}"),
        };
        assert_eq!(replayed, 2);
        assert_eq!(skipped, 0);
        assert_eq!(repo.head_tip().unwrap(), Some(new_tip));

        // Parent chain: new_tip <- c1' <- main_tip.
        let c2_snap = repo.snapshot(&new_tip).unwrap();
        assert_eq!(c2_snap.message, "feature c2");
        assert_eq!(c2_snap.parents.len(), 1);
        let c1_new_id = c2_snap.parents[0];
        let c1_snap = repo.snapshot(&c1_new_id).unwrap();
        assert_eq!(c1_snap.message, "feature c1");
        assert_eq!(c1_snap.parents, vec![main_tip]);
        assert_ne!(c1_new_id, c1);

        // Working tree matches the final root: all three files present.
        assert!(root.join("base.txt").exists());
        assert!(root.join("main.txt").exists());
        assert!(root.join("c1.txt").exists());
        assert!(root.join("c2.txt").exists());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_fast_paths() {
        let root = tmp_root("rebase-ff");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // Current (main) is already an ancestor of feature (target): FastForwarded.
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"f\n").unwrap();
        let feature_tip = repo.commit("me", "feature adds f").unwrap();
        repo.switch("main").unwrap();

        let outcome = repo.rebase("feature", "me").unwrap();
        assert_eq!(outcome, RebaseResult::FastForwarded(feature_tip));
        assert_eq!(repo.head_tip().unwrap(), Some(feature_tip));
        let ops = repo.oplog().unwrap();
        assert_eq!(ops.last().unwrap().desc, "rebase onto feature (ff)");

        // Target is now an ancestor of current: AlreadyUpToDate.
        let outcome = repo.rebase("feature", "me").unwrap();
        assert_eq!(outcome, RebaseResult::AlreadyUpToDate);
        assert_eq!(repo.head_tip().unwrap(), Some(feature_tip), "tip must not move");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn conflicting_rebase_aborts_with_refs_byte_identical() {
        let root = tmp_root("rebase-conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();
        // Stay on feature: rebase feature onto main.

        // Snapshot the entire .sc/refs dir (path -> bytes) before rebasing.
        let refs_dir = root.join(".sc/refs");
        let snapshot_refs = |dir: &std::path::Path| -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
            let mut out = std::collections::BTreeMap::new();
            for entry in walkdir(dir) {
                let bytes = std::fs::read(&entry).unwrap();
                out.insert(entry, bytes);
            }
            out
        };
        fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            let mut out = Vec::new();
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries {
                    let e = e.unwrap();
                    let p = e.path();
                    if p.is_dir() {
                        out.extend(walkdir(&p));
                    } else {
                        out.push(p);
                    }
                }
            }
            out
        }

        let before_refs = snapshot_refs(&refs_dir);
        let before_x = std::fs::read(root.join("x.txt")).unwrap();
        let ops_before = repo.oplog().unwrap().len();

        let err = repo.rebase("main", "me").unwrap_err();
        match err {
            Error::RebaseConflicts { paths, .. } => assert_eq!(paths, vec!["x.txt".to_string()]),
            other => panic!("expected RebaseConflicts, got {other:?}"),
        }

        let after_refs = snapshot_refs(&refs_dir);
        assert_eq!(before_refs, after_refs, "refs dir must be byte-identical after an aborted rebase");
        let after_x = std::fs::read(root.join("x.txt")).unwrap();
        assert_eq!(before_x, after_x, "working tree file must be unchanged");
        assert_eq!(repo.oplog().unwrap().len(), ops_before, "no new oplog record");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_skips_already_applied_commits() {
        let root = tmp_root("rebase-skip");
        // main independently makes the exact same edit as feature's commit A
        // (e.g. via a prior cherry-pick of an equivalent change), so replaying
        // A onto main during the rebase is `Empty` -> skipped.
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        repo.commit("me", "feature adds a").unwrap();
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "feature adds b").unwrap();

        repo.switch("main").unwrap();
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        repo.commit("me", "main makes same edit as feature's A").unwrap();

        // Rebase feature onto main.
        repo.switch("feature").unwrap();
        let outcome = repo.rebase("main", "me").unwrap();
        match outcome {
            RebaseResult::Rebased { replayed, skipped, .. } => {
                assert_eq!(replayed, 1, "only 'adds b' should replay");
                assert_eq!(skipped, 1, "'adds a' is already present -> skipped");
            }
            other => panic!("expected Rebased, got {other:?}"),
        }
        assert!(root.join("b.txt").exists());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Rebase's replay carries the *target*-side secret registry forward
    /// wholesale (spec-blessed, see `secrets_changed_from_parent`) rather
    /// than replaying a commit's own registry change — so a `secret add` in
    /// the rebased range must not survive into the new history: HEAD's
    /// registry afterwards must equal target's (unchanged). The warning
    /// itself goes to stderr and isn't asserted here.
    #[test]
    fn rebase_drops_secret_registry_changes_from_the_range() {
        let root = tmp_root("rebase-secrets");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main gains an unrelated commit so the rebase has real work to do.
        std::fs::write(root.join("main.txt"), b"main\n").unwrap();
        repo.commit("me", "main adds main.txt").unwrap();
        let target_registry = repo.snapshot(&repo.head_tip().unwrap().unwrap()).unwrap().secrets;

        // feature adds a secret, which lands in its snapshot's registry.
        repo.switch("feature").unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("DB_URL", b"v1", &[pk]).unwrap();
        assert_eq!(repo.secret_list().unwrap().len(), 1);

        let outcome = repo.rebase("main", "me").unwrap();
        match outcome {
            RebaseResult::Rebased { .. } => {}
            other => panic!("expected Rebased, got {other:?}"),
        }

        let new_tip = repo.head_tip().unwrap().unwrap();
        let new_registry = repo.snapshot(&new_tip).unwrap().secrets;
        assert_eq!(
            new_registry, target_registry,
            "replay must carry target's registry, not the rebased commit's secret add"
        );
        assert!(repo.secret_list().unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_range_with_merge_commit_is_refused() {
        let root = tmp_root("rebase-merge-refused");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("main2").unwrap();
        repo.branch("feature").unwrap();

        // main2 is a side branch that feature will merge in.
        repo.switch("main2").unwrap();
        std::fs::write(root.join("side.txt"), b"side\n").unwrap();
        repo.commit("me", "side commit").unwrap();

        // feature merges main2 in, producing a merge commit in feature's history.
        repo.switch("feature").unwrap();
        std::fs::write(root.join("feat.txt"), b"feat\n").unwrap();
        repo.commit("me", "feature commit").unwrap();
        let merged = repo.merge("main2", "me").unwrap();
        assert!(repo.snapshot(&merged).unwrap().parents.len() >= 2);
        let feature_tip_before = repo.head_tip().unwrap();

        // main gains an unrelated commit, so rebasing feature onto main has
        // real work to do (not a fast path).
        repo.switch("main").unwrap();
        std::fs::write(root.join("main.txt"), b"main\n").unwrap();
        repo.commit("me", "main adds main.txt").unwrap();

        repo.switch("feature").unwrap();
        assert_eq!(repo.head_tip().unwrap(), feature_tip_before);

        let err = repo.rebase("main", "me").unwrap_err();
        assert!(matches!(err, Error::CannotReplayMerge(id) if id == merged), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), feature_tip_before, "feature tip must not move");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }
}
