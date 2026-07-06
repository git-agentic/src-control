//! Replay core (P14): cherry-pick is a three-way merge whose base is the
//! replayed commit's first parent (empty base for a root commit). Consumed by
//! the cherry-pick/rebase CLI surface (Tasks 8-9) to apply one commit onto an
//! arbitrary target tree without requiring a full branch merge.

use scl_core::{FileMode, ObjectId};

use crate::error::{Error, Result};
use crate::merge;
use crate::refs;
use crate::repo::Repo;
use crate::worktree;

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

    let fm = merge::three_way_files(&mut store, base_root, onto_root, theirs_root)?;
    drop(store);

    if !fm.conflicts.is_empty() {
        return Ok(ReplayOutcome::Conflicts {
            files: fm.files,
            sidecars: fm.sidecars,
            paths: fm.conflicts,
        });
    }

    let write_set: Vec<(String, Vec<u8>, FileMode)> =
        fm.files.iter().map(|(p, m, b)| (p.clone(), b.clone(), *m)).collect();
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

        match replay_commit(self, picked_tip, ours_root)? {
            ReplayOutcome::Empty => Ok(PickResult::AlreadyApplied),
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
        crate::merge_state::write(&repo.layout, &ours_tip, &[]).unwrap();
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
        crate::merge_state::write(&repo.layout, &ours_tip, &[]).unwrap();
        let err = repo.cherry_pick("work-1", "me").unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(ours_tip), "tip must not move");

        crate::merge_state::clear(&repo.layout).unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }
}
