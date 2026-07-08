//! Reachability-based garbage collection for persistent repos.
//!
//! Under the single-writer lock: gather the full safe root set, walk every
//! object reachable from it, consolidate the reachable set into one fresh
//! packfile, delete the now-redundant loose copies, prune unreachable loose
//! objects older than a grace window, and drop superseded packs.
//!
//! Safety: a reachable object is never dropped. Deletions happen only after the
//! new pack is durably written. The grace window protects *loose* objects
//! (recently written, possibly staged); a *packed* unreachable object is
//! dropped without grace because it survived a prior gc (it was reachable then,
//! and is old now) — mirroring git's loose-vs-packed pruning model.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scl_core::{ObjectId, Store};

use crate::error::Result;
use crate::layout::Layout;
use crate::{merge_state, oplog, pick_state, reachable, rebase_state, refs, ws};

/// What a gc pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcStats {
    pub packed: usize,
    pub loose_pruned: usize,
    pub loose_kept: usize,
    pub packs_removed: usize,
}

/// The full safe root set (snapshot ids): all branch tips + resolved HEAD +
/// all remote-tracking tips + an in-progress merge's other parent + an
/// in-progress cherry-pick's picked commit (completion re-reads its rules;
/// its source branch could be deleted mid-pick) + every snapshot id still
/// referenced by the (already-trimmed) oplog — undo/redo must never dangle a
/// snapshot it can still restore to + a stopped rebase's accumulated fold
/// tip (`acc_tip` — the last landed snapshot; a `--continue` folds onward
/// from it) + an open `sc ws` session's base snapshot (workspaces are
/// forked from it and may still need to be harvested). An in-progress
/// merge's, pick's, or rebase's decided carried tree is a TREE root and is
/// added separately in [`run`].
fn roots(layout: &Layout) -> Result<Vec<ObjectId>> {
    let mut set: BTreeSet<ObjectId> = BTreeSet::new();
    for (_, id) in refs::list_heads(layout)? {
        set.insert(id);
    }
    if let Some(id) = refs::head_tip(layout)? {
        set.insert(id);
    }
    for (_, _, id) in refs::list_remote_tips(layout)? {
        set.insert(id);
    }
    if let Some(id) = merge_state::read_merge_head(layout)? {
        set.insert(id);
    }
    if let Some(id) = pick_state::read_pick_head(layout)? {
        set.insert(id);
    }
    if let Some(st) = rebase_state::read(layout)? {
        set.insert(st.acc_tip);
    }
    if let Some(s) = ws::read_manifest(layout)? {
        set.insert(s.base_snapshot);
    }
    for id in oplog::referenced_ids(layout)? {
        set.insert(id);
    }
    Ok(set.into_iter().collect())
}

/// Run a gc pass. Caller must already hold the repo lock.
pub fn run(layout: &Layout, store: &mut Store, grace: Duration) -> Result<GcStats> {
    let mut stats = GcStats::default();

    // Trim oplog records past the grace window BEFORE computing roots, so a
    // just-trimmed record's snapshot doesn't linger as a root this pass (it
    // always keeps the newest record regardless of cutoff).
    let cutoff = (SystemTime::now() - grace)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    oplog::trim_older_than(layout, cutoff)?;

    let roots = roots(layout)?;
    let mut reachable: BTreeSet<ObjectId> = reachable::reachable_objects(store, &roots)?;
    // An in-progress merge's or cherry-pick's decided carried tree
    // (MERGE_DECIDED_ROOT / PICK_DECIDED_ROOT) is a TREE root, not a
    // snapshot: its tree nodes are freshly written by the conflict path and
    // reachable from no snapshot yet, but completion needs them — protect
    // them like any other root. Each is walked ONLY under its own
    // in-progress HEAD: the conflict paths write the decided root BEFORE the
    // HEAD (crash discipline), so a crash in that window leaves a
    // decided-root file with no matching HEAD — such residue is inert
    // (completion ignores it, see `Repo::commit`) and must not retain a dead
    // tree forever.
    if merge_state::read_merge_head(layout)?.is_some() {
        if let Some(tree) = merge_state::read_decided_root(layout)? {
            reachable::walk_tree(store, tree, &mut reachable)?;
        }
    }
    if pick_state::read_pick_head(layout)?.is_some() {
        if let Some(tree) = pick_state::read_decided_root(layout)? {
            reachable::walk_tree(store, tree, &mut reachable)?;
        }
    }
    if let Some(tree) = rebase_state::read_decided_root(layout)? {
        reachable::walk_tree(store, tree, &mut reachable)?;
    }

    // 1. Repack the entire reachable set into one fresh pack (skip if empty).
    let new_hash = if reachable.is_empty() {
        None
    } else {
        let ids: Vec<ObjectId> = reachable.iter().copied().collect();
        let hash = store.write_pack(&ids)?;
        stats.packed = ids.len();
        Some(hash)
    };

    // 2/3. Walk loose objects: delete reachable (now packed) immediately; prune
    //      unreachable past the grace window; keep recent unreachable.
    let now = SystemTime::now();
    for id in store.list_loose()? {
        if reachable.contains(&id) {
            store.delete(&id)?; // safely preserved in the new pack
            continue;
        }
        let old_enough = match store.loose_mtime(&id)? {
            Some(mtime) => now.duration_since(mtime).map(|age| age >= grace).unwrap_or(false),
            None => false,
        };
        if old_enough {
            store.delete(&id)?;
            stats.loose_pruned += 1;
        } else {
            stats.loose_kept += 1;
        }
    }

    // 4. Drop superseded packs: the new pack holds the whole reachable set, so
    //    every other pack is redundant for reachable objects (and any object it
    //    holds that is now unreachable is intentionally reclaimed).
    if let Some(keep) = new_hash {
        for hash in store.pack_hashes() {
            if hash != keep {
                store.delete_pack(&hash)?;
                stats.packs_removed += 1;
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::Object;
    use std::time::Duration;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("scl-gc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn gc_packs_reachable_and_prunes_old_dangling() {
        let root = tmp_root("basic");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"reachable").unwrap();
        let snap = repo.commit("t", "c1").unwrap();

        // A dangling blob: put it straight into the store, referenced by no ref.
        let dangling = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            s.put(Object::blob(b"dangling-and-old".to_vec())).unwrap()
        };

        let stats = repo.gc(Duration::from_secs(0)).unwrap();
        assert!(stats.packed >= 1);
        assert!(stats.loose_pruned >= 1);

        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        // Reachable snapshot survives (now from the pack); dangling is gone.
        assert!(s.contains(&snap));
        assert!(!s.contains(&dangling));
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_keeps_recent_dangling_within_grace() {
        let root = tmp_root("recent");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("t", "c1").unwrap();
        let dangling = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            s.put(Object::blob(b"fresh-dangling".to_vec())).unwrap()
        };
        // Big grace window: the just-written dangling object must be kept.
        let stats = repo.gc(Duration::from_secs(3600)).unwrap();
        assert_eq!(stats.loose_pruned, 0);
        assert!(stats.loose_kept >= 1);
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(s.contains(&dangling));
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_protects_objects_reachable_only_via_remote_ref() {
        let root = tmp_root("remoteref");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base").unwrap();
        let base = repo.commit("t", "c1").unwrap();
        // Make a second commit, point a remote-tracking ref at it, then move the
        // local branch back so the second commit is reachable ONLY via the remote ref.
        std::fs::write(root.join("a.txt"), b"more").unwrap();
        let second = repo.commit("t", "c2").unwrap();
        refs::write_remote_tip(repo.layout(), "origin", "main", &second).unwrap();
        refs::write_branch_tip(repo.layout(), "main", &base).unwrap();

        repo.gc(Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(s.contains(&second), "remote-tracking ref must protect its commit");
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_protects_merge_head() {
        let root = tmp_root("mergehead");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base").unwrap();
        let base = repo.commit("t", "c1").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs").unwrap();
        let theirs = repo.commit("t", "c2").unwrap();
        // Point the branch back to base; record `theirs` only via MERGE_HEAD.
        refs::write_branch_tip(repo.layout(), "main", &base).unwrap();
        // Record a decided carried tree reachable from NO snapshot — exactly
        // what the conflict path writes; completion needs it after a mid-merge gc.
        let (decided_blob, decided_tree) = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            let blob = s.put(Object::blob(b"decided-only-bytes".to_vec())).unwrap();
            let tree = s
                .put(Object::Tree(scl_core::Tree::new(vec![scl_core::TreeEntry {
                    name: "d.txt".into(),
                    kind: scl_core::EntryKind::Blob,
                    id: blob,
                    mode: scl_core::FileMode::FILE,
                    perms: 0,
                }])))
                .unwrap();
            (blob, tree)
        };
        merge_state::write(repo.layout(), &theirs, &["a.txt".into()], Some(&decided_tree))
            .unwrap();

        repo.gc(Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(s.contains(&theirs), "MERGE_HEAD must protect the in-progress other parent");
        assert!(
            s.contains(&decided_tree) && s.contains(&decided_blob),
            "MERGE_DECIDED_ROOT must protect the decided carried tree + its blobs"
        );
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_protects_pick_head_and_pick_decided_root() {
        // P15 Task 7: an in-progress cherry-pick's picked commit (PICK_HEAD)
        // and its decided carried tree (PICK_DECIDED_ROOT) must survive a
        // mid-pick gc — completion reads the picked commit's rules and
        // carries absent protected files from the decided tree.
        let root = tmp_root("pickhead");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base").unwrap();
        let base = repo.commit("t", "c1").unwrap();
        std::fs::write(root.join("a.txt"), b"picked").unwrap();
        let picked = repo.commit("t", "c2").unwrap();
        // Point the branch back to base; record `picked` only via PICK_HEAD.
        refs::write_branch_tip(repo.layout(), "main", &base).unwrap();
        // Record a decided carried tree reachable from NO snapshot — exactly
        // what the pick conflict path writes; completion needs it after a
        // mid-pick gc.
        let (decided_blob, decided_tree) = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            let blob = s.put(Object::blob(b"pick-decided-only-bytes".to_vec())).unwrap();
            let tree = s
                .put(Object::Tree(scl_core::Tree::new(vec![scl_core::TreeEntry {
                    name: "d.txt".into(),
                    kind: scl_core::EntryKind::Blob,
                    id: blob,
                    mode: scl_core::FileMode::FILE,
                    perms: 0,
                }])))
                .unwrap();
            (blob, tree)
        };
        crate::pick_state::write(repo.layout(), &picked, &["a.txt".into()], Some(&decided_tree), None)
            .unwrap();

        repo.gc(Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(s.contains(&picked), "PICK_HEAD must protect the in-progress picked commit");
        assert!(
            s.contains(&decided_tree) && s.contains(&decided_blob),
            "PICK_DECIDED_ROOT must protect the decided carried tree + its blobs"
        );
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_protects_rebase_acc_tip_and_rebase_decided_root() {
        // P19 Task 1: a stopped rebase's accumulated fold tip (REBASE_STATE's
        // acc_tip) and its decided carried tree (REBASE_DECIDED_ROOT) must
        // survive a mid-rebase gc — `--continue` folds onward from acc_tip,
        // and completion carries absent protected files from the decided
        // tree, mirroring the merge/pick decided-root protections above.
        let root = tmp_root("rebasestate");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base").unwrap();
        let base = repo.commit("t", "c1").unwrap();
        // Build `acc_tip` as a snapshot object put directly into the store
        // (never through `repo.commit`), so it is reachable from no ref AND
        // referenced by no oplog record — the only thing keeping it alive
        // is REBASE_STATE's `acc_tip` field. Going through `repo.commit`
        // would leave an oplog record naming it too, masking whether
        // `roots()`'s `set.insert(st.acc_tip)` is actually load-bearing.
        let acc_tip = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            let base_snap = s.get_snapshot(&base).unwrap();
            s.put(Object::Snapshot(scl_core::Snapshot {
                root: base_snap.root,
                parents: vec![base],
                author: "t".into(),
                timestamp: base_snap.timestamp,
                message: "folded".into(),
                secrets: Default::default(),
                protection: Default::default(),
            }))
            .unwrap()
        };
        // Record a decided carried tree reachable from NO snapshot — exactly
        // what the rebase conflict path writes; completion needs it after a
        // mid-rebase gc.
        let (decided_blob, decided_tree) = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            let blob = s.put(Object::blob(b"rebase-decided-only-bytes".to_vec())).unwrap();
            let tree = s
                .put(Object::Tree(scl_core::Tree::new(vec![scl_core::TreeEntry {
                    name: "d.txt".into(),
                    kind: scl_core::EntryKind::Blob,
                    id: blob,
                    mode: scl_core::FileMode::FILE,
                    perms: 0,
                }])))
                .unwrap();
            (blob, tree)
        };
        let st = crate::rebase_state::RebaseState {
            branch: "main".into(),
            original_tip: acc_tip,
            target: "target".into(),
            acc_tip,
            conflicted: ObjectId::of(b"conflicted-commit"),
            remaining: vec![ObjectId::of(b"remaining-commit")],
            total: 3,
            author: "t".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        };
        crate::rebase_state::write(repo.layout(), &st).unwrap();
        crate::rebase_state::write_decided_root(repo.layout(), decided_tree).unwrap();

        repo.gc(Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(s.contains(&acc_tip), "REBASE_STATE's acc_tip must protect the fold's landed progress");
        assert!(
            s.contains(&decided_tree) && s.contains(&decided_blob),
            "REBASE_DECIDED_ROOT must protect the decided carried tree + its blobs"
        );
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_is_idempotent() {
        let root = tmp_root("idem");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("t", "c1").unwrap();
        repo.gc(Duration::from_secs(0)).unwrap();
        let second = repo.gc(Duration::from_secs(0)).unwrap();
        assert_eq!(second.loose_pruned, 0);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn oplog_referenced_snapshots_survive_gc() {
        let root = tmp_root("oplog-roots");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let c1 = repo.commit("t", "c1").unwrap();
        std::fs::write(root.join("a.txt"), b"two").unwrap();
        let c2 = repo.commit("t", "c2").unwrap();

        // Undo: tip back to c1; c2 is now unreachable from refs but still
        // referenced by the oplog (the undo record's "after" for main).
        repo.undo().unwrap();
        assert_eq!(refs::head_tip(repo.layout()).unwrap(), Some(c1));

        let stats = repo.gc(Duration::from_secs(0)).unwrap();
        assert_eq!(stats.loose_pruned, 0, "oplog-referenced c2 must not be pruned");

        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(s.contains(&c2), "c2 must survive gc: still referenced by the oplog");
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_trims_old_oplog_records_and_releases_roots() {
        let root = tmp_root("oplog-trim");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base").unwrap();
        let base = repo.commit("t", "base").unwrap();

        // A snapshot reachable ONLY via its own commit record; rewind the
        // branch tip directly (bypassing undo/oplog) so no inverse record is
        // added, leaving that one commit record as `old_snap`'s only root.
        std::fs::write(root.join("a.txt"), b"old").unwrap();
        let old_snap = repo.commit("t", "old snap").unwrap();
        refs::write_branch_tip(repo.layout(), "main", &base).unwrap();

        // Same shape, for a snapshot whose record must survive the trim.
        std::fs::write(root.join("a.txt"), b"fresh").unwrap();
        let fresh_snap = repo.commit("t", "fresh snap").unwrap();
        refs::write_branch_tip(repo.layout(), "main", &base).unwrap();

        // Find the record whose "after" is `old_snap` and hand-adjust its
        // timestamp far into the past by targeting its exact `ts <value>`
        // line in the raw file — a smaller, less brittle edit than
        // re-deriving the whole serialization format here (mirrors the
        // spirit of oplog's own `trim_keeps_newest_and_drops_old` test, which
        // does the analogous thing via the crate-internal `serialize`
        // helper). `fresh_snap`'s record is left on its real (current) clock
        // ts — it's always the newest record, so `trim_older_than` keeps it
        // regardless.
        let all = crate::oplog::read_all(repo.layout()).unwrap();
        let old_rec = all
            .iter()
            .find(|r| r.refs.iter().any(|(_, _, after)| *after == Some(old_snap)))
            .expect("old_snap's commit record must exist");
        assert_ne!(old_rec.seq, all.last().unwrap().seq, "old_snap's record must not be the newest");
        // All these records land in the same wall-clock second in a fast test
        // run, so their `ts` lines are identical text — a blind string
        // replace could land on the wrong block. Scope the edit to
        // `old_rec`'s own `op <seq>` block first, then rewrite only its `ts`
        // line within that slice.
        let raw = std::fs::read_to_string(repo.layout().oplog_path()).unwrap();
        let block_start = raw
            .find(&format!("op {}\n", old_rec.seq))
            .expect("old_rec's block must be present");
        let block_end = block_start + raw[block_start..].find("end\n").expect("block has an end line") + "end\n".len();
        let old_ts_line = format!("ts {}\n", old_rec.ts);
        let block = &raw[block_start..block_end];
        assert!(block.contains(&old_ts_line), "old record's ts line must be present in its own block");
        let patched_block = block.replacen(&old_ts_line, "ts 100\n", 1);
        let raw = format!("{}{}{}", &raw[..block_start], patched_block, &raw[block_end..]);
        std::fs::write(repo.layout().oplog_path(), raw).unwrap();

        // Zero grace (same convention as the other gc tests above): the
        // dangling snapshot, once its only root (the backdated record) is
        // trimmed, is prunable immediately.
        let stats = repo.gc(Duration::from_secs(0)).unwrap();

        let remaining = crate::oplog::read_all(repo.layout()).unwrap();
        assert!(
            !remaining.iter().any(|r| r.seq == old_rec.seq),
            "old record must be trimmed: {remaining:?}"
        );
        assert!(
            remaining
                .iter()
                .any(|r| r.refs.iter().any(|(_, _, after)| *after == Some(fresh_snap))),
            "fresh record must survive: {remaining:?}"
        );

        assert!(stats.loose_pruned >= 1, "old_snap's only root (the trimmed record) is gone");
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(!s.contains(&old_snap), "old_snap must be pruned once its only root is trimmed");
        assert!(s.contains(&fresh_snap), "fresh_snap stays alive via its surviving record");
        assert!(s.contains(&base), "base stays alive via the branch tip");
        drop(s);

        // Undo (which reads the log via `oplog::last`) still sees the
        // surviving fresh record after the trim rewrote the file.
        let last = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert!(last.refs.iter().any(|(_, _, after)| *after == Some(fresh_snap)));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn open_repo_holds_single_writer_lock_during_gc() {
        let root = tmp_root("held");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("t", "c1").unwrap();
        // A second open on the same repo is refused: the open `Repo` already holds
        // the single-writer lock, so gc always runs serialized against other writers.
        assert!(matches!(crate::repo::Repo::open(&root), Err(crate::error::Error::Locked(_))));
        repo.gc(Duration::from_secs(0)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }
}
