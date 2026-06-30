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
use std::time::{Duration, SystemTime};

use scl_core::{ObjectId, Store};

use crate::error::Result;
use crate::layout::Layout;
use crate::{merge_state, reachable, refs};

/// What a gc pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcStats {
    pub packed: usize,
    pub loose_pruned: usize,
    pub loose_kept: usize,
    pub packs_removed: usize,
}

/// The full safe root set: all branch tips + resolved HEAD + all
/// remote-tracking tips + an in-progress merge's other parent.
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
    Ok(set.into_iter().collect())
}

/// Run a gc pass. Caller must already hold the repo lock.
pub fn run(layout: &Layout, store: &mut Store, grace: Duration) -> Result<GcStats> {
    let mut stats = GcStats::default();
    let roots = roots(layout)?;
    let reachable: BTreeSet<ObjectId> = reachable::reachable_objects(store, &roots)?;

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
        merge_state::write(repo.layout(), &theirs, &["a.txt".into()]).unwrap();

        repo.gc(Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(s.contains(&theirs), "MERGE_HEAD must protect the in-progress other parent");
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
