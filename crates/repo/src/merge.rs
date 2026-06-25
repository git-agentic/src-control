//! Three-way merge: find the common ancestor over the snapshot `parents` DAG,
//! then reconcile file trees and secret registries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use scl_core::{FileMode, Object, ObjectId, Store};

use crate::diff3;
use crate::error::{Error, Result};
use crate::worktree::tree_file_entries;

/// The lowest common ancestor of `a` and `b` over the parent DAG, or `None` if
/// the two share no ancestor. Walks ancestors breadth-first from both tips.
pub fn merge_base(store: &mut Store, a: ObjectId, b: ObjectId) -> Result<Option<ObjectId>> {
    let a_anc = ancestors(store, a)?;
    // BFS from b; first node also in a's ancestor set is a lowest common ancestor.
    let mut seen = BTreeSet::new();
    let mut q = VecDeque::new();
    q.push_back(b);
    seen.insert(b);
    while let Some(id) = q.pop_front() {
        if a_anc.contains(&id) {
            return Ok(Some(id));
        }
        for p in store.get_snapshot(&id)?.parents {
            if seen.insert(p) {
                q.push_back(p);
            }
        }
    }
    Ok(None)
}

/// Whether `anc` is an ancestor of (or equal to) `desc`.
pub fn is_ancestor(store: &mut Store, anc: ObjectId, desc: ObjectId) -> Result<bool> {
    Ok(ancestors(store, desc)?.contains(&anc))
}

/// All ancestors of `id`, inclusive.
fn ancestors(store: &mut Store, id: ObjectId) -> Result<BTreeSet<ObjectId>> {
    let mut set = BTreeSet::new();
    let mut q = VecDeque::new();
    q.push_back(id);
    set.insert(id);
    while let Some(cur) = q.pop_front() {
        for p in store.get_snapshot(&cur)?.parents {
            if set.insert(p) {
                q.push_back(p);
            }
        }
    }
    Ok(set)
}

/// Resolved result of a three-way merge, ready to materialize.
pub struct Merge {
    /// Merged working set: `(path, mode, bytes)` (text-conflict files contain
    /// markers; binary-conflict files keep ours' bytes).
    pub files: Vec<(String, FileMode, Vec<u8>)>,
    /// Sidecars to write to the working tree only (e.g. `foo.bin.theirs`).
    pub sidecars: Vec<(String, Vec<u8>)>,
    /// Conflicted paths (empty => clean merge).
    pub conflicts: Vec<String>,
    /// Merged secret registry.
    pub secrets: BTreeMap<String, ObjectId>,
}

/// Three-way merge of the file trees and secret registries of `ours`/`theirs`
/// against their `base` snapshot.
pub fn three_way(
    store: &mut Store,
    base: ObjectId,
    ours: ObjectId,
    theirs: ObjectId,
) -> Result<Merge> {
    let base_snap = store.get_snapshot(&base)?;
    let ours_snap = store.get_snapshot(&ours)?;
    let theirs_snap = store.get_snapshot(&theirs)?;

    let secrets = merge_secrets(&base_snap.secrets, &ours_snap.secrets, &theirs_snap.secrets)?;

    let base_f = tree_file_entries(store, base_snap.root)?;
    let ours_f = tree_file_entries(store, ours_snap.root)?;
    let theirs_f = tree_file_entries(store, theirs_snap.root)?;

    let mut paths: BTreeSet<String> = BTreeSet::new();
    paths.extend(base_f.keys().cloned());
    paths.extend(ours_f.keys().cloned());
    paths.extend(theirs_f.keys().cloned());

    let mut files = Vec::new();
    let mut sidecars = Vec::new();
    let mut conflicts = Vec::new();

    for path in paths {
        let b = base_f.get(&path).copied();
        let o = ours_f.get(&path).copied();
        let t = theirs_f.get(&path).copied();

        // Resolve by blob id first (cheap, covers unchanged/one-sided/delete).
        let bo = b.map(|x| x.0);
        let oo = o.map(|x| x.0);
        let to = t.map(|x| x.0);

        if oo == to {
            // same on both sides (including both-deleted) — take ours if present
            if let Some((id, mode)) = o {
                files.push((path, mode, blob_bytes(store, id)?));
            }
            continue;
        }
        if oo == bo {
            // only theirs changed -> take theirs (present or deleted)
            if let Some((id, mode)) = t {
                files.push((path, mode, blob_bytes(store, id)?));
            }
            continue;
        }
        if to == bo {
            // only ours changed -> take ours
            if let Some((id, mode)) = o {
                files.push((path, mode, blob_bytes(store, id)?));
            }
            continue;
        }

        // Both sides changed differently.
        match (o, t) {
            (Some((oid, omode)), Some((tid, _tmode))) => {
                let ob = blob_bytes(store, oid)?;
                let tb = blob_bytes(store, tid)?;
                let bb = match b {
                    Some((bid, _)) => blob_bytes(store, bid)?,
                    None => Vec::new(),
                };
                match (std::str::from_utf8(&ob), std::str::from_utf8(&tb)) {
                    (Ok(os), Ok(ts)) => {
                        let base_text = std::str::from_utf8(&bb).unwrap_or("");
                        let m = diff3::merge_lines(base_text, os, ts);
                        if m.conflicted {
                            conflicts.push(path.clone());
                        }
                        files.push((path, omode, m.text.into_bytes()));
                    }
                    _ => {
                        // binary conflict: keep ours, write theirs sidecar
                        conflicts.push(path.clone());
                        sidecars.push((format!("{path}.theirs"), tb));
                        files.push((path, omode, ob));
                    }
                }
            }
            // delete/modify: one side deleted, the other modified -> conflict;
            // keep the surviving (modified) content and mark conflicted.
            (Some((oid, omode)), None) => {
                conflicts.push(path.clone());
                files.push((path, omode, blob_bytes(store, oid)?));
            }
            (None, Some((tid, tmode))) => {
                conflicts.push(path.clone());
                files.push((path, tmode, blob_bytes(store, tid)?));
            }
            (None, None) => unreachable!("oo==to already handled the both-absent case"),
        }
    }

    Ok(Merge { files, sidecars, conflicts, secrets })
}

/// Three-way merge of two secret registries against base. A name changed
/// differently on both sides is a `SecretMergeConflict`.
pub fn merge_secrets(
    base: &BTreeMap<String, ObjectId>,
    ours: &BTreeMap<String, ObjectId>,
    theirs: &BTreeMap<String, ObjectId>,
) -> Result<BTreeMap<String, ObjectId>> {
    let mut names: BTreeSet<&String> = BTreeSet::new();
    names.extend(base.keys());
    names.extend(ours.keys());
    names.extend(theirs.keys());

    let mut out = BTreeMap::new();
    for name in names {
        let b = base.get(name).copied();
        let o = ours.get(name).copied();
        let t = theirs.get(name).copied();
        let resolved = if o == t {
            o
        } else if o == b {
            t
        } else if t == b {
            o
        } else {
            return Err(Error::SecretMergeConflict(name.clone()));
        };
        if let Some(id) = resolved {
            out.insert(name.clone(), id);
        }
    }
    Ok(out)
}

fn blob_bytes(store: &mut Store, id: ObjectId) -> Result<Vec<u8>> {
    match store.get(&id)? {
        Object::Blob(b) => Ok(b.to_vec()),
        _ => Err(Error::BadRef(format!("expected blob for {id}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn snap(store: &mut Store, parents: Vec<ObjectId>, msg: &str) -> ObjectId {
        let root = store.put(Object::Tree(scl_core::Tree::new(vec![]))).unwrap();
        store
            .put(Object::Snapshot(scl_core::Snapshot {
                root,
                parents,
                author: "t".into(),
                timestamp: 0,
                message: msg.into(),
                secrets: BTreeMap::new(),
            }))
            .unwrap()
    }

    #[test]
    fn linear_and_diverged_merge_base() {
        let mut s = Store::with_budget(1 << 20);
        let a = snap(&mut s, vec![], "base");
        let b = snap(&mut s, vec![a], "ours");
        let c = snap(&mut s, vec![a], "theirs");
        // base of two children of `a` is `a`.
        assert_eq!(merge_base(&mut s, b, c).unwrap(), Some(a));
        // ancestor checks
        assert!(is_ancestor(&mut s, a, b).unwrap());
        assert!(!is_ancestor(&mut s, b, c).unwrap());
    }

    #[test]
    fn criss_cross_picks_a_common_ancestor() {
        let mut s = Store::with_budget(1 << 20);
        let root = snap(&mut s, vec![], "root");
        let x = snap(&mut s, vec![root], "x");
        let y = snap(&mut s, vec![root], "y");
        // two merge commits each with both parents
        let m1 = snap(&mut s, vec![x, y], "m1");
        let m2 = snap(&mut s, vec![y, x], "m2");
        let base = merge_base(&mut s, m1, m2).unwrap().unwrap();
        // x and y are both common ancestors; the result must be one of them.
        assert!(base == x || base == y);
    }

    #[test]
    fn unrelated_histories_have_no_base() {
        let mut s = Store::with_budget(1 << 20);
        let a = snap(&mut s, vec![], "a");
        let b = snap(&mut s, vec![], "b");
        assert_eq!(merge_base(&mut s, a, b).unwrap(), None);
    }

    use scl_vfs::Repo as VfsRepo;

    fn commit_files(
        store_repo: &VfsRepo,
        files: &[(&str, &str)],
        parents: Vec<ObjectId>,
    ) -> ObjectId {
        let fs: Vec<(String, Vec<u8>, FileMode)> = files
            .iter()
            .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec(), FileMode::FILE))
            .collect();
        let root = store_repo.write_tree(&fs).unwrap();
        let arc = store_repo.store();
        let mut s = arc.lock().unwrap();
        s.put(Object::Snapshot(scl_core::Snapshot {
            root,
            parents,
            author: "t".into(),
            timestamp: 0,
            message: "c".into(),
            secrets: BTreeMap::new(),
        }))
        .unwrap()
    }

    #[test]
    fn clean_three_way_merges_disjoint_files_and_lines() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(&repo, &[("shared.txt", "a\nb\nc\n"), ("only.txt", "keep\n")], vec![]);
        let ours = commit_files(&repo, &[("shared.txt", "a\nB\nc\n"), ("only.txt", "keep\n"), ("ours.txt", "o\n")], vec![base]);
        let theirs = commit_files(&repo, &[("shared.txt", "a\nb\nC\n"), ("only.txt", "keep\n")], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs).unwrap();
        assert!(m.conflicts.is_empty());
        let shared = m.files.iter().find(|(p, _, _)| p == "shared.txt").unwrap();
        assert_eq!(shared.2, b"a\nB\nC\n");
        assert!(m.files.iter().any(|(p, _, _)| p == "ours.txt"));
    }

    #[test]
    fn overlapping_lines_conflict() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(&repo, &[("f.txt", "a\nb\nc\n")], vec![]);
        let ours = commit_files(&repo, &[("f.txt", "a\nX\nc\n")], vec![base]);
        let theirs = commit_files(&repo, &[("f.txt", "a\nY\nc\n")], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs).unwrap();
        assert_eq!(m.conflicts, vec!["f.txt"]);
        let f = &m.files.iter().find(|(p, _, _)| p == "f.txt").unwrap().2;
        assert!(String::from_utf8_lossy(f).contains("<<<<<<< ours"));
    }

    #[test]
    fn secret_registry_conflict_is_reported() {
        let base = BTreeMap::new();
        let mut ours = BTreeMap::new();
        ours.insert("K".to_string(), ObjectId::of(b"o"));
        let mut theirs = BTreeMap::new();
        theirs.insert("K".to_string(), ObjectId::of(b"t"));
        let err = merge_secrets(&base, &ours, &theirs).unwrap_err();
        assert!(matches!(err, Error::SecretMergeConflict(n) if n == "K"));
    }
}
