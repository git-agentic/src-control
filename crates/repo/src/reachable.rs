//! Reachability over the object graph: every object id reachable from a set of
//! snapshot tips. Parameterized by an `ObjectSource` so it walks either the
//! local `Store` (push) or a remote `Transport` (clone/fetch). Reused by P8 gc.

use std::collections::{BTreeSet, VecDeque};

use scl_core::{EntryKind, Object, ObjectId, Store};

use crate::error::{Error, Result};
use crate::transport::Transport;

/// Minimal read access the walk needs: fetch a decoded object by id.
pub trait ObjectSource {
    fn get(&mut self, id: &ObjectId) -> Result<Object>;
}

impl ObjectSource for Store {
    fn get(&mut self, id: &ObjectId) -> Result<Object> {
        Ok(Store::get(self, id)?)
    }
}

/// An `ObjectSource` backed by a remote `Transport`.
pub struct TransportSource<'a> {
    pub(crate) transport: &'a dyn Transport,
}

impl ObjectSource for TransportSource<'_> {
    fn get(&mut self, id: &ObjectId) -> Result<Object> {
        let bytes = self.transport.get_object(id)?;
        let obj = Object::decode(&bytes).map_err(Error::from)?;
        if obj.id() != *id {
            return Err(Error::CorruptObject(*id));
        }
        Ok(obj)
    }
}

/// All object ids reachable from `tips`: each snapshot + its parents, its root
/// tree (recursively into subtrees and blobs), and its `secrets` registry
/// objects.
pub fn reachable_objects(src: &mut impl ObjectSource, tips: &[ObjectId]) -> Result<BTreeSet<ObjectId>> {
    let mut seen = BTreeSet::new();
    let mut snapshots: VecDeque<ObjectId> = VecDeque::new();
    for t in tips {
        if seen.insert(*t) {
            snapshots.push_back(*t);
        }
    }
    while let Some(sid) = snapshots.pop_front() {
        let snap = match src.get(&sid)? {
            Object::Snapshot(s) => s,
            _ => return Err(Error::BadRef(format!("expected snapshot {sid}"))),
        };
        for p in &snap.parents {
            if seen.insert(*p) {
                snapshots.push_back(*p);
            }
        }
        for id in snap.secrets.values() {
            seen.insert(*id);
        }
        walk_tree(src, snap.root, &mut seen)?;
    }
    Ok(seen)
}

/// Walk `root` and every subtree it reaches, recording trees and blobs in
/// `seen`. Uses an explicit stack rather than recursion so a deeply-nested
/// (possibly hostile) remote tree can't overflow the call stack.
fn walk_tree(src: &mut impl ObjectSource, root: ObjectId, seen: &mut BTreeSet<ObjectId>) -> Result<()> {
    let mut stack: Vec<ObjectId> = Vec::new();
    if seen.insert(root) {
        stack.push(root);
    }
    while let Some(tree_id) = stack.pop() {
        let tree = match src.get(&tree_id)? {
            Object::Tree(t) => t,
            _ => return Err(Error::BadRef(format!("expected tree {tree_id}"))),
        };
        for e in tree.entries {
            match e.kind {
                EntryKind::Blob => {
                    seen.insert(e.id);
                }
                EntryKind::Tree => {
                    if seen.insert(e.id) {
                        stack.push(e.id);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_vfs::Repo as VfsRepo;
    use std::collections::BTreeMap;

    #[test]
    fn reaches_snapshots_trees_blobs_and_secrets() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let root = repo
            .write_tree(&[("a.txt".into(), b"A".to_vec(), scl_core::FileMode::FILE)])
            .unwrap();
        let arc = repo.store();
        let (snap_id, blob_id, secret_id) = {
            let mut s = arc.lock().unwrap();
            let blob_id = Object::blob(b"A".to_vec()).id();
            let secret_id = s
                .put(Object::Secret(scl_core::Secret {
                    name: "K".into(),
                    nonce: vec![0; 24],
                    ciphertext: vec![1, 2, 3],
                    wrapped_keys: vec![],
                }))
                .unwrap();
            let mut secrets = BTreeMap::new();
            secrets.insert("K".to_string(), secret_id);
            let snap_id = s
                .put(Object::Snapshot(scl_core::Snapshot {
                    root,
                    parents: vec![],
                    author: "t".into(),
                    timestamp: 0,
                    message: "c".into(),
                    secrets,
                    protection: Default::default(),
                }))
                .unwrap();
            (snap_id, blob_id, secret_id)
        };
        let mut s = arc.lock().unwrap();
        let set = reachable_objects(&mut *s, &[snap_id]).unwrap();
        assert!(set.contains(&snap_id));
        assert!(set.contains(&root));
        assert!(set.contains(&blob_id));
        assert!(set.contains(&secret_id));
    }
}
