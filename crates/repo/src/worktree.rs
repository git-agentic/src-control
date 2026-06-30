//! Reading the on-disk working tree and diffing it against a snapshot.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{EntryKind, FileMode, Object, ObjectId, Protection, Store, Tree, PROTECTED};

use crate::error::Result;
use crate::layout::Layout;

/// Read all working-tree files (skipping `.sc/`) as `(relpath, bytes, mode)`.
pub fn read_worktree(layout: &Layout) -> Result<Vec<(String, Vec<u8>, FileMode)>> {
    let mut out = Vec::new();
    walk_disk(&layout.root, &layout.root, &layout.dot_sc, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_disk(
    base: &Path,
    dir: &Path,
    skip: &Path,
    out: &mut Vec<(String, Vec<u8>, FileMode)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == skip {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_disk(base, &path, skip, out)?;
        } else if ft.is_file() {
            let rel = path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            let bytes = std::fs::read(&path)?;
            let mode = file_mode(&path);
            out.push((rel, bytes, mode));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(path: &Path) -> FileMode {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) if m.permissions().mode() & 0o111 != 0 => FileMode::EXEC,
        _ => FileMode::FILE,
    }
}
#[cfg(not(unix))]
fn file_mode(_path: &Path) -> FileMode {
    FileMode::FILE
}

/// Flatten a snapshot's root tree to `path -> (blob id, mode)`.
pub fn tree_file_entries(
    store: &mut Store,
    root: ObjectId,
) -> Result<BTreeMap<String, (ObjectId, FileMode)>> {
    let mut out = BTreeMap::new();
    walk_entries(store, root, String::new(), &mut out)?;
    Ok(out)
}

fn walk_entries(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    out: &mut BTreeMap<String, (ObjectId, FileMode)>,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        match e.kind {
            EntryKind::Blob => {
                out.insert(path, (e.id, e.mode));
            }
            EntryKind::Tree => walk_entries(store, e.id, path, out)?,
        }
    }
    Ok(())
}

/// Flatten a snapshot's root tree to `path -> (blob id, mode, perms)`.
/// The `perms` byte carries per-entry flags such as [`scl_core::PROTECTED`].
pub fn tree_file_entries_with_perms(
    store: &mut Store,
    root: ObjectId,
) -> Result<BTreeMap<String, (ObjectId, FileMode, u8)>> {
    let mut out = BTreeMap::new();
    walk_entries_with_perms(store, root, String::new(), &mut out)?;
    Ok(out)
}

fn walk_entries_with_perms(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    out: &mut BTreeMap<String, (ObjectId, FileMode, u8)>,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        match e.kind {
            EntryKind::Blob => {
                out.insert(path, (e.id, e.mode, e.perms));
            }
            EntryKind::Tree => walk_entries_with_perms(store, e.id, path, out)?,
        }
    }
    Ok(())
}

/// Flatten a snapshot's root tree to `path -> blob id`.
pub fn tree_file_ids(store: &mut Store, root: ObjectId) -> Result<BTreeMap<String, ObjectId>> {
    let mut out = BTreeMap::new();
    walk_tree(store, root, String::new(), &mut out)?;
    Ok(out)
}

fn walk_tree(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    out: &mut BTreeMap<String, ObjectId>,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        match e.kind {
            EntryKind::Blob => {
                out.insert(path, e.id);
            }
            EntryKind::Tree => walk_tree(store, e.id, path, out)?,
        }
    }
    Ok(())
}

/// Difference between the working tree and a snapshot's root tree.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

/// Diff the working tree against `head_root` (None => unborn: all files added).
pub fn diff_worktree(
    layout: &Layout,
    store: &mut Store,
    head_root: Option<ObjectId>,
) -> Result<Diff> {
    let wt: BTreeMap<String, ObjectId> = read_worktree(layout)?
        .into_iter()
        .map(|(p, b, _)| (p, Object::blob(b).id()))
        .collect();
    let head = match head_root {
        Some(root) => tree_file_ids(store, root)?,
        None => BTreeMap::new(),
    };
    let mut diff = Diff::default();
    for (p, id) in &wt {
        match head.get(p) {
            None => diff.added.push(p.clone()),
            Some(hid) if hid != id => diff.modified.push(p.clone()),
            _ => {}
        }
    }
    for p in head.keys() {
        if !wt.contains_key(p) {
            diff.deleted.push(p.clone());
        }
    }
    Ok(diff)
}

/// Join a tree-relative path onto `root`, rejecting any component that could
/// escape the repo root (`..`, `.`, empty, or an absolute path). A committed
/// tree is attacker-influenced data, so an unsafe relpath is a hard error
/// rather than a silent skip — otherwise a malicious tree could write or delete
/// files anywhere on disk during `materialize`.
fn safe_join(root: &Path, rel: &str) -> Result<std::path::PathBuf> {
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(crate::error::Error::BadRef(format!("unsafe path in tree: {rel}")));
        }
    }
    Ok(root.join(rel))
}

/// Materialize a snapshot's file tree into the working dir.
///
/// For `PROTECTED` entries, decrypts with `identity` if it can unwrap the
/// blob's DEK from `protection.wrapped`; otherwise **skips** the file (neither
/// writes nor deletes it) and records its path in the returned `skipped` list.
/// Non-protected entries are written verbatim. Working files tracked by
/// `old_root` but absent from the target tree are deleted regardless of
/// protection status.
pub fn materialize(
    layout: &Layout,
    store: &mut Store,
    target_root: ObjectId,
    old_root: Option<ObjectId>,
    protection: &Protection,
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<Vec<String>> {
    let target = tree_file_entries_with_perms(store, target_root)?;
    if let Some(old) = old_root {
        for p in tree_file_ids(store, old)?.keys() {
            if !target.contains_key(p) {
                let full = safe_join(&layout.root, p)?;
                let _ = std::fs::remove_file(full);
            }
        }
    }
    let mut skipped = Vec::new();
    for (path, (blob_id, _mode, perms)) in &target {
        let full = safe_join(&layout.root, path)?;
        let bytes = match store.get(blob_id)? {
            Object::Blob(b) => b,
            _ => continue,
        };
        if perms & PROTECTED != 0 {
            // Protected: try to decrypt with the provided identity.
            let decrypted: Option<_> = (|| {
                let sk = identity?;
                let wks = protection.wrapped.get(blob_id)?;
                for wk in wks {
                    if let Ok(dek) = scl_crypto::unwrap_dek_with(wk, sk) {
                        if let Ok(pt) = scl_crypto::decrypt_path(&bytes, &dek) {
                            return Some(pt);
                        }
                    }
                }
                None
            })();
            match decrypted {
                Some(pt) => {
                    if let Some(parent) = full.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&full, &pt[..])?;
                    // `pt` (Zeroizing<Vec<u8>>) is dropped and zeroed here.
                }
                None => {
                    // No identity or no matching key: skip without writing.
                    skipped.push(path.clone());
                }
            }
        } else {
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&full, &bytes[..])?;
        }
    }
    Ok(skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::{Snapshot, TreeEntry};
    use std::collections::BTreeMap;

    fn tmp_objects(tag: &str) -> (Layout, Store) {
        let root = std::env::temp_dir().join(format!("scl-repo-wt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(layout.objects_dir()).unwrap();
        let store = Store::open_persistent(layout.objects_dir(), 1 << 20).unwrap();
        (layout, store)
    }

    #[test]
    fn materialize_rejects_path_traversal_entry() {
        let (layout, mut store) = tmp_objects("traversal");
        // Build a tree whose entry name is "..", bypassing vfs path normalization,
        // so materialize would otherwise write to the repo's *parent* directory.
        let blob = store.put(Object::blob(b"pwned".to_vec())).unwrap();
        let evil_tree = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "..".into(),
                kind: EntryKind::Blob,
                id: blob,
                mode: FileMode::FILE,
                perms: 0,
            }])))
            .unwrap();

        let err = materialize(&layout, &mut store, evil_tree, None, &Default::default(), None)
            .unwrap_err();
        assert!(matches!(err, crate::error::Error::BadRef(_)), "got {err:?}");
        // Nothing was written outside the repo root: the sibling "<root>.." path
        // would be the repo's parent dir; assert no stray "pwned" file landed there.
        let escaped = layout.root.parent().unwrap().join("pwned");
        assert!(!escaped.exists(), "materialize escaped the repo root");

        // A snapshot pointing at the evil tree must also be rejected by materialize.
        let snap = store
            .put(Object::Snapshot(Snapshot {
                root: evil_tree,
                parents: vec![],
                author: "a".into(),
                timestamp: 0,
                message: "m".into(),
                secrets: BTreeMap::new(),
                protection: Default::default(),
            }))
            .unwrap();
        let snap_root = store.get_snapshot(&snap).unwrap().root;
        assert!(materialize(&layout, &mut store, snap_root, None, &Default::default(), None).is_err());

        drop(store);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
