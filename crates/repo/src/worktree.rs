//! Reading the on-disk working tree and diffing it against a snapshot.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{EntryKind, FileMode, Object, ObjectId, Store, Tree};

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

/// Materialize a snapshot's file tree into the working dir, deleting working
/// files that are tracked by `old_root` but absent from the target.
pub fn materialize(
    layout: &Layout,
    store: &mut Store,
    target_root: ObjectId,
    old_root: Option<ObjectId>,
) -> Result<()> {
    let target = tree_file_ids(store, target_root)?;
    if let Some(old) = old_root {
        for p in tree_file_ids(store, old)?.keys() {
            if !target.contains_key(p) {
                let _ = std::fs::remove_file(layout.root.join(p));
            }
        }
    }
    for (path, blob_id) in &target {
        let bytes = match store.get(blob_id)? {
            Object::Blob(b) => b,
            _ => continue,
        };
        let full = layout.root.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&full, &bytes[..])?;
    }
    Ok(())
}
