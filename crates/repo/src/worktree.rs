//! Reading the on-disk working tree and diffing it against a snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use scl_core::{EntryKind, FileMode, Object, ObjectId, Protection, Store, Tree, PROTECTED};

use crate::error::{Error, Result};
use crate::ignore::Ignore;
use crate::layout::Layout;
use crate::sparse::Sparse;

/// Read all working-tree files (skipping `.sc/`) as `(relpath, bytes, mode)`.
///
/// Honors `.scignore` at the repo root, with git's model: an ignore rule hides
/// only **untracked** paths. `tracked` is the set of paths in HEAD — a tracked
/// path is always read even if a rule matches it, so adding a pattern can never
/// silently drop already-committed content from the next snapshot.
pub fn read_worktree(
    layout: &Layout,
    tracked: &BTreeSet<String>,
) -> Result<Vec<(String, Vec<u8>, FileMode)>> {
    let ignore = Ignore::load(&layout.root)?;
    let mut out = Vec::new();
    walk_disk(&layout.root, &layout.root, &layout.dot_sc, &ignore, tracked, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_disk(
    base: &Path,
    dir: &Path,
    skip: &Path,
    ignore: &Ignore,
    tracked: &BTreeSet<String>,
    out: &mut Vec<(String, Vec<u8>, FileMode)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == skip {
            continue;
        }
        let ft = entry.file_type()?;
        let rel = path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
        if ft.is_dir() {
            // Prune an ignored directory wholesale — unless a tracked path
            // lives under it, in which case we must descend to keep it.
            if ignore.matches(&rel) && !tracked_under(tracked, &rel) {
                continue;
            }
            walk_disk(base, &path, skip, ignore, tracked, out)?;
        } else if ft.is_file() {
            if ignore.matches(&rel) && !tracked.contains(&rel) {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let mode = file_mode(&path);
            out.push((rel, bytes, mode));
        }
    }
    Ok(())
}

/// Is any tracked path inside directory `dir` (repo-relative, no trailing `/`)?
fn tracked_under(tracked: &BTreeSet<String>, dir: &str) -> bool {
    let prefix = format!("{dir}/");
    tracked.range(prefix.clone()..).next().is_some_and(|p| p.starts_with(&prefix))
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

/// Gap-tolerant variant of [`tree_file_entries_with_perms`] for a partial
/// clone (P27 Task 4): descends only where `sparse.should_descend` says to,
/// mirroring `promisor`'s filtered reachability walk. A full (`is_full`)
/// spec behaves identically to the unfiltered walk. This exists because the
/// unfiltered walk calls `store.get_tree`/`store.get` on every entry in the
/// tree regardless of the sparse spec — correct when every object is
/// guaranteed present (P24's stated invariant: "every object stays in the
/// CAS regardless of the spec"), but a promisor-filtered clone breaks that
/// guarantee for out-of-filter subtrees, which were never fetched at all.
/// `materialize` is the only caller today; other flatteners
/// (`tree_file_ids`, `tree_file_entries_with_perms` itself) are used by
/// commit/merge/diff paths that are out of this task's scope and still
/// assume full CAS presence (a documented boundary, not a Task 4 fix).
pub(crate) fn tree_file_entries_with_perms_sparse(
    store: &mut Store,
    root: ObjectId,
    sparse: &Sparse,
) -> Result<BTreeMap<String, (ObjectId, FileMode, u8)>> {
    if sparse.is_full() {
        return tree_file_entries_with_perms(store, root);
    }
    let mut out = BTreeMap::new();
    walk_entries_with_perms_sparse(store, root, String::new(), sparse, &mut out)?;
    Ok(out)
}

fn walk_entries_with_perms_sparse(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    sparse: &Sparse,
    out: &mut BTreeMap<String, (ObjectId, FileMode, u8)>,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        match e.kind {
            EntryKind::Blob => {
                if sparse.matches(&path) {
                    out.insert(path, (e.id, e.mode, e.perms));
                }
            }
            EntryKind::Tree => {
                if sparse.should_descend(&path) {
                    walk_entries_with_perms_sparse(store, e.id, path, sparse, out)?;
                }
            }
        }
    }
    Ok(())
}

/// Splice `parent_id`'s out-of-sparse subtrees/entries back into `built_id`
/// by id, never reading the content of anything that lies outside `sparse`
/// (P27 Task 4). `commit` on a partial clone builds `built_id` purely from
/// in-sparse content (the promisor filter never fetched the rest, so it
/// can't be flattened to bytes and re-put — see `snapshot_files`'s carry
/// block), which on its own would silently DROP every out-of-sparse
/// subtree from the new root. This walks `parent_id`'s tree entries and,
/// for each one that lies outside `sparse`, grafts the parent's own
/// `TreeEntry` (its id, unchanged) into the built tree instead of
/// descending into it — a whole out-of-sparse subtree is carried forward
/// as one structural-sharing id copy, the id-level analogue of the
/// per-blob byte-carry `snapshot_files` already does for in-sparse
/// protected content. An ancestor directory that must be descended through
/// to reach a deeper in-sparse prefix (`should_descend`) recurses instead
/// of being grafted whole, so any genuinely in-sparse content beneath it
/// keeps coming from the built side. Returns `Err(GappedPathContent)` (I1,
/// P27 Task 4 review) instead of grafting when the built side already has
/// an entry at a fully out-of-sparse path — `read_worktree` doesn't respect
/// the sparse spec, so content written under a gapped subtree would
/// otherwise be silently discarded by the id-only graft.
///
/// Scope: single-parent (non-merge) commits only — `snapshot_files` only
/// calls this when `decided_root`/`merge_head` are both absent. Grafting a
/// TWO-parent (merge/pick) result against a partial clone's gaps is a
/// documented boundary, not solved here (mirrors the pre-existing P24
/// sparse+merge boundary notes).
pub(crate) fn graft_out_of_sparse(
    store: &mut Store,
    built_id: ObjectId,
    parent_id: ObjectId,
    sparse: &Sparse,
    prefix: &str,
) -> Result<ObjectId> {
    if built_id == parent_id {
        // Nothing under this subtree changed at all — already identical,
        // no need to read either side.
        return Ok(built_id);
    }
    let built_tree: Tree = store.get_tree(&built_id)?;
    let parent_tree: Tree = store.get_tree(&parent_id)?;

    let mut by_name: BTreeMap<String, scl_core::TreeEntry> =
        built_tree.entries.into_iter().map(|e| (e.name.clone(), e)).collect();

    for pe in parent_tree.entries {
        let path = if prefix.is_empty() { pe.name.clone() } else { format!("{prefix}/{}", pe.name) };
        if sparse.matches(&path) {
            // In-sparse: the built side already reflects the working tree's
            // current state (including a genuine deletion) — parent's entry
            // must not resurrect it.
            continue;
        }
        if !sparse.should_descend(&path) {
            // Fully out-of-sparse: graft the parent's entry verbatim, by id
            // only — never loaded. But `read_worktree` scans the whole disk
            // tree with no regard for the sparse spec (it only honors
            // `.scignore`), so if the built side already has an entry here,
            // someone wrote content under a path this partial clone never
            // fetched. Overwriting it wholesale with the parent's untouched
            // id (the pre-fix behavior) would silently DISCARD that content
            // (I1) — there's no way to fold it into a subtree we don't have
            // on this clone. Refuse loudly instead.
            if by_name.contains_key(&pe.name) {
                return Err(Error::GappedPathContent(path));
            }
            by_name.insert(pe.name.clone(), pe);
            continue;
        }
        // An ancestor directory: some deeper prefix is in-sparse, so recurse
        // rather than grafting the whole thing whole.
        if pe.kind != EntryKind::Tree {
            // A file sitting where the sparse spec expects a descendable
            // directory (a genuinely malformed/unexpected shape) — leave
            // whatever the built side already decided.
            continue;
        }
        let child_built_id = match by_name.get(&pe.name) {
            Some(be) if be.kind == EntryKind::Tree => be.id,
            _ => store.put(Object::Tree(Tree::default()))?,
        };
        let merged_child = graft_out_of_sparse(store, child_built_id, pe.id, sparse, &path)?;
        by_name.insert(
            pe.name.clone(),
            scl_core::TreeEntry {
                name: pe.name,
                kind: EntryKind::Tree,
                id: merged_child,
                mode: pe.mode,
                perms: 0,
            },
        );
    }

    let tree = Object::Tree(Tree::new(by_name.into_values().collect()));
    Ok(store.put(tree)?)
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

/// Gap-tolerant variant of [`tree_file_ids`] for a partial clone (P27 Task
/// 4), mirroring [`tree_file_entries_with_perms_sparse`]: descends only
/// where `sparse.should_descend` says to, so it never `store.get`s a
/// never-fetched out-of-filter subtree. A full spec behaves identically to
/// the unfiltered walk. Used by `Repo::tracked_paths_at` — an out-of-sparse
/// path can never be "tracked" in a way that matters to `.scignore`
/// filtering, since it is never materialized on disk in the first place.
pub(crate) fn tree_file_ids_sparse(
    store: &mut Store,
    root: ObjectId,
    sparse: &Sparse,
) -> Result<BTreeMap<String, ObjectId>> {
    if sparse.is_full() {
        return tree_file_ids(store, root);
    }
    let mut out = BTreeMap::new();
    walk_tree_sparse(store, root, String::new(), sparse, &mut out)?;
    Ok(out)
}

fn walk_tree_sparse(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    sparse: &Sparse,
    out: &mut BTreeMap<String, ObjectId>,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        match e.kind {
            EntryKind::Blob => {
                if sparse.matches(&path) {
                    out.insert(path, e.id);
                }
            }
            EntryKind::Tree => {
                if sparse.should_descend(&path) {
                    walk_tree_sparse(store, e.id, path, sparse, out)?;
                }
            }
        }
    }
    Ok(())
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
///
/// Protection-aware: a HEAD entry flagged `PROTECTED` stores ciphertext, while
/// the working copy (when present) is decrypted plaintext, so a naive plaintext
/// id comparison would always report it modified. Instead, for a PROTECTED HEAD
/// path:
/// - absent on disk => CLEAN (the expected state for an unauthorized/skipped
///   checkout — not a user deletion);
/// - present on disk => re-encrypt the disk bytes convergently (`encrypt_path`
///   is a pure, keyless function) and compare the resulting ciphertext blob id
///   to the stored one: equal => CLEAN, different => MODIFIED (a genuine edit).
///
/// Non-protected paths use the usual plaintext-blob-id comparison.
///
/// Sparse-aware: a HEAD path outside `sparse` is never materialized (see
/// `materialize`), so it's also expected-absent — same "absent => CLEAN, not
/// a user deletion" treatment as an unauthorized protected file. Without this,
/// `sc status`/the dirty-tree checks in `switch`/`merge`/`rebase` would read
/// every out-of-sparse path as a deletion and permanently block those
/// operations once a sparse spec is set.
pub fn diff_worktree(
    layout: &Layout,
    store: &mut Store,
    head_root: Option<ObjectId>,
    // Per-entry `PROTECTED` perms (read from the HEAD tree) are the authoritative
    // signal; the policy is taken explicitly so callers thread it consistently and
    // a future richer diff (e.g. prefix-aware reporting) needs no signature change.
    _protection: &Protection,
    sparse: &Sparse,
) -> Result<Diff> {
    let head = match head_root {
        Some(root) => tree_file_entries_with_perms(store, root)?,
        None => BTreeMap::new(),
    };
    let tracked: BTreeSet<String> = head.keys().cloned().collect();
    let wt: BTreeMap<String, Vec<u8>> =
        read_worktree(layout, &tracked)?.into_iter().map(|(p, b, _)| (p, b)).collect();
    let mut diff = Diff::default();
    for (p, bytes) in &wt {
        match head.get(p) {
            None => diff.added.push(p.clone()),
            Some((hid, _mode, perms)) => {
                let disk_id = if perms & PROTECTED != 0 {
                    // Convergent re-encryption yields the same id as the commit did.
                    Object::blob(scl_crypto::encrypt_path(bytes).0).id()
                } else {
                    Object::blob(bytes.clone()).id()
                };
                if &disk_id != hid {
                    diff.modified.push(p.clone());
                }
            }
        }
    }
    for (p, (_hid, _mode, perms)) in &head {
        if !wt.contains_key(p) {
            // A path outside the sparse spec is expected-absent, exactly like
            // an unauthorized protected file — not a user deletion.
            if !sparse.matches(p) {
                continue;
            }
            // A PROTECTED HEAD path absent on disk is the expected state for an
            // unauthorized/skipped checkout — clean, not a user deletion.
            if perms & PROTECTED != 0 {
                continue;
            }
            diff.deleted.push(p.clone());
        }
    }
    Ok(diff)
}

/// Join a tree-relative path onto `root`, rejecting any component that could
/// escape the repo root (`..`, `.`, empty, or an absolute path). A committed
/// tree is attacker-influenced data, so an unsafe relpath is a hard error
/// rather than a silent skip — otherwise a malicious tree could write or delete
/// files anywhere on disk during `materialize`. `pub(crate)` so the conflicted
/// merge path (Task 6, P15) can write plaintext marker files straight to the
/// working tree with the same traversal guard.
pub(crate) fn safe_join(root: &Path, rel: &str) -> Result<std::path::PathBuf> {
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(crate::error::Error::BadRef(format!("unsafe path in tree: {rel}")));
        }
    }
    Ok(root.join(rel))
}

/// Materialize a snapshot's file tree into the working dir.
///
/// `sparse` filters the disk view: a target entry outside `sparse` is never
/// written (the CAS tree still has it — this only governs the disk copy), and
/// the old-root removal pass also drops an on-disk file that's now outside
/// `sparse` even if the target tree still tracks it (the sparse-narrowing
/// case — see `Repo::set_sparse`). A full (empty) `Sparse` matches everything,
/// so this is a no-op filter for every caller that isn't sparse-aware yet.
///
/// For `PROTECTED` entries, decrypts with `identity` if it can unwrap the
/// blob's DEK from `protection.wrapped`; otherwise **skips** the file (neither
/// writes nor deletes it) and records its path in the returned `skipped` list.
/// Non-protected entries are written verbatim. Working files tracked by
/// `old_root` but absent from the target tree (or now outside `sparse`) are
/// deleted regardless of protection status.
pub fn materialize(
    layout: &Layout,
    store: &mut Store,
    target_root: ObjectId,
    old_root: Option<ObjectId>,
    protection: &Protection,
    identity: Option<&scl_crypto::SecretKey>,
    sparse: &Sparse,
) -> Result<Vec<String>> {
    // Gap-tolerant when sparse is active (P27 Task 4): a promisor-filtered
    // clone never fetched out-of-filter subtrees at all, so an unfiltered
    // walk here would `NotFound` on them. `old_root`'s walk stays
    // unfiltered below — clone (the case that hits this) always passes
    // `old_root: None`; widening a partial clone's sparse view beyond its
    // promisor filter via `old_root` remains a documented boundary, not
    // fixed by this task.
    let target = tree_file_entries_with_perms_sparse(store, target_root, sparse)?;
    if let Some(old) = old_root {
        for p in tree_file_ids(store, old)?.keys() {
            if !target.contains_key(p) || !sparse.matches(p) {
                let full = safe_join(&layout.root, p)?;
                let _ = std::fs::remove_file(full);
            }
        }
    }
    let mut skipped = Vec::new();
    for (path, (blob_id, _mode, perms)) in &target {
        if !sparse.matches(path) {
            continue;
        }
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
                    // No identity or no matching key: skip without writing. Remove
                    // any pre-existing on-disk file at this path so stale plaintext
                    // can't linger when a path becomes protected across a switch for
                    // a non-recipient (confidentiality). A failed removal must
                    // surface — swallowing it leaves plaintext on disk.
                    match std::fs::remove_file(&full) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
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
    fn read_worktree_respects_scignore_but_keeps_tracked() {
        let root =
            std::env::temp_dir().join(format!("scl-repo-wt-ignore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let layout = Layout::at(&root);
        std::fs::write(root.join(".scignore"), "target\n*.log\n").unwrap();
        std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        std::fs::write(root.join("target/debug/app"), b"\x7fELF").unwrap();
        std::fs::write(root.join("foo.log"), b"noise").unwrap();
        std::fs::write(root.join("tracked.log"), b"kept").unwrap();

        let tracked: std::collections::BTreeSet<String> =
            std::iter::once("tracked.log".to_string()).collect();
        let files = read_worktree(&layout, &tracked).unwrap();
        let paths: Vec<&str> = files.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(paths, vec![".scignore", "src/main.rs", "tracked.log"]);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn failed_stale_plaintext_removal_is_an_error_not_silent() {
        use std::os::unix::fs::PermissionsExt;
        // When a non-recipient materializes a tree with a PROTECTED path, any
        // stale on-disk plaintext at that path must be removed. If removal
        // fails, plaintext would silently linger — a confidentiality leak — so
        // materialize must surface the failure, not swallow it.
        let (layout, mut store) = tmp_objects("stale-ro");
        std::fs::create_dir_all(layout.root.join("vault")).unwrap();
        std::fs::write(layout.root.join("vault/secret.txt"), b"plaintext").unwrap();

        let blob = store.put(Object::blob(b"ciphertext".to_vec())).unwrap();
        let inner = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "secret.txt".into(),
                kind: EntryKind::Blob,
                id: blob,
                mode: FileMode::FILE,
                perms: PROTECTED,
            }])))
            .unwrap();
        let root_tree = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "vault".into(),
                kind: EntryKind::Tree,
                id: inner,
                mode: FileMode::FILE,
                perms: 0,
            }])))
            .unwrap();

        // Read-only parent dir: unlink of vault/secret.txt now fails.
        let vault = layout.root.join("vault");
        std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = materialize(&layout, &mut store, root_tree, None, &Default::default(), None, &Sparse::default());

        // Restore perms before asserting so cleanup always works.
        std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err(), "swallowing a failed stale-plaintext removal leaks plaintext");
        assert!(vault.join("secret.txt").exists());

        drop(store);
        std::fs::remove_dir_all(&layout.root).unwrap();
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

        let err = materialize(&layout, &mut store, evil_tree, None, &Default::default(), None, &Sparse::default())
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
        assert!(materialize(&layout, &mut store, snap_root, None, &Default::default(), None, &Sparse::default()).is_err());

        drop(store);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
