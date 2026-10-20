//! Reading the on-disk working tree and diffing it against a snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use scl_core::{EntryKind, FileMode, Object, ObjectId, Protection, Store, Tree, PROTECTED};

use crate::cache::ProtectedCache;
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
    walk_disk(
        &layout.root,
        &layout.root,
        &layout.dot_sc,
        &ignore,
        tracked,
        &mut out,
    )?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The paths [`read_worktree`] would return, without reading a byte of any file:
/// the same walk, ignore rules and tracked-path exemption, for callers that
/// only need the list (`Repo::worktree_paths`).
pub fn list_worktree_paths(layout: &Layout, tracked: &BTreeSet<String>) -> Result<Vec<String>> {
    let ignore = Ignore::load(&layout.root)?;
    let mut out = Vec::new();
    walk_disk_paths(
        &layout.root,
        &layout.root,
        &layout.dot_sc,
        &ignore,
        tracked,
        &mut out,
    )?;
    out.sort();
    Ok(out)
}

fn walk_disk_paths(
    base: &Path,
    dir: &Path,
    skip: &Path,
    ignore: &Ignore,
    tracked: &BTreeSet<String>,
    out: &mut Vec<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == skip {
            continue;
        }
        let ft = entry.file_type()?;
        let rel = path
            .strip_prefix(base)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if ft.is_dir() {
            if ignore.matches(&rel) && !tracked_under(tracked, &rel) {
                continue;
            }
            walk_disk_paths(base, &path, skip, ignore, tracked, out)?;
        } else if ft.is_file() {
            if ignore.matches(&rel) && !tracked.contains(&rel) {
                continue;
            }
            out.push(rel);
        }
    }
    Ok(())
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
        let rel = path
            .strip_prefix(base)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
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
    tracked
        .range(prefix.clone()..)
        .next()
        .is_some_and(|p| p.starts_with(&prefix))
}

/// Write `bytes` to `path` and lay down the recorded `mode`'s executable bit,
/// the one place checkout-style writes go through so `read_worktree` (which
/// reads the mode back from the filesystem) round-trips. EXEC adds an execute
/// bit wherever the file already has a read bit (the umask-respecting default
/// stays); FILE clears any execute bits an existing file had; setuid/setgid/
/// sticky are always cleared. A no-op off unix; a filesystem that refuses the
/// chmod (no mode bits) is not an error (see [`scl_vfs::apply_file_mode`]).
pub(crate) fn write_file(path: &Path, bytes: &[u8], mode: FileMode) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    apply_file_mode(path, mode)
}

/// The mode half of [`write_file`], for a caller that wrote the bytes itself
/// (the stopped-op widen writes atomically).
pub(crate) use scl_vfs::apply_file_mode;

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
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
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
    walk_entries_with_perms_sparse(store, root, String::new(), sparse, &mut out, false)?;
    Ok(out)
}

/// [`tree_file_entries_with_perms_sparse`] that skips a tree the store lacks
/// instead of failing. For a parent read only as a fallback on a partial clone
/// (ADR-0049 merge completion): a subtree it does not hold lies where the
/// decided root already decided, and is never the only record of a path.
pub(crate) fn tree_file_entries_with_perms_sparse_present(
    store: &mut Store,
    root: ObjectId,
    sparse: &Sparse,
) -> Result<BTreeMap<String, (ObjectId, FileMode, u8)>> {
    let mut out = BTreeMap::new();
    if store.contains(&root) {
        walk_entries_with_perms_sparse(store, root, String::new(), sparse, &mut out, true)?;
    }
    Ok(out)
}

fn walk_entries_with_perms_sparse(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    sparse: &Sparse,
    out: &mut BTreeMap<String, (ObjectId, FileMode, u8)>,
    skip_absent: bool,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        match e.kind {
            EntryKind::Blob => {
                if sparse.matches(&path) {
                    out.insert(path, (e.id, e.mode, e.perms));
                }
            }
            EntryKind::Tree => {
                if sparse.should_descend(&path) && (!skip_absent || store.contains(&e.id)) {
                    walk_entries_with_perms_sparse(store, e.id, path, sparse, out, skip_absent)?;
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
    promisor: &crate::promisor::Promisor,
    prefix: &str,
) -> Result<ObjectId> {
    if built_id == parent_id {
        // Nothing under this subtree changed at all — already identical,
        // no need to read either side.
        return Ok(built_id);
    }
    let built_tree: Tree = store.get_tree(&built_id)?;
    let parent_tree: Tree = store.get_tree(&parent_id)?;
    let parent_names: BTreeSet<String> =
        parent_tree.entries.iter().map(|e| e.name.clone()).collect();
    // P27 Task 5 review Critical fix: a built-side entry whose name the
    // parent tree has NO entry for at all (so the loop below never visits
    // it) can still sit at a fully out-of-filter path — e.g. a brand-new
    // top-level directory this partial clone never fetched anything under.
    // The I1 check inside the loop below only fires when the parent
    // already has a same-name entry there; this closes that gap by
    // scanning the built side for any survivor once up front, against the
    // UNION of the promisor filter and the sparse view (ADR-0048): the
    // filter records what a clone asked for, and a widened view can reach
    // paths the filter does not, so a path is refused only if it lies
    // outside both. (Before widening existed `sparse` was never wider than
    // the filter, so nothing is newly refused.) Refuse loudly rather than let it land in the
    // new root, where `sc gc` would classify it as an unreachable gap and
    // prune it — even though it's genuinely reachable and the origin never
    // had it (P27 Task 5 review Critical).
    for e in &built_tree.entries {
        if parent_names.contains(&e.name) {
            continue;
        }
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        if !promisor.should_descend(&path) && !sparse.should_descend(&path) {
            return Err(Error::GappedPathContent(path));
        }
    }

    let mut by_name: BTreeMap<String, scl_core::TreeEntry> = built_tree
        .entries
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();

    for pe in parent_tree.entries {
        let path = if prefix.is_empty() {
            pe.name.clone()
        } else {
            format!("{prefix}/{}", pe.name)
        };
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
            // A file where the sparse spec expects a descendable directory
            // (a merge can swap a directory for a file, ADR-0049). A file
            // that does not match the view is out of it, so it is grafted by
            // id like any other out-of-sparse entry; dropping it would lose
            // the path. When the built side already holds the name (a file
            // replaced by a directory, or rewritten in place) it decided
            // that path, so it stays.
            by_name.entry(pe.name.clone()).or_insert(pe);
            continue;
        }
        let child_built_id = match by_name.get(&pe.name) {
            Some(be) if be.kind == EntryKind::Tree => be.id,
            _ => store.put(Object::Tree(Tree::default()))?,
        };
        let merged_child =
            graft_out_of_sparse(store, child_built_id, pe.id, sparse, promisor, &path)?;
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
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        match e.kind {
            EntryKind::Blob => {
                out.insert(path, (e.id, e.mode, e.perms));
            }
            EntryKind::Tree => walk_entries_with_perms(store, e.id, path, out)?,
        }
    }
    Ok(())
}

/// The file entry at `path` under `root`, found by descending its components
/// instead of flattening the tree (ADR-0049 decision 8). `Ok(None)` means the
/// path is not in the tree. A tree on the way that this store lacks is never
/// read as absence: on a partial clone it is the gap error naming `path`, on a
/// full clone the plain not-found, so a gap cannot pass for a deletion.
/// A path that names a directory is also `None`: callers ask for files.
pub(crate) fn tree_entry_at(
    store: &mut Store,
    root: ObjectId,
    path: &str,
    partial: bool,
) -> Result<Option<(ObjectId, FileMode, u8)>> {
    let comps: Vec<&str> = path.split('/').collect();
    let mut cur = root;
    for (i, comp) in comps.iter().enumerate() {
        if !store.contains(&cur) {
            return Err(if partial {
                crate::promisor::partial_gap_hint(path)
            } else {
                scl_core::Error::NotFound(cur).into()
            });
        }
        let tree: Tree = store.get_tree(&cur)?;
        let Some(e) = tree.get(comp) else {
            return Ok(None);
        };
        let last = i + 1 == comps.len();
        match (e.kind, last) {
            (EntryKind::Blob, true) => return Ok(Some((e.id, e.mode, e.perms))),
            (EntryKind::Tree, false) => cur = e.id,
            _ => return Ok(None),
        }
    }
    Ok(None)
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
    walk_tree_sparse(store, root, String::new(), sparse, &mut out, false)?;
    Ok(out)
}

/// Like [`tree_file_ids_sparse`], but skips a subtree the store lacks instead
/// of failing. For `materialize`'s old-root removal walk on a partial clone:
/// the old root was laid out under a preflighted view, so an absent subtree
/// lay outside that view and has nothing on disk to remove. A fetch can leave
/// a tree absent that is inside the promisor filter but outside the view
/// (ADR-0048).
fn tree_file_ids_sparse_present(
    store: &mut Store,
    root: ObjectId,
    sparse: &Sparse,
) -> Result<BTreeMap<String, ObjectId>> {
    let mut out = BTreeMap::new();
    if store.contains(&root) {
        walk_tree_sparse(store, root, String::new(), sparse, &mut out, true)?;
    }
    Ok(out)
}

fn walk_tree_sparse(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    sparse: &Sparse,
    out: &mut BTreeMap<String, ObjectId>,
    skip_absent: bool,
) -> Result<()> {
    let tree: Tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        match e.kind {
            EntryKind::Blob => {
                if sparse.matches(&path) {
                    out.insert(path, e.id);
                }
            }
            EntryKind::Tree => {
                if sparse.should_descend(&path) && (!skip_absent || store.contains(&e.id)) {
                    walk_tree_sparse(store, e.id, path, sparse, out, skip_absent)?;
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
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
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
/// - present on disk, format dispatches on the `RANDOMIZED` bit (P33):
///   - clear (convergent/legacy) => re-encrypt the disk bytes convergently
///     (`encrypt_path` is a pure, keyless function) and compare the
///     resulting ciphertext blob id to the stored one: equal => CLEAN,
///     different => MODIFIED (a genuine edit). Unchanged from pre-P33.
///   - set (randomized) => re-encryption proves nothing (a fresh seal never
///     matches the old ciphertext even for identical plaintext), so the only
///     public-key-free unchanged proof is the local stat cache
///     (`cache::unchanged`, Task 3): a hit reports CLEAN, a miss/disagreement
///     reports MODIFIED — spurious-but-safe, never incorrect.
///
/// Non-protected paths use the usual plaintext-blob-id comparison.
///
/// Sparse-aware: a HEAD path outside `sparse` is never materialized (see
/// `materialize`), so it's also expected-absent — same "absent => CLEAN, not
/// a user deletion" treatment as an unauthorized protected file. Without this,
/// `sc status`/the dirty-tree checks in `switch`/`merge`/`rebase` would read
/// every out-of-sparse path as a deletion and permanently block those
/// operations once a sparse spec is set.
///
/// Gap-tolerant on a partial clone (P27 Task 5, T5-I3): flattens HEAD's tree
/// with [`tree_file_entries_with_perms_sparse`] instead of the unfiltered
/// walker, mirroring `materialize`'s existing choice. On a full (non-partial)
/// repo this is byte-for-byte identical to the old unfiltered walk whenever
/// `sparse` is full (the sparse-aware flattener falls back to the unfiltered
/// one in that case) — the only behavior change is that an out-of-`sparse`
/// path is now never fetched from the store at all, instead of being fetched
/// and then filtered out by the loop below. On a partial clone this walk never
/// touches an object outside the view, so a gapped out-of-view path is
/// expected-absent, not a deletion. (A lazy clone's view may extend past its
/// promisor filter; the filled closure under the view is present.)
pub(crate) fn diff_worktree(
    layout: &Layout,
    store: &mut Store,
    head_root: Option<ObjectId>,
    // Per-entry `PROTECTED` perms (read from the HEAD tree) are the authoritative
    // signal; the policy is taken explicitly so callers thread it consistently and
    // a future richer diff (e.g. prefix-aware reporting) needs no signature change.
    _protection: &Protection,
    sparse: &Sparse,
    cache: Option<&ProtectedCache>,
) -> Result<Diff> {
    let head = match head_root {
        Some(root) => tree_file_entries_with_perms_sparse(store, root, sparse)?,
        None => BTreeMap::new(),
    };
    let tracked: BTreeSet<String> = head.keys().cloned().collect();
    let wt: BTreeMap<String, Vec<u8>> = read_worktree(layout, &tracked)?
        .into_iter()
        .map(|(p, b, _)| (p, b))
        .collect();
    let mut diff = Diff::default();
    for (p, bytes) in &wt {
        match head.get(p) {
            None => diff.added.push(p.clone()),
            Some((hid, _mode, perms)) => {
                let disk_id = if perms & PROTECTED != 0 {
                    if perms & scl_core::RANDOMIZED == 0 {
                        // Convergent (legacy) entry: re-encryption yields the same
                        // id as the commit did — still exact, no cache needed.
                        Object::blob(scl_crypto::encrypt_path(bytes).0).id()
                    } else {
                        // Randomized entry (P33): re-encrypting proves nothing. The
                        // stat cache (stat hit, then keyed-tag fallback) is the only
                        // public-key-free unchanged proof; a missing entry reports
                        // modified — spurious-but-safe, never incorrect. The cache
                        // resolves the abs stat path against its own checkout root.
                        match cache.and_then(|c| c.unchanged(p, bytes)) {
                            Some(id) => id,
                            None => {
                                diff.modified.push(p.clone());
                                continue;
                            }
                        }
                    }
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
            return Err(crate::error::Error::BadRef(format!(
                "unsafe path in tree: {rel}"
            )));
        }
    }
    Ok(root.join(rel))
}

/// Check, before anything is written, that every object the sparse view needs
/// under `root` is in the store (ADR-0048, the view closure obligation). Only a
/// partial clone can have such a gap, so a full clone returns immediately and
/// keeps its existing behavior. On a gap this fails with
/// [`Error::GapInView`], naming the path and the filter prefix `sc backfill`
/// can repair, instead of the raw `NotFound` the write loop would raise after
/// it had already rewritten part of the working tree. No network: filling the
/// gap on a lazy clone is a separate, later step.
pub(crate) fn preflight_view(
    layout: &Layout,
    store: &mut Store,
    root: ObjectId,
    sparse: &Sparse,
) -> Result<()> {
    let Some(promisor) = crate::promisor::load(layout)? else {
        return Ok(());
    };
    let gap = |path: &str| {
        // With a blob limit the missing object is a file, and `sc backfill`
        // repairs it by its own path rather than a covering prefix (ADR-0055).
        // The limit is the cause only for a path in the clone's scope; a path
        // outside it (a view widened past the filter) was left out by the filter.
        let sized = promisor.blob_limit().filter(|_| promisor.matches(path));
        let prefix = if sized.is_some() && !path.is_empty() {
            path.to_string()
        } else {
            promisor
                .prefixes()
                .iter()
                .find(|p| {
                    let bare = p.trim_end_matches('/');
                    path == bare || path.starts_with(&format!("{bare}/"))
                })
                .cloned()
                // Outside the filter (a view widened past it): name the path
                // itself, which `sc backfill` accepts as a prefix. For the root
                // tree there is no path, so fall back to the first filter prefix.
                .or_else(|| (!path.is_empty()).then(|| path.to_string()))
                .or_else(|| promisor.prefixes().first().cloned())
                .unwrap_or_default()
        };
        Error::GapInView {
            path: if path.is_empty() {
                "(root tree)".to_string()
            } else {
                path.to_string()
            },
            prefix,
            blob_limit: sized,
        }
    };
    if !store.contains(&root) {
        return Err(gap(""));
    }
    let mut stack = vec![(root, String::new())];
    while let Some((tree_id, path)) = stack.pop() {
        let tree: Tree = store.get_tree(&tree_id)?;
        for e in tree.entries {
            let child = if path.is_empty() {
                e.name.clone()
            } else {
                format!("{path}/{}", e.name)
            };
            match e.kind {
                EntryKind::Blob => {
                    if sparse.matches(&child) && !store.contains(&e.id) {
                        return Err(gap(&child));
                    }
                }
                EntryKind::Tree => {
                    if sparse.should_descend(&child) {
                        if !store.contains(&e.id) {
                            return Err(gap(&child));
                        }
                        stack.push((e.id, child));
                    }
                }
            }
        }
    }
    Ok(())
}

/// `(plain files with blob id and mode, protected paths)` a widened view adds.
type AddedViewFiles = (Vec<(String, ObjectId, FileMode)>, Vec<String>);

/// The plain (unprotected) files a widened view (`new`, which covers `old`)
/// brings in from `root`, with blob ids and modes: what [`lay_out_added_view`]
/// writes. Protected entries are returned apart, as `(plain, protected)`.
pub(crate) fn added_view_files(
    store: &mut Store,
    root: ObjectId,
    old: &Sparse,
    new: &Sparse,
) -> Result<AddedViewFiles> {
    let (mut plain, mut protected) = (Vec::new(), Vec::new());
    for (path, (blob_id, mode, perms)) in tree_file_entries_with_perms_sparse(store, root, new)? {
        if old.matches(&path) {
            continue;
        }
        if perms & PROTECTED != 0 {
            protected.push(path);
        } else {
            plain.push((path, blob_id, mode));
        }
    }
    Ok((plain, protected))
}

/// Of `paths`, those that exist in the tree at `root` as plain files and whose
/// file on disk has exactly the blob's bytes: what an interrupted widen wrote
/// and nobody changed since. A file that merely has the same bytes but was
/// never recorded is the user's, which is why callers pass only recorded paths.
pub(crate) fn recorded_paths_laid(
    layout: &Layout,
    store: &mut Store,
    root: ObjectId,
    paths: &std::collections::BTreeSet<String>,
) -> Result<std::collections::BTreeSet<String>> {
    let partial = crate::promisor::load(layout)?.is_some();
    let mut laid = std::collections::BTreeSet::new();
    for path in paths {
        // A lookup that fails (a gap) reads as "not laid".
        let Ok(Some((blob_id, _, perms))) = tree_entry_at(store, root, path, partial) else {
            continue;
        };
        if perms & PROTECTED != 0 {
            continue;
        }
        let Ok(Object::Blob(bytes)) = store.get(&blob_id) else {
            continue;
        };
        let full = safe_join(&layout.root, path)?;
        // A symlink is never ours, and a read error reads as "not laid".
        let is_file = full.symlink_metadata().is_ok_and(|m| m.is_file());
        if is_file && std::fs::read(&full).is_ok_and(|disk| disk[..] == bytes[..]) {
            laid.insert(path.clone());
        }
    }
    Ok(laid)
}

/// Of the paths an interrupted widen recorded (`recorded`), those the widen
/// from `old` to `new` would write that are already on disk with the decided
/// root's bytes: the widen's own earlier writes.
pub(crate) fn added_view_already_laid(
    layout: &Layout,
    store: &mut Store,
    root: ObjectId,
    old: &Sparse,
    new: &Sparse,
    recorded: &std::collections::BTreeSet<String>,
) -> Result<std::collections::BTreeSet<String>> {
    let added: std::collections::BTreeSet<String> = added_view_files(store, root, old, new)?
        .0
        .into_iter()
        .map(|(p, ..)| p)
        .filter(|p| recorded.contains(p))
        .collect();
    recorded_paths_laid(layout, store, root, &added)
}

/// Lay out the files that a widened view (`new`, which covers `old`) brings
/// in from `root`, and nothing else: no removal pass, and no rewrite of a path
/// `old` already laid out (it may hold conflict markers or the user's
/// resolution). A protected entry is not decrypted: it is left absent and
/// returned, since the caller has no wrap map for `root`. Each file is written
/// atomically, so an interruption never leaves a half-written one.
pub(crate) fn lay_out_added_view(
    layout: &Layout,
    store: &mut Store,
    root: ObjectId,
    old: &Sparse,
    new: &Sparse,
) -> Result<Vec<String>> {
    let (plain, protected) = added_view_files(store, root, old, new)?;
    for (path, blob_id, mode) in plain {
        let Object::Blob(bytes) = store.get(&blob_id)? else {
            continue;
        };
        let full = safe_join(&layout.root, &path)?;
        clear_dir_obstruction(&full, &path)?;
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        scl_core::fsutil::atomic_write_durable(&full, &bytes[..])?;
        apply_file_mode(&full, mode)?;
    }
    Ok(protected)
}

/// Make room for a file at `full` (tracked path `path`) where a directory
/// stands: the removal pass has deleted the tracked files under it, so what is
/// left is a husk of empty directories, which goes. A directory that still
/// holds anything (an untracked or ignored file of the user's) is never
/// touched: the error names it, and the caller's state stays retryable (#247).
pub(crate) fn clear_dir_obstruction(full: &Path, path: &str) -> Result<()> {
    // Bottom-up `remove_dir`, never `remove_dir_all`: a file created after the
    // check makes a directory non-empty and the removal fail, not vanish.
    fn prune(dir: &Path) -> std::io::Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            // A child swapped for a symlink since the check is never followed.
            if !e.file_type()?.is_dir() {
                return Err(std::io::ErrorKind::DirectoryNotEmpty.into());
            }
            prune(&e.path())?;
        }
        std::fs::remove_dir(dir)
    }
    let is_dir = full.symlink_metadata().is_ok_and(|m| m.is_dir());
    // Empty directories go whoever made them: they hold nothing to lose. (A
    // forward op refuses a user's empty directory up front instead, because
    // before its removal pass it cannot tell one from a husk.)
    if is_dir && !(dir_clearable(full, path, &|_| false) && prune(full).is_ok()) {
        return Err(Error::InvalidArgument(format!(
            "cannot write {path}: a directory with untracked or ignored content stands there; \
             move it away, then retry"
        )));
    }
    Ok(())
}

/// Whether the directory `dir` (tracked path `rel`) holds only directories and
/// regular files that `removable` names, all the way down: no symlink, no
/// other file, no unreadable subdirectory, no name that is not UTF-8. Reads
/// only; `materialize` runs it for every directory a target file replaces
/// before its first removal, so a refusal leaves the working tree untouched.
fn dir_clearable(dir: &Path, rel: &str, removable: &dyn Fn(&str) -> bool) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.into_iter().all(|e| {
        let Ok(e) = e else { return false };
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            return false;
        };
        let child = format!("{rel}/{name}");
        match e.file_type() {
            Ok(t) if t.is_dir() => dir_clearable(&e.path(), &child, removable),
            Ok(t) if t.is_file() => removable(&child),
            _ => false,
        }
    })
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
///
/// Gap-tolerant on a partial clone (P27 Task 5): both the target walk and
/// the old-root removal walk are bounded so neither ever `store.get`s an
/// out-of-view (possibly never-fetched) object. The target walk is bounded by
/// `sparse`; the old-root walk by the spec the old root was laid out under
/// (see [`materialize_with_old_view`]), since narrowing is exactly the case
/// that needs to enumerate paths `sparse` no longer matches. Before the first
/// write, a partial clone's view closure is checked present (`preflight_view`).
pub(crate) fn materialize(
    layout: &Layout,
    store: &mut Store,
    target_root: ObjectId,
    old_root: Option<ObjectId>,
    protection: &Protection,
    identity: Option<&scl_crypto::SecretKey>,
    sparse: &Sparse,
    cache: Option<&mut ProtectedCache>,
) -> Result<Vec<String>> {
    materialize_with_old_view(
        layout,
        store,
        target_root,
        old_root,
        protection,
        identity,
        sparse,
        None,
        cache,
    )
}

/// [`materialize`] for a caller that is CHANGING the sparse spec (`sparse set`).
/// `old_view` is the spec that was in effect when `old_root` was laid out: the
/// removal walk is bounded by it, because everything on disk lies inside it
/// and nothing outside it was ever written. `None` means the spec is
/// unchanged, so `sparse` itself is the bound (ADR-0048; this replaces the
/// promisor-filter bound, which stops being a superset of the view once a lazy
/// clone can widen it past the filter).
#[allow(clippy::too_many_arguments)]
pub(crate) fn materialize_with_old_view(
    layout: &Layout,
    store: &mut Store,
    target_root: ObjectId,
    old_root: Option<ObjectId>,
    protection: &Protection,
    identity: Option<&scl_crypto::SecretKey>,
    sparse: &Sparse,
    old_view: Option<&Sparse>,
    mut cache: Option<&mut ProtectedCache>,
) -> Result<Vec<String>> {
    // Fail before the first write if the view's closure is not all present
    // (partial clones only; ADR-0048). The check lives here so every caller
    // is covered and none can forget it.
    preflight_view(layout, store, target_root, sparse)?;
    // With no old tree there is no removal pass, so an empty directory at a
    // target path is the user's, not a husk: leave it, and let the write fail.
    let clear = |full: &Path, path: &str| {
        if old_root.is_some() {
            clear_dir_obstruction(full, path)
        } else {
            Ok(())
        }
    };
    // Gap-tolerant when sparse is active (P27 Task 4): a promisor-filtered
    // clone never fetched out-of-filter subtrees at all, so an unfiltered
    // walk here would `NotFound` on them.
    let target = tree_file_entries_with_perms_sparse(store, target_root, sparse)?;
    // Set when an interrupted `sparse set`'s marker widened the removal bound;
    // cleared once this call has finished laying the tree out under `sparse`.
    let mut prev_marker_used = false;
    if let Some(old) = old_root {
        // The old-root removal walk: bounded by the spec the old root was
        // laid out under (`old_view`, or `sparse` itself when the spec is
        // unchanged), not by the promisor filter (ADR-0048). `old` is
        // enumerated to find paths that WERE materialized and might now need
        // removing, so the NEW, possibly narrower spec can't be the bound when
        // it changed: narrowing is exactly the case that needs to enumerate
        // paths it no longer matches. Everything on disk lies inside the old
        // view, and the walk skips subtrees the store lacks (they were outside
        // it, so nothing of them is on disk). A full (non-partial) repo keeps
        // the old unfiltered walk exactly (`Sparse::default()` falls back to
        // `tree_file_ids` inside `tree_file_ids_sparse`).
        let (old_walk_bound, partial) = match crate::promisor::load(layout)? {
            Some(_) => {
                let mut bound = old_view.unwrap_or(sparse).clone();
                // An interrupted `sparse set` left the replaced spec behind:
                // files laid out under it are still on disk.
                if let Some(prev) = crate::sparse::load_prev(layout)? {
                    bound = bound.union(&prev);
                    prev_marker_used = true;
                }
                (bound, true)
            }
            None => (Sparse::default(), false),
        };
        let old_files = if partial {
            tree_file_ids_sparse_present(store, old, &old_walk_bound)?
        } else {
            tree_file_ids_sparse(store, old, &old_walk_bound)?
        };
        let gone = |p: &str| !target.contains_key(p) || !sparse.matches(p);
        // Before the first removal: a directory a target file must replace
        // may hold only directories and files this pass is about to delete.
        // Anything else is the user's, and refusing now (rather than at the
        // write, after the pass and earlier writes) changes nothing (#247).
        for path in target.keys().filter(|p| sparse.matches(p)) {
            let full = safe_join(&layout.root, path)?;
            if full.symlink_metadata().is_ok_and(|m| m.is_dir())
                && !dir_clearable(&full, path, &|c| old_files.contains_key(c) && gone(c))
            {
                return Err(Error::InvalidArgument(format!(
                    "cannot write {path}: a directory with untracked or ignored content stands \
                     there; move it away, then retry"
                )));
            }
        }
        for p in old_files.keys() {
            if gone(p) {
                let full = safe_join(&layout.root, p)?;
                let _ = std::fs::remove_file(full);
            }
        }
    }
    let mut skipped = Vec::new();
    for (path, (blob_id, mode, perms)) in &target {
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
                    clear(&full, path)?;
                    if let Some(parent) = full.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    write_file(&full, &pt[..], *mode)?;
                    // Record a randomized entry's cache entry right after the
                    // write (P33): without this, the next `diff_worktree`/
                    // `status` on this exact, unmodified plaintext has no
                    // stat-hit or keyed-tag to match and spuriously reports
                    // it as modified — since re-encryption can't prove
                    // unchanged-ness for a randomized seal. Mirrors the
                    // record call `commit`'s carry/fresh-seal paths already
                    // make (`repo.rs`'s `snapshot_files`).
                    if perms & scl_core::RANDOMIZED != 0 {
                        if let Some(c) = cache.as_deref_mut() {
                            c.record(path, &pt, *blob_id);
                        }
                    }
                    // `pt` (Zeroizing<Vec<u8>>) is dropped and zeroed here.
                }
                None => {
                    // No identity or no matching key: skip without writing. Remove
                    // any pre-existing on-disk file at this path so stale plaintext
                    // can't linger when a path becomes protected across a switch for
                    // a non-recipient (confidentiality). A failed removal must
                    // surface — swallowing it leaves plaintext on disk.
                    clear(&full, path)?;
                    match std::fs::remove_file(&full) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                    skipped.push(path.clone());
                }
            }
        } else {
            clear(&full, path)?;
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)?;
            }
            write_file(&full, &bytes[..], *mode)?;
        }
    }
    // The removal walk above covered the replaced view, and the tree is now
    // laid out under `sparse`: the marker has done its job. Leaving it would
    // widen every later removal walk and delete files the user created
    // outside the view.
    if prev_marker_used {
        crate::sparse::clear_prev(layout)?;
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
        let root = std::env::temp_dir().join(format!("scl-repo-wt-ignore-{}", std::process::id()));
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

        let result = materialize(
            &layout,
            &mut store,
            root_tree,
            None,
            &Default::default(),
            None,
            &Sparse::default(),
            None,
        );

        // Restore perms before asserting so cleanup always works.
        std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            result.is_err(),
            "swallowing a failed stale-plaintext removal leaks plaintext"
        );
        assert!(vault.join("secret.txt").exists());

        drop(store);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    /// A merge can swap a directory for a file. When the file lies outside a
    /// view whose prefixes sit below it, the graft must carry it by id, not
    /// skip it as a malformed ancestor (ADR-0049 decision 8).
    #[test]
    fn graft_carries_an_out_of_view_file_standing_where_a_directory_was() {
        let (layout, mut store) = tmp_objects("graft-dir-to-file");
        let file = |store: &mut Store, name: &str, bytes: &[u8]| TreeEntry {
            name: name.into(),
            kind: EntryKind::Blob,
            id: store.put(Object::blob(bytes.to_vec())).unwrap(),
            mode: FileMode::FILE,
            perms: 0,
        };
        let other = file(&mut store, "other.txt", b"o");
        // The decided tree replaced directory `src/` with the file `src`.
        let src_file = file(&mut store, "src", b"now a file");
        let parent = store
            .put(Object::Tree(Tree::new(vec![
                other.clone(),
                src_file.clone(),
            ])))
            .unwrap();
        // The built side comes from the view: only `other.txt` survives.
        let built = store
            .put(Object::Tree(Tree::new(vec![other.clone()])))
            .unwrap();
        let sparse = Sparse::new(vec!["src/a.txt".into(), "other.txt".into()]);
        let promisor = crate::promisor::Promisor::new("origin", vec!["src/a.txt".into()]);
        let out = graft_out_of_sparse(&mut store, built, parent, &sparse, &promisor, "").unwrap();
        let tree = store.get_tree(&out).unwrap();
        assert_eq!(tree.get("src").map(|e| e.id), Some(src_file.id));
        assert_eq!(tree.get("other.txt").map(|e| e.id), Some(other.id));
        let _ = std::fs::remove_dir_all(&layout.root);
    }

    /// A single-tip commit that replaces the file `src` with a directory
    /// holding an in-view file: the built side decided that path, so the
    /// graft keeps it and does not resurrect the old file or refuse.
    #[test]
    fn graft_keeps_a_directory_the_built_side_put_where_a_file_was() {
        let (layout, mut store) = tmp_objects("graft-file-to-dir");
        let blob =
            |store: &mut Store, bytes: &[u8]| store.put(Object::blob(bytes.to_vec())).unwrap();
        let old_file = blob(&mut store, b"was a file");
        let a = blob(&mut store, b"a");
        let parent = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "src".into(),
                kind: EntryKind::Blob,
                id: old_file,
                mode: FileMode::FILE,
                perms: 0,
            }])))
            .unwrap();
        let dir = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "a.txt".into(),
                kind: EntryKind::Blob,
                id: a,
                mode: FileMode::FILE,
                perms: 0,
            }])))
            .unwrap();
        let built = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "src".into(),
                kind: EntryKind::Tree,
                id: dir,
                mode: FileMode(0o755),
                perms: 0,
            }])))
            .unwrap();
        let sparse = Sparse::new(vec!["src/a.txt".into()]);
        let promisor = crate::promisor::Promisor::new("origin", vec!["src/".into()]);
        let out = graft_out_of_sparse(&mut store, built, parent, &sparse, &promisor, "").unwrap();
        assert_eq!(out, built, "the built directory stays");
        let _ = std::fs::remove_dir_all(&layout.root);
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

        let err = materialize(
            &layout,
            &mut store,
            evil_tree,
            None,
            &Default::default(),
            None,
            &Sparse::default(),
            None,
        )
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
        assert!(materialize(
            &layout,
            &mut store,
            snap_root,
            None,
            &Default::default(),
            None,
            &Sparse::default(),
            None
        )
        .is_err());

        drop(store);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn diff_dispatches_randomized_entries_through_the_cache() {
        let (layout, mut store) = tmp_objects("p33-diff");
        // Build a HEAD tree with one RANDOMIZED protected entry whose plaintext
        // sits on disk, exactly as an authorized checkout leaves it.
        let pt = b"top secret".to_vec();
        let (cipher, _dek) = scl_crypto::encrypt_path_randomized(&pt);
        let blob = Object::blob(cipher.clone());
        let blob_id = blob.id();
        store.put(blob).unwrap();
        let inner = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "x".into(),
                kind: EntryKind::Blob,
                id: blob_id,
                mode: FileMode::FILE,
                perms: PROTECTED | scl_core::RANDOMIZED,
            }])))
            .unwrap();
        let root = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "secret".into(),
                kind: EntryKind::Tree,
                id: inner,
                mode: FileMode::FILE,
                perms: 0,
            }])))
            .unwrap();

        let abs = layout.root.join("secret/x");
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, &pt).unwrap();

        let key = crate::cache::local_key(&layout).unwrap();
        let mut cache = crate::cache::ProtectedCache::open(key, layout.root.clone(), None);

        // No cache entry: spurious-but-safe MODIFIED.
        let d = diff_worktree(
            &layout,
            &mut store,
            Some(root),
            &Protection::default(),
            &Sparse::default(),
            Some(&cache),
        )
        .unwrap();
        assert_eq!(d.modified, vec!["secret/x"]);

        // Recorded: provably clean.
        cache.record("secret/x", &pt, blob_id);
        let d = diff_worktree(
            &layout,
            &mut store,
            Some(root),
            &Protection::default(),
            &Sparse::default(),
            Some(&cache),
        )
        .unwrap();
        assert!(d.modified.is_empty() && d.added.is_empty() && d.deleted.is_empty());

        // Genuine edit: modified again (tag mismatch).
        std::fs::write(&abs, b"edited").unwrap();
        let d = diff_worktree(
            &layout,
            &mut store,
            Some(root),
            &Protection::default(),
            &Sparse::default(),
            Some(&cache),
        )
        .unwrap();
        assert_eq!(d.modified, vec!["secret/x"]);

        drop(store);
        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    #[test]
    fn materialize_populates_the_cache_for_decrypted_files() {
        // P33 Task 7 Step 1 pin: materializing a RANDOMIZED protected entry
        // for an authorized identity must record the decrypted plaintext into
        // the threaded cache, so the very next `unchanged` on the untouched
        // on-disk plaintext proves it clean (a randomized seal can't be proven
        // unchanged by re-encrypting).
        let (layout, mut store) = tmp_objects("p33-mat-cache");
        let (sk, pk) = scl_crypto::generate_keypair();
        let pt = b"top secret".to_vec();
        let (cipher, dek) = scl_crypto::encrypt_path_randomized(&pt);
        let blob = Object::blob(cipher);
        let blob_id = blob.id();
        store.put(blob).unwrap();
        let inner = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "x".into(),
                kind: EntryKind::Blob,
                id: blob_id,
                mode: FileMode::FILE,
                perms: PROTECTED | scl_core::RANDOMIZED,
            }])))
            .unwrap();
        let root = store
            .put(Object::Tree(Tree::new(vec![TreeEntry {
                name: "secret".into(),
                kind: EntryKind::Tree,
                id: inner,
                mode: FileMode::FILE,
                perms: 0,
            }])))
            .unwrap();

        let mut wrapped = BTreeMap::new();
        wrapped.insert(blob_id, vec![scl_crypto::wrap_dek_for(&dek, &pk)]);
        let prot = Protection {
            prefixes: Vec::new(),
            wrapped,
        };

        let key = crate::cache::local_key(&layout).unwrap();
        let mut cache = crate::cache::ProtectedCache::open(key, layout.root.clone(), None);
        let skipped = materialize(
            &layout,
            &mut store,
            root,
            None,
            &prot,
            Some(&sk),
            &Sparse::default(),
            Some(&mut cache),
        )
        .unwrap();
        assert!(
            skipped.is_empty(),
            "authorized identity decrypts, nothing skipped"
        );
        assert_eq!(
            std::fs::read(layout.root.join("secret/x")).unwrap(),
            pt,
            "plaintext materialized on disk"
        );
        // The cache now proves the untouched plaintext unchanged.
        assert_eq!(cache.unchanged("secret/x", &pt), Some(blob_id));

        drop(store);
        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    /// The paths-only walk lists exactly what the reading walk returns, honoring
    /// `.scignore` and the tracked-path exemption, without reading file bytes.
    #[test]
    fn list_worktree_paths_matches_read_worktree() {
        let root = std::env::temp_dir().join(format!("scl-listpaths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".sc")).unwrap();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::create_dir_all(root.join("ignored")).unwrap();
        std::fs::write(root.join(".scignore"), "ignored/\n*.tmp\n").unwrap();
        std::fs::write(root.join("a/b/f.txt"), b"1").unwrap();
        std::fs::write(root.join("a/skip.tmp"), b"2").unwrap();
        std::fs::write(root.join("ignored/keep.txt"), b"3").unwrap();
        std::fs::write(root.join("ignored/drop.txt"), b"4").unwrap();
        std::fs::write(root.join("top.txt"), b"5").unwrap();
        let layout = Layout::at(&root);
        // A tracked path under an ignored directory is still listed.
        let tracked: BTreeSet<String> = ["ignored/keep.txt".to_string()].into();
        let listed = list_worktree_paths(&layout, &tracked).unwrap();
        let read: Vec<String> = read_worktree(&layout, &tracked)
            .unwrap()
            .into_iter()
            .map(|(p, _, _)| p)
            .collect();
        assert_eq!(listed, read);
        assert!(listed.contains(&"ignored/keep.txt".to_string()));
        assert!(!listed.contains(&"ignored/drop.txt".to_string()));
        assert!(!listed.contains(&"a/skip.tmp".to_string()));
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// setuid/setgid/sticky never survive a write (git recreates files and
    /// carries none over): a pre-existing 02644 file must not become 02755.
    #[cfg(unix)]
    #[test]
    fn write_file_clears_special_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("scl-repo-wt-special-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        for (want, expect) in [(FileMode::EXEC, 0o755), (FileMode::FILE, 0o644)] {
            std::fs::write(&f, b"x").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o2644)).unwrap();
            if mode(&f) & 0o2000 == 0 {
                continue; // filesystem drops the bit: nothing to test
            }
            write_file(&f, b"y", want).unwrap();
            assert_eq!(mode(&f), expect);
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }
}
