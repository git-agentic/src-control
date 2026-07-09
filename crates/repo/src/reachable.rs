//! Reachability over the object graph: every object id reachable from a set of
//! snapshot tips. Parameterized by an `ObjectSource` so it walks either the
//! local `Store` (push) or a remote `Transport` (clone/fetch). Reused by P8 gc.

use std::collections::{BTreeSet, HashSet, VecDeque};

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
    Ok(reachable_objects_filtered(src, tips, None)?.included)
}

/// Walk `root` and every subtree it reaches, recording trees and blobs in
/// `seen`. Uses an explicit stack rather than recursion so a deeply-nested
/// (possibly hostile) remote tree can't overflow the call stack. `pub(crate)`
/// so gc can protect an in-progress merge's decided carried tree
/// (`MERGE_DECIDED_ROOT`), which is a TREE root, not a snapshot. Unfiltered:
/// thin wrapper over [`walk_tree_filtered`] with `filter = None`.
pub(crate) fn walk_tree(src: &mut impl ObjectSource, root: ObjectId, seen: &mut BTreeSet<ObjectId>) -> Result<()> {
    let mut gaps = BTreeSet::new();
    // `filter = None` never consults `expanded` (see the bare-id gate below),
    // so a throwaway empty set is correct and harmless here.
    let mut expanded = HashSet::new();
    walk_tree_filtered(src, root, seen, &mut gaps, None, &mut expanded)
}

/// Like [`walk_tree`], but tolerant of an absent child: a missing tree or
/// blob id is simply not inserted into `seen` and not descended into,
/// instead of erroring (P27 final review I1). Used only by gc's
/// defense-in-depth walk-in of a PRESENT gap-frontier tree
/// (`gc.rs::run`): `ingest_pack_file`'s write pass is not all-or-nothing,
/// so a crash-interrupted `sc backfill` (Ctrl-C, power loss) can leave a
/// gap-frontier tree present locally while one of its children never
/// landed. The strict [`walk_tree`] would `get()` that missing child and
/// hard-error, bricking `sc gc` on a partial clone — which this walk-in
/// exists specifically to prevent. Presence is also checked BEFORE
/// inserting an id into `seen` (not just before recursing into it):
/// `gc::run`'s next step, `Store::write_pack`, `get()`s every id in the
/// reachable set it's handed, so an absent id smuggled into `seen` here
/// would just move the same hard error one step later. A present child
/// below an absent one is intentionally NOT reached (matches the
/// documented nuance that gc only protects content connected to the local
/// graph — see ADR-0037's gc section). Takes `&mut Store` directly (not
/// the generic `ObjectSource`) since gc always walks the local store.
pub(crate) fn walk_tree_present_only(store: &mut Store, root: ObjectId, seen: &mut BTreeSet<ObjectId>) -> Result<()> {
    if !store.contains(&root) || !seen.insert(root) {
        return Ok(());
    }
    let mut stack = vec![root];
    while let Some(tree_id) = stack.pop() {
        let tree = match Store::get(store, &tree_id)? {
            Object::Tree(t) => t,
            _ => return Err(Error::BadRef(format!("expected tree {tree_id}"))),
        };
        for e in tree.entries {
            if !store.contains(&e.id) {
                continue;
            }
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

/// The prefix predicate a filtered reachability/tree walk needs. Implemented
/// by [`crate::promisor::Promisor`] (P27 Task 1); `crate::sparse::Sparse`
/// could implement it too, but that wiring is not required by this task. A
/// trait (rather than taking `&Promisor` directly) keeps this module from
/// depending on promisor internals — reachable.rs is reused by both gc (P8)
/// and the transport layer, neither of which should need to know about
/// partial-clone bookkeeping.
pub trait PrefixFilter {
    /// Whether `path` is itself in-filter (its blob/tree should be included).
    fn matches(&self, path: &str) -> bool;
    /// Whether a tree walk should descend into `path` at all (in-filter, or
    /// an ancestor of an in-filter prefix). The empty root path always
    /// descends.
    fn should_descend(&self, path: &str) -> bool;
}

impl PrefixFilter for crate::promisor::Promisor {
    fn matches(&self, path: &str) -> bool {
        crate::promisor::Promisor::matches(self, path)
    }
    fn should_descend(&self, path: &str) -> bool {
        crate::promisor::Promisor::should_descend(self, path)
    }
}

/// The result of a filtered reachability walk: `included` are the object ids
/// actually fetched/kept; `gaps` are ids referenced by an included parent
/// tree but excluded by the filter — never `get()`'d, so they may be absent
/// on a partial-clone source without error. `included` and `gaps` are
/// disjoint by construction: content addressing can dedup one id to two
/// different paths (a byte-identical subtree reachable at both an in-filter
/// and an out-of-filter path), so an id that is in-filter anywhere always
/// wins and is scrubbed out of `gaps` before returning — `gaps` means
/// "referenced but never held," never "held AND gapped."
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reachable {
    pub included: BTreeSet<ObjectId>,
    pub gaps: BTreeSet<ObjectId>,
}

/// Like [`reachable_objects`], but when a filter is given, prune out-of-filter
/// subtrees/blobs from the walk: a parent tree is always included (its
/// structure + child ids), but an out-of-filter child is neither recursed
/// into nor included — its id is recorded in `gaps` instead. The snapshot
/// walk (parents, secrets, root) is unchanged in either mode; only tree
/// descent is filtered. `filter = None` reproduces `reachable_objects`
/// byte-for-byte (empty `gaps`) — `reachable_objects` is defined in terms of
/// this function precisely to keep that guarantee structural, not just
/// tested.
pub fn reachable_objects_filtered(
    src: &mut impl ObjectSource,
    tips: &[ObjectId],
    filter: Option<&dyn PrefixFilter>,
) -> Result<Reachable> {
    let mut included = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    let mut snapshots: VecDeque<ObjectId> = VecDeque::new();
    for t in tips {
        if included.insert(*t) {
            snapshots.push_back(*t);
        }
    }
    // (id, path) pairs already pushed for expansion, under a filter only.
    // Hoisted to span EVERY snapshot's walk in this call (not just one), so
    // a later snapshot whose ROOT tree dedups to an already-expanded
    // subtree from an earlier snapshot's walk still gets its own root
    // expanded at its own (root, "") path — see `walk_tree_filtered`'s doc
    // comment for why a bare-id gate on the root is wrong under a filter
    // (C1, P27 final review).
    let mut expanded: HashSet<(ObjectId, String)> = HashSet::new();
    while let Some(sid) = snapshots.pop_front() {
        let snap = match src.get(&sid)? {
            Object::Snapshot(s) => s,
            _ => return Err(Error::BadRef(format!("expected snapshot {sid}"))),
        };
        for p in &snap.parents {
            if included.insert(*p) {
                snapshots.push_back(*p);
            }
        }
        for id in snap.secrets.values() {
            included.insert(*id);
        }
        walk_tree_filtered(src, snap.root, &mut included, &mut gaps, filter, &mut expanded)?;
    }
    // A byte-identical subtree can be gapped at one path and included at
    // another (same id, different filter verdict per path) — included
    // always wins. See the disjointness note on `Reachable`.
    gaps.retain(|id| !included.contains(id));
    Ok(Reachable { included, gaps })
}

/// Path-tracking tree descent shared by [`walk_tree`] (filter = None) and
/// [`reachable_objects_filtered`]. Stack items are `(tree_id, path)`, the
/// snapshot root at path `""`. For each entry, `child_path` is `name` at the
/// root or `"{path}/{name}"` beneath it. With no filter, every entry is
/// included and every subtree recursed into (today's behavior, unchanged).
/// With a filter: a blob is included iff `filter.matches(child_path)`,
/// otherwise its id goes to `gaps`; a tree is included + pushed for descent
/// iff `filter.should_descend(child_path)`, otherwise its id goes to `gaps`
/// — referenced by the parent, but never fetched. This is why an
/// out-of-filter id never triggers `NotFound` on a source that's missing
/// it: gaps are collected by id straight from the parent's `TreeEntry`,
/// never passed to `src.get()`. An in-filter id that's absent on `src` WILL
/// be `get()`'d and surfaces as a genuine error — that is the correct,
/// desired corruption signal.
///
/// Expansion dedup is filter-mode-dependent. With `filter = None`, a
/// bare-id gate on `included` is correct and cheapest: verdicts don't
/// depend on path, so a shared subtree only ever needs expanding once.
/// Under a filter, verdicts ARE per-path (`should_descend`/`matches` take
/// `child_path`), but content addressing can still dedup a byte-identical
/// subtree to one id reachable at two different paths with two different
/// verdicts. Gating expansion on bare id there would expand the shared
/// subtree only at whichever path is popped first, silently dropping any
/// in-filter content that's ONLY reachable via a second, later path (the
/// first path's out-of-filter verdict wins by accident of traversal
/// order). So under a filter, expansion is gated on the `(id, path)` pair
/// instead — `included` still dedups by bare id for the *result*, since an
/// id counts as held once regardless of how many paths reach it.
///
/// `expanded` is owned by the caller and spans the WHOLE reachability walk
/// (every tip/snapshot in one `reachable_objects_filtered` call), not just
/// this one subtree walk (C1, P27 final review). The ROOT push is gated on
/// it too, under a filter: a snapshot's root tree can content-dedup to a
/// subtree an earlier snapshot in the same walk already expanded at a
/// different path (e.g. "move everything into x/" — the parent's root
/// tree id equals the child's `x` subtree id). Gating the root push on a
/// bare `included.insert(root)` would then skip that snapshot's root walk
/// entirely (its id is already in `included` from the earlier subtree),
/// silently dropping any in-filter content only reachable via that root's
/// own path (`""`). With `filter = None`, verdicts don't depend on path at
/// all, so the original bare-id gate on `included` stays byte-identical —
/// `expanded` is never consulted in that branch.
fn walk_tree_filtered(
    src: &mut impl ObjectSource,
    root: ObjectId,
    included: &mut BTreeSet<ObjectId>,
    gaps: &mut BTreeSet<ObjectId>,
    filter: Option<&dyn PrefixFilter>,
    expanded: &mut HashSet<(ObjectId, String)>,
) -> Result<()> {
    let mut stack: Vec<(ObjectId, String)> = Vec::new();
    match filter {
        None => {
            if included.insert(root) {
                stack.push((root, String::new()));
            }
        }
        Some(_) => {
            included.insert(root);
            if expanded.insert((root, String::new())) {
                stack.push((root, String::new()));
            }
        }
    }
    while let Some((tree_id, path)) = stack.pop() {
        let tree = match src.get(&tree_id)? {
            Object::Tree(t) => t,
            _ => return Err(Error::BadRef(format!("expected tree {tree_id}"))),
        };
        for e in tree.entries {
            let child_path = if path.is_empty() {
                e.name.clone()
            } else {
                format!("{path}/{}", e.name)
            };
            match e.kind {
                EntryKind::Blob => match filter {
                    None => {
                        included.insert(e.id);
                    }
                    Some(f) => {
                        if f.matches(&child_path) {
                            included.insert(e.id);
                        } else {
                            gaps.insert(e.id);
                        }
                    }
                },
                EntryKind::Tree => match filter {
                    None => {
                        if included.insert(e.id) {
                            stack.push((e.id, child_path));
                        }
                    }
                    Some(f) => {
                        if f.should_descend(&child_path) {
                            included.insert(e.id);
                            if expanded.insert((e.id, child_path.clone())) {
                                stack.push((e.id, child_path));
                            }
                        } else {
                            gaps.insert(e.id);
                        }
                    }
                },
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

    /// Builds a two-subtree repo (`src/a.txt`, `docs/b.txt`) and returns
    /// `(store, snap_id, root_id, src_tree_id, src_blob_id, docs_tree_id, docs_blob_id)`.
    fn two_subtree_repo() -> (
        std::sync::Arc<std::sync::Mutex<Store>>,
        ObjectId,
        ObjectId,
        ObjectId,
        ObjectId,
        ObjectId,
        ObjectId,
    ) {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let root = repo
            .write_tree(&[
                ("src/a.txt".into(), b"A".to_vec(), scl_core::FileMode::FILE),
                ("docs/b.txt".into(), b"B".to_vec(), scl_core::FileMode::FILE),
            ])
            .unwrap();
        let arc = repo.store();
        let (src_tree_id, src_blob_id, docs_tree_id, docs_blob_id) = {
            let mut s = arc.lock().unwrap();
            let root_tree = match Store::get(&mut s, &root).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let mut src_tree_id = None;
            let mut docs_tree_id = None;
            for e in &root_tree.entries {
                match e.name.as_str() {
                    "src" => src_tree_id = Some(e.id),
                    "docs" => docs_tree_id = Some(e.id),
                    _ => {}
                }
            }
            let src_tree_id = src_tree_id.unwrap();
            let docs_tree_id = docs_tree_id.unwrap();
            let src_blob_id = match Store::get(&mut s, &src_tree_id).unwrap() {
                Object::Tree(t) => t.entries[0].id,
                _ => panic!("expected tree"),
            };
            let docs_blob_id = match Store::get(&mut s, &docs_tree_id).unwrap() {
                Object::Tree(t) => t.entries[0].id,
                _ => panic!("expected tree"),
            };
            (src_tree_id, src_blob_id, docs_tree_id, docs_blob_id)
        };
        let snap_id = {
            let mut s = arc.lock().unwrap();
            s.put(Object::Snapshot(scl_core::Snapshot {
                root,
                parents: vec![],
                author: "t".into(),
                timestamp: 0,
                message: "c".into(),
                secrets: BTreeMap::new(),
                protection: Default::default(),
            }))
            .unwrap()
        };
        (arc, snap_id, root, src_tree_id, src_blob_id, docs_tree_id, docs_blob_id)
    }

    #[test]
    fn filtered_prunes_out_of_prefix_subtree() {
        let (arc, snap_id, root, src_tree_id, src_blob_id, docs_tree_id, docs_blob_id) = two_subtree_repo();
        let filter = crate::promisor::Promisor::new("origin", vec!["src/".into()]);
        let mut s = arc.lock().unwrap();
        let r = reachable_objects_filtered(&mut *s, &[snap_id], Some(&filter)).unwrap();

        assert!(r.included.contains(&snap_id));
        assert!(r.included.contains(&root));
        assert!(r.included.contains(&src_tree_id));
        assert!(r.included.contains(&src_blob_id));

        assert!(!r.included.contains(&docs_tree_id));
        assert!(!r.included.contains(&docs_blob_id));
        assert!(r.gaps.contains(&docs_tree_id));
    }

    #[test]
    fn filtered_keeps_ancestor_trees() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let root = repo
            .write_tree(&[
                ("src/app/x.txt".into(), b"X".to_vec(), scl_core::FileMode::FILE),
                ("src/other/y.txt".into(), b"Y".to_vec(), scl_core::FileMode::FILE),
            ])
            .unwrap();
        let arc = repo.store();
        let (src_tree_id, app_tree_id, x_blob_id, other_tree_id, y_blob_id) = {
            let mut s = arc.lock().unwrap();
            let root_tree = match Store::get(&mut s, &root).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let src_tree_id = root_tree.entries.iter().find(|e| e.name == "src").unwrap().id;
            let src_tree = match Store::get(&mut s, &src_tree_id).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let app_tree_id = src_tree.entries.iter().find(|e| e.name == "app").unwrap().id;
            let other_tree_id = src_tree.entries.iter().find(|e| e.name == "other").unwrap().id;
            let app_tree = match Store::get(&mut s, &app_tree_id).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let x_blob_id = app_tree.entries[0].id;
            let other_tree = match Store::get(&mut s, &other_tree_id).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let y_blob_id = other_tree.entries[0].id;
            (src_tree_id, app_tree_id, x_blob_id, other_tree_id, y_blob_id)
        };
        let snap_id = {
            let mut s = arc.lock().unwrap();
            s.put(Object::Snapshot(scl_core::Snapshot {
                root,
                parents: vec![],
                author: "t".into(),
                timestamp: 0,
                message: "c".into(),
                secrets: BTreeMap::new(),
                protection: Default::default(),
            }))
            .unwrap()
        };

        let filter = crate::promisor::Promisor::new("origin", vec!["src/app/".into()]);
        let mut s = arc.lock().unwrap();
        let r = reachable_objects_filtered(&mut *s, &[snap_id], Some(&filter)).unwrap();

        assert!(r.included.contains(&root));
        assert!(r.included.contains(&src_tree_id));
        assert!(r.included.contains(&app_tree_id));
        assert!(r.included.contains(&x_blob_id));

        assert!(!r.included.contains(&other_tree_id));
        assert!(r.gaps.contains(&other_tree_id));
        // MINOR: the out-of-filter sibling blob under the excluded "other"
        // tree must not be included either — only "other"'s tree id (a gap)
        // is recorded, not its child contents (never walked).
        assert!(!r.included.contains(&y_blob_id));
    }

    #[test]
    fn filter_none_is_strict_unchanged() {
        let (arc, snap_id, ..) = two_subtree_repo();
        let mut s = arc.lock().unwrap();
        let unfiltered = reachable_objects(&mut *s, &[snap_id]).unwrap();
        let filtered = reachable_objects_filtered(&mut *s, &[snap_id], None).unwrap();
        assert_eq!(filtered.included, unfiltered);
        assert!(filtered.gaps.is_empty());
    }

    /// The reviewer's exact repro for the CRITICAL: `a/x/f.txt`, `a/y/g.txt`,
    /// `b/x/f.txt`, `b/y/g.txt` where trees `a` and `b` are byte-identical
    /// (same entries -> same id). Filter `["a/x/", "b/y/"]` means the shared
    /// tree must expand at BOTH paths: at "a" only "x" is in-filter, at "b"
    /// only "y" is. A bare-id expansion gate expands the shared tree once
    /// (whichever of "a"/"b" is popped first) and silently drops the
    /// in-filter content that's only reachable via the other path. This
    /// test fails on that old bare-id gate (verified by temporarily
    /// reverting the gate) and passes with the (id, path) gate.
    #[test]
    fn deduped_tree_included_under_each_path() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let root = repo
            .write_tree(&[
                ("a/x/f.txt".into(), b"F".to_vec(), scl_core::FileMode::FILE),
                ("a/y/g.txt".into(), b"G".to_vec(), scl_core::FileMode::FILE),
                ("b/x/f.txt".into(), b"F".to_vec(), scl_core::FileMode::FILE),
                ("b/y/g.txt".into(), b"G".to_vec(), scl_core::FileMode::FILE),
            ])
            .unwrap();
        let arc = repo.store();
        let (a_tree_id, b_tree_id, ax_tree_id, by_tree_id, f_blob_id, g_blob_id) = {
            let mut s = arc.lock().unwrap();
            let root_tree = match Store::get(&mut s, &root).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let a_tree_id = root_tree.entries.iter().find(|e| e.name == "a").unwrap().id;
            let b_tree_id = root_tree.entries.iter().find(|e| e.name == "b").unwrap().id;
            // Content addressing: identical entries under "a" and "b" mean
            // the two subtrees hash to the same id.
            assert_eq!(a_tree_id, b_tree_id, "test setup assumption: a and b subtrees must share an id");
            let a_tree = match Store::get(&mut s, &a_tree_id).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let ax_tree_id = a_tree.entries.iter().find(|e| e.name == "x").unwrap().id;
            let ay_tree_id = a_tree.entries.iter().find(|e| e.name == "y").unwrap().id;
            // "x" and "y" under a/b are also identical to each other's
            // counterpart across a and b (same single-file content), but we
            // just need distinct ids for x vs y here.
            let by_tree_id = ay_tree_id;
            let ax_tree = match Store::get(&mut s, &ax_tree_id).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let f_blob_id = ax_tree.entries[0].id;
            let ay_tree = match Store::get(&mut s, &ay_tree_id).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let g_blob_id = ay_tree.entries[0].id;
            (a_tree_id, b_tree_id, ax_tree_id, by_tree_id, f_blob_id, g_blob_id)
        };
        assert_eq!(a_tree_id, b_tree_id);
        let snap_id = {
            let mut s = arc.lock().unwrap();
            s.put(Object::Snapshot(scl_core::Snapshot {
                root,
                parents: vec![],
                author: "t".into(),
                timestamp: 0,
                message: "c".into(),
                secrets: BTreeMap::new(),
                protection: Default::default(),
            }))
            .unwrap()
        };

        let filter = crate::promisor::Promisor::new("origin", vec!["a/x/".into(), "b/y/".into()]);
        let mut s = arc.lock().unwrap();
        let r = reachable_objects_filtered(&mut *s, &[snap_id], Some(&filter)).unwrap();

        // In-filter content at BOTH paths must be included: a/x's f.txt and
        // b/y's g.txt.
        assert!(r.included.contains(&ax_tree_id), "a/x tree must be included");
        assert!(r.included.contains(&f_blob_id), "a/x/f.txt blob must be included");
        assert!(r.included.contains(&by_tree_id), "b/y tree must be included");
        assert!(r.included.contains(&g_blob_id), "b/y/g.txt blob must be included");

        // Disjointness: nothing that's included may also linger in gaps.
        assert!(!r.gaps.contains(&ax_tree_id));
        assert!(!r.gaps.contains(&f_blob_id));
        assert!(!r.gaps.contains(&by_tree_id));
        assert!(!r.gaps.contains(&g_blob_id));
    }

    /// The final-review CRITICAL (C1): a snapshot whose ROOT tree
    /// content-dedups to an already-expanded SUBTREE from another
    /// snapshot's walk in the same call must still have its own root
    /// walked — the everyday "move everything into x/" history. `c1`'s
    /// root is `{a/f.txt, z/g.txt}`; `c2` moves both into `x/`, so `c2`'s
    /// root is `{x: T}` where `T` is byte-identical to (and therefore
    /// shares the id of) `c1`'s own root tree. Two tips are walked in the
    /// same call — `c2` (like a branch `main` tip) and `c1` (like a branch
    /// `old` tip, mirroring `sc clone`'s multi-branch tip list) — with `c2`
    /// popped first (tips are walked before any snapshot only discovered
    /// as a parent). The filter `["x/a/", "z/"]` means `z/g.txt` is
    /// in-filter only at `c1`'s own root path (`""`), never at `c2`'s `x`
    /// path (only `x/a/` matches there). A bare-id root gate would expand
    /// `T` once (at path `"x"`, discovered via `c2`) and then skip `c1`'s
    /// root walk entirely — silently dropping `z/g.txt`. This test fails on
    /// that old bare-id gate and passes with the `expanded.insert((root,
    /// ""))` gate (mirrors `scratchpad/repro_root_dedup.sh`).
    #[test]
    fn filtered_walk_root_dedup_not_dropped() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let root1 = repo
            .write_tree(&[
                ("a/f.txt".into(), b"AAA".to_vec(), scl_core::FileMode::FILE),
                ("z/g.txt".into(), b"ZZZ".to_vec(), scl_core::FileMode::FILE),
            ])
            .unwrap();
        let root2 = repo
            .write_tree(&[
                ("x/a/f.txt".into(), b"AAA".to_vec(), scl_core::FileMode::FILE),
                ("x/z/g.txt".into(), b"ZZZ".to_vec(), scl_core::FileMode::FILE),
            ])
            .unwrap();
        let arc = repo.store();
        let (z_tree_id, z_blob_id) = {
            let mut s = arc.lock().unwrap();
            let root2_tree = match Store::get(&mut s, &root2).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let x_tree_id = root2_tree.entries.iter().find(|e| e.name == "x").unwrap().id;
            assert_eq!(x_tree_id, root1, "test setup assumption: c2's x/ subtree must dedup to c1's root");
            let root1_tree = match Store::get(&mut s, &root1).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let z_tree_id = root1_tree.entries.iter().find(|e| e.name == "z").unwrap().id;
            let z_tree = match Store::get(&mut s, &z_tree_id).unwrap() {
                Object::Tree(t) => t,
                _ => panic!("expected tree"),
            };
            let z_blob_id = z_tree.entries[0].id;
            (z_tree_id, z_blob_id)
        };
        let (snap1_id, snap2_id) = {
            let mut s = arc.lock().unwrap();
            let snap1_id = s
                .put(Object::Snapshot(scl_core::Snapshot {
                    root: root1,
                    parents: vec![],
                    author: "t".into(),
                    timestamp: 0,
                    message: "c1".into(),
                    secrets: BTreeMap::new(),
                    protection: Default::default(),
                }))
                .unwrap();
            let snap2_id = s
                .put(Object::Snapshot(scl_core::Snapshot {
                    root: root2,
                    parents: vec![snap1_id],
                    author: "t".into(),
                    timestamp: 1,
                    message: "move into x/".into(),
                    secrets: BTreeMap::new(),
                    protection: Default::default(),
                }))
                .unwrap();
            (snap1_id, snap2_id)
        };

        let filter = crate::promisor::Promisor::new("origin", vec!["x/a/".into(), "z/".into()]);
        let mut s = arc.lock().unwrap();
        // Both tips in one call, `snap2` (the dedup donor) first — mirrors
        // `sc clone` walking every branch tip (`main` @ c2, `old` @ c1) in
        // one `reachable_objects_filtered` call.
        let r = reachable_objects_filtered(&mut *s, &[snap2_id, snap1_id], Some(&filter)).unwrap();

        assert!(r.included.contains(&z_tree_id), "c1's own z/ tree must be included, not dropped");
        assert!(r.included.contains(&z_blob_id), "c1's own z/g.txt blob must be included, not dropped");
        assert!(!r.gaps.contains(&z_tree_id));
        assert!(!r.gaps.contains(&z_blob_id));
    }

    /// The IMPORTANT: an out-of-filter child must never be fetched from the
    /// source, so a partial-clone source that's genuinely missing
    /// out-of-filter objects does not error.
    #[test]
    fn gap_object_is_never_fetched() {
        let (arc, snap_id, _root, _src_tree_id, _src_blob_id, docs_tree_id, docs_blob_id) = two_subtree_repo();
        {
            let mut s = arc.lock().unwrap();
            s.delete(&docs_tree_id).unwrap();
            s.delete(&docs_blob_id).unwrap();
        }
        let filter = crate::promisor::Promisor::new("origin", vec!["src/".into()]);
        let mut s = arc.lock().unwrap();
        let r = reachable_objects_filtered(&mut *s, &[snap_id], Some(&filter)).unwrap();
        assert!(r.gaps.contains(&docs_tree_id));
        assert!(!r.included.contains(&docs_tree_id));
        assert!(!r.included.contains(&docs_blob_id));
    }

    #[test]
    fn in_filter_absent_is_an_error() {
        let (arc, snap_id, _root, src_tree_id, ..) = two_subtree_repo();
        {
            let mut s = arc.lock().unwrap();
            // Simulate corruption: the in-filter `src` tree is missing from the
            // source. It's an in-filter TREE (not a blob) because only trees are
            // ever `get()`'d during the walk — blob ids come straight from the
            // already-fetched parent tree's entries and are never independently
            // fetched here, so a missing in-filter *blob* can't surface as an
            // error from this walk (the transport layer verifies blob content
            // separately). A missing in-filter tree, by contrast, must be
            // fetched to keep descending, and that's the corruption this walk
            // can and must detect.
            s.delete(&src_tree_id).unwrap();
        }
        let filter = crate::promisor::Promisor::new("origin", vec!["src/".into()]);
        let mut s = arc.lock().unwrap();
        let err = reachable_objects_filtered(&mut *s, &[snap_id], Some(&filter)).unwrap_err();
        match err {
            Error::Core(scl_core::Error::NotFound(_)) => {}
            other => panic!("expected NotFound for missing in-filter object, got {other:?}"),
        }
    }
}
