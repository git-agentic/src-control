//! The server-side rule for moving a ref (`Transport::update_ref`), shared by
//! every transport that serves refs.
//!
//! The pushing client checks fast-forward itself, but a writer need not be our
//! client, and object ingest has no connectivity check, so the receiver must
//! decide on its own (as git's receive-pack does). A ref move is accepted only
//! when:
//!
//! - **Kind:** the new tip is a snapshot or a private-branch manifest, and has
//!   the same kind as the branch's current tip (a branch cannot flip between
//!   public and private; publishing is a rewrite, not a fast-forward).
//! - **Ancestry:** the current tip is an ancestor of the new one. A snapshot's
//!   ancestors are its parents, which must be snapshots; a manifest's are its
//!   `prev` chain, which must be manifests. A manifest's `base` is deliberately
//!   not an ancestor link: it names a public snapshot, not an earlier state of
//!   the branch.
//! - **Connectivity:** everything the new history needs is held, so no clone,
//!   fetch or gc ever meets a dangling id. The check covers only what the push
//!   added: it stops at any existing ref tip (trusted, like the current tip),
//!   and under a new commit it descends only into subtrees that differ from the
//!   same path in a parent. A parent that is itself new is verified in the same
//!   walk, so skipping what it already names is sound.
//!
//! Anything missing, of the wrong kind, or unreadable is a refusal.

use std::collections::{BTreeSet, HashSet, VecDeque};

use scl_core::{BranchManifest, EntryKind, Object, ObjectId, Snapshot, Tree};

use crate::error::{Error, Result};

/// What an object is, as far as the ref rule cares. Blobs carry no content:
/// the rule only needs to know one is there and what it is.
#[derive(Clone)]
pub(crate) enum Node {
    Snapshot(Snapshot),
    Tree(Tree),
    Manifest(BranchManifest),
    Blob,
    Sealed,
    /// A secret, signature or transcript.
    Other,
}

impl Node {
    pub(crate) fn of(obj: Object) -> Node {
        match obj {
            Object::Snapshot(s) => Node::Snapshot(s),
            Object::Tree(t) => Node::Tree(t),
            Object::Manifest(m) => Node::Manifest(m),
            Object::Blob(_) => Node::Blob,
            Object::Sealed(_) => Node::Sealed,
            _ => Node::Other,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Node::Snapshot(_) => "snapshot",
            Node::Tree(_) => "tree",
            Node::Manifest(_) => "manifest",
            Node::Blob => "blob",
            Node::Sealed => "sealed object",
            Node::Other => "secret, signature or transcript",
        }
    }
}

/// Read access to the objects a ref move is judged against; it must include
/// what the same push just uploaded. A cached read can outlive a gc prune, so
/// the caller confirms what it relied on is still on disk once it holds the
/// repo lock.
pub(crate) trait RefObjects {
    /// The object, or `None` when it is not held.
    fn node(&mut self, id: &ObjectId) -> Result<Option<Node>>;
    /// Like [`RefObjects::node`], for an object expected to be a file's
    /// content: an implementation may avoid loading a large blob to say so.
    fn leaf(&mut self, id: &ObjectId) -> Result<Option<Node>> {
        self.node(id)
    }
    /// Whether the object is held, without reading it where that is cheaper.
    fn held(&mut self, id: &ObjectId) -> Result<bool>;
}

/// Tree and file-content ids already verified in one check.
#[derive(Default)]
struct Verified {
    trees: HashSet<ObjectId>,
    leaves: HashSet<ObjectId>,
}

fn refuse<T>(msg: String) -> Result<T> {
    Err(Error::InvalidArgument(format!("ref update refused: {msg}")))
}

fn read<S: RefObjects>(src: &mut S, id: &ObjectId, what: &str) -> Result<Node> {
    match src.node(id)? {
        Some(n) => Ok(n),
        None => refuse(format!("{what} {id} is not held here")),
    }
}

fn read_snapshot<S: RefObjects>(src: &mut S, id: &ObjectId, what: &str) -> Result<Snapshot> {
    match read(src, id, what)? {
        Node::Snapshot(s) => Ok(s),
        other => refuse(format!("{what} {id} is a {}, not a snapshot", other.kind())),
    }
}

fn read_manifest<S: RefObjects>(src: &mut S, id: &ObjectId, what: &str) -> Result<BranchManifest> {
    match read(src, id, what)? {
        Node::Manifest(m) => Ok(m),
        other => refuse(format!("{what} {id} is a {}, not a manifest", other.kind())),
    }
}

fn require_held<S: RefObjects>(src: &mut S, id: &ObjectId, what: &str) -> Result<()> {
    if src.held(id)? {
        Ok(())
    } else {
        refuse(format!("{what} {id} is not held here"))
    }
}

/// Decide whether branch `current` (its tip, `None` for a new branch) may move
/// to `new`. `tips` is every existing ref's tip, trusted as already connected.
pub(crate) fn check_ref_move<S: RefObjects>(
    src: &mut S,
    tips: &BTreeSet<ObjectId>,
    current: Option<ObjectId>,
    new: ObjectId,
) -> Result<()> {
    let new_node = read(src, &new, "ref target")?;
    if !matches!(new_node, Node::Snapshot(_) | Node::Manifest(_)) {
        return refuse(format!(
            "ref target {new} is a {}, not a snapshot or manifest",
            new_node.kind()
        ));
    }
    if let Some(cur) = current {
        let cur_node = read(src, &cur, "current tip")?;
        if std::mem::discriminant(&cur_node) != std::mem::discriminant(&new_node) {
            return refuse(format!(
                "branch tip {cur} is a {} but {new} is a {}; a branch cannot change kind",
                cur_node.kind(),
                new_node.kind()
            ));
        }
    }
    let mut boundary = tips.clone();
    boundary.extend(current);
    match new_node {
        Node::Snapshot(_) => {
            if let Some(cur) = current {
                if !snapshot_reaches(src, new, cur)? {
                    return Err(Error::NonFastForward);
                }
            }
            verify_snapshots(src, &boundary, &[new], &mut Verified::default())
        }
        Node::Manifest(m) => verify_manifests(src, &boundary, current, new, m),
        _ => unreachable!("kind checked above"),
    }
}

/// Is `target` an ancestor of `from` over snapshot parents (early exit)?
fn snapshot_reaches<S: RefObjects>(src: &mut S, from: ObjectId, target: ObjectId) -> Result<bool> {
    let mut seen = HashSet::from([from]);
    let mut queue = VecDeque::from([from]);
    while let Some(id) = queue.pop_front() {
        for p in read_snapshot(src, &id, "commit")?.parents {
            if p == target {
                return Ok(true);
            }
            if seen.insert(p) {
                queue.push_back(p);
            }
        }
    }
    Ok(false)
}

/// Connectivity of the snapshot history reachable from `starts`, stopping at
/// `boundary`. `done` collects tree and blob ids already verified.
fn verify_snapshots<S: RefObjects>(
    src: &mut S,
    boundary: &BTreeSet<ObjectId>,
    starts: &[ObjectId],
    done: &mut Verified,
) -> Result<()> {
    let mut seen: HashSet<ObjectId> = starts.iter().copied().collect();
    let mut queue: VecDeque<ObjectId> = seen.iter().copied().collect();
    while let Some(id) = queue.pop_front() {
        if boundary.contains(&id) {
            continue;
        }
        let snap = read_snapshot(src, &id, "commit")?;
        let mut parent_roots = Vec::with_capacity(snap.parents.len());
        for p in &snap.parents {
            parent_roots.push(read_snapshot(src, p, "parent commit")?.root);
            if seen.insert(*p) {
                queue.push_back(*p);
            }
        }
        for sid in snap.secrets.values() {
            require_held(src, sid, "secret")?;
        }
        verify_tree(src, snap.root, &parent_roots, done)?;
    }
    Ok(())
}

/// Everything under tree `root` is held, with the right kind, descending only
/// into entries that differ from the same path under one of `parent_roots`.
/// An explicit stack keeps a hostile, deeply nested tree from overflowing the
/// call stack. `trees` and `leaves` memoize what has been verified, apart from
/// each other: an id is verified as one kind only, so an entry that names it as
/// the other kind is refused rather than trusted, and a shared-subtree DAG is
/// not walked once per path.
fn verify_tree<S: RefObjects>(
    src: &mut S,
    root: ObjectId,
    parent_roots: &[ObjectId],
    seen: &mut Verified,
) -> Result<()> {
    let mut stack = vec![(root, parent_roots.to_vec())];
    while let Some((id, parents)) = stack.pop() {
        if parents.contains(&id) || !seen.trees.insert(id) {
            continue;
        }
        let tree = match read(src, &id, "tree")? {
            Node::Tree(t) => t,
            other => return refuse(format!("tree {id} is a {}, not a tree", other.kind())),
        };
        // A parent tree that is not held cannot vouch for anything; the
        // commit that names it fails its own check.
        let mut parent_trees = Vec::new();
        for p in &parents {
            if let Some(Node::Tree(t)) = src.node(p)? {
                parent_trees.push(t);
            }
        }
        for e in &tree.entries {
            let same: Vec<&scl_core::TreeEntry> = parent_trees
                .iter()
                .filter_map(|t| t.get(&e.name))
                .filter(|pe| pe.kind == e.kind)
                .collect();
            if same.iter().any(|pe| pe.id == e.id) {
                continue;
            }
            match e.kind {
                EntryKind::Tree => stack.push((e.id, same.iter().map(|pe| pe.id).collect())),
                EntryKind::Blob => {
                    if seen.leaves.contains(&e.id) {
                        continue;
                    }
                    match src.leaf(&e.id)? {
                        Some(Node::Blob | Node::Sealed) => {
                            seen.leaves.insert(e.id);
                        }
                        Some(other) => {
                            return refuse(format!(
                                "file entry {} names {}, a {}, not file content",
                                e.name,
                                e.id,
                                other.kind()
                            ))
                        }
                        None => return refuse(format!("file content {} is not held here", e.id)),
                    }
                }
            }
        }
    }
    Ok(())
}

/// A manifest tip: its `prev` chain (manifests) must reach `current`, and each
/// new manifest must have its `base`, `anchors` (snapshots with held history)
/// and sealed `closure` held.
fn verify_manifests<S: RefObjects>(
    src: &mut S,
    boundary: &BTreeSet<ObjectId>,
    current: Option<ObjectId>,
    new: ObjectId,
    new_manifest: BranchManifest,
) -> Result<()> {
    let mut chain = Vec::new();
    let (mut id, mut m) = (new, new_manifest);
    let mut found = false;
    loop {
        if Some(id) == current {
            found = true;
            break;
        }
        // A new branch needs no ancestry, so it can stop at a trusted tip.
        if current.is_none() && boundary.contains(&id) {
            break;
        }
        let prev = m.prev;
        chain.push(m);
        match prev {
            None => break,
            Some(p) => {
                m = read_manifest(src, &p, "previous manifest")?;
                id = p;
            }
        }
    }
    if current.is_some() && !found {
        return Err(Error::NonFastForward);
    }
    let mut done = Verified::default();
    for m in &chain {
        let roots: Vec<ObjectId> = std::iter::once(m.base)
            .chain(m.anchors.iter().copied())
            .collect();
        for r in &roots {
            read_snapshot(src, r, "manifest base or anchor")?;
        }
        verify_snapshots(src, boundary, &roots, &mut done)?;
        for c in &m.closure {
            require_held(src, c, "sealed object")?;
        }
    }
    Ok(())
}
