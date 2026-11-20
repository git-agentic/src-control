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
    Secret,
    /// A signature or transcript.
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
            Object::Secret(_) => Node::Secret,
            _ => Node::Other,
        }
    }

    fn kind(&self) -> Kind {
        match self {
            Node::Blob => Kind::Blob,
            Node::Sealed => Kind::Sealed,
            Node::Secret => Kind::Secret,
            Node::Snapshot(_) => Kind::Other("snapshot"),
            Node::Tree(_) => Kind::Other("tree"),
            Node::Manifest(_) => Kind::Other("manifest"),
            Node::Other => Kind::Other("signature or transcript"),
        }
    }
}

/// An object's kind, for the places the rule only needs that and not the
/// content (file content, sealed closure entries, secrets).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Blob,
    Sealed,
    Secret,
    /// Anything else, by name.
    Other(&'static str),
}

impl Kind {
    /// From a kind name as [`Object::kind_name`] spells it.
    pub(crate) fn of_name(name: &'static str) -> Kind {
        match name {
            "blob" => Kind::Blob,
            "sealed" => Kind::Sealed,
            "secret" => Kind::Secret,
            other => Kind::Other(other),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Blob => "blob",
            Kind::Sealed => "sealed object",
            Kind::Secret => "secret",
            Kind::Other(n) => n,
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
    /// The kind of an object expected to be file content, a sealed closure
    /// entry or a secret, or `None` when it is not held. An implementation
    /// that can say so without loading the object should (a blob can be large).
    fn leaf(&mut self, id: &ObjectId) -> Result<Option<Kind>> {
        Ok(self.node(id)?.map(|n| n.kind()))
    }
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
        other => refuse(format!(
            "{what} {id} is a {}, not a snapshot",
            other.kind().name()
        )),
    }
}

fn read_manifest<S: RefObjects>(src: &mut S, id: &ObjectId, what: &str) -> Result<BranchManifest> {
    match read(src, id, what)? {
        Node::Manifest(m) => Ok(m),
        other => refuse(format!(
            "{what} {id} is a {}, not a manifest",
            other.kind().name()
        )),
    }
}

/// `id` must be held and be of kind `want`.
fn require_kind<S: RefObjects>(src: &mut S, id: &ObjectId, want: Kind, what: &str) -> Result<()> {
    match src.leaf(id)? {
        Some(k) if k == want => Ok(()),
        Some(k) => refuse(format!(
            "{what} {id} is a {}, not a {}",
            k.name(),
            want.name()
        )),
        None => refuse(format!("{what} {id} is not held here")),
    }
}

/// Decide whether branch `current` (its tip, `None` for a new branch) may move
/// to `new`. `tips` is every existing ref's tip, trusted as already connected.
/// Returns the tips the verdict actually leaned on (where the walk stopped), so
/// the caller can confirm each is still a tip when the move is applied: a tip
/// that was removed or rewritten meanwhile no longer vouches for its history.
pub(crate) fn check_ref_move<S: RefObjects>(
    src: &mut S,
    tips: &BTreeSet<ObjectId>,
    current: Option<ObjectId>,
    new: ObjectId,
) -> Result<BTreeSet<ObjectId>> {
    let new_node = read(src, &new, "ref target")?;
    if !matches!(new_node, Node::Snapshot(_) | Node::Manifest(_)) {
        return refuse(format!(
            "ref target {new} is a {}, not a snapshot or manifest",
            new_node.kind().name()
        ));
    }
    if let Some(cur) = current {
        let cur_node = read(src, &cur, "current tip")?;
        if std::mem::discriminant(&cur_node) != std::mem::discriminant(&new_node) {
            return refuse(format!(
                "branch tip {cur} is a {} but {new} is a {}; a branch cannot change kind",
                cur_node.kind().name(),
                new_node.kind().name()
            ));
        }
    }
    let mut boundary = tips.clone();
    boundary.extend(current);
    let mut trusted = BTreeSet::new();
    match new_node {
        Node::Snapshot(_) => {
            if let Some(cur) = current {
                if !snapshot_reaches(src, new, cur)? {
                    return Err(Error::NonFastForward);
                }
            }
            verify_snapshots(
                src,
                &boundary,
                &mut trusted,
                &[new],
                &mut Verified::default(),
            )?;
        }
        Node::Manifest(m) => verify_manifests(src, &boundary, &mut trusted, current, new, m)?,
        _ => unreachable!("kind checked above"),
    }
    Ok(trusted)
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
/// `boundary`, which it records in `trusted` as it stops. `done` collects tree
/// and blob ids already verified.
fn verify_snapshots<S: RefObjects>(
    src: &mut S,
    boundary: &BTreeSet<ObjectId>,
    trusted: &mut BTreeSet<ObjectId>,
    starts: &[ObjectId],
    done: &mut Verified,
) -> Result<()> {
    let mut seen: HashSet<ObjectId> = starts.iter().copied().collect();
    let mut queue: VecDeque<ObjectId> = seen.iter().copied().collect();
    while let Some(id) = queue.pop_front() {
        if boundary.contains(&id) {
            trusted.insert(id);
            continue;
        }
        let snap = read_snapshot(src, &id, "commit")?;
        let mut parent_roots = Vec::with_capacity(snap.parents.len());
        let mut parent_secrets = Vec::with_capacity(snap.parents.len());
        for p in &snap.parents {
            let parent = read_snapshot(src, p, "parent commit")?;
            parent_roots.push(parent.root);
            parent_secrets.push(parent.secrets);
            if seen.insert(*p) {
                queue.push_back(*p);
            }
        }
        // Secret registry entries must be secrets; one a parent already has
        // is inside its verified closure.
        for (name, sid) in &snap.secrets {
            if parent_secrets.iter().any(|m| m.get(name) == Some(sid)) {
                continue;
            }
            require_kind(src, sid, Kind::Secret, "secret registry entry")?;
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
            other => {
                return refuse(format!(
                    "tree {id} is a {}, not a tree",
                    other.kind().name()
                ))
            }
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
                        Some(Kind::Blob) => {
                            seen.leaves.insert(e.id);
                        }
                        Some(other) => {
                            return refuse(format!(
                                "file entry {} names {}, a {}, not file content",
                                e.name,
                                e.id,
                                other.name()
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
    trusted: &mut BTreeSet<ObjectId>,
    current: Option<ObjectId>,
    new: ObjectId,
    new_manifest: BranchManifest,
) -> Result<()> {
    let mut chain: Vec<BranchManifest> = Vec::new();
    // The manifest the chain stops at (the current tip, or a trusted tip for a
    // new branch), whose closure is already verified.
    let mut terminal: Option<BranchManifest> = None;
    let (mut id, mut m) = (new, new_manifest);
    let mut found = false;
    loop {
        if Some(id) == current {
            found = true;
            trusted.insert(id);
            terminal = Some(m);
            break;
        }
        // A new branch needs no ancestry, so it can stop at a trusted tip.
        if current.is_none() && boundary.contains(&id) {
            trusted.insert(id);
            terminal = Some(m);
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
    for (i, m) in chain.iter().enumerate() {
        let roots: Vec<ObjectId> = std::iter::once(m.base)
            .chain(m.anchors.iter().copied())
            .collect();
        for r in &roots {
            read_snapshot(src, r, "manifest base or anchor")?;
        }
        verify_snapshots(src, boundary, trusted, &roots, &mut done)?;
        // Every closure entry must be a sealed object: one naming a public
        // snapshot would make reachability mark it seen without walking it.
        // An entry the previous manifest already lists is inside its verified
        // closure (that manifest is the next in the chain, or the terminal).
        let known: HashSet<&ObjectId> = chain
            .get(i + 1)
            .or(terminal.as_ref())
            .map(|o| o.closure.iter().collect())
            .unwrap_or_default();
        for c in &m.closure {
            if !known.contains(c) {
                require_kind(src, c, Kind::Sealed, "manifest closure entry")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::{FileMode, SealedObj, TreeEntry};
    use std::collections::HashMap;

    /// An in-memory object source that records every id it is asked about.
    #[derive(Default)]
    struct Counting {
        objects: HashMap<ObjectId, Node>,
        asked: Vec<ObjectId>,
    }

    impl Counting {
        fn add(&mut self, o: Object) -> ObjectId {
            let id = o.id();
            self.objects.insert(id, Node::of(o));
            id
        }
    }

    impl RefObjects for Counting {
        fn node(&mut self, id: &ObjectId) -> Result<Option<Node>> {
            self.asked.push(*id);
            Ok(self.objects.get(id).cloned())
        }
    }

    fn tree(entries: &[(&str, EntryKind, ObjectId)]) -> Object {
        Object::Tree(Tree::new(
            entries
                .iter()
                .map(|(name, kind, id)| TreeEntry {
                    name: name.to_string(),
                    kind: *kind,
                    id: *id,
                    mode: FileMode::FILE,
                    perms: 0,
                })
                .collect(),
        ))
    }

    fn snap(root: ObjectId, parents: &[ObjectId]) -> Object {
        Object::Snapshot(Snapshot {
            root,
            parents: parents.to_vec(),
            author: "t".into(),
            timestamp: 0,
            message: String::new(),
            secrets: Default::default(),
            protection: Default::default(),
        })
    }

    /// Only what a push changed is looked at: unchanged files in a changed
    /// directory, and unchanged closure entries and secrets, are inside the
    /// parent's verified closure and are never read (a file can be large).
    #[test]
    fn unchanged_content_is_not_read() {
        let mut src = Counting::default();
        let big: Vec<ObjectId> = (0..3u8)
            .map(|i| src.add(Object::blob(vec![i; 64])))
            .collect();
        let entry = |name: &'static str, id| (name, EntryKind::Blob, id);
        let dir_old = src.add(tree(&[
            entry("big0", big[0]),
            entry("big1", big[1]),
            entry("big2", big[2]),
        ]));
        let root_old = src.add(tree(&[("d", EntryKind::Tree, dir_old)]));
        let secret = src.add(Object::Secret(scl_core::Secret {
            name: "k".into(),
            nonce: vec![],
            ciphertext: vec![],
            wrapped_keys: vec![],
        }));
        let parent = {
            let Object::Snapshot(mut s) = snap(root_old, &[]) else {
                unreachable!()
            };
            s.secrets.insert("k".into(), secret);
            src.add(Object::Snapshot(s))
        };

        // The child adds one file to the directory and keeps everything else.
        let added = src.add(Object::blob(b"new file".to_vec()));
        let dir_new = src.add(tree(&[
            entry("big0", big[0]),
            entry("big1", big[1]),
            entry("big2", big[2]),
            entry("new", added),
        ]));
        let root_new = src.add(tree(&[("d", EntryKind::Tree, dir_new)]));
        let child = {
            let Object::Snapshot(mut s) = snap(root_new, &[parent]) else {
                unreachable!()
            };
            s.secrets.insert("k".into(), secret);
            src.add(Object::Snapshot(s))
        };

        src.asked.clear();
        check_ref_move(&mut src, &BTreeSet::from([parent]), Some(parent), child).unwrap();
        for unchanged in big.iter().chain([&secret]) {
            assert!(
                !src.asked.contains(unchanged),
                "{unchanged} is unchanged and must not be read"
            );
        }
        assert!(src.asked.contains(&added), "the new file is checked");

        // The same for a manifest: entries its predecessor already lists.
        let sealed: Vec<ObjectId> = (0..3u8)
            .map(|i| {
                src.add(Object::Sealed(SealedObj {
                    payload: std::sync::Arc::from(vec![i].into_boxed_slice()),
                }))
            })
            .collect();
        let manifest = |prev: Option<ObjectId>, closure: &[ObjectId]| {
            Object::Manifest(scl_core::BranchManifest {
                base: parent,
                prev,
                anchors: vec![],
                closure: closure.to_vec(),
                index_ct: vec![],
                kek_wraps: vec![],
            })
        };
        let m1 = src.add(manifest(None, &sealed[..2]));
        let m2 = src.add(manifest(Some(m1), &sealed));
        src.asked.clear();
        check_ref_move(&mut src, &BTreeSet::from([m1]), Some(m1), m2).unwrap();
        assert!(!src.asked.contains(&sealed[0]) && !src.asked.contains(&sealed[1]));
        assert!(
            src.asked.contains(&sealed[2]),
            "the new closure entry is checked"
        );
    }
}
