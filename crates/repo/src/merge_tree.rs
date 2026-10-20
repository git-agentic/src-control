//! Tree-recursive three-way merge (ADR-0049, P37c).
//!
//! The flatten merge ([`crate::merge::three_way_files`]) reads every file of
//! all three trees. On a partial clone most of those objects are absent, and
//! most of them do not matter: where the three sides agree on a subtree by id,
//! the answer is known without reading below it. [`merge_trees`] merges one
//! directory level at a time and *carries* such a subtree by id, unread.
//!
//! A subtree is carried only when that is provably the same answer the flatten
//! merge gives:
//!
//! - it is identical on all three sides, or
//! - the sides do not all differ (`ours == theirs`, `base == theirs` or
//!   `base == ours`, by tree id) **and** it is policy-disjoint: no protection
//!   rule covers it or lies inside it. A side can already hold plaintext under
//!   its own rule (`protect` records the rule before it encrypts), and the full
//!   merge re-encrypts every plain survivor under a union rule, so a subtree
//!   that intersects a rule is read, not carried.
//!
//! Everything else recurses, and at the leaves the per-path rules are the very
//! same function the flatten merge uses ([`crate::merge::merge_path`]), so the
//! two engines cannot disagree on a leaf.
//!
//! The engine is pull-based. It never fetches: when it must read an object the
//! store lacks it returns [`TreeMerge::Needs`] with the `(id, path)` pairs, the
//! caller fills them (outside the store lock) and calls again.

use std::collections::{BTreeMap, BTreeSet};

use scl_core::{EntryKind, FileMode, ObjectId, Protection, Store, TreeEntry};

use crate::error::{Error, Result};
use crate::fill::FillStats;
use crate::merge::{check_path_collisions, merge_path, FileEntry, FileMerge, MergeAcc};

/// What the merge carried by id instead of reading.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Carried {
    /// The whole merged root is this tree, as is (the three roots agreed).
    Root(ObjectId),
    /// Subtrees to overlay by id onto the tree built from the enumerated
    /// files, as `(path, entry)` where the entry's name is the last component.
    Entries(Vec<(String, TreeEntry)>),
}

/// A finished tree merge.
///
/// **`merge.wrapped_carry` is incomplete whenever anything was carried**: it
/// holds wraps only for the protected blobs of the regions the merge read, and a
/// carried subtree's protected blobs are never enumerated. Building the merged
/// snapshot's `protection.wrapped` from it, then pruning to reachable blobs as
/// the full merge does, would permanently drop every recipient's access to
/// those blobs. Use [`TreeMergeDone::merged_wraps`] instead.
#[derive(Debug)]
pub(crate) struct TreeMergeDone {
    /// The resolved files of every region the merge read.
    pub merge: FileMerge,
    /// The subtrees it did not read.
    pub carried: Carried,
}

impl TreeMergeDone {
    /// Did the merge carry any subtree by id?
    pub fn carried_any(&self) -> bool {
        match &self.carried {
            Carried::Root(_) => true,
            Carried::Entries(v) => !v.is_empty(),
        }
    }

    /// The wraps the merged snapshot must start from (ADR-0049 decision 4).
    /// If anything was carried, the complete union of the input wraps (ours,
    /// theirs, base; an id seen as deleted at one path may survive under a
    /// carried subtree elsewhere, so no per-id pruning is sound). Otherwise
    /// just the enumerated regions' wraps, which the caller prunes to
    /// reachable blobs exactly as the full merge does.
    pub fn merged_wraps(
        &self,
        ours: &Protection,
        theirs: &Protection,
        base: &Protection,
    ) -> BTreeMap<ObjectId, Vec<scl_core::WrappedKey>> {
        let mut out = self.merge.wrapped_carry.clone();
        if !self.carried_any() {
            return out;
        }
        for p in [ours, theirs, base] {
            for (id, wks) in &p.wrapped {
                let entry = out.entry(*id).or_default();
                *entry = crate::protect::union_wraps(entry, wks);
            }
        }
        out
    }
}

/// An object a pass could not read: where the traversal found it and whether
/// it is a directory (so a gap error does not blame a blob-size limit for a
/// missing tree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Need {
    pub(crate) id: ObjectId,
    pub(crate) path: String,
    pub(crate) tree: bool,
}

/// The outcome of one [`merge_trees`] pass.
#[derive(Debug)]
pub(crate) enum TreeMerge {
    /// The pass needs these objects (subtrees or blobs the store lacks), each
    /// with the path at which the traversal found it. Fill them and call again.
    Needs(Vec<Need>),
    Done(TreeMergeDone),
}

struct Walk<'a> {
    prots: [&'a Protection; 3],
    rules: Vec<String>,
    identity: Option<&'a scl_crypto::SecretKey>,
    acc: MergeAcc,
    carried: Vec<(String, TreeEntry)>,
    carried_root: Option<ObjectId>,
    needs: Vec<Need>,
    needs_seen: BTreeSet<ObjectId>,
}

impl Walk<'_> {
    fn need(&mut self, id: ObjectId, path: &str, tree: bool) {
        if self.needs_seen.insert(id) {
            self.needs.push(Need {
                id,
                path: path.to_string(),
                tree,
            });
        }
    }

    /// Does any rule cover `path` or lie inside it? Checked in both
    /// directions at `/` boundaries. Every rule counts, including rules present
    /// on only one side and rules whose recipients have all been revoked
    /// (tombstones gate future seals; they do not remove the prefix).
    fn intersects_rule(&self, path: &str) -> bool {
        self.rules.iter().any(|bare| {
            path.is_empty()
                || path == bare
                || path.starts_with(&format!("{bare}/"))
                || bare.starts_with(&format!("{path}/"))
        })
    }
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{path}/{name}")
    }
}

fn file_entry(e: &TreeEntry) -> FileEntry {
    (e.id, e.mode, e.perms)
}

/// Merge `base`/`ours`/`theirs` (root tree ids with their snapshots'
/// protection policies; `base: None` is the empty base) one directory level at
/// a time, carrying subtrees by id where that is provably safe. See the module
/// docs. On a full store this never returns [`TreeMerge::Needs`].
pub(crate) fn merge_trees(
    store: &mut Store,
    base: Option<(ObjectId, &Protection)>,
    ours: (ObjectId, &Protection),
    theirs: (ObjectId, &Protection),
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<TreeMerge> {
    let default_prot = Protection::default();
    let (base_root, base_prot) = match base {
        Some((r, p)) => (Some(r), p),
        None => (None, &default_prot),
    };
    let prots = [ours.1, theirs.1, base_prot];
    let mut rules: BTreeSet<String> = BTreeSet::new();
    for p in prots {
        for r in &p.prefixes {
            rules.insert(r.prefix.trim_end_matches('/').to_string());
        }
    }
    let mut w = Walk {
        prots,
        rules: rules.into_iter().collect(),
        identity,
        acc: MergeAcc::default(),
        carried: Vec::new(),
        carried_root: None,
        needs: Vec::new(),
        needs_seen: BTreeSet::new(),
    };
    let root_entry = |id: ObjectId| TreeEntry {
        name: String::new(),
        kind: EntryKind::Tree,
        id,
        mode: FileMode::FILE,
        perms: 0,
    };
    tree_node(
        store,
        &mut w,
        "",
        [
            base_root.map(root_entry),
            Some(root_entry(ours.0)),
            Some(root_entry(theirs.0)),
        ],
    )?;
    // A pass that needs objects discards everything it accumulated: leaves
    // push into `acc` before some reads that can come back NotFound, so a
    // partial `acc` must never survive into the next round. The caller fills
    // and calls again from scratch.
    if !w.needs.is_empty() {
        return Ok(TreeMerge::Needs(w.needs));
    }
    let carried = match w.carried_root {
        Some(id) => Carried::Root(id),
        None => Carried::Entries(w.carried),
    };
    // Reject `x` as both file and directory before anything is written. The
    // carried entries count as directories at their paths.
    check_path_collisions(
        w.acc
            .files
            .iter()
            .map(|f| f.path.as_str())
            .chain(match &carried {
                Carried::Entries(v) => v.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
                Carried::Root(_) => Vec::new(),
            }),
    )?;
    Ok(TreeMerge::Done(TreeMergeDone {
        merge: w.acc.into(),
        carried,
    }))
}

impl crate::repo::Repo {
    /// Run [`merge_trees`] to completion on this repo's store, filling what it
    /// asks for between passes (ADR-0049 decision 5). Every pass takes the
    /// store lock and releases it before the fill, which takes it too. A pass
    /// that needs objects discards its work, so a round is idempotent and an
    /// interrupted fill resumes from current presence.
    ///
    /// An id asked for again after it was filled means the store reports it
    /// present while the traversal cannot read it (a stale index entry): that
    /// would loop forever, so it fails instead.
    pub(crate) fn tree_merge_filled(
        &self,
        base: Option<(ObjectId, &Protection)>,
        ours: (ObjectId, &Protection),
        theirs: (ObjectId, &Protection),
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<(TreeMergeDone, FillStats)> {
        let mut filler = self.needs_filler()?;
        fill_loop(
            || {
                let store_arc = self.vfs().store();
                let mut store = store_arc.lock().unwrap();
                merge_trees(&mut store, base, ours, theirs, identity)
            },
            |needs| filler.fill(needs),
        )
    }
}

/// The pass-then-fill loop of [`Repo::tree_merge_filled`], with the pass and
/// the fill as parameters so the no-progress guard can be tested without a
/// store whose index disagrees with itself.
fn fill_loop(
    mut pass: impl FnMut() -> Result<TreeMerge>,
    mut fill: impl FnMut(&[Need]) -> Result<FillStats>,
) -> Result<(TreeMergeDone, FillStats)> {
    let mut stats = FillStats::default();
    let mut asked: BTreeSet<ObjectId> = BTreeSet::new();
    loop {
        let needs = match pass()? {
            TreeMerge::Done(done) => return Ok((done, stats)),
            TreeMerge::Needs(needs) => needs,
        };
        if let Some(Need { id, path, .. }) = needs.iter().find(|n| asked.contains(&n.id)) {
            return Err(Error::Protocol(format!(
                "merge asked again for object {id} (at {path:?}) after it was fetched; \
                 the object store and its index disagree"
            )));
        }
        asked.extend(needs.iter().map(|n| n.id));
        let round = fill(&needs)?;
        stats.requests += round.requests;
        stats.objects += round.objects;
    }
}

/// Visit one name at `path` with its (up to three) entries.
fn visit(store: &mut Store, w: &mut Walk, path: &str, ents: [Option<TreeEntry>; 3]) -> Result<()> {
    let present: Vec<&TreeEntry> = ents.iter().flatten().collect();
    if present.iter().all(|e| e.kind == EntryKind::Blob) {
        let [b, o, t] = &ents;
        match merge_path(
            store,
            path.to_string(),
            b.as_ref().map(file_entry),
            o.as_ref().map(file_entry),
            t.as_ref().map(file_entry),
            &w.prots,
            w.identity,
            &mut w.acc,
        ) {
            Ok(()) => Ok(()),
            // A blob the leaf must read is absent: ask for it.
            Err(Error::Core(scl_core::Error::NotFound(id))) => {
                w.need(id, path, false);
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else if present.iter().all(|e| e.kind == EntryKind::Tree) {
        tree_node(store, w, path, ents)
    } else {
        enumerate_mixed(store, w, path, ents)
    }
}

/// All present entries at `path` are trees.
fn tree_node(
    store: &mut Store,
    w: &mut Walk,
    path: &str,
    ents: [Option<TreeEntry>; 3],
) -> Result<()> {
    let id = |e: &Option<TreeEntry>| e.as_ref().map(|x| x.id);
    let (bi, oi, ti) = (id(&ents[0]), id(&ents[1]), id(&ents[2]));

    // Which entry would be carried, and is carrying it safe?
    let carry_from: Option<&Option<TreeEntry>> = if oi == ti || bi == ti {
        // ours == theirs, or only ours changed: ours is the answer.
        Some(&ents[1])
    } else if bi == oi {
        // only theirs changed.
        Some(&ents[2])
    } else {
        None
    };
    if let Some(src) = carry_from {
        match src {
            // The surviving result is a deletion: nothing to carry or read.
            None => return Ok(()),
            Some(entry) => {
                let identical = bi == oi && oi == ti;
                if identical || !w.intersects_rule(path) {
                    carry(w, path, entry);
                    return Ok(());
                }
            }
        }
    }

    // Recurse: read each present node (asking for the ones we lack) and visit
    // the union of their names.
    let mut trees: [Option<scl_core::Tree>; 3] = [None, None, None];
    let mut missing = false;
    for e in ents.iter().flatten() {
        if !store.contains(&e.id) {
            w.need(e.id, path, e.kind == EntryKind::Tree);
            missing = true;
        }
    }
    if missing {
        return Ok(());
    }
    for (i, e) in ents.iter().enumerate() {
        if let Some(e) = e {
            trees[i] = Some(store.get_tree(&e.id)?);
        }
    }
    let names: BTreeSet<String> = trees
        .iter()
        .flatten()
        .flat_map(|t| t.entries.iter().map(|e| e.name.clone()))
        .collect();
    for name in names {
        let child = |t: &Option<scl_core::Tree>| t.as_ref().and_then(|t| t.get(&name).cloned());
        let kids = [child(&trees[0]), child(&trees[1]), child(&trees[2])];
        visit(store, w, &join(path, &name), kids)?;
    }
    Ok(())
}

fn carry(w: &mut Walk, path: &str, entry: &TreeEntry) {
    if path.is_empty() {
        w.carried_root = Some(entry.id);
    } else {
        let mut e = entry.clone();
        e.name = path.rsplit('/').next().unwrap_or(path).to_string();
        w.carried.push((path.to_string(), e));
    }
}

/// A name is a blob on some sides and a tree on others. Flatten every side
/// that has a tree under this name (asking for what is absent), add the blob
/// sides as the path itself, and resolve per path with the shared leaf rules.
fn enumerate_mixed(
    store: &mut Store,
    w: &mut Walk,
    path: &str,
    ents: [Option<TreeEntry>; 3],
) -> Result<()> {
    let mut maps: [BTreeMap<String, FileEntry>; 3] = Default::default();
    for (i, e) in ents.iter().enumerate() {
        let Some(e) = e else { continue };
        match e.kind {
            EntryKind::Blob => {
                maps[i].insert(path.to_string(), file_entry(e));
            }
            EntryKind::Tree => flatten_present(store, w, e.id, path, &mut maps[i])?,
        }
    }
    let paths: BTreeSet<String> = maps.iter().flat_map(|m| m.keys().cloned()).collect();
    for p in paths {
        let [b, o, t] = [&maps[0], &maps[1], &maps[2]].map(|m| m.get(&p).copied());
        match merge_path(store, p.clone(), b, o, t, &w.prots, w.identity, &mut w.acc) {
            Ok(()) => {}
            Err(Error::Core(scl_core::Error::NotFound(id))) => w.need(id, &p, false),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Flatten a subtree to leaf entries, asking for any tree the store lacks.
fn flatten_present(
    store: &mut Store,
    w: &mut Walk,
    root: ObjectId,
    prefix: &str,
    out: &mut BTreeMap<String, FileEntry>,
) -> Result<()> {
    let mut stack = vec![(root, prefix.to_string())];
    while let Some((id, p)) = stack.pop() {
        if !store.contains(&id) {
            w.need(id, &p, true);
            continue;
        }
        let tree = store.get_tree(&id)?;
        for e in tree.entries {
            let child = join(&p, &e.name);
            match e.kind {
                EntryKind::Blob => {
                    out.insert(child, file_entry(&e));
                }
                EntryKind::Tree => stack.push((e.id, child)),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::three_way_files;
    use scl_core::{ProtectPrefix, PROTECTED};
    use scl_vfs::Repo as VfsRepo;
    use std::collections::HashSet;

    // ---- a tiny deterministic generator (no external RNG dependency) -------

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn chance(&mut self, num: u64, den: u64) -> bool {
            self.below(den) < num
        }
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Leaf {
        content: u8,
        exec: bool,
        prot: bool,
    }
    type Files = BTreeMap<String, Leaf>;

    fn leaf_bytes(l: &Leaf) -> Vec<u8> {
        let k = l.content;
        match (l.prot, k >= 4) {
            (true, _) => format!("cipher{k}").into_bytes(),
            (false, false) => format!("text line {k}\n").into_bytes(),
            (false, true) => vec![0xff, 0xfe, k],
        }
    }

    fn rand_path(rng: &mut Rng) -> String {
        const NAMES: [&str; 4] = ["a", "b", "c", "f"];
        let depth = 1 + rng.below(3) as usize;
        (0..depth)
            .map(|_| NAMES[rng.below(4) as usize])
            .collect::<Vec<_>>()
            .join("/")
    }

    fn collides(files: &Files, path: &str) -> bool {
        files.keys().any(|k| {
            k == path || k.starts_with(&format!("{path}/")) || path.starts_with(&format!("{k}/"))
        })
    }

    fn rand_leaf(rng: &mut Rng) -> Leaf {
        Leaf {
            content: rng.below(6) as u8,
            exec: rng.chance(1, 4),
            prot: rng.chance(1, 4),
        }
    }

    fn gen_base(rng: &mut Rng) -> Files {
        let mut f = Files::new();
        for _ in 0..rng.below(9) {
            let p = rand_path(rng);
            if !collides(&f, &p) {
                f.insert(p, rand_leaf(rng));
            }
        }
        f
    }

    /// A side derived from `base`: each file kept, deleted, edited or chmod'd,
    /// plus a few additions (which may collide with the other side's names).
    fn mutate(rng: &mut Rng, base: &Files, aggression: u64) -> Files {
        let mut f = Files::new();
        for (p, l) in base {
            if rng.chance(aggression, 10) {
                match rng.below(4) {
                    0 => continue, // delete
                    1 => {
                        let mut l = l.clone();
                        l.content = rng.below(6) as u8;
                        f.insert(p.clone(), l);
                    }
                    2 => {
                        let mut l = l.clone();
                        l.exec = !l.exec;
                        f.insert(p.clone(), l);
                    }
                    _ => {
                        let mut l = l.clone();
                        l.prot = !l.prot;
                        f.insert(p.clone(), l);
                    }
                }
            } else {
                f.insert(p.clone(), l.clone());
            }
        }
        for _ in 0..rng.below(3) {
            let p = rand_path(rng);
            if !collides(&f, &p) {
                f.insert(p, rand_leaf(rng));
            }
        }
        f
    }

    fn build(repo: &VfsRepo, files: &Files) -> ObjectId {
        let v: Vec<(String, Vec<u8>, FileMode, u8)> = files
            .iter()
            .map(|(p, l)| {
                (
                    p.clone(),
                    leaf_bytes(l),
                    if l.exec {
                        FileMode::EXEC
                    } else {
                        FileMode::FILE
                    },
                    if l.prot { PROTECTED } else { 0 },
                )
            })
            .collect();
        repo.write_tree_with_perms(&v).unwrap()
    }

    fn rand_policy(rng: &mut Rng) -> Protection {
        const RULES: [&str; 5] = ["a", "b/a", "c", "f", "b/c/f"];
        let mut p = Protection::default();
        for r in RULES {
            if rng.chance(1, 4) {
                p.prefixes.push(ProtectPrefix {
                    prefix: if rng.chance(1, 2) {
                        format!("{r}/")
                    } else {
                        r.to_string()
                    },
                    recipients: Vec::new(),
                });
            }
        }
        p
    }

    type Flat = BTreeMap<String, (FileMode, u8, Vec<u8>, bool)>;

    fn flat_of_files(files: &[crate::merge::MergedFile]) -> Flat {
        files
            .iter()
            .map(|f| {
                (
                    f.path.clone(),
                    (f.mode, f.perms, f.bytes.clone(), f.needs_encrypt),
                )
            })
            .collect()
    }

    fn expand(store: &mut Store, done: &TreeMergeDone) -> Flat {
        let mut flat = flat_of_files(&done.merge.files);
        let mut add = |store: &mut Store, prefix: &str, id: ObjectId| {
            for (p, (bid, mode, perms)) in
                crate::worktree::tree_file_entries_with_perms(store, id).unwrap()
            {
                let path = if prefix.is_empty() {
                    p
                } else {
                    format!("{prefix}/{p}")
                };
                let bytes = match store.get(&bid).unwrap() {
                    scl_core::Object::Blob(b) => b.to_vec(),
                    _ => panic!("expected blob"),
                };
                assert!(
                    flat.insert(path.clone(), (mode, perms, bytes, false))
                        .is_none(),
                    "carried {path} also enumerated"
                );
            }
        };
        match &done.carried {
            Carried::Root(id) => add(store, "", *id),
            Carried::Entries(v) => {
                for (path, e) in v {
                    add(store, path, e.id);
                }
            }
        }
        flat
    }

    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    fn sorted_sidecars(v: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
        let mut v = v.to_vec();
        v.sort();
        v
    }

    /// Tree id at `path` under `root` (None if absent or not a tree).
    fn tree_at(store: &mut Store, root: ObjectId, path: &str) -> Option<ObjectId> {
        let mut cur = root;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let t = store.get_tree(&cur).ok()?;
            let e = t.get(comp)?;
            if e.kind != EntryKind::Tree {
                return None;
            }
            cur = e.id;
        }
        Some(cur)
    }

    /// Every node (tree or blob) reachable from `root`, with its path.
    fn all_nodes(store: &mut Store, root: ObjectId) -> Vec<(String, ObjectId)> {
        let mut out = vec![(String::new(), root)];
        let mut stack = vec![(root, String::new())];
        while let Some((id, p)) = stack.pop() {
            let t = store.get_tree(&id).unwrap();
            for e in t.entries {
                let child = join(&p, &e.name);
                out.push((child.clone(), e.id));
                if e.kind == EntryKind::Tree {
                    stack.push((e.id, child));
                }
            }
        }
        out
    }

    fn carried_paths(c: &Carried) -> Vec<String> {
        match c {
            Carried::Root(_) => vec![String::new()],
            Carried::Entries(v) => v.iter().map(|(p, _)| p.clone()).collect(),
        }
    }

    fn under(path: &str, prefix: &str) -> bool {
        prefix.is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
    }

    fn rule_intersects(prots: &[&Protection], path: &str) -> bool {
        prots.iter().flat_map(|p| p.prefixes.iter()).any(|r| {
            let bare = r.prefix.trim_end_matches('/');
            path.is_empty()
                || path == bare
                || path.starts_with(&format!("{bare}/"))
                || bare.starts_with(&format!("{path}/"))
        })
    }

    #[derive(Default, Debug)]
    struct Coverage {
        merged: u32,
        carried_some: u32,
        carried_root: u32,
        conflicts: u32,
        sidecars: u32,
        needed_fill: u32,
        refused_collision: u32,
        refused_identity: u32,
    }

    /// One random case: the engine (on the full store, and on a store with
    /// objects removed and refilled on demand) against the flatten merge.
    fn run_case(seed: u64, cov: &mut Coverage) {
        let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        let base = gen_base(&mut rng);
        let aggr = 1 + rng.below(6);
        let ours = mutate(&mut rng, &base, aggr);
        let theirs = mutate(&mut rng, &base, aggr);
        let bp = rand_policy(&mut rng);
        let op = if rng.chance(2, 3) {
            bp.clone()
        } else {
            rand_policy(&mut rng)
        };
        let tp = if rng.chance(2, 3) {
            bp.clone()
        } else {
            rand_policy(&mut rng)
        };
        // Give each side wraps for (some of) its protected blobs, for a random
        // recipient subset, so the wrap union can be checked.
        let (mut bp, mut op, mut tp) = (bp, op, tp);
        for (files, prot) in [(&base, &mut bp), (&ours, &mut op), (&theirs, &mut tp)] {
            for l in files.values().filter(|l| l.prot) {
                let id = scl_core::Object::blob(leaf_bytes(l)).id();
                for r in ["r1", "r2", "r3"] {
                    if rng.chance(1, 2) {
                        prot.wrapped
                            .entry(id)
                            .or_default()
                            .push(scl_core::WrappedKey {
                                recipient_id: r.to_string(),
                                wrapped_dek: vec![rng.below(256) as u8],
                            });
                    }
                }
            }
        }

        let full_repo = VfsRepo::new(Store::with_budget(1 << 22));
        let (rb, ro, rt) = (
            build(&full_repo, &base),
            build(&full_repo, &ours),
            build(&full_repo, &theirs),
        );
        let arc = full_repo.store();
        let mut full = arc.lock().unwrap();

        let flat_res = three_way_files(&mut full, Some((rb, &bp)), (ro, &op), (rt, &tp), None);
        let eng_res = merge_trees(&mut full, Some((rb, &bp)), (ro, &op), (rt, &tp), None);

        match (flat_res, eng_res) {
            (Ok(fm), Ok(TreeMerge::Done(done))) => {
                cov.merged += 1;
                match &done.carried {
                    Carried::Root(_) => cov.carried_root += 1,
                    Carried::Entries(v) if !v.is_empty() => cov.carried_some += 1,
                    _ => {}
                }
                if !fm.conflicts.is_empty() {
                    cov.conflicts += 1;
                }
                if !fm.sidecars.is_empty() {
                    cov.sidecars += 1;
                }
                let want = flat_of_files(&fm.files);
                let got = expand(&mut full, &done);
                assert_eq!(got, want, "seed {seed}: file sets differ");
                assert_eq!(
                    sorted(done.merge.conflicts.clone()),
                    sorted(fm.conflicts.clone()),
                    "seed {seed}: conflicts differ"
                );
                assert_eq!(
                    sorted_sidecars(&done.merge.sidecars),
                    sorted_sidecars(&fm.sidecars),
                    "seed {seed}: sidecars differ"
                );

                // Wraps: the merged snapshot must keep every wrap the full merge
                // keeps, and lose none the inputs held for a protected blob that
                // survives in the result.
                let recips = |ws: Option<&Vec<scl_core::WrappedKey>>| -> BTreeSet<String> {
                    ws.map(|v| v.iter().map(|w| w.recipient_id.clone()).collect())
                        .unwrap_or_default()
                };
                let merged_wraps = done.merged_wraps(&op, &tp, &bp);
                for (id, wks) in &fm.wrapped_carry {
                    let want: BTreeSet<String> =
                        wks.iter().map(|w| w.recipient_id.clone()).collect();
                    assert!(
                        recips(merged_wraps.get(id)).is_superset(&want),
                        "seed {seed}: engine lost wraps the full merge keeps for {id}"
                    );
                }
                for (path, (_, perms, bytes, _)) in &got {
                    if perms & PROTECTED == 0 {
                        continue;
                    }
                    let id = scl_core::Object::blob(bytes.clone()).id();
                    let held: BTreeSet<String> = [&op, &tp, &bp]
                        .iter()
                        .flat_map(|p| recips(p.wrapped.get(&id)))
                        .collect();
                    if done.carried_any() {
                        assert!(
                            recips(merged_wraps.get(&id)).is_superset(&held),
                            "seed {seed}: carried merge dropped input wraps for protected {path}"
                        );
                    }
                }

                // Policy: a carried subtree is policy-disjoint, or identical
                // on all three sides.
                let prots = [&op, &tp, &bp];
                for path in carried_paths(&done.carried) {
                    let ids = [rb, ro, rt].map(|r| tree_at(&mut full, r, &path));
                    let identical = ids[0].is_some() && ids[0] == ids[1] && ids[1] == ids[2];
                    assert!(
                        identical || !rule_intersects(&prots, &path),
                        "seed {seed}: carried {path:?} intersects a rule and is not identical"
                    );
                }

                // The same case on a store with objects missing: the engine
                // asks for what it needs, never for anything under a carried
                // subtree, and ends with the same answer.
                let part_repo = VfsRepo::new(Store::with_budget(1 << 22));
                let _ = (
                    build(&part_repo, &base),
                    build(&part_repo, &ours),
                    build(&part_repo, &theirs),
                );
                let part_arc = part_repo.store();
                let mut part = part_arc.lock().unwrap();
                let mut universe: HashSet<ObjectId> = HashSet::new();
                for r in [rb, ro, rt] {
                    for (_, id) in all_nodes(&mut full, r) {
                        universe.insert(id);
                    }
                }
                let mut drop_rng = Rng(seed ^ 0xDEADBEEF | 1);
                for id in &universe {
                    if drop_rng.chance(1, 2) {
                        let _ = part.delete(id);
                    }
                }
                // Objects that appear at an uncarried path are fair game.
                let carried = carried_paths(&done.carried);
                let mut allowed: HashSet<ObjectId> = HashSet::new();
                for r in [rb, ro, rt] {
                    for (p, id) in all_nodes(&mut full, r) {
                        if !carried.iter().any(|c| {
                            if c.is_empty() {
                                !p.is_empty()
                            } else {
                                under(&p, c)
                            }
                        }) {
                            allowed.insert(id);
                        }
                    }
                    allowed.insert(r);
                }
                let mut node_paths: HashSet<(String, ObjectId)> = HashSet::new();
                for r in [rb, ro, rt] {
                    for (p, id) in all_nodes(&mut full, r) {
                        node_paths.insert((p, id));
                    }
                }
                let mut rounds = 0;
                let done2 = loop {
                    rounds += 1;
                    assert!(rounds < 64, "seed {seed}: fill loop did not converge");
                    match merge_trees(&mut part, Some((rb, &bp)), (ro, &op), (rt, &tp), None)
                        .unwrap_or_else(|e| panic!("seed {seed}: partial engine error {e:?}"))
                    {
                        TreeMerge::Done(d) => break d,
                        TreeMerge::Needs(list) => {
                            if rounds == 1 {
                                cov.needed_fill += 1;
                            }
                            assert!(!list.is_empty());
                            for Need { id, path, .. } in list {
                                assert!(
                                    allowed.contains(&id),
                                    "seed {seed}: asked for {id} under a carried subtree"
                                );
                                assert!(
                                    node_paths.contains(&(path.clone(), id)),
                                    "seed {seed}: Needs reported {path:?} for {id}, which is not where it lives"
                                );
                                let obj = full.get(&id).unwrap();
                                part.put(obj).unwrap();
                            }
                        }
                    }
                };
                // Carried subtrees may be absent on the partial store, so
                // compare against the full-store expansion via the full store.
                assert_eq!(
                    expand(&mut full, &done2),
                    want,
                    "seed {seed}: partial run differs"
                );
                assert_eq!(
                    sorted(done2.merge.conflicts.clone()),
                    sorted(fm.conflicts.clone()),
                    "seed {seed}: partial run conflicts differ"
                );
                assert_eq!(
                    sorted_sidecars(&done2.merge.sidecars),
                    sorted_sidecars(&fm.sidecars),
                    "seed {seed}: partial run sidecars differ"
                );
            }
            (Err(a), Err(b)) => {
                // Both refuse. The first error may differ (traversal order), but
                // both must be one of the deliberate refusals.
                for e in [&a, &b] {
                    match e {
                        Error::PathCollision(_) => cov.refused_collision += 1,
                        Error::ProtectedMergeNeedsIdentity(_) => cov.refused_identity += 1,
                        _ => {}
                    }
                }
                let ok = |e: &Error| {
                    matches!(
                        e,
                        Error::ProtectedMergeNeedsIdentity(_) | Error::PathCollision(_)
                    )
                };
                assert!(
                    ok(&a) && ok(&b),
                    "seed {seed}: unexpected errors {a:?} / {b:?}"
                );
            }
            (Ok(_), Ok(TreeMerge::Needs(n))) => {
                panic!("seed {seed}: engine asked for {n:?} on a full store")
            }
            (Ok(_), Err(e)) => panic!("seed {seed}: engine refused ({e:?}) but flatten merged"),
            (Err(e), Ok(_)) => panic!("seed {seed}: flatten refused ({e:?}) but engine merged"),
        }
    }

    #[test]
    fn engine_matches_the_flatten_merge_on_random_trees() {
        let mut cov = Coverage::default();
        for seed in 0..4000u64 {
            run_case(seed, &mut cov);
        }
        eprintln!("coverage: {cov:?}");
        // The generator must actually reach the interesting paths, or a green
        // run proves nothing.
        assert!(cov.merged > 1000, "{cov:?}");
        assert!(cov.carried_some > 300, "{cov:?}");
        assert!(cov.carried_root > 5, "{cov:?}");
        assert!(cov.conflicts > 100, "{cov:?}");
        assert!(cov.sidecars > 10, "{cov:?}");
        assert!(cov.needed_fill > 300, "{cov:?}");
        assert!(cov.refused_collision > 50, "{cov:?}");
        assert!(cov.refused_identity > 50, "{cov:?}");
    }

    // ---- named cases ------------------------------------------------------

    fn files(items: &[(&str, u8, bool)]) -> Files {
        items
            .iter()
            .map(|(p, c, prot)| {
                (
                    p.to_string(),
                    Leaf {
                        content: *c,
                        exec: false,
                        prot: *prot,
                    },
                )
            })
            .collect()
    }

    fn rule(prefix: &str) -> Protection {
        let mut p = Protection::default();
        p.prefixes.push(ProtectPrefix {
            prefix: prefix.to_string(),
            recipients: Vec::new(),
        });
        p
    }

    fn done(m: TreeMerge) -> TreeMergeDone {
        match m {
            TreeMerge::Done(d) => d,
            TreeMerge::Needs(n) => panic!("unexpected Needs {n:?}"),
        }
    }

    #[test]
    fn disjoint_edits_are_carried_unread() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = build(&repo, &files(&[("docs/x", 1, false), ("src/y", 1, false)]));
        let ours = build(&repo, &files(&[("docs/x", 2, false), ("src/y", 1, false)]));
        let theirs = build(&repo, &files(&[("docs/x", 1, false), ("src/y", 3, false)]));
        let p = rule("secret");
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let d =
            done(merge_trees(&mut s, Some((base, &p)), (ours, &p), (theirs, &p), None).unwrap());
        assert!(d.merge.files.is_empty(), "nothing was read");
        match d.carried {
            Carried::Entries(v) => {
                let paths: Vec<&str> = v.iter().map(|(p, _)| p.as_str()).collect();
                assert_eq!(paths, vec!["docs", "src"]);
            }
            other => panic!("expected entries, got {other:?}"),
        }
    }

    #[test]
    fn plaintext_under_a_sides_own_rule_is_enumerated_not_carried() {
        // Ours edits a file under `secret/`, which is ruled on ours, and the
        // file is plaintext (the state `protect` leaves before it encrypts).
        // A carry would keep the plaintext; the full merge would encrypt it.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = build(
            &repo,
            &files(&[("secret/f", 1, false), ("other/g", 1, false)]),
        );
        let ours = build(
            &repo,
            &files(&[("secret/f", 2, false), ("other/g", 1, false)]),
        );
        let p = rule("secret");
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let d = done(merge_trees(&mut s, Some((base, &p)), (ours, &p), (base, &p), None).unwrap());
        let f = d.merge.files.iter().find(|f| f.path == "secret/f").unwrap();
        assert_eq!(
            f.perms & PROTECTED,
            0,
            "still plaintext, so the repo layer encrypts it"
        );
        match d.carried {
            Carried::Entries(v) => {
                let paths: Vec<&str> = v.iter().map(|(p, _)| p.as_str()).collect();
                assert_eq!(
                    paths,
                    vec!["other"],
                    "only the policy-disjoint subtree is carried"
                );
            }
            other => panic!("expected entries, got {other:?}"),
        }
    }

    #[test]
    fn identical_subtree_under_a_rule_is_carried() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let all = build(&repo, &files(&[("secret/f", 1, false), ("a", 1, false)]));
        let ours = build(&repo, &files(&[("secret/f", 1, false), ("a", 2, false)]));
        let p = rule("secret");
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let d = done(merge_trees(&mut s, Some((all, &p)), (ours, &p), (all, &p), None).unwrap());
        match d.carried {
            Carried::Entries(v) => {
                assert!(
                    v.iter().any(|(p, _)| p == "secret"),
                    "identical on all three: carried"
                );
            }
            other => panic!("expected entries, got {other:?}"),
        }
    }

    #[test]
    fn identical_roots_carry_the_root() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let r = build(&repo, &files(&[("a/b", 1, false)]));
        let p = Protection::default();
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let d = done(merge_trees(&mut s, Some((r, &p)), (r, &p), (r, &p), None).unwrap());
        assert_eq!(d.carried, Carried::Root(r));
        assert!(d.merge.files.is_empty());
    }

    #[test]
    fn a_missing_subtree_in_the_differing_region_is_requested_with_its_path() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = build(&repo, &files(&[("d/x", 1, false)]));
        let ours = build(&repo, &files(&[("d/x", 2, false)]));
        let theirs = build(&repo, &files(&[("d/x", 3, false)]));
        let p = Protection::default();
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let d_ours = tree_at(&mut s, ours, "d").unwrap();
        s.delete(&d_ours).unwrap();
        match merge_trees(&mut s, Some((base, &p)), (ours, &p), (theirs, &p), None).unwrap() {
            TreeMerge::Needs(n) => assert_eq!(
                n,
                vec![Need {
                    id: d_ours,
                    path: "d".to_string(),
                    tree: true
                }]
            ),
            other => panic!("expected Needs, got {other:?}"),
        }
    }

    #[test]
    fn a_file_and_a_directory_with_the_same_name_collide() {
        // Ours adds file `x`; theirs adds directory `x/`: a mixed-kind name,
        // which the engine enumerates (it is never carried), so the collision
        // check sees both `x` and `x/y`.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let ours = build(&repo, &files(&[("x", 1, false)]));
        let theirs = build(&repo, &files(&[("x/y", 1, false)]));
        let p = Protection::default();
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let err = merge_trees(&mut s, None, (ours, &p), (theirs, &p), None).unwrap_err();
        assert!(matches!(err, Error::PathCollision(_)), "got {err:?}");
    }

    fn empty_done() -> TreeMerge {
        TreeMerge::Done(TreeMergeDone {
            merge: FileMerge {
                files: vec![],
                sidecars: vec![],
                conflicts: vec![],
                wrapped_carry: Default::default(),
            },
            carried: Carried::Entries(vec![]),
        })
    }

    fn blob_need(id: ObjectId, path: &str) -> Need {
        Need {
            id,
            path: path.into(),
            tree: false,
        }
    }

    #[test]
    fn fill_loop_fills_then_finishes_and_sums_the_cost() {
        let a = scl_core::Object::blob(b"a".to_vec()).id();
        let b = scl_core::Object::blob(b"b".to_vec()).id();
        let mut passes = vec![
            TreeMerge::Needs(vec![blob_need(a, "x")]),
            TreeMerge::Needs(vec![blob_need(b, "x/y")]),
            empty_done(),
        ]
        .into_iter();
        let mut filled: Vec<ObjectId> = Vec::new();
        let (_, stats) = fill_loop(
            || Ok(passes.next().unwrap()),
            |needs| {
                filled.extend(needs.iter().map(|n| n.id));
                Ok(FillStats {
                    requests: 1,
                    objects: needs.len(),
                })
            },
        )
        .unwrap();
        assert_eq!(filled, vec![a, b]);
        assert_eq!(
            stats,
            FillStats {
                requests: 2,
                objects: 2
            }
        );
    }

    #[test]
    fn fill_loop_fails_when_a_filled_id_is_asked_for_again() {
        // The store claims to hold the object (the fill succeeds) while the
        // traversal still cannot read it: without the guard this spins forever.
        let a = scl_core::Object::blob(b"a".to_vec()).id();
        let mut rounds = 0;
        let err = fill_loop(
            || Ok(TreeMerge::Needs(vec![blob_need(a, "x")])),
            |_| {
                rounds += 1;
                Ok(FillStats::default())
            },
        )
        .unwrap_err();
        assert_eq!(rounds, 1, "one fill, then the repeat is caught");
        assert!(
            matches!(&err, Error::Protocol(m) if m.contains("asked again")),
            "got {err:?}"
        );
    }
}
