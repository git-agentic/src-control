//! Three-way merge: find the common ancestor over the snapshot `parents` DAG,
//! then reconcile file trees and secret registries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use scl_core::{FileMode, Object, ObjectId, Protection, Store, WrappedKey, PROTECTED};

use crate::diff3;
use crate::error::{Error, Result};
use crate::protect;
use crate::worktree::tree_file_entries_with_perms;

/// *A* lowest common ancestor of `a` and `b` over the parent DAG, or `None` if
/// the two share no ancestor. Walks ancestors breadth-first from both tips. In a
/// criss-cross history there can be multiple incomparable LCAs; the one returned
/// is BFS-order-dependent and may differ if `a` and `b` are swapped.
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

/// One merged file in a [`FileMerge`] working set.
///
/// `bytes` carries ciphertext when a protected entry was resolved by
/// ciphertext-id fast path (`needs_encrypt: false` — the blob survives as-is,
/// its wraps travel in [`FileMerge::wrapped_carry`]); it carries plaintext when
/// a protected entry was content-merged (`needs_encrypt: true` — a later stage
/// must re-encrypt before committing). Plain files are always plaintext with
/// `perms: 0, needs_encrypt: false`.
///
/// Public (not `pub(crate)`) only because it is exposed through the public
/// [`Merge::files`] field; construction stays crate-internal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedFile {
    pub path: String,
    pub mode: FileMode,
    /// Ciphertext when carried; plaintext when `needs_encrypt`.
    pub bytes: Vec<u8>,
    /// Per-entry permission flags; [`scl_core::PROTECTED`] preserved.
    pub perms: u8,
    /// True iff `bytes` is decrypted plaintext that must be re-encrypted
    /// (and its DEK re-wrapped) before the merge result is committed.
    pub needs_encrypt: bool,
}

/// File-level result of a three-way tree merge (no secret registries).
/// Extracted from [`three_way`] so replay (P14) can merge trees against an
/// optional base — a root commit replays against the empty tree.
#[derive(Debug)]
pub(crate) struct FileMerge {
    pub files: Vec<MergedFile>,
    /// Sidecars to write to the working tree only (e.g. `foo.bin.theirs`);
    /// plaintext for protected binary conflicts.
    pub sidecars: Vec<(String, Vec<u8>)>,
    pub conflicts: Vec<String>,
    /// Wrapped DEKs for every surviving carried ciphertext blob, keyed by its
    /// id: the union (`protect::union_wraps`) over whichever input protections
    /// knew the blob. A later stage merges these into the snapshot's policy.
    pub wrapped_carry: BTreeMap<ObjectId, Vec<WrappedKey>>,
}

/// Resolved result of a three-way merge, ready to materialize.
pub struct Merge {
    /// Merged working set (text-conflict files contain markers;
    /// binary-conflict files keep ours' bytes).
    pub files: Vec<MergedFile>,
    /// Sidecars to write to the working tree only (e.g. `foo.bin.theirs`).
    pub sidecars: Vec<(String, Vec<u8>)>,
    /// Conflicted paths (empty => clean merge).
    pub conflicts: Vec<String>,
    /// Merged secret registry.
    pub secrets: BTreeMap<String, ObjectId>,
    /// Wrapped DEKs for every surviving carried ciphertext blob (see
    /// [`FileMerge::wrapped_carry`]) — threaded up from `three_way_files` so
    /// `Repo::merge_with_identity` (P15) can union it with freshly-encrypted
    /// wraps without a second file-tree walk. Extending `Merge` rather than
    /// having callers reach into `FileMerge` directly keeps `three_way`'s
    /// signature the single seam repo.rs depends on.
    pub wrapped_carry: BTreeMap<ObjectId, Vec<WrappedKey>>,
}

/// Three-way merge of the file trees and secret registries of `ours`/`theirs`
/// against their `base` snapshot. `identity` gates content merges of protected
/// paths: without one, any protected path that diverged in content on both
/// sides fails with [`Error::ProtectedMergeNeedsIdentity`].
pub fn three_way(
    store: &mut Store,
    base: ObjectId,
    ours: ObjectId,
    theirs: ObjectId,
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<Merge> {
    let base_snap = store.get_snapshot(&base)?;
    let ours_snap = store.get_snapshot(&ours)?;
    let theirs_snap = store.get_snapshot(&theirs)?;

    let secrets = merge_secrets(&base_snap.secrets, &ours_snap.secrets, &theirs_snap.secrets)?;

    let fm = three_way_files(
        store,
        Some((base_snap.root, &base_snap.protection)),
        (ours_snap.root, &ours_snap.protection),
        (theirs_snap.root, &theirs_snap.protection),
        identity,
    )?;

    Ok(Merge {
        files: fm.files,
        sidecars: fm.sidecars,
        conflicts: fm.conflicts,
        secrets,
        wrapped_carry: fm.wrapped_carry,
    })
}

/// Three-way merge of file trees by root id, each paired with its snapshot's
/// protection policy (consulted for wrapped DEKs). `base: None` is the empty
/// base: every path reads as absent on the base side.
///
/// A path is *protected* iff any side's entry carries the [`PROTECTED`] bit.
/// Protected paths resolve by ciphertext-id fast path where possible (no
/// identity needed: the surviving ciphertext is carried verbatim and its wraps
/// recorded in [`FileMerge::wrapped_carry`]). Content-divergent protected
/// paths require `identity` to decrypt the inputs and diff3 the plaintexts;
/// their outputs are plaintext flagged `needs_encrypt`.
pub(crate) fn three_way_files(
    store: &mut Store,
    base: Option<(ObjectId, &Protection)>,
    ours: (ObjectId, &Protection),
    theirs: (ObjectId, &Protection),
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<FileMerge> {
    let default_prot = Protection::default();
    let (base_f, base_prot) = match base {
        Some((r, p)) => (tree_file_entries_with_perms(store, r)?, p),
        None => (Default::default(), &default_prot),
    };
    let (ours_root, ours_prot) = ours;
    let (theirs_root, theirs_prot) = theirs;
    let ours_f = tree_file_entries_with_perms(store, ours_root)?;
    let theirs_f = tree_file_entries_with_perms(store, theirs_root)?;
    // Wrap lookups search the sides first (their policies are current), then
    // base (the only holder of wraps for blobs both sides replaced).
    let prots: [&Protection; 3] = [ours_prot, theirs_prot, base_prot];

    let mut paths: BTreeSet<String> = BTreeSet::new();
    paths.extend(base_f.keys().cloned());
    paths.extend(ours_f.keys().cloned());
    paths.extend(theirs_f.keys().cloned());

    let mut files: Vec<MergedFile> = Vec::new();
    let mut sidecars = Vec::new();
    let mut conflicts = Vec::new();
    let mut wrapped_carry: BTreeMap<ObjectId, Vec<WrappedKey>> = BTreeMap::new();

    for path in paths {
        let b = base_f.get(&path).copied();
        let o = ours_f.get(&path).copied();
        let t = theirs_f.get(&path).copied();

        if ![b, o, t].iter().flatten().any(|e| e.2 & PROTECTED != 0) {
            // ---- all-plain arm: pre-P15 logic verbatim ----

            // Resolve by blob id first (cheap, covers unchanged/one-sided/delete).
            let bo = b.map(|x| x.0);
            let oo = o.map(|x| x.0);
            let to = t.map(|x| x.0);

            if oo == to {
                // same on both sides (including both-deleted) — take ours if present
                if let Some((id, mode, _)) = o {
                    files.push(plain(path, mode, blob_bytes(store, id)?));
                }
                continue;
            }
            if oo == bo {
                // only theirs changed -> take theirs (present or deleted)
                if let Some((id, mode, _)) = t {
                    files.push(plain(path, mode, blob_bytes(store, id)?));
                }
                continue;
            }
            if to == bo {
                // only ours changed -> take ours
                if let Some((id, mode, _)) = o {
                    files.push(plain(path, mode, blob_bytes(store, id)?));
                }
                continue;
            }

            // Both sides changed differently.
            match (o, t) {
                (Some((oid, omode, _)), Some((tid, tmode, _))) => {
                    // Mode resolves like Git: executable if either side is.
                    let mode = if omode == FileMode::EXEC || tmode == FileMode::EXEC {
                        FileMode::EXEC
                    } else {
                        FileMode::FILE
                    };
                    let ob = blob_bytes(store, oid)?;
                    let tb = blob_bytes(store, tid)?;
                    let bb = match b {
                        Some((bid, _, _)) => blob_bytes(store, bid)?,
                        None => Vec::new(),
                    };
                    match (std::str::from_utf8(&ob), std::str::from_utf8(&tb)) {
                        (Ok(os), Ok(ts)) => {
                            // A non-UTF-8 base falls back to an empty base (rare
                            // encoding-change case): yields a conservative conflict,
                            // never corruption.
                            let base_text = std::str::from_utf8(&bb).unwrap_or("");
                            let m = diff3::merge_lines(base_text, os, ts);
                            if m.conflicted {
                                conflicts.push(path.clone());
                            }
                            files.push(plain(path, mode, m.text.into_bytes()));
                        }
                        _ => {
                            // binary conflict: keep ours, write theirs sidecar
                            conflicts.push(path.clone());
                            sidecars.push((format!("{path}.theirs"), tb));
                            files.push(plain(path, mode, ob));
                        }
                    }
                }
                // delete/modify: one side deleted, the other modified -> conflict;
                // keep the surviving (modified) content and mark conflicted.
                (Some((oid, omode, _)), None) => {
                    conflicts.push(path.clone());
                    files.push(plain(path, omode, blob_bytes(store, oid)?));
                }
                (None, Some((tid, tmode, _))) => {
                    conflicts.push(path.clone());
                    files.push(plain(path, tmode, blob_bytes(store, tid)?));
                }
                (None, None) => unreachable!("oo==to already handled the both-absent case"),
            }
            continue;
        }

        // ---- protected arm ----
        // Fast paths compare (raw blob id, PROTECTED bit): the id logic of the
        // plain arm transfers directly to ciphertext ids, but a PROTECTED-bit
        // flip alone is also a change, so the bit joins the comparison key. Any
        // resolution here carries the winner's raw bytes verbatim — ciphertext
        // is never decrypted on a fast path, so no identity is needed.
        let key = |e: Option<(ObjectId, FileMode, u8)>| e.map(|(id, _, p)| (id, p & PROTECTED));
        let (bk, ok, tk) = (key(b), key(o), key(t));

        let winner = if ok == tk {
            // same on both sides (including both-deleted) — take ours if present
            Some(o)
        } else if ok == bk {
            // only theirs changed -> take theirs (present or cleanly deleted)
            Some(t)
        } else if tk == bk {
            // only ours changed -> take ours
            Some(o)
        } else {
            None
        };
        if let Some(w) = winner {
            if let Some((id, mode, perms)) = w {
                if perms & PROTECTED != 0 {
                    // Unioning wraps across ours/theirs/base means a wrap
                    // revoked on only ONE side is resurrected for an unchanged
                    // blob — consistent with P11's revoke-is-metadata-only
                    // stance (ADR-0019): the old DEK was never secret from a
                    // past recipient anyway; a cryptographic cutover requires
                    // `secret rotate` / re-wrap, not a merge.
                    let wraps = known_wraps(&prots, &id);
                    if !wraps.is_empty() {
                        wrapped_carry.insert(id, wraps);
                    }
                    // An empty union (no input protection knows this blob)
                    // gets no wrapped_carry entry, not an error: the input was
                    // already undecryptable on every side — the merge
                    // preserves that state, it never worsens it.
                }
                files.push(MergedFile {
                    path,
                    mode,
                    bytes: blob_bytes(store, id)?,
                    perms,
                    needs_encrypt: false,
                });
            }
            continue;
        }

        // Content-divergent (both differ from base and each other; delete-vs-
        // modify; or the PROTECTED bit itself differs between sides): protected
        // inputs must be decrypted, which requires an identity — enforced
        // inside `plain_input`, so a case that only touches plain inputs (e.g.
        // delete-vs-modify with a plain survivor) still resolves without one.
        match (o, t) {
            (Some(oe), Some(te)) => {
                // Mode resolves like Git: executable if either side is.
                let mode = if oe.1 == FileMode::EXEC || te.1 == FileMode::EXEC {
                    FileMode::EXEC
                } else {
                    FileMode::FILE
                };
                // The PROTECTED bit resolves like the exec bit: protected if
                // either side is. (A protected base with two plain sides means
                // the rule was removed on both — the output stays plain.)
                let perms = (oe.2 | te.2) & PROTECTED;
                let needs_encrypt = perms != 0;
                // Decrypted inputs stay in `Zeroizing` until the final output
                // copy; `bb` never leaves it — the base plaintext is only read
                // for diff3 and is wiped when it drops.
                let ob = plain_input(store, oe, &prots, identity, &path)?;
                let tb = plain_input(store, te, &prots, identity, &path)?;
                let bb = match b {
                    Some(be) => plain_input(store, be, &prots, identity, &path)?,
                    None => scl_crypto::Zeroizing::new(Vec::new()),
                };
                match (std::str::from_utf8(&ob), std::str::from_utf8(&tb)) {
                    (Ok(os), Ok(ts)) => {
                        // Same non-UTF-8-base fallback as the plain arm.
                        let base_text = std::str::from_utf8(&bb).unwrap_or("");
                        let m = diff3::merge_lines(base_text, os, ts);
                        if m.conflicted {
                            conflicts.push(path.clone());
                        }
                        files.push(MergedFile {
                            path,
                            mode,
                            bytes: m.text.into_bytes(),
                            perms,
                            needs_encrypt,
                        });
                    }
                    _ => {
                        // binary conflict: keep ours, write theirs sidecar —
                        // both in plaintext, so the user can resolve.
                        conflicts.push(path.clone());
                        sidecars.push((format!("{path}.theirs"), tb.to_vec()));
                        files.push(MergedFile {
                            path,
                            mode,
                            bytes: ob.to_vec(),
                            perms,
                            needs_encrypt,
                        });
                    }
                }
            }
            // delete/modify: one side deleted, the other modified -> conflict;
            // keep the surviving (modified) content — decrypted to plaintext
            // when protected, so conflict resolution sees the real content.
            (Some(oe), None) | (None, Some(oe)) => {
                conflicts.push(path.clone());
                let perms = oe.2 & PROTECTED;
                let bytes = plain_input(store, oe, &prots, identity, &path)?;
                files.push(MergedFile {
                    path,
                    mode: oe.1,
                    bytes: bytes.to_vec(),
                    perms,
                    needs_encrypt: perms != 0,
                });
            }
            (None, None) => unreachable!("ok==tk already handled the both-absent case"),
        }
    }

    Ok(FileMerge { files, sidecars, conflicts, wrapped_carry })
}

/// Shorthand for an unprotected [`MergedFile`].
fn plain(path: String, mode: FileMode, bytes: Vec<u8>) -> MergedFile {
    MergedFile { path, mode, bytes, perms: 0, needs_encrypt: false }
}

/// Union of every wrap the given protections know for `id` (deduped by
/// recipient, deterministic order).
fn known_wraps(prots: &[&Protection], id: &ObjectId) -> Vec<WrappedKey> {
    let mut wraps: Vec<WrappedKey> = Vec::new();
    for p in prots {
        if let Some(w) = p.wrapped.get(id) {
            wraps = protect::union_wraps(&wraps, w);
        }
    }
    wraps
}

/// A merge input's plaintext: raw bytes for a plain entry; for a PROTECTED
/// entry, decrypt via the wraps known to `prots` — which requires `identity`
/// ([`Error::ProtectedMergeNeedsIdentity`] when absent, `NotAuthorized` when
/// present but no wrap unwraps for it).
///
/// Returned in `Zeroizing` so decrypted plaintext is wiped on drop (same
/// convention as `worktree::materialize`, worktree.rs ~301): callers copy out
/// only at the final output step, and an input that never reaches the output
/// (notably the base side) is zeroed without ever leaving the wrapper.
fn plain_input(
    store: &mut Store,
    entry: (ObjectId, FileMode, u8),
    prots: &[&Protection],
    identity: Option<&scl_crypto::SecretKey>,
    path: &str,
) -> Result<scl_crypto::Zeroizing<Vec<u8>>> {
    let bytes = blob_bytes(store, entry.0)?;
    if entry.2 & PROTECTED == 0 {
        return Ok(scl_crypto::Zeroizing::new(bytes));
    }
    let sk = identity.ok_or_else(|| Error::ProtectedMergeNeedsIdentity(path.to_string()))?;
    Ok(protect::decrypt_with(&bytes, &entry.0, prots, sk, path)?)
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
                protection: Default::default(),
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
            protection: Default::default(),
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
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert!(m.conflicts.is_empty());
        let shared = m.files.iter().find(|f| f.path == "shared.txt").unwrap();
        assert_eq!(shared.bytes, b"a\nB\nC\n");
        assert!(m.files.iter().any(|f| f.path == "ours.txt"));
    }

    #[test]
    fn overlapping_lines_conflict() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(&repo, &[("f.txt", "a\nb\nc\n")], vec![]);
        let ours = commit_files(&repo, &[("f.txt", "a\nX\nc\n")], vec![base]);
        let theirs = commit_files(&repo, &[("f.txt", "a\nY\nc\n")], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert_eq!(m.conflicts, vec!["f.txt"]);
        let f = &m.files.iter().find(|f| f.path == "f.txt").unwrap().bytes;
        assert!(String::from_utf8_lossy(f).contains("<<<<<<< ours"));
    }

    /// Like `commit_files` but takes raw bytes, so non-UTF-8 blobs can be built.
    fn commit_bytes(
        store_repo: &VfsRepo,
        files: &[(&str, Vec<u8>)],
        parents: Vec<ObjectId>,
    ) -> ObjectId {
        let fs: Vec<(String, Vec<u8>, FileMode)> = files
            .iter()
            .map(|(p, c)| (p.to_string(), c.clone(), FileMode::FILE))
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
            protection: Default::default(),
        }))
        .unwrap()
    }

    #[test]
    fn delete_modify_ours_deletes_theirs_modifies_conflict() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(&repo, &[("f.txt", "a\nb\nc\n")], vec![]);
        // ours deletes f.txt (absent from the file set)
        let ours = commit_files(&repo, &[("keep.txt", "k\n")], vec![base]);
        // theirs modifies f.txt
        let theirs = commit_files(&repo, &[("f.txt", "a\nB\nc\n")], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert_eq!(m.conflicts, vec!["f.txt"]);
        // surviving (theirs') content is kept
        let f = m.files.iter().find(|f| f.path == "f.txt").unwrap();
        assert_eq!(f.bytes, b"a\nB\nc\n");
    }

    #[test]
    fn delete_modify_ours_modifies_theirs_deletes_conflict() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(&repo, &[("f.txt", "a\nb\nc\n")], vec![]);
        // ours modifies f.txt
        let ours = commit_files(&repo, &[("f.txt", "a\nB\nc\n")], vec![base]);
        // theirs deletes f.txt
        let theirs = commit_files(&repo, &[("keep.txt", "k\n")], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert_eq!(m.conflicts, vec!["f.txt"]);
        let f = m.files.iter().find(|f| f.path == "f.txt").unwrap();
        assert_eq!(f.bytes, b"a\nB\nc\n");
    }

    #[test]
    fn both_deleted_is_clean_and_absent() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(&repo, &[("f.txt", "a\nb\nc\n"), ("keep.txt", "k\n")], vec![]);
        // both sides delete f.txt
        let ours = commit_files(&repo, &[("keep.txt", "k\n")], vec![base]);
        let theirs = commit_files(&repo, &[("keep.txt", "k\n")], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert!(m.conflicts.is_empty());
        assert!(!m.files.iter().any(|f| f.path == "f.txt"));
    }

    #[test]
    fn one_sided_delete_is_clean_and_absent() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(&repo, &[("f.txt", "a\nb\nc\n"), ("keep.txt", "k\n")], vec![]);
        // ours deletes f.txt; theirs leaves it unchanged
        let ours = commit_files(&repo, &[("keep.txt", "k\n")], vec![base]);
        let theirs = commit_files(&repo, &[("f.txt", "a\nb\nc\n"), ("keep.txt", "k\n")], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert!(m.conflicts.is_empty());
        assert!(!m.files.iter().any(|f| f.path == "f.txt"));
    }

    #[test]
    fn binary_conflict_keeps_ours_and_writes_sidecar() {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_bytes(&repo, &[("b.bin", vec![0x00])], vec![]);
        // two different non-UTF-8 byte sequences
        let ours = commit_bytes(&repo, &[("b.bin", vec![0xff, 0x00])], vec![base]);
        let theirs = commit_bytes(&repo, &[("b.bin", vec![0x00, 0xff])], vec![base]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert_eq!(m.conflicts, vec!["b.bin"]);
        // sidecar with theirs' bytes
        let sidecar = m.sidecars.iter().find(|(p, _)| p == "b.bin.theirs").unwrap();
        assert_eq!(sidecar.1, vec![0x00, 0xff]);
        // file kept with ours' bytes
        let f = m.files.iter().find(|f| f.path == "b.bin").unwrap();
        assert_eq!(f.bytes, vec![0xff, 0x00]);
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

    // ---- P15: perms-aware three_way_files ----

    use scl_core::{Protection, PROTECTED};

    /// Convergently encrypt `content`, wrap its DEK for `pk`, and register the
    /// wrap in `prot` under the ciphertext blob's id. Returns the ciphertext.
    fn enc_file(prot: &mut Protection, pk: &scl_crypto::PublicKey, content: &[u8]) -> Vec<u8> {
        let (cipher, dek) = scl_crypto::encrypt_path(content);
        let id = Object::blob(cipher.clone()).id();
        prot.wrapped
            .entry(id)
            .or_default()
            .push(scl_crypto::wrap_dek_for(&dek, pk));
        cipher
    }

    /// Write a tree whose files carry explicit `perms` bytes; returns its root id.
    fn tree_with_perms(repo: &VfsRepo, files: &[(&str, Vec<u8>, u8)]) -> ObjectId {
        let fs: Vec<(String, Vec<u8>, FileMode, u8)> = files
            .iter()
            .map(|(p, c, perms)| (p.to_string(), c.clone(), FileMode::FILE, *perms))
            .collect();
        repo.write_tree_with_perms(&fs).unwrap()
    }

    #[test]
    fn protected_id_fast_paths_need_no_identity() {
        // One side edits secret/a.txt, the other edits secret/b.txt: both
        // resolve by ciphertext-id equality — no identity, no decryption.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mut bp, mut op, mut tp) =
            (Protection::default(), Protection::default(), Protection::default());
        let a1 = enc_file(&mut bp, &alice_pk, b"a1\n");
        let b1 = enc_file(&mut bp, &alice_pk, b"b1\n");
        let a2 = enc_file(&mut op, &alice_pk, b"a2\n");
        let b1_o = enc_file(&mut op, &alice_pk, b"b1\n");
        let a1_t = enc_file(&mut tp, &alice_pk, b"a1\n");
        let b2 = enc_file(&mut tp, &alice_pk, b"b2\n");
        let base = tree_with_perms(
            &repo,
            &[("secret/a.txt", a1, PROTECTED), ("secret/b.txt", b1, PROTECTED)],
        );
        let ours = tree_with_perms(
            &repo,
            &[("secret/a.txt", a2.clone(), PROTECTED), ("secret/b.txt", b1_o, PROTECTED)],
        );
        let theirs = tree_with_perms(
            &repo,
            &[("secret/a.txt", a1_t, PROTECTED), ("secret/b.txt", b2.clone(), PROTECTED)],
        );
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let fm =
            three_way_files(&mut s, Some((base, &bp)), (ours, &op), (theirs, &tp), None).unwrap();
        assert!(fm.conflicts.is_empty());
        let fa = fm.files.iter().find(|f| f.path == "secret/a.txt").unwrap();
        assert_eq!(fa.bytes, a2, "ours' edit carried as ciphertext");
        let fb = fm.files.iter().find(|f| f.path == "secret/b.txt").unwrap();
        assert_eq!(fb.bytes, b2, "theirs' edit carried as ciphertext");
        assert!(fm.files.iter().all(|f| !f.needs_encrypt));
        assert!(fm.files.iter().all(|f| f.perms & PROTECTED != 0));
        let a2_id = Object::blob(a2).id();
        let b2_id = Object::blob(b2).id();
        assert!(fm.wrapped_carry.contains_key(&a2_id), "surviving a.txt blob's wraps carried");
        assert!(fm.wrapped_carry.contains_key(&b2_id), "surviving b.txt blob's wraps carried");
    }

    /// Fixture for the content-divergent cases: secret/a.txt protected on all
    /// three sides with distinct contents. Returns (repo, roots, protections).
    fn divergent_protected_fixture(
        pk: &scl_crypto::PublicKey,
        base_c: &[u8],
        ours_c: &[u8],
        theirs_c: &[u8],
    ) -> (VfsRepo, (ObjectId, Protection), (ObjectId, Protection), (ObjectId, Protection)) {
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (mut bp, mut op, mut tp) =
            (Protection::default(), Protection::default(), Protection::default());
        let cb = enc_file(&mut bp, pk, base_c);
        let co = enc_file(&mut op, pk, ours_c);
        let ct = enc_file(&mut tp, pk, theirs_c);
        let base = tree_with_perms(&repo, &[("secret/a.txt", cb, PROTECTED)]);
        let ours = tree_with_perms(&repo, &[("secret/a.txt", co, PROTECTED)]);
        let theirs = tree_with_perms(&repo, &[("secret/a.txt", ct, PROTECTED)]);
        (repo, (base, bp), (ours, op), (theirs, tp))
    }

    #[test]
    fn protected_both_changed_requires_identity() {
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (repo, (base, bp), (ours, op), (theirs, tp)) =
            divergent_protected_fixture(&alice_pk, b"a1\n", b"a2\n", b"a3\n");
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let err = three_way_files(&mut s, Some((base, &bp)), (ours, &op), (theirs, &tp), None)
            .unwrap_err();
        assert!(
            matches!(&err, Error::ProtectedMergeNeedsIdentity(p) if p == "secret/a.txt"),
            "got {err:?}"
        );
    }

    #[test]
    fn protected_both_changed_merges_plaintext_with_identity() {
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        // Non-overlapping line edits: ours edits line 1, theirs edits line 3.
        let (repo, (base, bp), (ours, op), (theirs, tp)) = divergent_protected_fixture(
            &alice_pk,
            b"l1\nl2\nl3\n",
            b"L1\nl2\nl3\n",
            b"l1\nl2\nL3\n",
        );
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let fm = three_way_files(
            &mut s,
            Some((base, &bp)),
            (ours, &op),
            (theirs, &tp),
            Some(&alice_sk),
        )
        .unwrap();
        assert!(fm.conflicts.is_empty());
        assert_eq!(fm.files.len(), 1);
        let f = &fm.files[0];
        assert_eq!(f.path, "secret/a.txt");
        assert!(f.needs_encrypt, "content merge outputs plaintext pending re-encryption");
        assert!(f.perms & PROTECTED != 0);
        assert_eq!(f.bytes, b"L1\nl2\nL3\n", "both edits present in plaintext");
    }

    #[test]
    fn protected_conflict_carries_plaintext_markers() {
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        // Same-line edits conflict.
        let (repo, (base, bp), (ours, op), (theirs, tp)) = divergent_protected_fixture(
            &alice_pk,
            b"l1\nl2\nl3\n",
            b"l1\nOURS\nl3\n",
            b"l1\nTHEIRS\nl3\n",
        );
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let fm = three_way_files(
            &mut s,
            Some((base, &bp)),
            (ours, &op),
            (theirs, &tp),
            Some(&alice_sk),
        )
        .unwrap();
        assert_eq!(fm.conflicts, vec!["secret/a.txt"]);
        let f = fm.files.iter().find(|f| f.path == "secret/a.txt").unwrap();
        let text = String::from_utf8_lossy(&f.bytes);
        assert!(text.contains("<<<<<<<"), "markers present: {text}");
        assert!(text.contains("OURS") && text.contains("THEIRS"), "both plaintexts: {text}");
        assert!(f.needs_encrypt);
    }

    #[test]
    fn unauthorized_identity_is_not_authorized() {
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        let (repo, (base, bp), (ours, op), (theirs, tp)) =
            divergent_protected_fixture(&alice_pk, b"a1\n", b"a2\n", b"a3\n");
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let err = three_way_files(
            &mut s,
            Some((base, &bp)),
            (ours, &op),
            (theirs, &tp),
            Some(&mallory_sk),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotAuthorized(_)), "got {err:?}");
    }

    // ---- pinning tests for the decided resolution-rule edges (review) ----

    #[test]
    fn one_sided_protect_resolves_keyless() {
        // Decided edge #1: fast-path keys are (blob id, PROTECTED bit). ours
        // left x.txt untouched (equal to base in id AND bit); theirs added the
        // rule and re-encrypted. This is a one-sided change: resolved with NO
        // identity, carrying theirs' ciphertext + PROTECTED + wraps.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bp, op) = (Protection::default(), Protection::default());
        let mut tp = Protection::default();
        let ct = enc_file(&mut tp, &alice_pk, b"hello\n");
        let base = tree_with_perms(&repo, &[("x.txt", b"hello\n".to_vec(), 0)]);
        let ours = tree_with_perms(&repo, &[("x.txt", b"hello\n".to_vec(), 0)]);
        let theirs = tree_with_perms(&repo, &[("x.txt", ct.clone(), PROTECTED)]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let fm =
            three_way_files(&mut s, Some((base, &bp)), (ours, &op), (theirs, &tp), None).unwrap();
        assert!(fm.conflicts.is_empty());
        let f = fm.files.iter().find(|f| f.path == "x.txt").unwrap();
        assert_eq!(f.bytes, ct, "theirs' ciphertext carried verbatim");
        assert!(f.perms & PROTECTED != 0);
        assert!(!f.needs_encrypt);
        assert!(fm.wrapped_carry.contains_key(&Object::blob(ct).id()));
    }

    #[test]
    fn delete_vs_modify_plain_survivor_needs_no_identity() {
        // Decided edge #2: identity is demanded lazily, per protected input
        // actually read. Base was protected, ours removed the rule and
        // modified (plain survivor), theirs deleted: the survivor is plain,
        // base is never consulted for delete-vs-modify — no identity needed.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let mut bp = Protection::default();
        let (op, tp) = (Protection::default(), Protection::default());
        let cb = enc_file(&mut bp, &alice_pk, b"secret\n");
        let base = tree_with_perms(&repo, &[("f.txt", cb, PROTECTED), ("keep.txt", b"k\n".to_vec(), 0)]);
        let ours = tree_with_perms(&repo, &[("f.txt", b"public\n".to_vec(), 0), ("keep.txt", b"k\n".to_vec(), 0)]);
        let theirs = tree_with_perms(&repo, &[("keep.txt", b"k\n".to_vec(), 0)]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let fm =
            three_way_files(&mut s, Some((base, &bp)), (ours, &op), (theirs, &tp), None).unwrap();
        assert_eq!(fm.conflicts, vec!["f.txt"], "delete-vs-modify still conflicts");
        let f = fm.files.iter().find(|f| f.path == "f.txt").unwrap();
        assert_eq!(f.bytes, b"public\n", "plain survivor kept as-is");
        assert_eq!(f.perms, 0);
        assert!(!f.needs_encrypt);
    }

    #[test]
    fn protected_base_plain_divergent_sides_decrypts_base_outputs_plain() {
        // Decided edge #3: rule removed on both sides (historically), sides
        // diverged in plaintext. The protected BASE must be decrypted so
        // diff3 has the true ancestor (identity required), but the output is
        // plain — both sides chose plain, so perms 0 / needs_encrypt false.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let mut bp = Protection::default();
        let (op, tp) = (Protection::default(), Protection::default());
        let cb = enc_file(&mut bp, &alice_pk, b"l1\nl2\nl3\n");
        let base = tree_with_perms(&repo, &[("f.txt", cb, PROTECTED)]);
        let ours = tree_with_perms(&repo, &[("f.txt", b"L1\nl2\nl3\n".to_vec(), 0)]);
        let theirs = tree_with_perms(&repo, &[("f.txt", b"l1\nl2\nL3\n".to_vec(), 0)]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        // Without an identity the base can't be decrypted for the ancestor.
        let err = three_way_files(&mut s, Some((base, &bp)), (ours, &op), (theirs, &tp), None)
            .unwrap_err();
        assert!(matches!(&err, Error::ProtectedMergeNeedsIdentity(p) if p == "f.txt"), "got {err:?}");
        // With one, the merge is clean against the true ancestor and PLAIN.
        let fm = three_way_files(
            &mut s,
            Some((base, &bp)),
            (ours, &op),
            (theirs, &tp),
            Some(&alice_sk),
        )
        .unwrap();
        assert!(fm.conflicts.is_empty());
        let f = fm.files.iter().find(|f| f.path == "f.txt").unwrap();
        assert_eq!(f.bytes, b"L1\nl2\nL3\n");
        assert_eq!(f.perms, 0, "both sides removed the rule — output stays plain");
        assert!(!f.needs_encrypt);
    }

    #[test]
    fn delete_vs_modify_protected_survivor_decrypts_with_identity() {
        // Decided edge #4: a PROTECTED survivor of delete-vs-modify is
        // decrypted (identity-gated) so the conflicted file is resolvable in
        // plaintext, flagged needs_encrypt.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let mut bp = Protection::default();
        let mut op = Protection::default();
        let tp = Protection::default();
        let cb = enc_file(&mut bp, &alice_pk, b"v1\n");
        let co = enc_file(&mut op, &alice_pk, b"v2\n");
        let base = tree_with_perms(&repo, &[("secret/f", cb, PROTECTED), ("keep.txt", b"k\n".to_vec(), 0)]);
        let ours = tree_with_perms(&repo, &[("secret/f", co, PROTECTED), ("keep.txt", b"k\n".to_vec(), 0)]);
        let theirs = tree_with_perms(&repo, &[("keep.txt", b"k\n".to_vec(), 0)]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        // Keyless: the protected survivor can't be decrypted.
        let err = three_way_files(&mut s, Some((base, &bp)), (ours, &op), (theirs, &tp), None)
            .unwrap_err();
        assert!(matches!(&err, Error::ProtectedMergeNeedsIdentity(p) if p == "secret/f"), "got {err:?}");
        // With identity: conflict marked, survivor in plaintext, needs_encrypt.
        let fm = three_way_files(
            &mut s,
            Some((base, &bp)),
            (ours, &op),
            (theirs, &tp),
            Some(&alice_sk),
        )
        .unwrap();
        assert_eq!(fm.conflicts, vec!["secret/f"]);
        let f = fm.files.iter().find(|f| f.path == "secret/f").unwrap();
        assert_eq!(f.bytes, b"v2\n", "surviving (modified) plaintext kept");
        assert!(f.perms & PROTECTED != 0);
        assert!(f.needs_encrypt);
    }

    #[test]
    fn wrapped_carry_unions_wraps_from_both_sides() {
        // Decided edge #5: an unchanged protected blob whose sides know
        // different recipient sets (theirs granted bob one-sidedly) carries
        // the UNION of the wraps.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        let mut bp = Protection::default();
        let mut op = Protection::default();
        let mut tp = Protection::default();
        let ct = enc_file(&mut bp, &alice_pk, b"s\n");
        let _ = enc_file(&mut op, &alice_pk, b"s\n"); // convergent: same blob id
        let _ = enc_file(&mut tp, &alice_pk, b"s\n");
        let _ = enc_file(&mut tp, &bob_pk, b"s\n"); // theirs also granted bob
        let root = tree_with_perms(&repo, &[("secret/f", ct.clone(), PROTECTED)]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let fm =
            three_way_files(&mut s, Some((root, &bp)), (root, &op), (root, &tp), None).unwrap();
        assert!(fm.conflicts.is_empty());
        let wraps = &fm.wrapped_carry[&Object::blob(ct).id()];
        assert_eq!(wraps.len(), 2, "alice's wrap deduped, bob's grant unioned in");
        let alice_id = alice_pk.recipient_id().to_string();
        let bob_id = bob_pk.recipient_id().to_string();
        assert!(wraps.iter().any(|w| w.recipient_id == alice_id));
        assert!(wraps.iter().any(|w| w.recipient_id == bob_id));
    }

    #[test]
    fn perms_divergence_requires_identity_when_keyless() {
        // Companion to perms_divergence_resolves_protected: the same
        // PROTECTED-bit divergence with identity None must refuse, not
        // silently pick a side.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let op = Protection::default();
        let mut tp = Protection::default();
        let ct = enc_file(&mut tp, &alice_pk, b"hello\n");
        let ours = tree_with_perms(&repo, &[("x.txt", b"bye\n".to_vec(), 0)]);
        let theirs = tree_with_perms(&repo, &[("x.txt", ct, PROTECTED)]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let err = three_way_files(&mut s, None, (ours, &op), (theirs, &tp), None).unwrap_err();
        assert!(matches!(&err, Error::ProtectedMergeNeedsIdentity(p) if p == "x.txt"), "got {err:?}");
    }

    #[test]
    fn perms_divergence_resolves_protected() {
        // ours committed x.txt plain; theirs committed the same content
        // protected (the rule was added on theirs). PROTECTED bit divergence
        // is content divergence: identity-gated, output protected plaintext.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let op = Protection::default();
        let mut tp = Protection::default();
        let ct = enc_file(&mut tp, &alice_pk, b"hello\n");
        let ours = tree_with_perms(&repo, &[("x.txt", b"hello\n".to_vec(), 0)]);
        let theirs = tree_with_perms(&repo, &[("x.txt", ct, PROTECTED)]);
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let fm =
            three_way_files(&mut s, None, (ours, &op), (theirs, &tp), Some(&alice_sk)).unwrap();
        assert!(fm.conflicts.is_empty());
        let f = fm.files.iter().find(|f| f.path == "x.txt").unwrap();
        assert!(f.perms & PROTECTED != 0, "protection wins the perms divergence");
        assert!(f.needs_encrypt);
        assert_eq!(f.bytes, b"hello\n");
    }

    #[test]
    fn plain_merges_unchanged() {
        // Captured pre-change expectation of the all-plain scenario: the
        // protected-aware rewrite must produce byte-identical output.
        let repo = VfsRepo::new(Store::with_budget(1 << 20));
        let base = commit_files(
            &repo,
            &[("shared.txt", "a\nb\nc\n"), ("only.txt", "keep\n")],
            vec![],
        );
        let ours = commit_files(
            &repo,
            &[("shared.txt", "a\nB\nc\n"), ("only.txt", "keep\n"), ("ours.txt", "o\n")],
            vec![base],
        );
        let theirs = commit_files(
            &repo,
            &[("shared.txt", "a\nb\nC\n"), ("only.txt", "keep\n")],
            vec![base],
        );
        let arc = repo.store();
        let mut s = arc.lock().unwrap();
        let m = three_way(&mut s, base, ours, theirs, None).unwrap();
        assert!(m.conflicts.is_empty());
        // Exact captured outcome: paths, modes, bytes — and no protected residue.
        let got: Vec<(String, FileMode, Vec<u8>)> =
            m.files.iter().map(|f| (f.path.clone(), f.mode, f.bytes.clone())).collect();
        assert_eq!(
            got,
            vec![
                ("only.txt".to_string(), FileMode::FILE, b"keep\n".to_vec()),
                ("ours.txt".to_string(), FileMode::FILE, b"o\n".to_vec()),
                ("shared.txt".to_string(), FileMode::FILE, b"a\nB\nC\n".to_vec()),
            ]
        );
        assert!(m.files.iter().all(|f| !f.needs_encrypt && f.perms == 0));
        assert!(m.sidecars.is_empty());
    }
}
