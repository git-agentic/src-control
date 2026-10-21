//! Private branches (P34, ADR-0044): per-branch access control.
//!
//! A private branch's ref points at a [`BranchManifest`] instead of a
//! snapshot. Every object the branch introduces — snapshot, tree, blob — is
//! sealed individually (`Object::Sealed`, fresh random DEK each) and the
//! branch's *inner* world is a normal plaintext CAS DAG whose ids appear only
//! inside the KEK-encrypted index. Sealing is **copy-on-write**: an inner id
//! absent from the index is a public object read straight from the store, so
//! unchanged content is never duplicated and the references to it live only
//! inside ciphertext.
//!
//! Nothing in this module ever writes inner plaintext to the persistent
//! store: inner objects exist as decoded values in memory (and, for merges,
//! in a RAM-only ephemeral `Store`) and as sealed ciphertext on disk. The
//! only path that writes inner content as public objects is `publish`, after
//! its scanner gate.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use scl_core::{
    BranchManifest, EntryKind, FileMode, Object, ObjectId, Protection, SealedObj, Snapshot, Store,
    Tree, TreeEntry, WrappedKey, PROTECTED,
};
use scl_crypto::{BranchIndex, IndexEntry, PublicKey, RecipientId, SecretKey};

use crate::error::{Error, Result};
use crate::refs;
use crate::repo::Repo;
use crate::worktree::{self, Diff};

/// An opened private branch: the manifest plus the decrypted key material.
/// Constructing one **is** authorization — it requires an identity that
/// unwraps the branch KEK. The KEK and every DEK in the index zeroize on drop
/// (best-effort, `BranchIndex`'s own contract).
pub(crate) struct PrivateCtx {
    pub manifest_id: ObjectId,
    pub manifest: BranchManifest,
    pub kek: scl_crypto::Zeroizing<[u8; 32]>,
    pub index: BranchIndex,
}

impl PrivateCtx {
    /// The inner (plaintext-id) tip snapshot id. At branch creation this is
    /// the public base itself; after the first private commit it is a private
    /// inner id resolvable only through the index.
    pub(crate) fn inner_tip(&self) -> Result<ObjectId> {
        self.index
            .inner_tip
            .ok_or_else(|| Error::BadRef("private branch manifest has no inner tip".into()))
    }
}

impl Repo {
    /// Decode the object a branch ref points at and return its manifest when
    /// the branch is private. `Ok(None)` for a public branch.
    pub fn branch_manifest(&self, name: &str) -> Result<Option<(ObjectId, BranchManifest)>> {
        let tip = refs::read_branch_tip(&self.layout, name)?
            .ok_or_else(|| Error::NoSuchBranch(name.to_string()))?;
        Ok(self.manifest_at(&tip)?.map(|m| (tip, m)))
    }

    /// `Some(manifest)` iff the object at `id` is a branch manifest.
    pub(crate) fn manifest_at(&self, id: &ObjectId) -> Result<Option<BranchManifest>> {
        let store_arc = self.vfs.store();
        let obj = store_arc.lock().unwrap().get(id)?;
        match obj {
            Object::Manifest(m) => Ok(Some(m)),
            _ => Ok(None),
        }
    }

    /// Whether the named branch is private.
    pub fn is_private_branch(&self, name: &str) -> Result<bool> {
        Ok(self.branch_manifest(name)?.is_some())
    }

    /// Whether `identity` can open the named private branch — the listing
    /// marker probe (`(private)` vs `(private, no access)`). Discards all key
    /// material; `Ok(false)` for a non-recipient or a public branch.
    pub fn can_open_private(&self, name: &str, identity: Option<&SecretKey>) -> Result<bool> {
        match self.branch_manifest(name)? {
            None => Ok(false),
            Some((mid, manifest)) => match self.open_private(name, mid, manifest, identity) {
                Ok(_) => Ok(true),
                Err(Error::PrivateNoAccess(_)) => Ok(false),
                Err(e) => Err(e),
            },
        }
    }

    /// `Some((branch, manifest id, manifest))` iff HEAD's branch is private.
    pub fn head_private(&self) -> Result<Option<(String, ObjectId, BranchManifest)>> {
        let branch = refs::current_branch(&self.layout)?;
        match refs::read_branch_tip(&self.layout, &branch)? {
            None => Ok(None),
            Some(tip) => Ok(self.manifest_at(&tip)?.map(|m| (branch.clone(), tip, m))),
        }
    }

    /// Guard: refuse `op` when the current branch is private. The cheap check
    /// every snapshot-assuming ref-moving operation calls first, so the
    /// refusal names the real cause instead of surfacing as a decode error.
    pub(crate) fn refuse_on_private(&self, op: &str) -> Result<()> {
        if self.head_private()?.is_some() {
            return Err(Error::PrivateUnsupported(op.to_string()));
        }
        Ok(())
    }

    /// Authorize against a manifest: unwrap the branch KEK with `identity` and
    /// decrypt the index. Fails `PrivateNoAccess` when no wrap unwraps.
    pub(crate) fn open_private(
        &self,
        branch: &str,
        manifest_id: ObjectId,
        manifest: BranchManifest,
        identity: Option<&SecretKey>,
    ) -> Result<PrivateCtx> {
        let sk = identity.ok_or_else(|| Error::PrivateNoAccess(branch.to_string()))?;
        let my_id = sk.public().recipient_id();
        // Try the caller's own wrap first (cheap exact match), then every
        // wrap (a rewrapped manifest may carry stale recipient-id labels).
        let mut wraps: Vec<&WrappedKey> = manifest.kek_wraps.iter().collect();
        wraps.sort_by_key(|w| w.recipient_id != my_id.as_str());
        for wk in wraps {
            if let Ok(kek) = scl_crypto::unwrap_kek_with(wk, sk) {
                let index = BranchIndex::decrypt(&manifest.index_ct, &kek)
                    .map_err(|_| Error::BadRef("private branch index failed to decrypt".into()))?;
                return Ok(PrivateCtx {
                    manifest_id,
                    manifest,
                    kek,
                    index,
                });
            }
        }
        Err(Error::PrivateNoAccess(branch.to_string()))
    }

    /// Resolve + authorize a private branch by name in one step.
    pub(crate) fn open_private_branch(
        &self,
        name: &str,
        identity: Option<&SecretKey>,
    ) -> Result<PrivateCtx> {
        let (mid, manifest) = self
            .branch_manifest(name)?
            .ok_or_else(|| Error::NotPrivateBranch(name.to_string()))?;
        self.open_private(name, mid, manifest, identity)
    }

    // ---- inner-object resolution --------------------------------------------

    /// Fetch an inner object: an index hit resolves through its sealed
    /// ciphertext; a miss is a public object read directly. The decoded
    /// object's id must equal the requested id — a mismatch means a corrupt
    /// (or tampered-with) index entry and is refused loudly.
    pub(crate) fn get_inner(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        id: &ObjectId,
    ) -> Result<Object> {
        match ctx.index.entries.get(id) {
            None => store.get(id).map_err(Error::from),
            Some(entry) => {
                let sealed = match store.get(&entry.sealed)? {
                    Object::Sealed(s) => s,
                    other => {
                        return Err(Error::BadRef(format!(
                            "index maps {id} to a non-sealed object ({})",
                            other.kind_name()
                        )))
                    }
                };
                let encoding = scl_crypto::open_object(&sealed.payload, &entry.dek)?;
                let obj = Object::decode(&encoding)?;
                if obj.id() != *id {
                    return Err(Error::CorruptObject(*id));
                }
                Ok(obj)
            }
        }
    }

    pub(crate) fn get_inner_snapshot(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        id: &ObjectId,
    ) -> Result<Snapshot> {
        match self.get_inner(store, ctx, id)? {
            Object::Snapshot(s) => Ok(s),
            other => Err(Error::BadRef(format!(
                "expected snapshot at {id}, found {}",
                other.kind_name()
            ))),
        }
    }

    /// Flatten an inner tree to `path -> (inner blob id, mode, perms)`.
    pub(crate) fn inner_tree_files(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        root: ObjectId,
    ) -> Result<BTreeMap<String, (ObjectId, FileMode, u8)>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![(root, String::new())];
        while let Some((tree_id, prefix)) = stack.pop() {
            let tree = match self.get_inner(store, ctx, &tree_id)? {
                Object::Tree(t) => t,
                other => {
                    return Err(Error::BadRef(format!(
                        "expected tree at {tree_id}, found {}",
                        other.kind_name()
                    )))
                }
            };
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
                    EntryKind::Tree => stack.push((e.id, path)),
                }
            }
        }
        Ok(out)
    }

    /// Every inner id (trees + blobs) reachable in an inner tree. The
    /// carried-set authority for the copy-on-write sealing decision: an id in
    /// here (and not in the index) is public content reachable from the base
    /// by induction, so referencing it never strands a peer.
    fn inner_tree_closure(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        root: ObjectId,
    ) -> Result<BTreeSet<ObjectId>> {
        let mut out = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(tree_id) = stack.pop() {
            if !out.insert(tree_id) {
                continue;
            }
            let tree = match self.get_inner(store, ctx, &tree_id)? {
                Object::Tree(t) => t,
                other => {
                    return Err(Error::BadRef(format!(
                        "expected tree at {tree_id}, found {}",
                        other.kind_name()
                    )))
                }
            };
            for e in tree.entries {
                match e.kind {
                    EntryKind::Blob => {
                        out.insert(e.id);
                    }
                    EntryKind::Tree => stack.push(e.id),
                }
            }
        }
        Ok(out)
    }

    /// Inner blob bytes via the resolver.
    fn inner_blob(&self, store: &mut Store, ctx: &PrivateCtx, id: &ObjectId) -> Result<Vec<u8>> {
        match self.get_inner(store, ctx, id)? {
            Object::Blob(b) => Ok(b.to_vec()),
            other => Err(Error::BadRef(format!(
                "expected blob at {id}, found {}",
                other.kind_name()
            ))),
        }
    }

    // ---- creation -------------------------------------------------------------

    /// Create a private branch at the current (public) tip: mint a KEK, wrap
    /// it for creator + recipients + escrow, and point the new ref at a
    /// manifest whose index is empty (copy-on-write: nothing is sealed until
    /// content actually changes).
    pub fn branch_private(
        &self,
        name: &str,
        creator: &SecretKey,
        recipients: &[PublicKey],
        escrows: &[PublicKey],
    ) -> Result<ObjectId> {
        // A private branch is checked out by flattening and sealing whole
        // trees, which a partial clone cannot do (ADR-0048). Refuse up front
        // rather than create a branch that cannot be switched to.
        self.refuse_on_partial("sc branch --private")?;
        crate::repo::validate_branch_name(name)?;
        if self.layout.ref_path(name).exists() {
            return Err(Error::BadRef(format!("branch already exists: {name}")));
        }
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        if self.manifest_at(&tip)?.is_some() {
            return Err(Error::PrivateUnsupported(
                "creating a private branch from a private branch".into(),
            ));
        }

        let kek = scl_crypto::generate_kek();
        // Creator is always wrapped in; recipients + escrow deduped by id.
        let mut wrap_keys: Vec<PublicKey> = vec![creator.public()];
        for pk in recipients.iter().chain(escrows.iter()) {
            if !wrap_keys
                .iter()
                .any(|k| k.recipient_id() == pk.recipient_id())
            {
                wrap_keys.push(pk.clone());
            }
        }
        let kek_wraps: Vec<WrappedKey> = wrap_keys
            .iter()
            .map(|pk| scl_crypto::wrap_kek_for(&kek, pk))
            .collect();

        let index = BranchIndex {
            inner_tip: Some(tip),
            entries: BTreeMap::new(),
        };
        let manifest = BranchManifest {
            base: tip,
            prev: None,
            anchors: Vec::new(),
            closure: Vec::new(),
            index_ct: index.encrypt(&kek),
            kek_wraps,
        };
        let store_arc = self.vfs.store();
        let mid = store_arc.lock().unwrap().put(Object::Manifest(manifest))?;
        refs::write_branch_tip(&self.layout, name, &mid)?;
        let head = refs::current_branch(&self.layout)?;
        crate::oplog::record(
            &self.layout,
            &format!("branch {name} (private)"),
            &head,
            &head,
            &[(name.to_string(), None, Some(mid))],
        )?;
        Ok(mid)
    }

    // ---- checkout / status / log ----------------------------------------------

    /// Materialize a private branch's inner tip into the working tree
    /// (recipient context — plaintext on disk is the authorized checkout,
    /// same posture as a protected-path decrypt). `old_paths` is the file set
    /// of the tree being switched away from; anything there that the target
    /// doesn't track (or that falls outside `sparse`) is removed.
    fn materialize_private(
        &self,
        op: &str,
        store: &mut Store,
        ctx: &PrivateCtx,
        target_root: ObjectId,
        old_paths: &BTreeSet<String>,
        protection: &Protection,
        identity: &SecretKey,
        restores: bool,
    ) -> Result<Vec<String>> {
        let sparse = self.sparse_spec()?;
        let target = self.inner_tree_files(store, ctx, target_root)?;
        // Before the first removal or write: nothing of the user's may be
        // replaced (see `refuse_untracked_paths`).
        self.refuse_untracked_paths(op, old_paths, target.keys())?;
        // A restore (abort) re-lays the tree the stop started from: nothing is
        // added, and `old_paths` is only what the stop wrote, in view.
        if !restores {
            self.refuse_untracked_out_of_view_paths(
                op,
                &sparse,
                old_paths,
                &target.keys().cloned().collect(),
            )?;
        }
        // A path outside the view is never laid out, so a copy on disk is the
        // user's own (#256). A failed removal is an error: the file may be
        // decrypted plaintext that must not linger.
        worktree::refuse_blocked_parents(
            &self.layout.root,
            target.keys().filter(|p| sparse.matches(p)),
            &|c| old_paths.contains(c) && !target.contains_key(c),
        )?;
        for p in old_paths {
            if !target.contains_key(p)
                && sparse.matches(p)
                && !worktree::under_symlink(&self.layout.root, p)
            {
                let full = worktree::safe_join(&self.layout.root, p)?;
                match std::fs::remove_file(full) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let mut skipped = Vec::new();
        for (path, (blob_id, mode, perms)) in &target {
            if !sparse.matches(path) {
                continue;
            }
            let full = worktree::safe_join(&self.layout.root, path)?;
            let bytes = self.inner_blob(store, ctx, blob_id)?;
            if perms & PROTECTED != 0 {
                // A path-protected file carried from the base: still the P7
                // envelope, decrypted via the inner snapshot's wraps.
                match crate::protect::decrypt_with(&bytes, blob_id, &[protection], identity, path) {
                    Ok(pt) => {
                        worktree::clear_dir_obstruction(&full, path)?;
                        if let Some(parent) = full.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        worktree::write_file(&full, &pt[..], *mode)?;
                    }
                    Err(_) => {
                        // KEK recipient without path access: skip, never
                        // leave stale plaintext behind (same rule as
                        // `worktree::materialize`).
                        worktree::clear_dir_obstruction(&full, path)?;
                        match std::fs::remove_file(&full) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.into()),
                        }
                        skipped.push(path.clone());
                    }
                }
            } else {
                worktree::clear_dir_obstruction(&full, path)?;
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                worktree::write_file(&full, &bytes[..], *mode)?;
            }
        }
        Ok(skipped)
    }

    /// Switch onto a private branch (called by `switch_with_identity` once it
    /// detects a manifest ref). The dirty check against the OLD branch has
    /// already run in the caller.
    pub(crate) fn switch_to_private(
        &self,
        name: &str,
        manifest_id: ObjectId,
        manifest: BranchManifest,
        identity: Option<&SecretKey>,
        old_paths: &BTreeSet<String>,
    ) -> Result<Vec<String>> {
        let ctx = self.open_private(name, manifest_id, manifest, identity)?;
        let sk = identity.expect("open_private succeeded, identity present");
        let head_before = refs::current_branch(&self.layout)?;
        let tip_snap = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let tip = ctx.inner_tip()?;
            self.get_inner_snapshot(&mut store, &ctx, &tip)?
        };
        let skipped = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            self.materialize_private(
                "switch",
                &mut store,
                &ctx,
                tip_snap.root,
                old_paths,
                &tip_snap.protection,
                sk,
                false,
            )?
        };
        refs::write_head(&self.layout, name)?;
        crate::oplog::record(
            &self.layout,
            &format!("switch {name}"),
            &head_before,
            name,
            &[],
        )?;
        Ok(skipped)
    }

    /// Working-tree status against a private HEAD. Requires a recipient
    /// identity (the KEK gates even knowing what the tree contains).
    pub fn status_private(&self, identity: Option<&SecretKey>) -> Result<Diff> {
        let (branch, mid, manifest) = self
            .head_private()?
            .ok_or_else(|| Error::NotPrivateBranch("HEAD".into()))?;
        let ctx = self.open_private(&branch, mid, manifest, identity)?;
        let sk = identity.expect("open_private succeeded");
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let tip = ctx.inner_tip()?;
        let snap = self.get_inner_snapshot(&mut store, &ctx, &tip)?;
        let head = self.inner_tree_files(&mut store, &ctx, snap.root)?;
        let sparse = self.sparse_spec()?;
        let tracked: BTreeSet<String> = head.keys().cloned().collect();
        let wt: BTreeMap<String, Vec<u8>> = worktree::read_worktree(&self.layout, &tracked)?
            .into_iter()
            .map(|(p, b, _)| (p, b))
            .collect();
        let mut diff = Diff::default();
        for (p, bytes) in &wt {
            match head.get(p) {
                None => diff.added.push(p.clone()),
                Some((hid, _mode, perms)) => {
                    if *perms & PROTECTED != 0 {
                        // Carried path-ciphertext: unchanged iff the on-disk
                        // plaintext decrypts equal. We hold an identity by
                        // construction; an unresolvable wrap reports modified
                        // (spurious-but-safe, mirrors the P33 posture).
                        let ct = self.inner_blob(&mut store, &ctx, hid)?;
                        match crate::protect::decrypt_with(&ct, hid, &[&snap.protection], sk, p) {
                            Ok(pt) if pt.as_slice() == bytes.as_slice() => {}
                            _ => diff.modified.push(p.clone()),
                        }
                    } else if Object::blob(bytes.clone()).id() != *hid {
                        diff.modified.push(p.clone());
                    }
                }
            }
        }
        for (p, (_hid, _mode, perms)) in &head {
            if !wt.contains_key(p) {
                if !sparse.matches(p) || *perms & PROTECTED != 0 {
                    continue;
                }
                diff.deleted.push(p.clone());
            }
        }
        Ok(diff)
    }

    /// Paths tracked by the private HEAD's inner tip. Needs a recipient
    /// identity (the tree structure is sealed).
    pub(crate) fn private_tracked_paths(
        &self,
        identity: Option<&SecretKey>,
    ) -> Result<BTreeSet<String>> {
        let (branch, mid, manifest) = self
            .head_private()?
            .ok_or_else(|| Error::NotPrivateBranch("HEAD".into()))?;
        let ctx = self.open_private(&branch, mid, manifest, identity)?;
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let tip = ctx.inner_tip()?;
        let root = self.get_inner_snapshot(&mut store, &ctx, &tip)?.root;
        Ok(self
            .inner_tree_files(&mut store, &ctx, root)?
            .into_keys()
            .collect())
    }

    /// Line-level unified diff of the working tree against a private HEAD.
    /// Same rendering as `diff_unified`; carried path-protected entries are
    /// compared via decryption (we hold an identity by construction) but
    /// their content is reported status-only, matching the public rule.
    pub fn diff_unified_private(&self, identity: Option<&SecretKey>) -> Result<String> {
        let (branch, mid, manifest) = self
            .head_private()?
            .ok_or_else(|| Error::NotPrivateBranch("HEAD".into()))?;
        let ctx = self.open_private(&branch, mid, manifest, identity)?;
        let sk = identity.expect("open_private succeeded");
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let tip = ctx.inner_tip()?;
        let snap = self.get_inner_snapshot(&mut store, &ctx, &tip)?;
        let head = self.inner_tree_files(&mut store, &ctx, snap.root)?;
        let sparse = self.sparse_spec()?;
        let tracked: BTreeSet<String> = head.keys().cloned().collect();
        let wt: BTreeMap<String, Vec<u8>> = worktree::read_worktree(&self.layout, &tracked)?
            .into_iter()
            .map(|(p, b, _)| (p, b))
            .collect();
        let mut paths: BTreeSet<&String> = wt.keys().collect();
        paths.extend(head.keys());
        let mut out = String::new();
        for path in paths {
            let disk = wt.get(path);
            match head.get(path) {
                None => {
                    let bytes = disk.expect("path came from one of the two maps");
                    crate::repo::push_file_diff(&mut out, path, &[], bytes);
                }
                Some((blob_id, _mode, perms)) if *perms & PROTECTED != 0 => {
                    if let Some(bytes) = disk {
                        let ct = self.inner_blob(&mut store, &ctx, blob_id)?;
                        let changed = !matches!(
                            crate::protect::decrypt_with(&ct, blob_id, &[&snap.protection], sk, path),
                            Ok(pt) if pt.as_slice() == bytes.as_slice()
                        );
                        if changed {
                            out.push_str(&format!(
                                "protected file changed: {path} (content not shown)\n"
                            ));
                        }
                    }
                }
                Some((blob_id, _mode, _perms)) => {
                    if disk.is_none() && !sparse.matches(path) {
                        continue;
                    }
                    let old = self.inner_blob(&mut store, &ctx, blob_id)?;
                    match disk {
                        None => crate::repo::push_file_diff(&mut out, path, &old, &[]),
                        Some(bytes) => {
                            if Object::blob(bytes.clone()).id() != *blob_id {
                                crate::repo::push_file_diff(&mut out, path, &old, bytes);
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// History of a private branch: inner snapshots from the inner tip, then
    /// straight through into public history past the fork point (the resolver
    /// falls through to the store on an index miss).
    pub fn log_private(&self, identity: Option<&SecretKey>) -> Result<Vec<(ObjectId, Snapshot)>> {
        let (branch, mid, manifest) = self
            .head_private()?
            .ok_or_else(|| Error::NotPrivateBranch("HEAD".into()))?;
        let ctx = self.open_private(&branch, mid, manifest, identity)?;
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let mut out = Vec::new();
        let mut next = Some(ctx.inner_tip()?);
        while let Some(id) = next {
            let snap = self.get_inner_snapshot(&mut store, &ctx, &id)?;
            next = snap.parents.first().copied();
            out.push((id, snap));
        }
        Ok(out)
    }

    // ---- commit ----------------------------------------------------------------

    /// Commit the working tree onto a private branch: scanner-gated like a
    /// public commit, then copy-on-write sealing — only objects genuinely new
    /// to the branch are sealed; unchanged content keeps its prior inner id
    /// (public or already-sealed). Completes an in-progress merge-from-public
    /// exactly like the public commit path (two parents, union policy).
    pub fn commit_private(
        &self,
        author: &str,
        message: &str,
        identity: Option<&SecretKey>,
    ) -> Result<ObjectId> {
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        let (branch, mid, manifest) = self
            .head_private()?
            .ok_or_else(|| Error::NotPrivateBranch("HEAD".into()))?;
        let ctx = self.open_private(&branch, mid, manifest, identity)?;
        let sk = identity.expect("open_private succeeded");
        let merge_head = crate::merge_state::read_merge_head(&self.layout)?;
        let sparse = self.sparse_spec()?;

        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let inner_tip = ctx.inner_tip()?;
        let prev_snap = self.get_inner_snapshot(&mut store, &ctx, &inner_tip)?;

        // Policy + secrets: tip's, or the union with theirs on merge completion
        // (same discipline as `snapshot_files`' merge-completion arm).
        // A merge completion also re-derives the merge's outcome for the paths
        // it cannot read from disk (see below).
        let mut decided: Option<BTreeMap<String, (ObjectId, FileMode, u8)>> = None;
        let mut decided_blobs: BTreeMap<ObjectId, Vec<u8>> = BTreeMap::new();
        let (protection, secrets) = match merge_head {
            None => (prev_snap.protection.clone(), prev_snap.secrets.clone()),
            Some(mh) => {
                let theirs = store.get_snapshot(&mh)?;
                let prefixes = crate::protect::merge_prefixes(
                    &prev_snap.protection.prefixes,
                    &theirs.protection.prefixes,
                );
                let mut wrapped = prev_snap.protection.wrapped.clone();
                for (id, wks) in &theirs.protection.wrapped {
                    let entry = wrapped.entry(*id).or_default();
                    *entry = crate::protect::union_wraps(entry, wks);
                }
                let base = self
                    .merge_base_private(&mut store, &ctx, inner_tip, mh)?
                    .ok_or(Error::NoCommonAncestor)?;
                let base_snap = self.get_inner_snapshot(&mut store, &ctx, &base)?;
                let fm = self.private_three_way(
                    &mut store, &ctx, &prev_snap, &theirs, &base_snap, identity,
                )?;
                let (entries, blobs, _) = decide_merged(&fm);
                decided = Some(entries);
                decided_blobs = blobs;
                let secs = crate::merge::merge_secrets(
                    &base_snap.secrets,
                    &prev_snap.secrets,
                    &theirs.secrets,
                )?;
                (Protection { prefixes, wrapped }, secs)
            }
        };

        let prior = self.inner_tree_files(&mut store, &ctx, prev_snap.root)?;
        let mut tracked: BTreeSet<String> = prior.keys().cloned().collect();
        // A path the merge decided is part of the outcome, so an ignore rule
        // on the private side must not hide the stop's write of it (as
        // `with_decided_paths` does on the public path, ADR-0049 q19).
        if let Some(d) = &decided {
            tracked.extend(d.keys().cloned());
        }
        let files = worktree::read_worktree(&self.layout, &tracked)?;
        // A sidecar the stop wrote is working-tree scratch: it reaches neither
        // the scanner nor the sealed tree, unless the merge's outcome tracks
        // that name (then it is the user's own file).
        let (files, sidecars) = if merge_head.is_some() {
            let scratch = crate::conflict_plaintext::read_sidecars(&self.layout)?;
            let source = decided.as_ref().unwrap_or(&prior);
            let is_scratch = |p: &str| scratch.contains(p) && !source.contains_key(p);
            (
                files
                    .into_iter()
                    .filter(|(p, _, _)| !is_scratch(p))
                    .collect(),
                scratch,
            )
        } else {
            (files, Default::default())
        };
        // Paths the stop wrote in plaintext. One now absent from disk was
        // deleted by the user: it must not be carried back from the merge.
        let conflict_plaintext = if merge_head.is_some() {
            crate::conflict_plaintext::read(&self.layout)?
        } else {
            Default::default()
        };

        // Scanner gate on the plaintext partition (protected-prefix files are
        // sealed at publish, exempt here exactly as in a public commit).
        let plain_for_scan: Vec<(String, Vec<u8>, FileMode)> = files
            .iter()
            .filter(|(p, _, _)| crate::protect::matching_prefix(&protection, p).is_none())
            .cloned()
            .collect();
        let report = self.scan_files(&plain_for_scan)?;
        if !report.is_empty() {
            return Err(Error::SecretDetected(report));
        }

        // Decide each path: carry the prior entry or mint a new inner blob.
        let mut entries: BTreeMap<String, (ObjectId, FileMode, u8)> = BTreeMap::new();
        let mut new_blobs: BTreeMap<ObjectId, Vec<u8>> = BTreeMap::new();
        let disk_paths: BTreeSet<String> = files.iter().map(|(p, _, _)| p.clone()).collect();
        for (path, bytes, mode) in files {
            let prior_e = prior.get(&path);
            match prior_e {
                Some((pid, pmode, perms)) if *perms & PROTECTED != 0 => {
                    // Carried path-ciphertext: unchanged iff plaintext matches.
                    let ct = self.inner_blob(&mut store, &ctx, pid)?;
                    let same = crate::protect::decrypt_with(&ct, pid, &[&protection], sk, &path)
                        .map(|pt| pt.as_slice() == bytes.as_slice())
                        .unwrap_or(false);
                    if same {
                        entries.insert(path, (*pid, *pmode, *perms));
                    } else {
                        // Edited: it becomes a plain inner blob; publish will
                        // re-seal it under the path rule.
                        let id = Object::blob(bytes.clone()).id();
                        new_blobs.entry(id).or_insert(bytes);
                        entries.insert(path, (id, mode, 0));
                    }
                }
                _ => {
                    let id = Object::blob(bytes.clone()).id();
                    if prior_e.map(|(pid, _, _)| *pid) != Some(id) {
                        new_blobs.entry(id).or_insert(bytes);
                    }
                    entries.insert(path, (id, mode, 0));
                }
            }
        }
        // Carry paths that are expected-absent: outside sparse, or PROTECTED
        // and skipped on disk (never silently drop protected content). On a
        // merge completion the source is the merge's decided outcome, not the prior tip, so a path the public side
        // deleted stays deleted and its clean adds and modifies land (#240,
        // same rule as the public path, #238). It is re-derived rather than
        // recorded: a decided tree cannot sit in unsealed `.sc/` state.
        let source = decided.as_ref().unwrap_or(&prior);
        for (path, e) in source {
            if entries.contains_key(path)
                || disk_paths.contains(path)
                || conflict_plaintext.contains(path)
            {
                continue;
            }
            if !sparse.matches(path) || e.2 & PROTECTED != 0 {
                entries.insert(path.clone(), *e);
                if let Some(bytes) = decided_blobs.get(&e.0) {
                    new_blobs.entry(e.0).or_insert_with(|| bytes.clone());
                }
            }
        }

        // Carried-set for the sealing decision: prior tree closure, plus
        // theirs' closure on merge completion (content adopted from a public
        // merge head is already public — sealing it would only waste space).
        let mut carried = self.inner_tree_closure(&mut store, &ctx, prev_snap.root)?;
        if let Some(mh) = merge_head {
            let theirs_root = store.get_snapshot(&mh)?.root;
            carried.extend(
                worktree::tree_file_entries_with_perms(&mut store, theirs_root)?
                    .values()
                    .map(|(id, _, _)| *id),
            );
            carried.extend(public_tree_ids(&mut store, theirs_root)?);
        }

        let parents = match merge_head {
            None => vec![inner_tip],
            Some(mh) => vec![inner_tip, mh],
        };
        let mut index = ctx.index.clone();
        let committed_paths: BTreeSet<String> = entries.keys().cloned().collect();
        let new_tip = self.seal_commit(
            &mut store, &ctx, &mut index, &carried, entries, new_blobs, parents, secrets,
            protection, author, message,
        )?;

        // Carry anchors forward; a merge-completion commit adds the public
        // merge head (its objects were carried into the sealed tree).
        let anchors = extend_anchors(&ctx.manifest.anchors, merge_head.into_iter());
        let new_manifest = BranchManifest {
            base: ctx.manifest.base,
            prev: Some(ctx.manifest_id),
            anchors,
            closure: index.entries.values().map(|e| e.sealed).collect(),
            index_ct: index.encrypt(&ctx.kek),
            kek_wraps: ctx.manifest.kek_wraps.clone(),
        };
        let new_mid = store.put(Object::Manifest(new_manifest))?;
        drop(store);
        // The sidecars were left out of the sealed tree; remove them before
        // the ref moves, or the next commit would take them. A failure here
        // fails this commit with nothing moved and the record intact.
        if !sidecars.is_empty() {
            self.remove_conflict_sidecars_unless(&mut |p| committed_paths.contains(p))?;
        }
        refs::write_branch_tip(&self.layout, &branch, &new_mid)?;
        crate::merge_state::clear(&self.layout)?;
        let label = if merge_head.is_some() {
            "commit (merge)"
        } else {
            "commit"
        };
        let first_line = message.lines().next().unwrap_or("");
        crate::oplog::record(
            &self.layout,
            &format!("{label}: {first_line}"),
            &branch,
            &branch,
            &[(branch.clone(), Some(ctx.manifest_id), Some(new_mid))],
        )?;
        Ok(new_tip)
    }

    /// Abandon a stopped merge into the private branch at HEAD: put the
    /// private tip back on disk and clear the merge state. The ref never moved
    /// during the stop and nothing was stored outside the sealed manifest, so
    /// only the checkout needs restoring. It needs the identity (the tip is a
    /// manifest); a caller who cannot open the branch is refused before any
    /// write, leaving the stop intact for someone who can.
    pub(crate) fn merge_abort_private(
        &self,
        identity: Option<&SecretKey>,
    ) -> Result<crate::repo::AbortReport> {
        let (branch, mid, manifest) = self
            .head_private()?
            .ok_or_else(|| Error::NotPrivateBranch("HEAD".into()))?;
        let ctx = self.open_private(&branch, mid, manifest, identity)?;
        let sk = identity.expect("open_private succeeded");
        let theirs_id = crate::merge_state::read_merge_head(&self.layout)?
            .expect("in_progress is true but MERGE_HEAD is absent");
        let sparse = self.sparse_spec()?;
        let plaintext = crate::conflict_plaintext::read(&self.layout)?;
        let conflicted: BTreeSet<String> = crate::merge_state::read_conflicts(&self.layout)?
            .into_iter()
            .collect();

        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let inner_tip = ctx.inner_tip()?;
        let ours = self.get_inner_snapshot(&mut store, &ctx, &inner_tip)?;
        let theirs = store.get_snapshot(&theirs_id)?;
        let prior = self.inner_tree_files(&mut store, &ctx, ours.root)?;
        // The stop wrote files from theirs, in view only; those the restored
        // tip does not track must go, but only the stop's own: a conflicted
        // path or recorded plaintext, or a file that is still theirs' bytes.
        // A stop keeps no decided root for a private branch (it would be
        // unsealed), so a conflicted path cannot be compared by content.
        // Anything else at such a path is the user's and is reported (#255).
        let mut written: BTreeSet<String> = prior
            .keys()
            .filter(|p| sparse.matches(p))
            .cloned()
            .collect();
        let mut kept = Vec::new();
        for (p, (blob_id, _, perms)) in
            worktree::tree_file_entries_with_perms(&mut store, theirs.root)?
        {
            if prior.contains_key(&p) || !sparse.matches(&p) {
                continue;
            }
            let full = worktree::safe_join(&self.layout.root, &p)?;
            // Not knowing what stands there must stop the abort before it
            // clears the stop's records (decrypted text could linger).
            let Some(meta) = worktree::lstat(&full)? else {
                continue;
            };
            let recorded = plaintext.contains(&p);
            // The stop wrote regular files: a symlink there is the user's.
            let ours = meta.is_file()
                && !worktree::under_symlink(&self.layout.root, &p)
                && if perms & PROTECTED != 0 {
                    recorded
                } else {
                    recorded || conflicted.contains(&p) || worktree::disk_is_blob(&full, &blob_id)
                };
            if ours {
                written.insert(p);
            } else {
                kept.push(p);
            }
        }
        let skipped = self.materialize_private(
            "merge --abort",
            &mut store,
            &ctx,
            ours.root,
            &written,
            &ours.protection,
            sk,
            true,
        )?;
        drop(store);
        // After the restore, so a failed restore leaves the sidecars to retry.
        self.remove_conflict_sidecars_unless(&mut |p| prior.contains_key(p))?;
        crate::merge_state::clear(&self.layout)?;
        Ok(crate::repo::AbortReport { skipped, kept })
    }

    /// Build inner trees + snapshot from a decided file map, seal everything
    /// genuinely new (not in the index, not in `carried`), record the new
    /// DEKs in `index`, and return the new inner tip id. The shared tail of
    /// `commit_private` and `merge_into_private`'s clean path.
    #[allow(clippy::too_many_arguments)]
    fn seal_commit(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        index: &mut BranchIndex,
        carried: &BTreeSet<ObjectId>,
        entries: BTreeMap<String, (ObjectId, FileMode, u8)>,
        new_blobs: BTreeMap<ObjectId, Vec<u8>>,
        parents: Vec<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        mut protection: Protection,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        // Prune wraps to path-ciphertext blobs actually reachable (commit's
        // rebuild discipline).
        let reachable: BTreeSet<ObjectId> = entries.values().map(|(id, _, _)| *id).collect();
        protection.wrapped.retain(|id, _| reachable.contains(id));

        let (root, trees) = build_tree_objects(&entries)?;
        let snapshot = Object::Snapshot(Snapshot {
            root,
            parents,
            author: author.to_string(),
            timestamp: crate::repo::unix_now(),
            message: message.to_string(),
            secrets,
            protection,
        });
        let snap_id = snapshot.id();

        let mut to_seal: Vec<(ObjectId, Vec<u8>)> = Vec::new();
        for (id, bytes) in new_blobs {
            if !index.entries.contains_key(&id) && !carried.contains(&id) {
                to_seal.push((id, Object::blob(bytes).encode()));
            }
        }
        for t in trees {
            let id = t.id();
            if !index.entries.contains_key(&id) && !carried.contains(&id) {
                to_seal.push((id, t.encode()));
            }
        }
        to_seal.push((snap_id, snapshot.encode()));

        for (inner_id, encoding) in to_seal {
            let (payload, dek) = scl_crypto::seal_object(&encoding);
            let sealed_id = store.put(Object::Sealed(SealedObj {
                payload: payload.into(),
            }))?;
            index.entries.insert(
                inner_id,
                IndexEntry {
                    sealed: sealed_id,
                    dek: *dek,
                },
            );
        }
        index.inner_tip = Some(snap_id);
        let _ = ctx; // ctx retained by callers for kek/manifest fields
        Ok(snap_id)
    }

    /// A lowest common ancestor between an inner snapshot and a public one,
    /// walking the mixed graph through the resolver. Always returns a public
    /// id when `Some` (a private snapshot can never be an ancestor of a
    /// public tip).
    fn merge_base_private(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        ours_inner: ObjectId,
        theirs_public: ObjectId,
    ) -> Result<Option<ObjectId>> {
        let ours_anc = self.inner_ancestors(store, ctx, ours_inner)?;
        let mut seen = BTreeSet::new();
        let mut q = VecDeque::new();
        q.push_back(theirs_public);
        seen.insert(theirs_public);
        while let Some(id) = q.pop_front() {
            if ours_anc.contains(&id) {
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

    /// All ancestors of an inner snapshot (inclusive), via the resolver —
    /// crosses seamlessly into public history at the fork point.
    fn inner_ancestors(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        id: ObjectId,
    ) -> Result<BTreeSet<ObjectId>> {
        let mut set = BTreeSet::new();
        let mut q = VecDeque::new();
        q.push_back(id);
        set.insert(id);
        while let Some(cur) = q.pop_front() {
            for p in self.get_inner_snapshot(store, ctx, &cur)?.parents {
                if set.insert(p) {
                    q.push_back(p);
                }
            }
        }
        Ok(set)
    }
}

/// Build the tree objects for a flat `path -> (id, mode, perms)` map without
/// touching any store: returns the root tree id plus every tree object built
/// (the sealing loop decides which of them are new). Pure — the inner world's
/// analogue of `vfs::write_tree_with_perms`.
///
/// Refuses a path that is both a file and the parent of another (#278), like
/// the public builder: a private commit carries absent protected and
/// out-of-view paths too.
pub(crate) fn build_tree_objects(
    entries: &BTreeMap<String, (ObjectId, FileMode, u8)>,
) -> Result<(ObjectId, Vec<Object>)> {
    scl_vfs::check_file_dir_collisions(entries.keys().map(String::as_str))?;
    let mut trees = Vec::new();
    let root = build_subtree(entries, "", &mut trees);
    Ok((root, trees))
}

fn build_subtree(
    entries: &BTreeMap<String, (ObjectId, FileMode, u8)>,
    prefix: &str,
    out: &mut Vec<Object>,
) -> ObjectId {
    let mut files: Vec<TreeEntry> = Vec::new();
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for (path, (id, mode, perms)) in entries.range(prefix.to_string()..) {
        let rel = match prefix.is_empty() {
            true => path.as_str(),
            false => match path.strip_prefix(prefix) {
                Some(r) => r,
                None => break, // sorted map: past the prefix range
            },
        };
        match rel.split_once('/') {
            None => files.push(TreeEntry {
                name: rel.to_string(),
                kind: EntryKind::Blob,
                id: *id,
                mode: *mode,
                perms: *perms,
            }),
            Some((dir, _)) => {
                dirs.insert(dir.to_string());
            }
        }
    }
    for dir in dirs {
        let sub_prefix = if prefix.is_empty() {
            format!("{dir}/")
        } else {
            format!("{prefix}{dir}/")
        };
        let sub_id = build_subtree(entries, &sub_prefix, out);
        files.push(TreeEntry {
            name: dir,
            kind: EntryKind::Tree,
            id: sub_id,
            // Match vfs's `build_subtree_inner` byte-for-byte: an unchanged
            // subtree must hash to the SAME id as its public original, or the
            // copy-on-write carry check would spuriously re-seal it.
            mode: FileMode(0o755),
            perms: 0,
        });
    }
    let tree = Object::Tree(Tree::new(files));
    let id = tree.id();
    out.push(tree);
    id
}

/// Every tree id reachable under a PUBLIC root (subtree ids only; blob ids
/// come from `tree_file_entries_with_perms`). Helper for the merge-completion
/// carried set.
fn public_tree_ids(store: &mut Store, root: ObjectId) -> Result<BTreeSet<ObjectId>> {
    let mut out = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !out.insert(id) {
            continue;
        }
        let tree = store.get_tree(&id)?;
        for e in tree.entries {
            if e.kind == EntryKind::Tree {
                stack.push(e.id);
            }
        }
    }
    Ok(out)
}

/// Merge new public reachability anchors into a manifest's existing set,
/// deduped and sorted (canonical). Anchors are cumulative across a branch's
/// history; a redundant anchor (already reachable from `base` or another
/// anchor) is harmless — the reachability walk is idempotent — so no store
/// walk is needed here to prune, and the growth is bounded by the number of
/// merges (a documented manifest-scalability boundary, ADR-0044 deferred).
pub(crate) fn extend_anchors(
    existing: &[ObjectId],
    new: impl Iterator<Item = ObjectId>,
) -> Vec<ObjectId> {
    let mut set: BTreeSet<ObjectId> = existing.iter().copied().collect();
    set.extend(new);
    set.into_iter().collect()
}

/// Escrow/recipient sets must never be empty on a rewrap (seal-to-zero
/// footgun — the same rule `secrets::require_recipients` enforces).
pub(crate) fn require_nonempty_recipients(keys: &[PublicKey], what: &str) -> Result<()> {
    if keys.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "{what} would leave zero recipients able to read the branch; refusing"
        )));
    }
    Ok(())
}

/// Membership helpers shared by grant/revoke: the recipient ids currently
/// wrapped on a manifest.
pub(crate) fn wrapped_ids(manifest: &BranchManifest) -> BTreeSet<String> {
    manifest
        .kek_wraps
        .iter()
        .map(|w| w.recipient_id.clone())
        .collect()
}

impl Repo {
    // ---- membership -----------------------------------------------------------

    /// Grant: wrap the branch KEK for one more recipient. O(1) — one manifest
    /// rewrite, no object churn, no index change.
    pub fn branch_grant(
        &self,
        name: &str,
        identity: &SecretKey,
        new: &PublicKey,
    ) -> Result<ObjectId> {
        self.guard_states()?;
        let ctx = self.open_private_branch(name, Some(identity))?;
        let mut kek_wraps = ctx.manifest.kek_wraps.clone();
        let new_id = new.recipient_id().to_string();
        kek_wraps.retain(|w| w.recipient_id != new_id);
        kek_wraps.push(scl_crypto::wrap_kek_for(&ctx.kek, new));
        let manifest = BranchManifest {
            base: ctx.manifest.base,
            prev: Some(ctx.manifest_id),
            anchors: ctx.manifest.anchors.clone(),
            closure: ctx.manifest.closure.clone(),
            index_ct: ctx.manifest.index_ct.clone(),
            kek_wraps,
        };
        self.replace_manifest(name, &ctx, manifest, &format!("branch grant {name}"))
    }

    /// Revoke + rewrap, atomically: mint a fresh KEK, re-encrypt the index
    /// under it, and wrap it for every remaining recipient (resolved to
    /// public keys by the caller) — zero content plaintext, zero object-id
    /// churn. `remaining` must cover every currently-wrapped recipient except
    /// the revoked one; anything uncoverable is a loud error, never silent
    /// access loss.
    pub fn branch_revoke(
        &self,
        name: &str,
        identity: &SecretKey,
        revoked: &RecipientId,
        remaining: &[PublicKey],
    ) -> Result<ObjectId> {
        self.guard_states()?;
        let ctx = self.open_private_branch(name, Some(identity))?;
        let current = wrapped_ids(&ctx.manifest);
        if !current.contains(revoked.as_str()) {
            return Err(Error::InvalidArgument(format!(
                "recipient {revoked} holds no wrap on branch {name}"
            )));
        }
        require_nonempty_recipients(remaining, "revoke")?;
        let remaining_ids: BTreeSet<String> = remaining
            .iter()
            .map(|pk| pk.recipient_id().to_string())
            .collect();
        if remaining_ids.contains(revoked.as_str()) {
            return Err(Error::InvalidArgument(format!(
                "revoked recipient {revoked} is still in the remaining set"
            )));
        }
        let uncovered: Vec<String> = current
            .iter()
            .filter(|id| id.as_str() != revoked.as_str() && !remaining_ids.contains(*id))
            .cloned()
            .collect();
        if !uncovered.is_empty() {
            return Err(Error::InvalidArgument(format!(
                "cannot rewrap for current recipient(s) {} — no public key known \
                 (add them to .sc/recipients.toml or revoke them too)",
                uncovered.join(", ")
            )));
        }

        let new_kek = scl_crypto::generate_kek();
        let kek_wraps: Vec<WrappedKey> = remaining
            .iter()
            .map(|pk| scl_crypto::wrap_kek_for(&new_kek, pk))
            .collect();
        let manifest = BranchManifest {
            base: ctx.manifest.base,
            prev: Some(ctx.manifest_id),
            anchors: ctx.manifest.anchors.clone(),
            closure: ctx.manifest.closure.clone(),
            index_ct: ctx.index.encrypt(&new_kek),
            kek_wraps,
        };
        self.replace_manifest(name, &ctx, manifest, &format!("branch revoke {name}"))
    }

    fn replace_manifest(
        &self,
        name: &str,
        ctx: &PrivateCtx,
        manifest: BranchManifest,
        desc: &str,
    ) -> Result<ObjectId> {
        let store_arc = self.vfs.store();
        let new_mid = store_arc.lock().unwrap().put(Object::Manifest(manifest))?;
        refs::write_branch_tip(&self.layout, name, &new_mid)?;
        let head = refs::current_branch(&self.layout)?;
        crate::oplog::record(
            &self.layout,
            desc,
            &head,
            &head,
            &[(name.to_string(), Some(ctx.manifest_id), Some(new_mid))],
        )?;
        Ok(new_mid)
    }

    fn guard_states(&self) -> Result<()> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        Ok(())
    }

    // ---- merge (public -> private) ---------------------------------------------

    /// Merge a PUBLIC branch into the private branch at HEAD (the one legal
    /// direction — private → public is refused everywhere and only `publish`
    /// crosses it). The three-way itself is the existing `three_way_files`,
    /// run against a RAM-only ephemeral store holding the three tree closures
    /// (decrypted inner objects hash to their inner ids, so content
    /// addressing is consistent and no plaintext ever touches disk).
    pub fn merge_into_private(
        &self,
        branch: &str,
        author: &str,
        identity: Option<&SecretKey>,
    ) -> Result<(ObjectId, Vec<String>)> {
        self.guard_states()?;
        let (head, mid, manifest) = self
            .head_private()?
            .ok_or_else(|| Error::NotPrivateBranch("HEAD".into()))?;
        let ctx = self.open_private(&head, mid, manifest, identity)?;
        let sk = identity.expect("open_private succeeded");
        let dirty = self.status_private(identity)?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before merging".into(),
            ));
        }
        let theirs = refs::resolve_tip(&self.layout, branch)?
            .ok_or_else(|| Error::NoSuchBranch(branch.to_string()))?;
        if self.manifest_at(&theirs)?.is_some() {
            return Err(Error::PrivateIntegration(branch.to_string()));
        }
        if self.promisor()?.is_some() {
            return Err(crate::promisor::partial_clone_unsupported("merge"));
        }

        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let inner_tip = ctx.inner_tip()?;
        let ours_snap = self.get_inner_snapshot(&mut store, &ctx, &inner_tip)?;
        let theirs_snap = store.get_snapshot(&theirs)?;

        // Short-circuits over the mixed ancestry.
        let ours_anc = self.inner_ancestors(&mut store, &ctx, inner_tip)?;
        if ours_anc.contains(&theirs) {
            return Err(Error::UpToDate);
        }
        if crate::merge::is_ancestor(&mut store, inner_tip, theirs).unwrap_or(false) {
            // Fast-forward: only possible while the private branch has no
            // private commits yet (a private inner id can never be a public
            // ancestor). The branch STAYS private — the index just adopts the
            // public tip as its inner tip; nothing needs sealing.
            let mut index = ctx.index.clone();
            index.inner_tip = Some(theirs);
            // The inner tip is now a public snapshot descended from `base`
            // (not reachable from it) — anchor it so the manifest stays
            // self-contained and transferable.
            let anchors = extend_anchors(&ctx.manifest.anchors, std::iter::once(theirs));
            let new_manifest = BranchManifest {
                base: ctx.manifest.base,
                prev: Some(ctx.manifest_id),
                anchors,
                closure: ctx.manifest.closure.clone(),
                index_ct: index.encrypt(&ctx.kek),
                kek_wraps: ctx.manifest.kek_wraps.clone(),
            };
            let new_mid = store.put(Object::Manifest(new_manifest.clone()))?;
            let old_paths: BTreeSet<String> = self
                .inner_tree_files(&mut store, &ctx, ours_snap.root)?
                .into_keys()
                .collect();
            let ff_ctx = PrivateCtx {
                manifest_id: new_mid,
                manifest: new_manifest,
                kek: ctx.kek.clone(),
                index,
            };
            let skipped = self.materialize_private(
                "merge",
                &mut store,
                &ff_ctx,
                theirs_snap.root,
                &old_paths,
                &theirs_snap.protection,
                sk,
                false,
            )?;
            drop(store);
            refs::write_branch_tip(&self.layout, &head, &new_mid)?;
            crate::oplog::record(
                &self.layout,
                &format!("merge {branch} (ff)"),
                &head,
                &head,
                &[(head.clone(), Some(ctx.manifest_id), Some(new_mid))],
            )?;
            return Ok((theirs, skipped));
        }

        let base = self
            .merge_base_private(&mut store, &ctx, inner_tip, theirs)?
            .ok_or(Error::NoCommonAncestor)?;
        let base_snap = self.get_inner_snapshot(&mut store, &ctx, &base)?;

        let fm = self.private_three_way(
            &mut store,
            &ctx,
            &ours_snap,
            &theirs_snap,
            &base_snap,
            identity,
        )?;
        let secrets = crate::merge::merge_secrets(
            &base_snap.secrets,
            &ours_snap.secrets,
            &theirs_snap.secrets,
        )?;
        let prefixes = crate::protect::merge_prefixes(
            &ours_snap.protection.prefixes,
            &theirs_snap.protection.prefixes,
        );

        let (entries, new_blobs, wrapped) = decide_merged(&fm);

        if !fm.conflicts.is_empty() {
            // A conflict outside the sparse view has nowhere to show its
            // markers: refuse before any write, like the public path (#220).
            let sparse = self.sparse_spec()?;
            let outside: Vec<&str> = fm
                .conflicts
                .iter()
                .map(String::as_str)
                .filter(|p| !sparse.matches(p))
                .collect();
            if !outside.is_empty() {
                return Err(Error::InvalidArgument(format!(
                    "conflict in {} is outside your sparse checkout; switch to a public branch, \
                     run `sc sparse set` to include it, then retry",
                    outside.join(", ")
                )));
            }
            // Conflict state: the IN-VIEW files land on disk in plaintext
            // (markers, sidecars, decrypted protected content — we hold the
            // identity by construction). Never through the CAS. Out-of-view
            // paths are not laid out; completion re-derives their merged
            // value (`commit_private`, #240). It reads MERGE_HEAD.
            let prior_entries = self.inner_tree_files(&mut store, &ctx, ours_snap.root)?;
            let prior_paths: BTreeSet<String> = prior_entries.keys().cloned().collect();
            // Completion reads the working tree, where a file wins over the
            // merge's addition: refuse one in the way outside the view (#248).
            let merged_paths: BTreeSet<String> = fm.files.iter().map(|f| f.path.clone()).collect();
            self.refuse_untracked_out_of_view_paths("merge", &sparse, &prior_paths, &merged_paths)?;
            // Carried protected ciphertext: decrypt for the resolver to see
            // (completion re-seals it as needed). One this recipient cannot
            // read has its old plaintext dropped, so completion carries the
            // merged entry instead of recommitting the stale one. Decide all
            // of it, and refuse a collision, before writing anything.
            let prots = Protection {
                prefixes: prefixes.clone(),
                wrapped: fm.wrapped_carry.clone(),
            };
            let mut plaintext: BTreeMap<&str, Option<Vec<u8>>> = BTreeMap::new();
            for f in fm.files.iter().filter(|f| sparse.matches(&f.path)) {
                if f.perms & PROTECTED == 0 || f.needs_encrypt {
                    continue;
                }
                let id = Object::blob(f.bytes.clone()).id();
                if let Ok(pt) = crate::protect::decrypt_with(&f.bytes, &id, &[&prots], sk, &f.path)
                {
                    plaintext.insert(&f.path, Some(pt.to_vec()));
                    continue;
                }
                let full = worktree::safe_join(&self.layout.root, &f.path)?;
                // A symlink (even one whose target reads as the old bytes)
                // is the user's file, never the checkout's copy.
                let on_disk = match std::fs::symlink_metadata(&full) {
                    Ok(m) if m.file_type().is_file() => Some(Some(std::fs::read(&full)?)),
                    Ok(_) => Some(None),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(e.into()),
                };
                if let Some(disk) = on_disk {
                    // Only the tracked prior-tip plaintext is ours to drop.
                    let stale = match prior_entries.get(&f.path) {
                        Some((pid, _, perms)) if perms & PROTECTED != 0 => {
                            let ct = self.inner_blob(&mut store, &ctx, pid)?;
                            crate::protect::decrypt_with(
                                &ct,
                                pid,
                                &[&ours_snap.protection],
                                sk,
                                &f.path,
                            )
                            .map(|pt| Some(pt.as_slice()) == disk.as_deref())
                            .unwrap_or(false)
                        }
                        _ => false,
                    };
                    if !stale {
                        return Err(Error::InvalidArgument(format!(
                            "{} exists and is not the tracked copy, but the merged version is \
                             protected and you cannot read it; move it away, then retry",
                            f.path
                        )));
                    }
                }
                plaintext.insert(&f.path, None);
            }
            drop(store);
            // A sidecar lands beside its conflicted file and is removed again
            // at completion or abort, so it must not stand on a file either
            // side tracks or on one the user owns (the public stop's rule).
            let merged_paths: BTreeSet<String> = fm.files.iter().map(|f| f.path.clone()).collect();
            for (name, _) in &fm.sidecars {
                if prior_paths.contains(name) || merged_paths.contains(name) {
                    return Err(Error::InvalidArgument(format!(
                        "merge has conflicts, and its sidecar {name} would overwrite a tracked \
                         file; rename or remove that file, then retry"
                    )));
                }
                let full = worktree::safe_join(&self.layout.root, name)?;
                if full.symlink_metadata().is_ok() {
                    return Err(Error::InvalidArgument(format!(
                        "merge has conflicts, and writing {name} would overwrite an untracked \
                         or ignored file or directory (possibly a sidecar left by an earlier \
                         stop); move it away, then retry"
                    )));
                }
            }
            // Removals first: a failed one must fail the stop before any
            // other write, or completion would commit the stale plaintext.
            for (path, pt) in &plaintext {
                if pt.is_none() {
                    let full = worktree::safe_join(&self.layout.root, path)?;
                    match std::fs::remove_file(&full) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            // Drop the prior-tip paths the merge deleted, with the removals
            // above and before any conflict output is written: a failure here
            // then leaves no markers without a merge state, and is never
            // swallowed (completion would resurrect the file from disk).
            for p in prior_paths.difference(&merged_paths) {
                if !sparse.matches(p) {
                    continue;
                }
                let full = worktree::safe_join(&self.layout.root, p)?;
                match std::fs::remove_file(full) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            // Record what is about to land on disk in plaintext, and the
            // sidecars, before writing it: completion and abort need both
            // (see `conflict_plaintext`). Nothing here is sealed, and it names
            // only paths the checkout already holds.
            crate::conflict_plaintext::write(
                &self.layout,
                &fm.files
                    .iter()
                    .filter(|f| {
                        sparse.matches(&f.path)
                            && (f.needs_encrypt
                                || matches!(plaintext.get(f.path.as_str()), Some(Some(_))))
                    })
                    .map(|f| f.path.clone())
                    .collect::<Vec<_>>(),
            )?;
            crate::conflict_plaintext::write_sidecars(
                &self.layout,
                &fm.sidecars
                    .iter()
                    .map(|(n, _)| n.clone())
                    .collect::<Vec<_>>(),
            )?;
            for f in fm.files.iter().filter(|f| sparse.matches(&f.path)) {
                let full = worktree::safe_join(&self.layout.root, &f.path)?;
                if matches!(plaintext.get(f.path.as_str()), Some(None)) {
                    continue;
                }
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if let Some(Some(pt)) = plaintext.get(f.path.as_str()) {
                    worktree::write_file(&full, &pt[..], f.mode)?;
                } else {
                    worktree::write_file(&full, &f.bytes, f.mode)?;
                }
            }
            for (name, bytes) in &fm.sidecars {
                let full = worktree::safe_join(&self.layout.root, name)?;
                std::fs::write(&full, bytes)?;
            }
            crate::merge_state::write(&self.layout, &theirs, &fm.conflicts, None)?;
            return Err(Error::MergeConflicts(fm.conflicts.len()));
        }

        // Clean merge: seal + commit in one step.
        let mut carried = self.inner_tree_closure(&mut store, &ctx, ours_snap.root)?;
        carried.extend(
            worktree::tree_file_entries_with_perms(&mut store, theirs_snap.root)?
                .values()
                .map(|(id, _, _)| *id),
        );
        carried.extend(public_tree_ids(&mut store, theirs_snap.root)?);
        carried.extend(
            worktree::tree_file_entries_with_perms(&mut store, base_snap.root)?
                .values()
                .map(|(id, _, _)| *id),
        );
        carried.extend(public_tree_ids(&mut store, base_snap.root)?);

        let mut index = ctx.index.clone();
        let new_tip = self.seal_commit(
            &mut store,
            &ctx,
            &mut index,
            &carried,
            entries,
            new_blobs,
            vec![inner_tip, theirs],
            secrets,
            Protection { prefixes, wrapped },
            author,
            &format!("merge {branch}"),
        )?;
        // Anchor the merged-in public tip: its objects were carried into the
        // sealed tree as unsealed public references (copy-on-write).
        let anchors = extend_anchors(&ctx.manifest.anchors, std::iter::once(theirs));
        let new_manifest = BranchManifest {
            base: ctx.manifest.base,
            prev: Some(ctx.manifest_id),
            anchors,
            closure: index.entries.values().map(|e| e.sealed).collect(),
            index_ct: index.encrypt(&ctx.kek),
            kek_wraps: ctx.manifest.kek_wraps.clone(),
        };
        let new_mid = store.put(Object::Manifest(new_manifest.clone()))?;
        // Re-lay the working tree from the merged inner tip.
        let old_paths: BTreeSet<String> = self
            .inner_tree_files(&mut store, &ctx, ours_snap.root)?
            .into_keys()
            .collect();
        let merged_ctx = PrivateCtx {
            manifest_id: new_mid,
            manifest: new_manifest,
            kek: ctx.kek.clone(),
            index,
        };
        let merged_root = self
            .get_inner_snapshot(&mut store, &merged_ctx, &new_tip)?
            .root;
        let merged_prot = self
            .get_inner_snapshot(&mut store, &merged_ctx, &new_tip)?
            .protection;
        let skipped = self.materialize_private(
            "merge",
            &mut store,
            &merged_ctx,
            merged_root,
            &old_paths,
            &merged_prot,
            sk,
            false,
        )?;
        drop(store);
        refs::write_branch_tip(&self.layout, &head, &new_mid)?;
        crate::oplog::record(
            &self.layout,
            &format!("merge {branch}"),
            &head,
            &head,
            &[(head.clone(), Some(ctx.manifest_id), Some(new_mid))],
        )?;
        Ok((new_tip, skipped))
    }

    /// The three-way of a public `theirs` into the private `ours`, run against
    /// a RAM-only store holding the three tree closures (decrypted inner
    /// objects hash to their inner ids, so content addressing is consistent
    /// and no plaintext ever touches disk). Deterministic in its inputs, so
    /// `commit_private` re-derives a stopped merge's outcome instead of
    /// persisting it (#240).
    fn private_three_way(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        ours: &Snapshot,
        theirs: &Snapshot,
        base: &Snapshot,
        identity: Option<&SecretKey>,
    ) -> Result<crate::merge::FileMerge> {
        let mut ram = Store::with_budget(usize::MAX / 2);
        self.copy_closure_inner(store, ctx, ours.root, &mut ram)?;
        copy_closure_public(store, theirs.root, &mut ram)?;
        copy_closure_public(store, base.root, &mut ram)?;
        crate::merge::three_way_files(
            &mut ram,
            Some((base.root, &base.protection)),
            (ours.root, &ours.protection),
            (theirs.root, &theirs.protection),
            identity,
        )
    }

    /// Copy an inner tree closure (trees + blobs, decoded plaintext values)
    /// into a RAM-only store. Ids are content addresses of the decoded
    /// values, so the copy is a faithful CAS fragment.
    fn copy_closure_inner(
        &self,
        store: &mut Store,
        ctx: &PrivateCtx,
        root: ObjectId,
        ram: &mut Store,
    ) -> Result<()> {
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if ram.contains(&id) {
                continue;
            }
            let obj = self.get_inner(store, ctx, &id)?;
            if let Object::Tree(t) = &obj {
                for e in &t.entries {
                    stack.push(e.id);
                }
            }
            ram.put(obj)?;
        }
        Ok(())
    }

    // ---- publish ----------------------------------------------------------------

    /// Publish a private branch: replay its full private history as plaintext
    /// public snapshots (messages/authors/timestamps preserved, parents
    /// remapped, fork point unchanged), re-sealing protected-prefix files
    /// through the normal P7/P33 path, then move the branch ref to the
    /// published tip. The scanner runs over every decrypted plain file BEFORE
    /// any public object is written — a secret committed under seal must not
    /// sail into plaintext history at the moment of publish. One ref move =
    /// the atomic point; the manifest chain becomes garbage for `sc gc`.
    pub fn branch_publish(&self, name: &str, identity: &SecretKey) -> Result<(ObjectId, usize)> {
        self.guard_states()?;
        let ctx = self.open_private_branch(name, Some(identity))?;
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let inner_tip = ctx.inner_tip()?;

        // Nothing private ever committed: the ref just becomes the public tip.
        if !ctx.index.entries.contains_key(&inner_tip) {
            drop(store);
            refs::write_branch_tip(&self.layout, name, &inner_tip)?;
            let head = refs::current_branch(&self.layout)?;
            crate::oplog::record(
                &self.layout,
                &format!("branch publish {name}"),
                &head,
                &head,
                &[(name.to_string(), Some(ctx.manifest_id), Some(inner_tip))],
            )?;
            return Ok((inner_tip, 0));
        }

        // Collect the private snapshot chain (ids in the index), topo-ordered
        // parents-first.
        let order = {
            let mut order: Vec<ObjectId> = Vec::new();
            let mut seen: BTreeSet<ObjectId> = BTreeSet::new();
            let mut stack = vec![(inner_tip, false)];
            while let Some((id, expanded)) = stack.pop() {
                if expanded {
                    order.push(id);
                    continue;
                }
                if !seen.insert(id) {
                    continue;
                }
                stack.push((id, true));
                for p in self.get_inner_snapshot(&mut store, &ctx, &id)?.parents {
                    if ctx.index.entries.contains_key(&p) && !seen.contains(&p) {
                        stack.push((p, false));
                    }
                }
            }
            order
        };

        // Phase 1: build every public object in memory, scanning as we go.
        // NOTHING is written until the whole branch passes.
        let mut to_put: Vec<Object> = Vec::new();
        let mut id_map: BTreeMap<ObjectId, ObjectId> = BTreeMap::new(); // inner -> published
        let mut tip_cache_records: Vec<(String, Vec<u8>, ObjectId)> = Vec::new();
        for inner_id in &order {
            let snap = self.get_inner_snapshot(&mut store, &ctx, inner_id)?;
            let files = self.inner_tree_files(&mut store, &ctx, snap.root)?;
            let mut plain: Vec<(String, Vec<u8>, FileMode)> = Vec::new();
            let mut to_encrypt: Vec<crate::protect::SealInput> = Vec::new();
            let mut published: BTreeMap<String, (ObjectId, FileMode, u8)> = BTreeMap::new();
            let mut wrapped: BTreeMap<ObjectId, Vec<WrappedKey>> = BTreeMap::new();
            for (path, (id, mode, perms)) in &files {
                if perms & PROTECTED != 0 {
                    // Carried path-ciphertext: already a public object; keep
                    // the entry + its wraps verbatim.
                    if let Some(wks) = snap.protection.wrapped.get(id) {
                        wrapped.insert(*id, wks.clone());
                    }
                    published.insert(path.clone(), (*id, *mode, *perms));
                    continue;
                }
                let bytes = self.inner_blob(&mut store, &ctx, id)?;
                match crate::protect::matching_prefix(&snap.protection, path) {
                    Some(rule) => {
                        to_encrypt.push((path.clone(), bytes, *mode, rule.granted_keys()))
                    }
                    None => plain.push((path.clone(), bytes, *mode)),
                }
            }
            let report = self.scan_files(&plain)?;
            if !report.is_empty() {
                return Err(Error::SecretDetected(report));
            }
            // Keep the pre-seal plaintexts of the TIP snapshot's protected
            // files: the cache records below need them so the working tree
            // reads clean right after publish (rewrap's discipline).
            let seal_plaintexts: BTreeMap<String, Vec<u8>> = if *inner_id == inner_tip {
                to_encrypt
                    .iter()
                    .map(|(p, b, _, _)| (p.clone(), b.clone()))
                    .collect()
            } else {
                BTreeMap::new()
            };
            let (encrypted, fresh) = crate::protect::encrypt_protected(to_encrypt)?;
            for (path, ct, mode, perms) in encrypted {
                let blob = Object::blob(ct.clone());
                let bid = blob.id();
                published.insert(path.clone(), (bid, mode, perms));
                to_put.push(blob);
                if let Some(b) = seal_plaintexts.get(&path) {
                    tip_cache_records.push((path.clone(), b.clone(), bid));
                }
            }
            for (id, wks) in fresh {
                wrapped.insert(id, wks);
            }
            for (path, bytes, mode) in &plain {
                let blob = Object::blob(bytes.clone());
                published.insert(path.clone(), (blob.id(), *mode, 0));
                to_put.push(blob);
            }
            let (root, trees) = build_tree_objects(&published)?;
            to_put.extend(trees);
            let parents: Vec<ObjectId> = snap
                .parents
                .iter()
                .map(|p| id_map.get(p).copied().unwrap_or(*p))
                .collect();
            let pub_snap = Object::Snapshot(Snapshot {
                root,
                parents,
                author: snap.author.clone(),
                timestamp: snap.timestamp,
                message: snap.message.clone(),
                secrets: snap.secrets.clone(),
                protection: Protection {
                    prefixes: snap.protection.prefixes.clone(),
                    wrapped,
                },
            });
            id_map.insert(*inner_id, pub_snap.id());
            to_put.push(pub_snap);
        }
        let published_tip = *id_map.get(&inner_tip).expect("tip is in order");
        let resealed = tip_cache_records.len();

        // Phase 2: everything passed — write the objects, then the ref.
        for obj in to_put {
            store.put(obj)?;
        }
        drop(store);
        refs::write_branch_tip(&self.layout, name, &published_tip)?;
        // Cache records so protected files read clean immediately (best-effort).
        if !tip_cache_records.is_empty() {
            if let Ok(mut cache) = self.open_protected_cache() {
                for (path, plaintext, bid) in &tip_cache_records {
                    cache.record(path, plaintext, *bid);
                }
                cache.save_best_effort();
            }
        }
        let head = refs::current_branch(&self.layout)?;
        crate::oplog::record(
            &self.layout,
            &format!("branch publish {name}"),
            &head,
            &head,
            &[(name.to_string(), Some(ctx.manifest_id), Some(published_tip))],
        )?;
        Ok((published_tip, resealed))
    }
}

/// Decide the merged file map for the inner world: carried PROTECTED
/// ciphertext keeps its id + wraps; everything else (plain carries, diff3
/// outputs, decrypted protected merges) becomes a plain inner blob — publish
/// re-seals protected prefixes into public form.
#[allow(clippy::type_complexity)]
fn decide_merged(
    fm: &crate::merge::FileMerge,
) -> (
    BTreeMap<String, (ObjectId, FileMode, u8)>,
    BTreeMap<ObjectId, Vec<u8>>,
    BTreeMap<ObjectId, Vec<WrappedKey>>,
) {
    let mut entries = BTreeMap::new();
    let mut new_blobs = BTreeMap::new();
    let mut wrapped = BTreeMap::new();
    for f in &fm.files {
        let id = Object::blob(f.bytes.clone()).id();
        if f.perms & PROTECTED != 0 && !f.needs_encrypt {
            if let Some(wks) = fm.wrapped_carry.get(&id) {
                wrapped.insert(id, wks.clone());
            }
            entries.insert(f.path.clone(), (id, f.mode, f.perms));
        } else {
            new_blobs.entry(id).or_insert_with(|| f.bytes.clone());
            entries.insert(f.path.clone(), (id, f.mode, 0));
        }
    }
    (entries, new_blobs, wrapped)
}

/// Copy a PUBLIC tree closure (trees + blobs) into the RAM store.
fn copy_closure_public(store: &mut Store, root: ObjectId, ram: &mut Store) -> Result<()> {
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if ram.contains(&id) {
            continue;
        }
        let obj = store.get(&id)?;
        if let Object::Tree(t) = &obj {
            for e in &t.entries {
                stack.push(e.id);
            }
        }
        ram.put(obj)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-priv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(root: &std::path::Path, rel: &str, content: &str) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    /// A repo with one public commit plus alice/bob keypairs.
    fn setup(
        tag: &str,
    ) -> (
        std::path::PathBuf,
        Repo,
        (SecretKey, PublicKey),
        (SecretKey, PublicKey),
    ) {
        let root = tmp_root(tag);
        let repo = Repo::init(&root).unwrap();
        write(&root, "readme.txt", "public content\n");
        write(&root, "src/lib.rs", "pub fn hello() {}\n");
        repo.commit("tester", "public base").unwrap();
        let alice = scl_crypto::generate_keypair();
        let bob = scl_crypto::generate_keypair();
        (root, repo, alice, bob)
    }

    /// Every non-sealed object in the store must be free of `needle`: the
    /// honest opacity check (on-disk bytes are zstd-compressed, so a raw
    /// byte scan of `.sc/objects` would pass vacuously).
    fn assert_opaque(repo: &Repo, needle: &[u8]) {
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = store.all_ids().unwrap();
        for id in ids {
            let obj = store.get(&id).unwrap();
            match &obj {
                Object::Sealed(_) | Object::Manifest(_) => continue,
                _ => {}
            }
            let enc = obj.encode();
            assert!(
                !enc.windows(needle.len()).any(|w| w == needle),
                "plaintext {:?} leaked into a public {} object {id}",
                String::from_utf8_lossy(needle),
                obj.kind_name()
            );
        }
    }

    #[test]
    fn lifecycle_commit_status_log_and_disk_hygiene() {
        let (root, repo, (alice_sk, _alice_pk), _bob) = setup("life");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();

        write(&root, "fix.txt", "THE-SECRET-FIX\n");
        write(&root, "src/lib.rs", "pub fn hello() { patched(); }\n");
        let st = repo.status_private(Some(&alice_sk)).unwrap();
        assert_eq!(st.added, vec!["fix.txt".to_string()]);
        assert_eq!(st.modified, vec!["src/lib.rs".to_string()]);

        repo.commit_private("alice", "private: SECRET-MSG", Some(&alice_sk))
            .unwrap();
        let st = repo.status_private(Some(&alice_sk)).unwrap();
        assert!(st.added.is_empty() && st.modified.is_empty() && st.deleted.is_empty());

        // Log: private commit first, then straight into public history.
        let log = repo.log_private(Some(&alice_sk)).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].1.message, "private: SECRET-MSG");
        assert_eq!(log[1].1.message, "public base");

        // Opacity: no non-sealed object carries the content, the path, or
        // the message.
        assert_opaque(&repo, b"THE-SECRET-FIX");
        assert_opaque(&repo, b"fix.txt");
        assert_opaque(&repo, b"SECRET-MSG");

        // Switching to the public branch removes the private plaintext from
        // disk and restores the public content.
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        assert!(!root.join("fix.txt").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("src/lib.rs")).unwrap(),
            "pub fn hello() {}\n"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Switching to a private branch that tracks `fix.txt` must not replace an
    /// untracked `fix.txt` on the public checkout.
    #[test]
    fn switching_to_a_private_branch_refuses_to_overwrite_an_untracked_file() {
        let (root, repo, (alice_sk, _alice_pk), _bob) = setup("guard-private");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "PRIVATE\n");
        repo.commit_private("alice", "adds fix.txt", Some(&alice_sk))
            .unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        assert!(!root.join("fix.txt").exists());
        write(&root, "fix.txt", "MINE\n");

        let err = repo
            .switch_with_identity("fix", Some(&alice_sk))
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidArgument(m) if m.contains("would overwrite")),
            "got {err:?}"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("fix.txt")).unwrap(),
            "MINE\n"
        );
        assert!(repo.head_private().unwrap().is_none(), "HEAD did not move");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn non_recipient_is_refused_everywhere() {
        let (root, repo, (alice_sk, _), (bob_sk, _bob_pk)) = setup("noaccess");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "sealed\n");
        repo.commit_private("alice", "m", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        // Bob (not a recipient) and keyless are both refused.
        assert!(matches!(
            repo.switch_with_identity("fix", Some(&bob_sk)),
            Err(Error::PrivateNoAccess(_))
        ));
        assert!(matches!(
            repo.switch_with_identity("fix", None),
            Err(Error::PrivateNoAccess(_))
        ));
        assert!(!repo.can_open_private("fix", Some(&bob_sk)).unwrap());
        assert!(repo.can_open_private("fix", Some(&alice_sk)).unwrap());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cow_sealing_unchanged_content_is_never_resealed() {
        let (root, repo, (alice_sk, _), _bob) = setup("cow");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        // Creation seals nothing (copy-on-write: empty closure).
        let (_, m0) = repo.branch_manifest("fix").unwrap().unwrap();
        assert!(m0.closure.is_empty(), "creation must seal nothing");

        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "v1\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        // One new blob + one changed root tree + one snapshot = 3 sealed.
        let (_, m1) = repo.branch_manifest("fix").unwrap().unwrap();
        assert_eq!(
            m1.closure.len(),
            3,
            "unchanged src/ subtree must be carried"
        );

        // A commit with no working-tree change seals exactly ONE new object
        // (the snapshot; even the root tree id is unchanged).
        repo.commit_private("alice", "c2 empty", Some(&alice_sk))
            .unwrap();
        let (_, m2) = repo.branch_manifest("fix").unwrap().unwrap();
        assert_eq!(
            m2.closure.len(),
            4,
            "no-change commit seals only the snapshot"
        );
        assert_eq!(m2.prev, Some(Object::Manifest(m1.clone()).id()));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_is_wrap_only_and_revoke_rotates_the_kek() {
        let (root, repo, (alice_sk, alice_pk), (bob_sk, bob_pk)) = setup("members");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "v1\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        let (_, before) = repo.branch_manifest("fix").unwrap().unwrap();

        // Grant: bob can open; closure and index bytes are untouched.
        assert!(!repo.can_open_private("fix", Some(&bob_sk)).unwrap());
        repo.branch_grant("fix", &alice_sk, &bob_pk).unwrap();
        assert!(repo.can_open_private("fix", Some(&bob_sk)).unwrap());
        let (_, after_grant) = repo.branch_manifest("fix").unwrap().unwrap();
        assert_eq!(after_grant.closure, before.closure);
        assert_eq!(after_grant.index_ct, before.index_ct, "grant is wrap-only");

        // Revoke bob: fresh KEK, index re-encrypted, object ids untouched.
        repo.branch_revoke(
            "fix",
            &alice_sk,
            &bob_pk.recipient_id(),
            std::slice::from_ref(&alice_pk),
        )
        .unwrap();
        let (_, after_revoke) = repo.branch_manifest("fix").unwrap().unwrap();
        assert!(!repo.can_open_private("fix", Some(&bob_sk)).unwrap());
        assert!(repo.can_open_private("fix", Some(&alice_sk)).unwrap());
        assert_eq!(after_revoke.closure, before.closure, "zero object churn");
        assert_ne!(after_revoke.index_ct, before.index_ct, "index re-encrypted");

        // Guard rails: revoking with a remaining set that misses a current
        // recipient, or an empty one, is a loud error.
        repo.branch_grant("fix", &alice_sk, &bob_pk).unwrap();
        assert!(matches!(
            repo.branch_revoke("fix", &alice_sk, &bob_pk.recipient_id(), &[]),
            Err(Error::InvalidArgument(_))
        ));
        let (charlie_sk, charlie_pk) = scl_crypto::generate_keypair();
        let _ = charlie_sk;
        repo.branch_grant("fix", &alice_sk, &charlie_pk).unwrap();
        // Remaining covers alice but not charlie -> refuse (never silent loss).
        assert!(matches!(
            repo.branch_revoke(
                "fix",
                &alice_sk,
                &bob_pk.recipient_id(),
                std::slice::from_ref(&alice_pk)
            ),
            Err(Error::InvalidArgument(_))
        ));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn publish_replays_history_and_the_branch_becomes_public() {
        let (root, repo, (alice_sk, _), _bob) = setup("publish");
        let base = repo.head_tip().unwrap().unwrap();
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "v1\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "v2\n");
        repo.commit_private("alice", "c2", Some(&alice_sk)).unwrap();

        let (published_tip, resealed) = repo.branch_publish("fix", &alice_sk).unwrap();
        assert_eq!(resealed, 0);
        // The ref now points at a plaintext snapshot; normal log works and
        // history is preserved commit-by-commit down to the unchanged base.
        assert!(repo.branch_manifest("fix").unwrap().is_none());
        let log = repo.log().unwrap();
        assert_eq!(log[0].0, published_tip);
        assert_eq!(log[0].1.message, "c2");
        assert_eq!(log[1].1.message, "c1");
        assert_eq!(log[2].0, base, "fork-point parent keeps its public id");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn publish_scanner_gate_aborts_before_any_public_write() {
        let (root, repo, (alice_sk, _), _bob) = setup("pubscan");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        // A secret-looking file: allowlist it so the private COMMIT passes,
        // then remove the allowlist so PUBLISH must catch it.
        let secret = "aws_secret_access_key = \"AKIAIOSFODNN7EXAMPLE99\"\n";
        write(&root, "creds.env", secret);
        let blob_id = Object::blob(secret.as_bytes().to_vec()).id();
        let allow = root.join(".sc/scanner-allowlist.toml");
        std::fs::write(
            &allow,
            format!("[[allow]]\nblob = \"{}\"\n", blob_id.to_hex()),
        )
        .unwrap();
        repo.commit_private("alice", "sealed secret", Some(&alice_sk))
            .unwrap();
        std::fs::remove_file(&allow).unwrap();

        let (mid_before, _) = repo.branch_manifest("fix").unwrap().unwrap();
        let objects_before = {
            let store_arc = repo.vfs().store();
            let n = store_arc.lock().unwrap().all_ids().unwrap().len();
            n
        };
        assert!(matches!(
            repo.branch_publish("fix", &alice_sk),
            Err(Error::SecretDetected(_))
        ));
        // Nothing public was written and the ref did not move.
        let (mid_after, _) = repo.branch_manifest("fix").unwrap().unwrap();
        assert_eq!(
            mid_before, mid_after,
            "ref must not move on a failed publish"
        );
        let objects_after = {
            let store_arc = repo.vfs().store();
            let n = store_arc.lock().unwrap().all_ids().unwrap().len();
            n
        };
        assert_eq!(
            objects_before, objects_after,
            "a failed publish must write no objects"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_public_into_private_clean_then_conflicted() {
        let (root, repo, (alice_sk, _), _bob) = setup("mergein");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "private line\n");
        repo.commit_private("alice", "private c1", Some(&alice_sk))
            .unwrap();

        // main moves on with a DISJOINT file: merge-in resolves clean.
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "main-only.txt", "from main\n");
        repo.commit("tester", "main moves").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        let (merged, _skipped) = repo
            .merge_into_private("main", "alice", Some(&alice_sk))
            .unwrap();
        assert!(root.join("main-only.txt").exists());
        assert!(root.join("fix.txt").exists());
        // Two parents: prior inner tip + main's public tip.
        let log = repo.log_private(Some(&alice_sk)).unwrap();
        assert_eq!(log[0].0, merged);
        assert_eq!(log[0].1.parents.len(), 2);
        assert_opaque(&repo, b"private line");

        // Conflicting edits on BOTH sides stop with markers + merge state.
        // `whichpub.txt` is a public file added alongside the conflict — the
        // conflict-completion path must anchor it just like the clean path.
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "shared.txt", "base\n");
        write(&root, "whichpub.txt", "public-conflict-era\n");
        repo.commit("tester", "add shared").unwrap();
        let pub_blob = Object::blob("public-conflict-era\n".as_bytes().to_vec()).id();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        repo.merge_into_private("main", "alice", Some(&alice_sk))
            .unwrap();
        write(&root, "shared.txt", "private edit\n");
        repo.commit_private("alice", "edit shared", Some(&alice_sk))
            .unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "shared.txt", "public edit\n");
        repo.commit("tester", "edit shared on main").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        assert!(matches!(
            repo.merge_into_private("main", "alice", Some(&alice_sk)),
            Err(Error::MergeConflicts(1))
        ));
        let marked = std::fs::read_to_string(root.join("shared.txt")).unwrap();
        assert!(marked.contains("<<<<<<<"), "markers on disk: {marked}");
        // Resolve + complete through the private commit path: two parents.
        write(&root, "shared.txt", "resolved\n");
        let completed = repo
            .commit_private("alice", "resolve merge", Some(&alice_sk))
            .unwrap();
        let log = repo.log_private(Some(&alice_sk)).unwrap();
        assert_eq!(log[0].0, completed);
        assert_eq!(log[0].1.parents.len(), 2, "completion records both parents");
        assert!(!crate::merge_state::in_progress(repo.layout()));
        // The CONFLICT-completion path anchors merged-in public content too:
        // a public file brought in alongside the conflict stays reachable
        // from the manifest alone (transferable), same as the clean path.
        let (mid, _) = repo.branch_manifest("fix").unwrap().unwrap();
        let reachable = {
            let store_arc = repo.vfs().store();
            let mut store = store_arc.lock().unwrap();
            crate::reachable::reachable_objects(&mut *store, &[mid]).unwrap()
        };
        assert!(
            reachable.contains(&pub_blob),
            "conflict-completed merge must anchor its merged-in public blob"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merged_in_private_branch_is_self_contained_for_transfer() {
        // Regression (advisor review): a public commit merged INTO a private
        // branch is carried into the sealed tree as an unsealed public
        // reference (copy-on-write). Without a reachability anchor on the
        // manifest, pushing only the private branch to a peer lacking that
        // public commit would strand the sealed tree. The manifest's closure
        // walk MUST reach the merged-in public blob.
        let (root, repo, (alice_sk, _), _bob) = setup("selfcontained");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "private\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();

        // main gains a NEW file after the fork, then merge it in.
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "main-only.txt", "public-after-fork\n");
        repo.commit("tester", "b2").unwrap();
        let main_blob = Object::blob("public-after-fork\n".as_bytes().to_vec()).id();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        repo.merge_into_private("main", "alice", Some(&alice_sk))
            .unwrap();

        let (mid, _) = repo.branch_manifest("fix").unwrap().unwrap();
        // The crisp discriminator: reachability from the manifest tip ALONE
        // (a keyless transfer's want set) must contain the merged-in blob.
        let store_arc = repo.vfs().store();
        let reachable = {
            let mut store = store_arc.lock().unwrap();
            crate::reachable::reachable_objects(&mut *store, &[mid]).unwrap()
        };
        assert!(
            reachable.contains(&main_blob),
            "merged-in public blob must be reachable from the private manifest \
             (else the branch is non-transferable)"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn recipient_opens_a_merged_branch_cloned_without_the_public_source() {
        // The transfer-level twin: clone ONLY the private branch's closure
        // into a fresh peer that never received the public branch the merge
        // pulled from, and assert a recipient can still switch onto it. Built
        // by copying exactly the manifest's reachable set (what a filtered
        // want for that ref would transfer) into a fresh store.
        let (root, repo, (alice_sk, _), _bob) = setup("mergeclone");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "private\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "main-only.txt", "public-after-fork\n");
        repo.commit("tester", "b2").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        repo.merge_into_private("main", "alice", Some(&alice_sk))
            .unwrap();
        let (mid, _) = repo.branch_manifest("fix").unwrap().unwrap();

        // Peer repo: copy the manifest's reachable closure only (no `main`
        // ref, no oplog), point `fix` at the manifest, and open it.
        let peer_root = tmp_root("mergeclone-peer");
        let peer = Repo::init(&peer_root).unwrap();
        {
            let src_arc = repo.vfs().store();
            let mut src = src_arc.lock().unwrap();
            let reachable = crate::reachable::reachable_objects(&mut *src, &[mid]).unwrap();
            let dst_arc = peer.vfs().store();
            let mut dst = dst_arc.lock().unwrap();
            for id in &reachable {
                let obj = src.get(id).unwrap();
                dst.put(obj).unwrap();
            }
        }
        crate::refs::write_branch_tip(peer.layout(), "fix", &mid).unwrap();
        // Leave HEAD on the unborn default (like a fresh clone) so the switch
        // is a genuine cross-branch materialize, not a same-branch no-op that
        // would dirty-check an unmaterialized tree.

        // The recipient opens the merged branch on a peer that never had `main`.
        let skipped = peer
            .switch_with_identity("fix", Some(&alice_sk))
            .expect("recipient must open a merged branch cloned without the public source");
        assert!(skipped.is_empty());
        assert_eq!(
            std::fs::read_to_string(peer_root.join("main-only.txt")).unwrap(),
            "public-after-fork\n",
            "the merged-in public file must materialize on the peer"
        );
        assert_eq!(
            std::fs::read_to_string(peer_root.join("fix.txt")).unwrap(),
            "private\n"
        );

        drop(repo);
        drop(peer);
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&peer_root).unwrap();
    }

    #[test]
    fn private_to_public_integration_is_refused() {
        let (root, repo, (alice_sk, _), _bob) = setup("valve");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "sealed\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        assert!(matches!(
            repo.merge_with_identity("fix", "tester", None),
            Err(Error::PrivateIntegration(_))
        ));
        assert!(matches!(
            repo.cherry_pick("fix", "tester", None, None),
            Err(Error::PrivateIntegration(_))
        ));
        assert!(matches!(
            repo.rebase("fix", "tester", None),
            Err(Error::PrivateIntegration(_))
        ));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn undo_restores_the_previous_manifest() {
        let (root, repo, (alice_sk, _), _bob) = setup("undo");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "v1\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        let (mid1, _) = repo.branch_manifest("fix").unwrap().unwrap();
        write(&root, "fix.txt", "v2\n");
        repo.commit_private("alice", "c2", Some(&alice_sk)).unwrap();

        repo.undo().unwrap();
        let (mid_after, _) = repo.branch_manifest("fix").unwrap().unwrap();
        assert_eq!(mid_after, mid1, "undo restores the prior manifest");
        // The branch still opens and reads correctly.
        let log = repo.log_private(Some(&alice_sk)).unwrap();
        assert_eq!(log[0].1.message, "c1");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_preserves_the_manifest_closure() {
        let (root, repo, (alice_sk, _), _bob) = setup("gc");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "survives gc\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();

        repo.gc(std::time::Duration::ZERO).unwrap();

        // Everything still reads after a zero-grace gc.
        let log = repo.log_private(Some(&alice_sk)).unwrap();
        assert_eq!(log[0].1.message, "c1");
        let st = repo.status_private(Some(&alice_sk)).unwrap();
        assert!(st.added.is_empty() && st.modified.is_empty() && st.deleted.is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn filtered_clone_excludes_private_branches_full_clone_carries_them() {
        let (root, repo, (alice_sk, _), _bob) = setup("clonefilter");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "src/private.rs", "sealed\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        drop(repo);

        // Full clone: the private ref travels (ciphertext + manifest).
        let full_dst = tmp_root("clonefilter-full");
        let full = Repo::clone_to(&root, &full_dst).unwrap();
        assert!(full.branch_manifest("fix").unwrap().is_some());
        full.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        assert_eq!(
            std::fs::read_to_string(full_dst.join("src/private.rs")).unwrap(),
            "sealed\n"
        );
        drop(full);

        // Filtered clone: the private ref is excluded entirely.
        let part_dst = tmp_root("clonefilter-part");
        let part = Repo::clone_url_filtered(
            &root.display().to_string(),
            &part_dst,
            Some(&["src/".to_string()]),
        )
        .unwrap();
        let names: Vec<String> = part
            .branches()
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(
            !names.contains(&"fix".to_string()),
            "filtered clone must exclude private refs"
        );
        drop(part);

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&full_dst).unwrap();
        std::fs::remove_dir_all(&part_dst).unwrap();
    }

    /// ADR-0055 B2: "filter active" is `prefixes || blob_limit`, so a clone
    /// whose only filter is a size limit also leaves the private ref out.
    #[test]
    fn size_only_clone_excludes_private_branches() {
        let (root, repo, (alice_sk, _), _bob) = setup("clonesize");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "src/private.rs", "sealed\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        drop(repo);

        let part_dst = tmp_root("clonesize-part");
        let part = Repo::clone_url_limited(
            &root.display().to_string(),
            &part_dst,
            &[],
            Some(1024),
            false,
        )
        .unwrap();
        let names: Vec<String> = part
            .branches()
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(
            !names.contains(&"fix".to_string()),
            "a size-only clone must exclude private refs: {names:?}"
        );
        assert!(names.contains(&"main".to_string()));
        drop(part);

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&part_dst).unwrap();
    }

    #[test]
    fn wire_pack_for_a_private_branch_carries_ciphertext_only() {
        let (root, repo, (alice_sk, _), _bob) = setup("wire");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "wire-secret.txt", "WIRE-SENTINEL-CONTENT\n");
        repo.commit_private("alice", "WIRE-SENTINEL-MESSAGE", Some(&alice_sk))
            .unwrap();
        let (mid, manifest) = repo.branch_manifest("fix").unwrap().unwrap();
        drop(repo);

        // Build the exact pack a push/fetch of this branch would stream (the
        // wire server's GetPack delegates to this same builder), then DECODE
        // every record: pack records are zstd-compressed, so asserting on the
        // raw stream would be vacuous. Every decoded object must be Sealed,
        // the manifest itself, or free of the plaintext markers.
        let transport = crate::transport::LocalTransport::open(&root).unwrap();
        let guard = transport.build_pack_tempfile(&[mid], &[], None).unwrap();
        let pack = std::fs::read(guard.path()).unwrap();
        let objects = scl_core::pack::parse_pack(&pack).unwrap();
        assert!(
            objects.iter().any(|(id, _)| *id == mid),
            "manifest must travel"
        );
        for sealed_id in &manifest.closure {
            assert!(
                objects.iter().any(|(id, _)| id == sealed_id),
                "sealed closure object missing from pack"
            );
        }
        for (id, obj) in &objects {
            match obj {
                Object::Sealed(_) | Object::Manifest(_) => continue,
                _ => {}
            }
            let enc = obj.encode();
            for needle in [
                b"WIRE-SENTINEL-CONTENT".as_slice(),
                b"WIRE-SENTINEL-MESSAGE".as_slice(),
                b"wire-secret.txt".as_slice(),
            ] {
                assert!(
                    !enc.windows(needle.len()).any(|w| w == needle),
                    "plaintext leaked in wire object {id}"
                );
            }
        }

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn manifest_ancestry_is_prev_chain_and_publish_is_not_a_fast_forward() {
        let (root, repo, (alice_sk, _), (_, bob_pk)) = setup("ancestry");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        let (m1, _) = repo.branch_manifest("fix").unwrap().unwrap();
        repo.branch_grant("fix", &alice_sk, &bob_pk).unwrap();
        let (m2, _) = repo.branch_manifest("fix").unwrap().unwrap();

        let store_arc = repo.vfs().store();
        {
            let mut store = store_arc.lock().unwrap();
            // Push's ff check runs over the manifest prev chain: the
            // superseded manifest is an ancestor of its successor, never the
            // reverse (a stale manifest can't ff over a newer one).
            assert!(crate::merge::is_ancestor(&mut store, m1, m2).unwrap());
            assert!(!crate::merge::is_ancestor(&mut store, m2, m1).unwrap());
        }

        // Publish is a REWRITE, not a fast-forward: the published snapshot
        // shares no structural link with the manifest it replaced (ids differ
        // by construction), so the pre-publish manifest is NOT an ancestor of
        // the published tip. This is what makes a rollback-republish over a
        // newer remote manifest a non-ff (refused) instead of a silent
        // clobber of grants/revokes/commits — the Copilot-review data-loss
        // hole. A publish-push over a remote still holding the private
        // manifest is a genuine non-ff: the remote fetches, or the operator
        // force-pushes (same posture as amend/rebase).
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "fix.txt", "v1\n");
        repo.commit_private("alice", "c1", Some(&alice_sk)).unwrap();
        let (m3, _) = repo.branch_manifest("fix").unwrap().unwrap();
        let (published, _) = repo.branch_publish("fix", &alice_sk).unwrap();
        {
            let mut store = store_arc.lock().unwrap();
            assert!(
                !crate::merge::is_ancestor(&mut store, m3, published).unwrap(),
                "publish must not read as a fast-forward over the private manifest"
            );
            // And crucially: a ROLLED-BACK older manifest is likewise not an
            // ancestor of a published tip that shares its base — the specific
            // hole the reviewer flagged.
            assert!(!crate::merge::is_ancestor(&mut store, m1, published).unwrap());
        }

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn protected_paths_survive_a_private_round_trip() {
        let (root, repo, (alice_sk, alice_pk), _bob) = setup("protpath");
        // A protected prefix on the PUBLIC branch first.
        repo.protect("vault/", std::slice::from_ref(&alice_pk), None)
            .unwrap();
        write(&root, "vault/key.pem", "PEM-PLAINTEXT\n");
        repo.commit("tester", "add protected").unwrap();

        // Private branch: edit the protected file under seal.
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "vault/key.pem", "PEM-ROTATED\n");
        repo.commit_private("alice", "rotate pem", Some(&alice_sk))
            .unwrap();
        assert_opaque(&repo, b"PEM-ROTATED");

        // Publish: the edited file is re-sealed through the P7/P33 path —
        // PROTECTED in the published tree, never public plaintext.
        let (tip, resealed) = repo.branch_publish("fix", &alice_sk).unwrap();
        assert_eq!(resealed, 1, "one protected file re-sealed at publish");
        assert_opaque(&repo, b"PEM-ROTATED");
        let snap = repo.snapshot(&tip).unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let files = crate::worktree::tree_file_entries_with_perms(&mut store, snap.root).unwrap();
        let (_, _, perms) = files["vault/key.pem"];
        assert!(perms & PROTECTED != 0, "published entry stays protected");

        drop(store);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A stopped merge-in must complete a protected path the completer cannot
    /// read (skipped on disk) from the merge's outcome, not the prior tip, on
    /// a full checkout too (#240 review): `main` rotated the file and the
    /// private side never touched it.
    #[test]
    fn merge_completion_takes_an_unreadable_protected_path_from_the_merge() {
        unreadable_protected_path_case("protmerge", false);
    }

    /// Same, with the protected prefix outside a sparse view.
    #[test]
    fn sparse_merge_completion_takes_an_unreadable_protected_path_from_the_merge() {
        unreadable_protected_path_case("protmerge-sparse", true);
    }

    fn unreadable_protected_path_case(tag: &str, sparse: bool) {
        let (root, repo, (alice_sk, _), (bob_sk, bob_pk)) = setup(tag);
        repo.protect("vault/", std::slice::from_ref(&bob_pk), None)
            .unwrap();
        write(&root, "vault/key.pem", "PEM-V1\n");
        repo.commit("tester", "add protected").unwrap();
        repo.branch_private("fix", &alice_sk, std::slice::from_ref(&bob_pk), &[])
            .unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "src/lib.rs", "private\n");
        repo.commit_private("alice", "private work", Some(&alice_sk))
            .unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "src/lib.rs", "public\n");
        write(&root, "vault/key.pem", "PEM-V2\n");
        repo.commit("tester", "main moves").unwrap();
        if sparse {
            repo.set_sparse(&["src/".to_string()], Some(&alice_sk))
                .unwrap();
        }
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        assert!(matches!(
            repo.merge_into_private("main", "alice", Some(&alice_sk)),
            Err(Error::MergeConflicts(1))
        ));
        write(&root, "src/lib.rs", "resolved\n");
        repo.commit_private("alice", "resolve", Some(&alice_sk))
            .unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("fix", Some(&bob_sk)).unwrap();
        if sparse {
            // The view still applies to bob; widen it to see the vault.
            repo.switch_with_identity("main", Some(&bob_sk)).unwrap();
            repo.set_sparse(&["src/".to_string(), "vault/".to_string()], Some(&bob_sk))
                .unwrap();
            repo.switch_with_identity("fix", Some(&bob_sk)).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(root.join("src/lib.rs")).unwrap(),
            "resolved\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("vault/key.pem")).unwrap(),
            "PEM-V2\n",
            "the public rotation was reverted by the stale carry"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists(), "test dir left behind");
    }

    /// The public side revokes the completer from a protected prefix and
    /// rotates the file: the stop cannot decrypt the new ciphertext, so the
    /// old plaintext must not survive on disk to be recommitted (#240 review).
    #[test]
    fn merge_completion_does_not_recommit_a_revoked_protected_file() {
        let (root, repo, (alice_sk, alice_pk), (bob_sk, bob_pk)) = setup("protrevoke");
        repo.protect("vault/", &[alice_pk.clone(), bob_pk.clone()], None)
            .unwrap();
        write(&root, "vault/key.pem", "PEM-V1\n");
        repo.commit("tester", "add protected").unwrap();
        repo.branch_private("fix", &alice_sk, std::slice::from_ref(&bob_pk), &[])
            .unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "src/lib.rs", "private\n");
        repo.commit_private("alice", "private work", Some(&alice_sk))
            .unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        repo.revoke("vault/", &alice_pk.recipient_id()).unwrap();
        write(&root, "vault/key.pem", "PEM-V2\n");
        write(&root, "src/lib.rs", "public\n");
        repo.commit("tester", "rotate").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        assert!(matches!(
            repo.merge_into_private("main", "alice", Some(&alice_sk)),
            Err(Error::MergeConflicts(1))
        ));
        write(&root, "src/lib.rs", "resolved\n");
        repo.commit_private("alice", "resolve", Some(&alice_sk))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("src/lib.rs")).unwrap(),
            "resolved\n"
        );
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("fix", Some(&bob_sk)).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("vault/key.pem")).unwrap(),
            "PEM-V2\n",
            "the revoked key came back from the prior tip"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// A path the public side adds in view must land even when the private
    /// side's `.scignore` ignores it: completion reads the re-derived paths
    /// regardless of ignore rules (#240 review, ADR-0049 q19).
    #[test]
    fn merge_completion_reads_a_decided_path_an_ignore_rule_hides() {
        let (root, repo, (alice_sk, _), _bob) = setup("ignoredadd");
        repo.branch_private("fix", &alice_sk, &[], &[]).unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "src/lib.rs", "private\n");
        write(&root, ".scignore", "*.log\n");
        repo.commit_private("alice", "private work", Some(&alice_sk))
            .unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "src/lib.rs", "public\n");
        write(&root, "src/build.log", "from-main\n");
        repo.commit("tester", "main moves").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        assert!(matches!(
            repo.merge_into_private("main", "alice", Some(&alice_sk)),
            Err(Error::MergeConflicts(1))
        ));
        write(&root, "src/lib.rs", "resolved\n");
        repo.commit_private("alice", "resolve", Some(&alice_sk))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("src/build.log")).unwrap(),
            "from-main\n"
        );
        let (_, mid, manifest) = repo.head_private().unwrap().unwrap();
        let ctx = repo
            .open_private("fix", mid, manifest, Some(&alice_sk))
            .unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let tip = ctx.inner_tip().unwrap();
        let snap = repo.get_inner_snapshot(&mut store, &ctx, &tip).unwrap();
        let files = repo.inner_tree_files(&mut store, &ctx, snap.root).unwrap();
        assert!(files.contains_key("src/build.log"), "public add dropped");
        drop(store);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// Scenario shared by the two stop-time protected tests: `vault/` is
    /// protected to alice and bob, the private `fix` has both as recipients,
    /// and `main` revokes alice, adds `vault/new.pem` (sealed to bob only) and
    /// edits `src/lib.rs` so the merge stops on that one conflict.
    fn revoked_addition_setup(tag: &str) -> (std::path::PathBuf, Repo, SecretKey) {
        let (root, repo, (alice_sk, alice_pk), (_bob_sk, bob_pk)) = setup(tag);
        repo.protect("vault/", &[alice_pk.clone(), bob_pk.clone()], None)
            .unwrap();
        write(&root, "vault/key.pem", "PEM-V1\n");
        repo.commit("tester", "add protected").unwrap();
        repo.branch_private("fix", &alice_sk, std::slice::from_ref(&bob_pk), &[])
            .unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        write(&root, "src/lib.rs", "private\n");
        repo.commit_private("alice", "private work", Some(&alice_sk))
            .unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        repo.revoke("vault/", &alice_pk.recipient_id()).unwrap();
        write(&root, "vault/new.pem", "PEM-NEW\n");
        write(&root, "src/lib.rs", "public\n");
        repo.commit("tester", "rotate").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        (root, repo, alice_sk)
    }

    /// An untracked file at a path whose merged protected version the
    /// recipient cannot read is the user's, not stale plaintext: the stop
    /// refuses before any write and leaves it intact.
    #[test]
    fn private_stop_refuses_an_untracked_file_at_an_unreadable_protected_path() {
        let (root, repo, alice_sk) = revoked_addition_setup("protuntracked");
        write(&root, "vault/new.pem", "MINE\n");
        let (_, before, _) = repo.head_private().unwrap().unwrap();
        let err = repo
            .merge_into_private("main", "alice", Some(&alice_sk))
            .unwrap_err();
        assert!(err.to_string().contains("vault/new.pem"), "{err}");
        assert_eq!(
            std::fs::read_to_string(root.join("vault/new.pem")).unwrap(),
            "MINE\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("src/lib.rs")).unwrap(),
            "private\n",
            "refusal wrote nothing"
        );
        assert!(!crate::merge_state::in_progress(repo.layout()));
        assert_eq!(repo.head_private().unwrap().unwrap().1, before);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// If the stale plaintext cannot be removed the stop fails before any
    /// write or state change; it must not stop and let completion commit it.
    #[cfg(unix)]
    #[test]
    fn private_stop_fails_when_stale_protected_plaintext_cannot_be_removed() {
        use std::os::unix::fs::PermissionsExt;
        let (root, repo, alice_sk) = revoked_addition_setup("protrmfail");
        // The tracked copy of vault/key.pem is stale once main rotates it.
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "vault/key.pem", "PEM-V2\n");
        repo.commit("tester", "rotate key").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        let (_, before, _) = repo.head_private().unwrap().unwrap();
        let dir = root.join("vault");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let can_write = std::fs::write(dir.join("probe"), b"x").is_ok();
        let res = repo.merge_into_private("main", "alice", Some(&alice_sk));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !can_write {
            assert!(matches!(res, Err(Error::Io(_))), "{res:?}");
            assert!(!crate::merge_state::in_progress(repo.layout()));
            assert_eq!(repo.head_private().unwrap().unwrap().1, before);
            assert_eq!(
                std::fs::read_to_string(root.join("src/lib.rs")).unwrap(),
                "private\n",
                "nothing else was written"
            );
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// A symlink at an unreadable protected path is the user's file even when
    /// its target reads as the old plaintext: the stop refuses, leaves it.
    #[cfg(unix)]
    #[test]
    fn private_stop_refuses_a_symlink_at_an_unreadable_protected_path() {
        let (root, repo, alice_sk) = revoked_addition_setup("protsymlink");
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        write(&root, "vault/key.pem", "PEM-V2\n");
        repo.commit("tester", "rotate key").unwrap();
        repo.switch_with_identity("fix", Some(&alice_sk)).unwrap();
        // Tracked vault/key.pem replaced by a link whose target reads "PEM-V1".
        write(&root, "elsewhere.txt", "PEM-V1\n");
        std::fs::remove_file(root.join("vault/key.pem")).unwrap();
        std::os::unix::fs::symlink("../elsewhere.txt", root.join("vault/key.pem")).unwrap();
        let err = repo
            .merge_into_private("main", "alice", Some(&alice_sk))
            .unwrap_err();
        assert!(err.to_string().contains("vault/key.pem"), "{err}");
        assert!(std::fs::symlink_metadata(root.join("vault/key.pem"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!crate::merge_state::in_progress(repo.layout()));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }
}
