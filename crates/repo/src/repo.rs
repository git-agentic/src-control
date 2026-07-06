//! The persistent repository: ties a persistent `Store` to the `.sc/` layout.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{Object, ObjectId, Protection, Snapshot, Store, WrappedKey};
use scl_vfs::Repo as VfsRepo;

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lock::RepoLock;
use crate::refs;
use crate::worktree::{self, Diff};

const DEFAULT_BRANCH: &str = "main";
pub(crate) const DEFAULT_BUDGET: usize = 512 * 1024 * 1024;

/// A working-tree file headed for encryption at commit time:
/// `(path, plaintext bytes, file mode, recipient pubkeys)`.
type ProtectedFile = (String, Vec<u8>, scl_core::FileMode, Vec<[u8; 32]>);

/// Working-tree status against HEAD.
pub type Status = Diff;

/// A handle to an open persistent repo. Holds the single-writer lock for its
/// lifetime.
pub struct Repo {
    pub(crate) layout: Layout,
    pub(crate) vfs: VfsRepo,
    _lock: RepoLock,
}

impl Repo {
    /// Create a new repo at `root` (errors if `.sc/` already exists).
    pub fn init(root: impl AsRef<Path>) -> Result<Repo> {
        let layout = Layout::at(root.as_ref());
        // The exists-check then create_dir_all is a benign TOCTOU: under the
        // single-writer assumption (one `sc` process per repo at a time) no
        // concurrent creator can race between the two; a second `init` either
        // sees `.sc` and errors here or loses the lock in `open_layout`.
        if layout.dot_sc.exists() {
            return Err(Error::RepoExists(layout.dot_sc.display().to_string()));
        }
        std::fs::create_dir_all(layout.objects_dir())?;
        std::fs::create_dir_all(layout.refs_heads_dir())?;
        refs::write_head(&layout, DEFAULT_BRANCH)?;
        Self::open_layout(layout, DEFAULT_BUDGET)
    }

    /// Open an existing repo by discovering `.sc/` at or above `start`.
    pub fn open(start: impl AsRef<Path>) -> Result<Repo> {
        let layout = Layout::discover(start)?;
        Self::open_layout(layout, DEFAULT_BUDGET)
    }

    /// Open an existing repo with an explicit memory budget for the shared
    /// object cache (bytes). `open` uses `DEFAULT_BUDGET`; workspace sessions
    /// (`sc work --budget-mb`) size the cache to the fleet they fork.
    pub fn open_with_budget(start: impl AsRef<Path>, budget_bytes: usize) -> Result<Repo> {
        let layout = Layout::discover(start)?;
        Self::open_layout(layout, budget_bytes)
    }

    fn open_layout(layout: Layout, budget_bytes: usize) -> Result<Repo> {
        let lock = RepoLock::acquire(&layout)?;
        let store = Store::open_persistent(layout.objects_dir(), budget_bytes)?;
        Ok(Repo { layout, vfs: VfsRepo::new(store), _lock: lock })
    }

    /// The resolved on-disk paths for this repo (root, `.sc/`, refs, etc.).
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The tip snapshot of the current branch (None if unborn).
    pub fn head_tip(&self) -> Result<Option<ObjectId>> {
        refs::head_tip(&self.layout)
    }

    /// The root tree of the current tip (None if unborn).
    fn head_root(&self) -> Result<Option<ObjectId>> {
        match self.head_tip()? {
            Some(tip) => {
                let store_arc = self.vfs.store();
                let root = store_arc.lock().unwrap().get_snapshot(&tip)?.root;
                Ok(Some(root))
            }
            None => Ok(None),
        }
    }

    /// Scan a set of working-tree files for plaintext secrets, skipping any blob
    /// whose content hash is in `.sc/scanner-allowlist.toml`.
    pub fn scan_files(
        &self,
        files: &[(String, Vec<u8>, scl_core::FileMode)],
    ) -> Result<crate::scanner::ScanReport> {
        let allow =
            crate::scanner::Allowlist::load(&self.layout.dot_sc.join("scanner-allowlist.toml"))?;
        let mut findings = Vec::new();
        for (path, bytes, _mode) in files {
            let id = Object::blob(bytes.clone()).id();
            if allow.is_allowed(&id) {
                continue;
            }
            for hit in crate::scanner::scan(path, bytes) {
                findings.push(crate::scanner::Finding {
                    path: path.clone(),
                    rule: crate::scanner::rule_label(&hit.rule),
                    blob_id: id,
                    line: hit.line,
                });
            }
        }
        Ok(crate::scanner::ScanReport { findings })
    }

    /// Scan the current working tree for plaintext secrets (read-only).
    pub fn scan_worktree(&self) -> Result<crate::scanner::ScanReport> {
        let files = worktree::read_worktree(&self.layout, &self.tracked_paths()?)?;
        self.scan_files(&files)
    }

    /// Paths tracked by HEAD (empty when the branch is unborn). `.scignore`
    /// rules never hide these — same model as git.
    fn tracked_paths(&self) -> Result<std::collections::BTreeSet<String>> {
        match self.head_tip()? {
            None => Ok(Default::default()),
            Some(tip) => {
                let root = self.snapshot(&tip)?.root;
                let store_arc = self.vfs.store();
                let mut store = store_arc.lock().unwrap();
                Ok(worktree::tree_file_ids(&mut store, root)?.into_keys().collect())
            }
        }
    }

    /// The commit pipeline minus ref movement: split protected/plaintext files,
    /// scan the plaintext (Err(SecretDetected) on a hit), convergently encrypt
    /// protected files, carry forward absent still-protected content from
    /// `tip`, and persist the resulting snapshot with `tip` (+ `merge_head`)
    /// as parents. Used by `commit` (HEAD tip) and by workspace harvest (P13,
    /// arbitrary base tip, no merge head). Advances no refs.
    pub(crate) fn snapshot_files(
        &self,
        files: Vec<(String, Vec<u8>, scl_core::FileMode)>,
        tip: Option<ObjectId>,
        merge_head: Option<ObjectId>,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        // Read the tip snapshot exactly once; extract both protection and secrets.
        let (mut protection, secrets) = match (tip, merge_head) {
            (None, _) => (Protection::default(), BTreeMap::new()),
            (Some(t), None) => {
                let snap = self.snapshot(&t)?;
                (snap.protection, snap.secrets)
            }
            (Some(t), Some(_)) => {
                let prot = self.snapshot(&t)?.protection;
                let secs = self.merged_secrets_for_commit(tip, merge_head)?;
                (prot, secs)
            }
        };

        // Single pass: split protected files (capturing each rule's recipients, so
        // the encryption loop needn't look the prefix up again) from plaintext.
        let mut plain: Vec<(String, Vec<u8>, scl_core::FileMode)> = Vec::new();
        let mut protected: Vec<ProtectedFile> = Vec::new();
        for (path, bytes, mode) in files {
            match crate::protect::matching_prefix(&protection, &path) {
                Some(rule) => protected.push((path, bytes, mode, rule.recipients.clone())),
                None => plain.push((path, bytes, mode)),
            }
        }

        // Scan only plaintext files (protected files are encrypted on purpose).
        let report = self.scan_files(&plain)?;
        if !report.is_empty() {
            return Err(Error::SecretDetected(report));
        }

        // Encrypt protected files; accumulate fresh wrapped DEKs keyed by blob id.
        let mut all: Vec<(String, Vec<u8>, scl_core::FileMode, u8)> =
            plain.into_iter().map(|(p, b, m)| (p, b, m, 0u8)).collect();
        let mut fresh_wrapped: BTreeMap<ObjectId, Vec<WrappedKey>> = BTreeMap::new();
        for (path, bytes, mode, recipients) in protected {
            let (blob_bytes, dek) = scl_crypto::encrypt_path(&bytes);
            // Build the blob object once for its id; `write_tree_with_perms` does
            // the (idempotent) store insert below — no second explicit `put`.
            let blob_id = Object::blob(blob_bytes.clone()).id();
            let wks: Vec<WrappedKey> = recipients
                .iter()
                .map(|pk| scl_crypto::wrap_dek_for(&dek, &scl_crypto::PublicKey::from_bytes(*pk)))
                .collect();
            fresh_wrapped.insert(blob_id, wks);
            all.push((path, blob_bytes, mode, scl_core::PROTECTED));
        }

        // Safe-by-default: carry forward still-protected files that are absent
        // from the working tree. `commit` cannot distinguish "absent because the
        // committer isn't a recipient (skipped at checkout)" from "the committer
        // deleted it" — an absent protected path reads as clean either way (see
        // Task 5 `status`). We therefore never silently drop protected content
        // on a non-merge commit: a still-protected path that is missing from
        // disk is carried forward verbatim from the tip (its exact ciphertext
        // blob and wrapped DEKs). This closes the hole where a non-recipient's
        // unrelated commit would otherwise destroy ciphertext they cannot even
        // read. (Explicit deletion of a protected file is a future operation,
        // out of scope.) Scope: this scans only `tip` (ours), so it covers
        // non-merge commits. Merge commits do not yet carry forward theirs-side
        // protected content; merge-of-protected is a separate follow-on.
        if let Some(tip_id) = tip {
            let on_disk: std::collections::BTreeSet<String> =
                all.iter().map(|(p, _, _, _)| p.clone()).collect();
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let tip_root = store.get_snapshot(&tip_id)?.root;
            let entries = worktree::tree_file_entries_with_perms(&mut store, tip_root)?;
            for (path, (blob_id, mode, perms)) in entries {
                if perms & scl_core::PROTECTED == 0
                    || crate::protect::matching_prefix(&protection, &path).is_none()
                    || on_disk.contains(&path)
                {
                    continue;
                }
                let bytes = match store.get(&blob_id)? {
                    Object::Blob(b) => b.to_vec(),
                    _ => continue,
                };
                all.push((path, bytes, mode, scl_core::PROTECTED));
                // Preserve this blob's wraps. Carried-forward blobs are absent
                // from `fresh_wrapped` (they never hit the on-disk encrypt loop),
                // so the prior-wrap reuse below won't cover them — add them here.
                // `or_insert_with` so an on-disk file already sharing this blob id
                // keeps its freshly-wrapped DEKs.
                if let Some(prior_wks) = protection.wrapped.get(&blob_id) {
                    fresh_wrapped.entry(blob_id).or_insert_with(|| prior_wks.clone());
                }
            }
        }

        let root = self.vfs.write_tree_with_perms(&all)?;

        // Rebuild policy.wrapped from only this commit's protected blobs, dropping
        // any stale entries. Crucially, reuse the prior wrap bytes for an unchanged
        // (blob_id, recipient_id): convergent encryption keeps blob ids stable, but
        // `wrap_dek_for` randomizes its ephemeral key — re-wrapping every commit
        // would change the `protection` encoding (and thus the snapshot id) for
        // identical content, breaking "same content -> stable history". Carrying the
        // prior wrap forward keeps it stable; only a newly-added recipient (or a new
        // blob) gets a fresh wrap, and a revoked recipient is already absent here.
        let prior = std::mem::take(&mut protection.wrapped);
        for (blob_id, wks) in fresh_wrapped.iter_mut() {
            if let Some(prior_wks) = prior.get(blob_id) {
                for wk in wks.iter_mut() {
                    if let Some(existing) =
                        prior_wks.iter().find(|p| p.recipient_id == wk.recipient_id)
                    {
                        *wk = existing.clone();
                    }
                }
            }
        }
        protection.wrapped = fresh_wrapped;

        let mut parents: Vec<ObjectId> = tip.into_iter().collect();
        if let Some(theirs) = merge_head {
            parents.push(theirs);
        }
        self.build_snapshot(root, parents, secrets, protection, author, message)
    }

    /// Snapshot the working tree into a new commit on the current branch. When a
    /// merge is in progress, records both parents and clears the merge state.
    /// Files under a protected prefix are convergently encrypted (scanner-exempt);
    /// only plaintext files are scanned.
    pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
        let files = worktree::read_worktree(&self.layout, &self.tracked_paths()?)?;
        let tip = self.head_tip()?;
        let merge_head = crate::merge_state::read_merge_head(&self.layout)?;
        let id = self.snapshot_files(files, tip, merge_head, author, message)?;
        let branch = refs::current_branch(&self.layout)?;
        refs::write_branch_tip(&self.layout, &branch, &id)?;
        crate::merge_state::clear(&self.layout)?;
        Ok(id)
    }

    /// Decode the snapshot at `id` from the store. Small utility reused across
    /// commit, grant/revoke (Task 6), and tests.
    pub(crate) fn snapshot(&self, id: &ObjectId) -> Result<Snapshot> {
        let store_arc = self.vfs.store();
        let snap = store_arc.lock().unwrap().get_snapshot(id)?;
        Ok(snap)
    }

    /// Secrets to record on a commit: during a merge, the conflict-free merged
    /// registry of the two parents; otherwise the tip's registry.
    fn merged_secrets_for_commit(
        &self,
        tip: Option<ObjectId>,
        merge_head: Option<ObjectId>,
    ) -> Result<BTreeMap<String, ObjectId>> {
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        match (tip, merge_head) {
            (Some(ours), Some(theirs)) => {
                let base = crate::merge::merge_base(&mut store, ours, theirs)?
                    .ok_or(Error::NoCommonAncestor)?;
                let bs = store.get_snapshot(&base)?.secrets;
                let os = store.get_snapshot(&ours)?.secrets;
                let ts = store.get_snapshot(&theirs)?.secrets;
                crate::merge::merge_secrets(&bs, &os, &ts)
            }
            (Some(ours), None) => Ok(store.get_snapshot(&ours)?.secrets),
            (None, _) => Ok(BTreeMap::new()),
        }
    }

    /// Persist a snapshot object (no ref movement). The workspace harvest
    /// (P13) commits to non-HEAD branches, so snapshot construction must not
    /// be welded to "advance the current branch".
    pub(crate) fn build_snapshot(
        &self,
        root: ObjectId,
        parents: Vec<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        protection: Protection,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let snap = Object::Snapshot(Snapshot {
            root,
            parents,
            author: author.to_string(),
            timestamp: unix_now(),
            message: message.to_string(),
            secrets,
            protection,
        });
        let store_arc = self.vfs.store();
        let id = store_arc.lock().unwrap().put(snap)?;
        Ok(id)
    }

    /// Build + persist a snapshot and advance the current branch ref.
    pub(crate) fn commit_snapshot(
        &self,
        root: ObjectId,
        parents: Vec<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        protection: Protection,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let id = self.build_snapshot(root, parents, secrets, protection, author, message)?;
        let branch = refs::current_branch(&self.layout)?;
        refs::write_branch_tip(&self.layout, &branch, &id)?;
        Ok(id)
    }

    /// Working-tree status against HEAD, plus merge-in-progress info.
    pub fn status(&self) -> Result<Status> {
        let (head_root, protection) = match self.head_tip()? {
            Some(tip) => {
                let snap = self.snapshot(&tip)?;
                (Some(snap.root), snap.protection)
            }
            None => (None, Protection::default()),
        };
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        worktree::diff_worktree(&self.layout, &mut store, head_root, &protection)
    }

    /// Line-level unified diff of the working tree against HEAD (`sc diff`).
    ///
    /// Text files get standard `---`/`+++`/`@@` hunks; a file with a NUL byte
    /// on either side is reported as binary. `PROTECTED` HEAD entries follow
    /// the same rules as [`Repo::status`]: absent-on-disk is clean (skipped
    /// checkout, not a deletion), an on-disk edit is detected by convergent
    /// re-encryption — but the content is never shown (it would be ciphertext
    /// vs plaintext noise at best, a leak at worst).
    pub fn diff_unified(&self) -> Result<String> {
        use scl_core::PROTECTED;
        let head_root = self.head_tip()?.map(|t| self.snapshot(&t)).transpose()?.map(|s| s.root);
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let head = match head_root {
            Some(root) => worktree::tree_file_entries_with_perms(&mut store, root)?,
            None => BTreeMap::new(),
        };
        let tracked: std::collections::BTreeSet<String> = head.keys().cloned().collect();
        let wt: BTreeMap<String, Vec<u8>> = worktree::read_worktree(&self.layout, &tracked)?
            .into_iter()
            .map(|(p, b, _)| (p, b))
            .collect();

        let mut paths: std::collections::BTreeSet<&String> = wt.keys().collect();
        paths.extend(head.keys());

        let mut out = String::new();
        for path in paths {
            let disk = wt.get(path);
            match head.get(path) {
                None => {
                    // Added file.
                    let bytes = disk.expect("path came from one of the two maps");
                    push_file_diff(&mut out, path, &[], bytes);
                }
                Some((blob_id, _mode, perms)) if *perms & PROTECTED != 0 => {
                    // Never show protected content; report the change status only.
                    if let Some(bytes) = disk {
                        let disk_id = Object::blob(scl_crypto::encrypt_path(bytes).0).id();
                        if disk_id != *blob_id {
                            out.push_str(&format!(
                                "protected file changed: {path} (content not shown)\n"
                            ));
                        }
                    }
                }
                Some((blob_id, _mode, _perms)) => {
                    let old = match store.get(blob_id)? {
                        Object::Blob(b) => b,
                        _ => continue,
                    };
                    match disk {
                        None => push_file_diff(&mut out, path, &old, &[]),
                        Some(bytes) => {
                            if Object::blob(bytes.clone()).id() != *blob_id {
                                push_file_diff(&mut out, path, &old, bytes);
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Conflicted paths if a merge is in progress (empty otherwise).
    pub fn merge_conflicts(&self) -> Result<Vec<String>> {
        crate::merge_state::read_conflicts(&self.layout)
    }

    /// Whether a merge is currently in progress.
    pub fn merge_in_progress(&self) -> bool {
        crate::merge_state::in_progress(&self.layout)
    }

    /// Merge `branch` into the current branch. Fast-forwards when possible;
    /// auto-commits a two-parent snapshot on a clean merge; on conflicts writes
    /// markers + merge state and returns `MergeConflicts`. If the current
    /// branch is unborn (no commits yet), adopts `theirs` wholesale — the same
    /// fast-forward-from-empty behavior Git uses when merging into an unborn
    /// branch — so `sc init` followed directly by `sc fetch` + `sc merge`
    /// (e.g. from a freshly imported git remote) works without an intervening
    /// local commit.
    pub fn merge(&self, branch: &str, author: &str) -> Result<ObjectId> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before merging".into(),
            ));
        }
        let theirs = refs::resolve_tip(&self.layout, branch)?
            .ok_or_else(|| Error::NoSuchBranch(branch.to_string()))?;
        let ours = match self.head_tip()? {
            Some(ours) => ours,
            None => {
                // Unborn local branch: adopt theirs wholesale (fast-forward from empty).
                let store_arc = self.vfs.store();
                let mut store = store_arc.lock().unwrap();
                let theirs_snap = store.get_snapshot(&theirs)?;
                let theirs_root = theirs_snap.root;
                let theirs_protection = theirs_snap.protection;
                worktree::materialize(
                    &self.layout,
                    &mut store,
                    theirs_root,
                    None,
                    &theirs_protection,
                    None,
                )?;
                drop(store);
                let branch_name = refs::current_branch(&self.layout)?;
                refs::write_branch_tip(&self.layout, &branch_name, &theirs)?;
                return Ok(theirs);
            }
        };

        // Ancestor short-circuits.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            if crate::merge::is_ancestor(&mut store, theirs, ours)? {
                return Err(Error::UpToDate);
            }
            if crate::merge::is_ancestor(&mut store, ours, theirs)? {
                // fast-forward: advance ref + materialize, no merge commit
                let theirs_snap = store.get_snapshot(&theirs)?;
                let theirs_root = theirs_snap.root;
                let theirs_protection = theirs_snap.protection;
                let ours_root = store.get_snapshot(&ours)?.root;
                worktree::materialize(
                    &self.layout,
                    &mut store,
                    theirs_root,
                    Some(ours_root),
                    &theirs_protection,
                    None,
                )?;
                drop(store);
                let branch_name = refs::current_branch(&self.layout)?;
                refs::write_branch_tip(&self.layout, &branch_name, &theirs)?;
                return Ok(theirs);
            }
        }

        // Real three-way merge.
        let (merge_result, ours_root) = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let base = crate::merge::merge_base(&mut store, ours, theirs)?
                .ok_or(Error::NoCommonAncestor)?;

            // Fail closed on protected content. `three_way` flattens trees without
            // the `perms` byte and would push raw ciphertext into the working tree
            // as an ordinary unprotected blob, destroying the encrypted files (even
            // the legitimate recipient could no longer decrypt the merge commit).
            // Properly threading perms + wrapped DEKs through the merge is a
            // deliberate backlog follow-on; until then we refuse rather than corrupt.
            // This is a pure read + early return: nothing is written to the working
            // tree or refs before the guard fires.
            for snap_id in [base, ours, theirs] {
                let root = store.get_snapshot(&snap_id)?.root;
                let entries = worktree::tree_file_entries_with_perms(&mut store, root)?;
                if entries.values().any(|(_, _, perms)| perms & scl_core::PROTECTED != 0) {
                    return Err(Error::MergeProtected(branch.to_string()));
                }
            }

            let m = crate::merge::three_way(&mut store, base, ours, theirs)?;
            let ours_root = store.get_snapshot(&ours)?.root;
            (m, ours_root)
        };

        // Build the merged tree from the resolved file set.
        let write_set: Vec<(String, Vec<u8>, scl_core::FileMode)> =
            merge_result.files.iter().map(|(p, m, b)| (p.clone(), b.clone(), *m)).collect();
        let merged_root = self.vfs.write_tree(&write_set)?;

        // Materialize merged tree into the working dir, then write sidecars.
        // Protected merges are refused by the guard above, so this path only ever
        // sees unprotected blobs: the merged tree legitimately has no PROTECTED
        // entries, so no identity is needed and no files will be skipped.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(
                &self.layout,
                &mut store,
                merged_root,
                Some(ours_root),
                &scl_core::Protection::default(),
                None,
            )?;
        }
        for (rel, bytes) in &merge_result.sidecars {
            let full = self.layout.root.join(rel);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(full, bytes)?;
        }

        if merge_result.conflicts.is_empty() {
            // Clean merge: two-parent snapshot now. Carry ours' protection forward.
            let ours_protection = {
                let store_arc = self.vfs.store();
                let p = store_arc.lock().unwrap().get_snapshot(&ours)?.protection;
                p
            };
            let id = self.commit_snapshot(
                merged_root,
                vec![ours, theirs],
                merge_result.secrets,
                ours_protection,
                author,
                &format!("merge {branch}"),
            )?;
            Ok(id)
        } else {
            // Conflict markers are already on disk; record MERGE_HEAD last. A
            // crash in this window leaves marked files but no merge state — under
            // the single-writer lock this is recoverable: re-running `merge`
            // simply redoes the (idempotent) materialize + write.
            crate::merge_state::write(&self.layout, &theirs, &merge_result.conflicts)?;
            Err(Error::MergeConflicts(merge_result.conflicts.len()))
        }
    }

    /// Abandon an in-progress merge: restore the working tree to the current tip
    /// and clear merge state. Errors if no merge is in progress.
    ///
    /// Returns the protected paths that could not be restored. No identity is
    /// available at abort time, so protected files are skipped (left absent)
    /// rather than decrypted — that's expected; re-supply an identity via a
    /// `switch_with_identity` back to the branch to materialize them.
    pub fn merge_abort(&self) -> Result<Vec<String>> {
        if !crate::merge_state::in_progress(&self.layout) {
            return Err(Error::InvalidArgument("no merge in progress".into()));
        }
        let theirs_id = crate::merge_state::read_merge_head(&self.layout)?
            .expect("in_progress is true but MERGE_HEAD is absent");
        // Remove any .theirs sidecars recorded as conflicts.
        for path in crate::merge_state::read_conflicts(&self.layout)? {
            let _ = std::fs::remove_file(self.layout.root.join(format!("{path}.theirs")));
        }
        // Restore working tree to ours tip. Pass theirs' root as `old_root` so
        // the deletion pass drops files the conflicted merge pulled in from
        // theirs; materializing against ours==old would delete nothing.
        let mut skipped = Vec::new();
        let ours_tip = self.head_tip()?;
        if let Some(ours_id) = ours_tip {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let ours_snap = store.get_snapshot(&ours_id)?;
            let ours_root = ours_snap.root;
            let ours_protection = ours_snap.protection;
            let theirs_root = store.get_snapshot(&theirs_id)?.root;
            // No identity at abort time: protected files in ours are skipped (not decrypted).
            skipped = worktree::materialize(
                &self.layout,
                &mut store,
                ours_root,
                Some(theirs_root),
                &ours_protection,
                None,
            )?;
        }
        crate::merge_state::clear(&self.layout)?;
        Ok(skipped)
    }

    /// Snapshots from the current tip back through parents (newest first).
    pub fn log(&self) -> Result<Vec<(ObjectId, Snapshot)>> {
        let mut out = Vec::new();
        let mut next = self.head_tip()?;
        while let Some(id) = next {
            let store_arc = self.vfs.store();
            let snap = store_arc.lock().unwrap().get_snapshot(&id)?;
            next = snap.parents.first().copied();
            out.push((id, snap));
        }
        Ok(out)
    }

    /// List branch names (sorted) and whether each is the current HEAD branch.
    pub fn branches(&self) -> Result<Vec<(String, bool)>> {
        let current = refs::current_branch(&self.layout)?;
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.layout.refs_heads_dir()) {
            for e in entries {
                let e = e?;
                if e.file_type()?.is_file() {
                    names.push(e.file_name().to_string_lossy().into_owned());
                }
            }
        }
        names.sort();
        Ok(names.into_iter().map(|n| (n.clone(), n == current)).collect())
    }

    /// Create `name` pointing at the current tip (errors if unborn or exists).
    pub fn branch(&self, name: &str) -> Result<()> {
        validate_branch_name(name)?;
        if self.layout.ref_path(name).exists() {
            return Err(Error::BadRef(format!("branch already exists: {name}")));
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        refs::write_branch_tip(&self.layout, name, &tip)
    }

    /// Switch HEAD to `name` and materialize its tip into the working tree.
    ///
    /// Refuses to switch when the working tree has uncommitted modifications or
    /// deletions, because `materialize` would silently overwrite them. (New,
    /// untracked files are left in place and so don't block the switch.) The
    /// dirty check is protection-aware (see `status`/`diff_worktree`): a
    /// decrypted protected file that matches HEAD is clean and a skipped/absent
    /// protected file is clean, but a genuine edit to a protected file blocks
    /// the switch like any other uncommitted change.
    ///
    /// Returns the list of protected paths skipped (not decrypted) because no
    /// identity was provided. Use `switch_with_identity` to supply one.
    pub fn switch(&self, name: &str) -> Result<Vec<String>> {
        self.switch_with_identity(name, None)
    }

    /// Like [`switch`][Repo::switch] but decrypts `PROTECTED` files using
    /// `identity` when possible. Returns the list of protected paths that were
    /// skipped because the identity could not unwrap their DEK.
    pub fn switch_with_identity(
        &self,
        name: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<Vec<String>> {
        validate_branch_name(name)?;
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        // The protection-aware dirty check (status) already treats unchanged
        // decrypted protected files and skipped/absent protected files as clean,
        // so a reported modification/deletion is a genuine uncommitted change.
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before switching".into(),
            ));
        }
        let target_tip = refs::read_branch_tip(&self.layout, name)?
            .ok_or_else(|| Error::NoSuchBranch(name.to_string()))?;
        let old_root = self.head_root()?;
        let (target_root, target_protection) = {
            let store_arc = self.vfs.store();
            let snap = store_arc.lock().unwrap().get_snapshot(&target_tip)?;
            (snap.root, snap.protection)
        };
        let skipped = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(
                &self.layout,
                &mut store,
                target_root,
                old_root,
                &target_protection,
                identity,
            )?
        };
        refs::write_head(&self.layout, name)?;
        Ok(skipped)
    }


    /// Expose the underlying VFS repo handle (needed by secrets.rs methods).
    pub(crate) fn vfs_handle(&self) -> &VfsRepo {
        &self.vfs
    }

    /// The underlying VFS handle (objects live behind its `Store`). Test/gc use.
    pub fn vfs(&self) -> &VfsRepo {
        &self.vfs
    }

    /// Garbage-collect this repo: pack the reachable set and prune unreachable
    /// loose objects older than `grace`. Persistent repos only. The open `Repo`
    /// already holds the single-writer lock, so the whole pass is serialized
    /// against other writers.
    pub fn gc(&self, grace: std::time::Duration) -> Result<crate::gc::GcStats> {
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        crate::gc::run(&self.layout, &mut store, grace)
    }

}

/// Current unix time in seconds, for snapshot timestamps. Snapshot ids
/// legitimately depend on commit time (as in Git); nothing in the system
/// requires two separate commits of identical content to share an id.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Append one file's diff to `out`: unified hunks for text, a one-line notice
/// for binary content (NUL byte on either side).
fn push_file_diff(out: &mut String, path: &str, old: &[u8], new: &[u8]) {
    if old.contains(&0) || new.contains(&0) {
        out.push_str(&format!("Binary files a/{path} and b/{path} differ\n"));
        return;
    }
    let old_s = String::from_utf8_lossy(old);
    let new_s = String::from_utf8_lossy(new);
    out.push_str(&crate::textdiff::unified(path, &old_s, &new_s));
}


/// Reject branch names that would escape or corrupt `refs/heads/`. A branch name
/// becomes a single path component under `refs/heads/`, so names containing path
/// separators, the special `.`/`..` components, or a leading dot are refused.
pub(crate) fn validate_branch_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
    {
        return Err(Error::BadRef(format!("invalid branch name: {name:?}")));
    }
    Ok(())
}

/// Test seam: commit a snapshot that adds or replaces a protected prefix rule in
/// the current tip's protection policy. Used by tests that need a prefix rule
/// in place before calling `commit`; Task 6 provides the real `protect` API.
#[cfg(test)]
impl Repo {
    pub(crate) fn test_set_protected_prefix(
        &self,
        prefix: &str,
        recipients: &[scl_crypto::PublicKey],
    ) -> Result<ObjectId> {
        use scl_core::{ProtectPrefix, Protection};
        let (root, parents, secrets, mut protection) = match self.head_tip()? {
            Some(t) => {
                let snap = self.snapshot(&t)?;
                (snap.root, vec![t], snap.secrets, snap.protection)
            }
            None => {
                let root = self.vfs.write_tree(&[])?;
                (root, vec![], BTreeMap::new(), Protection::default())
            }
        };
        protection.prefixes.retain(|p| p.prefix != prefix);
        protection.prefixes.push(ProtectPrefix {
            prefix: prefix.to_string(),
            recipients: recipients.iter().map(|pk| pk.to_bytes()).collect(),
        });
        self.commit_snapshot(root, parents, secrets, protection, "system", "set protected prefix")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-cmd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn scignore_hides_untracked_from_status_and_commit_but_not_tracked() {
        let root = tmp_root("scignore");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join(".scignore"), "junk\n").unwrap();
        std::fs::create_dir_all(root.join("junk")).unwrap();
        std::fs::write(root.join("junk/big.bin"), b"x").unwrap();
        std::fs::write(root.join("real.txt"), b"content").unwrap();

        // status: the ignored path is invisible; the real file and .scignore show.
        let st = repo.status().unwrap();
        assert_eq!(st.added, vec![".scignore".to_string(), "real.txt".to_string()]);

        // commit: the snapshot tree must not contain the ignored path.
        let id = repo.commit("t", "c1").unwrap();
        let store_arc = repo.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let snap_root = store.get_snapshot(&id).unwrap().root;
        let entries = worktree::tree_file_ids(&mut store, snap_root).unwrap();
        drop(store);
        assert!(entries.contains_key("real.txt"));
        assert!(!entries.keys().any(|p| p.starts_with("junk/")), "ignored path committed");

        // A tracked file stays tracked even when a later rule matches it.
        std::fs::write(root.join(".scignore"), "junk\nreal.txt\n").unwrap();
        std::fs::write(root.join("real.txt"), b"changed").unwrap();
        let st = repo.status().unwrap();
        assert!(
            st.modified.contains(&"real.txt".to_string()),
            "tracked file must not be ignored: {:?}",
            st
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rejects_unsafe_branch_names() {
        // Direct checks on the validator.
        for bad in ["", ".", "..", "a/b", "a\\b", ".hidden"] {
            assert!(
                matches!(validate_branch_name(bad), Err(Error::BadRef(_))),
                "expected {bad:?} to be rejected"
            );
        }
        assert!(validate_branch_name("feature").is_ok());

        // And via the public API, so a traversal name can't reach the ref path.
        let root = tmp_root("badbranch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();
        assert!(matches!(repo.branch(".."), Err(Error::BadRef(_))));
        assert!(matches!(repo.switch("a/b"), Err(Error::BadRef(_))));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn init_commit_reopen_log() {
        let root = tmp_root("commit");
        {
            let repo = Repo::init(&root).unwrap();
            std::fs::write(root.join("README.md"), b"hello").unwrap();
            repo.commit("me", "first").unwrap();
        } // drop releases lock + Store
        let repo2 = Repo::open(&root).unwrap();
        let log = repo2.log().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1.message, "first");
        drop(repo2);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn status_reports_add_modify_delete() {
        let root = tmp_root("status");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("keep.txt"), b"v1").unwrap();
        std::fs::write(root.join("gone.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();
        // modify keep, delete gone, add new
        std::fs::write(root.join("keep.txt"), b"v2").unwrap();
        std::fs::remove_file(root.join("gone.txt")).unwrap();
        std::fs::write(root.join("new.txt"), b"n").unwrap();
        let s = repo.status().unwrap();
        assert_eq!(s.added, vec!["new.txt"]);
        assert_eq!(s.modified, vec!["keep.txt"]);
        assert_eq!(s.deleted, vec!["gone.txt"]);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn branch_switch_materializes_and_repoints_head() {
        let root = tmp_root("branch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"on-main").unwrap();
        repo.commit("me", "main work").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        // commit a feature-only file
        std::fs::write(root.join("feature.txt"), b"f").unwrap();
        repo.commit("me", "feature work").unwrap();
        assert!(root.join("feature.txt").exists());
        // switch back to main: feature.txt must disappear, a.txt remain
        repo.switch("main").unwrap();
        assert!(!root.join("feature.txt").exists());
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"on-main");
        let branches = repo.branches().unwrap();
        assert!(branches.contains(&("main".to_string(), true)));
        assert!(branches.contains(&("feature".to_string(), false)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switch_refuses_to_clobber_uncommitted_changes() {
        let root = tmp_root("switch-dirty");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        // Uncommitted edit to a tracked file.
        std::fs::write(root.join("a.txt"), b"local-edit").unwrap();
        let err = repo.switch("feature").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        // The uncommitted edit must be preserved (switch did not materialize).
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"local-edit");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fast_forward_advances_without_merge_commit() {
        let root = tmp_root("ff");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("b.txt"), b"new").unwrap();
        let feat = repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();
        let merged = repo.merge("feature", "me").unwrap();
        assert_eq!(merged, feat, "fast-forward points main at feature tip");
        assert!(root.join("b.txt").exists());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clean_merge_creates_two_parent_snapshot() {
        let root = tmp_root("clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        // ours: change line 2 on main
        std::fs::write(root.join("shared.txt"), b"a\nB\nc\n").unwrap();
        let ours = repo.commit("me", "ours").unwrap();
        // theirs: change line 3 on feature
        repo.switch("feature").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nC\n").unwrap();
        let theirs = repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        let merge = repo.merge("feature", "me").unwrap();
        assert_eq!(std::fs::read(root.join("shared.txt")).unwrap(), b"a\nB\nC\n");
        let store_arc = repo.vfs_handle().store();
        let snap = store_arc.lock().unwrap().get_snapshot(&merge).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs]);
        let _ = base;
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn conflict_marks_tree_and_finalizes_on_commit() {
        let root = tmp_root("conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        let ours = repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        let theirs = repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert!(repo.merge_in_progress());
        let marked = std::fs::read_to_string(root.join("f.txt")).unwrap();
        assert!(marked.contains("<<<<<<< ours") && marked.contains(">>>>>>> theirs"));

        // resolve and commit -> two-parent merge snapshot, state cleared
        std::fs::write(root.join("f.txt"), b"a\nZ\nc\n").unwrap();
        let merge = repo.commit("me", "resolve").unwrap();
        assert!(!repo.merge_in_progress());
        let store_arc = repo.vfs_handle().store();
        let snap = store_arc.lock().unwrap().get_snapshot(&merge).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs]);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_abort_restores_and_clears() {
        let root = tmp_root("abort");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        let _ = repo.merge("feature", "me").unwrap_err();
        repo.merge_abort().unwrap();
        assert!(!repo.merge_in_progress());
        // working tree restored to ours' content (no markers)
        assert_eq!(std::fs::read(root.join("f.txt")).unwrap(), b"a\nX\nc\n");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_refuses_dirty_tree() {
        let root = tmp_root("dirty-merge");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"feat").unwrap();
        repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();
        std::fs::write(root.join("a.txt"), b"dirty-local").unwrap();
        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_abort_drops_theirs_only_files() {
        let root = tmp_root("abort-theirs-only");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        // ours: modify f.txt on main
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours").unwrap();
        // theirs: modify f.txt AND add new.txt on feature
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        std::fs::write(root.join("new.txt"), b"from-theirs").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let _ = repo.merge("feature", "me").unwrap_err();
        assert!(root.join("new.txt").exists(), "merge pulled in theirs' new.txt");
        repo.merge_abort().unwrap();
        assert!(!repo.merge_in_progress());
        // theirs-only file must be gone, f.txt restored to ours' content
        assert!(!root.join("new.txt").exists(), "abort must drop theirs-only new.txt");
        assert_eq!(std::fs::read(root.join("f.txt")).unwrap(), b"a\nX\nc\n");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_refuses_when_protected_paths_present() {
        // A real three-way merge cannot yet thread perms + wrapped DEKs through
        // `three_way`; doing so would strip protection and write ciphertext to the
        // working tree. The merge must fail closed and leave the repo untouched.
        let root = tmp_root("p7-merge-protected");
        let repo = Repo::init(&root).unwrap();
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.test_set_protected_prefix("secret/", &[pk]).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        std::fs::write(root.join("shared.txt"), b"base\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // Divergent change on each branch from the common base (a real three-way).
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        let ours = repo.commit("me", "ours adds a.txt").unwrap();
        repo.switch_with_identity("feature", Some(&sk)).unwrap();
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "theirs adds b.txt").unwrap();
        // Back on main, authorized, so the protected file is decrypted on disk.
        repo.switch_with_identity("main", Some(&sk)).unwrap();
        assert_eq!(std::fs::read(root.join("secret/db.txt")).unwrap(), b"hunter2");

        // The merge must refuse, naming the branch.
        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeProtected(_)), "got {err:?}");

        // Working tree untouched: still decrypted plaintext, no raw ciphertext.
        assert_eq!(
            std::fs::read(root.join("secret/db.txt")).unwrap(),
            b"hunter2",
            "protected file must be unchanged (no ciphertext written) when merge refused",
        );
        // theirs-only file was never pulled in; no merge state recorded.
        assert!(!root.join("b.txt").exists(), "nothing from theirs written");
        assert!(!repo.merge_in_progress(), "no MERGE_HEAD recorded");
        // HEAD unmoved: no merge commit was created.
        assert_eq!(repo.head_tip().unwrap(), Some(ours), "HEAD must not advance");
        let _ = base;
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_rejects_a_plaintext_secret_and_writes_nothing() {
        let root = tmp_root("scan-reject");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("clean.txt"), b"hello").unwrap();
        std::fs::write(root.join("creds.txt"), b"aws = AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let err = repo.commit("me", "leak").unwrap_err();
        assert!(matches!(err, Error::SecretDetected(_)), "got {err:?}");
        // Nothing committed: the branch is still unborn.
        assert_eq!(repo.head_tip().unwrap(), None);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn allowlisted_blob_hash_lets_commit_through() {
        let root = tmp_root("scan-allow");
        let repo = Repo::init(&root).unwrap();
        let secret = b"aws = AKIAIOSFODNN7EXAMPLE\n";
        std::fs::write(root.join("creds.txt"), secret).unwrap();
        // Compute the blob hash the scanner will object to.
        let id = scl_core::Object::blob(secret.to_vec()).id();
        std::fs::create_dir_all(&repo.layout().dot_sc).unwrap();
        std::fs::write(
            repo.layout().dot_sc.join("scanner-allowlist.toml"),
            format!("[[allow]]\nblob = \"{}\"\nnote = \"test fixture\"\n", id.to_hex()),
        )
        .unwrap();
        // Now the commit succeeds.
        let cid = repo.commit("me", "allowed").unwrap();
        assert!(repo.head_tip().unwrap() == Some(cid));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clean_tree_commits_normally() {
        let root = tmp_root("scan-clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"just some text\n").unwrap();
        assert!(repo.commit("me", "ok").is_ok());
        let rep = repo.scan_worktree().unwrap();
        assert!(rep.is_empty());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clone_copies_objects_refs_head_and_worktree() {
        let a = tmp_root("clone-src");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("README.md"), b"hello from A\n").unwrap();
            repo.commit("me", "first").unwrap();
            repo.branch("feature").unwrap();
        }
        let b = tmp_root("clone-dst");
        let _ = std::fs::remove_dir_all(&b); // clone_to inits it
        let cloned = Repo::clone_to(&a, &b).unwrap();
        // HEAD + branches copied
        assert!(cloned.head_tip().unwrap().is_some());
        let branches: Vec<String> =
            cloned.branches().unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(
            branches.contains(&"main".to_string()) && branches.contains(&"feature".to_string())
        );
        // working tree materialized
        assert_eq!(std::fs::read(b.join("README.md")).unwrap(), b"hello from A\n");
        // origin recorded
        assert_eq!(
            cloned.remotes().unwrap(),
            vec![("origin".to_string(), a.display().to_string())]
        );
        // origin/* remote-tracking refs seeded so merge/fetch resolve immediately
        assert_eq!(
            crate::refs::read_remote_tip(cloned.layout(), "origin", "main").unwrap(),
            cloned.head_tip().unwrap()
        );
        drop(cloned);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn clone_preserves_committed_secret_decryptable_only_with_key() {
        let a = tmp_root("clone-secret-src");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"x\n").unwrap();
            repo.commit("me", "base").unwrap();
            repo.secret_add("DB_URL", b"postgres://secret", &[alice_pk]).unwrap();
        }
        let b = tmp_root("clone-secret-dst");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();

        // The secret travelled: it's in the cloned registry...
        let list = brepo.secret_list().unwrap();
        assert!(list.iter().any(|s| s.name == "DB_URL"));
        // ...as ciphertext only an authorized key can read.
        let code_ok = brepo
            .run(
                &alice_sk,
                &["sh".into(), "-c".into(), "test \"$DB_URL\" = postgres://secret".into()],
            )
            .unwrap();
        assert_eq!(code_ok, 0, "alice's key decrypts the cloned secret");
        let code_denied = brepo
            .run(
                &mallory_sk,
                &["sh".into(), "-c".into(), "test -z \"$DB_URL\"".into()],
            )
            .unwrap();
        assert_eq!(code_denied, 0, "non-recipient sees no DB_URL (ciphertext stays sealed)");

        drop(brepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn fetch_updates_remote_tracking_then_merge_integrates() {
        let a = tmp_root("fetch-src");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"base\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("fetch-dst");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();

        // New commit on A.
        let a_tip = {
            let arepo = Repo::open(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"base\nA-change\n").unwrap();
            arepo.commit("me", "A change").unwrap()
        };

        // B fetches: remote-tracking ref advances, local branch does not.
        let updated = brepo.fetch("origin").unwrap();
        assert!(updated.iter().any(|(br, id)| br == "main" && *id == a_tip));
        assert_eq!(
            crate::refs::read_remote_tip(&brepo.layout, "origin", "main").unwrap(),
            Some(a_tip)
        );

        // Merge the fetched ref (fast-forward) and verify the file updated.
        brepo.merge("origin/main", "me").unwrap();
        assert_eq!(std::fs::read(b.join("f.txt")).unwrap(), b"base\nA-change\n");

        drop(brepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn merge_into_unborn_branch_adopts_theirs_wholesale() {
        // A freshly `init`ed repo has an unborn local branch (no commits yet).
        // Merging a branch into it (e.g. after fetching remote history) must
        // adopt that branch's tip directly rather than erroring `Unborn`.
        let a = tmp_root("unborn-merge-src");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"from-theirs\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("unborn-merge-dst");
        let _ = std::fs::remove_dir_all(&b);
        std::fs::create_dir_all(&b).unwrap();
        let unborn = Repo::init(&b).unwrap();
        unborn.remote_add("origin", a.to_str().unwrap()).unwrap();
        let fetched = unborn.fetch("origin").unwrap();
        assert!(fetched.iter().any(|(br, _)| br == "main"));
        assert_eq!(unborn.head_tip().unwrap(), None, "local branch is still unborn before merge");

        let merged = unborn.merge("origin/main", "me").unwrap();
        assert_eq!(std::fs::read(b.join("f.txt")).unwrap(), b"from-theirs\n");
        assert_eq!(unborn.head_tip().unwrap(), Some(merged));

        drop(unborn);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn push_fast_forward_advances_remote_and_rejects_non_ff() {
        let a = tmp_root("push-remote");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"base\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("push-local");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();

        // B commits and pushes (fast-forward).
        std::fs::write(b.join("f.txt"), b"base\nB-change\n").unwrap();
        let b_tip = brepo.commit("me", "B change").unwrap();
        let pushed = brepo.push("origin").unwrap();
        assert_eq!(pushed, b_tip);
        // A's main now points at B's tip and A has the objects.
        let arepo = Repo::open(&a).unwrap();
        assert_eq!(arepo.head_tip().unwrap(), Some(b_tip));

        // An immediate re-push is a no-op (already up to date) and still succeeds.
        assert_eq!(brepo.push("origin").unwrap(), b_tip);

        // A diverges; B's next push is non-ff.
        std::fs::write(a.join("f.txt"), b"base\nB-change\nA-diverge\n").unwrap();
        arepo.commit("me", "A diverge").unwrap();
        std::fs::write(b.join("f.txt"), b"base\nB-change\nB-again\n").unwrap();
        brepo.commit("me", "B again").unwrap();
        assert!(matches!(brepo.push("origin"), Err(Error::NonFastForward)));

        drop(brepo);
        drop(arepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn open_with_budget_bounds_the_store() {
        let dir = std::env::temp_dir().join(format!("sc-test-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            Repo::init(&dir).unwrap();
        } // drop → release lock
        let repo = Repo::open_with_budget(&dir, 4 * 1024 * 1024).unwrap();
        assert_eq!(repo.vfs().stats().budget_bytes, 4 * 1024 * 1024);
        drop(repo);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn commit_encrypts_files_under_a_protected_prefix() {
        let root = tmp_root("p7-commit");
        let repo = Repo::init(&root).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        // Seed a protected prefix via the test seam (Task 6 provides the real `protect`).
        repo.test_set_protected_prefix("secret/", &[pk]).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let cid = repo.commit("me", "add secret").unwrap();
        // The policy must have exactly one wrapped-DEK entry.
        let snap = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            s.get_snapshot(&cid).unwrap()
        };
        assert_eq!(snap.protection.wrapped.len(), 1, "one protected blob");
        // The stored blob bytes must be ciphertext (not the plaintext).
        let blob_id = *snap.protection.wrapped.keys().next().unwrap();
        let obj = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            s.get(&blob_id).unwrap()
        };
        if let scl_core::Object::Blob(b) = obj {
            assert_ne!(&b[..], b"hunter2", "blob must be ciphertext, not plaintext");
        } else {
            panic!("expected Blob object");
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unchanged_protected_file_keeps_stable_wrapped_dek_across_commits() {
        // Regression: `wrap_dek_for` randomizes its ephemeral key, so naively
        // re-wrapping every commit would change `protection.wrapped` (and the
        // snapshot encoding) even when the protected content is identical. The
        // prior wrap must be carried forward for an unchanged (blob, recipient).
        let root = tmp_root("p7-stable-wrap");
        let repo = Repo::init(&root).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.test_set_protected_prefix("secret/", &[pk]).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        std::fs::write(root.join("plain.txt"), b"v1").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let w1 = repo.snapshot(&c1).unwrap().protection.wrapped;

        // Change only the unrelated plaintext file; the protected file is untouched.
        std::fs::write(root.join("plain.txt"), b"v2").unwrap();
        let c2 = repo.commit("me", "touch plain").unwrap();
        let w2 = repo.snapshot(&c2).unwrap().protection.wrapped;

        assert_ne!(c1, c2, "the two commits are distinct");
        // Same blob id (convergent) AND byte-identical wrapped DEKs (carried forward).
        assert_eq!(w1, w2, "wrapped DEKs must be stable for unchanged protected content");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn protect_records_prefix_and_encrypts_matching_file() {
        let root = tmp_root("p7-protect");
        let repo = Repo::init(&root).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        // Commit unrelated history first so `protect` runs against an existing
        // tip (exercises the `Some(tip)` branch, not just the unborn case).
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        repo.commit("me", "base").unwrap();
        // Write a matching file first, then protect: it must be encrypted + wrapped.
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let cid = repo.protect("secret/", &[pk], None).unwrap();
        let snap = repo.snapshot(&cid).unwrap();
        // The prefix is recorded.
        assert!(snap.protection.prefixes.iter().any(|p| p.prefix == "secret/"));
        // Exactly one wrapped protected blob, and it is ciphertext.
        assert_eq!(snap.protection.wrapped.len(), 1, "one protected blob");
        let blob_id = *snap.protection.wrapped.keys().next().unwrap();
        let obj = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            s.get(&blob_id).unwrap()
        };
        match obj {
            scl_core::Object::Blob(b) => assert_ne!(&b[..], b"hunter2", "blob must be ciphertext"),
            _ => panic!("expected Blob"),
        }
        // The tree entry is PROTECTED.
        let entries = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap()
        };
        let (_id, _m, perms) = entries.get("secret/db.txt").copied().unwrap();
        assert_ne!(perms & scl_core::PROTECTED, 0, "db.txt must be PROTECTED");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_adds_recipient_without_changing_file_objects() {
        let root = tmp_root("p7-grant");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let root1 = repo.snapshot(&c1).unwrap().root;
        let c2 = repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        let snap2 = repo.snapshot(&c2).unwrap();
        assert_eq!(snap2.root, root1, "grant must not change the file tree");
        // bob now has a wrapped DEK for the protected blob.
        let any = snap2.protection.wrapped.values().next().unwrap();
        assert_eq!(any.len(), 2, "alice + bob");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_on_unprotected_prefix_errors_not_protected() {
        let root = tmp_root("p7-grant-noprefix");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, _alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();
        let err = repo.grant("nope/", &alice_sk, &bob_pk).unwrap_err();
        assert!(matches!(err, Error::NotProtected(_)), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_with_non_recipient_identity_errors_not_authorized() {
        let root = tmp_root("p7-grant-unauth");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        // mallory is not a recipient → cannot recover the DEK to grant.
        let err = repo.grant("secret/", &mallory_sk, &bob_pk).unwrap_err();
        assert!(matches!(err, Error::NotAuthorized(_)), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_surfaces_tampered_wrap_as_crypto_error_not_unauthorized() {
        // A wrap addressed to the authorized identity that fails to decrypt
        // (tampered) must surface as a hard crypto error, not be misclassified
        // as NotAuthorized.
        let root = tmp_root("p7-grant-tamper");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let snap = repo.snapshot(&c1).unwrap();

        // Tamper alice's wrap bytes (recipient id intact) and commit it forward.
        let mut protection = snap.protection;
        for wks in protection.wrapped.values_mut() {
            for w in wks.iter_mut() {
                let n = w.wrapped_dek.len();
                w.wrapped_dek[n - 1] ^= 0xFF;
            }
        }
        repo.commit_snapshot(snap.root, vec![c1], snap.secrets, protection, "test", "tamper")
            .unwrap();

        let err = repo.grant("secret/", &alice_sk, &bob_pk).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "tamper must be a crypto error, got {err:?}");
        assert!(!matches!(err, Error::NotAuthorized(_)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn revoke_removes_wrapped_entries_and_prefix_membership() {
        let root = tmp_root("p7-revoke");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let root1 = repo.snapshot(&c1).unwrap().root;
        // Grant bob, then revoke him.
        let c2 = repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        assert_eq!(repo.snapshot(&c2).unwrap().protection.wrapped.values().next().unwrap().len(), 2);
        let bob_id = bob_pk.recipient_id();
        let c3 = repo.revoke("secret/", &bob_id).unwrap();
        let snap3 = repo.snapshot(&c3).unwrap();
        // Root tree unchanged (policy-only).
        assert_eq!(snap3.root, root1, "revoke must not change the file tree");
        // bob's wrap is gone; only alice remains.
        let wks = snap3.protection.wrapped.values().next().unwrap();
        assert_eq!(wks.len(), 1, "only alice remains");
        assert!(!wks.iter().any(|w| w.recipient_id == bob_id.as_str()));
        // bob is no longer in the prefix rule's recipients.
        let rule = snap3.protection.prefixes.iter().find(|p| p.prefix == "secret/").unwrap();
        assert!(!rule.recipients.iter().any(|pk| {
            scl_crypto::PublicKey::from_bytes(*pk).recipient_id() == bob_id
        }));
        // protected_prefixes reflects the surviving recipient.
        let listed = repo.protected_prefixes().unwrap();
        let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
        assert_eq!(recips, &vec![alice_pk.recipient_id()]);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_carries_forward_absent_protected_files_for_non_recipient() {
        // Regression: a non-recipient checks out (protected file skipped/absent),
        // then commits something unrelated. The absent protected file and its
        // wrapped DEKs must SURVIVE — a non-recipient must not silently destroy
        // ciphertext they cannot read.
        let root = tmp_root("p7-carry-forward");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();

        // Seed the prefix on a commit, branch "other" BEFORE the protected file
        // exists so switching there (then back as mallory) leaves it absent.
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        repo.branch("other").unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add secret").unwrap();

        // Capture c1's protected blob id + alice's wrap count.
        let snap1 = repo.snapshot(&c1).unwrap();
        let blob1 = {
            let entries = {
                let a = repo.vfs_handle().store();
                let mut s = a.lock().unwrap();
                worktree::tree_file_entries_with_perms(&mut s, snap1.root).unwrap()
            };
            let (id, _mode, perms) = entries.get("secret/db.txt").copied().unwrap();
            assert_ne!(perms & scl_core::PROTECTED, 0, "db.txt must be PROTECTED in c1");
            id
        };
        assert_eq!(snap1.protection.wrapped.get(&blob1).map(|w| w.len()), Some(1));

        // As mallory: switch away (deletes db.txt) then back (skipped, absent).
        repo.switch_with_identity("other", Some(&mallory_sk)).unwrap();
        let skipped = repo.switch_with_identity("main", Some(&mallory_sk)).unwrap();
        assert!(skipped.contains(&"secret/db.txt".to_string()));
        assert!(!root.join("secret/db.txt").exists(), "protected file absent for mallory");

        // Mallory commits an UNRELATED file.
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        let c2 = repo.commit("mallory", "unrelated").unwrap();

        // The protected ciphertext + its wrap survived mallory's commit.
        let snap2 = repo.snapshot(&c2).unwrap();
        assert_eq!(
            snap2.protection.wrapped.get(&blob1).map(|w| w.len()),
            Some(1),
            "alice's wrapped DEK must survive a non-recipient commit"
        );
        let entries2 = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap2.root).unwrap()
        };
        let (id2, _m, perms2) = entries2.get("secret/db.txt").copied().expect("db.txt still in tree");
        assert_ne!(perms2 & scl_core::PROTECTED, 0, "db.txt must still be PROTECTED");
        assert_eq!(id2, blob1, "same ciphertext blob carried forward unchanged");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn push_creates_a_new_remote_branch() {
        let a = tmp_root("push-newbr-remote");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"x\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("push-newbr-local");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();
        brepo.branch("feature").unwrap();
        brepo.switch("feature").unwrap();
        std::fs::write(b.join("g.txt"), b"feat\n").unwrap();
        let tip = brepo.commit("me", "feature").unwrap();
        brepo.push("origin").unwrap();
        let arepo = Repo::open(&a).unwrap();
        assert_eq!(crate::refs::read_branch_tip(arepo.layout(), "feature").unwrap(), Some(tip));
        drop(brepo);
        drop(arepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn authorized_checkout_decrypts_unauthorized_skips() {
        // Setup: init repo, generate alice + mallory key pairs.
        let root = tmp_root("p7-checkout");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();

        // Seed the protection prefix via the test seam (Task 6 will provide
        // the real `protect` API). Branch "other" at this policy-only commit so
        // it has no protected files — switching to it will delete secret/db.txt
        // from the working tree and switching back as mallory will skip writing it.
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        repo.branch("other").unwrap();

        // Add the protected file and commit on "main": it is encrypted for alice.
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();

        // Switch away (deletes working-tree secret/db.txt) then back as alice → decrypts.
        repo.switch_with_identity("other", Some(&alice_sk)).unwrap();
        assert!(!root.join("secret/db.txt").exists(), "switch to other must clear the protected file");
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        assert_eq!(
            std::fs::read(root.join("secret/db.txt")).unwrap(),
            b"hunter2",
            "alice's key must decrypt the protected file on switch back to main"
        );

        // Switch away again (clears file), then back as mallory → skipped (file absent).
        repo.switch_with_identity("other", Some(&mallory_sk)).unwrap();
        let skipped = repo.switch_with_identity("main", Some(&mallory_sk)).unwrap();
        assert!(
            skipped.contains(&"secret/db.txt".to_string()),
            "mallory's switch must report secret/db.txt as skipped"
        );
        assert!(
            !root.join("secret/db.txt").exists(),
            "unauthorized switch must not write the protected file"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn status_clean_for_decrypted_protected_file() {
        // A decrypted protected file on disk must read as CLEAN: status compares
        // the convergent re-encryption of the disk bytes to the stored ciphertext.
        let root = tmp_root("p7-status-clean");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        // The working file is plaintext while HEAD holds ciphertext, yet status
        // must report no changes (no spurious modified/deleted/added).
        let s = repo.status().unwrap();
        assert!(s.modified.is_empty(), "decrypted protected file must not show as modified: {s:?}");
        assert!(s.deleted.is_empty(), "protected file present on disk must not show as deleted: {s:?}");
        assert!(s.added.is_empty(), "{s:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switch_refuses_genuine_edit_to_protected_file() {
        // A real edit to a decrypted protected file must BLOCK the switch (no
        // silent data loss) and the edit must be preserved.
        let root = tmp_root("p7-switch-edit");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        repo.branch("other").unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        // Genuinely edit the protected file (still plaintext on disk).
        std::fs::write(root.join("secret/db.txt"), b"edited-secret").unwrap();
        // status must report it modified (convergent re-encryption differs).
        assert!(repo.status().unwrap().modified.contains(&"secret/db.txt".to_string()));
        // switch must refuse and preserve the edit.
        let err = repo.switch("other").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(root.join("secret/db.txt")).unwrap(),
            b"edited-secret",
            "the uncommitted edit to the protected file must be preserved"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switching_to_protected_branch_removes_stale_plaintext_for_non_recipient() {
        // A path that is plaintext on branch A and protected on branch B must be
        // ABSENT (not the stale A plaintext) after a non-recipient switches A->B.
        let root = tmp_root("p7-stale-plaintext");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();

        // Branch A (main): data/x.txt as plaintext.
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::write(root.join("data/x.txt"), b"plaintext-A").unwrap();
        repo.commit("me", "plaintext on A").unwrap();

        // Branch B: same path, but data/ is protected -> committed as ciphertext.
        repo.branch("b").unwrap();
        repo.switch("b").unwrap();
        repo.test_set_protected_prefix("data/", &[alice_pk]).unwrap();
        repo.commit("me", "encrypt on B").unwrap();

        // Back on A: the working file is plaintext again.
        repo.switch("main").unwrap();
        assert_eq!(std::fs::read(root.join("data/x.txt")).unwrap(), b"plaintext-A");

        // Switch A->B as mallory (non-recipient): the file is skipped AND the
        // stale plaintext must be removed (confidentiality).
        let skipped = repo.switch_with_identity("b", Some(&mallory_sk)).unwrap();
        assert!(skipped.contains(&"data/x.txt".to_string()), "mallory must skip the protected file");
        assert!(
            !root.join("data/x.txt").exists(),
            "stale A plaintext must be removed when the path becomes protected for a non-recipient"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn push_then_clone_via_pack_roundtrips_history() {
        let origin = std::env::temp_dir().join(format!("scl-bulk-origin-{}", std::process::id()));
        let work = std::env::temp_dir().join(format!("scl-bulk-work-{}", std::process::id()));
        let clone = std::env::temp_dir().join(format!("scl-bulk-clone-{}", std::process::id()));
        for p in [&origin, &work, &clone] { let _ = std::fs::remove_dir_all(p); }

        // origin is an empty remote; work pushes two commits to it.
        Repo::init(&origin).unwrap();
        let w = Repo::init(&work).unwrap();
        w.remote_add("origin", &origin.display().to_string()).unwrap();
        std::fs::write(work.join("a.txt"), b"one").unwrap();
        w.commit("t", "c1").unwrap();
        std::fs::write(work.join("a.txt"), b"two").unwrap();
        let tip = w.commit("t", "c2").unwrap();
        w.push("origin").unwrap();

        // Clone the origin elsewhere; HEAD tip + its objects must be present.
        let c = Repo::clone_to(&origin, &clone).unwrap();
        assert_eq!(c.head_tip().unwrap(), Some(tip));

        for p in [&origin, &work, &clone] { std::fs::remove_dir_all(p).unwrap(); }
    }

    #[test]
    fn merge_and_switch_refuse_while_merge_in_progress() {
        let root = tmp_root("guard-in-progress");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        // Trigger a conflict so a merge is in progress.
        let _ = repo.merge("feature", "me").unwrap_err();
        assert!(repo.merge_in_progress());
        // Both `merge` and `switch` must refuse mid-merge.
        assert!(matches!(repo.merge("feature", "me"), Err(Error::MergeInProgress)));
        assert!(matches!(repo.switch("feature"), Err(Error::MergeInProgress)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Regression: after a clone, an incremental fetch must send only the new
    /// delta — not the full history. Under the old bug, `transfer_objects`
    /// derived `haves` from the remote's tips (the objects being fetched), so
    /// on a clone→advance→fetch cycle the intersection would be empty and the
    /// remote would re-send the entire reachable closure. The fix derives haves
    /// from the local repo's refs, which are closure-complete by construction.
    ///
    /// This test proves the property directly against `LocalTransport::get_pack`:
    /// with correct local haves the pack for the new tip MUST exclude objects
    /// that were already present in the clone.
    #[test]
    fn fetch_transfers_only_delta_not_full_history() {
        let remote_root = tmp_root("delta-remote");
        let local_root = tmp_root("delta-local");
        let _ = std::fs::remove_dir_all(&local_root); // clone_to inits it

        // ── step 1: remote gets c1 with a distinctive large blob ─────────────
        let big_blob_bytes: Vec<u8> = vec![0xCDu8; 4096];
        let big_blob_id = scl_core::Object::blob(big_blob_bytes.clone()).id();
        {
            let remote = Repo::init(&remote_root).unwrap();
            std::fs::write(remote_root.join("large.bin"), &big_blob_bytes).unwrap();
            remote.commit("me", "c1 large").unwrap();
        }

        // ── step 2: clone the remote to local (local holds c1 and its objects) ─
        let local = Repo::clone_to(&remote_root, &local_root).unwrap();
        let c1 = local.head_tip().unwrap().expect("clone should have a HEAD tip");

        // ── step 3: remote advances with a small new file (c2) ──────────────
        let c2 = {
            let remote = Repo::open(&remote_root).unwrap();
            std::fs::write(remote_root.join("small.txt"), b"delta").unwrap();
            remote.commit("me", "c2 small").unwrap()
        };

        // ── step 4: verify correct haves and delta pack ───────────────────────
        // Open local store and compute local_have_tips (the fix path).
        let store_arc = local.vfs.store();
        let store = store_arc.lock().unwrap();

        let haves = crate::sync::local_have_tips(&local.layout, &store).unwrap();
        assert!(haves.contains(&c1), "local haves must include c1 ({c1})");

        // Build the delta pack: remote only sends what local doesn't have.
        use crate::transport::Transport as _;
        let transport = crate::transport::LocalTransport::open(&remote_root).unwrap();
        let pack = transport.get_pack(&[c2], &haves).unwrap();
        let entries: Vec<scl_core::ObjectId> = scl_core::pack::parse_pack(&pack)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        // The pack MUST include the new tip snapshot.
        assert!(
            entries.contains(&c2),
            "delta pack must contain c2; got {entries:?}"
        );
        // The pack MUST NOT contain c1 (local already has it).
        assert!(
            !entries.contains(&c1),
            "delta pack must not re-send c1 that local already holds"
        );
        // The pack MUST NOT contain the large distinctive blob (part of c1's closure).
        assert!(
            !entries.contains(&big_blob_id),
            "delta pack must not re-send the large blob that was in c1"
        );

        drop(store);
        drop(local);
        std::fs::remove_dir_all(&remote_root).unwrap();
        std::fs::remove_dir_all(&local_root).unwrap();
    }
}
