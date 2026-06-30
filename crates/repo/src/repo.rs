//! The persistent repository: ties a persistent `Store` to the `.sc/` layout.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{Object, ObjectId, Protection, Snapshot, Store};
use scl_vfs::Repo as VfsRepo;

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lock::RepoLock;
use crate::reachable;
use crate::refs;
use crate::remote::RemoteConfig;
use crate::transport::{LocalTransport, Transport};
use crate::worktree::{self, Diff};

const DEFAULT_BRANCH: &str = "main";
const DEFAULT_BUDGET: usize = 512 * 1024 * 1024;

/// Working-tree status against HEAD.
pub type Status = Diff;

/// A handle to an open persistent repo. Holds the single-writer lock for its
/// lifetime.
pub struct Repo {
    layout: Layout,
    vfs: VfsRepo,
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
        Self::open_layout(layout)
    }

    /// Open an existing repo by discovering `.sc/` at or above `start`.
    pub fn open(start: impl AsRef<Path>) -> Result<Repo> {
        let layout = Layout::discover(start)?;
        Self::open_layout(layout)
    }

    fn open_layout(layout: Layout) -> Result<Repo> {
        let lock = RepoLock::acquire(&layout)?;
        let store = Store::open_persistent(layout.objects_dir(), DEFAULT_BUDGET)?;
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
        let files = worktree::read_worktree(&self.layout)?;
        self.scan_files(&files)
    }

    /// Snapshot the working tree into a new commit on the current branch. When a
    /// merge is in progress, records both parents and clears the merge state.
    pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
        let files = worktree::read_worktree(&self.layout)?;
        let report = self.scan_files(&files)?;
        if !report.is_empty() {
            return Err(Error::SecretDetected(report));
        }
        let root = self.vfs.write_tree(&files)?;
        let tip = self.head_tip()?;
        let merge_head = crate::merge_state::read_merge_head(&self.layout)?;

        let secrets = self.merged_secrets_for_commit(tip, merge_head)?;

        // Carry forward the tip's protection policy unchanged (Task 4 will apply encryption).
        let protection = match tip {
            Some(t) => {
                let store_arc = self.vfs.store();
                let p = store_arc.lock().unwrap().get_snapshot(&t)?.protection;
                p
            }
            None => Protection::default(),
        };

        let mut parents: Vec<ObjectId> = tip.into_iter().collect();
        if let Some(theirs) = merge_head {
            parents.push(theirs);
        }
        let id = self.commit_snapshot(root, parents, secrets, protection, author, message)?;
        crate::merge_state::clear(&self.layout)?;
        Ok(id)
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
        let snap = Object::Snapshot(Snapshot {
            root,
            parents,
            author: author.to_string(),
            timestamp: 0,
            message: message.to_string(),
            secrets,
            protection,
        });
        let store_arc = self.vfs.store();
        let id = store_arc.lock().unwrap().put(snap)?;
        let branch = refs::current_branch(&self.layout)?;
        refs::write_branch_tip(&self.layout, &branch, &id)?;
        Ok(id)
    }

    /// Working-tree status against HEAD, plus merge-in-progress info.
    pub fn status(&self) -> Result<Status> {
        let head_root = self.head_root()?;
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        worktree::diff_worktree(&self.layout, &mut store, head_root)
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
    /// markers + merge state and returns `MergeConflicts`.
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
        let ours = self.head_tip()?.ok_or(Error::Unborn)?;
        let theirs = refs::resolve_tip(&self.layout, branch)?
            .ok_or_else(|| Error::NoSuchBranch(branch.to_string()))?;

        // Ancestor short-circuits.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            if crate::merge::is_ancestor(&mut store, theirs, ours)? {
                return Err(Error::UpToDate);
            }
            if crate::merge::is_ancestor(&mut store, ours, theirs)? {
                // fast-forward: advance ref + materialize, no merge commit
                let theirs_root = store.get_snapshot(&theirs)?.root;
                let ours_root = store.get_snapshot(&ours)?.root;
                worktree::materialize(&self.layout, &mut store, theirs_root, Some(ours_root))?;
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
            let m = crate::merge::three_way(&mut store, base, ours, theirs)?;
            let ours_root = store.get_snapshot(&ours)?.root;
            (m, ours_root)
        };

        // Build the merged tree from the resolved file set.
        let write_set: Vec<(String, Vec<u8>, scl_core::FileMode)> =
            merge_result.files.iter().map(|(p, m, b)| (p.clone(), b.clone(), *m)).collect();
        let merged_root = self.vfs.write_tree(&write_set)?;

        // Materialize merged tree into the working dir, then write sidecars.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(&self.layout, &mut store, merged_root, Some(ours_root))?;
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
    pub fn merge_abort(&self) -> Result<()> {
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
        let ours_root = self.head_root()?;
        if let Some(root) = ours_root {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let theirs_root = store.get_snapshot(&theirs_id)?.root;
            worktree::materialize(&self.layout, &mut store, root, Some(theirs_root))?;
        }
        crate::merge_state::clear(&self.layout)
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
    /// untracked files are left in place and so don't block the switch.)
    pub fn switch(&self, name: &str) -> Result<()> {
        validate_branch_name(name)?;
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before switching".into(),
            ));
        }
        let target_tip = refs::read_branch_tip(&self.layout, name)?
            .ok_or_else(|| Error::NoSuchBranch(name.to_string()))?;
        let old_root = self.head_root()?;
        let target_root = {
            let store_arc = self.vfs.store();
            let r = store_arc.lock().unwrap().get_snapshot(&target_tip)?.root;
            r
        };
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(&self.layout, &mut store, target_root, old_root)?;
        }
        refs::write_head(&self.layout, name)
    }

    /// Expose the underlying VFS repo handle (needed by secrets.rs methods).
    pub(crate) fn vfs_handle(&self) -> &VfsRepo {
        &self.vfs
    }

    /// Add a named remote to `.sc/config`. The name becomes a path component
    /// under `refs/remotes/`, so it is validated like a branch name to keep a
    /// hostile name (e.g. `../heads`) from escaping into `refs/heads/`.
    pub fn remote_add(&self, name: &str, url: &str) -> Result<()> {
        validate_branch_name(name)?;
        let mut cfg = RemoteConfig::load(&self.layout)?;
        cfg.add(name, url)?;
        cfg.save(&self.layout)
    }

    /// List configured remotes as `(name, url)`.
    pub fn remotes(&self) -> Result<Vec<(String, String)>> {
        let cfg = RemoteConfig::load(&self.layout)?;
        Ok(cfg.remote.into_iter().map(|(n, r)| (n, r.url)).collect())
    }

    /// Clone the repo at `src` into a fresh repo at `dst`. Transfers all objects
    /// reachable from src's branches via `LocalTransport`, copies refs + HEAD,
    /// seeds `origin/*` remote-tracking refs, records `origin = src`, and
    /// materializes HEAD into the dst working tree.
    ///
    /// On `Err`, `dst` may be left with a partially-initialized `.sc/`; the
    /// caller should remove it before retrying.
    pub fn clone_to(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<Repo> {
        let src = src.as_ref();
        let transport = LocalTransport::open(src)?;
        let remote_refs = transport.list_refs()?;
        let head_branch = transport.head_branch()?;

        let dst_repo = Repo::init(dst.as_ref())?;

        // Transfer every object reachable from the remote's branch tips.
        let tips: Vec<ObjectId> = remote_refs.iter().map(|(_, id)| *id).collect();
        {
            let store_arc = dst_repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            transfer_objects(&transport, &mut store, &tips)?;
        }

        // Copy branches + HEAD, and seed origin/* remote-tracking refs so
        // `merge origin/<branch>` resolves immediately and `fetch` has a baseline.
        for (branch, tip) in &remote_refs {
            refs::write_branch_tip(&dst_repo.layout, branch, tip)?;
            refs::write_remote_tip(&dst_repo.layout, "origin", branch, tip)?;
        }
        refs::write_head(&dst_repo.layout, &head_branch)?;

        // Record origin.
        dst_repo.remote_add("origin", &src.display().to_string())?;

        // Materialize HEAD into the working tree.
        if let Some(root) = dst_repo.head_root()? {
            let store_arc = dst_repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(&dst_repo.layout, &mut store, root, None)?;
        }
        Ok(dst_repo)
    }

    /// Fetch objects + branch tips from `remote` into remote-tracking refs
    /// (`refs/remotes/<remote>/<branch>`). Local branches are left untouched.
    pub fn fetch(&self, remote: &str) -> Result<Vec<(String, ObjectId)>> {
        let cfg = RemoteConfig::load(&self.layout)?;
        let url = cfg.url(remote).ok_or_else(|| Error::NoSuchRemote(remote.to_string()))?;
        let transport = LocalTransport::open(url)?;
        let remote_refs = transport.list_refs()?;

        let tips: Vec<ObjectId> = remote_refs.iter().map(|(_, id)| *id).collect();
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            transfer_objects(&transport, &mut store, &tips)?;
        }
        for (branch, tip) in &remote_refs {
            refs::write_remote_tip(&self.layout, remote, branch, tip)?;
        }
        Ok(remote_refs)
    }

    /// Push the current branch to `remote`, fast-forward-only. Creates the remote
    /// branch if absent. Errors `NonFastForward` if the remote has commits not
    /// reachable from the local tip.
    pub fn push(&self, remote: &str) -> Result<ObjectId> {
        let cfg = RemoteConfig::load(&self.layout)?;
        let url = cfg.url(remote).ok_or_else(|| Error::NoSuchRemote(remote.to_string()))?;
        let transport = LocalTransport::open(url)?;
        let branch = refs::current_branch(&self.layout)?;
        let local_tip = self.head_tip()?.ok_or(Error::Unborn)?;

        // Fast-forward check against the remote's current tip for this branch.
        if let Some((_, remote_tip)) =
            transport.list_refs()?.into_iter().find(|(b, _)| *b == branch)
        {
            if remote_tip == local_tip {
                // Already up to date: skip all remote I/O (no transfer, no ref write).
                return Ok(local_tip);
            }
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            if !crate::merge::is_ancestor(&mut store, remote_tip, local_tip)? {
                return Err(Error::NonFastForward);
            }
        }

        // Transfer objects the remote lacks, then advance the remote ref.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let ids = reachable::reachable_objects(&mut *store, &[local_tip])?;
            for id in ids {
                if !transport.has_object(&id)? {
                    let bytes = store.get(&id)?.encode();
                    transport.put_object(&id, &bytes)?;
                }
            }
        }
        transport.update_ref(&branch, &local_tip)?;
        Ok(local_tip)
    }
}

/// Pull every object reachable from `tips` out of `transport` and into `store`,
/// skipping ids already present. The reachability walk only decodes snapshots +
/// trees (small); each blob is fetched exactly once here — there is no
/// large-object double-read. Callers hold the store lock across this call, so it
/// must not acquire any other lock. Shared by `clone_to` and `fetch`.
fn transfer_objects(
    transport: &impl Transport,
    store: &mut Store,
    tips: &[ObjectId],
) -> Result<()> {
    let mut tsrc = reachable::TransportSource { transport };
    for id in reachable::reachable_objects(&mut tsrc, tips)? {
        if store.contains(&id) {
            continue;
        }
        let bytes = transport.get_object(&id)?;
        let got = store.put(Object::decode(&bytes)?)?;
        if got != id {
            return Err(Error::CorruptObject(id));
        }
    }
    Ok(())
}

/// Reject branch names that would escape or corrupt `refs/heads/`. A branch name
/// becomes a single path component under `refs/heads/`, so names containing path
/// separators, the special `.`/`..` components, or a leading dot are refused.
fn validate_branch_name(name: &str) -> Result<()> {
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
}
