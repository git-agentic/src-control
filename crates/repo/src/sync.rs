//! Remote-sync operations on [`Repo`]: remote config, `clone_to`, `fetch`,
//! `push`, and the shared object-transfer helpers. Split from `repo.rs` for
//! cohesion — same `impl Repo` extension pattern as `secrets.rs`.

use std::path::Path;

use scl_core::{ObjectId, Store};

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::reachable;
use crate::refs;
use crate::worktree;
use crate::repo::validate_branch_name;
use crate::remote::RemoteConfig;
use crate::repo::Repo;
use crate::stdio_transport::open_transport;
use crate::transport::Transport;

impl Repo {
    /// Add a named remote to `.sc/config`. The name becomes a path component
    /// under `refs/remotes/`, so it is validated like a branch name to keep a
    /// hostile name (e.g. `../heads`) from escaping into `refs/heads/`.
    pub fn remote_add(&self, name: &str, url: &str) -> Result<()> {
        validate_branch_name(name)?;
        let mut cfg = RemoteConfig::load(&self.layout)?;
        cfg.add(name, url)?;
        cfg.save(&self.layout)
    }

    /// Add a named Git-backed remote to `.sc/config`.
    pub fn remote_add_git(&self, name: &str, url: &str) -> Result<()> {
        validate_branch_name(name)?;
        let mut cfg = RemoteConfig::load(&self.layout)?;
        cfg.add_kind(name, url, crate::remote::RemoteKind::Git)?;
        cfg.save(&self.layout)
    }

    /// List configured remotes as `(name, url)`.
    pub fn remotes(&self) -> Result<Vec<(String, String)>> {
        let cfg = RemoteConfig::load(&self.layout)?;
        Ok(cfg.remote.into_iter().map(|(n, r)| (n, r.url)).collect())
    }

    /// Clone the repo at local path `src` into a fresh repo at `dst`.
    /// Path-flavored convenience over [`Repo::clone_url`].
    pub fn clone_to(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<Repo> {
        Self::clone_url(&src.as_ref().display().to_string(), dst)
    }

    /// Clone the repo at `src_url` (local path or `ssh://…`) into a fresh repo
    /// at `dst`. Transfers all objects reachable from src's branches, copies
    /// refs + HEAD, seeds `origin/*` remote-tracking refs, records
    /// `origin = src_url`, and materializes HEAD into the dst working tree.
    ///
    /// On `Err`, `dst` may be left with a partially-initialized `.sc/`; the
    /// caller should remove it before retrying.
    pub fn clone_url(src_url: &str, dst: impl AsRef<Path>) -> Result<Repo> {
        let transport = open_transport(src_url)?;
        let remote_refs = transport.list_refs()?;
        let head_branch = transport.head_branch()?;

        let dst_repo = Repo::init(dst.as_ref())?;

        // Transfer every object reachable from the remote's branch tips.
        let tips: Vec<ObjectId> = remote_refs.iter().map(|(_, id)| *id).collect();
        {
            let store_arc = dst_repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            // Fresh clone dst has no local refs yet → no haves → full transfer.
            transfer_objects(transport.as_ref(), &mut store, &tips, &[])?;
        }

        // Copy branches + HEAD, and seed origin/* remote-tracking refs so
        // `merge origin/<branch>` resolves immediately and `fetch` has a baseline.
        for (branch, tip) in &remote_refs {
            refs::write_branch_tip(&dst_repo.layout, branch, tip)?;
            refs::write_remote_tip(&dst_repo.layout, "origin", branch, tip)?;
        }
        refs::write_head(&dst_repo.layout, &head_branch)?;

        // Record origin.
        dst_repo.remote_add("origin", src_url)?;

        // Materialize HEAD into the working tree. No identity is available at
        // clone time, so PROTECTED files are skipped (ciphertext stays in objects
        // but plaintext is not written to disk — correct for unauthorized clones).
        if let Some(head_tip) = dst_repo.head_tip()? {
            let store_arc = dst_repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let head_snap = store.get_snapshot(&head_tip)?;
            let head_root = head_snap.root;
            let head_protection = head_snap.protection;
            worktree::materialize(&dst_repo.layout, &mut store, head_root, None, &head_protection, None)?;
        }
        Ok(dst_repo)
    }

    /// Fetch objects + branch tips from `remote` into remote-tracking refs
    /// (`refs/remotes/<remote>/<branch>`). Local branches are left untouched.
    pub fn fetch(&self, remote: &str) -> Result<Vec<(String, ObjectId)>> {
        let cfg = RemoteConfig::load(&self.layout)?;
        let url = cfg.url(remote).ok_or_else(|| Error::NoSuchRemote(remote.to_string()))?;
        let transport = open_transport(url)?;
        let remote_refs = transport.list_refs()?;

        let tips: Vec<ObjectId> = remote_refs.iter().map(|(_, id)| *id).collect();
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            // Derive haves from local refs before the mutable borrow for transfer.
            let haves = local_have_tips(&self.layout, &store)?;
            transfer_objects(transport.as_ref(), &mut store, &tips, &haves)?;
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
        let transport = open_transport(url)?;
        let branch = refs::current_branch(&self.layout)?;
        let local_tip = self.head_tip()?.ok_or(Error::Unborn)?;

        // Fast-forward check against the remote's current tip for this branch.
        // The tip we checked against is remembered and passed to `update_ref`,
        // which revalidates it under the remote's lock (compare-and-swap) — so
        // a push racing us fails there instead of being silently clobbered.
        let expected_old = transport
            .list_refs()?
            .into_iter()
            .find(|(b, _)| *b == branch)
            .map(|(_, tip)| tip);
        if let Some(remote_tip) = expected_old {
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

        // Build one pack of the objects the remote lacks, send it in bulk, then
        // advance the remote ref.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let mut send: Vec<(ObjectId, Vec<u8>)> = Vec::new();
            for id in reachable::reachable_objects(&mut *store, &[local_tip])? {
                if !transport.has_object(&id)? {
                    send.push((id, store.get(&id)?.encode()));
                }
            }
            if !send.is_empty() {
                let (pack, _idx) = scl_core::pack::build_pack(&send)?;
                transport.put_pack(&pack)?;
            }
        }
        transport.update_ref(&branch, &local_tip, expected_old.as_ref())?;
        Ok(local_tip)
    }
}

/// The tips we already hold locally: every local branch and remote-tracking ref
/// target that is present in the store. Passed as `haves` so a fetch pulls only
/// the delta the remote has beyond what we already have. Safe to advertise
/// because refs advance only after a fully-successful transfer, so every ref
/// target's closure is complete in the store.
pub(crate) fn local_have_tips(layout: &Layout, store: &Store) -> Result<Vec<ObjectId>> {
    let mut out = Vec::new();
    for (_, id) in refs::list_heads(layout)? {
        if store.contains(&id) {
            out.push(id);
        }
    }
    for (_, _, id) in refs::list_remote_tips(layout)? {
        if store.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Pull every object reachable from `tips` out of `transport` and into `store`.
/// `haves` tells the remote which objects the local store already has so it can
/// omit them from the pack; `parse_pack` verifies each record. Callers hold the
/// store lock across this call, so it must not acquire any other lock. Shared by
/// `clone_to` and `fetch`.
fn transfer_objects(
    transport: &dyn Transport,
    store: &mut Store,
    tips: &[ObjectId],
    haves: &[ObjectId],
) -> Result<()> {
    let pack = transport.get_pack(tips, haves)?;
    // parse_pack verifies every record; write each object into the local store.
    for (id, obj) in scl_core::pack::parse_pack(&pack)? {
        let got = store.put(obj)?;
        if got != id {
            return Err(Error::CorruptObject(id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::repo::Repo;

    #[test]
    fn clone_url_with_plain_path_matches_clone_to() {
        let pid = std::process::id();
        let src = std::env::temp_dir().join(format!("scl-cloneurl-src-{pid}"));
        let dst = std::env::temp_dir().join(format!("scl-cloneurl-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
        std::fs::create_dir_all(&src).unwrap();

        let repo = Repo::init(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"one").unwrap();
        let tip = repo.commit("t", "c1").unwrap();

        let cloned = Repo::clone_url(src.to_str().unwrap(), &dst).unwrap();
        assert_eq!(cloned.head_tip().unwrap(), Some(tip));
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"one");
        // origin records the URL string verbatim.
        assert_eq!(
            cloned.remotes().unwrap(),
            vec![("origin".to_string(), src.to_str().unwrap().to_string())]
        );

        std::fs::remove_dir_all(&src).unwrap();
        std::fs::remove_dir_all(&dst).unwrap();
    }
}
