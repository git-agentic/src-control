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
            transfer_objects(&dst_repo.layout, transport.as_ref(), &mut store, &tips, &[])?;
            // Clone-specific belt-and-suspenders (P22 Task 3): the transfer
            // above already indexes every signature object it wrote via
            // `index_incoming`, but a fresh clone is a wholesale copy of the
            // whole reachable set — cheap and simplest to instead trust a
            // full post-copy scan of what actually landed on disk, rather
            // than depending on the transfer call site's exact bookkeeping.
            // Idempotent: `reindex` rewrites the index from scratch, so
            // running it after `index_incoming` already populated entries
            // is a no-op on top of a no-op, not a double-count.
            crate::signatures::reindex(&dst_repo.layout, &mut store)?;
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
            // Clone doesn't transfer `.sc/sparse` (out of P24 scope — sparse
            // config is local, like `.scignore`), so a fresh clone always
            // starts full: `Sparse::default()` here, not `dst_repo.sparse_spec()`.
            worktree::materialize(
                &dst_repo.layout,
                &mut store,
                head_root,
                None,
                &head_protection,
                None,
                &crate::sparse::Sparse::default(),
            )?;
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
            transfer_objects(&self.layout, transport.as_ref(), &mut store, &tips, &haves)?;
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
        //
        // Bounded client push (P25 final-review fix): this used to collect
        // every missing object's encoded bytes into `send: Vec<(ObjectId,
        // Vec<u8>)>` and call `build_pack`, holding roughly two full pack
        // images in RAM (the `send` Vec plus `build_pack`'s output) — the
        // same unbounded-RAM shape the fetch side had. Now only the id list
        // is collected (32 bytes each); the pack itself is built one object
        // at a time into a guarded temp file via
        // `transport::write_ids_to_temp_pack` (the same PackWriter-based
        // helper `LocalTransport::build_pack_tempfile` uses — one
        // ids-to-temp-pack-file implementation shared by both), and an
        // opened `File` reader of that temp file is handed to
        // `transport.put_pack` — peak RAM is one object.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let reachable = reachable::reachable_objects(&mut *store, &[local_tip])?;
            // Sender seam (P22 Task 3): unlike `fetch`/`clone`, `push` builds
            // its outgoing set directly from a local reachability walk
            // rather than calling `Transport::get_pack` — so the
            // `get_pack`-side signature extension in `LocalTransport` never
            // runs for a push. Extend the reachable set here the same way:
            // every indexed signature covering a snapshot already in it.
            let snaps: Vec<ObjectId> = reachable.iter().copied().collect();
            let sig_ids = crate::signatures::indexed_signature_ids_for(&self.layout, &snaps)?;
            let mut send_ids: Vec<ObjectId> = Vec::new();
            for id in reachable.into_iter().chain(sig_ids) {
                if !transport.has_object(&id)? {
                    send_ids.push(id);
                }
            }
            if !send_ids.is_empty() {
                let guard = crate::transport::write_ids_to_temp_pack(
                    &self.layout,
                    &mut store,
                    &send_ids,
                )?;
                let mut f = std::fs::File::open(guard.path())?;
                transport.put_pack(&mut f)?;
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
/// omit them from the pack. Callers hold the store lock across this call, so it
/// must not acquire any other lock. Shared by `clone_to` and `fetch`.
///
/// Receiver seam (P22 Task 3): this is the client-side ingestion path for
/// BOTH `fetch` and `clone_url` (over local paths and ssh:// alike — this
/// function is transport-agnostic) — unlike a push, which lands via
/// `Transport::put_pack` on the remote, a pull writes straight into `store`
/// here, so `index_incoming` on exactly the ids this call just wrote is the
/// matching seam. `clone_url` additionally runs a full `signatures::reindex`
/// once its transfer is complete (see there for why the belt-and-suspenders).
///
/// Bounded client fetch (P25 final-review fix): `transport.get_pack` used to
/// destream the whole pack into a `Vec<u8>` here before a non-streaming
/// `parse_pack` — for a large clone/fetch, the receiving end is typically
/// this client, so that `Vec` was exactly the unbounded-RAM cap-lift the P25
/// spec explicitly chose *not* to ship. Instead, spill `get_pack`'s output
/// into a guarded temp file under `.sc/tmp/` (removed on drop, success or
/// error alike) and hand the path to [`crate::transport::ingest_pack_file`],
/// the same two-pass atomic-after-verify bounded ingest the server and the
/// ssh wire already use — peak RAM here is one object, not the whole pack.
/// `ingest_pack_file` already calls `index_incoming` on exactly the ids it
/// wrote, so this function must not call it a second time.
fn transfer_objects(
    layout: &Layout,
    transport: &dyn Transport,
    store: &mut Store,
    tips: &[ObjectId],
    haves: &[ObjectId],
) -> Result<()> {
    let guard = crate::transport::TempPackGuard::new(layout)?;
    {
        let mut f = std::fs::File::create(guard.path())?;
        transport.get_pack(tips, haves, &mut f)?;
    }
    crate::transport::ingest_pack_file(layout, store, guard.path())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::repo::Repo;
    use crate::signatures::SigStatus;
    use crate::sync::transfer_objects;

    #[test]
    fn signatures_ride_fetch_push_and_clone_local() {
        // A: the "server" repo — one signed commit to start.
        let pid = std::process::id();
        let a_root = std::env::temp_dir().join(format!("scl-sigxfer-a-{pid}"));
        let b_root = std::env::temp_dir().join(format!("scl-sigxfer-b-{pid}"));
        let _ = std::fs::remove_dir_all(&a_root);
        let _ = std::fs::remove_dir_all(&b_root);
        std::fs::create_dir_all(&a_root).unwrap();

        let a = Repo::init(&a_root).unwrap();
        std::fs::write(a_root.join("f1"), b"one").unwrap();
        let snap1 = a.commit("t", "c1").unwrap();
        let (_s, identity) = scl_crypto::generate_identity_v2();
        a.sign_snapshot(snap1, &identity).unwrap();
        let signer = identity.signing.as_ref().unwrap().public().to_bytes();
        let mut trust = std::collections::HashMap::new();
        trust.insert(signer, "alice".to_string());

        // clone: B pulls A wholesale. The signature must exist AND be
        // indexed at B (not just present as a dangling CAS object) — that
        // is what makes sig_status resolve to Trusted rather than Unsigned.
        let b = Repo::clone_to(&a_root, &b_root).unwrap();
        assert_eq!(b.sig_status(&snap1, &trust).unwrap(), SigStatus::Trusted("alice".to_string()));

        // fetch: A gets a second signed commit; B fetches and must pick up
        // the new signature via `transfer_objects`'s `index_incoming` call
        // (not the clone-only `reindex` path, which only runs on clone_url).
        std::fs::write(a_root.join("f2"), b"two").unwrap();
        let snap2 = a.commit("t", "c2").unwrap();
        a.sign_snapshot(snap2, &identity).unwrap();
        // `push` below opens its OWN `LocalTransport` onto A's `.sc/`, which
        // takes A's repo lock for `update_ref` — drop this handle first so
        // it isn't held twice from the same process (RepoLock isn't
        // reentrant); reopened after the push to check A's final state.
        drop(a);
        b.fetch("origin").unwrap();
        assert_eq!(b.sig_status(&snap2, &trust).unwrap(), SigStatus::Trusted("alice".to_string()));

        // push: bring B's local branch up to snap2 (fetch only advanced the
        // remote-tracking ref, not the local branch — fast-forward merge),
        // then add and sign a third commit on top and push it back to A.
        b.merge("origin/main", "t").unwrap();
        std::fs::write(b_root.join("f3"), b"three").unwrap();
        let snap3 = b.commit("t", "c3").unwrap();
        b.sign_snapshot(snap3, &identity).unwrap();
        b.push("origin").unwrap();
        // A's receiver seam is `LocalTransport::put_pack` — verify A's index
        // picked up the pushed signature via `index_incoming` there.
        let a = Repo::open(&a_root).unwrap();
        assert_eq!(a.sig_status(&snap3, &trust).unwrap(), SigStatus::Trusted("alice".to_string()));

        drop(a);
        drop(b);
        std::fs::remove_dir_all(&a_root).unwrap();
        std::fs::remove_dir_all(&b_root).unwrap();
    }

    #[test]
    fn retroactive_signature_propagates_on_refetch() {
        // The Task 3 review scenario: a signature added to a snapshot AFTER
        // the receiver's last sync must still show up on the receiver's next
        // fetch. The original `get_pack` sender-side extension folded
        // `indexed_signature_ids_for` into `have_set` by snapshot
        // reachability alone, wrongly assuming "have the snapshot" implies
        // "have every signature ever indexed for it" — that silently
        // defeated ADR-0032's promised retroactive signing on the most
        // common sync path (repeat fetch). This proves the fix.
        let pid = std::process::id();
        let a_root = std::env::temp_dir().join(format!("scl-retrosig-a-{pid}"));
        let b_root = std::env::temp_dir().join(format!("scl-retrosig-b-{pid}"));
        let _ = std::fs::remove_dir_all(&a_root);
        let _ = std::fs::remove_dir_all(&b_root);
        std::fs::create_dir_all(&a_root).unwrap();

        // A commits, unsigned.
        let a = Repo::init(&a_root).unwrap();
        std::fs::write(a_root.join("f1"), b"one").unwrap();
        let snap = a.commit("t", "c1").unwrap();

        // B clones — the commit is unsigned at clone time.
        let b = Repo::clone_to(&a_root, &b_root).unwrap();
        let (_s, identity) = scl_crypto::generate_identity_v2();
        let signer = identity.signing.as_ref().unwrap().public().to_bytes();
        let mut trust = std::collections::HashMap::new();
        trust.insert(signer, "alice".to_string());
        assert_eq!(b.sig_status(&snap, &trust).unwrap(), SigStatus::Unsigned);

        // A signs the OLD commit retroactively. B already has `snap` (same
        // object id, already reachable from its cloned branch tip) — this is
        // exactly the case the buggy have-side extension mishandled.
        a.sign_snapshot(snap, &identity).unwrap();
        drop(a);

        // B fetches again: the retroactive signature must propagate even
        // though B already had the snapshot itself.
        b.fetch("origin").unwrap();
        assert_eq!(
            b.sig_status(&snap, &trust).unwrap(),
            SigStatus::Trusted("alice".to_string()),
            "retroactive signature must propagate on refetch even though the receiver already \
             had the signed snapshot"
        );
        assert_eq!(
            b.signatures_for(&snap).unwrap().len(),
            1,
            "B's index must list the retroactively-fetched signature"
        );

        drop(b);
        std::fs::remove_dir_all(&a_root).unwrap();
        std::fs::remove_dir_all(&b_root).unwrap();
    }

    #[test]
    fn signatures_ride_ssh_transport() {
        // The wire-protocol pipe harness `WireClient` <-> `wire::serve` IS
        // the ssh code path minus the ssh process spawn (StdioTransport
        // shells out to `ssh … sc serve --stdio`, which just runs
        // `wire::serve` on the far end) — mirrors
        // `stdio_transport::tests::wire_client_satisfies_the_transport_contract`.
        // Driving `transfer_objects` (the exact fn `fetch`/`clone_url` call)
        // against that client proves the put_pack/get_pack seams cover the
        // wire, not just `LocalTransport`.
        use crate::stdio_transport::WireClient;
        use crate::wire;

        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-sigssh-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-sigssh-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&src_root).unwrap();

        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("a.txt"), b"one").unwrap();
        let tip = src.commit("t", "c1").unwrap();
        let (_s, identity) = scl_crypto::generate_identity_v2();
        src.sign_snapshot(tip, &identity).unwrap();
        let signer = identity.signing.as_ref().unwrap().public().to_bytes();
        let mut trust = std::collections::HashMap::new();
        trust.insert(signer, "alice".to_string());

        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let server_root = src_root.clone();
        let server =
            std::thread::spawn(move || wire::serve(&server_root, &mut server_read, &mut server_write));
        let client = WireClient::handshake(client_read, client_write).unwrap();

        let dst = Repo::init(&dst_root).unwrap();
        {
            let store_arc = dst.vfs().store();
            let mut store = store_arc.lock().unwrap();
            transfer_objects(&dst.layout, &client, &mut store, &[tip], &[]).unwrap();
        }
        client.bye().unwrap();
        drop(client);
        server.join().unwrap().unwrap();

        assert_eq!(dst.sig_status(&tip, &trust).unwrap(), SigStatus::Trusted("alice".to_string()));

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    fn tmp_dir_is_empty(layout: &crate::layout::Layout) -> bool {
        match std::fs::read_dir(layout.tmp_dir()) {
            Ok(mut entries) => entries.next().is_none(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => panic!("unexpected error reading .sc/tmp: {e}"),
        }
    }

    /// P25 final-review fix: `transfer_objects` (the client-side fetch/clone
    /// ingestion path) used to destream the whole pack into a `Vec<u8>`
    /// before a non-streaming `parse_pack` — unbounded client RAM on the
    /// dominant large-clone scenario. It now spills through a guarded temp
    /// file and `ingest_pack_file`, the same bounded two-pass machinery the
    /// server and the ssh wire already use. Driven over the real chunked
    /// wire (`WireClient`/`wire::serve`, mirroring
    /// `signatures_ride_ssh_transport`) so this exercises the actual client
    /// code path a real `ssh://` clone/fetch takes, not just `LocalTransport`.
    /// Asserts: every object lands with the right id, AND the client's
    /// `.sc/tmp` is empty afterward (peak-RAM boundedness isn't directly
    /// observable from a test, but zero residue is the same "spilled and
    /// cleaned up, not buffered in a `Vec`" signature the sibling
    /// zero-residue tests use).
    #[test]
    fn fetch_client_ingests_via_tempfile_zero_residue() {
        use crate::stdio_transport::WireClient;
        use crate::wire;

        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-fetchtmp-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-fetchtmp-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&src_root).unwrap();

        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("a.txt"), b"one").unwrap();
        let c1 = src.commit("t", "c1").unwrap();
        std::fs::write(src_root.join("a.txt"), b"two").unwrap();
        let c2 = src.commit("t", "c2").unwrap();

        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let server_root = src_root.clone();
        let server =
            std::thread::spawn(move || wire::serve(&server_root, &mut server_read, &mut server_write));
        let client = WireClient::handshake(client_read, client_write).unwrap();

        let dst = Repo::init(&dst_root).unwrap();
        {
            let store_arc = dst.vfs().store();
            let mut store = store_arc.lock().unwrap();
            transfer_objects(dst.layout(), &client, &mut store, &[c2], &[]).unwrap();
            assert!(store.contains(&c1), "c1 must have landed (ancestor of the want)");
            assert!(store.contains(&c2), "c2 (the want) must have landed");
        }
        client.bye().unwrap();
        drop(client);
        server.join().unwrap().unwrap();

        assert!(
            tmp_dir_is_empty(dst.layout()),
            "client's .sc/tmp must be empty after a successful fetch — spilled temp pack file \
             must be cleaned up, not left as residue"
        );

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// P25 final-review fix, push side: `Repo::push` used to collect every
    /// missing object's encoded bytes into a `Vec<(ObjectId, Vec<u8>)>` and
    /// call `build_pack` fully in RAM — roughly two full pack images resident
    /// (the `send` Vec plus `build_pack`'s output). It now collects only ids
    /// and streams the pack to a guarded temp file one object at a time via
    /// `transport::write_ids_to_temp_pack`, then hands an opened `File`
    /// reader to `transport.put_pack`. A plain local-path remote already
    /// dispatches through the real `Transport` trait (`LocalTransport`, the
    /// same seam an `ssh://` remote's `StdioTransport` implements) so this
    /// exercises the actual `Repo::push` client code, not a bypass.
    #[test]
    fn push_client_builds_via_tempfile_zero_residue() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-pushtmp-src-{pid}"));
        let remote_root = std::env::temp_dir().join(format!("scl-pushtmp-remote-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&remote_root);
        std::fs::create_dir_all(&src_root).unwrap();

        // The "remote" is itself a full repo (push needs a repo with a valid
        // .sc/ to fast-forward-update refs into) that the pusher pushes to
        // over a plain local path — exercising `Repo::push`'s real client code.
        let remote = Repo::init(&remote_root).unwrap();
        std::fs::write(remote_root.join("seed.txt"), b"seed").unwrap();
        let seed = remote.commit("t", "seed").unwrap();
        drop(remote);

        let pusher = Repo::clone_to(&remote_root, &src_root).unwrap();
        std::fs::write(src_root.join("a.txt"), b"one").unwrap();
        let c1 = pusher.commit("t", "c1").unwrap();

        let pushed_tip = pusher.push("origin").unwrap();
        assert_eq!(pushed_tip, c1);

        // Every object the pusher sent must be present on the remote.
        let remote_reopened = Repo::open(&remote_root).unwrap();
        {
            let store_arc = remote_reopened.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(store.contains(&seed), "pre-existing remote object must still be present");
            assert!(store.contains(&c1), "pushed commit must have landed on the remote");
        }
        assert_eq!(remote_reopened.head_tip().unwrap(), Some(c1));

        assert!(
            tmp_dir_is_empty(pusher.layout()),
            "pusher's own .sc/tmp must be empty after a successful push — the guarded temp pack \
             file built via write_ids_to_temp_pack must be cleaned up, not left as residue"
        );

        drop(pusher);
        drop(remote_reopened);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&remote_root).unwrap();
    }

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
