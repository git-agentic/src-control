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
    /// at `dst`. Full (unfiltered) clone — thin wrapper over
    /// [`Repo::clone_url_filtered`] with `filter = None`, so every existing
    /// caller/behavior is unchanged (no `.sc/promisor`, no `.sc/sparse`).
    pub fn clone_url(src_url: &str, dst: impl AsRef<Path>) -> Result<Repo> {
        Self::clone_url_filtered(src_url, dst, None)
    }

    /// Clone the repo at `src_url` (local path or `ssh://…`) into a fresh repo
    /// at `dst`. Transfers objects reachable from src's branches, copies
    /// refs + HEAD, seeds `origin/*` remote-tracking refs, records
    /// `origin = src_url`, and materializes HEAD into the dst working tree.
    ///
    /// `filter`: `None` is a full clone (unchanged behavior). `Some(prefixes)`
    /// is a partial clone (P27): the transfer only pulls objects matching
    /// `prefixes` (Task 3's prefix-scoped `get_pack`), and — before the final
    /// materialize — this writes `.sc/promisor` (the durable fetch-filter
    /// marker: `origin = src_url` + `prefixes`, so `Repo::backfill` later
    /// knows where and what to widen from) AND `.sc/sparse` (the same
    /// prefixes), so the initial checkout only lays out in-filter paths.
    /// Writing `.sc/sparse` first is load-bearing, not cosmetic: the final
    /// `worktree::materialize` call below would otherwise try to read the
    /// gapped (never-transferred) out-of-filter blobs and fail with
    /// `NotFound` — the sparse spec is what tells `materialize` to skip them.
    ///
    /// On `Err`, `dst` may be left with a partially-initialized `.sc/`; the
    /// caller should remove it before retrying.
    pub fn clone_url_filtered(
        src_url: &str,
        dst: impl AsRef<Path>,
        filter: Option<&[String]>,
    ) -> Result<Repo> {
        let transport = open_transport(src_url)?;
        let remote_refs = transport.list_refs()?;
        let head_branch = transport.head_branch()?;

        let dst_repo = Repo::init(dst.as_ref())?;

        // Transfer every (in-filter, when filtered) object reachable from
        // the remote's branch tips.
        let tips: Vec<ObjectId> = remote_refs.iter().map(|(_, id)| *id).collect();
        {
            let store_arc = dst_repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            // Fresh clone dst has no local refs yet → no haves → full transfer
            // (of whatever `filter` scopes it to).
            transfer_objects(&dst_repo.layout, transport.as_ref(), &mut store, &tips, &[], filter)?;
            // Clone-specific belt-and-suspenders (P22 Task 3): the transfer
            // above already indexes every signature object it wrote via
            // `index_incoming`, but a fresh clone is a wholesale copy of the
            // whole (in-filter) reachable set — cheap and simplest to instead
            // trust a full post-copy scan of what actually landed on disk,
            // rather than depending on the transfer call site's exact
            // bookkeeping. Idempotent: `reindex` rewrites the index from
            // scratch, so running it after `index_incoming` already populated
            // entries is a no-op on top of a no-op, not a double-count.
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

        // Partial clone: persist the durable fetch-filter marker + a matching
        // sparse spec BEFORE the final materialize (see doc comment above for
        // why the ordering matters). A full clone keeps the pre-P27 behavior
        // exactly: no `.sc/promisor`, and `Sparse::default()` (full
        // materialization) rather than `dst_repo.sparse_spec()` — clone still
        // doesn't transfer a pre-existing `.sc/sparse` from the source (out
        // of P24 scope, sparse config is local like `.scignore`).
        let sparse_spec = match filter {
            Some(prefixes) => {
                let promisor = crate::promisor::Promisor::new(src_url, prefixes.to_vec());
                crate::promisor::store(&dst_repo.layout, &promisor)?;
                let sparse = crate::sparse::Sparse::new(prefixes.to_vec());
                crate::sparse::store(&dst_repo.layout, &sparse)?;
                sparse
            }
            None => crate::sparse::Sparse::default(),
        };

        // Materialize HEAD into the working tree. No identity is available at
        // clone time, so PROTECTED files are skipped (ciphertext stays in objects
        // but plaintext is not written to disk — correct for unauthorized clones).
        if let Some(head_tip) = dst_repo.head_tip()? {
            let store_arc = dst_repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let head_snap = store.get_snapshot(&head_tip)?;
            let head_root = head_snap.root;
            let head_protection = head_snap.protection;
            worktree::materialize(
                &dst_repo.layout,
                &mut store,
                head_root,
                None,
                &head_protection,
                None,
                &sparse_spec,
            )?;
        }
        Ok(dst_repo)
    }

    /// Backfill: widen a partial clone by fetching every object matching
    /// `prefixes` that the current `.sc/promisor` filter excluded, from the
    /// promisor's recorded origin. Errors if this repo is not a partial
    /// clone (`.sc/promisor` absent — nothing to backfill).
    ///
    /// `haves` is deliberately empty, not "every locally-present object id"
    /// (an earlier read of this task assumed the latter — see the P27 Task 4
    /// report for the full reasoning). `Transport::get_pack`'s `haves`
    /// contract (`build_pack_tempfile`) treats each have as a *tip*: it
    /// computes that tip's FULL unfiltered reachable set on the origin and
    /// subtracts it from the want set. A partial clone's local branch tip
    /// does NOT have a complete closure (that is the entire premise of a
    /// promisor filter), so passing it as a have would make the origin
    /// subtract objects we don't actually hold — silently returning an empty
    /// (or incomplete) pack. Passing non-snapshot ids as haves fails outright
    /// (`get_pack`'s tip walk expects `Object::Snapshot`). So this fetch
    /// conservatively re-sends the small already-present snapshot/tree
    /// metadata that the filtered want-walk touches along the way to the
    /// genuinely-new blobs — wasteful, not incorrect: `ingest_pack_file`'s
    /// underlying `put` is idempotent on content-addressed ids.
    ///
    /// `tips` (the `wants`) must be snapshot ids the ORIGIN can resolve
    /// (I2, P27 Task 4 review): `get_pack`'s tip walk runs against the
    /// origin's own object graph, so a want it has never seen is a hard
    /// error there, not an empty result. Local branch heads are the wrong
    /// source once ANY commit has been made locally after the clone (or
    /// after the last `fetch`) without being pushed — the origin has never
    /// seen that snapshot id. The out-of-filter subtree ids being backfilled
    /// are unchanged since clone time regardless (this clone never touched
    /// them), so any tip the origin is known to have already reaches them;
    /// `refs/remotes/origin/*` is exactly that — written by
    /// `clone_url_filtered` at clone time and kept current by `fetch` — so
    /// backfill uses those remote-tracking tips instead of local heads.
    pub fn backfill(&self, prefixes: &[String]) -> Result<()> {
        if prefixes.is_empty() {
            return Err(Error::InvalidArgument(
                "backfill requires at least one prefix".into(),
            ));
        }
        let mut promisor = crate::promisor::load(&self.layout)?.ok_or_else(|| {
            Error::InvalidArgument(
                "not a partial clone (.sc/promisor absent); nothing to backfill".into(),
            )
        })?;
        let transport = open_transport(&promisor.origin)?;

        let tips: Vec<ObjectId> = refs::list_remote_tips(&self.layout)?
            .into_iter()
            .filter(|(remote, _, _)| remote == "origin")
            .map(|(_, _, id)| id)
            .collect();
        if tips.is_empty() {
            return Err(Error::InvalidArgument(
                "no refs/remotes/origin/* tracking refs recorded; run `sc fetch origin` first"
                    .into(),
            ));
        }

        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            transfer_objects(&self.layout, transport.as_ref(), &mut store, &tips, &[], Some(prefixes))?;
        }

        promisor.widen(prefixes);
        crate::promisor::store(&self.layout, &promisor)?;
        Ok(())
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
            transfer_objects(&self.layout, transport.as_ref(), &mut store, &tips, &haves, None)?;
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
            // Partial-clone push (P27 Task 4): an unfiltered reachability
            // walk would descend into any gapped (never-fetched)
            // out-of-filter subtree and NotFound on the missing tree/blob
            // object. When this repo is a partial clone, walk with its
            // promisor filter instead — this sends exactly the (possibly
            // newly-committed) in-filter objects; the origin already has
            // every out-of-filter object untouched (a P24/P15 carry-by-id
            // commit never wrote to them), so a full clone of the origin
            // still sees the intact gapped subtree after the push lands.
            let promisor = self.promisor()?;
            let reachable = match &promisor {
                Some(p) => {
                    reachable::reachable_objects_filtered(
                        &mut *store,
                        &[local_tip],
                        Some(p as &dyn reachable::PrefixFilter),
                    )?
                    .included
                }
                None => reachable::reachable_objects(&mut *store, &[local_tip])?,
            };
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
    filter: Option<&[String]>,
) -> Result<()> {
    let guard = crate::transport::TempPackGuard::new(layout)?;
    {
        let mut f = std::fs::File::create(guard.path())?;
        transport.get_pack(tips, haves, filter, &mut f)?;
    }
    crate::transport::ingest_pack_file(layout, store, guard.path())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::repo::Repo;
    use crate::signatures::SigStatus;
    use crate::sync::transfer_objects;
    use scl_core::ObjectId;

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
            transfer_objects(&dst.layout, &client, &mut store, &[tip], &[], None).unwrap();
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
            transfer_objects(dst.layout(), &client, &mut store, &[c2], &[], None).unwrap();
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

    // ── P27 Task 4: `sc clone --filter` + `.sc/promisor` + `sc backfill` +
    // partial-clone push round-trip. ──

    /// Build a repo at `root` with `src/a.txt` and `docs/b.txt`, each in
    /// their own subtree, and one commit. Returns (repo, tip, docs blob id,
    /// docs subTREE id — the root's `docs` entry id, comparable without
    /// ever loading the tree itself, which is what a partial-clone
    /// verification needs since that tree may be gapped on the dst side).
    fn tmp_repo_with_src_and_docs(root: &std::path::Path) -> (Repo, ObjectId, ObjectId, ObjectId) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        let repo = Repo::init(root).unwrap();
        std::fs::write(root.join("src/a.txt"), b"src-one").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"docs-one").unwrap();
        let tip = repo.commit("t", "c1").unwrap();

        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let snap = store.get_snapshot(&tip).unwrap();
        let root_tree = store.get_tree(&snap.root).unwrap();
        let docs_tree_id = root_tree.get("docs").unwrap().id;
        let docs_tree = store.get_tree(&docs_tree_id).unwrap();
        let docs_blob_id = docs_tree.get("b.txt").unwrap().id;
        drop(store);
        (repo, tip, docs_blob_id, docs_tree_id)
    }

    #[test]
    fn partial_clone_omits_out_of_filter_objects() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-pclone-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-pclone-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);

        let (src, tip, docs_blob_id, _docs_tree_id) = tmp_repo_with_src_and_docs(&src_root);
        let src_blob_id = {
            let store_arc = src.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let snap = store.get_snapshot(&tip).unwrap();
            let root_tree = store.get_tree(&snap.root).unwrap();
            let src_tree_id = root_tree.get("src").unwrap().id;
            let src_tree = store.get_tree(&src_tree_id).unwrap();
            src_tree.get("a.txt").unwrap().id
        };

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        {
            let store_arc = dst.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(store.contains(&src_blob_id), "in-filter src/ blob must be present");
            assert!(!store.contains(&docs_blob_id), "out-of-filter docs/ blob must NOT be present");
        }

        let promisor = dst.promisor().unwrap().expect(".sc/promisor must exist after a filtered clone");
        assert_eq!(promisor.origin, src_root.to_str().unwrap());
        assert_eq!(promisor.prefixes(), &["src/".to_string()]);

        let sparse = dst.sparse_spec().unwrap();
        assert_eq!(sparse.prefixes(), &["src/".to_string()]);

        // The working tree only materialized the in-filter subtree.
        assert!(dst_root.join("src/a.txt").exists());
        assert!(!dst_root.join("docs/b.txt").exists());

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn partial_clone_commit_and_push_round_trips() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-pcpush-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-pcpush-dst-{pid}"));
        let full_root = std::env::temp_dir().join(format!("scl-pcpush-full-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        let _ = std::fs::remove_dir_all(&full_root);

        let (src, _tip, _docs_blob_id, docs_tree_id) = tmp_repo_with_src_and_docs(&src_root);
        drop(src);

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        // Edit the in-filter file and commit. The docs/ subtree is carried
        // forward by id (P27 Task 4's `graft_out_of_sparse`, built on P24/P15
        // carry-by-id discipline) without ever reading the gapped docs/
        // object — this repo's store never held (and still doesn't hold) the
        // docs/ tree or blob object at all.
        std::fs::write(dst_root.join("src/a.txt"), b"src-two").unwrap();
        let new_tip = dst.commit("t", "c2").unwrap();

        // The new snapshot's root tree must still reference the ORIGINAL
        // docs/ subtree id byte-identically — the commit never touched the
        // gap. Compared at the root-entry level only (never loading the docs
        // tree itself, which stays gapped on this partial clone).
        {
            let store_arc = dst.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let new_snap = store.get_snapshot(&new_tip).unwrap();
            let new_root_tree = store.get_tree(&new_snap.root).unwrap();
            let new_docs_entry_id = new_root_tree.get("docs").unwrap().id;
            assert_eq!(
                new_docs_entry_id, docs_tree_id,
                "the grafted docs/ entry must reference the original subtree id byte-identically"
            );
            assert!(
                !store.contains(&docs_tree_id),
                "the docs/ subtree must still be a gap after commit — carry-by-id must never \
                 have read (and thus never re-put) it"
            );
        }

        // Push back to origin — this must not NotFound on the gapped docs/
        // subtree (the P27 Task 4 push fix: a filtered reachability walk
        // when this repo is a partial clone).
        dst.push("origin").unwrap();

        // A full clone of the origin sees the src/ edit AND the intact docs/.
        let full = Repo::clone_url(src_root.to_str().unwrap(), &full_root).unwrap();
        assert_eq!(full.head_tip().unwrap(), Some(new_tip));
        assert_eq!(std::fs::read(full_root.join("src/a.txt")).unwrap(), b"src-two");
        assert_eq!(std::fs::read(full_root.join("docs/b.txt")).unwrap(), b"docs-one");

        drop(dst);
        drop(full);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
        std::fs::remove_dir_all(&full_root).unwrap();
    }

    #[test]
    fn partial_commit_preserves_out_of_filter_protected_wraps() {
        // C1 (P27 Task 4 review, Critical): a commit on a partial clone that
        // only touches in-filter paths must not strip the wrapped DEKs of
        // out-of-filter PROTECTED files — the graft carries the docs/
        // subtree forward by id, so its ciphertext blob never went through
        // the encrypt-or-carry loop that feeds `fresh_wrapped`, and the old
        // (pre-fix) `reuse_prior_wraps` rebuild silently dropped its wraps.
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-pcwrap-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-pcwrap-dst-{pid}"));
        let full_root = std::env::temp_dir().join(format!("scl-pcwrap-full-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        let _ = std::fs::remove_dir_all(&full_root);

        std::fs::create_dir_all(src_root.join("src")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("src/a.txt"), b"src-one").unwrap();
        src.protect("docs/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::write(src_root.join("docs/secret.txt"), b"docs-secret").unwrap();
        src.commit("t", "c1").unwrap();

        let docs_blob_id = {
            let store_arc = src.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let tip = src.head_tip().unwrap().unwrap();
            let snap = store.get_snapshot(&tip).unwrap();
            let root_tree = store.get_tree(&snap.root).unwrap();
            let docs_tree_id = root_tree.get("docs").unwrap().id;
            let docs_tree = store.get_tree(&docs_tree_id).unwrap();
            let id = docs_tree.get("secret.txt").unwrap().id;
            assert!(
                snap.protection.wrapped.contains_key(&id),
                "docs/secret.txt must be wrapped at the src tip"
            );
            id
        };
        drop(src);

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        std::fs::write(dst_root.join("src/a.txt"), b"src-two").unwrap();
        let new_tip = dst.commit("t", "c2").unwrap();

        {
            let store_arc = dst.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let new_snap = store.get_snapshot(&new_tip).unwrap();
            assert!(
                new_snap.protection.wrapped.contains_key(&docs_blob_id),
                "C1: new snapshot must still carry the out-of-filter docs/ ciphertext's wrapped DEK"
            );
            assert!(
                crate::protect::matching_prefix(&new_snap.protection, "docs/secret.txt").is_some(),
                "C1: the docs/ protection rule must survive a partial commit"
            );
        }

        dst.push("origin").unwrap();

        let full = Repo::clone_url(src_root.to_str().unwrap(), &full_root).unwrap();
        assert_eq!(full.head_tip().unwrap(), Some(new_tip));
        let branch = crate::refs::current_branch(full.layout()).unwrap();
        let skipped = full.switch_with_identity(&branch, Some(&alice_sk)).unwrap();
        assert!(
            skipped.is_empty(),
            "alice's identity must decrypt docs/secret.txt after push + full clone, skipped: {skipped:?}"
        );
        assert_eq!(
            std::fs::read(full_root.join("docs/secret.txt")).unwrap(),
            b"docs-secret",
            "C1: a full clone must still be able to decrypt docs/secret.txt under alice's identity"
        );

        drop(dst);
        drop(full);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
        std::fs::remove_dir_all(&full_root).unwrap();
    }

    #[test]
    fn partial_commit_refuses_content_under_gapped_path() {
        // I1 (P27 Task 4 review, Important): `read_worktree` scans the whole
        // disk tree with no regard for the sparse/filter spec, so a file
        // written under a gapped (never-fetched) subtree is picked up into
        // the built tree — the id-only graft must not silently discard it
        // by overwriting that subtree wholesale with the parent's untouched
        // id. It must refuse loudly instead.
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-gapwrite-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-gapwrite-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);

        let (src, _tip, _docs_blob_id, _docs_tree_id) = tmp_repo_with_src_and_docs(&src_root);
        drop(src);

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        // docs/ was never materialized on this partial clone (it's gapped),
        // but nothing stops a caller from writing there directly.
        std::fs::create_dir_all(dst_root.join("docs")).unwrap();
        std::fs::write(dst_root.join("docs/b.txt"), b"clobbered-by-mistake").unwrap();

        let err = dst.commit("t", "oops").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("docs") && msg.contains("backfill"),
            "I1: committing content under a gapped path must refuse clearly and point at \
             `sc backfill`, got: {msg}"
        );

        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn backfill_makes_out_of_filter_present() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-backfill-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-backfill-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);

        let (src, _tip, docs_blob_id, _docs_tree_id) = tmp_repo_with_src_and_docs(&src_root);
        drop(src);

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();
        {
            let store_arc = dst.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(!store.contains(&docs_blob_id), "docs/ must be gapped before backfill");
        }

        dst.backfill(&["docs/".to_string()]).unwrap();

        {
            let store_arc = dst.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(store.contains(&docs_blob_id), "docs/ blob must be present after backfill");
        }

        let promisor = dst.promisor().unwrap().unwrap();
        assert_eq!(promisor.prefixes(), &["src/".to_string(), "docs/".to_string()]);

        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn backfill_after_local_commit_works() {
        // I2 (P27 Task 4 review, Important): backfill's `wants` must be
        // tips the ORIGIN can resolve. A local commit made after the clone
        // (never pushed) produces a snapshot id the origin has never seen —
        // using local branch heads as `wants` (the pre-fix behavior) makes
        // `get_pack`'s tip walk fail on the origin. The out-of-filter
        // subtree being backfilled is unchanged since clone time, so any
        // tip the origin is known to have (recorded in
        // `refs/remotes/origin/*`) already reaches it.
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-backfilllocal-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-backfilllocal-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);

        let (src, _tip, docs_blob_id, _docs_tree_id) = tmp_repo_with_src_and_docs(&src_root);
        drop(src);

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        // Edit + commit locally — do NOT push. The origin has never seen
        // this new snapshot id.
        std::fs::write(dst_root.join("src/a.txt"), b"src-local-edit").unwrap();
        dst.commit("t", "local-only").unwrap();

        {
            let store_arc = dst.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(!store.contains(&docs_blob_id), "docs/ must be gapped before backfill");
        }

        dst.backfill(&["docs/".to_string()]).unwrap();

        {
            let store_arc = dst.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(
                store.contains(&docs_blob_id),
                "I2: docs/ blob must be present after backfill, even after a local unpushed commit"
            );
        }

        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn backfill_requires_at_least_one_prefix() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-backfillarity-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-backfillarity-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);

        let (src, _tip, _docs_blob_id, _docs_tree_id) = tmp_repo_with_src_and_docs(&src_root);
        drop(src);

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        let err = dst.backfill(&[]).unwrap_err();
        assert!(
            err.to_string().contains("at least one prefix"),
            "backfill with zero prefixes must error, got: {err}"
        );

        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn backfill_on_full_clone_errors() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-backfillfull-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-backfillfull-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&src_root).unwrap();

        let repo = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("a.txt"), b"one").unwrap();
        repo.commit("t", "c1").unwrap();
        drop(repo);

        let dst = Repo::clone_url(src_root.to_str().unwrap(), &dst_root).unwrap();
        assert!(dst.promisor().unwrap().is_none(), "a full clone must have no .sc/promisor");

        let err = dst.backfill(&["docs/".to_string()]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not a partial clone"),
            "backfill on a full clone must error clearly, got: {msg}"
        );

        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// Loopback `sc+http://` server standing in for `sc serve --http`
    /// (mirrors `http_transport::tests::spawn_loopback_server`, duplicated
    /// here rather than exposed `pub(crate)` across modules for one test).
    fn spawn_backfill_http_server(
        root: std::path::PathBuf,
    ) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || loop {
            let (sock, _addr) = match listener.accept() {
                Ok(x) => x,
                Err(_) => return,
            };
            let mut reader = std::io::BufReader::new(sock.try_clone().unwrap());
            let mut sock = sock;
            let _target = match crate::http_transport::read_client_opening(&mut reader) {
                Ok(t) => t,
                Err(_) => return,
            };
            crate::http_transport::write_status(&mut sock, 200).unwrap();
            if crate::wire::serve(&root, &mut reader, &mut sock).is_err() {
                return;
            }
        });
        (port, handle)
    }

    /// Partial clone + backfill driven over the real `sc+http://` loopback
    /// transport (P26), not just a local path — proves Task 3's filtered
    /// `get_pack` and this task's `.sc/promisor`/backfill wiring both work
    /// over the wire, not only `LocalTransport`.
    #[test]
    fn partial_clone_and_backfill_over_http_loopback() {
        let pid = std::process::id();
        let src_root = std::env::temp_dir().join(format!("scl-pclonehttp-src-{pid}"));
        let dst_root = std::env::temp_dir().join(format!("scl-pclonehttp-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);

        let (src, _tip, docs_blob_id, _docs_tree_id) = tmp_repo_with_src_and_docs(&src_root);

        let (port, server) = spawn_backfill_http_server(src_root.clone());
        let url = format!("sc+http://127.0.0.1:{port}/repo");

        let dst = Repo::clone_url_filtered(&url, &dst_root, Some(&["src/".to_string()])).unwrap();
        {
            let store_arc = dst.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(!store.contains(&docs_blob_id), "docs/ must be gapped over http too");
        }

        dst.backfill(&["docs/".to_string()]).unwrap();
        {
            let store_arc = dst.vfs().store();
            let store = store_arc.lock().unwrap();
            assert!(store.contains(&docs_blob_id), "docs/ must be backfilled over http too");
        }

        drop(dst);
        drop(src);
        // The loopback server loops accepting connections until one of the
        // per-connection calls errors (e.g. EOF on shutdown) — dropping the
        // repos above doesn't stop it, so just detach rather than join.
        drop(server);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }
}
