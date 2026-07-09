//! Snapshot signatures (P22 provenance): the repo-side `.sc/signatures`
//! index over core's [`scl_core::SignatureObj`] and four-state verification.
//!
//! `crates/core` stays crypto-free — `SignatureObj` is raw bytes. This module
//! owns the only place `scl_core::Object::Signature` meets `scl_crypto`:
//! producing a signature (`sign_snapshot`), storing it in the CAS, indexing
//! it, and verifying it (`sig_status`).
//!
//! Index file `.sc/signatures`: append-only, one `<snapshot-hex>
//! <sig-object-hex>` line per indexed signature. Multiple signers can each
//! index their own signature over the same snapshot (multiple lines sharing
//! a snapshot hex). Appends dedup (a signer signing the same snapshot twice
//! is a no-op, both because the object id is identical — Ed25519 signing is
//! deterministic — and because the index line would be identical). `gc`
//! rewrites the file atomically when it prunes dead entries; every other
//! writer treats the file as append-only.

use std::collections::BTreeSet;

use scl_core::{Object, ObjectId, SignatureObj};

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::repo::Repo;

/// Verification status of one snapshot's signatures against a trust map.
///
/// Precedence (checked in this order, and never masked by a "better"
/// outcome found later): any signature that fails to verify (corrupt bytes,
/// wrong key, tampered snapshot id) makes the whole snapshot `Invalid` —
/// even if another signature on the same snapshot is both valid and
/// trusted. Only once every indexed signature verifies do we look at trust:
/// any signer in the trust map makes it `Trusted`; otherwise, having at
/// least one valid signature from an unrecognized signer makes it
/// `Untrusted`; no indexed signatures at all makes it `Unsigned`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SigStatus {
    Trusted(String),
    Untrusted([u8; 32]),
    Invalid,
    Unsigned,
}

/// Parse one `<snapshot-hex> <sig-hex>` index line. Returns `None` for a
/// malformed line (wrong field count or bad hex) rather than erroring — the
/// index is a best-effort cache, not the source of truth (the CAS objects
/// are), so a corrupt line is skipped, not fatal.
fn parse_line(line: &str) -> Option<(ObjectId, ObjectId)> {
    let mut parts = line.split_whitespace();
    let snap = parts.next()?.parse::<ObjectId>().ok()?;
    let sig = parts.next()?.parse::<ObjectId>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((snap, sig))
}

fn read_index(layout: &Layout) -> Result<Vec<(ObjectId, ObjectId)>> {
    let path = layout.signatures_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    Ok(contents.lines().filter_map(parse_line).collect())
}

/// Rewrite the whole index file atomically (temp file + rename), so a
/// concurrent reader never observes a half-written index.
fn write_index(layout: &Layout, entries: &[(ObjectId, ObjectId)]) -> Result<()> {
    let mut out = String::new();
    for (snap, sig) in entries {
        out.push_str(&format!("{} {}\n", snap.to_hex(), sig.to_hex()));
    }
    scl_core::fsutil::atomic_write_durable(&layout.signatures_path(), out.as_bytes())?;
    Ok(())
}

/// Append one `(snapshot, sig_id)` entry, deduping against an identical
/// existing entry.
pub(crate) fn append_index(layout: &Layout, snapshot: ObjectId, sig_id: ObjectId) -> Result<()> {
    let mut entries = read_index(layout)?;
    if entries.iter().any(|(s, g)| *s == snapshot && *g == sig_id) {
        return Ok(());
    }
    entries.push((snapshot, sig_id));
    write_index(layout, &entries)
}

/// gc integration: given the reachable object set already computed by
/// `gc::run` (after roots + the merge/pick/rebase decided-root walks, before
/// packing), keep only index entries whose snapshot is still reachable, root
/// each surviving entry's signature object into `reachable` (so the repack
/// keeps it and the loose-object sweep never treats it as dangling), and
/// atomically rewrite the index to drop the rest. Dead signature objects are
/// deliberately NOT rooted here — they fall out of `reachable` and are swept
/// by the same loose-object aging/pruning `gc::run` already applies to every
/// other unreachable object, so a dead entry's signature object is pruned on
/// the same grace-window schedule as anything else.
///
/// Returns the number of dropped entries (0 when nothing needed pruning, in
/// which case the index file is left untouched rather than rewritten).
pub(crate) fn gc_prune(layout: &Layout, reachable: &mut BTreeSet<ObjectId>) -> Result<usize> {
    let entries = read_index(layout)?;
    if entries.is_empty() {
        return Ok(0);
    }
    let mut kept = Vec::with_capacity(entries.len());
    for (snap, sig_id) in &entries {
        if reachable.contains(snap) {
            reachable.insert(*sig_id);
            kept.push((*snap, *sig_id));
        }
    }
    let dropped = entries.len() - kept.len();
    if dropped > 0 {
        write_index(layout, &kept)?;
    }
    Ok(dropped)
}

/// Receiver-side seam (Task 3): given a batch of object ids just written to
/// the local store (e.g. by a pull/fetch/clone transfer), detect which of
/// them are `TAG_SIGNATURE` objects and index them. Returns how many were
/// indexed.
///
/// # `NotFound` is a hard error here
///
/// Every caller of this function (`LocalTransport::put_pack`,
/// `sync::transfer_objects`) passes ids it *just wrote* to `store` in the
/// same call — "ids just written" is this seam's contract, not "ids that
/// might exist". A `NotFound` therefore means the caller passed an id that
/// was never actually stored: a genuine bug (e.g. a future caller reusing
/// this function with a stale/unrelated id list), not a benign gap. An
/// earlier draft silently skipped `NotFound` as "not our concern here";
/// that would mask exactly this class of bug at the seam meant to catch it,
/// so it now propagates like any other store error. Callers with a looser
/// contract (ids that may or may not resolve) should filter before calling,
/// not rely on this function to do it silently.
pub(crate) fn index_incoming(
    layout: &Layout,
    store: &mut scl_core::Store,
    ids: &[ObjectId],
) -> Result<usize> {
    let mut count = 0;
    for id in ids {
        match store.get(id)? {
            Object::Signature(sig) => {
                append_index(layout, sig.snapshot, *id)?;
                count += 1;
            }
            _ => {}
        }
    }
    Ok(count)
}

/// Full-store rebuild of the signature index (Task 3): scan every object the
/// store can resolve (loose + packed — `Store::all_ids`, not a reachability
/// walk, since a `SignatureObj` is a leaf no tree/snapshot references), keep
/// the ones that are `Object::Signature` whose `snapshot` also resolves
/// locally, and atomically rewrite the index to exactly that set (not an
/// append — stale entries from a half-written prior index are dropped too).
///
/// Used by the local clone path: clone's initial transfer is a wholesale
/// copy of every object the sender's `get_pack` chose to include (which, via
/// the sender seam below, already includes every indexed signature for the
/// cloned snapshots). Rebuilding by scanning the freshly-copied store is
/// simpler and no less correct than threading the transfer's exact id list
/// through to `index_incoming` — it doesn't depend on the transfer call site
/// bookkeeping the right ids, only on the objects actually landing on disk.
/// O(store), which is fine for a one-shot clone of a store that size.
pub(crate) fn reindex(layout: &Layout, store: &mut scl_core::Store) -> Result<usize> {
    let mut entries: Vec<(ObjectId, ObjectId)> = Vec::new();
    for id in store.all_ids()? {
        if let Object::Signature(sig) = store.get(&id)? {
            if store.contains(&sig.snapshot) {
                entries.push((sig.snapshot, id));
            }
        }
    }
    entries.sort();
    entries.dedup();
    let count = entries.len();
    write_index(layout, &entries)?;
    Ok(count)
}

/// Sender-side seam (Task 3): the indexed signature object ids covering any
/// of `snapshots`, deduped and sorted — the set a push/export needs to
/// carry alongside the snapshots themselves so the receiving repo's index
/// stays complete.
pub(crate) fn indexed_signature_ids_for(
    layout: &Layout,
    snapshots: &[ObjectId],
) -> Result<Vec<ObjectId>> {
    let wanted: BTreeSet<ObjectId> = snapshots.iter().copied().collect();
    let mut out: BTreeSet<ObjectId> = BTreeSet::new();
    for (snap, sig_id) in read_index(layout)? {
        if wanted.contains(&snap) {
            out.insert(sig_id);
        }
    }
    Ok(out.into_iter().collect())
}

/// Shared four-state precedence over an already-loaded signature list,
/// parameterized on `verify` so both [`Repo::sig_status`] (snapshot domain)
/// and `Repo::transcript_sig_status` (transcript domain, in
/// `transcripts.rs`) apply the identical precedence rule without
/// duplicating it. See [`SigStatus`] for the precedence itself.
pub(crate) fn status_from(
    sigs: &[SignatureObj],
    target: &ObjectId,
    trusted: &std::collections::HashMap<[u8; 32], String>,
    verify: impl Fn(&[u8; 32], &[u8; 32], &[u8; 64]) -> bool,
) -> SigStatus {
    if sigs.is_empty() {
        return SigStatus::Unsigned;
    }
    let mut trusted_name: Option<String> = None;
    let mut untrusted_signer: Option<[u8; 32]> = None;
    for s in sigs {
        let valid = verify(&s.signer, target.as_bytes(), &s.sig);
        if !valid {
            // Precedence: any invalid signature wins immediately, never
            // masked by a valid/trusted one found earlier or later.
            return SigStatus::Invalid;
        }
        match trusted.get(&s.signer) {
            Some(name) if trusted_name.is_none() => trusted_name = Some(name.clone()),
            None if untrusted_signer.is_none() => untrusted_signer = Some(s.signer),
            _ => {}
        }
    }
    if let Some(name) = trusted_name {
        return SigStatus::Trusted(name);
    }
    if let Some(signer) = untrusted_signer {
        return SigStatus::Untrusted(signer);
    }
    unreachable!("sigs is non-empty and every signature is valid, so one of the two branches above must have set a value")
}

impl Repo {
    /// Sign `snapshot` with `identity`'s signing half: build the
    /// [`SignatureObj`], put it in the CAS, and append it to the
    /// `.sc/signatures` index. Idempotent — Ed25519 signing is
    /// deterministic, so the same signer signing the same snapshot twice
    /// produces byte-identical `SignatureObj` content, hence the same
    /// content-addressed object id, hence `put` is a no-op dedup and
    /// `append_index` skips the duplicate line.
    ///
    /// Errors with [`Error::InvalidArgument`] if `identity` is a v1
    /// (encryption-only) identity with no signing half.
    ///
    /// Deliberately carries none of the merge/pick/rebase in-progress
    /// guards `commit`/`secret_add`/etc. use: those guards protect operations
    /// that create commits or move branch refs, so a stopped merge/pick/
    /// rebase has a pending ref move that a naive concurrent op could
    /// clobber. Signing writes neither — one CAS `put` plus an index
    /// append — so there is no ref state for it to race with or corrupt.
    pub fn sign_snapshot(&self, snapshot: ObjectId, identity: &scl_crypto::Identity) -> Result<ObjectId> {
        let signing = identity.signing.as_ref().ok_or_else(|| {
            Error::InvalidArgument(
                "identity has no signing half (v1 identity); signing requires a v2 (scl-id-) \
                 identity"
                    .into(),
            )
        })?;
        let signer = signing.public().to_bytes();
        let sig = scl_crypto::sign_snapshot_id(signing, snapshot.as_bytes());
        let sig_obj = SignatureObj { snapshot, signer, sig };
        let id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Signature(sig_obj))?;
            i
        };
        append_index(self.layout(), snapshot, id)?;
        Ok(id)
    }

    /// All indexed signatures for `snapshot`, loaded from the CAS.
    pub fn signatures_for(&self, snapshot: &ObjectId) -> Result<Vec<SignatureObj>> {
        let entries = read_index(self.layout())?;
        let arc = self.store_arc();
        let mut store = arc.lock().unwrap();
        let mut out = Vec::new();
        for (snap, sig_id) in entries {
            if snap != *snapshot {
                continue;
            }
            match store.get(&sig_id)? {
                Object::Signature(s) => out.push(s),
                _ => {
                    return Err(Error::InvalidArgument(format!(
                        "signature index entry {sig_id} does not resolve to a signature object"
                    )))
                }
            }
        }
        Ok(out)
    }

    /// Verification status of `snapshot` against `trusted` (signer pubkey
    /// bytes -> display name). See [`SigStatus`] for the precedence rule.
    pub fn sig_status(
        &self,
        snapshot: &ObjectId,
        trusted: &std::collections::HashMap<[u8; 32], String>,
    ) -> Result<SigStatus> {
        let sigs = self.signatures_for(snapshot)?;
        Ok(status_from(&sigs, snapshot, trusted, scl_crypto::verify_snapshot_sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-sig-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn sign_is_idempotent_and_indexed() {
        let root = tmp_root("idem");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, identity) = scl_crypto::generate_identity_v2();

        let sig_id1 = repo.sign_snapshot(snap, &identity).unwrap();
        let sig_id2 = repo.sign_snapshot(snap, &identity).unwrap();
        assert_eq!(sig_id1, sig_id2, "same signer+snapshot must yield the same object id");

        let sigs = repo.signatures_for(&snap).unwrap();
        assert_eq!(sigs.len(), 1, "idempotent sign must leave a single index entry, not two");
        assert_eq!(sigs[0].snapshot, snap);
        assert_eq!(sigs[0].signer, identity.signing.as_ref().unwrap().public().to_bytes());

        // The index file itself has exactly one line for this snapshot.
        let raw = std::fs::read_to_string(repo.layout().signatures_path()).unwrap();
        assert_eq!(raw.lines().count(), 1, "index must dedup the repeated sign, got: {raw:?}");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sign_errors_on_v1_identity() {
        let root = tmp_root("v1");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();

        let (sk, _pk) = scl_crypto::generate_keypair();
        let identity = scl_crypto::Identity { enc: sk, signing: None };
        let err = repo.sign_snapshot(snap, &identity).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

        assert!(repo.signatures_for(&snap).unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sig_status_four_states() {
        let root = tmp_root("four-states");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();

        // Unsigned: no indexed signatures at all.
        assert_eq!(repo.sig_status(&snap, &HashMap::new()).unwrap(), SigStatus::Unsigned);

        // Untrusted: a valid signature from a signer not in the trust map.
        let (_s1, id1) = scl_crypto::generate_identity_v2();
        repo.sign_snapshot(snap, &id1).unwrap();
        let signer1 = id1.signing.as_ref().unwrap().public().to_bytes();
        assert_eq!(
            repo.sig_status(&snap, &HashMap::new()).unwrap(),
            SigStatus::Untrusted(signer1)
        );

        // Trusted: same signature, now the signer is in the trust map.
        let mut trust = HashMap::new();
        trust.insert(signer1, "alice".to_string());
        assert_eq!(
            repo.sig_status(&snap, &trust).unwrap(),
            SigStatus::Trusted("alice".to_string())
        );

        // Invalid: hand-construct a second, corrupted signature object and
        // index it directly (bypassing `sign_snapshot`, which can only ever
        // produce a valid signature) to prove precedence — Invalid must win
        // EVEN THOUGH the first (trusted, valid) signature is still indexed.
        let bad_sig_obj = scl_core::SignatureObj {
            snapshot: snap,
            signer: [7u8; 32], // not a valid Ed25519 point either, but that's fine: verify_snapshot_sig returns false, not a panic
            sig: [9u8; 64],
        };
        let bad_id = {
            let arc = repo.store();
            let i = arc.lock().unwrap().put(scl_core::Object::Signature(bad_sig_obj)).unwrap();
            i
        };
        // Append directly to the index (simulating a second signer / a
        // replicated signature) rather than going through `sign_snapshot`.
        {
            let raw = std::fs::read_to_string(repo.layout().signatures_path()).unwrap();
            let extra = format!("{} {}\n", snap.to_hex(), bad_id.to_hex());
            std::fs::write(repo.layout().signatures_path(), raw + &extra).unwrap();
        }
        assert_eq!(
            repo.sig_status(&snap, &trust).unwrap(),
            SigStatus::Invalid,
            "an invalid signature must win over an existing valid+trusted one"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_prunes_signatures_of_dead_snapshots_keeps_live() {
        let root = tmp_root("gc");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base").unwrap();
        let live = repo.commit("t", "c1").unwrap();

        // A second, orphaned snapshot: commit it, then rewind the branch tip
        // directly (bypassing undo/oplog, mirroring gc.rs's own
        // `gc_trims_old_oplog_records_and_releases_roots` idiom) so it is
        // reachable from no ref. `trim_older_than` always keeps the NEWEST
        // oplog record regardless of cutoff, so a third commit is needed to
        // push a newer record ahead of `dead`'s — otherwise `dead`'s own
        // commit record would be "the newest" and survive the trim below,
        // keeping `dead` alive as an oplog root and defeating the test.
        std::fs::write(root.join("a.txt"), b"dead").unwrap();
        let dead = repo.commit("t", "c2").unwrap();
        crate::refs::write_branch_tip(repo.layout(), "main", &live).unwrap();
        std::fs::write(root.join("a.txt"), b"fresh").unwrap();
        repo.commit("t", "c3").unwrap();
        crate::refs::write_branch_tip(repo.layout(), "main", &live).unwrap();

        let (_s, identity) = scl_crypto::generate_identity_v2();
        let live_sig_id = repo.sign_snapshot(live, &identity).unwrap();
        let dead_sig_id = repo.sign_snapshot(dead, &identity).unwrap();

        // Trim every record except the newest (c3's), releasing `dead` as an
        // oplog root — its signature's only remaining claim to life is the
        // (now stale) index entry, exactly what this test exercises.
        crate::oplog::trim_older_than(repo.layout(), i64::MAX).unwrap();

        repo.gc(Duration::from_secs(0)).unwrap();

        // Live snapshot's signature survives: index entry and CAS object.
        let live_sigs = repo.signatures_for(&live).unwrap();
        assert_eq!(live_sigs.len(), 1);
        assert!(repo.store().lock().unwrap().contains(&live_sig_id));

        // Dead snapshot's signature is gone: index entry dropped, CAS
        // object pruned.
        assert!(repo.signatures_for(&dead).unwrap().is_empty(), "dead entry must be dropped from the index");
        assert!(
            !repo.store().lock().unwrap().contains(&dead_sig_id),
            "dead signature object must be pruned"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn index_incoming_indexes_signatures_and_ignores_other_kinds() {
        let root = tmp_root("incoming-ok");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, identity) = scl_crypto::generate_identity_v2();

        // Build a signature object without going through `sign_snapshot` (so
        // it is NOT yet indexed), plus an ordinary blob id, and hand both to
        // `index_incoming` as "just written" — mirroring what a real
        // transfer seam passes (a mixed batch of every object kind).
        let signing = identity.signing.as_ref().unwrap();
        let sig = scl_crypto::sign_snapshot_id(signing, snap.as_bytes());
        let sig_obj = SignatureObj { snapshot: snap, signer: signing.public().to_bytes(), sig };
        let (sig_id, blob_id) = {
            let arc = repo.store();
            let mut s = arc.lock().unwrap();
            let sig_id = s.put(Object::Signature(sig_obj)).unwrap();
            let blob_id = s.put(Object::blob(b"not a signature".to_vec())).unwrap();
            (sig_id, blob_id)
        };
        assert!(repo.signatures_for(&snap).unwrap().is_empty(), "not indexed yet");

        let count = {
            let arc = repo.store();
            let mut s = arc.lock().unwrap();
            index_incoming(repo.layout(), &mut s, &[sig_id, blob_id]).unwrap()
        };
        assert_eq!(count, 1, "only the signature object counts, the blob is skipped silently");
        assert_eq!(repo.signatures_for(&snap).unwrap().len(), 1);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn index_incoming_errors_on_notfound_id_rather_than_skipping() {
        // The seam's contract is "ids just written" — a NotFound id means the
        // caller broke that contract, which must surface as a hard error, not
        // be silently swallowed (see the doc comment on `index_incoming`).
        let root = tmp_root("incoming-notfound");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("t", "c1").unwrap();

        let phantom = ObjectId::of(b"never actually stored");
        let err = {
            let arc = repo.store();
            let mut s = arc.lock().unwrap();
            index_incoming(repo.layout(), &mut s, &[phantom]).unwrap_err()
        };
        assert!(
            matches!(err, Error::Core(scl_core::Error::NotFound(id)) if id == phantom),
            "got {err:?}"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn reindex_rebuilds_from_a_full_store_scan() {
        let root = tmp_root("reindex");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, identity) = scl_crypto::generate_identity_v2();
        let sig_id = repo.sign_snapshot(snap, &identity).unwrap();

        // Simulate "clone landed the objects but the index file never made
        // the trip" (e.g. it lives outside the CAS on purpose): wipe the
        // index file, then reindex from the store contents alone.
        std::fs::remove_file(repo.layout().signatures_path()).unwrap();
        assert!(repo.signatures_for(&snap).unwrap().is_empty(), "index wiped");

        let count = {
            let arc = repo.store();
            let mut s = arc.lock().unwrap();
            reindex(repo.layout(), &mut s).unwrap()
        };
        assert_eq!(count, 1);
        let sigs = repo.signatures_for(&snap).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].snapshot, snap);
        assert!(repo.store().lock().unwrap().contains(&sig_id));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn reindex_drops_entries_whose_snapshot_is_gone() {
        // A signature object can outlive its snapshot in the store transiently
        // (e.g. mid-transfer); reindex must not manufacture an index entry for
        // a snapshot the local store cannot resolve.
        let root = tmp_root("reindex-orphan");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, identity) = scl_crypto::generate_identity_v2();
        repo.sign_snapshot(snap, &identity).unwrap();

        let phantom_snap = ObjectId::of(b"a snapshot id nobody stored");
        let signing = identity.signing.as_ref().unwrap();
        let orphan_sig = scl_crypto::sign_snapshot_id(signing, phantom_snap.as_bytes());
        let orphan_obj =
            SignatureObj { snapshot: phantom_snap, signer: signing.public().to_bytes(), sig: orphan_sig };
        {
            let arc = repo.store();
            let mut s = arc.lock().unwrap();
            s.put(Object::Signature(orphan_obj)).unwrap();
        }

        let count = {
            let arc = repo.store();
            let mut s = arc.lock().unwrap();
            reindex(repo.layout(), &mut s).unwrap()
        };
        assert_eq!(count, 1, "only the real snapshot's signature is kept");
        assert!(repo.signatures_for(&snap).unwrap().len() == 1);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
