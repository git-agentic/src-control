//! Session transcripts (P30 provenance): the repo-side `.sc/transcripts`
//! index over core's bytes-only [`scl_core::Transcript`], plus sealing and
//! attachment.
//!
//! `crates/core` stays crypto-free — a `Transcript` is raw bytes. This
//! module is the only place it meets `scl_crypto`: sealing the body via
//! `scl_crypto::seal` (plaintext never enters the CAS — only the sealed
//! ciphertext is stored), storing the result, and indexing it.
//!
//! Index file `.sc/transcripts`: append-only, one `<snapshot-hex>
//! <transcript-object-hex>` line per attachment. One-to-many — a single
//! snapshot can have any number of attached transcripts (e.g. multiple
//! agents, multiple sessions, a re-attach after editing the body).
//! Identical re-attaches dedup, both because sealing is otherwise
//! nondeterministic per-call (fresh nonce) — an actual duplicate line only
//! occurs if the exact same object id is appended twice — and because
//! `append_index` itself dedups by `(snapshot, transcript)` pair regardless.
//! `gc` rewrites the file atomically when it prunes dead entries; every
//! other writer treats the file as append-only. Mirrors `signatures.rs`'s
//! index discipline verbatim.
//!
//! Drops (ADR-0038 addendum): a second file `.sc/transcript-drops` holds one
//! `<snapshot-hex> <tombstone-hex> <dropped-hex>` line per drop tombstone (a
//! bare `Transcript`, see `Transcript::drop_tombstone`). The grow-only set of
//! dropped ids filters every read of the live index, so a dropped transcript
//! stays invisible whatever order its lines and objects arrive in.

use std::collections::BTreeSet;

use scl_core::{Object, ObjectId, Secret, SignatureObj, Transcript};

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lock::with_index_lock;
use crate::repo::Repo;
use crate::signatures::SigStatus;

/// Parse one `<snapshot-hex> <transcript-hex>` index line. Returns `None`
/// for a malformed line (wrong field count or bad hex) rather than erroring
/// — the index is a best-effort cache, not the source of truth (the CAS
/// objects are), so a corrupt line is skipped, not fatal.
fn parse_line(line: &str) -> Option<(ObjectId, ObjectId)> {
    let mut parts = line.split_whitespace();
    let snap = parts.next()?.parse::<ObjectId>().ok()?;
    let tid = parts.next()?.parse::<ObjectId>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((snap, tid))
}

/// The live index file as written, including entries a tombstone has since
/// hidden (gc purges those).
fn read_raw(layout: &Layout) -> Result<Vec<(ObjectId, ObjectId)>> {
    let path = layout.transcripts_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    Ok(contents.lines().filter_map(parse_line).collect())
}

/// The live index minus every dropped transcript.
fn read_index(layout: &Layout) -> Result<Vec<(ObjectId, ObjectId)>> {
    let dropped = dropped_ids(layout)?;
    Ok(read_raw(layout)?
        .into_iter()
        .filter(|(_, tid)| !dropped.contains(tid))
        .collect())
}

/// One drop-tombstone line: `(snapshot, tombstone object, dropped transcript)`.
type DropEntry = (ObjectId, ObjectId, ObjectId);

fn read_drops(layout: &Layout) -> Result<Vec<DropEntry>> {
    let contents = match std::fs::read_to_string(layout.transcript_drops_path()) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    Ok(contents
        .lines()
        .filter_map(|line| {
            let mut p = line.split_whitespace().map(|f| f.parse::<ObjectId>().ok());
            let e = (p.next()??, p.next()??, p.next()??);
            p.next().is_none().then_some(e)
        })
        .collect())
}

fn write_drops(layout: &Layout, entries: &[DropEntry]) -> Result<()> {
    let mut out = String::new();
    for (snap, tomb, dropped) in entries {
        out.push_str(&format!(
            "{} {} {}\n",
            snap.to_hex(),
            tomb.to_hex(),
            dropped.to_hex()
        ));
    }
    scl_core::fsutil::atomic_write_durable(&layout.transcript_drops_path(), out.as_bytes())?;
    Ok(())
}

fn dropped_ids(layout: &Layout) -> Result<BTreeSet<ObjectId>> {
    Ok(read_drops(layout)?.into_iter().map(|(_, _, d)| d).collect())
}

/// Record one tombstone, deduping an identical existing line. The line is
/// appended (one short `O_APPEND` write; atomic on a local filesystem only, NFS
/// gives no such guarantee), not
/// merged into a rewrite of the file, so concurrent ingests (the HTTP serve
/// path holds no repo lock) cannot lose each other's drop line. A racing
/// duplicate line is harmless: readers treat the file as a set.
fn append_drop(layout: &Layout, entry: DropEntry) -> Result<()> {
    // Under the index lock only so `reindex`'s whole-file rewrite cannot drop
    // a line appended meanwhile.
    with_index_lock(layout, || append_drop_locked(layout, entry))
}

fn append_drop_locked(layout: &Layout, entry: DropEntry) -> Result<()> {
    use std::io::Write;
    if read_drops(layout)?.contains(&entry) {
        return Ok(());
    }
    let path = layout.transcript_drops_path();
    let is_new = !path.exists();
    // A crash or ENOSPC mid-write can leave a line without its newline; start
    // on a fresh line so this one is not merged into the torn tail.
    let torn = std::fs::read(&path).is_ok_and(|b| b.last().is_some_and(|c| *c != b'\n'));
    let line = format!(
        "{}{} {} {}\n",
        if torn { "\n" } else { "" },
        entry.0.to_hex(),
        entry.1.to_hex(),
        entry.2.to_hex()
    );
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    if is_new {
        // Make the new directory entry durable too.
        scl_core::fsutil::fsync_dir(&layout.dot_sc)?;
    }
    Ok(())
}

/// Most held-but-unhonored tombstones remembered (#230). A peer can push
/// arbitrarily many, so the set is a FIFO ring: the newest win, and an evicted
/// one is only lost to a push-only remote (a fetching peer is re-sent every
/// retained tombstone on each fetch).
const MAX_PENDING: usize = 1024;

/// Distinct signature targets `index_incoming` looks up per batch.
const MAX_SIG_LOOKUPS: usize = 1024;

/// A missing file is empty; any other read failure is an error, so gc never
/// treats an unreadable pending list as empty and sweeps what it roots.
fn read_pending(layout: &Layout) -> Result<Vec<ObjectId>> {
    match std::fs::read_to_string(layout.transcript_pending_path()) {
        Ok(s) => Ok(s.lines().filter_map(|l| l.trim().parse().ok()).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Error::Io(e)),
    }
}

fn write_pending(layout: &Layout, ids: &[ObjectId]) -> Result<()> {
    let path = layout.transcript_pending_path();
    if ids.is_empty() {
        for p in [&path, &layout.transcript_pending_trust_path()] {
            match std::fs::remove_file(p) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Error::Io(e)),
                _ => {}
            }
        }
        return Ok(());
    }
    let out: String = ids.iter().map(|i| format!("{}\n", i.to_hex())).collect();
    scl_core::fsutil::atomic_write_durable(&path, out.as_bytes())?;
    Ok(())
}

/// Remember `new` tombstones for re-evaluation, deduped, newest last, capped
/// at [`MAX_PENDING`]. Writes only when the set changes. `fp` is the trusted
/// set they were just judged under.
fn note_pending(layout: &Layout, new: &[ObjectId], fp: &str) -> Result<()> {
    if new.is_empty() {
        return Ok(());
    }
    // Dedupe the batch (order kept), then only its newest MAX_PENDING can
    // survive.
    let mut once = BTreeSet::new();
    let new: Vec<ObjectId> = new.iter().copied().filter(|i| once.insert(*i)).collect();
    let new = &new[new.len().saturating_sub(MAX_PENDING)..];
    with_index_lock(layout, || {
        let mut all = read_pending(layout)?;
        let mut seen: BTreeSet<ObjectId> = all.iter().copied().collect();
        let mut added = false;
        for id in new {
            if seen.insert(*id) {
                all.push(*id);
                added = true;
            }
        }
        if !added {
            return Ok(());
        }
        let excess = all.len().saturating_sub(MAX_PENDING);
        all.drain(..excess);
        write_pending(layout, &all)?;
        // Entries are judged under the trust in force now; remember which.
        if read_trust_state(layout).is_none() {
            save_trust_state(layout, fp, 0)?;
        }
        Ok(())
    })
}

type Trusted = std::collections::HashMap<[u8; 32], String>;

/// Failed passes (an object would not read) after which the same trusted set
/// is not retried again, so an unreadable object cannot make every open or
/// served connection take the exclusive lock forever. A changed set retries.
const MAX_RETRIES: u32 = 3;

/// Fingerprint of the trusted-signer key set (the only configuration the
/// honoring check reads), so an unrelated edit to `recipients.toml` does not
/// count as a trust change. Computed from the same map used for judging, so
/// the value saved is the set the entries were judged under.
fn fp_of(trusted: &Trusted) -> String {
    let mut keys: Vec<&[u8; 32]> = trusted.keys().collect();
    keys.sort();
    let mut h = blake3::Hasher::new();
    for k in keys {
        h.update(k.as_slice());
    }
    h.finalize().to_hex().to_string()
}

/// `.sc/transcript-pending-trust`: `<fingerprint> <failed passes>`.
fn read_trust_state(layout: &Layout) -> Option<(String, u32)> {
    let s = std::fs::read_to_string(layout.transcript_pending_trust_path()).ok()?;
    let mut it = s.split_whitespace();
    let fp = it.next()?.to_string();
    Some((fp, it.next().and_then(|n| n.parse().ok()).unwrap_or(0)))
}

fn save_trust_state(layout: &Layout, fp: &str, failed: u32) -> Result<()> {
    scl_core::fsutil::atomic_write_durable(
        &layout.transcript_pending_trust_path(),
        format!("{fp} {failed}").as_bytes(),
    )?;
    Ok(())
}

/// Pending tombstones exist and were last judged under another trusted set,
/// or a pass failed and retries remain.
fn needs_judging(layout: &Layout, fp: &str) -> bool {
    layout.transcript_pending_path().exists()
        && match read_trust_state(layout) {
            None => true,
            Some((saved, failed)) => saved != fp || (failed > 0 && failed < MAX_RETRIES),
        }
}

/// Whether [`reevaluate_if_trust_changed`] has work. One `exists` check when
/// nothing is pending; no lock and no store access, so a server can call it
/// per connection.
pub(crate) fn trust_changed(layout: &Layout) -> bool {
    layout.transcript_pending_path().exists()
        && needs_judging(layout, &fp_of(&trusted_signers(layout)))
}

/// Judge the pending tombstones again when [`trust_changed`], then record the
/// trust they were judged under. The re-check triggers (open, transport open,
/// ingest) all go through here so none of them does work or takes a lock
/// while the trust is unchanged. An entry that could not be read keeps the
/// pass "failed" (up to [`MAX_RETRIES`] times per trusted set) instead of
/// advancing the fingerprint, so repairing the object lets a later trigger
/// try again.
pub(crate) fn reevaluate_if_trust_changed(
    layout: &Layout,
    store: &mut scl_core::Store,
) -> Result<usize> {
    let trusted = trusted_signers(layout);
    let fp = fp_of(&trusted);
    if !needs_judging(layout, &fp) || crate::signatures::migration_pending(layout) {
        return Ok(0);
    }
    // The pass rewrites the pending list, so it runs under the index lock.
    // Judged again inside it: a racing pass may have just finished the work.
    with_index_lock(layout, || {
        if !needs_judging(layout, &fp) {
            return Ok(0);
        }
        let (honored, incomplete) = reevaluate_inner(layout, store, &trusted)?;
        let failed = match (incomplete, read_trust_state(layout)) {
            (false, _) => 0,
            (true, Some((saved, n))) if saved == fp => n + 1,
            (true, _) => 1,
        };
        save_trust_state(layout, &fp, failed)?;
        Ok(honored)
    })
}

/// Rewrite the whole index file atomically (temp file + rename), so a
/// concurrent reader never observes a half-written index.
fn write_index(layout: &Layout, entries: &[(ObjectId, ObjectId)]) -> Result<()> {
    let mut out = String::new();
    for (snap, tid) in entries {
        out.push_str(&format!("{} {}\n", snap.to_hex(), tid.to_hex()));
    }
    scl_core::fsutil::atomic_write_durable(&layout.transcripts_path(), out.as_bytes())?;
    Ok(())
}

/// Append one `(snapshot, transcript_id)` entry, deduping against an
/// identical existing entry.
pub(crate) fn append_index(
    layout: &Layout,
    snapshot: ObjectId,
    transcript_id: ObjectId,
) -> Result<()> {
    with_index_lock(layout, || {
        if dropped_ids(layout)?.contains(&transcript_id) {
            return Ok(());
        }
        let mut entries = read_index(layout)?;
        if entries
            .iter()
            .any(|(s, t)| *s == snapshot && *t == transcript_id)
        {
            return Ok(());
        }
        entries.push((snapshot, transcript_id));
        write_index(layout, &entries)
    })
}

/// `[signing]` keys listed under `[signers] trusted` in `.sc/recipients.toml`:
/// the same trust set `sc verify` uses. Unreadable or malformed config yields
/// an empty set, so remote tombstones are ignored (fail-closed).
fn trusted_signers(layout: &Layout) -> std::collections::HashMap<[u8; 32], String> {
    #[derive(serde::Deserialize, Default)]
    struct Signers {
        #[serde(default)]
        trusted: Vec<String>,
    }
    #[derive(serde::Deserialize, Default)]
    struct TrustFile {
        #[serde(default)]
        signing: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        signers: Option<Signers>,
    }
    let parsed: TrustFile = std::fs::read_to_string(layout.dot_sc.join("recipients.toml"))
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default();
    let mut out = std::collections::HashMap::new();
    for name in parsed.signers.unwrap_or_default().trusted {
        if let Some(pk) = parsed
            .signing
            .get(&name)
            .and_then(|k| scl_crypto::SigPublicKey::from_key_string(k).ok())
        {
            out.insert(pk.to_bytes(), name);
        }
    }
    out
}

/// The message a drop signature covers: a domain-separated digest of the
/// tombstone id, NOT the bare id. A plain `sign_transcript` signature over the
/// tombstone id (e.g. from an older binary's bulk `sc transcript sign`, which
/// indexes tombstones as live transcripts) must never authorize a drop.
pub(crate) fn drop_digest(tomb: &ObjectId) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(Transcript::DROP_AGENT.as_bytes());
    h.update(tomb.as_bytes());
    *h.finalize().as_bytes()
}

/// Whether an incoming tombstone may hide its transcript (ADR-0038 addendum,
/// "Who may drop"). All of: the tombstone's snapshot exists locally; if the
/// dropped transcript is held locally it is a real transcript on that same
/// snapshot; and a signature over the drop digest verifies under a key in
/// `trusted`. An unsigned or untrusted tombstone stays an inert object.
fn tombstone_honored(
    store: &mut scl_core::Store,
    trusted: &Trusted,
    sigs: &crate::signatures::SigIndex,
    tomb: ObjectId,
    t: &Transcript,
    dropped: ObjectId,
) -> Result<bool> {
    // The claimed snapshot must be a real snapshot, not any object we hold.
    if !store.contains(&t.snapshot) || !matches!(store.get(&t.snapshot)?, Object::Snapshot(_)) {
        return Ok(false);
    }
    if store.contains(&dropped) {
        match store.get(&dropped)? {
            Object::Transcript(d) if d.dropped_id().is_none() && d.snapshot == t.snapshot => {}
            _ => return Ok(false),
        }
    }
    // The index holds one signature per (target, signer), so only the trusted
    // signers are looked up: at most one read and one verification each, and
    // signatures from keys anyone else made are never reached (#257).
    for signer in trusted.keys() {
        let Some(sid) = sigs.by(&tomb, signer) else {
            continue;
        };
        if let Object::Signature(sig) = store.get(&sid)? {
            if sig.signer == *signer
                && scl_crypto::verify_transcript_sig(signer, &drop_digest(&tomb), &sig.sig)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Public snapshot->transcript index (one-to-many), for lookup/tests.
pub fn load(layout: &Layout) -> Result<Vec<(ObjectId, ObjectId)>> {
    read_index(layout)
}

/// gc integration: given the reachable object set already computed by
/// `gc::run`, keep only index entries whose snapshot is still reachable,
/// root each surviving entry's transcript object into `reachable` (so the
/// repack keeps it and the loose-object sweep never treats it as dangling
/// — and, since a transcript's own signature would be keyed by the
/// transcript id in `.sc/signatures`, rooting the transcript id here before
/// `signatures::gc_prune` runs is what keeps that ordering load-bearing),
/// and atomically rewrite the index to drop the rest. Dead transcript
/// objects are deliberately NOT rooted here — they fall out of `reachable`
/// and are swept by the same loose-object aging/pruning `gc::run` already
/// applies to every other unreachable object.
///
/// Returns the number of dropped entries (0 when nothing needed pruning, in
/// which case the index file is left untouched rather than rewritten).
pub(crate) fn gc_prune(layout: &Layout, reachable: &mut BTreeSet<ObjectId>) -> Result<usize> {
    with_index_lock(layout, || gc_prune_locked(layout, reachable))
}

fn gc_prune_locked(layout: &Layout, reachable: &mut BTreeSet<ObjectId>) -> Result<usize> {
    // Tombstones are load-bearing against resurrection: root them (and keep
    // their lines) even when their snapshot is dead. The dropped transcript
    // itself is never rooted, so it is swept after the grace window.
    let drops = read_drops(layout)?;
    reachable.extend(drops.iter().map(|(_, tomb, _)| *tomb));
    // Held-but-unhonored tombstones stay until trusted or evicted (#230).
    reachable.extend(read_pending(layout)?);
    let dropped: BTreeSet<ObjectId> = drops.iter().map(|(_, _, d)| *d).collect();
    let entries = read_raw(layout)?;
    let mut kept = Vec::with_capacity(entries.len());
    for (snap, tid) in &entries {
        if dropped.contains(tid) {
            continue;
        }
        if reachable.contains(snap) {
            reachable.insert(*tid);
            kept.push((*snap, *tid));
        }
    }
    let pruned = entries.len() - kept.len();
    if pruned > 0 {
        write_index(layout, &kept)?;
    }
    Ok(pruned)
}

/// Receiver-side seam (Task 3/4): given a batch of object ids just written
/// to the local store (e.g. by a pull/fetch/clone transfer), detect which
/// of them are `Transcript` objects and index them. Returns how many were
/// indexed.
///
/// # `NotFound` is a hard error here
///
/// Every caller passes ids it *just wrote* to `store` in the same call —
/// "ids just written" is this seam's contract, not "ids that might exist".
/// A `NotFound` therefore means the caller passed an id that was never
/// actually stored: a genuine bug, not a benign gap — mirrors
/// `signatures::index_incoming`'s discipline verbatim.
pub(crate) fn index_incoming(
    layout: &Layout,
    store: &mut scl_core::Store,
    ids: &[ObjectId],
) -> Result<usize> {
    let mut count = 0;
    let trusted = trusted_signers(layout);
    let sigs = crate::signatures::load_sig_index(layout, None, &trusted)?;
    let mut held = Vec::new();
    // Tombstones already recorded as drops need nothing: every fetch re-sends
    // them all, so skipping them keeps a resend O(new) rather than O(drops^2).
    let mut recorded: BTreeSet<ObjectId> = read_drops(layout)?
        .into_iter()
        .map(|(_, tomb, _)| tomb)
        .collect();
    // Honor a tombstone, or remember a signed one whose snapshot is held but
    // that is inert: a push-only remote is never sent it again (#230). One
    // whose snapshot is absent is not kept: it can only hide a body that
    // arrives later, and a fetching peer is re-sent it anyway.
    let mut consider = |store: &mut scl_core::Store, id: ObjectId, t: &Transcript, d: ObjectId| {
        if recorded.contains(&id) {
            return Ok::<_, Error>(());
        }
        if tombstone_honored(store, &trusted, &sigs, id, t, d)? {
            append_drop(layout, (t.snapshot, id, d))?;
            recorded.insert(id);
        } else if sigs.is_signed(&id) && store.contains(&t.snapshot) {
            held.push(id);
        }
        Ok(())
    };
    // Each tombstone is considered once per batch, and the signature-driven
    // lookups (one object read per distinct target) are capped.
    let mut considered = BTreeSet::new();
    let mut looked_up = BTreeSet::new();
    let mut lookups = 0;
    for id in ids {
        match store.get(id)? {
            Object::Transcript(t) => match t.dropped_id() {
                Some(dropped) => {
                    if considered.insert(*id) {
                        consider(store, *id, &t, dropped)?
                    }
                }
                None => {
                    append_index(layout, t.snapshot, *id)?;
                    count += 1;
                }
            },
            // A signature that lands after the tombstone it covers (separate
            // transfers) is a reason to look at that tombstone again.
            Object::Signature(s)
                if lookups < MAX_SIG_LOOKUPS
                    && !considered.contains(&s.snapshot)
                    && looked_up.insert(s.snapshot)
                    && store.contains(&s.snapshot) =>
            {
                lookups += 1;
                if let Object::Transcript(t) = store.get(&s.snapshot)? {
                    if let Some(dropped) = t.dropped_id() {
                        considered.insert(s.snapshot);
                        consider(store, s.snapshot, &t, dropped)?;
                    }
                }
            }
            _ => {}
        }
    }
    note_pending(layout, &held, &fp_of(&trusted))?;
    Ok(count)
}

/// Re-run the honoring checks on every remembered tombstone (#230): a signer
/// trusted since, or a snapshot or signature that arrived since, now lets the
/// drop take effect without the sender re-sending it. Idempotent; cost is
/// bounded by [`MAX_PENDING`] and zero when nothing is pending. An entry whose
/// object is gone, or that no longer decodes as a tombstone, is forgotten.
/// Returns how many drops were honored.
#[cfg(test)]
pub(crate) fn reevaluate_pending(layout: &Layout, store: &mut scl_core::Store) -> Result<usize> {
    Ok(reevaluate_inner(layout, store, &trusted_signers(layout))?.0)
}

/// [`reevaluate_pending`] plus whether some entry could not be judged because
/// an object failed to read.
fn reevaluate_inner(
    layout: &Layout,
    store: &mut scl_core::Store,
    trusted: &Trusted,
) -> Result<(usize, bool)> {
    let pending = read_pending(layout)?;
    if pending.is_empty() {
        return Ok((0, false));
    }
    let mut incomplete = false;
    let wanted: BTreeSet<ObjectId> = pending.iter().copied().collect();
    let sigs = crate::signatures::load_sig_index(layout, Some(&wanted), trusted)?;
    let (mut keep, mut honored) = (Vec::new(), 0);
    for id in &pending {
        if !store.contains(id) {
            continue;
        }
        let t = match store.get(id) {
            Ok(Object::Transcript(t)) => t,
            Ok(_) => continue,
            // Unreadable now, maybe fine later: keep it.
            Err(_) => {
                incomplete = true;
                keep.push(*id);
                continue;
            }
        };
        let Some(dropped) = t.dropped_id() else {
            continue;
        };
        // An unreadable object keeps the entry for the next trigger rather
        // than aborting the rest.
        match tombstone_honored(store, trusted, &sigs, *id, &t, dropped) {
            Ok(true) => {
                append_drop(layout, (t.snapshot, *id, dropped))?;
                honored += 1;
            }
            Ok(false) => keep.push(*id),
            Err(_) => {
                incomplete = true;
                keep.push(*id);
            }
        }
    }
    if keep.len() != pending.len() {
        write_pending(layout, &keep)?;
    }
    Ok((honored, incomplete))
}

/// Full-store rebuild of the transcript index (clone path): scan every
/// object the store can resolve (`Store::all_ids`, not a reachability walk
/// — a `Transcript` is a leaf no tree/snapshot references), keep the ones
/// that are `Object::Transcript` whose `snapshot` also resolves locally,
/// and atomically rewrite the index to exactly that set (not an append —
/// stale entries from a half-written prior index are dropped too).
///
/// The scan and the tombstone signature checks run without the index lock. A
/// serve-path ingest into the same store stores its objects before it appends
/// (under the lock), so under the lock the rebuild lists the store again,
/// after a few unlocked catch-up passes, and judges only what appeared since,
/// plus the transcripts whose snapshot was missing and the tombstones that
/// were not honored yet (their signature or trust may have landed since) (#274):
/// an append made during the scan is covered, and one made after the rewrite
/// lands on top of it. The locked listing also reloads the pack index, so
/// packs another handle wrote since this store opened count too.
pub(crate) fn reindex(layout: &Layout, store: &mut scl_core::Store) -> Result<usize> {
    reindex_with(layout, store, || {}, || {})
}

/// [`reindex`] with hooks so a test can interleave an ingest deterministically:
/// `after_scan` runs after the first scan, `before_lock` after the unlocked
/// catch-up passes, so only the locked pass can absorb what it does.
fn reindex_with(
    layout: &Layout,
    store: &mut scl_core::Store,
    after_scan: impl FnOnce(),
    before_lock: impl FnOnce(),
) -> Result<usize> {
    let mut scan = Scan::default();
    scan.pass(layout, store)?;
    after_scan();
    // Catch up on what arrived meanwhile without the lock, so the locked pass
    // has little left to judge however large a concurrent push was. Bounded: a
    // writer that keeps adding objects cannot postpone the write.
    for _ in 0..CATCH_UP_PASSES {
        if !scan.pass(layout, store)? {
            break;
        }
    }
    before_lock();
    with_index_lock(layout, || {
        store.reload_packs()?;
        scan.pass(layout, store)?;
        let drops: Vec<DropEntry> = scan
            .honored
            .values()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let dropped: BTreeSet<ObjectId> = drops.iter().map(|(_, _, d)| *d).collect();
        let entries: Vec<(ObjectId, ObjectId)> = scan
            .bodies
            .iter()
            .filter(|(id, _)| !dropped.contains(id))
            .map(|(id, snap)| (*snap, *id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        write_index(layout, &entries)?;
        write_drops(layout, &drops)?;
        Ok(entries.len())
    })
}

/// Unlocked catch-up passes `reindex` makes before taking the lock.
const CATCH_UP_PASSES: usize = 4;

/// What [`reindex`] has learned about the store so far, across passes.
#[derive(Default)]
struct Scan {
    seen: BTreeSet<ObjectId>,
    /// Transcripts (and tombstones) listed before their snapshot landed:
    /// `(id, snapshot)`, retried each pass (an ingest stores a pack's objects
    /// one by one).
    waiting: Vec<(ObjectId, ObjectId)>,
    /// Live-index candidates: transcript id to snapshot.
    bodies: std::collections::BTreeMap<ObjectId, ObjectId>,
    /// Every tombstone with a held snapshot, honored or not: tombstone id to
    /// the tombstone and the id it drops.
    tombs: std::collections::BTreeMap<ObjectId, (Transcript, ObjectId)>,
    /// The tombstones honored so far, as the drop line each would write.
    honored: std::collections::BTreeMap<ObjectId, DropEntry>,
    /// Fingerprint of the trusted set `honored` was judged under.
    fp: String,
}

impl Scan {
    /// One pass: decode the objects not seen yet, plus the waiting ones whose
    /// snapshot is now held, then judge the tombstones again under the current
    /// trusted set and signature index. Returns whether any new object was
    /// listed.
    fn pass(&mut self, layout: &Layout, store: &mut scl_core::Store) -> Result<bool> {
        let new: Vec<ObjectId> = store
            .all_ids()?
            .into_iter()
            .filter(|id| self.seen.insert(*id))
            .collect();
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.waiting)
            .into_iter()
            .partition(|(_, snap)| store.contains(snap));
        self.waiting = waiting;
        let retry = ready.into_iter().map(|(id, _)| id);
        for id in new.iter().copied().chain(retry) {
            let Object::Transcript(t) = store.get(&id)? else {
                continue;
            };
            if !store.contains(&t.snapshot) {
                self.waiting.push((id, t.snapshot));
            } else if let Some(dropped) = t.dropped_id() {
                self.tombs.insert(id, (t, dropped));
            } else {
                self.bodies.insert(id, t.snapshot);
            }
        }
        let any_new = !new.is_empty();
        self.judge(layout, store, &new.into_iter().collect())?;
        Ok(any_new)
    }

    /// Judge the tombstones not honored yet (their signature or the signer's
    /// trust may have landed since), and again any whose dropped transcript is
    /// among the `new` objects, under the trusted set and signature index as
    /// they are now. A changed trusted set invalidates every earlier verdict.
    fn judge(
        &mut self,
        layout: &Layout,
        store: &mut scl_core::Store,
        new: &BTreeSet<ObjectId>,
    ) -> Result<()> {
        if self.tombs.is_empty() {
            return Ok(());
        }
        let trusted = trusted_signers(layout);
        let fp = fp_of(&trusted);
        if fp != self.fp {
            self.honored.clear();
            self.fp = fp;
        }
        let wanted: BTreeSet<ObjectId> = self.tombs.keys().copied().collect();
        let sigs = crate::signatures::load_sig_index(layout, Some(&wanted), &trusted)?;
        for (id, (t, dropped)) in &self.tombs {
            if self.honored.contains_key(id) && !new.contains(dropped) {
                continue;
            }
            if tombstone_honored(store, &trusted, &sigs, *id, t, *dropped)? {
                self.honored.insert(*id, (t.snapshot, *id, *dropped));
            } else {
                self.honored.remove(id);
            }
        }
        Ok(())
    }
}

/// Sender-side seam (Task 3/4): the indexed transcript object ids (and drop
/// signed tombstones) covering any of `snapshots`, deduped and sorted — the set a push/export needs to
/// carry alongside the snapshots themselves so the receiving repo's index
/// stays complete.
pub(crate) fn indexed_transcript_ids_for(
    layout: &Layout,
    snapshots: &[ObjectId],
    snapshot_held: &dyn Fn(&ObjectId) -> bool,
) -> Result<Vec<ObjectId>> {
    let wanted: BTreeSet<ObjectId> = snapshots.iter().copied().collect();
    let mut out: BTreeSet<ObjectId> = BTreeSet::new();
    for (snap, tid) in read_index(layout)? {
        if wanted.contains(&snap) {
            out.insert(tid);
        }
    }
    // A retained signed tombstone travels when its snapshot is in `snapshots`
    // or is no longer held here: gc keeps a tombstone after it collects its
    // snapshot, and a stale peer that still lists the body must still be told
    // (#230). A tombstone whose snapshot is still held but outside this
    // transfer (an unpublished branch) stays home, so its ids do not leak to a
    // peer that never had the snapshot. Cost: one tombstone plus one signature
    // per such drop, which receivers dedupe and ignore when they cannot use
    // it. An unsigned (local-only) drop is never sent: peers would ignore it,
    // and an older peer would index it as a live transcript.
    let drops = read_drops(layout)?;
    if !drops.is_empty() {
        let tombs: BTreeSet<ObjectId> = drops.iter().map(|(_, tomb, _)| *tomb).collect();
        let sigs = crate::signatures::load_sig_index(layout, Some(&tombs), &Default::default())?;
        out.extend(
            drops
                .into_iter()
                .filter(|(snap, tomb, _)| {
                    sigs.is_signed(tomb) && (wanted.contains(snap) || !snapshot_held(snap))
                })
                .map(|(_, tomb, _)| tomb),
        );
    }
    Ok(out.into_iter().collect())
}

impl Repo {
    /// Seal `body` for `recipients` and attach it as a [`Transcript`] to
    /// `snapshot`: the body is scanned by the P5 scanner (warn-only — the
    /// body is sealed before it's stored, and refusing to record it would
    /// destroy provenance rather than protect anything), sealed via
    /// `scl_crypto::seal` (plaintext never enters the CAS — only the
    /// resulting ciphertext is put in the store), and indexed under
    /// `snapshot` (one-to-many; a snapshot can carry multiple transcripts).
    ///
    /// Returns the new transcript object's id. Errors with
    /// [`Error::InvalidArgument`] (via `secrets::require_recipients`) if
    /// `recipients` is empty — an unreadable transcript is a footgun, not a
    /// useful record.
    pub fn attach_transcript(
        &self,
        snapshot: ObjectId,
        agent: &str,
        session: &str,
        body: &[u8],
        recipients: &[scl_crypto::PublicKey],
    ) -> Result<ObjectId> {
        if self.manifest_at(&snapshot)?.is_some() {
            return Err(Error::PrivateUnsupported("sc transcript attach".into()));
        }
        crate::secrets::require_recipients(recipients)?;

        // P5 scan-and-WARN (never reject): the body is about to be sealed,
        // so a hit is recorded for the operator's attention, not blocked.
        for hit in crate::scanner::scan(session, body) {
            eprintln!(
                "warning: transcript body matched the secret scanner (rule {:?} at line {}); \
                 it is sealed, so this is recorded — rotate any real secret it exposes",
                hit.rule, hit.line
            );
        }

        let sealed = scl_crypto::seal(session, body, recipients);
        let transcript = Transcript {
            snapshot,
            agent: agent.to_string(),
            session: session.to_string(),
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            wrapped_keys: sealed.wrapped_keys,
        };
        let id = {
            let arc = self.store_arc();
            let mut store = arc.lock().unwrap();
            store.put(Object::Transcript(transcript))?
        };
        append_index(self.layout(), snapshot, id)?;
        Ok(id)
    }

    /// Drop the live transcript whose id starts with `id_prefix`: store a drop
    /// tombstone and record it, so the transcript vanishes from `list`/`show`
    /// and no later fetch can restore it (ADR-0038 addendum). The body object
    /// is reclaimed by `gc` after its grace window. Returns the dropped id.
    ///
    /// The local store always honors its own drop. With `signer`, the
    /// tombstone is also signed (over its drop digest) so peers whose
    /// `[signers] trusted` list names that key honor it too; without one the
    /// drop stays local-only (peers ignore an unsigned tombstone).
    pub fn drop_transcript(
        &self,
        id_prefix: &str,
        signer: Option<&scl_crypto::Identity>,
    ) -> Result<ObjectId> {
        if signer.is_some_and(|i| i.signing.is_none()) {
            return Err(Error::InvalidArgument(
                "identity has no signing half (v1 identity); a signed drop requires a v2 \
                 (scl-id-) identity"
                    .into(),
            ));
        }
        let prefix = id_prefix.to_ascii_lowercase();
        let matches: BTreeSet<(ObjectId, ObjectId)> = read_index(self.layout())?
            .into_iter()
            .filter(|(_, tid)| !prefix.is_empty() && tid.to_hex().starts_with(&prefix))
            .collect();
        let mut it = matches.into_iter();
        let (snap, tid) = match (it.next(), it.next()) {
            (Some(m), None) => m,
            (None, _) => {
                return Err(Error::InvalidArgument(format!(
                    "no live transcript matches {id_prefix:?} (see `sc transcript list`)"
                )))
            }
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "transcript id prefix {id_prefix:?} is ambiguous"
                )))
            }
        };
        let tomb = {
            let arc = self.store_arc();
            let mut store = arc.lock().unwrap();
            store.put(Object::Transcript(Transcript::drop_tombstone(snap, &tid)))?
        };
        if let Some(signing) = signer.and_then(|i| i.signing.as_ref()) {
            self.sign_drop(tomb, signing)?;
        }
        append_drop(self.layout(), (snap, tomb, tid))?;
        Ok(tid)
    }

    /// Sign `tomb`'s drop digest and index the signature under the tombstone id
    /// (shared `.sc/signatures` index, so the signature rides with the tombstone).
    pub(crate) fn sign_drop(&self, tomb: ObjectId, key: &scl_crypto::SigningKey) -> Result<()> {
        let sig_obj = SignatureObj {
            snapshot: tomb,
            signer: key.public().to_bytes(),
            sig: scl_crypto::sign_transcript_id(key, &drop_digest(&tomb)),
        };
        let arc = self.store_arc();
        let mut store = arc.lock().unwrap();
        let id = store.put(Object::Signature(sig_obj))?;
        crate::signatures::append_index(self.layout(), &mut store, id)
    }

    /// All indexed transcripts for `snapshot`, loaded from the CAS (id +
    /// object, still sealed — opening them is Task 3).
    pub fn transcripts_for(&self, snapshot: &ObjectId) -> Result<Vec<(ObjectId, Transcript)>> {
        let entries = read_index(self.layout())?;
        let arc = self.store_arc();
        let mut store = arc.lock().unwrap();
        let mut out = Vec::new();
        for (snap, tid) in entries {
            if snap != *snapshot {
                continue;
            }
            match store.get(&tid)? {
                Object::Transcript(t) => out.push((tid, t)),
                _ => {
                    return Err(Error::InvalidArgument(format!(
                        "transcript index entry {tid} does not resolve to a transcript object"
                    )))
                }
            }
        }
        Ok(out)
    }

    /// Decrypt a transcript's body with `identity`. Builds a [`Secret`] from
    /// the transcript's envelope fields and reuses `scl_crypto::open`
    /// VERBATIM — zero new crypto. `name` is set to the transcript's own
    /// `session` field: `attach_transcript` sealed the body via
    /// `scl_crypto::seal(session, body, recipients)`, and `seal`/`open` bind
    /// `name` into the AEAD associated data, so `open` only authenticates
    /// against the exact `session` string the body was originally sealed
    /// under (an empty/placeholder name fails authentication, not just
    /// convention). Returns a `Zeroizing` buffer so the plaintext body is
    /// zeroed on drop.
    pub fn open_transcript(
        &self,
        tid: &ObjectId,
        identity: &scl_crypto::SecretKey,
    ) -> Result<scl_crypto::Zeroizing<Vec<u8>>> {
        let obj = {
            let arc = self.store_arc();
            let o = arc.lock().unwrap().get(tid)?;
            o
        };
        let t = match obj {
            Object::Transcript(t) => t,
            _ => return Err(Error::InvalidArgument(format!("{tid} is not a transcript"))),
        };
        let secret = Secret {
            name: t.session,
            nonce: t.nonce,
            ciphertext: t.ciphertext,
            wrapped_keys: t.wrapped_keys,
        };
        Ok(scl_crypto::open(&secret, identity)?)
    }

    /// Sign a transcript id under the transcript domain
    /// (`scl_crypto::sign_transcript_id`); store the resulting
    /// [`SignatureObj`] and index it in the SHARED `.sc/signatures` index
    /// (keyed by the signed target id — a transcript id here, a snapshot id
    /// for `sign_snapshot`). Errors with [`Error::InvalidArgument`] if
    /// `identity` has no signing half (a v1 identity), mirroring
    /// `sign_snapshot`.
    pub fn sign_transcript(
        &self,
        tid: ObjectId,
        identity: &scl_crypto::Identity,
    ) -> Result<ObjectId> {
        let signing = identity.signing.as_ref().ok_or_else(|| {
            Error::InvalidArgument(
                "identity has no signing half (v1 identity); signing requires a v2 (scl-id-) \
                 identity"
                    .into(),
            )
        })?;
        let signer = signing.public().to_bytes();
        let sig = scl_crypto::sign_transcript_id(signing, tid.as_bytes());
        let sig_obj = SignatureObj {
            snapshot: tid,
            signer,
            sig,
        };
        let arc = self.store_arc();
        let mut store = arc.lock().unwrap();
        let id = store.put(Object::Signature(sig_obj))?;
        crate::signatures::append_index(self.layout(), &mut store, id)?;
        Ok(id)
    }

    /// Four-state verification of a transcript's signatures — mirrors
    /// `Repo::sig_status` but verifies under the TRANSCRIPT domain
    /// (`scl_crypto::verify_transcript_sig`), sharing the same precedence
    /// logic via `signatures::status_from`.
    pub fn transcript_sig_status(
        &self,
        tid: &ObjectId,
        trusted: &std::collections::HashMap<[u8; 32], String>,
    ) -> Result<SigStatus> {
        let sigs = self.signatures_for(tid)?;
        Ok(crate::signatures::status_from(
            &sigs,
            tid,
            trusted,
            scl_crypto::verify_transcript_sig,
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::repo::Repo;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("scl-repo-transcripts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn attach_seals_body_and_plaintext_never_in_cas() {
        let root = tmp_root("attach");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_sk_str, id) = scl_crypto::generate_identity_v2();
        let pk = id.enc.public();

        let body = b"USER: fix the bug\nAGENT: done";
        let tid = repo
            .attach_transcript(snap, "claude-code", "s1", body, &[pk])
            .unwrap();

        // Indexed one-to-many under the snapshot.
        let idx = load(repo.layout()).unwrap();
        assert!(idx.iter().any(|(s, t)| *s == snap && *t == tid));

        // The stored object is a Transcript whose ciphertext != plaintext.
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        match store.get(&tid).unwrap() {
            scl_core::Object::Transcript(t) => {
                assert_eq!(t.snapshot, snap);
                assert_ne!(t.ciphertext.as_slice(), body);
                assert!(!t.wrapped_keys.is_empty());
            }
            _ => panic!("not a transcript"),
        }
        drop(store);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn open_recovers_body_and_sign_status_is_trusted() {
        let root = tmp_root("open");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, id) = scl_crypto::generate_identity_v2();
        let body = b"USER: hi\nAGENT: hello";
        let tid = repo
            .attach_transcript(snap, "a", "s", body, &[id.enc.public()])
            .unwrap();

        // decrypt round-trips
        let got = repo.open_transcript(&tid, &id.enc).unwrap();
        assert_eq!(got.as_slice(), body);

        // sign + verify four-state
        repo.sign_transcript(tid, &id).unwrap();
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(
            id.signing.as_ref().unwrap().public().to_bytes(),
            "me".to_string(),
        );
        assert_eq!(
            repo.transcript_sig_status(&tid, &trusted).unwrap(),
            crate::signatures::SigStatus::Trusted("me".into())
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_prunes_transcripts_of_dead_snapshots() {
        // A transcript whose snapshot is NOT in `reachable` is dropped from
        // the index and its id is NOT rooted; a live one is kept and
        // rooted.
        let root = tmp_root("gc");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let live = repo.commit("t", "c1").unwrap();
        let (_s, id) = scl_crypto::generate_identity_v2();
        let t_live = repo
            .attach_transcript(live, "a", "s", b"body", &[id.enc.public()])
            .unwrap();
        let dead = ObjectId::of(b"dead-snap");
        // hand-insert a dead-snapshot index line:
        append_index(repo.layout(), dead, ObjectId::of(b"dead-transcript")).unwrap();

        let mut reachable: std::collections::BTreeSet<ObjectId> = [live].into_iter().collect();
        let dropped = gc_prune(repo.layout(), &mut reachable).unwrap();
        assert_eq!(dropped, 1, "the dead-snapshot entry is dropped");
        assert!(
            reachable.contains(&t_live),
            "the live transcript id is rooted"
        );
        assert!(load(repo.layout()).unwrap().iter().all(|(s, _)| *s == live));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Trust `identity`'s signing key as `me` in `repo`'s recipients.toml.
    pub(crate) fn trust_signer(repo: &Repo, identity: &scl_crypto::Identity) {
        let key = identity.signing.as_ref().unwrap().public().to_key_string();
        std::fs::write(
            repo.layout().dot_sc.join("recipients.toml"),
            format!("[signing]\nme = \"{key}\"\n[signers]\ntrusted = [\"me\"]\n"),
        )
        .unwrap();
    }

    /// Number of tombstones `repo` is remembering for re-evaluation.
    pub(crate) fn pending_count(repo: &Repo) -> usize {
        read_pending(repo.layout()).unwrap().len()
    }

    #[test]
    fn drop_hides_transcript_and_blocks_resurrection() {
        let root = tmp_root("drop");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, id) = scl_crypto::generate_identity_v2();
        let keep = repo
            .attach_transcript(snap, "a", "keep", b"keep", &[id.enc.public()])
            .unwrap();
        let gone = repo
            .attach_transcript(snap, "a", "gone", b"gone", &[id.enc.public()])
            .unwrap();

        // Empty and unknown prefixes are refused.
        assert!(repo.drop_transcript("", None).is_err());
        assert!(repo.drop_transcript("zz", None).is_err());

        assert_eq!(
            repo.drop_transcript(&gone.to_hex()[..12], None).unwrap(),
            gone
        );
        let live: Vec<_> = repo
            .transcripts_for(&snap)
            .unwrap()
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        assert_eq!(live, vec![keep], "only the kept transcript is listed");
        assert!(
            repo.drop_transcript(&gone.to_hex(), None).is_err(),
            "a dropped id is no longer live"
        );

        // Resurrection attempt: a fetch re-indexes the dropped body.
        append_index(repo.layout(), snap, gone).unwrap();
        assert!(load(repo.layout()).unwrap().iter().all(|(_, t)| *t != gone));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn incoming_tombstone_needs_a_trusted_signature_and_matching_snapshot() {
        let root = tmp_root("forge");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        std::fs::write(root.join("f"), b"y").unwrap();
        let other_snap = repo.commit("t", "c2").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let (_s, attacker) = scl_crypto::generate_identity_v2();
        let victim = repo
            .attach_transcript(snap, "a", "v", b"victim", &[owner.enc.public()])
            .unwrap();
        trust_signer(&repo, &owner);

        let arc = repo.store_arc();
        let ingest = |tomb: Transcript, signer: Option<&scl_crypto::Identity>| -> bool {
            let tomb_id = arc.lock().unwrap().put(Object::Transcript(tomb)).unwrap();
            if let Some(who) = signer {
                repo.sign_drop(tomb_id, who.signing.as_ref().unwrap())
                    .unwrap();
            }
            let mut store = arc.lock().unwrap();
            index_incoming(repo.layout(), &mut store, &[tomb_id]).unwrap();
            drop(store);
            read_drops(repo.layout())
                .unwrap()
                .iter()
                .any(|d| d.1 == tomb_id)
        };

        // Unsigned, signed by an untrusted key, and wrong-snapshot tombstones
        // (even with a trusted signature) are all ignored.
        let good = Transcript::drop_tombstone(snap, &victim);
        assert!(!ingest(good.clone(), None));
        assert!(!ingest(good.clone(), Some(&attacker)));
        assert!(!ingest(
            Transcript::drop_tombstone(other_snap, &victim),
            Some(&owner)
        ));
        // A tombstone whose "snapshot" is a blob we hold is ignored, even ahead
        // of the body.
        let blob = arc
            .lock()
            .unwrap()
            .put(Object::Blob(std::sync::Arc::from(&b"not a snapshot"[..])))
            .unwrap();
        assert!(!ingest(
            Transcript::drop_tombstone(blob, &ObjectId::of(b"future")),
            Some(&owner)
        ));
        // A tombstone for a snapshot this store has never seen is ignored too.
        let unknown = ObjectId::of(b"unknown-snap");
        assert!(!ingest(
            Transcript::drop_tombstone(unknown, &victim),
            Some(&owner)
        ));
        assert_eq!(repo.transcripts_for(&snap).unwrap().len(), 1);

        // A plain transcript signature over the bare tombstone id (what an
        // older binary's bulk `sc transcript sign` would produce) is not a
        // drop, and is not indexed either, so it cannot take the owner's slot
        // from the real drop signature below.
        let plain = {
            let id = arc
                .lock()
                .unwrap()
                .put(Object::Transcript(Transcript::drop_tombstone(
                    snap, &victim,
                )))
                .unwrap();
            assert!(repo.sign_transcript(id, &owner).is_err());
            let mut store = arc.lock().unwrap();
            index_incoming(repo.layout(), &mut store, &[id]).unwrap();
            id
        };
        assert!(read_drops(repo.layout())
            .unwrap()
            .iter()
            .all(|d| d.1 != plain));
        assert_eq!(repo.transcripts_for(&snap).unwrap().len(), 1);

        // A trusted signature on a matching tombstone is honored.
        assert!(ingest(good, Some(&owner)));
        assert!(repo.transcripts_for(&snap).unwrap().is_empty());
        // The sender ships the tombstone with its snapshot.
        assert_eq!(
            indexed_transcript_ids_for(repo.layout(), &[snap], &|_| true)
                .unwrap()
                .len(),
            1
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tombstone_honored_before_the_body_arrives_hides_it_on_arrival() {
        let (_s, owner) = scl_crypto::generate_identity_v2();
        // Origin makes a real transcript and a signed drop for it.
        let src_root = tmp_root("early-src");
        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("f"), b"x").unwrap();
        let snap = src.commit("t", "c1").unwrap();
        let body_id = src
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        let body = src.store_arc().lock().unwrap().get(&body_id).unwrap();
        src.drop_transcript(&body_id.to_hex(), Some(&owner))
            .unwrap();
        let (snap_, tomb, _) = read_drops(src.layout()).unwrap()[0];
        assert_eq!(snap_, snap);

        // Receiver already has the snapshot (same repo history) and trusts the signer.
        let dst_root = tmp_root("early-dst");
        let dst = Repo::clone_to(&src_root, &dst_root).unwrap();
        trust_signer(&dst, &owner);
        let arc = dst.store_arc();
        let mut store = arc.lock().unwrap();
        // Tombstone + its signature arrive first, body not held.
        let tomb_obj = src.store_arc().lock().unwrap().get(&tomb).unwrap();
        store.put(tomb_obj).unwrap();
        for sid in crate::signatures::indexed_signature_ids_for(src.layout(), &[tomb]).unwrap() {
            let o = src.store_arc().lock().unwrap().get(&sid).unwrap();
            store.put(o).unwrap();
            crate::signatures::index_incoming(dst.layout(), &mut store, &[sid]).unwrap();
        }
        index_incoming(dst.layout(), &mut store, &[tomb]).unwrap();
        assert_eq!(read_drops(dst.layout()).unwrap().len(), 1, "honored early");
        // Then the body arrives: it must not be indexed.
        let id = store.put(body).unwrap();
        assert_eq!(id, body_id);
        index_incoming(dst.layout(), &mut store, &[id]).unwrap();
        drop(store);
        assert!(dst.transcripts_for(&snap).unwrap().is_empty());

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn gc_prune_keeps_a_tombstone_whose_snapshot_died_and_never_roots_the_body() {
        let root = tmp_root("gc-dead");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        repo.drop_transcript(&body.to_hex(), Some(&owner)).unwrap();
        let tomb = read_drops(repo.layout()).unwrap()[0].1;

        // The snapshot is no longer reachable.
        let mut reachable = BTreeSet::new();
        gc_prune(repo.layout(), &mut reachable).unwrap();
        assert!(
            reachable.contains(&tomb),
            "tombstone rooted despite dead snapshot"
        );
        assert!(!reachable.contains(&body), "dropped body is never rooted");
        assert_eq!(read_drops(repo.layout()).unwrap().len(), 1);
        assert!(load(repo.layout()).unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn reindex_honors_a_signed_tombstone_only_for_a_trusted_signer() {
        let root = tmp_root("reindex");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        repo.drop_transcript(&body.to_hex(), Some(&owner)).unwrap();
        // Unsigned drops are local-only: never offered to a peer.
        let keep = repo
            .attach_transcript(snap, "a", "k", b"keep", &[owner.enc.public()])
            .unwrap();
        repo.drop_transcript(&keep.to_hex(), None).unwrap();
        let sent = indexed_transcript_ids_for(repo.layout(), &[snap], &|_| true).unwrap();
        let drops = read_drops(repo.layout()).unwrap();
        assert_eq!(sent.len(), 1);
        assert!(drops.iter().any(|d| sent.contains(&d.1) && d.2 == body));

        // Both bodies (and the tombstones) sit in the store; rebuild indexes.
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        crate::signatures::reindex(repo.layout(), &mut store).unwrap();
        assert_eq!(
            reindex(repo.layout(), &mut store).unwrap(),
            2,
            "no trust: both bodies are live again"
        );
        drop(store);
        assert_eq!(
            load(repo.layout()).unwrap().len(),
            2,
            "untrusted: both visible"
        );
        assert!(read_drops(repo.layout()).unwrap().is_empty());

        trust_signer(&repo, &owner);
        let mut store = arc.lock().unwrap();
        reindex(repo.layout(), &mut store).unwrap();
        drop(store);
        let live: Vec<_> = load(repo.layout())
            .unwrap()
            .into_iter()
            .map(|e| e.1)
            .collect();
        assert_eq!(
            live,
            vec![keep],
            "signed drop honored, unsigned drop is not"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sender_offers_a_signed_tombstone_for_its_set_or_a_collected_snapshot() {
        let root = tmp_root("send-all");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let signed = repo
            .attach_transcript(snap, "a", "s", b"signed", &[owner.enc.public()])
            .unwrap();
        let unsigned = repo
            .attach_transcript(snap, "a", "u", b"unsigned", &[owner.enc.public()])
            .unwrap();
        repo.drop_transcript(&signed.to_hex(), Some(&owner))
            .unwrap();
        repo.drop_transcript(&unsigned.to_hex(), None).unwrap();
        let drops = read_drops(repo.layout()).unwrap();
        let tomb = drops.iter().find(|d| d.2 == signed).unwrap().1;

        // `snap` is held here but outside the transfer set (an unpublished
        // branch): the tombstone stays home, so its ids do not leak.
        let held = |_: &ObjectId| true;
        assert!(indexed_transcript_ids_for(repo.layout(), &[], &held)
            .unwrap()
            .is_empty());
        // In the transfer set: sent, signed one only.
        let sent = indexed_transcript_ids_for(repo.layout(), &[snap], &held).unwrap();
        assert!(sent.contains(&tomb) && !sent.contains(&signed));
        // gc collected the snapshot: still sent, so a stale peer is told.
        let gone = |_: &ObjectId| false;
        let sent = indexed_transcript_ids_for(repo.layout(), &[], &gone).unwrap();
        assert_eq!(sent, vec![tomb], "the signed tombstone only");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn held_tombstone_is_honored_after_the_signer_is_trusted_and_never_before() {
        let root = tmp_root("pending");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let (_s, stranger) = scl_crypto::generate_identity_v2();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        let arc = repo.store_arc();
        let put_tomb = |signer: Option<&scl_crypto::Identity>| {
            let tomb = Transcript::drop_tombstone(snap, &body);
            let id = arc.lock().unwrap().put(Object::Transcript(tomb)).unwrap();
            if let Some(who) = signer {
                repo.sign_drop(id, who.signing.as_ref().unwrap()).unwrap();
            }
            id
        };

        // Unsigned: inert and not remembered. Signed by nobody trusted: held.
        let unsigned = put_tomb(None);
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[unsigned]).unwrap();
        assert!(read_pending(repo.layout()).unwrap().is_empty());
        drop(store);
        let signed = put_tomb(Some(&owner));
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[signed]).unwrap();
        assert_eq!(read_pending(repo.layout()).unwrap(), vec![signed]);
        assert_eq!(reevaluate_pending(repo.layout(), &mut store).unwrap(), 0);
        assert!(read_drops(repo.layout()).unwrap().is_empty());
        drop(store);

        // A trusted stranger does not make the owner's tombstone count.
        trust_signer(&repo, &stranger);
        let mut store = arc.lock().unwrap();
        assert_eq!(reevaluate_pending(repo.layout(), &mut store).unwrap(), 0);
        drop(store);
        assert_eq!(load(repo.layout()).unwrap().len(), 1, "still visible");

        // Gc keeps a held tombstone and its signature.
        let mut reachable = BTreeSet::new();
        gc_prune(repo.layout(), &mut reachable).unwrap();
        assert!(reachable.contains(&signed));

        trust_signer(&repo, &owner);
        let mut store = arc.lock().unwrap();
        assert_eq!(reevaluate_pending(repo.layout(), &mut store).unwrap(), 1);
        assert_eq!(
            reevaluate_pending(repo.layout(), &mut store).unwrap(),
            0,
            "idempotent: nothing is pending any more"
        );
        drop(store);
        assert!(load(repo.layout()).unwrap().is_empty(), "now hidden");
        assert!(!repo.layout().transcript_pending_path().exists());
        assert_eq!(read_drops(repo.layout()).unwrap().len(), 1);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_signature_that_lands_after_its_held_tombstone_makes_it_pending() {
        let root = tmp_root("late-sig");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        let tomb = repo
            .store_arc()
            .lock()
            .unwrap()
            .put(Object::Transcript(Transcript::drop_tombstone(snap, &body)))
            .unwrap();
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[tomb]).unwrap();
        assert!(
            read_pending(repo.layout()).unwrap().is_empty(),
            "unsigned: not kept"
        );
        drop(store);

        // The signature arrives in a later transfer, without the tombstone.
        repo.sign_drop(tomb, owner.signing.as_ref().unwrap())
            .unwrap();
        let sig = crate::signatures::indexed_signature_ids_for(repo.layout(), &[tomb]).unwrap()[0];
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[sig]).unwrap();
        assert_eq!(read_pending(repo.layout()).unwrap(), vec![tomb]);
        drop(store);

        trust_signer(&repo, &owner);
        let mut store = arc.lock().unwrap();
        assert_eq!(reevaluate_pending(repo.layout(), &mut store).unwrap(), 1);
        drop(store);
        assert!(load(repo.layout()).unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn junk_signatures_sorting_ahead_of_the_real_one_cannot_keep_a_drop_inert() {
        // B1: a pack is ordered by object id, so a writer can place junk
        // signatures (claiming the trusted key) ahead of the real one. They
        // must not reach the index, whatever the cap.
        let root = tmp_root("sig-ahead");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let key = owner.signing.as_ref().unwrap();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        trust_signer(&repo, &owner);
        let tomb_obj = Object::Transcript(Transcript::drop_tombstone(snap, &body));
        let tomb = tomb_obj.id();
        let real = Object::Signature(SignatureObj {
            snapshot: tomb,
            signer: key.public().to_bytes(),
            sig: scl_crypto::sign_transcript_id(key, &drop_digest(&tomb)),
        });
        let mut objs = vec![tomb_obj, real.clone()];
        // Junk claiming the trusted key, and valid signatures by other keys,
        // all with ids below the real signature's.
        let mut i = 0u64;
        let mut junk = 0;
        while junk < 20 {
            i += 1;
            let mut sig = [0u8; 64];
            sig[..8].copy_from_slice(&i.to_le_bytes());
            let o = Object::Signature(SignatureObj {
                snapshot: tomb,
                signer: key.public().to_bytes(),
                sig,
            });
            if o.id() < real.id() {
                objs.push(o);
                junk += 1;
            }
        }
        let junk_ids: Vec<ObjectId> = objs[2..].iter().map(Object::id).collect();
        let (_s2, other) = scl_crypto::generate_identity_v2();
        let other_key = other.signing.as_ref().unwrap();
        // One valid-but-untrusted signature: indexed, never honored.
        objs.push(Object::Signature(SignatureObj {
            snapshot: tomb,
            signer: other_key.public().to_bytes(),
            sig: scl_crypto::sign_transcript_id(other_key, &drop_digest(&tomb)),
        }));
        objs.sort_by_key(Object::id);
        let encoded: Vec<(ObjectId, Vec<u8>)> = objs.iter().map(|o| (o.id(), o.encode())).collect();
        let (pack, _idx) = scl_core::pack::build_pack(&encoded).unwrap();
        let path = root.join("incoming.pack");
        std::fs::write(&path, pack).unwrap();

        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        crate::transport::ingest_pack_file(repo.layout(), &mut store, &path).unwrap();
        drop(store);

        let indexed = crate::signatures::indexed_signature_ids_for(repo.layout(), &[tomb]).unwrap();
        assert!(indexed.contains(&real.id()));
        assert!(
            junk_ids.iter().all(|j| !indexed.contains(j)),
            "forged signatures are never indexed"
        );
        assert_eq!(read_drops(repo.layout()).unwrap().len(), 1, "drop honored");
        assert!(load(repo.layout()).unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_signature_over_an_absent_target_is_not_indexed() {
        let root = tmp_root("sig-dangling");
        let repo = Repo::init(&root).unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let key = owner.signing.as_ref().unwrap();
        let ghost = ObjectId::of(b"nothing here");
        let id = repo
            .store_arc()
            .lock()
            .unwrap()
            .put(Object::Signature(SignatureObj {
                snapshot: ghost,
                signer: key.public().to_bytes(),
                sig: scl_crypto::sign_transcript_id(key, &drop_digest(&ghost)),
            }))
            .unwrap();
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        assert_eq!(
            crate::signatures::index_incoming(repo.layout(), &mut store, &[id]).unwrap(),
            0
        );
        drop(store);
        assert!(
            crate::signatures::indexed_signature_ids_for(repo.layout(), &[ghost])
                .unwrap()
                .is_empty()
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_pending_tombstones_signature_survives_gc_and_trust_change_is_detected_once() {
        let root = tmp_root("pending-gc");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        let arc = repo.store_arc();
        let tomb = arc
            .lock()
            .unwrap()
            .put(Object::Transcript(Transcript::drop_tombstone(snap, &body)))
            .unwrap();
        repo.sign_drop(tomb, owner.signing.as_ref().unwrap())
            .unwrap();
        let sig = crate::signatures::indexed_signature_ids_for(repo.layout(), &[tomb]).unwrap()[0];
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[tomb]).unwrap();
        drop(store);
        assert_eq!(read_pending(repo.layout()).unwrap(), vec![tomb]);

        // Nothing changed since it was judged: no trigger, no work.
        assert!(!trust_changed(repo.layout()));
        repo.gc(std::time::Duration::from_secs(0)).unwrap();
        let store = arc.lock().unwrap();
        assert!(store.contains(&tomb) && store.contains(&sig));
        drop(store);
        assert_eq!(repo.signatures_for(&tomb).unwrap().len(), 1);

        trust_signer(&repo, &owner);
        assert!(trust_changed(repo.layout()));
        let mut store = arc.lock().unwrap();
        assert_eq!(
            reevaluate_if_trust_changed(repo.layout(), &mut store).unwrap(),
            1
        );
        drop(store);
        assert!(!trust_changed(repo.layout()));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn concurrent_drop_appends_lose_no_line() {
        let root = tmp_root("append-race");
        let repo = Repo::init(&root).unwrap();
        let layout = repo.layout().clone();
        let handles: Vec<_> = (0..16u32)
            .map(|i| {
                let layout = layout.clone();
                std::thread::spawn(move || {
                    let e = |tag: &str| ObjectId::of(format!("{tag}{i}").as_bytes());
                    append_drop(&layout, (e("s"), e("t"), e("d"))).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(read_drops(&layout).unwrap().len(), 16);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn signature_lookups_per_batch_are_deduplicated_and_capped() {
        let root = tmp_root("sig-batch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let arc = repo.store_arc();
        // Many signatures over one snapshot: one lookup, not one per signature.
        let ids: Vec<ObjectId> = (0..50u64)
            .map(|i| {
                let mut signer = [0u8; 32];
                signer[..8].copy_from_slice(&(i + 1).to_le_bytes());
                arc.lock()
                    .unwrap()
                    .put(Object::Signature(SignatureObj {
                        snapshot: snap,
                        signer,
                        sig: [1u8; 64],
                    }))
                    .unwrap()
            })
            .collect();
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &ids).unwrap();
        drop(store);
        assert!(read_pending(repo.layout()).unwrap().is_empty());
        assert!(read_drops(repo.layout()).unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_recorded_drop_is_not_requeued_and_a_batch_is_deduped_before_the_cap() {
        let root = tmp_root("recorded");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        repo.drop_transcript(&body.to_hex(), Some(&owner)).unwrap();
        let tomb = read_drops(repo.layout()).unwrap()[0].1;

        // Signer no longer trusted, tombstone re-sent: already recorded, so
        // it is not queued again.
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[tomb]).unwrap();
        drop(store);
        assert!(read_pending(repo.layout()).unwrap().is_empty());

        // The same id repeated fills no more than one slot.
        let a = ObjectId::of(b"a");
        let b = ObjectId::of(b"b");
        let mut batch = vec![a];
        batch.extend(std::iter::repeat_n(b, MAX_PENDING + 10));
        note_pending(repo.layout(), &batch, "fp").unwrap();
        assert_eq!(read_pending(repo.layout()).unwrap(), vec![a, b]);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn pending_set_is_a_bounded_fifo_and_forgets_missing_objects() {
        let root = tmp_root("pending-cap");
        let repo = Repo::init(&root).unwrap();
        let ids: Vec<ObjectId> = (0..MAX_PENDING + 5)
            .map(|i| ObjectId::of(format!("t{i}").as_bytes()))
            .collect();
        note_pending(repo.layout(), &ids, "fp").unwrap();
        note_pending(repo.layout(), &ids[10..13], "fp").unwrap(); // dedup, no growth
        let held = read_pending(repo.layout()).unwrap();
        assert_eq!(held.len(), MAX_PENDING);
        assert_eq!(held[0], ids[5], "oldest evicted");
        assert_eq!(held[MAX_PENDING - 1], ids[MAX_PENDING + 4]);

        // None of these objects exist: a re-evaluation forgets them all.
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        assert_eq!(reevaluate_pending(repo.layout(), &mut store).unwrap(), 0);
        drop(store);
        assert!(!repo.layout().transcript_pending_path().exists());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_drop_signature_sorting_below_its_tombstone_in_the_pack_is_indexed_and_honored() {
        let root = tmp_root("sig-below-tomb");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let key = owner.signing.as_ref().unwrap();
        trust_signer(&repo, &owner);
        // Sealing is randomized, so each attach mints a new body (and tombstone
        // id) until the signature's id sorts below the tombstone's.
        let (body, tomb_obj, sig_obj) = loop {
            let body = repo
                .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
                .unwrap();
            let tomb_obj = Object::Transcript(Transcript::drop_tombstone(snap, &body));
            let tomb = tomb_obj.id();
            let sig_obj = Object::Signature(SignatureObj {
                snapshot: tomb,
                signer: key.public().to_bytes(),
                sig: scl_crypto::sign_transcript_id(key, &drop_digest(&tomb)),
            });
            if sig_obj.id() < tomb {
                break (body, tomb_obj, sig_obj);
            }
        };
        let _ = body;
        let mut objs = [tomb_obj, sig_obj.clone()];
        objs.sort_by_key(Object::id);
        assert_eq!(objs[0].id(), sig_obj.id());
        let enc: Vec<(ObjectId, Vec<u8>)> = objs.iter().map(|o| (o.id(), o.encode())).collect();
        let (pack, _idx) = scl_core::pack::build_pack(&enc).unwrap();
        let path = root.join("in.pack");
        std::fs::write(&path, pack).unwrap();
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        crate::transport::ingest_pack_file(repo.layout(), &mut store, &path).unwrap();
        drop(store);
        assert_eq!(read_drops(repo.layout()).unwrap().len(), 1);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_torn_drop_line_does_not_swallow_the_next_append() {
        let root = tmp_root("torn");
        let repo = Repo::init(&root).unwrap();
        let e = |t: &str| ObjectId::of(t.as_bytes());
        append_drop(repo.layout(), (e("s1"), e("t1"), e("d1"))).unwrap();
        // A crash left half a line with no newline.
        let path = repo.layout().transcript_drops_path();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, &e("s2").to_hex().as_bytes()[..20]).unwrap();
        drop(f);
        append_drop(repo.layout(), (e("s3"), e("t3"), e("d3"))).unwrap();
        let drops = read_drops(repo.layout()).unwrap();
        assert_eq!(drops.len(), 2, "the torn line is skipped, the next is kept");
        assert!(drops.contains(&(e("s3"), e("t3"), e("d3"))));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn an_unreadable_pending_object_is_retried_a_bounded_number_of_times() {
        let root = tmp_root("retries");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        let arc = repo.store_arc();
        let tomb = arc
            .lock()
            .unwrap()
            .put(Object::Transcript(Transcript::drop_tombstone(snap, &body)))
            .unwrap();
        repo.sign_drop(tomb, owner.signing.as_ref().unwrap())
            .unwrap();
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[tomb]).unwrap();
        assert_eq!(read_pending(repo.layout()).unwrap(), vec![tomb]);
        drop(store);

        // Make the tombstone unreadable but still "contained".
        let path = std::fs::read_dir(repo.layout().objects_dir())
            .unwrap()
            .flat_map(|d| std::fs::read_dir(d.unwrap().path()).into_iter().flatten())
            .map(|f| f.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&tomb.to_hex()[2..])
            });
        let path = path.expect("the tombstone is a loose object");
        let saved = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"garbage").unwrap();
        // A fresh store, so no cached copy hides the damage.
        let mut fresh =
            scl_core::Store::open_persistent(repo.layout().objects_dir(), 1 << 20).unwrap();
        trust_signer(&repo, &owner);
        for _ in 0..MAX_RETRIES {
            assert!(trust_changed(repo.layout()));
            reevaluate_if_trust_changed(repo.layout(), &mut fresh).unwrap();
        }
        assert!(!trust_changed(repo.layout()), "retries are bounded");
        assert_eq!(
            read_pending(repo.layout()).unwrap(),
            vec![tomb],
            "entry kept"
        );

        std::fs::write(&path, saved).unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn valid_signatures_from_hundreds_of_other_keys_cannot_keep_a_drop_inert() {
        // #257: a writer who signs the predictable tombstone id with many keys
        // of their own, ahead of the real signature, used to fill the
        // per-tombstone read cap. Honoring now looks only at trusted signers.
        let root = tmp_root("sig-flood");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        let key = owner.signing.as_ref().unwrap();
        let body = repo
            .attach_transcript(snap, "a", "s", b"body", &[owner.enc.public()])
            .unwrap();
        trust_signer(&repo, &owner);
        let arc = repo.store_arc();
        let tomb = arc
            .lock()
            .unwrap()
            .put(Object::Transcript(Transcript::drop_tombstone(snap, &body)))
            .unwrap();
        let junk: Vec<ObjectId> = (0..300)
            .map(|_| {
                let (_s, who) = scl_crypto::generate_identity_v2();
                let k = who.signing.as_ref().unwrap();
                arc.lock()
                    .unwrap()
                    .put(Object::Signature(SignatureObj {
                        snapshot: tomb,
                        signer: k.public().to_bytes(),
                        sig: scl_crypto::sign_transcript_id(k, &drop_digest(&tomb)),
                    }))
                    .unwrap()
            })
            .collect();
        let real = arc
            .lock()
            .unwrap()
            .put(Object::Signature(SignatureObj {
                snapshot: tomb,
                signer: key.public().to_bytes(),
                sig: scl_crypto::sign_transcript_id(key, &drop_digest(&tomb)),
            }))
            .unwrap();
        let mut store = arc.lock().unwrap();
        assert_eq!(
            crate::signatures::index_incoming(repo.layout(), &mut store, &junk).unwrap(),
            300,
            "every valid junk signature is indexed, one slot per key"
        );
        crate::signatures::index_incoming(repo.layout(), &mut store, &[real]).unwrap();
        index_incoming(repo.layout(), &mut store, &[tomb]).unwrap();
        drop(store);
        assert_eq!(read_drops(repo.layout()).unwrap().len(), 1, "drop honored");
        assert!(load(repo.layout()).unwrap().is_empty());

        // A resend of the junk adds nothing: the slots are taken.
        let mut store = arc.lock().unwrap();
        crate::signatures::index_incoming(repo.layout(), &mut store, &junk).unwrap();
        drop(store);
        assert_eq!(
            crate::signatures::indexed_signature_ids_for(repo.layout(), &[tomb])
                .unwrap()
                .len(),
            301
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// `n` threads each push a pack (a snapshot signature, a transcript, a
    /// tombstone for it and the tombstone's untrusted signature) at one served
    /// directory; every derived index entry must survive (#260). With
    /// `repo_open` a `Repo` holds the repo lock throughout, like a local `sc`
    /// command; otherwise each thread also moves a ref, taking the repo lock.
    fn concurrent_ingests_lose_nothing(tag: &str, repo_open: bool) {
        let n = 8usize;
        let src_root = tmp_root(&format!("{tag}-src"));
        let dst_root = tmp_root(&format!("{tag}-dst"));
        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("f"), b"x").unwrap();
        let snap = src.commit("t", "c1").unwrap();
        let src_arc = src.store_arc();
        let mut packs = Vec::new();
        for i in 0..n {
            let (_s, who) = scl_crypto::generate_identity_v2();
            let k = who.signing.as_ref().unwrap();
            let tid = src
                .attach_transcript(snap, "a", &format!("s{i}"), b"body", &[who.enc.public()])
                .unwrap();
            let tomb = Object::Transcript(Transcript::drop_tombstone(snap, &tid));
            let tomb_id = tomb.id();
            let objs = [
                Object::Signature(SignatureObj {
                    snapshot: snap,
                    signer: k.public().to_bytes(),
                    sig: scl_crypto::sign_snapshot_id(k, snap.as_bytes()),
                }),
                src_arc.lock().unwrap().get(&tid).unwrap(),
                tomb,
                Object::Signature(SignatureObj {
                    snapshot: tomb_id,
                    signer: k.public().to_bytes(),
                    sig: scl_crypto::sign_transcript_id(k, &drop_digest(&tomb_id)),
                }),
            ];
            let enc: Vec<(ObjectId, Vec<u8>)> = objs.iter().map(|o| (o.id(), o.encode())).collect();
            let path = dst_root.join(format!("in-{i}.pack"));
            // dst is created below; the packs live beside it.
            packs.push((path, enc, tomb_id));
        }
        let dst = Repo::init(&dst_root).unwrap();
        dst.store_arc()
            .lock()
            .unwrap()
            .put(src_arc.lock().unwrap().get(&snap).unwrap())
            .unwrap();
        for (path, enc, _) in &packs {
            std::fs::write(path, scl_core::pack::build_pack(enc).unwrap().0).unwrap();
        }
        let layout = dst.layout().clone();
        let held = if repo_open {
            Some(dst)
        } else {
            drop(dst);
            None
        };

        let handles: Vec<_> = packs
            .iter()
            .enumerate()
            .map(|(i, (path, _, _))| {
                let (root, path) = (dst_root.clone(), path.clone());
                std::thread::spawn(move || {
                    let t = crate::transport::LocalTransport::open(&root).unwrap();
                    t.ingest_from(&path).unwrap();
                    if !repo_open {
                        use crate::transport::Transport;
                        // The repo lock is try-once: retry while another
                        // connection holds it. Finishing at all shows the
                        // index lock never waits on it.
                        let started = std::time::Instant::now();
                        while let Err(e) = t.update_ref(&format!("b{i}"), &snap, None) {
                            assert!(matches!(e, Error::Locked(_)), "{e:?}");
                            assert!(started.elapsed().as_secs() < 30, "update_ref starved");
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let tombs: Vec<ObjectId> = packs.iter().map(|(_, _, t)| *t).collect();
        let mut targets = tombs.clone();
        targets.push(snap);
        assert_eq!(
            crate::signatures::indexed_signature_ids_for(&layout, &targets)
                .unwrap()
                .len(),
            2 * n,
            "a signature index entry was lost"
        );
        assert_eq!(
            load(&layout).unwrap().len(),
            n,
            "a transcript entry was lost"
        );
        let mut pending = read_pending(&layout).unwrap();
        pending.sort();
        let mut want = tombs;
        want.sort();
        assert_eq!(pending, want, "a pending entry was lost");

        drop(held);
        drop(src);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
        assert!(!src_root.exists() && !dst_root.exists());
    }

    #[test]
    fn concurrent_serve_ingests_lose_no_index_entry_beside_a_local_command() {
        concurrent_ingests_lose_nothing("conc-open", true);
    }

    #[test]
    fn concurrent_serve_ingests_lose_no_index_entry_and_do_not_deadlock_with_update_ref() {
        concurrent_ingests_lose_nothing("conc-ref", false);
    }

    /// A pack of `objs`, as a serve-path ingest receives it.
    fn pack_of(objs: &[Object]) -> Vec<u8> {
        let enc: Vec<(ObjectId, Vec<u8>)> = objs.iter().map(|o| (o.id(), o.encode())).collect();
        scl_core::pack::build_pack(&enc).unwrap().0
    }

    /// A signature by `who` over the drop digest of `tomb`.
    fn drop_sig(who: &scl_crypto::Identity, tomb: ObjectId) -> Object {
        let k = who.signing.as_ref().unwrap();
        Object::Signature(SignatureObj {
            snapshot: tomb,
            signer: k.public().to_bytes(),
            sig: scl_crypto::sign_transcript_id(k, &drop_digest(&tomb)),
        })
    }

    fn put_pack_into(root: &std::path::Path, pack: &[u8]) {
        use crate::transport::Transport;
        crate::transport::LocalTransport::open(root)
            .unwrap()
            .put_pack(&mut &pack[..])
            .unwrap();
    }

    /// Run `reindex_with` on `dest`, calling `ingest` once, after the first
    /// scan or (`just_before_lock`) only after the unlocked catch-up passes.
    fn reindex_racing(dest: &Repo, just_before_lock: bool, ingest: impl FnOnce()) -> usize {
        let ingest = std::cell::RefCell::new(Some(ingest));
        let arc = dest.store_arc();
        let mut store = arc.lock().unwrap();
        reindex_with(
            dest.layout(),
            &mut store,
            || {
                if !just_before_lock {
                    (ingest.borrow_mut().take().unwrap())();
                }
            },
            || {
                if just_before_lock {
                    (ingest.borrow_mut().take().unwrap())();
                }
            },
        )
        .unwrap()
    }

    /// A source repo with `snap`, a trusting `dest` that holds it, and the
    /// identity `dest` trusts.
    fn race_fixture(tag: &str) -> (Repo, ObjectId, Repo, scl_crypto::Identity) {
        let src = Repo::init(tmp_root(&format!("{tag}-src"))).unwrap();
        std::fs::write(src.layout().root.join("f"), b"x").unwrap();
        let snap = src.commit("t", "c1").unwrap();
        let dest = Repo::init(tmp_root(&format!("{tag}-dst"))).unwrap();
        dest.store_arc()
            .lock()
            .unwrap()
            .put(src.store_arc().lock().unwrap().get(&snap).unwrap())
            .unwrap();
        let (_s, owner) = scl_crypto::generate_identity_v2();
        trust_signer(&dest, &owner);
        (src, snap, dest, owner)
    }

    fn body_of(src: &Repo, snap: ObjectId, label: &str, who: &scl_crypto::Identity) -> Object {
        let id = src
            .attach_transcript(snap, "a", label, label.as_bytes(), &[who.enc.public()])
            .unwrap();
        src.store_arc().lock().unwrap().get(&id).unwrap()
    }

    fn clean_up(repos: &[Repo]) {
        let roots: Vec<_> = repos.iter().map(|r| r.layout().root.clone()).collect();
        for r in roots {
            std::fs::remove_dir_all(&r).unwrap();
            assert!(!r.exists());
        }
    }

    #[test]
    fn reindex_keeps_an_ingest_that_lands_during_its_scan() {
        // The ingest lands after the first scan, or only after the unlocked
        // catch-up passes (so just the locked pass can absorb it). Without the
        // locked relisting the rewrite replaces the index it appended to.
        for just_before_lock in [false, true] {
            let (src, snap, dest, owner) = race_fixture(&format!("race-{just_before_lock}"));
            let base = body_of(&src, snap, "base", &owner);
            let keep = body_of(&src, snap, "keep", &owner);
            let doomed = body_of(&src, snap, "doomed", &owner);
            let tomb = Object::Transcript(Transcript::drop_tombstone(snap, &doomed.id()));
            dest.store_arc().lock().unwrap().put(base.clone()).unwrap();
            let pack = pack_of(&[
                keep.clone(),
                doomed.clone(),
                tomb.clone(),
                drop_sig(&owner, tomb.id()),
            ]);
            let root = dest.layout().root.clone();
            let count = reindex_racing(&dest, just_before_lock, || put_pack_into(&root, &pack));
            assert_eq!(count, 2);
            let mut live: Vec<_> = load(dest.layout())
                .unwrap()
                .into_iter()
                .map(|e| e.1)
                .collect();
            live.sort();
            let mut want = vec![base.id(), keep.id()];
            want.sort();
            assert_eq!(live, want, "a transcript index line was lost");
            assert_eq!(
                read_drops(dest.layout()).unwrap(),
                vec![(snap, tomb.id(), doomed.id())],
                "the tombstone was lost"
            );
            clean_up(&[src, dest]);
        }
    }

    #[test]
    fn reindex_judges_again_what_lands_after_the_first_scan() {
        // A transcript listed before its snapshot, and a tombstone listed
        // before its signature: both are settled by what arrives later, and
        // a late signature by a key that is not trusted still honors nothing.
        for (just_before_lock, trusted_signer) in
            [(false, true), (true, true), (false, false), (true, false)]
        {
            let (src, snap, dest, owner) =
                race_fixture(&format!("late-{just_before_lock}-{trusted_signer}"));
            let (_s, stranger) = scl_crypto::generate_identity_v2();
            let signer = if trusted_signer { &owner } else { &stranger };
            std::fs::write(src.layout().root.join("f"), b"y").unwrap();
            let snap2 = src.commit("t", "c2").unwrap();
            let snap2_obj = src.store_arc().lock().unwrap().get(&snap2).unwrap();
            let orphan = body_of(&src, snap2, "orphan", &owner);
            let doomed = body_of(&src, snap, "doomed", &owner);
            let tomb = Object::Transcript(Transcript::drop_tombstone(snap, &doomed.id()));
            for o in [&orphan, &doomed, &tomb] {
                dest.store_arc().lock().unwrap().put(o.clone()).unwrap();
            }
            let pack = pack_of(&[snap2_obj, drop_sig(signer, tomb.id())]);
            let root = dest.layout().root.clone();
            let count = reindex_racing(&dest, just_before_lock, || put_pack_into(&root, &pack));
            let mut live: Vec<_> = load(dest.layout())
                .unwrap()
                .into_iter()
                .map(|e| e.1)
                .collect();
            live.sort();
            let (mut want, drops) = if trusted_signer {
                (vec![orphan.id()], vec![(snap, tomb.id(), doomed.id())])
            } else {
                (vec![orphan.id(), doomed.id()], vec![])
            };
            want.sort();
            assert_eq!(count, want.len());
            assert_eq!(live, want, "the late snapshot or signature is mishandled");
            assert_eq!(read_drops(dest.layout()).unwrap(), drops);
            clean_up(&[src, dest]);
        }
    }

    #[test]
    fn reindex_sees_a_pack_another_handle_wrote_since_the_store_opened() {
        for just_before_lock in [false, true] {
            let (src, snap, dest, owner) = race_fixture(&format!("pack-{just_before_lock}"));
            let late = body_of(&src, snap, "late", &owner);
            let late_id = late.id();
            let objects = dest.layout().objects_dir();
            let count = reindex_racing(&dest, just_before_lock, || {
                let mut s2 =
                    scl_core::Store::open_persistent(objects, crate::repo::default_budget())
                        .unwrap();
                s2.put(late).unwrap();
                s2.write_pack(&[late_id]).unwrap();
                s2.delete(&late_id).unwrap();
            });
            assert_eq!(count, 1);
            assert_eq!(load(dest.layout()).unwrap(), vec![(snap, late_id)]);
            clean_up(&[src, dest]);
        }
    }
}
