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

/// Record one tombstone, deduping an identical existing line.
fn append_drop(layout: &Layout, entry: DropEntry) -> Result<()> {
    let mut entries = read_drops(layout)?;
    if !entries.contains(&entry) {
        entries.push(entry);
        write_drops(layout, &entries)?;
    }
    Ok(())
}

/// Most held-but-unhonored tombstones remembered (#230). A peer can push
/// arbitrarily many, so the set is a FIFO ring: the newest win, and an evicted
/// one is only lost to a push-only remote (a fetching peer is re-sent every
/// retained tombstone on each fetch).
const MAX_PENDING: usize = 1024;

/// Signature objects `tombstone_honored` reads per tombstone, and how many of
/// those that claim a trusted key it verifies. A peer can attach any number of
/// junk signature objects to a target and this runs on every open, so the work
/// is capped; a real tombstone carries one or two. Signatures by an untrusted
/// key cost one read and never count against the verification cap, so they
/// cannot push a trusted one out of it.
const MAX_SIG_READS: usize = 256;
const MAX_SIG_VERIFIES: usize = 8;

/// Distinct signature targets `index_incoming` looks up per batch.
const MAX_SIG_LOOKUPS: usize = 1024;

fn read_pending(layout: &Layout) -> Vec<ObjectId> {
    std::fs::read_to_string(layout.transcript_pending_path())
        .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

fn write_pending(layout: &Layout, ids: &[ObjectId]) -> Result<()> {
    let path = layout.transcript_pending_path();
    if ids.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::Io(e)),
            _ => Ok(()),
        };
    }
    let out: String = ids.iter().map(|i| format!("{}\n", i.to_hex())).collect();
    scl_core::fsutil::atomic_write_durable(&path, out.as_bytes())?;
    Ok(())
}

/// Remember `new` tombstones for re-evaluation, deduped, newest last, capped
/// at [`MAX_PENDING`]. Writes only when the set changes.
fn note_pending(layout: &Layout, new: &[ObjectId]) -> Result<()> {
    // Only the newest MAX_PENDING of a (peer-sized) batch can survive.
    let new = &new[new.len().saturating_sub(MAX_PENDING)..];
    let mut all = read_pending(layout);
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
    write_pending(layout, &all)
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
fn drop_digest(tomb: &ObjectId) -> [u8; 32] {
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
    trusted: &std::collections::HashMap<[u8; 32], String>,
    sigs: &std::collections::HashMap<ObjectId, Vec<ObjectId>>,
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
    let mut verifies = 0;
    for sid in sigs
        .get(&tomb)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .take(MAX_SIG_READS)
    {
        if let Object::Signature(sig) = store.get(sid)? {
            if !trusted.contains_key(&sig.signer) {
                continue;
            }
            if scl_crypto::verify_transcript_sig(&sig.signer, &drop_digest(&tomb), &sig.sig) {
                return Ok(true);
            }
            verifies += 1;
            if verifies >= MAX_SIG_VERIFIES {
                break;
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
    // Tombstones are load-bearing against resurrection: root them (and keep
    // their lines) even when their snapshot is dead. The dropped transcript
    // itself is never rooted, so it is swept after the grace window.
    let drops = read_drops(layout)?;
    reachable.extend(drops.iter().map(|(_, tomb, _)| *tomb));
    // Held-but-unhonored tombstones stay until trusted or evicted (#230).
    reachable.extend(read_pending(layout));
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
    let sigs = crate::signatures::index_by_target(layout)?;
    let mut held = Vec::new();
    // Honor a tombstone, or remember a signed one that is held but inert: a
    // push-only remote is never sent it again (#230).
    let mut consider = |store: &mut scl_core::Store, id: ObjectId, t: &Transcript, d: ObjectId| {
        if tombstone_honored(store, &trusted, &sigs, id, t, d)? {
            append_drop(layout, (t.snapshot, id, d))?;
        } else if sigs.contains_key(&id) {
            held.push(id);
        }
        Ok::<_, Error>(())
    };
    // Each tombstone is considered once per batch, and the signature-driven
    // lookups (one object read per distinct target) are capped.
    let mut considered = BTreeSet::new();
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
    note_pending(layout, &held)?;
    Ok(count)
}

/// Re-run the honoring checks on every remembered tombstone (#230): a signer
/// trusted since, or a snapshot or signature that arrived since, now lets the
/// drop take effect without the sender re-sending it. Idempotent; cost is
/// bounded by [`MAX_PENDING`] and zero when nothing is pending. An entry whose
/// object is gone, or that no longer decodes as a tombstone, is forgotten.
/// Returns how many drops were honored.
pub(crate) fn reevaluate_pending(layout: &Layout, store: &mut scl_core::Store) -> Result<usize> {
    let pending = read_pending(layout);
    if pending.is_empty() {
        return Ok(0);
    }
    let trusted = trusted_signers(layout);
    let mut sigs = crate::signatures::index_by_target(layout)?;
    let wanted: BTreeSet<ObjectId> = pending.iter().copied().collect();
    sigs.retain(|target, _| wanted.contains(target));
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
                keep.push(*id);
                continue;
            }
        };
        let Some(dropped) = t.dropped_id() else {
            continue;
        };
        // An unreadable object keeps the entry for the next trigger rather
        // than aborting the rest.
        if tombstone_honored(store, &trusted, &sigs, *id, &t, dropped).unwrap_or(false) {
            append_drop(layout, (t.snapshot, *id, dropped))?;
            honored += 1;
        } else {
            keep.push(*id);
        }
    }
    if keep.len() != pending.len() {
        write_pending(layout, &keep)?;
    }
    Ok(honored)
}

/// Full-store rebuild of the transcript index (clone path): scan every
/// object the store can resolve (`Store::all_ids`, not a reachability walk
/// — a `Transcript` is a leaf no tree/snapshot references), keep the ones
/// that are `Object::Transcript` whose `snapshot` also resolves locally,
/// and atomically rewrite the index to exactly that set (not an append —
/// stale entries from a half-written prior index are dropped too).
pub(crate) fn reindex(layout: &Layout, store: &mut scl_core::Store) -> Result<usize> {
    let mut entries: Vec<(ObjectId, ObjectId)> = Vec::new();
    let mut drops: Vec<DropEntry> = Vec::new();
    let trusted = trusted_signers(layout);
    let sigs = crate::signatures::index_by_target(layout)?;
    for id in store.all_ids()? {
        if let Object::Transcript(t) = store.get(&id)? {
            if !store.contains(&t.snapshot) {
                continue;
            }
            match t.dropped_id() {
                Some(dropped) => {
                    if tombstone_honored(store, &trusted, &sigs, id, &t, dropped)? {
                        drops.push((t.snapshot, id, dropped));
                    }
                }
                None => entries.push((t.snapshot, id)),
            }
        }
    }
    drops.sort();
    drops.dedup();
    let dropped: BTreeSet<ObjectId> = drops.iter().map(|(_, _, d)| *d).collect();
    entries.retain(|(_, tid)| !dropped.contains(tid));
    entries.sort();
    entries.dedup();
    let count = entries.len();
    write_index(layout, &entries)?;
    write_drops(layout, &drops)?;
    Ok(count)
}

/// Sender-side seam (Task 3/4): the indexed transcript object ids (and drop
/// signed tombstones) covering any of `snapshots`, deduped and sorted — the set a push/export needs to
/// carry alongside the snapshots themselves so the receiving repo's index
/// stays complete.
pub(crate) fn indexed_transcript_ids_for(
    layout: &Layout,
    snapshots: &[ObjectId],
) -> Result<Vec<ObjectId>> {
    let wanted: BTreeSet<ObjectId> = snapshots.iter().copied().collect();
    let mut out: BTreeSet<ObjectId> = BTreeSet::new();
    for (snap, tid) in read_index(layout)? {
        if wanted.contains(&snap) {
            out.insert(tid);
        }
    }
    // Every retained signed tombstone travels on every transfer, not only
    // those of `snapshots`: gc keeps a tombstone after it collects its
    // snapshot, and a stale peer that still lists the body must still be told
    // (#230). Cost: one tombstone plus one signature per drop, which receivers
    // dedupe and ignore when they cannot use it. An unsigned (local-only) drop
    // is never sent: peers would ignore it, and an older peer would index it
    // as a live transcript.
    let drops = read_drops(layout)?;
    if !drops.is_empty() {
        let sigs = crate::signatures::index_by_target(layout)?;
        out.extend(
            drops
                .into_iter()
                .filter(|(_, tomb, _)| sigs.contains_key(tomb))
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
        let id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Signature(sig_obj))?;
            i
        };
        crate::signatures::append_index(self.layout(), tomb, id)
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
        let id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Signature(sig_obj))?;
            i
        };
        crate::signatures::append_index(self.layout(), tid, id)?;
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
        read_pending(repo.layout()).len()
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
        // older binary's bulk `sc transcript sign` would produce) is not a drop.
        let plain = {
            let id = arc
                .lock()
                .unwrap()
                .put(Object::Transcript(Transcript::drop_tombstone(
                    snap, &victim,
                )))
                .unwrap();
            repo.sign_transcript(id, &owner).unwrap();
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
            indexed_transcript_ids_for(repo.layout(), &[snap])
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
        let sent = indexed_transcript_ids_for(repo.layout(), &[snap]).unwrap();
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
    fn sender_offers_every_retained_signed_tombstone_whatever_the_transfer_set() {
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

        // `snap` is not in the transfer set (gc may have collected it).
        let sent = indexed_transcript_ids_for(repo.layout(), &[]).unwrap();
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
        assert!(read_pending(repo.layout()).is_empty());
        drop(store);
        let signed = put_tomb(Some(&owner));
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[signed]).unwrap();
        assert_eq!(read_pending(repo.layout()), vec![signed]);
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
        assert!(read_pending(repo.layout()).is_empty(), "unsigned: not kept");
        drop(store);

        // The signature arrives in a later transfer, without the tombstone.
        repo.sign_drop(tomb, owner.signing.as_ref().unwrap())
            .unwrap();
        let sig = crate::signatures::index_by_target(repo.layout()).unwrap()[&tomb][0];
        let mut store = arc.lock().unwrap();
        index_incoming(repo.layout(), &mut store, &[sig]).unwrap();
        assert_eq!(read_pending(repo.layout()), vec![tomb]);
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
    fn a_flood_of_untrusted_signatures_cannot_keep_a_trusted_one_from_honoring() {
        let root = tmp_root("sig-flood");
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
        // Far more junk signatures by untrusted keys than any cap, indexed
        // before the real one.
        let arc = repo.store_arc();
        let mut junk_ids = Vec::new();
        for i in 0..(MAX_SIG_READS + 40) {
            let mut signer = [0u8; 32];
            signer[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            let junk = SignatureObj {
                snapshot: tomb,
                signer,
                sig: [7u8; 64],
            };
            junk_ids.push(arc.lock().unwrap().put(Object::Signature(junk)).unwrap());
        }
        let mut store = arc.lock().unwrap();
        crate::signatures::index_incoming(repo.layout(), &mut store, &junk_ids).unwrap();
        drop(store);
        repo.sign_drop(tomb, owner.signing.as_ref().unwrap())
            .unwrap();
        trust_signer(&repo, &owner);
        let sigs = crate::signatures::index_by_target(repo.layout()).unwrap();
        assert!(
            sigs[&tomb].len() > MAX_SIG_READS,
            "real one sits past the read cap"
        );

        // Reading is capped, so put the real one first to model the normal
        // case (it arrives with the tombstone): junk afterwards is harmless.
        let mut ordered = sigs.clone();
        let last = ordered.get_mut(&tomb).unwrap().pop().unwrap();
        ordered.get_mut(&tomb).unwrap().insert(0, last);
        let mut store = arc.lock().unwrap();
        let trusted = trusted_signers(repo.layout());
        let t = match store.get(&tomb).unwrap() {
            Object::Transcript(t) => t,
            _ => unreachable!(),
        };
        assert!(tombstone_honored(&mut store, &trusted, &ordered, tomb, &t, body).unwrap());

        // Untrusted junk ahead of a trusted signature is skipped for free:
        // 20 junk signatures put the real one at index 20 (past the 8
        // verification cap, inside the read cap).
        let mut mid = sigs.clone();
        let v = mid.get_mut(&tomb).unwrap();
        let last = v.pop().unwrap();
        v.truncate(20);
        v.push(last);
        assert!(tombstone_honored(&mut store, &trusted, &mid, tomb, &t, body).unwrap());
        drop(store);

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
        assert!(read_pending(repo.layout()).is_empty());
        assert!(read_drops(repo.layout()).unwrap().is_empty());

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
        note_pending(repo.layout(), &ids).unwrap();
        note_pending(repo.layout(), &ids[10..13]).unwrap(); // dedup, no growth
        let held = read_pending(repo.layout());
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
}
