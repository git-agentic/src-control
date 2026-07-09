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

use std::collections::BTreeSet;

use scl_core::{Object, ObjectId, Transcript};

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::repo::Repo;

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

fn read_index(layout: &Layout) -> Result<Vec<(ObjectId, ObjectId)>> {
    let path = layout.transcripts_path();
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
    for (snap, tid) in entries {
        out.push_str(&format!("{} {}\n", snap.to_hex(), tid.to_hex()));
    }
    scl_core::fsutil::atomic_write_durable(&layout.transcripts_path(), out.as_bytes())?;
    Ok(())
}

/// Append one `(snapshot, transcript_id)` entry, deduping against an
/// identical existing entry.
pub(crate) fn append_index(layout: &Layout, snapshot: ObjectId, transcript_id: ObjectId) -> Result<()> {
    let mut entries = read_index(layout)?;
    if entries.iter().any(|(s, t)| *s == snapshot && *t == transcript_id) {
        return Ok(());
    }
    entries.push((snapshot, transcript_id));
    write_index(layout, &entries)
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
    let entries = read_index(layout)?;
    if entries.is_empty() {
        return Ok(0);
    }
    let mut kept = Vec::with_capacity(entries.len());
    for (snap, tid) in &entries {
        if reachable.contains(snap) {
            reachable.insert(*tid);
            kept.push((*snap, *tid));
        }
    }
    let dropped = entries.len() - kept.len();
    if dropped > 0 {
        write_index(layout, &kept)?;
    }
    Ok(dropped)
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
    for id in ids {
        match store.get(id)? {
            Object::Transcript(t) => {
                append_index(layout, t.snapshot, *id)?;
                count += 1;
            }
            _ => {}
        }
    }
    Ok(count)
}

/// Full-store rebuild of the transcript index (clone path): scan every
/// object the store can resolve (`Store::all_ids`, not a reachability walk
/// — a `Transcript` is a leaf no tree/snapshot references), keep the ones
/// that are `Object::Transcript` whose `snapshot` also resolves locally,
/// and atomically rewrite the index to exactly that set (not an append —
/// stale entries from a half-written prior index are dropped too).
pub(crate) fn reindex(layout: &Layout, store: &mut scl_core::Store) -> Result<usize> {
    let mut entries: Vec<(ObjectId, ObjectId)> = Vec::new();
    for id in store.all_ids()? {
        if let Object::Transcript(t) = store.get(&id)? {
            if store.contains(&t.snapshot) {
                entries.push((t.snapshot, id));
            }
        }
    }
    entries.sort();
    entries.dedup();
    let count = entries.len();
    write_index(layout, &entries)?;
    Ok(count)
}

/// Sender-side seam (Task 3/4): the indexed transcript object ids covering
/// any of `snapshots`, deduped and sorted — the set a push/export needs to
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-transcripts-{tag}-{}", std::process::id()));
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
        let tid = repo.attach_transcript(snap, "claude-code", "s1", body, &[pk]).unwrap();

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
    fn gc_prunes_transcripts_of_dead_snapshots() {
        // A transcript whose snapshot is NOT in `reachable` is dropped from
        // the index and its id is NOT rooted; a live one is kept and
        // rooted.
        let root = tmp_root("gc");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let live = repo.commit("t", "c1").unwrap();
        let (_s, id) = scl_crypto::generate_identity_v2();
        let t_live = repo.attach_transcript(live, "a", "s", b"body", &[id.enc.public()]).unwrap();
        let dead = ObjectId::of(b"dead-snap");
        // hand-insert a dead-snapshot index line:
        append_index(repo.layout(), dead, ObjectId::of(b"dead-transcript")).unwrap();

        let mut reachable: std::collections::BTreeSet<ObjectId> = [live].into_iter().collect();
        let dropped = gc_prune(repo.layout(), &mut reachable).unwrap();
        assert_eq!(dropped, 1, "the dead-snapshot entry is dropped");
        assert!(reachable.contains(&t_live), "the live transcript id is rooted");
        assert!(load(repo.layout()).unwrap().iter().all(|(s, _)| *s == live));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
