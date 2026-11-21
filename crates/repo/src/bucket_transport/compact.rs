//! Bucket remote compaction and gc (#216, ADR-0057).
//!
//! Two phases, each safe on its own. `consolidate` merges small live packs and
//! commits the result with one manifest CAS (a no-op log entry plus a
//! checkpoint whose pack list is the trimmed set). `sweep` then deletes what no
//! manifest chain can reach: log entries and checkpoints behind a cutoff old
//! enough that no reader still needs them, and packs nothing names. Nothing is
//! ever deleted that the current manifest references, and the manifest itself
//! is never deleted, so a failure between any two operations leaves a bucket a
//! cold start reads.
//!
//! On a Git carrier (`sc+git::`) the host reports no trustworthy object age, so
//! the sweep takes ages from the first-sighting record (`sightings`) instead of
//! the bucket's modification times, sizes packs from their idx instead of
//! downloading them, and deletes with leases (`Bucket::delete_leased`) so a key
//! someone re-created after the listing survives (ADR-0057 addendum).

mod sightings;

use super::{capped, declared_pack_len, BucketTransport};
use crate::error::{Error, Result};
use crate::walfmt::{
    checkpoint_key, idx_key, log_key, pack_key, Checkpoint, LogEntry, Manifest, MAX_LIST,
};
use scl_core::pack::{parse_index, parse_pack_reader};
use scl_core::ObjectId;
use scl_objio::{Fetched, ObjectMeta};
use sightings::Sightings;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

/// Replans after a lost manifest CAS or a concurrent compactor before giving up.
const MAX_ATTEMPTS: u32 = 4;

/// Unreferenced packs deleted between two looks at the manifest.
const PACK_DELETE_BATCH: usize = 16;

/// Decoded bytes one merge pack may hold, as a multiple of `group_bytes`
/// (which counts compressed bytes).
const DECODED_FACTOR: u64 = 4;

/// Knobs for [`BucketTransport::compact`]. The defaults are what
/// `sc remote compact` uses.
#[derive(Debug, Clone)]
pub struct CompactOptions {
    /// Nothing unreferenced is deleted until it is at least this old (and the
    /// checkpoint that superseded it is too). Mirrors `sc gc --prune-expire`.
    pub prune_expire: Duration,
    /// Plan and report; write and delete nothing.
    pub dry_run: bool,
    /// Live packs smaller than this are merge candidates.
    pub small_pack_bytes: u64,
    /// Upper bound on the summed size of one merge group (bounds peak RAM).
    pub group_bytes: u64,
    /// Clock override for tests; `None` is the wall clock at the start of the run.
    pub now: Option<SystemTime>,
}

impl Default for CompactOptions {
    fn default() -> Self {
        CompactOptions {
            prune_expire: Duration::from_secs(24 * 3600),
            dry_run: false,
            small_pack_bytes: 16 << 20,
            group_bytes: 64 << 20,
            now: None,
        }
    }
}

/// What a compaction did, or with `dry_run`, what it would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompactReport {
    pub dry_run: bool,
    /// Live packs folded into new ones, and how many new packs replaced them.
    pub packs_merged: usize,
    pub packs_created: usize,
    /// The manifest's `checkpoint_seq` after phase 1.
    pub checkpoint_seq: u64,
    /// The sweep cutoff `K` (0 when no checkpoint is old enough yet).
    pub cutoff: u64,
    pub logs_deleted: usize,
    pub checkpoints_deleted: usize,
    /// Pack hashes removed (each is a `.pack` and a `.idx`).
    pub packs_deleted: usize,
    pub bytes_deleted: u64,
    /// Unreferenced packs kept because they are younger than `prune_expire`.
    pub packs_held_back: usize,
    /// Why something was skipped or stopped early.
    pub notes: Vec<String>,
}

/// `checkpoints/00…065` or `log/00…065` -> 65.
fn seq_of(key: &str) -> Option<u64> {
    key.rsplit('/').next()?.parse().ok()
}

/// Whole seconds since the Unix epoch, the resolution of the age record.
fn unix_secs(t: SystemTime) -> Result<u64> {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::InvalidArgument("the clock is before 1970".into()))
}

/// `packs/<hash>.pack` / `packs/<hash>.idx` -> `<hash>`.
fn hash_of(key: &str) -> Option<&str> {
    let name = key.strip_prefix("packs/")?;
    name.strip_suffix(".pack")
        .or_else(|| name.strip_suffix(".idx"))
}

/// Bytes of the `.pack` and `.idx` objects behind these packs; a pack in
/// `declared` (a Git carrier, which lists no sizes) counts that many instead.
fn pack_bytes(packs: &[(&String, &Vec<ObjectMeta>)], declared: &BTreeMap<String, u64>) -> u64 {
    packs
        .iter()
        .map(|(h, ms)| {
            declared
                .get(*h)
                .copied()
                .unwrap_or_else(|| ms.iter().map(|m| m.size).sum())
        })
        .sum()
}

/// What one sweep attempt sees in the bucket.
struct Listing {
    ckpts: Vec<(u64, ObjectMeta)>,
    logs: Vec<(u64, ObjectMeta)>,
    /// `.pack` and `.idx` objects by pack hash.
    by_hash: BTreeMap<String, Vec<ObjectMeta>>,
    /// Git carrier only: the tag each listed key held in this very listing, the
    /// lease its delete is conditional on (the oid whose age was judged is the
    /// oid deleted; nothing lists twice).
    tags: BTreeMap<String, String>,
}

/// Greedy size-tiered grouping: smallest candidates first, a group closes when
/// the next pack would push it past `group_bytes`. Groups of one are dropped
/// (there is nothing to merge).
fn plan_groups(
    live: &[String],
    sizes: &BTreeMap<String, u64>,
    opts: &CompactOptions,
) -> Vec<Vec<String>> {
    let mut small: Vec<(u64, &String)> = live
        .iter()
        .filter_map(|h| sizes.get(h).map(|s| (*s, h)))
        .filter(|(s, _)| *s < opts.small_pack_bytes)
        .collect();
    small.sort();
    let mut groups: Vec<Vec<String>> = Vec::new();
    let (mut cur, mut sum): (Vec<String>, u64) = (Vec::new(), 0);
    for (size, hash) in small {
        if !cur.is_empty() && sum + size > opts.group_bytes {
            groups.push(std::mem::take(&mut cur));
            sum = 0;
        }
        cur.push(hash.clone());
        sum += size;
    }
    groups.push(cur);
    groups.retain(|g| g.len() >= 2);
    groups
}

impl BucketTransport {
    /// Compact this bucket remote (ADR-0057): merge small packs, then delete
    /// log entries, checkpoints and packs no reader or writer can still need.
    /// Safe to run while others push and fetch; run one at a time, from one
    /// host (concurrent runs stay correct but waste work, and on a Git carrier
    /// runs that share the age record need clocks within far less than the grace
    /// window). Needs bucket list and delete rights (on a Git repository, push
    /// access).
    pub fn compact(&self, opts: &CompactOptions) -> Result<CompactReport> {
        let mut rep = CompactReport {
            dry_run: opts.dry_run,
            ..CompactReport::default()
        };
        if self.git_carrier {
            // An unusable age record stops the run before phase 1 writes anything.
            self.read_sightings(unix_secs(opts.now.unwrap_or_else(SystemTime::now))?)?;
        }
        self.refresh()?;
        if self.view.borrow().is_none() {
            // No manifest yet: nothing to merge, but a first push that died after
            // uploading its pack left debris the sweep can still age out.
            rep.notes
                .push("bucket has no manifest: only aged orphan packs are swept".into());
        } else {
            rep.checkpoint_seq = self
                .view
                .borrow()
                .as_ref()
                .map_or(0, |v| v.manifest.checkpoint_seq);
            self.consolidate(opts, &mut rep)?;
        }
        // Read the clock after phase 1 so a zero grace sees its own checkpoint.
        let now = opts.now.unwrap_or_else(SystemTime::now);
        self.sweep(opts, now, &mut rep)?;
        Ok(rep)
    }

    /// Phase 1: merge small live packs and commit with one manifest CAS.
    fn consolidate(&self, opts: &CompactOptions, rep: &mut CompactReport) -> Result<()> {
        // Manifest tag of an attempt that found a planned member pack missing.
        let mut missing_on: Option<String> = None;
        'attempt: for _ in 0..MAX_ATTEMPTS {
            self.refresh()?;
            let (live, nrefs) = {
                let view = self.view.borrow();
                let v = view.as_ref().expect("checked non-empty");
                let mut seen = BTreeSet::new();
                let live: Vec<String> = v
                    .packs
                    .iter()
                    .filter(|h| seen.insert((*h).clone()))
                    .cloned()
                    .collect();
                (live, v.refs.len())
            };
            // A Git carrier's `list_meta` downloads every value, so its sizes
            // come from the idx files the view already parsed (a hint: the idx is
            // writer-controlled, which the body check below backs up).
            let sizes: BTreeMap<String, u64> = if self.git_carrier {
                self.view
                    .borrow()
                    .as_ref()
                    .map(|v| v.pack_sizes.clone())
                    .unwrap_or_default()
            } else {
                self.bucket
                    .list_meta("packs/")?
                    .into_iter()
                    .filter(|m| m.key.ends_with(".pack"))
                    .filter_map(|m| hash_of(&m.key).map(|h| (h.to_string(), m.size)))
                    .collect()
            };
            let groups = plan_groups(&live, &sizes, opts);
            if groups.is_empty() {
                if live.len() > MAX_LIST {
                    rep.notes.push(format!(
                        "{} live packs exceed the checkpoint cap of {MAX_LIST} and none is small \
                         enough to merge; folding stays off",
                        live.len()
                    ));
                }
                return Ok(());
            }
            let replaced: BTreeSet<String> = groups.iter().flatten().cloned().collect();
            if live.len() - replaced.len() + groups.len() > MAX_LIST || nrefs > MAX_LIST {
                rep.notes.push(format!(
                    "merging would leave more than {MAX_LIST} packs (or {nrefs} refs exceed the \
                     cap): a checkpoint could not hold it, nothing merged"
                ));
                return Ok(());
            }
            let mut created = Vec::new();
            // The packs actually folded: a source that fills a part alone is
            // left where it is (#263), so this can be a subset of `replaced`.
            let mut merged: BTreeSet<String> = BTreeSet::new();
            for group in &groups {
                let mut objects: BTreeMap<ObjectId, Vec<u8>> = BTreeMap::new();
                let mut decoded = 0u64;
                let mut part: Vec<&String> = Vec::new();
                for hash in group {
                    let Fetched::New { bytes, .. } = self.bucket.get(&pack_key(hash), None)? else {
                        // Either another compactor retired it (the manifest has
                        // moved: replan) or the bucket is damaged (same manifest
                        // twice: say so instead of retrying).
                        let tag = self.view.borrow().as_ref().map(|v| v.tag.clone());
                        if tag == missing_on {
                            return Err(Error::Wal(format!(
                                "pack {hash} on chain but body absent"
                            )));
                        }
                        missing_on = tag;
                        continue 'attempt;
                    };
                    // The idx that sized this pack is the writer's word: a pack
                    // far over what it declared is not merged (nor decoded).
                    if self.git_carrier
                        && bytes.len() as u64 > opts.small_pack_bytes.saturating_mul(2)
                    {
                        rep.notes.push(format!(
                            "pack {hash} is {} bytes, far over what its idx declares: left unmerged",
                            bytes.len()
                        ));
                        continue;
                    }
                    parse_pack_reader(std::io::Cursor::new(&bytes[..]), |id, obj| {
                        let enc = obj.encode();
                        decoded += enc.len() as u64;
                        objects.insert(id, enc);
                        Ok(())
                    })?;
                    part.push(hash);
                    // Compressed sizes bound the group, not the decoded bytes held
                    // here; spill to a pack of its own before RAM balloons.
                    if decoded > opts.group_bytes.saturating_mul(DECODED_FACTOR) {
                        self.flush_part(&mut objects, &mut part, &mut created, &mut merged, opts)?;
                        decoded = 0;
                    }
                }
                self.flush_part(&mut objects, &mut part, &mut created, &mut merged, opts)?;
            }
            if created.is_empty() {
                rep.notes.push(
                    "no merge would reduce the pack count: every candidate is large once decoded, \
                     nothing merged"
                        .into(),
                );
                return Ok(());
            }
            if opts.dry_run {
                // Split parts can outnumber the planned groups: size the
                // checkpoint the real run would build, as it does.
                if super::fold_would_overflow(nrefs, live.len() - merged.len() + created.len()) {
                    rep.notes.push(format!(
                        "the merged checkpoint would exceed the cap of {MAX_LIST}: nothing merged"
                    ));
                    return Ok(());
                }
                rep.packs_merged = merged.len();
                rep.packs_created = created.len();
                return Ok(());
            }
            // Fence + fold in one CAS: the manifest tag we read is the state
            // the checkpoint describes, so a lost CAS just replans.
            self.refresh()?;
            let (tag, head_seq, head_branch, refs, packs) = {
                let view = self.view.borrow();
                let v = view.as_ref().expect("checked non-empty");
                (
                    v.tag.clone(),
                    v.manifest.head_seq,
                    v.manifest.head_branch.clone(),
                    v.refs
                        .iter()
                        .map(|(b, id)| (b.clone(), *id))
                        .collect::<Vec<_>>(),
                    v.packs.clone(),
                )
            };
            let packs_now: BTreeSet<String> = packs.iter().cloned().collect();
            let mut seen = BTreeSet::new();
            let mut kept: Vec<String> = packs
                .into_iter()
                .filter(|h| !merged.contains(h) && seen.insert(h.clone()))
                .collect();
            for h in &created {
                if seen.insert(h.clone()) {
                    kept.push(h.clone());
                }
            }
            // Recheck both axes on the state we are about to publish: pushes
            // that landed while we merged can have pushed either over the cap,
            // and an undecodable checkpoint would brick the remote.
            if super::fold_would_overflow(refs.len(), kept.len()) {
                rep.notes.push(
                    "new pushes took the checkpoint over the cap while merging: nothing merged"
                        .into(),
                );
                return Ok(());
            }
            // Another compactor may have retired some of the packs we merged
            // already: replan rather than publish a second copy of the same data.
            if !merged.is_subset(&packs_now) {
                continue 'attempt;
            }
            let mut try_seq = head_seq + 1;
            let entry = LogEntry {
                seq: 0,
                parent_seq: head_seq,
                packs: created.clone(),
                updates: vec![],
            };
            let seq = loop {
                let mut candidate = entry.clone();
                candidate.seq = try_seq;
                if self
                    .bucket
                    .put_new(&log_key(try_seq), &candidate.encode())?
                {
                    break try_seq;
                }
                try_seq += 1;
            };
            let ck = Checkpoint {
                seq,
                refs,
                packs: kept,
            };
            if !self.bucket.put_new(&checkpoint_key(seq), &ck.encode())? {
                continue 'attempt; // slot debris from a crashed run: claim a later one
            }
            let manifest = Manifest {
                head_seq: seq,
                checkpoint_seq: seq,
                head_branch,
            };
            // A sweep by another compactor may have removed a merged pack that
            // was a content-identical leftover; never commit a name that is gone.
            self.ensure_packs_present(&created)?;
            if self
                .bucket
                .put_if_tag("manifest", &manifest.encode(), Some(&tag))?
                .is_some()
            {
                self.refresh()?;
                rep.packs_merged = merged.len();
                rep.packs_created = created.len();
                rep.checkpoint_seq = seq;
                return Ok(());
            }
        }
        rep.notes.push(format!(
            "manifest kept moving or a concurrent compaction raced ({MAX_ATTEMPTS} attempts): \
             nothing merged, rerun"
        ));
        Ok(())
    }

    /// Upload the objects of the source packs in `part` as one pack and mark
    /// them merged, leaving `objects` and `part` empty. A part of fewer than two
    /// sources is dropped: rewriting one pack into one gains nothing, and a
    /// source whose decoded bytes alone pass the spill limit would otherwise
    /// cost an upload per source (#263).
    fn flush_part(
        &self,
        objects: &mut BTreeMap<ObjectId, Vec<u8>>,
        part: &mut Vec<&String>,
        created: &mut Vec<String>,
        merged: &mut BTreeSet<String>,
        opts: &CompactOptions,
    ) -> Result<()> {
        let objects: Vec<(ObjectId, Vec<u8>)> = std::mem::take(objects).into_iter().collect();
        let sources = std::mem::take(part);
        if sources.len() < 2 {
            return Ok(());
        }
        // A dry run reads and splits the same way but uploads nothing, so its
        // counts match what a real run would do.
        created.push(if opts.dry_run {
            String::new()
        } else {
            self.upload_pack(&objects)?.0
        });
        merged.extend(sources.into_iter().cloned());
        Ok(())
    }

    /// Phase 2: delete what is behind the cutoff and what nothing names.
    fn sweep(&self, opts: &CompactOptions, now: SystemTime, rep: &mut CompactReport) -> Result<()> {
        // `modified <= old_before` means "at least prune_expire old".
        let old_before = now
            .checked_sub(opts.prune_expire)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let old = |m: &ObjectMeta| m.modified <= old_before;
        'attempt: for _ in 0..MAX_ATTEMPTS {
            self.refresh()?;
            let (tag, ck_seq, live) = match self.view.borrow().as_ref() {
                Some(v) => (
                    Some(v.tag.clone()),
                    v.manifest.checkpoint_seq,
                    v.packs.iter().cloned().collect::<BTreeSet<String>>(),
                ),
                None => (None, 0, BTreeSet::new()),
            };
            // A lost race on the age record means someone else updated it: replan.
            let Some(Listing {
                ckpts,
                logs,
                by_hash,
                tags,
            }) = self.list_for_sweep(opts, now, rep)?
            else {
                continue;
            };
            let cutoff = ckpts
                .iter()
                .filter(|(s, m)| *s <= ck_seq && old(m))
                .map(|(s, _)| *s)
                .max()
                .unwrap_or(0);
            if cutoff == 0 && ck_seq > 0 {
                rep.notes.push(
                    "no checkpoint is older than the grace window yet: log entries and older \
                     checkpoints are kept"
                        .into(),
                );
            }
            let del_logs: Vec<&ObjectMeta> = logs
                .iter()
                .filter(|(s, _)| cutoff > 0 && *s <= cutoff)
                .map(|(_, m)| m)
                .collect();
            let del_ckpts: Vec<&ObjectMeta> = ckpts
                .iter()
                .filter(|(s, _)| cutoff > 0 && *s < cutoff)
                .map(|(_, m)| m)
                .collect();

            // A hash is a candidate if the live chain does not name it and every
            // one of its objects (a lone `.pack` after an idx-first crash is
            // one) is old enough.
            let unnamed: Vec<(&String, &Vec<ObjectMeta>)> =
                by_hash.iter().filter(|(h, _)| !live.contains(*h)).collect();
            let (aged, young): (Vec<_>, Vec<_>) =
                unnamed.into_iter().partition(|(_, ms)| ms.iter().all(old));
            rep.packs_held_back = young.len();

            let mut del_packs: Vec<(&String, &Vec<ObjectMeta>)> = Vec::new();
            if !aged.is_empty() {
                // Retained structure may still name them: every kept
                // checkpoint and every kept log entry (on-chain or not).
                match self.retained_packs(&ckpts, &logs, cutoff) {
                    Ok(named) => {
                        del_packs = aged
                            .into_iter()
                            .filter(|(h, _)| !named.contains(*h))
                            .collect()
                    }
                    Err(e) => rep
                        .notes
                        .push(format!("packs kept, a retained record is unreadable: {e}")),
                }
            }

            // Log entries and checkpoints behind the cutoff would stay
            // unreachable whatever the manifest does meanwhile (the cutoff only
            // ever grows), but nothing is deleted on a picture the manifest has
            // moved past, so they too wait for the uncached manifest check below
            // (a busy remote can defer their cleanup to a rerun). Counters add up
            // across replans.
            rep.cutoff = rep.cutoff.max(cutoff);
            // Git carrier: pack sizes for the report, from the idx (the listing
            // carries none); a pack with no readable idx counts as 0 bytes.
            let declared = if self.git_carrier {
                self.declared_sizes(&del_packs, rep)
            } else {
                BTreeMap::new()
            };
            if opts.dry_run {
                rep.logs_deleted += del_logs.len();
                rep.checkpoints_deleted += del_ckpts.len();
                rep.bytes_deleted += del_logs
                    .iter()
                    .chain(del_ckpts.iter())
                    .map(|m| m.size)
                    .sum::<u64>();
                rep.packs_deleted += del_packs.len();
                rep.bytes_deleted += pack_bytes(&del_packs, &declared);
                if rep.packs_created > 0 {
                    rep.notes.push(
                        "dry run: the sweep figures describe the bucket as it is now; the merge \
                         and what it retires (its replaced packs, the log up to its new \
                         checkpoint) are not simulated"
                            .into(),
                    );
                }
                return Ok(());
            }
            // The manifest is read without any cache before anything is deleted
            // (a Git carrier answers a conditional read from its freshness
            // window without asking the host): a push that landed since this
            // attempt read the view may name what it would delete.
            if !(del_logs.is_empty() && del_ckpts.is_empty()) {
                if !self.manifest_unmoved(&tag)? {
                    continue;
                }
                rep.logs_deleted += del_logs.len();
                rep.checkpoints_deleted += del_ckpts.len();
                rep.bytes_deleted += del_logs
                    .iter()
                    .chain(del_ckpts.iter())
                    .map(|m| m.size)
                    .sum::<u64>();
                let keys: Vec<&str> = del_logs
                    .iter()
                    .chain(del_ckpts.iter())
                    .map(|m| m.key.as_str())
                    .collect();
                self.delete_keys(&keys, &tags)?;
            }
            // A pack nothing names can still be named by a push that lands
            // while we plan, and the delete loop can run long, so the manifest
            // is looked at before every batch: if it moved before the first, the
            // plan is stale (replan); later, what is left is kept. A push that
            // lands meanwhile may have re-used one of these old packs byte for
            // byte.
            for (i, batch) in del_packs.chunks(PACK_DELETE_BATCH).enumerate() {
                if !self.manifest_unmoved(&tag)? {
                    if i == 0 {
                        continue 'attempt;
                    }
                    rep.notes.push(format!(
                        "the manifest moved during pack deletion: {} unreferenced pack(s) kept, \
                         rerun",
                        del_packs.len() - i * PACK_DELETE_BATCH
                    ));
                    return Ok(());
                }
                rep.packs_deleted += batch.len();
                rep.bytes_deleted += pack_bytes(batch, &declared);
                // idx first: a half-deleted pack is then plain debris.
                for suffix in [".idx", ".pack"] {
                    let keys: Vec<&str> = batch
                        .iter()
                        .flat_map(|(_, ms)| ms.iter())
                        .map(|m| m.key.as_str())
                        .filter(|k| k.ends_with(suffix))
                        .collect();
                    self.delete_keys(&keys, &tags)?;
                }
            }
            return Ok(());
        }
        rep.notes.push(
            "the manifest kept moving during the sweep: what it had not yet deleted (log entries, \
             checkpoints, unreferenced packs) was kept, rerun"
                .into(),
        );
        Ok(())
    }

    /// Whether the manifest is still the one `tag` names (`None`: still absent),
    /// read with no cache so the answer comes from the bucket itself.
    fn manifest_unmoved(&self, tag: &Option<String>) -> Result<bool> {
        Ok(match (tag, self.bucket.get("manifest", None)?) {
            (Some(t), Fetched::New { tag: now, .. }) => *t == now,
            (None, Fetched::Absent) => true,
            _ => false,
        })
    }

    /// Delete `keys`. On a Git carrier each goes with the lease its listing
    /// gave it (`tags`), so a key that was re-created since survives; elsewhere
    /// it is a plain delete. A key with no lease is an error, never an
    /// unleased delete.
    fn delete_keys(&self, keys: &[&str], tags: &BTreeMap<String, String>) -> Result<()> {
        if !self.git_carrier {
            for key in keys {
                self.bucket.delete(key)?;
            }
            return Ok(());
        }
        let items = keys
            .iter()
            .map(|k| match tags.get(*k) {
                Some(t) => Ok((k.to_string(), t.clone())),
                None => Err(Error::Wal(format!(
                    "no lease for {k}: refusing to delete it"
                ))),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(self.bucket.delete_leased(&items)?)
    }

    /// Pack body sizes of `packs` as their idx declares them (a Git carrier's
    /// listing carries no sizes), for the report only. A pack whose idx cannot be
    /// read is left out and counts as 0 bytes; the report says so.
    fn declared_sizes(
        &self,
        packs: &[(&String, &Vec<ObjectMeta>)],
        rep: &mut CompactReport,
    ) -> BTreeMap<String, u64> {
        let mut sizes = BTreeMap::new();
        for (hash, _) in packs {
            if let Ok(Fetched::New { bytes, .. }) = self.bucket.get(&idx_key(hash), None) {
                if let Ok(entries) = parse_index(&bytes) {
                    sizes.insert((*hash).clone(), declared_pack_len(&entries));
                }
            }
        }
        let note = "Git carrier: byte counts are the pack bodies their idx declares; log entries, \
                    checkpoints and idx files count as 0, as does a pack with no readable idx";
        if !packs.is_empty() && !rep.notes.iter().any(|n| n == note) {
            rep.notes.push(note.into());
        }
        sizes
    }

    /// The age record as the bucket holds it, with the tag a compare-and-swap
    /// write must lead with (`None`: no record yet). A record that does not
    /// decode is an error, never "everything is old".
    fn read_sightings(&self, now_secs: u64) -> Result<(Sightings, Option<String>)> {
        match self.bucket.get(sightings::KEY, None)? {
            Fetched::Absent => Ok((Sightings::default(), None)),
            Fetched::New { bytes, tag } => Ok((
                Sightings::decode(&capped("age record", bytes)?, now_secs)?,
                Some(tag),
            )),
            Fetched::Unchanged => Err(Error::Wal(
                "age record: an unconditional read answered Unchanged".into(),
            )),
        }
    }

    /// What this attempt sees in the bucket. On a Git carrier it is one listing
    /// with each key's tag (no value is downloaded), aged by the first-sighting
    /// record: the record is brought up to this listing and written back (when
    /// it changed, and not for a dry run) BEFORE any decision uses it, so a run
    /// at least the grace window after a key was first seen is the earliest that
    /// can delete it. `None` means the record's compare-and-swap lost to another
    /// compactor: replan.
    fn list_for_sweep(
        &self,
        opts: &CompactOptions,
        now: SystemTime,
        rep: &mut CompactReport,
    ) -> Result<Option<Listing>> {
        if !self.git_carrier {
            let metas = |prefix: &str| -> Result<Vec<(u64, ObjectMeta)>> {
                Ok(self
                    .bucket
                    .list_meta(prefix)?
                    .into_iter()
                    .filter_map(|m| seq_of(&m.key).map(|s| (s, m)))
                    .collect())
            };
            let mut by_hash: BTreeMap<String, Vec<ObjectMeta>> = BTreeMap::new();
            for m in self.bucket.list_meta("packs/")? {
                if let Some(h) = hash_of(&m.key) {
                    by_hash.entry(h.to_string()).or_default().push(m);
                }
            }
            return Ok(Some(Listing {
                ckpts: metas("checkpoints/")?,
                logs: metas("log/")?,
                by_hash,
                tags: BTreeMap::new(),
            }));
        }
        let now_secs = unix_secs(now)?;
        let listed = self.bucket.list_tags("")?;
        let (before, record_tag) = self.read_sightings(now_secs)?;
        let seen = before.observe(&listed, now_secs);
        let added = seen.added_since(&before);
        if seen != before {
            if opts.dry_run {
                if added > 0 {
                    rep.notes.push(format!(
                        "dry run: {added} object(s) not seen before would be recorded by a real \
                         run; ages here are a lower bound"
                    ));
                }
            } else if self
                .bucket
                .put_if_tag(sightings::KEY, &seen.encode()?, record_tag.as_deref())?
                .is_none()
            {
                return Ok(None);
            } else if added > 0 {
                let note = format!(
                    "Git carrier: first sighting of {added} object(s) recorded at \
                     refs/sc/{}; an object is deleted only by a run at least the grace window \
                     after that",
                    sightings::KEY
                );
                if !rep.notes.contains(&note) {
                    rep.notes.push(note);
                }
            }
        }
        let aged = |key: &str| {
            SystemTime::UNIX_EPOCH + Duration::from_secs(seen.first_seen(key).unwrap_or(now_secs))
        };
        let (mut ckpts, mut logs) = (Vec::new(), Vec::new());
        let mut by_hash: BTreeMap<String, Vec<ObjectMeta>> = BTreeMap::new();
        let mut tags = BTreeMap::new();
        for (key, oid) in listed {
            let meta = |modified| ObjectMeta {
                key: key.clone(),
                size: 0,
                modified,
            };
            if key.starts_with("checkpoints/") {
                if let Some(s) = seq_of(&key) {
                    ckpts.push((s, meta(aged(&key))));
                }
            } else if key.starts_with("log/") {
                // Never aged: log entries go by sequence behind the cutoff.
                if let Some(s) = seq_of(&key) {
                    logs.push((s, meta(now)));
                }
            } else if let Some(h) = hash_of(&key) {
                by_hash
                    .entry(h.to_string())
                    .or_default()
                    .push(meta(aged(&key)));
            } else {
                continue;
            }
            tags.insert(key, oid);
        }
        Ok(Some(Listing {
            ckpts,
            logs,
            by_hash,
            tags,
        }))
    }

    /// Pack hashes named by structure the sweep keeps: checkpoints with
    /// `seq >= cutoff` and log entries with `seq > cutoff` (everything when
    /// `cutoff` is 0). Any record that fails to decode aborts: deleting packs
    /// on a partial picture is never right.
    fn retained_packs(
        &self,
        ckpts: &[(u64, ObjectMeta)],
        logs: &[(u64, ObjectMeta)],
        cutoff: u64,
    ) -> Result<BTreeSet<String>> {
        let mut named = BTreeSet::new();
        for (seq, m) in ckpts {
            if cutoff == 0 || *seq >= cutoff {
                let Fetched::New { bytes, .. } = self.bucket.get(&m.key, None)? else {
                    continue; // deleted since the listing: no longer retained
                };
                named.extend(
                    Checkpoint::decode(&capped("checkpoint", bytes)?)
                        .map_err(|e| Error::Wal(format!("{}: {e}", m.key)))?
                        .packs,
                );
            }
        }
        for (seq, m) in logs {
            if cutoff == 0 || *seq > cutoff {
                let Fetched::New { bytes, .. } = self.bucket.get(&m.key, None)? else {
                    continue;
                };
                named.extend(
                    LogEntry::decode(&capped("log entry", bytes)?)
                        .map_err(|e| Error::Wal(format!("{}: {e}", m.key)))?
                        .packs,
                );
            }
        }
        Ok(named)
    }
}

#[cfg(test)]
mod tests;
