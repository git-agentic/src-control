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

use super::{capped, BucketTransport};
use crate::error::{Error, Result};
use crate::walfmt::{checkpoint_key, log_key, pack_key, Checkpoint, LogEntry, Manifest, MAX_LIST};
use scl_core::pack::parse_pack_reader;
use scl_core::ObjectId;
use scl_objio::{Fetched, ObjectMeta};
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

/// `packs/<hash>.pack` / `packs/<hash>.idx` -> `<hash>`.
fn hash_of(key: &str) -> Option<&str> {
    let name = key.strip_prefix("packs/")?;
    name.strip_suffix(".pack")
        .or_else(|| name.strip_suffix(".idx"))
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
    /// Safe to run while others push and fetch; run one at a time (concurrent
    /// runs stay correct but waste work). Needs bucket list and delete rights.
    pub fn compact(&self, opts: &CompactOptions) -> Result<CompactReport> {
        let mut rep = CompactReport {
            dry_run: opts.dry_run,
            ..CompactReport::default()
        };
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
            let sizes: BTreeMap<String, u64> = self
                .bucket
                .list_meta("packs/")?
                .into_iter()
                .filter(|m| m.key.ends_with(".pack"))
                .filter_map(|m| hash_of(&m.key).map(|h| (h.to_string(), m.size)))
                .collect();
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
            if opts.dry_run {
                rep.packs_merged = replaced.len();
                rep.packs_created = groups.len();
                return Ok(());
            }
            let mut created = Vec::new();
            for group in &groups {
                let mut objects: BTreeMap<ObjectId, Vec<u8>> = BTreeMap::new();
                let mut decoded = 0u64;
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
                    parse_pack_reader(std::io::Cursor::new(&bytes[..]), |id, obj| {
                        let enc = obj.encode();
                        decoded += enc.len() as u64;
                        objects.insert(id, enc);
                        Ok(())
                    })?;
                    // Compressed sizes bound the group, not the decoded bytes held
                    // here; spill to a pack of its own before RAM balloons.
                    if decoded > opts.group_bytes.saturating_mul(DECODED_FACTOR) {
                        let part: Vec<(ObjectId, Vec<u8>)> =
                            std::mem::take(&mut objects).into_iter().collect();
                        created.push(self.upload_pack(&part)?.0);
                        decoded = 0;
                    }
                }
                if !objects.is_empty() {
                    let objects: Vec<(ObjectId, Vec<u8>)> = objects.into_iter().collect();
                    created.push(self.upload_pack(&objects)?.0);
                }
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
                .filter(|h| !replaced.contains(h) && seen.insert(h.clone()))
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
            if !replaced.is_subset(&packs_now) {
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
                rep.packs_merged = replaced.len();
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

    /// Phase 2: delete what is behind the cutoff and what nothing names.
    fn sweep(&self, opts: &CompactOptions, now: SystemTime, rep: &mut CompactReport) -> Result<()> {
        // `modified <= old_before` means "at least prune_expire old".
        let old_before = now
            .checked_sub(opts.prune_expire)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let old = |m: &ObjectMeta| m.modified <= old_before;
        for _ in 0..MAX_ATTEMPTS {
            self.refresh()?;
            let (tag, ck_seq, live) = match self.view.borrow().as_ref() {
                Some(v) => (
                    Some(v.tag.clone()),
                    v.manifest.checkpoint_seq,
                    v.packs.iter().cloned().collect::<BTreeSet<String>>(),
                ),
                None => (None, 0, BTreeSet::new()),
            };
            let ckpts: Vec<(u64, ObjectMeta)> = self
                .bucket
                .list_meta("checkpoints/")?
                .into_iter()
                .filter_map(|m| seq_of(&m.key).map(|s| (s, m)))
                .collect();
            let logs: Vec<(u64, ObjectMeta)> = self
                .bucket
                .list_meta("log/")?
                .into_iter()
                .filter_map(|m| seq_of(&m.key).map(|s| (s, m)))
                .collect();
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

            // Pack objects by hash; a hash is a candidate if the live chain
            // does not name it and every one of its objects is old enough.
            let mut by_hash: BTreeMap<String, Vec<ObjectMeta>> = BTreeMap::new();
            for m in self.bucket.list_meta("packs/")? {
                if let Some(h) = hash_of(&m.key) {
                    by_hash.entry(h.to_string()).or_default().push(m);
                }
            }
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

            // Log entries and checkpoints behind the cutoff are safe whatever
            // the manifest does meanwhile: the cutoff only ever grows, so they
            // stay unreachable. Counters add up across replans.
            rep.cutoff = rep.cutoff.max(cutoff);
            rep.logs_deleted += del_logs.len();
            rep.checkpoints_deleted += del_ckpts.len();
            rep.bytes_deleted += del_logs
                .iter()
                .chain(del_ckpts.iter())
                .map(|m| m.size)
                .sum::<u64>();
            if !opts.dry_run {
                for m in del_logs.iter().chain(del_ckpts.iter()) {
                    self.bucket.delete(&m.key)?;
                }
            }
            rep.packs_deleted += del_packs.len();
            rep.bytes_deleted += del_packs
                .iter()
                .flat_map(|(_, ms)| ms.iter().map(|m| m.size))
                .sum::<u64>();
            if opts.dry_run {
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
            // A pack nothing names can still be named by a push that lands
            // while we plan: if the manifest moved, replan the pack set
            // (nothing is deleted against a stale picture).
            let unmoved = matches!(
                (&tag, self.bucket.get("manifest", tag.as_deref())?),
                (Some(_), Fetched::Unchanged) | (None, Fetched::Absent)
            );
            if !unmoved {
                rep.packs_deleted -= del_packs.len();
                rep.bytes_deleted -= del_packs
                    .iter()
                    .flat_map(|(_, ms)| ms.iter().map(|m| m.size))
                    .sum::<u64>();
                continue;
            }
            // The delete loop can run long (one request per object), so look at
            // the manifest again between batches: a push that lands meanwhile
            // may have re-used one of these old packs byte for byte.
            for (i, batch) in del_packs.chunks(PACK_DELETE_BATCH).enumerate() {
                if i > 0
                    && !matches!(
                        (&tag, self.bucket.get("manifest", tag.as_deref())?),
                        (Some(_), Fetched::Unchanged) | (None, Fetched::Absent)
                    )
                {
                    let left = del_packs.len() - i * PACK_DELETE_BATCH;
                    rep.packs_deleted -= left;
                    rep.notes.push(format!(
                        "the manifest moved during pack deletion: {left} unreferenced pack(s) \
                         kept, rerun"
                    ));
                    return Ok(());
                }
                for (hash, _) in batch {
                    // idx first: a half-deleted pack is then plain debris.
                    self.bucket.delete(&format!("packs/{hash}.idx"))?;
                    self.bucket.delete(&pack_key(hash))?;
                }
            }
            return Ok(());
        }
        rep.notes.push(
            "the manifest kept moving during the sweep: unreferenced packs were kept, rerun".into(),
        );
        Ok(())
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
