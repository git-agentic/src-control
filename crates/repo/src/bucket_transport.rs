//! A [`Transport`] over an object-store bucket (P36a): immutable packs +
//! parent-linked log entries, one CAS'd manifest as the sole commit point.
//! See ADR-0046 and docs/superpowers/specs/2026-08-26-wal-bucket-backend-design.md.

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::walfmt::{idx_key, log_key, pack_key, LogEntry, Manifest, RefUpdate};
use scl_core::pack::{parse_index, read_object_at_bounded, IndexEntry, PackWriter};
use scl_core::{Object, ObjectId};
use scl_objio::{Bucket, Fetched};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;

/// Reconstructed state of the WAL at one manifest tag: the manifest itself,
/// the flattened branch tips after replaying the parent chain oldest-first,
/// and a lookup from object id to the pack that holds it.
struct WalView {
    /// The bucket's `ETag`/content-hash for the manifest this view was built
    /// from — handed back to `Bucket::get` on the next `refresh` so an
    /// unchanged manifest costs one conditional GET, not a full rebuild.
    tag: String,
    manifest: Manifest,
    /// branch -> tip, after replaying the parent chain oldest-first.
    refs: BTreeMap<String, ObjectId>,
    /// object id -> (pack hash, offset, length), from every on-chain pack's idx.
    index: BTreeMap<ObjectId, (String, u64, u64)>,
}

/// A [`Transport`] whose object graph and refs live entirely in an
/// object-storage bucket (S3-compatible or a local directory), read through
/// the parent-linked WAL log format `walfmt` defines. Readers walk the log
/// backward from the manifest's `head_seq` via `parent_seq` links — a log
/// entry's own claimed `seq` is never trusted for reachability, only for
/// self-consistency (it must match the slot it was read from and its parent
/// must strictly precede it). An entry not on that chain (e.g. a losing
/// racer's orphaned append) is invisible to every read method here, by
/// construction.
pub struct BucketTransport {
    bucket: Box<dyn Bucket>,
    view: RefCell<Option<WalView>>,
    /// Body bytes of the most recently used pack (walk locality: `get_pack`
    /// and repeated `get_object` calls tend to hit the same pack back to
    /// back, so caching the last one avoids re-fetching it byte for byte).
    pack_cache: RefCell<Option<(String, Vec<u8>)>>,
    /// Objects staged by `put_object`, flushed into one pack the next time
    /// `update_ref` is called (mirrors `LocalTransport`'s contract: `put_pack`
    /// writes objects up front, but `put_object` callers stage one at a time
    /// and expect the ref move to be what makes them durable-and-visible).
    staged: RefCell<Vec<(ObjectId, Vec<u8>)>>,
    /// Hashes of packs already uploaded (via `put_pack` or a `put_object`
    /// flush) that the *next* `update_ref` call's log entry must reference.
    /// `update_ref` takes this field's contents at the top of the call into
    /// a call-local copy — it survives that one call's internal CAS retries,
    /// but never leaks into a later, unrelated `update_ref` call on the same
    /// (possibly long-lived, e.g. `wire::serve`-hosted) transport regardless
    /// of whether this call succeeds or fails.
    pending_packs: RefCell<Vec<String>>,
}

/// Untrusted-length guard (P28 parity): refuse any WAL metadata value —
/// manifest, log entry, idx — larger than `MAX_OBJECT_SIZE` before decoding.
/// Pack bodies are exempt from this particular guard (they may legitimately
/// exceed it), but are not unguarded: `object_bytes` reads a pack body via
/// `scl_core::pack::read_object_at_bounded` (not the unbounded
/// `read_object_at` — that path is reserved for `Store`'s own
/// already-verified on-disk packs per ADR-0039's explicit trust split),
/// which caps both the compressed record length and the decompressed output
/// at `MAX_OBJECT_SIZE`, mirroring `parse_pack_reader`'s bounded decode. A
/// hostile bucket pack therefore cannot mount a decompression-bomb DoS
/// against `get_object`/`get_pack`.
fn capped(what: &str, bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.len() > scl_core::MAX_OBJECT_SIZE {
        return Err(Error::Wal(format!(
            "{what} exceeds MAX_OBJECT_SIZE (256 MiB)"
        )));
    }
    Ok(bytes)
}

/// Which bucket backend a [`BucketUrl`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketScheme {
    /// `sc+wal://` — a local directory used as the test/demo backend.
    Wal,
    /// `sc+s3://` — an S3-compatible object store.
    S3,
}

/// A parsed `sc+wal://<dir>` or `sc+s3://<bucket>/<prefix…>` remote URL.
/// `sc+wal` treats everything after the scheme as a directory path (so
/// `sc+wal:///abs/path` and `sc+wal://rel/path` both work); `sc+s3` splits
/// the first path component off as the bucket name and keeps the remainder
/// (possibly empty) as the key prefix.
pub struct BucketUrl {
    pub scheme: BucketScheme,
    pub bucket: String,
    pub prefix: String,
}

impl BucketUrl {
    /// Parse a bucket URL; anything malformed is `InvalidArgument` with a
    /// message naming the URL, so `remote add` can fail fast — including
    /// embedded CR/LF, which would otherwise smuggle extra "lines" into
    /// anything that later logs or shells out with the raw URL.
    pub fn parse(url: &str) -> Result<BucketUrl> {
        let (scheme, rest) = if let Some(r) = url.strip_prefix("sc+wal://") {
            (BucketScheme::Wal, r)
        } else if let Some(r) = url.strip_prefix("sc+s3://") {
            (BucketScheme::S3, r)
        } else {
            return Err(Error::InvalidArgument(format!(
                "not an sc+wal:// or sc+s3:// url: {url}"
            )));
        };
        if rest.is_empty() || rest.chars().any(|c| c == '\r' || c == '\n') {
            return Err(Error::InvalidArgument(format!("bad bucket url: {url}")));
        }
        Ok(match scheme {
            BucketScheme::Wal => BucketUrl {
                scheme,
                bucket: rest.to_string(),
                prefix: String::new(),
            },
            BucketScheme::S3 => {
                let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
                if bucket.is_empty() {
                    return Err(Error::InvalidArgument(format!("bad bucket url: {url}")));
                }
                BucketUrl {
                    scheme,
                    bucket: bucket.to_string(),
                    prefix: prefix.trim_matches('/').to_string(),
                }
            }
        })
    }
}

impl BucketTransport {
    /// Open the right bucket backend for a bucket URL (`sc+wal://` opens a
    /// local-directory test/demo backend, `sc+s3://` opens the real
    /// S3-compatible backend), then wrap it as a `Transport` the same way
    /// [`BucketTransport::from_bucket`] does.
    pub fn open(url: &str) -> Result<BucketTransport> {
        let parsed = BucketUrl::parse(url)?;
        let bucket: Box<dyn Bucket> = match parsed.scheme {
            BucketScheme::Wal => Box::new(scl_objio::DirBucket::open(&parsed.bucket)?),
            BucketScheme::S3 => Box::new(scl_objio::S3Bucket::open(&parsed.bucket, &parsed.prefix)?),
        };
        BucketTransport::from_bucket(bucket)
    }

    /// Open a transport directly over an already-constructed bucket backend.
    /// Fails only if the initial `refresh` (a conditional GET of the
    /// manifest plus a walk of its parent chain) errors — an entirely empty
    /// bucket is a valid, successfully-opened remote with no refs yet.
    pub fn from_bucket(bucket: Box<dyn Bucket>) -> Result<BucketTransport> {
        let t = BucketTransport {
            bucket,
            view: RefCell::new(None),
            pack_cache: RefCell::new(None),
            staged: RefCell::new(Vec::new()),
            pending_packs: RefCell::new(Vec::new()),
        };
        t.refresh()?;
        Ok(t)
    }

    /// One conditional GET of the manifest; on change, rebuild refs + index
    /// by walking parent links head -> 0 (seq numbers are claims; the chain
    /// is the truth — off-chain entries are garbage).
    fn refresh(&self) -> Result<()> {
        let cached_tag = self.view.borrow().as_ref().map(|v| v.tag.clone());
        match self.bucket.get("manifest", cached_tag.as_deref())? {
            Fetched::Unchanged => Ok(()),
            Fetched::Absent => {
                *self.view.borrow_mut() = None;
                Ok(())
            }
            Fetched::New { bytes, tag } => {
                let bytes = capped("manifest", bytes)?;
                let manifest = Manifest::decode(&bytes)?;
                let mut entries = Vec::new();
                let mut seq = manifest.head_seq;
                while seq != 0 {
                    let Fetched::New { bytes, .. } = self.bucket.get(&log_key(seq), None)? else {
                        return Err(Error::Wal(format!(
                            "log entry {seq} referenced by chain but absent"
                        )));
                    };
                    let e = LogEntry::decode(&capped("log entry", bytes)?)?;
                    if e.seq != seq {
                        return Err(Error::Wal(format!(
                            "log entry at {} claims seq {}",
                            seq, e.seq
                        )));
                    }
                    if e.parent_seq >= e.seq {
                        return Err(Error::Wal(format!(
                            "log entry {} has non-decreasing parent {}",
                            e.seq, e.parent_seq
                        )));
                    }
                    seq = e.parent_seq;
                    entries.push(e);
                }
                entries.reverse(); // oldest first
                let mut refs = BTreeMap::new();
                let mut index = BTreeMap::new();
                for e in &entries {
                    for u in &e.updates {
                        crate::refs::validate_branch_name(&u.branch)?;
                        refs.insert(u.branch.clone(), u.new);
                    }
                    for hash in &e.packs {
                        let Fetched::New { bytes, .. } = self.bucket.get(&idx_key(hash), None)?
                        else {
                            return Err(Error::Wal(format!("pack {hash} on chain but idx absent")));
                        };
                        let bytes = capped("pack idx", bytes)?;
                        for IndexEntry { id, offset, length } in parse_index(&bytes)? {
                            index.insert(id, (hash.clone(), offset, length));
                        }
                    }
                }
                *self.view.borrow_mut() = Some(WalView {
                    tag,
                    manifest,
                    refs,
                    index,
                });
                Ok(())
            }
        }
    }

    /// Canonical `encode()` bytes of one object, fetched via its pack
    /// (downloaded once per distinct pack hash and cached for walk locality).
    fn object_bytes(&self, id: &ObjectId) -> Result<Vec<u8>> {
        let (hash, offset, _len) = {
            let view = self.view.borrow();
            let view = view
                .as_ref()
                .ok_or_else(|| Error::Wal("bucket remote is empty".into()))?;
            view.index
                .get(id)
                .cloned()
                .ok_or(Error::CorruptObject(*id))?
        };
        let mut cache = self.pack_cache.borrow_mut();
        if cache.as_ref().map(|(h, _)| h.as_str()) != Some(hash.as_str()) {
            let Fetched::New { bytes, .. } = self.bucket.get(&pack_key(&hash), None)? else {
                return Err(Error::Wal(format!("pack {hash} on chain but body absent")));
            };
            *cache = Some((hash.clone(), bytes));
        }
        let (_, pack) = cache.as_ref().unwrap();
        Ok(read_object_at_bounded(pack, offset, id, scl_core::MAX_OBJECT_SIZE)?.encode())
    }

    /// Upload one pack (+ its idx) content-addressed by BLAKE3 of the pack
    /// bytes, so two callers who happen to pack the identical object set
    /// converge on the same key. `put_new`'s "key already exists" outcome is
    /// success here, not a conflict — identical content, nothing to redo.
    fn upload_pack(&self, objects: &[(ObjectId, Vec<u8>)]) -> Result<(String, Vec<ObjectId>)> {
        let (pack, idx) = scl_core::pack::build_pack(objects)?;
        let hash = hex::encode(blake3::hash(&pack).as_bytes());
        self.bucket.put_new(&pack_key(&hash), &pack)?;
        self.bucket.put_new(&idx_key(&hash), &idx)?;
        Ok((hash, objects.iter().map(|(id, _)| *id).collect()))
    }

    /// Pack and upload everything `put_object` has staged since the last
    /// flush, recording the resulting pack hash as pending. A no-op when
    /// nothing is staged (the common case for a `put_pack`-only caller).
    fn flush_staged(&self) -> Result<()> {
        let staged = std::mem::take(&mut *self.staged.borrow_mut());
        if staged.is_empty() {
            return Ok(());
        }
        // On upload failure (a real bucket can fail transiently: network,
        // 5xx, auth), put the objects back rather than dropping them — a
        // caller that retries `update_ref` must still see them staged, or
        // they'd be silently lost (CLAUDE.md: never silently drop data).
        match self.upload_pack(&staged) {
            Ok((hash, _)) => {
                self.pending_packs.borrow_mut().push(hash);
                Ok(())
            }
            Err(e) => {
                *self.staged.borrow_mut() = staged;
                Err(e)
            }
        }
    }
}

/// `ObjectSource` over the bucket for reachability walks (`get_pack`'s
/// want/have closures).
struct BucketSource<'a>(&'a BucketTransport);
impl crate::reachable::ObjectSource for BucketSource<'_> {
    fn get(&mut self, id: &ObjectId) -> Result<Object> {
        let bytes = self.0.object_bytes(id)?;
        Ok(Object::decode(&bytes)?)
    }
}

impl Transport for BucketTransport {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        self.refresh()?;
        Ok(self
            .view
            .borrow()
            .as_ref()
            .map(|v| v.refs.iter().map(|(b, id)| (b.clone(), *id)).collect())
            .unwrap_or_default())
    }

    fn head_branch(&self) -> Result<String> {
        self.refresh()?;
        self.view
            .borrow()
            .as_ref()
            .map(|v| v.manifest.head_branch.clone())
            .ok_or_else(|| Error::Remote("bucket remote is empty (no manifest)".into()))
    }

    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        self.refresh()?;
        Ok(self
            .view
            .borrow()
            .as_ref()
            .is_some_and(|v| v.index.contains_key(id)))
    }

    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.refresh()?;
        self.object_bytes(id)
    }

    fn get_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        filter: Option<&[String]>,
        out: &mut dyn Write,
    ) -> Result<()> {
        if filter.is_some() {
            return Err(Error::InvalidArgument(
                "partial clone from bucket remotes is not supported yet; clone via a served remote"
                    .into(),
            ));
        }
        self.refresh()?;
        let mut src = BucketSource(self);
        // haves the bucket doesn't know can't shrink the pack — skip them.
        let known_haves: Vec<ObjectId> = {
            let view = self.view.borrow();
            haves
                .iter()
                .copied()
                .filter(|h| view.as_ref().is_some_and(|v| v.index.contains_key(h)))
                .collect()
        };
        let have_set = crate::reachable::reachable_objects(&mut src, &known_haves)?;
        let want_set = crate::reachable::reachable_objects(&mut src, wants)?;
        let ids: Vec<ObjectId> = want_set.difference(&have_set).copied().collect();
        let mut writer = PackWriter::new(out, ids.len() as u32)?;
        for id in &ids {
            let bytes = self.object_bytes(id)?;
            writer.write_object(id, &bytes)?;
        }
        writer.finish()?; // idx discarded — transfer needs the body only
        Ok(())
    }

    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if ObjectId::of(bytes) != *id {
            return Err(Error::CorruptObject(*id));
        }
        self.staged.borrow_mut().push((*id, bytes.to_vec()));
        Ok(())
    }

    fn put_pack(&self, src: &mut dyn std::io::Read) -> Result<Vec<ObjectId>> {
        // Never trust a live incoming stream (P25/ADR-0039 pattern): verify
        // every record's hash as it streams in via the bounded reader parser,
        // then rebuild our own pack from the verified objects rather than
        // uploading the caller's bytes verbatim. `build_pack`'s output is
        // pinned byte-stable for a given object set (core), so the rebuilt
        // pack still content-addresses identically for identical input.
        let mut objects: Vec<(ObjectId, Vec<u8>)> = Vec::new();
        scl_core::pack::parse_pack_reader(src, |id, obj| {
            objects.push((id, obj.encode()));
            Ok(())
        })?;
        let (hash, ids) = self.upload_pack(&objects)?;
        self.pending_packs.borrow_mut().push(hash);
        Ok(ids)
    }

    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        crate::refs::validate_branch_name(branch)?;
        // Everything staged since the last flush becomes one more pending
        // pack before we even look at the manifest, so a retry below never
        // has to re-stage or re-upload it.
        self.flush_staged()?;
        // From here, the packs this call may commit are call-local: take them
        // out of the shared field entirely rather than clearing it only on
        // the success paths. A long-lived transport (e.g. `wire::serve` keeps
        // one instance per session) can see this call fail — NonFastForward,
        // or CAS exhaustion — and then be reused for an unrelated ref update;
        // if `pending_packs` were only cleared on success, that later,
        // unrelated call would commit a log entry citing packs this call
        // never landed, violating the invariant that a log entry's `packs`
        // list is exactly the packs its own ref updates need. Every exit from
        // this function — success, failure, or the loop below — simply lets
        // `pending` go out of scope; the packs themselves stay uploaded in
        // the bucket regardless (content-addressed, inert orphan garbage if
        // never referenced — correct per spec, compaction is a later phase).
        let pending: Vec<String> = std::mem::take(&mut *self.pending_packs.borrow_mut());
        const MAX_CAS_RETRIES: u32 = 16;
        for _ in 0..MAX_CAS_RETRIES {
            self.refresh()?;
            let (current, prev_tag, head_seq, checkpoint_seq, head_branch) = {
                let view = self.view.borrow();
                match view.as_ref() {
                    Some(v) => (
                        v.refs.get(branch).copied(),
                        Some(v.tag.clone()),
                        v.manifest.head_seq,
                        v.manifest.checkpoint_seq,
                        v.manifest.head_branch.clone(),
                    ),
                    None => (None, None, 0, 0, branch.to_string()),
                }
            };
            // Trait doc: setting the ref to the value it already has
            // succeeds regardless of `expected_old` — check this before the
            // fast-forward comparison below.
            if current.as_ref() == Some(id) {
                return Ok(());
            }
            if current.as_ref() != expected_old {
                return Err(Error::NonFastForward);
            }
            // Claim a log slot for this attempt. `put_new` on `log/<seq>` is
            // the claim: if another writer already landed that seq, we didn't
            // win it and try the next one — the entry we didn't win becomes
            // permanent off-chain garbage (never referenced by any manifest,
            // never read by `refresh`), which is fine, it costs one object.
            let entry = LogEntry {
                seq: 0, // overwritten per candidate in the claim loop below
                parent_seq: head_seq,
                packs: pending.clone(),
                updates: vec![RefUpdate {
                    branch: branch.to_string(),
                    old: current,
                    new: *id,
                }],
            };
            let mut try_seq = head_seq + 1;
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
            let manifest = Manifest {
                head_seq: seq,
                checkpoint_seq,
                head_branch,
            };
            if self
                .bucket
                .put_if_tag("manifest", &manifest.encode(), prev_tag.as_deref())?
                .is_some()
            {
                // Committed. The log entry we just claimed is now on-chain;
                // pull the fresh view (cheap: one conditional GET, since our
                // own write just changed the tag).
                self.refresh()?;
                return Ok(());
            }
            // Lost the manifest CAS: someone else's append won the race. Our
            // just-claimed log entry is now off-chain garbage too (it chains
            // from a parent that's no longer the head). Loop back to
            // `refresh()`: if this branch's tip moved off `expected_old` we
            // hit `NonFastForward` above; otherwise (a different branch or an
            // unrelated pack landed) we retry with a fresh entry claimed
            // under the new parent — `pending` (this call's local copy)
            // still lists our packs, so nothing is re-uploaded.
        }
        Err(Error::Remote(
            "manifest cas contention: gave up after 16 attempts".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Transport;
    use crate::walfmt::{idx_key, log_key, pack_key, LogEntry, Manifest, RefUpdate};
    use scl_core::ObjectId;
    use scl_objio::{Bucket, DirBucket};

    /// Build pack+idx bytes for the given objects (reuses core's builder).
    fn pack_of(objects: &[(ObjectId, Vec<u8>)]) -> (String, Vec<u8>, Vec<u8>) {
        let (pack, idx) = scl_core::pack::build_pack(objects).unwrap();
        let hash = hex::encode(blake3::hash(&pack).as_bytes());
        (hash, pack, idx)
    }

    /// A minimal one-commit object set: blob → tree → snapshot, exactly as a
    /// real repo would store them. Reuse the object constructors the repo
    /// crate already uses in its own tests (see sync.rs tests for the
    /// canonical way to mint a commit); returns (tip, objects). `tag`
    /// disambiguates the scratch repo path between the two call sites below
    /// — both share this process id, and `cargo test` runs tests on parallel
    /// threads within one process by default, so a bare pid-keyed path would
    /// let two callers race on the same directory (house pattern: see
    /// `transport.rs`'s `tmp_remote(tag)`).
    fn tiny_history(tag: &str) -> (ObjectId, Vec<(ObjectId, Vec<u8>)>) {
        let root = std::env::temp_dir().join(format!("scl-bt-hist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"hello wal").unwrap();
        let tip = repo.commit("t", "c1").unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = crate::reachable::reachable_objects(&mut *store, &[tip]).unwrap();
        let objects = ids
            .iter()
            .map(|id| (*id, store.get(id).unwrap().encode()))
            .collect();
        drop(store);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
        (tip, objects)
    }

    /// Like `tiny_history`, but with caller-chosen file content. `tiny_history`
    /// hardcodes content/author/message, so two calls close enough in time to
    /// land the same commit-timestamp second produce byte-identical Snapshot
    /// objects (same root, same empty parents) — fine for the read-half tests
    /// above, which only need *a* valid history, but wrong for a test that
    /// needs two genuinely distinct object sets (and thus distinct pack
    /// hashes) to tell "referenced" apart from "coincidentally identical".
    fn tiny_history_distinct(tag: &str, content: &[u8]) -> (ObjectId, Vec<(ObjectId, Vec<u8>)>) {
        let root = std::env::temp_dir().join(format!("scl-bt-hist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), content).unwrap();
        let tip = repo.commit("t", "c1").unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = crate::reachable::reachable_objects(&mut *store, &[tip]).unwrap();
        let objects = ids
            .iter()
            .map(|id| (*id, store.get(id).unwrap().encode()))
            .collect();
        drop(store);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
        (tip, objects)
    }

    #[test]
    fn reads_refs_objects_and_packs_from_a_hand_built_wal() {
        let broot = std::env::temp_dir().join(format!("scl-bt-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let bucket = DirBucket::open(&broot).unwrap();

        let (tip, objects) = tiny_history("read");
        let (hash, pack, idx) = pack_of(&objects);
        assert!(bucket.put_new(&pack_key(&hash), &pack).unwrap());
        assert!(bucket.put_new(&idx_key(&hash), &idx).unwrap());
        let entry = LogEntry {
            seq: 1,
            parent_seq: 0,
            packs: vec![hash.clone()],
            updates: vec![RefUpdate {
                branch: "main".into(),
                old: None,
                new: tip,
            }],
        };
        assert!(bucket.put_new(&log_key(1), &entry.encode()).unwrap());
        let m = Manifest {
            head_seq: 1,
            checkpoint_seq: 0,
            head_branch: "main".into(),
        };
        bucket
            .put_if_tag("manifest", &m.encode(), None)
            .unwrap()
            .unwrap();

        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert_eq!(t.head_branch().unwrap(), "main");
        assert!(t.has_object(&tip).unwrap());
        let bytes = t.get_object(&tip).unwrap();
        assert_eq!(ObjectId::of(&bytes), tip);
        // get_pack: full closure with no haves reproduces every object
        let mut out = Vec::new();
        t.get_pack(&[tip], &[], None, &mut out).unwrap();
        let got = scl_core::pack::parse_pack(&out).unwrap();
        assert_eq!(got.len(), objects.len());
        // filter is refused loudly, not ignored
        let filt = vec!["src/".to_string()];
        assert!(t
            .get_pack(&[tip], &[], Some(&filt), &mut Vec::new())
            .is_err());
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    #[test]
    fn empty_bucket_lists_no_refs_and_head_branch_errors() {
        let broot = std::env::temp_dir().join(format!("scl-bt-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t.list_refs().unwrap(), Vec::<(String, ObjectId)>::new());
        assert!(t.head_branch().is_err());
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    #[test]
    fn off_chain_log_entries_are_ignored() {
        // manifest head=1; a stray log/2 (orphan from a crashed/losing pusher)
        // must not affect refs.
        let broot = std::env::temp_dir().join(format!("scl-bt-orphan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let bucket = DirBucket::open(&broot).unwrap();
        let (tip, objects) = tiny_history("orphan");
        let (hash, pack, idx) = pack_of(&objects);
        bucket.put_new(&pack_key(&hash), &pack).unwrap();
        bucket.put_new(&idx_key(&hash), &idx).unwrap();
        let e1 = LogEntry {
            seq: 1,
            parent_seq: 0,
            packs: vec![hash],
            updates: vec![RefUpdate {
                branch: "main".into(),
                old: None,
                new: tip,
            }],
        };
        bucket.put_new(&log_key(1), &e1.encode()).unwrap();
        let orphan = LogEntry {
            seq: 2,
            parent_seq: 1,
            packs: vec![],
            updates: vec![RefUpdate {
                branch: "evil".into(),
                old: None,
                new: tip,
            }],
        };
        bucket.put_new(&log_key(2), &orphan.encode()).unwrap();
        let m = Manifest {
            head_seq: 1,
            checkpoint_seq: 0,
            head_branch: "main".into(),
        };
        bucket
            .put_if_tag("manifest", &m.encode(), None)
            .unwrap()
            .unwrap();

        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    #[test]
    fn push_via_trait_round_trips_into_a_fresh_bucket() {
        let broot = std::env::temp_dir().join(format!("scl-bt-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();

        let (tip, objects) = tiny_history("write");
        // exactly what sync::push does: pack, then CAS'd ref update
        let (pack, _idx) = scl_core::pack::build_pack(&objects).unwrap();
        let ids = t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        assert_eq!(ids.len(), objects.len());
        t.update_ref("main", &tip, None).unwrap();

        // a second transport sees it
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t2.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert_eq!(t2.head_branch().unwrap(), "main");
        assert!(t2.has_object(&tip).unwrap());
        drop((t, t2));
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    #[test]
    fn update_ref_honors_expected_old_semantics() {
        let broot = std::env::temp_dir().join(format!("scl-bt-cas-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (tip, objects) = tiny_history("cas");
        let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
        t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        t.update_ref("main", &tip, None).unwrap();
        // stale expected_old (None while the branch exists) => NonFastForward
        let other = ObjectId::of(b"not the tip");
        assert!(matches!(
            t.update_ref("main", &other, None),
            Err(Error::NonFastForward)
        ));
        // setting to the value it already has succeeds regardless of expected_old (trait doc)
        t.update_ref("main", &tip, None).unwrap();
        t.update_ref("main", &tip, Some(&other)).unwrap();
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    #[test]
    fn put_object_stages_and_update_ref_commits_them() {
        let broot = std::env::temp_dir().join(format!("scl-bt-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (tip, objects) = tiny_history("stage");
        for (id, bytes) in &objects {
            t.put_object(id, bytes).unwrap();
        }
        // corrupt bytes are rejected at staging time
        assert!(t.put_object(&tip, b"garbage").is_err());
        t.update_ref("main", &tip, None).unwrap();
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert!(t2.has_object(&tip).unwrap());
        drop((t, t2));
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    #[test]
    fn abandoned_pending_packs_do_not_leak_into_a_later_unrelated_update_ref() {
        // Regression for a review finding: `pending_packs` must not survive
        // a failed `update_ref` call into a later, unrelated `update_ref` on
        // the same (long-lived, e.g. `wire::serve`-hosted) transport
        // instance — the WAL's per-entry invariant is that a log entry's
        // `packs` list is exactly the packs its own ref updates need.
        let broot = std::env::temp_dir().join(format!("scl-bt-noleak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();

        // Land "main" -> tip1 normally, so a later push to "main" can fail
        // fast-forward.
        let (tip1, objects1) = tiny_history_distinct("noleak-main", b"main content");
        let (pack1, _) = scl_core::pack::build_pack(&objects1).unwrap();
        t.put_pack(&mut std::io::Cursor::new(pack1)).unwrap();
        t.update_ref("main", &tip1, None).unwrap();

        // Stage a second, unrelated pack, then attempt an update to "main"
        // that must fail NonFastForward *with pending packs non-empty* — the
        // exact condition the existing tests never exercised (they only hit
        // NonFastForward with nothing pending).
        let (_tip2, objects2) = tiny_history_distinct("noleak-abandoned", b"abandoned content");
        let (pack2, _) = scl_core::pack::build_pack(&objects2).unwrap();
        let abandoned_hash = hex::encode(blake3::hash(&pack2).as_bytes());
        t.put_pack(&mut std::io::Cursor::new(pack2)).unwrap();
        let bogus = ObjectId::of(b"not the real tip");
        assert!(matches!(
            t.update_ref("main", &bogus, None),
            Err(Error::NonFastForward)
        ));

        // A different, unrelated branch, on the SAME instance, with its own
        // freshly-staged pack — this call must succeed and must commit only
        // its own pack, never the one abandoned by the failed call above.
        let (tip3, objects3) = tiny_history_distinct("noleak-other", b"other content");
        let (pack3, _) = scl_core::pack::build_pack(&objects3).unwrap();
        let other_hash = hex::encode(blake3::hash(&pack3).as_bytes());
        t.put_pack(&mut std::io::Cursor::new(pack3)).unwrap();
        t.update_ref("other", &tip3, None).unwrap();

        // Decode the committed head log entry straight from the bucket and
        // check its `packs` list directly, independent of the transport's
        // own (already-passing) read half.
        let inspect = DirBucket::open(&broot).unwrap();
        let Fetched::New { bytes, .. } = inspect.get("manifest", None).unwrap() else {
            panic!("manifest must exist after two successful update_ref calls")
        };
        let manifest = Manifest::decode(&bytes).unwrap();
        let Fetched::New { bytes, .. } = inspect.get(&log_key(manifest.head_seq), None).unwrap()
        else {
            panic!("head log entry must exist")
        };
        let head_entry = LogEntry::decode(&bytes).unwrap();
        assert!(
            !head_entry.packs.contains(&abandoned_hash),
            "committed entry must not reference the pack abandoned by the failed call"
        );
        assert_eq!(
            head_entry.packs,
            vec![other_hash],
            "committed entry must reference exactly this call's own pack"
        );

        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    #[test]
    fn clone_push_fetch_round_trip_over_sc_wal_url() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-e2e-bucket-{pid}"));
        let a_root = std::env::temp_dir().join(format!("scl-bt-e2e-a-{pid}"));
        let b_root = std::env::temp_dir().join(format!("scl-bt-e2e-b-{pid}"));
        for d in [&broot, &a_root, &b_root] {
            let _ = std::fs::remove_dir_all(d);
        }
        std::fs::create_dir_all(&a_root).unwrap();
        let url = format!("sc+wal://{}", broot.display());

        // A: init, commit, add bucket remote, push (creates the bucket repo)
        let a = crate::repo::Repo::init(&a_root).unwrap();
        std::fs::write(a_root.join("f.txt"), b"one").unwrap();
        let tip1 = a.commit("t", "c1").unwrap();
        a.remote_add("origin", &url).unwrap();
        assert_eq!(a.push("origin").unwrap(), tip1);

        // B: clone from the bucket
        let b = crate::repo::Repo::clone_url(&url, &b_root).unwrap();
        assert_eq!(b.head_tip().unwrap(), Some(tip1));
        assert_eq!(std::fs::read(b_root.join("f.txt")).unwrap(), b"one");

        // B commits and pushes; A fetches and sees it
        std::fs::write(b_root.join("g.txt"), b"two").unwrap();
        let tip2 = b.commit("t", "c2").unwrap();
        b.push("origin").unwrap();
        drop(b);
        let fetched = a.fetch("origin").unwrap();
        assert!(fetched.iter().any(|(br, id)| br == "main" && *id == tip2));

        // stale push from A (still at tip1 + its own commit) => NonFastForward
        std::fs::write(a_root.join("h.txt"), b"three").unwrap();
        a.commit("t", "c3").unwrap();
        assert!(matches!(a.push("origin"), Err(Error::NonFastForward)));
        drop(a);
        for d in [&broot, &a_root, &b_root] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn bucket_url_parses_and_rejects() {
        let u = BucketUrl::parse("sc+s3://mybucket/team/repo").unwrap();
        assert!(matches!(u.scheme, BucketScheme::S3));
        assert_eq!(u.bucket, "mybucket");
        assert_eq!(u.prefix, "team/repo");
        let u = BucketUrl::parse("sc+s3://mybucket").unwrap();
        assert_eq!(u.prefix, "");
        let u = BucketUrl::parse("sc+wal:///tmp/x").unwrap();
        assert!(matches!(u.scheme, BucketScheme::Wal));
        assert!(BucketUrl::parse("sc+s3://").is_err());
        assert!(BucketUrl::parse("sc+s3://b\nad/x").is_err());
        assert!(BucketUrl::parse("http://nope").is_err());
    }

    /// P36a acceptance proof #1: two threads race `update_ref("main", ..)`
    /// from the same `expected_old`, targeting different (fake) tips. The
    /// bucket's `put_if_tag` CAS is the only serialization point — exactly
    /// one racer must win and the other must see a clean `NonFastForward`,
    /// never a deadlock, a double-commit, or a corrupt manifest.
    #[test]
    fn racing_pushes_same_branch_one_wins_one_gets_non_fast_forward() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-race-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        // seed: one commit on main
        let t0 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (base, objects) = tiny_history("race-seed");
        let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
        t0.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        t0.update_ref("main", &base, None).unwrap();
        drop(t0);

        // two threads race an update from the same expected_old to different tips.
        // A barrier forces both threads into `update_ref` at the same instant —
        // without it, the OS could simply run racer-a to completion before
        // racer-b's thread is even scheduled, and the (1, 1) result below
        // would hold trivially with the manifest CAS never actually contended.
        let mk_tip = |tag: &[u8]| {
            let obj = Object::blob(tag.to_vec()); // any distinct object works as a fake tip
            (obj.id(), obj.encode())
        };
        let gate = std::sync::Barrier::new(2);
        let results: Vec<Result<()>> = std::thread::scope(|s| {
            let handles: Vec<_> = [b"racer-a".as_slice(), b"racer-b".as_slice()]
                .into_iter()
                .map(|tag| {
                    let broot = broot.clone();
                    let gate = &gate;
                    s.spawn(move || {
                        let t = BucketTransport::from_bucket(Box::new(
                            DirBucket::open(&broot).unwrap(),
                        ))
                        .unwrap();
                        let (tip, bytes) = mk_tip(tag);
                        t.put_object(&tip, &bytes).unwrap();
                        gate.wait();
                        t.update_ref("main", &tip, Some(&base))
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let wins = results.iter().filter(|r| r.is_ok()).count();
        let nffs = results
            .iter()
            .filter(|r| matches!(r, Err(Error::NonFastForward)))
            .count();
        assert_eq!(
            (wins, nffs),
            (1, 1),
            "exactly one winner and one clean refusal: {results:?}"
        );
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    /// P36a acceptance proof #2: 8 threads push to 8 *distinct* branches
    /// concurrently with no external coordinator. Contention is at the
    /// manifest-CAS level only (every push races the same `manifest` key even
    /// though the branches don't conflict), so every push must eventually
    /// land via the retry loop.
    #[test]
    fn fleet_hammer_distinct_branches_all_land_without_coordinator() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-fleet-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        const N: usize = 8;
        // A barrier forces all N threads to call `update_ref` at essentially
        // the same instant — without it, short-lived threads could finish
        // one at a time with the OS never actually overlapping them, and
        // "all N land" would hold even against a broken retry loop that was
        // never exercised under real contention.
        let gate = std::sync::Barrier::new(N);
        std::thread::scope(|s| {
            for i in 0..N {
                let broot = broot.clone();
                let gate = &gate;
                s.spawn(move || {
                    let t = BucketTransport::from_bucket(Box::new(
                        DirBucket::open(&broot).unwrap(),
                    ))
                    .unwrap();
                    let obj = Object::blob(format!("agent-{i}").into_bytes());
                    t.put_object(&obj.id(), &obj.encode()).unwrap();
                    gate.wait();
                    // distinct branches: contention is manifest-level only, so
                    // every one must eventually land via CAS retry.
                    t.update_ref(&format!("work-{i}"), &obj.id(), None).unwrap();
                });
            }
        });
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let refs = t.list_refs().unwrap();
        assert_eq!(refs.len(), N, "all {N} agent branches present: {refs:?}");
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }

    /// P36a acceptance proof #3: a pusher that died after writing its pack +
    /// log entry, but before the manifest CAS, leaves debris that must be
    /// invisible to every reader (the manifest never points at it) — and a
    /// later, live push must step over the claimed seq rather than colliding
    /// with it.
    #[test]
    fn crash_debris_before_the_cas_is_invisible_and_later_pushes_step_over_it() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-crash-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        let bucket = DirBucket::open(&broot).unwrap();
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (tip, objects) = tiny_history("crash-seed");
        let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
        t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        t.update_ref("main", &tip, None).unwrap();

        // simulate a pusher that died after pack + log entry, before the CAS:
        let orphan_obj = Object::blob(b"never committed".to_vec());
        let (opack, oidx) =
            scl_core::pack::build_pack(&[(orphan_obj.id(), orphan_obj.encode())]).unwrap();
        let ohash = hex::encode(blake3::hash(&opack).as_bytes());
        bucket.put_new(&pack_key(&ohash), &opack).unwrap();
        bucket.put_new(&idx_key(&ohash), &oidx).unwrap();
        bucket
            .put_new(
                &log_key(2),
                &LogEntry {
                    seq: 2,
                    parent_seq: 1,
                    packs: vec![ohash],
                    updates: vec![RefUpdate {
                        branch: "doomed".into(),
                        old: None,
                        new: orphan_obj.id(),
                    }],
                }
                .encode(),
            )
            .unwrap();

        // invisible to readers…
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t2.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert!(!t2.has_object(&orphan_obj.id()).unwrap());
        // …and a live push steps over the claimed seq 2 (lands at 3+) and works.
        let next = Object::blob(b"after crash".to_vec());
        t2.put_object(&next.id(), &next.encode()).unwrap();
        t2.update_ref("recovered", &next.id(), None).unwrap();
        let t3 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let refs = t3.list_refs().unwrap();
        assert!(refs.contains(&("recovered".to_string(), next.id())));
        assert!(!refs.iter().any(|(b, _)| b == "doomed"));

        // Prove the "steps over" part directly, not just its visible effect:
        // the live push's claim loop must have found `log/2` already taken
        // by the orphan (a real collision) and landed at seq 3+ instead of
        // silently overwriting it — inspect the bucket straight, independent
        // of the transport's own (already-passing) read half.
        let inspect = DirBucket::open(&broot).unwrap();
        let Fetched::New { bytes, .. } = inspect.get("manifest", None).unwrap() else {
            panic!("manifest must exist after the live push")
        };
        let manifest = Manifest::decode(&bytes).unwrap();
        assert!(
            manifest.head_seq >= 3,
            "live push must claim a seq past the crashed pusher's seq 2, got {}",
            manifest.head_seq
        );
        let Fetched::New { bytes, .. } = inspect.get(&log_key(2), None).unwrap() else {
            panic!("the orphan's log/2 entry must still be present, untouched, as off-chain garbage")
        };
        let untouched = LogEntry::decode(&bytes).unwrap();
        assert_eq!(
            untouched.updates,
            vec![RefUpdate {
                branch: "doomed".into(),
                old: None,
                new: orphan_obj.id(),
            }],
            "the live push must never overwrite the claimed-but-uncommitted log/2 slot"
        );

        drop((t, t2, t3));
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
    }
}
