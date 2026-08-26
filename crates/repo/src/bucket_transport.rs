//! A [`Transport`] over an object-store bucket (P36a): immutable packs +
//! parent-linked log entries, one CAS'd manifest as the sole commit point.
//! See ADR-0046 and docs/superpowers/specs/2026-08-26-wal-bucket-backend-design.md.

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::walfmt::{idx_key, log_key, pack_key, LogEntry, Manifest};
use scl_core::pack::{parse_index, read_object_at, IndexEntry, PackWriter};
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
    // Task 5 adds: staged objects + pending pack hashes.
}

/// Untrusted-length guard (P28 parity): refuse any WAL metadata value —
/// manifest, log entry, idx — larger than `MAX_OBJECT_SIZE` before decoding.
/// Pack bodies are exempt (they may legitimately exceed it), but that leaves
/// a known gap: `object_bytes` reads a pack body via `read_object_at`, whose
/// `decompress_and_decode` calls `zstd::decode_all` with no output-size
/// bound (unlike `parse_pack_reader`'s streaming decoder in
/// `crates/core/src/pack.rs`, which caps both compressed and decompressed
/// length at `MAX_OBJECT_SIZE`). A hostile bucket pack can therefore mount a
/// decompression-bomb DoS against this transport's single-object reads. Out
/// of scope for this task (would mean changing `core`); tracked in
/// ROADMAP.md → Deferred.
fn capped(what: &str, bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.len() > scl_core::MAX_OBJECT_SIZE {
        return Err(Error::Wal(format!(
            "{what} exceeds MAX_OBJECT_SIZE (256 MiB)"
        )));
    }
    Ok(bytes)
}

impl BucketTransport {
    /// Open a transport directly over an already-constructed bucket backend.
    /// Fails only if the initial `refresh` (a conditional GET of the
    /// manifest plus a walk of its parent chain) errors — an entirely empty
    /// bucket is a valid, successfully-opened remote with no refs yet.
    pub fn from_bucket(bucket: Box<dyn Bucket>) -> Result<BucketTransport> {
        let t = BucketTransport {
            bucket,
            view: RefCell::new(None),
            pack_cache: RefCell::new(None),
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
        Ok(read_object_at(pack, offset, id)?.encode())
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

    fn put_object(&self, _id: &ObjectId, _bytes: &[u8]) -> Result<()> {
        Err(Error::Wal("bucket write half lands in Task 5".into()))
    }
    fn update_ref(
        &self,
        _branch: &str,
        _id: &ObjectId,
        _expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        Err(Error::Wal("bucket write half lands in Task 5".into()))
    }
    fn put_pack(&self, _src: &mut dyn std::io::Read) -> Result<Vec<ObjectId>> {
        Err(Error::Wal("bucket write half lands in Task 5".into()))
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
}
