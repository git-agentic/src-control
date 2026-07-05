//! Content-addressed object store with a bounded memory budget.
//!
//! Trees, snapshots, and secrets are small and always kept resident. Blob
//! content is bounded by a configurable byte budget; when an insert would
//! exceed it, the coldest reconstructible blobs are evicted (LRU). What happens
//! to an evicted blob depends on the [`Backend`]:
//!
//! - **Ephemeral, no spill** ([`SpillPolicy::Disallow`]): an over-budget insert
//!   fails loudly with [`Error::BudgetExceeded`] rather than thrashing.
//! - **Ephemeral, spill** ([`SpillPolicy::SpillTo`]): evicted blobs are written
//!   to a content-addressed temp directory and rehydrated on demand; that
//!   directory is removed on `Drop`, so a session leaves zero residual files.
//! - **Persistent** ([`Backend::Persistent`]): every object is written through
//!   to a durable objects directory on `put`; eviction merely drops the RAM copy
//!   (disk is authoritative) and a read-miss rehydrates from disk. The directory
//!   is never removed on `Drop`.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::Object;

/// zstd level for on-disk object payloads. 3 is the zstd default: fast, solid
/// ratio. The level is a storage detail — it never affects the content address,
/// which is BLAKE3 of the *decompressed* canonical bytes.
const COMPRESSION_LEVEL: i32 = 3;

/// What to do when the blob budget is exhausted (ephemeral mode only).
#[derive(Clone, Debug)]
pub enum SpillPolicy {
    /// Never spill: an over-budget insert returns `BudgetExceeded`.
    Disallow,
    /// Spill evicted blobs to this directory (created lazily, removed on drop).
    SpillTo(PathBuf),
}

/// Where objects live. Ephemeral is the Phase 1 RAM-first store; Persistent
/// write-throughs every object to a durable `.sc/objects/` directory.
#[derive(Clone, Debug)]
pub enum Backend {
    /// RAM + optional ephemeral spill; the spill dir is removed on `Drop`.
    Ephemeral(SpillPolicy),
    /// RAM + write-through to this objects directory; never removed on `Drop`.
    Persistent(PathBuf),
}

#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Maximum resident blob bytes. Trees/snapshots/secrets are not counted.
    pub budget_bytes: usize,
    /// Where objects live and what eviction does: RAM-only/spill (ephemeral) or
    /// durable write-through (persistent). See [`Backend`].
    pub backend: Backend,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            budget_bytes: 512 * 1024 * 1024,
            backend: Backend::Ephemeral(SpillPolicy::Disallow),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreStats {
    pub resident_blob_bytes: usize,
    pub budget_bytes: usize,
    pub resident_objects: usize,
    pub spilled_blobs: usize,
    pub evictions: u64,
    pub rehydrations: u64,
}

struct Resident {
    obj: Object,
    blob_size: usize,
    last_used: u64,
}

/// Where a packed object lives: which pack file and its record offset.
#[derive(Clone)]
struct PackLoc {
    pack_path: PathBuf,
    offset: u64,
}

/// The object store. Cheap to share base content across many worktrees because
/// blob bytes live behind `Arc`.
pub struct Store {
    cfg: StoreConfig,
    resident: HashMap<ObjectId, Resident>,
    /// Blobs evicted to spill, with their byte size for budget re-admission.
    spilled: HashMap<ObjectId, usize>,
    /// id -> pack location, union over all loaded packs (persistent only).
    pack_index: HashMap<ObjectId, PackLoc>,
    clock: u64,
    resident_blob_bytes: usize,
    spill_dir_ready: bool,
    evictions: u64,
    rehydrations: u64,
}

impl Store {
    pub fn new(cfg: StoreConfig) -> Self {
        Store {
            cfg,
            resident: HashMap::new(),
            spilled: HashMap::new(),
            pack_index: HashMap::new(),
            clock: 0,
            resident_blob_bytes: 0,
            spill_dir_ready: false,
            evictions: 0,
            rehydrations: 0,
        }
    }

    pub fn with_budget(budget_bytes: usize) -> Self {
        Store::new(StoreConfig { budget_bytes, ..Default::default() })
    }

    /// Open (or create) a persistent store backed by `objects_dir`.
    pub fn open_persistent(objects_dir: impl Into<PathBuf>, budget_bytes: usize) -> Result<Self> {
        let dir = objects_dir.into();
        std::fs::create_dir_all(&dir)?;
        let mut store = Store::new(StoreConfig {
            budget_bytes,
            backend: Backend::Persistent(dir),
        });
        store.reload_packs()?;
        Ok(store)
    }

    fn persistent_dir(&self) -> Option<&PathBuf> {
        match &self.cfg.backend {
            Backend::Persistent(p) => Some(p),
            Backend::Ephemeral(_) => None,
        }
    }

    pub fn stats(&self) -> StoreStats {
        StoreStats {
            resident_blob_bytes: self.resident_blob_bytes,
            budget_bytes: self.cfg.budget_bytes,
            resident_objects: self.resident.len(),
            spilled_blobs: self.spilled.len(),
            evictions: self.evictions,
            rehydrations: self.rehydrations,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Insert an object, returning its content address. Idempotent. In
    /// persistent mode the object is durably written before returning.
    pub fn put(&mut self, obj: Object) -> Result<ObjectId> {
        let id = obj.id();
        if self.resident.contains_key(&id) || self.spilled.contains_key(&id) {
            return Ok(id);
        }
        // Persistent: an object already durable on disk (e.g. evicted from RAM)
        // is a no-op. Re-admitting it here would double-count its bytes against
        // the budget; instead leave it on disk and let `get` rehydrate on demand.
        if self.persistent_dir().is_some() && self.existing_loose_path(&id).is_some() {
            // Already durable on disk (e.g. evicted from RAM); don't re-admit.
            return Ok(id);
        }
        // Persistent: write-through (idempotent) before admitting to RAM.
        if self.persistent_dir().is_some() {
            self.write_object_file(&id, &obj.encode())?;
        }
        let blob_size = obj.blob_size();
        if blob_size > 0 {
            self.ensure_capacity(blob_size, &id)?;
            self.resident_blob_bytes += blob_size;
        }
        let t = self.tick();
        self.resident.insert(id, Resident { obj, blob_size, last_used: t });
        Ok(id)
    }

    /// Fetch an object, rehydrating from the backend on a miss.
    pub fn get(&mut self, id: &ObjectId) -> Result<Object> {
        if let Some(r) = self.resident.get_mut(id) {
            r.last_used = {
                self.clock += 1;
                self.clock
            };
            return Ok(r.obj.clone());
        }
        // Ephemeral spill rehydrate (blobs only).
        if let Some(&size) = self.spilled.get(id) {
            let obj = self.read_spill(id)?;
            self.ensure_capacity(size, id)?;
            self.spilled.remove(id);
            self.resident_blob_bytes += size;
            self.rehydrations += 1;
            let t = self.tick();
            self.resident.insert(*id, Resident { obj: obj.clone(), blob_size: size, last_used: t });
            return Ok(obj);
        }
        // Persistent backend: load any object kind from disk (loose, else pack).
        if self.persistent_dir().is_some() {
            let obj = match self.existing_loose_path(id) {
                Some(_) => self.read_object_file(id)?,
                None => self.read_pack_object(id)?,
            };
            let blob_size = obj.blob_size();
            if blob_size > 0 {
                self.ensure_capacity(blob_size, id)?;
                self.resident_blob_bytes += blob_size;
            }
            self.rehydrations += 1;
            let t = self.tick();
            self.resident.insert(*id, Resident { obj: obj.clone(), blob_size, last_used: t });
            return Ok(obj);
        }
        Err(Error::NotFound(*id))
    }

    pub fn contains(&self, id: &ObjectId) -> bool {
        if self.resident.contains_key(id) || self.spilled.contains_key(id) {
            return true;
        }
        self.existing_loose_path(id).is_some() || self.pack_index.contains_key(id)
    }

    // ---- typed convenience helpers -----------------------------------------

    pub fn get_tree(&mut self, id: &ObjectId) -> Result<crate::object::Tree> {
        match self.get(id)? {
            Object::Tree(t) => Ok(t),
            _ => Err(Error::WrongKind(*id, "tree")),
        }
    }

    pub fn get_snapshot(&mut self, id: &ObjectId) -> Result<crate::object::Snapshot> {
        match self.get(id)? {
            Object::Snapshot(s) => Ok(s),
            _ => Err(Error::WrongKind(*id, "snapshot")),
        }
    }

    pub fn get_secret(&mut self, id: &ObjectId) -> Result<crate::object::Secret> {
        match self.get(id)? {
            Object::Secret(s) => Ok(s),
            _ => Err(Error::WrongKind(*id, "secret")),
        }
    }

    // ---- eviction ----------------------------------------------------------

    /// Free enough resident blob budget for `needed` bytes, excluding `incoming`
    /// (the id about to be inserted) from eviction candidates.
    fn ensure_capacity(&mut self, needed: usize, incoming: &ObjectId) -> Result<()> {
        if self.resident_blob_bytes + needed <= self.cfg.budget_bytes {
            return Ok(());
        }
        loop {
            if self.resident_blob_bytes + needed <= self.cfg.budget_bytes {
                return Ok(());
            }
            // Pick the coldest evictable blob (non-zero size, not the incoming one).
            let victim = self
                .resident
                .iter()
                .filter(|(id, r)| r.blob_size > 0 && *id != incoming)
                .min_by_key(|(_, r)| r.last_used)
                .map(|(id, _)| *id);

            let Some(victim) = victim else {
                // Nothing reclaimable.
                let available = self.resident_blob_bytes;
                return Err(Error::BudgetExceeded {
                    needed,
                    available,
                    budget: self.cfg.budget_bytes,
                });
            };

            match &self.cfg.backend {
                Backend::Ephemeral(SpillPolicy::Disallow) => {
                    let available = self.evictable_bytes(incoming);
                    return Err(Error::BudgetExceeded {
                        needed,
                        available,
                        budget: self.cfg.budget_bytes,
                    });
                }
                Backend::Ephemeral(SpillPolicy::SpillTo(_)) => self.evict_to_spill(&victim)?,
                Backend::Persistent(_) => self.drop_resident_blob(&victim),
            }
        }
    }

    fn evictable_bytes(&self, incoming: &ObjectId) -> usize {
        self.resident
            .iter()
            .filter(|(id, r)| r.blob_size > 0 && *id != incoming)
            .map(|(_, r)| r.blob_size)
            .sum()
    }

    fn evict_to_spill(&mut self, id: &ObjectId) -> Result<()> {
        let r = self.resident.get(id).expect("victim resident");
        let bytes = match &r.obj {
            Object::Blob(b) => b.clone(),
            _ => unreachable!("only blobs are evicted"),
        };
        let size = r.blob_size;
        self.write_spill(id, &bytes)?;
        self.resident.remove(id);
        self.resident_blob_bytes -= size;
        self.spilled.insert(*id, size);
        self.evictions += 1;
        Ok(())
    }

    // ---- spill backend ------------------------------------------------------

    fn spill_dir(&self) -> Option<&PathBuf> {
        match &self.cfg.backend {
            Backend::Ephemeral(SpillPolicy::SpillTo(p)) => Some(p),
            _ => None,
        }
    }

    /// Persistent eviction: drop the RAM copy; the durable file is authoritative.
    fn drop_resident_blob(&mut self, id: &ObjectId) {
        if let Some(r) = self.resident.remove(id) {
            self.resident_blob_bytes -= r.blob_size;
            self.evictions += 1;
        }
    }

    /// The sharded loose path `objects/<aa>/<rest>` for `id`, or `None` in
    /// ephemeral mode (which has no persistent objects dir).
    fn loose_path(&self, id: &ObjectId) -> Option<PathBuf> {
        let dir = self.persistent_dir()?;
        let hex = id.to_hex();
        Some(dir.join(&hex[..2]).join(&hex[2..]))
    }

    /// The legacy flat path `objects/<hex>` (pre-P8 repos), or `None` in ephemeral.
    fn flat_path(&self, id: &ObjectId) -> Option<PathBuf> {
        Some(self.persistent_dir()?.join(id.to_hex()))
    }

    /// The on-disk loose file for `id` if one exists (sharded preferred, then the
    /// legacy flat location), or `None`.
    fn existing_loose_path(&self, id: &ObjectId) -> Option<PathBuf> {
        if let Some(p) = self.loose_path(id) {
            if p.exists() {
                return Some(p);
            }
        }
        if let Some(p) = self.flat_path(id) {
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    /// Remove a loose object file (sharded or legacy flat) **and** drop any RAM /
    /// spill-map copy, so the object is truly gone unless a pack still holds it (in
    /// which case `get` rehydrates from the pack on demand). Without the RAM drop,
    /// `contains`/`get` would keep serving a pruned object from cache within a
    /// process. Absent on disk is success. Never removes packed objects — pack
    /// removal is `delete_pack`'s job.
    pub fn delete(&mut self, id: &ObjectId) -> Result<()> {
        if let Some(p) = self.existing_loose_path(id) {
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
        if let Some(r) = self.resident.remove(id) {
            self.resident_blob_bytes -= r.blob_size;
        }
        self.spilled.remove(id);
        Ok(())
    }

    /// mtime of `id`'s loose file (sharded or flat), or `None` if not loose.
    pub fn loose_mtime(&self, id: &ObjectId) -> Result<Option<std::time::SystemTime>> {
        match self.existing_loose_path(id) {
            Some(p) => Ok(Some(std::fs::metadata(&p)?.modified()?)),
            None => Ok(None),
        }
    }

    /// Every loose object id under the persistent objects dir: sharded
    /// `<aa>/<rest>` plus legacy flat `<hex>`. Skips `pack/`, tmp files, and any
    /// name that isn't a 64-char hex id. Empty in ephemeral mode.
    pub fn list_loose(&self) -> Result<Vec<ObjectId>> {
        let mut out = Vec::new();
        let Some(dir) = self.persistent_dir() else { return Ok(out) };
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::Io(e)),
        };
        for e in entries {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let ft = e.file_type()?;
            if ft.is_dir() {
                // A 2-hex shard directory; its children are the id's remaining hex.
                if name.len() != 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                    continue; // e.g. "pack"
                }
                for c in std::fs::read_dir(e.path())? {
                    let c = c?;
                    let rest = c.file_name().to_string_lossy().into_owned();
                    if let Ok(id) = format!("{name}{rest}").parse::<ObjectId>() {
                        out.push(id);
                    }
                }
            } else if let Ok(id) = name.parse::<ObjectId>() {
                out.push(id); // legacy flat file
            }
        }
        Ok(out)
    }

    /// Write `zstd(encode())` to the sharded `objects/<aa>/<rest>` idempotently
    /// (tmp + rename). Creates the shard directory.
    fn write_object_file(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        let path = self.loose_path(id).expect("persistent backend");
        if path.exists() {
            return Ok(());
        }
        let shard = path.parent().expect("sharded path has a parent");
        std::fs::create_dir_all(shard)?;
        let compressed = zstd::encode_all(std::io::Cursor::new(bytes), COMPRESSION_LEVEL)
            .map_err(Error::Io)?;
        crate::fsutil::atomic_write_durable(&path, &compressed)?;
        Ok(())
    }

    /// Read + verify + decode a loose object. Tries the sharded path then the
    /// legacy flat path; tries zstd-decompress then falls back to treating the
    /// bytes as a raw (pre-P8 uncompressed) canonical encoding. Either way the
    /// final canonical bytes are BLAKE3-verified against `id`.
    fn read_object_file(&self, id: &ObjectId) -> Result<Object> {
        let path = self.existing_loose_path(id).ok_or(Error::NotFound(*id))?;
        let raw = std::fs::read(&path)?;
        let canonical = match zstd::decode_all(std::io::Cursor::new(&raw)) {
            Ok(d) => d,
            Err(_) => raw, // legacy uncompressed loose file
        };
        if ObjectId::of(&canonical) != *id {
            return Err(Error::Malformed(format!("object {id} failed hash verification on read")));
        }
        Object::decode(&canonical)
    }

    fn ensure_spill_dir(&mut self) -> Result<()> {
        if !self.spill_dir_ready {
            if let Some(dir) = self.spill_dir() {
                std::fs::create_dir_all(dir)?;
                self.spill_dir_ready = true;
            }
        }
        Ok(())
    }

    fn write_spill(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        self.ensure_spill_dir()?;
        let path = self.spill_dir().unwrap().join(id.to_hex());
        // Content-addressed name => idempotent; skip if already written.
        if !path.exists() {
            std::fs::write(path, bytes)?;
        }
        Ok(())
    }

    /// `objects/pack` directory, or `None` in ephemeral mode.
    fn pack_dir(&self) -> Option<PathBuf> {
        Some(self.persistent_dir()?.join("pack"))
    }

    /// Rescan `objects/pack/*.idx`, rebuilding the in-memory id->location map.
    pub fn reload_packs(&mut self) -> Result<()> {
        self.pack_index.clear();
        let Some(pack_dir) = self.pack_dir() else { return Ok(()) };
        let entries = match std::fs::read_dir(&pack_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::Io(e)),
        };
        for e in entries {
            let e = e?;
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("idx") {
                continue;
            }
            let pack_path = path.with_extension("pack");
            if !pack_path.exists() {
                continue; // orphan idx; ignore
            }
            let idx_bytes = std::fs::read(&path)?;
            for ie in crate::pack::parse_index(&idx_bytes)? {
                self.pack_index
                    .entry(ie.id)
                    .or_insert(PackLoc { pack_path: pack_path.clone(), offset: ie.offset });
            }
        }
        Ok(())
    }

    /// Returns `true` if `id` is present in a loaded pack index.
    pub fn is_packed(&self, id: &ObjectId) -> bool {
        self.pack_index.contains_key(id)
    }

    /// Hashes (file stems) of currently-loaded packs.
    pub fn pack_hashes(&self) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for loc in self.pack_index.values() {
            if let Some(stem) = loc.pack_path.file_stem().and_then(|s| s.to_str()) {
                set.insert(stem.to_string());
            }
        }
        set.into_iter().collect()
    }

    /// Read a packed object: seek to its record and decompress+verify+decode.
    fn read_pack_object(&self, id: &ObjectId) -> Result<Object> {
        let loc = self.pack_index.get(id).ok_or(Error::NotFound(*id))?;
        // Read just the record: 4-byte length prefix then the compressed payload.
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&loc.pack_path)?;
        f.seek(SeekFrom::Start(loc.offset))?;
        let mut len_buf = [0u8; 4];
        f.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        f.read_exact(&mut payload)?;
        // Reuse the pure reader by framing the record as a 1-record slice.
        let mut framed = Vec::with_capacity(4 + len);
        framed.extend_from_slice(&len_buf);
        framed.extend_from_slice(&payload);
        crate::pack::read_object_at(&framed, 0, id)
    }

    /// Read every named object's canonical bytes, write a `<hash>.pack`/`.idx`
    /// under `objects/pack/`, refresh the index, and return the pack hash.
    pub fn write_pack(&mut self, ids: &[ObjectId]) -> Result<String> {
        let mut objects: Vec<(ObjectId, Vec<u8>)> = Vec::with_capacity(ids.len());
        for id in ids {
            objects.push((*id, self.get(id)?.encode()));
        }
        let (pack_bytes, idx_bytes) = crate::pack::build_pack(&objects)?;
        let hash = hex::encode(blake3::hash(&pack_bytes).as_bytes());
        let pack_dir = self.pack_dir().expect("persistent backend");
        std::fs::create_dir_all(&pack_dir)?;
        write_atomic(&pack_dir.join(format!("{hash}.pack")), &pack_bytes)?;
        write_atomic(&pack_dir.join(format!("{hash}.idx")), &idx_bytes)?;
        self.reload_packs()?;
        Ok(hash)
    }

    /// Remove a pack's `.pack` + `.idx` and forget its index entries.
    pub fn delete_pack(&mut self, hash: &str) -> Result<()> {
        if let Some(pack_dir) = self.pack_dir() {
            for ext in ["pack", "idx"] {
                let p = pack_dir.join(format!("{hash}.{ext}"));
                match std::fs::remove_file(&p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(Error::Io(e)),
                }
            }
        }
        self.reload_packs()
    }

    fn read_spill(&self, id: &ObjectId) -> Result<Object> {
        let path = self.spill_dir().ok_or(Error::NotFound(*id))?.join(id.to_hex());
        // Spill files hold RAW blob bytes (not `encode()` output), so reconstruct
        // the blob and verify its content address rather than hashing the bytes
        // directly.
        let bytes = std::fs::read(path)?;
        let obj = Object::blob(bytes);
        if obj.id() != *id {
            return Err(Error::Malformed(format!("spill object {id} failed hash verification")));
        }
        Ok(obj)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // Remove the spill directory so a session leaves zero residual files.
        if self.spill_dir_ready {
            if let Some(dir) = self.spill_dir() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}

/// Durable atomic write (fsync file, rename, fsync dir) — see [`crate::fsutil`].
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    Ok(crate::fsutil::atomic_write_durable(path, bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(n: usize, fill: u8) -> Object {
        Object::blob(vec![fill; n])
    }

    #[test]
    fn dedup_returns_same_id_and_counts_once() {
        let mut s = Store::with_budget(1024);
        let a = s.put(blob(100, 1)).unwrap();
        let b = s.put(blob(100, 1)).unwrap();
        assert_eq!(a, b);
        assert_eq!(s.stats().resident_blob_bytes, 100);
    }

    #[test]
    fn over_budget_without_spill_errors() {
        let mut s = Store::with_budget(150);
        s.put(blob(100, 1)).unwrap();
        let err = s.put(blob(100, 2)).unwrap_err();
        assert!(matches!(err, Error::BudgetExceeded { .. }), "got {err:?}");
    }

    #[test]
    fn lru_eviction_with_spill_roundtrips() {
        let dir = std::env::temp_dir().join(format!("scl-spill-test-{}", std::process::id()));
        let mut s = Store::new(StoreConfig {
            budget_bytes: 150,
            backend: Backend::Ephemeral(SpillPolicy::SpillTo(dir.clone())),
        });
        let a = s.put(blob(100, 0xAA)).unwrap();
        // Touch nothing; insert b -> a is coldest and must spill.
        let _b = s.put(blob(100, 0xBB)).unwrap();
        assert_eq!(s.stats().spilled_blobs, 1);
        assert_eq!(s.stats().evictions, 1);
        // Fetch a back -> rehydrates from spill, content intact.
        let got = s.get(&a).unwrap();
        match got {
            Object::Blob(b) => assert!(b.iter().all(|&x| x == 0xAA)),
            _ => panic!("wrong kind"),
        }
        assert_eq!(s.stats().rehydrations, 1);
        drop(s);
        assert!(!dir.exists(), "spill dir must be removed on drop");
    }

    use crate::object::{Object, Snapshot, Tree};
    use std::collections::BTreeMap;

    fn temp_objects_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("scl-persist-{tag}-{}", std::process::id()))
    }

    #[test]
    fn persistent_put_then_reopen_reads_all_kinds() {
        let dir = temp_objects_dir("reopen");
        let _ = std::fs::remove_dir_all(&dir);
        let blob_id;
        let snap_id;
        {
            let mut s = Store::open_persistent(&dir, 1024).unwrap();
            blob_id = s.put(Object::blob(b"hello".to_vec())).unwrap();
            let root = s.put(Object::Tree(Tree::new(vec![]))).unwrap();
            snap_id = s
                .put(Object::Snapshot(Snapshot {
                    root,
                    parents: vec![],
                    author: "a".into(),
                    timestamp: 0,
                    message: "m".into(),
                    secrets: BTreeMap::new(),
                    protection: Default::default(),
                }))
                .unwrap();
        } // store dropped; nothing deleted
        // Reopen on the same dir: resident cache is empty, must load from disk.
        let mut s2 = Store::open_persistent(&dir, 1024).unwrap();
        assert_eq!(&s2.get(&blob_id).unwrap().encode(), &Object::blob(b"hello".to_vec()).encode());
        assert!(matches!(s2.get(&snap_id).unwrap(), Object::Snapshot(_)));
        drop(s2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persistent_corrupt_object_fails_hash_verify() {
        let dir = temp_objects_dir("corrupt");
        let _ = std::fs::remove_dir_all(&dir);
        let id;
        {
            let mut s = Store::open_persistent(&dir, 1024).unwrap();
            id = s.put(Object::blob(b"data".to_vec())).unwrap();
        }
        // Corrupt the file on disk.
        let hex = id.to_hex();
        std::fs::write(dir.join(&hex[..2]).join(&hex[2..]), b"tampered").unwrap();
        let mut s2 = Store::open_persistent(&dir, 1024).unwrap();
        assert!(matches!(s2.get(&id), Err(Error::Malformed(_))));
        drop(s2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persistent_eviction_drops_ram_but_reloads_from_disk() {
        let dir = temp_objects_dir("evict");
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = Store::open_persistent(&dir, 150).unwrap();
        let a = s.put(Object::blob(vec![0xAA; 100])).unwrap();
        let _b = s.put(Object::blob(vec![0xBB; 100])).unwrap(); // forces a to evict from RAM
        assert!(s.stats().evictions >= 1);
        // a is gone from RAM but on disk; get reloads it.
        match s.get(&a).unwrap() {
            Object::Blob(b) => assert!(b.iter().all(|&x| x == 0xAA)),
            _ => panic!("wrong kind"),
        }
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persistent_writes_sharded_compressed_and_reads_back() {
        let dir = temp_objects_dir("shard");
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
        let id = s.put(Object::blob(b"hello sharded world".to_vec())).unwrap();
        // File lives at objects/<aa>/<rest>, NOT objects/<hex>.
        let hex = id.to_hex();
        let sharded = dir.join(&hex[..2]).join(&hex[2..]);
        assert!(sharded.exists(), "expected sharded path {sharded:?}");
        assert!(!dir.join(&hex).exists(), "must not write flat path");
        // Payload is compressed, not the raw canonical bytes.
        let on_disk = std::fs::read(&sharded).unwrap();
        assert_ne!(on_disk, Object::blob(b"hello sharded world".to_vec()).encode());
        // Reopen (empty RAM cache) and read back through decompress+verify.
        let mut s2 = Store::open_persistent(&dir, 1 << 20).unwrap();
        assert_eq!(s2.get(&id).unwrap().encode(), Object::blob(b"hello sharded world".to_vec()).encode());
        drop((s, s2));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_legacy_flat_uncompressed_object() {
        let dir = temp_objects_dir("legacy");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Simulate a pre-P8 repo: raw canonical bytes at flat objects/<hex>.
        let obj = Object::blob(b"legacy".to_vec());
        let id = obj.id();
        std::fs::write(dir.join(id.to_hex()), obj.encode()).unwrap();
        let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
        assert!(s.contains(&id));
        assert_eq!(s.get(&id).unwrap().encode(), obj.encode());
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_pack_then_read_after_loose_deleted() {
        let dir = temp_objects_dir("pack");
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
        let a = s.put(Object::blob(b"packed-a".to_vec())).unwrap();
        let b = s.put(Object::blob(b"packed-b".to_vec())).unwrap();
        let hash = s.write_pack(&[a, b]).unwrap();
        assert!(s.pack_hashes().contains(&hash));
        assert!(s.is_packed(&a) && s.is_packed(&b));
        // Delete the loose copies; the object must still be readable from the pack.
        s.delete(&a).unwrap();
        s.delete(&b).unwrap();
        assert!(s.list_loose().unwrap().is_empty());
        // Reopen so RAM cache is cold: read must come from the pack.
        let mut s2 = Store::open_persistent(&dir, 1 << 20).unwrap();
        assert_eq!(s2.get(&a).unwrap().encode(), Object::blob(b"packed-a".to_vec()).encode());
        assert!(s2.contains(&b));
        drop((s, s2));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_pack_forgets_its_objects() {
        let dir = temp_objects_dir("delpack");
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
        let a = s.put(Object::blob(b"x".to_vec())).unwrap();
        let hash = s.write_pack(&[a]).unwrap();
        s.delete(&a).unwrap(); // drop loose copy; only the pack has it now
        assert!(s.contains(&a));
        s.delete_pack(&hash).unwrap();
        assert!(!s.is_packed(&a));
        assert!(!s.contains(&a));
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persistent_reput_of_evicted_object_does_not_double_count() {
        let dir = temp_objects_dir("reput");
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = Store::open_persistent(&dir, 150).unwrap();
        let a = s.put(Object::blob(vec![0xAA; 100])).unwrap();
        let _b = s.put(Object::blob(vec![0xBB; 100])).unwrap(); // evicts a from RAM
        // After eviction only b is resident.
        assert_eq!(s.stats().resident_blob_bytes, 100);
        // Re-putting a (already durable on disk) must not re-admit + double-count.
        let a2 = s.put(Object::blob(vec![0xAA; 100])).unwrap();
        assert_eq!(a, a2);
        assert_eq!(
            s.stats().resident_blob_bytes,
            100,
            "re-put of an on-disk object must not re-admit to RAM"
        );
        // a is still readable (rehydrated from disk); this evicts b in turn.
        match s.get(&a).unwrap() {
            Object::Blob(b) => assert!(b.iter().all(|&x| x == 0xAA)),
            _ => panic!("wrong kind"),
        }
        assert_eq!(s.stats().resident_blob_bytes, 100);
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
