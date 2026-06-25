//! Content-addressed object store with a bounded memory budget.
//!
//! Trees, snapshots, and secrets are small and always kept resident. Blob
//! content is bounded by a configurable byte budget; when an insert would
//! exceed it, the coldest reconstructible blobs are evicted (LRU). With spill
//! enabled, evicted blobs are written to a content-addressed temp directory and
//! rehydrated on demand; without it, the store fails loudly with
//! [`Error::BudgetExceeded`] rather than thrashing.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::Object;

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

/// The object store. Cheap to share base content across many worktrees because
/// blob bytes live behind `Arc`.
pub struct Store {
    cfg: StoreConfig,
    resident: HashMap<ObjectId, Resident>,
    /// Blobs evicted to spill, with their byte size for budget re-admission.
    spilled: HashMap<ObjectId, usize>,
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
        Ok(Store::new(StoreConfig {
            budget_bytes,
            backend: Backend::Persistent(dir),
        }))
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
        // Persistent backend: load any object kind from disk.
        if self.persistent_dir().is_some() {
            let obj = self.read_object_file(id)?;
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
        if let Some(dir) = self.persistent_dir() {
            return dir.join(id.to_hex()).exists();
        }
        false
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

    /// Write `encode()` bytes to `objects/<hex>` idempotently (tmp + rename).
    fn write_object_file(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        let dir = self.persistent_dir().expect("persistent backend").clone();
        let final_path = dir.join(id.to_hex());
        if final_path.exists() {
            return Ok(());
        }
        let tmp = dir.join(format!("{}.tmp", id.to_hex()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &final_path)?;
        Ok(())
    }

    /// Read+verify+decode an object file. Hash mismatch => `Malformed`.
    fn read_object_file(&self, id: &ObjectId) -> Result<Object> {
        let dir = self.persistent_dir().ok_or(Error::NotFound(*id))?;
        let path = dir.join(id.to_hex());
        let bytes = std::fs::read(&path).map_err(|_| Error::NotFound(*id))?;
        if ObjectId::of(&bytes) != *id {
            return Err(Error::Malformed(format!("object {id} failed hash verification on read")));
        }
        Object::decode(&bytes)
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

    fn read_spill(&self, id: &ObjectId) -> Result<Object> {
        let path = self.spill_dir().ok_or(Error::NotFound(*id))?.join(id.to_hex());
        let bytes = std::fs::read(path)?;
        Ok(Object::blob(bytes))
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
        std::fs::write(dir.join(id.to_hex()), b"tampered").unwrap();
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
}
