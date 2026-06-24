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

/// What to do when the blob budget is exhausted.
#[derive(Clone, Debug)]
pub enum SpillPolicy {
    /// Never spill: an over-budget insert returns `BudgetExceeded`.
    Disallow,
    /// Spill evicted blobs to this directory (created lazily, removed on drop).
    SpillTo(PathBuf),
}

#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Maximum resident blob bytes. Trees/snapshots/secrets are not counted.
    pub budget_bytes: usize,
    pub spill: SpillPolicy,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            budget_bytes: 512 * 1024 * 1024,
            spill: SpillPolicy::Disallow,
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

    /// Insert an object, returning its content address. Idempotent: inserting
    /// content already present (resident or spilled) is a no-op that returns the
    /// existing id.
    pub fn put(&mut self, obj: Object) -> Result<ObjectId> {
        let id = obj.id();
        if self.resident.contains_key(&id) || self.spilled.contains_key(&id) {
            return Ok(id);
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

    /// Fetch an object, rehydrating from spill on a miss. Updates recency.
    pub fn get(&mut self, id: &ObjectId) -> Result<Object> {
        if let Some(r) = self.resident.get_mut(id) {
            r.last_used = {
                self.clock += 1;
                self.clock
            };
            return Ok(r.obj.clone());
        }
        if let Some(&size) = self.spilled.get(id) {
            let obj = self.read_spill(id)?;
            // Re-admit to RAM (may trigger further eviction of other blobs).
            self.ensure_capacity(size, id)?;
            self.spilled.remove(id);
            self.resident_blob_bytes += size;
            self.rehydrations += 1;
            let t = self.tick();
            self.resident.insert(*id, Resident { obj: obj.clone(), blob_size: size, last_used: t });
            return Ok(obj);
        }
        Err(Error::NotFound(*id))
    }

    pub fn contains(&self, id: &ObjectId) -> bool {
        self.resident.contains_key(id) || self.spilled.contains_key(id)
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

            match &self.cfg.spill {
                SpillPolicy::Disallow => {
                    let available = self.evictable_bytes(incoming);
                    return Err(Error::BudgetExceeded {
                        needed,
                        available,
                        budget: self.cfg.budget_bytes,
                    });
                }
                SpillPolicy::SpillTo(_) => self.evict_to_spill(&victim)?,
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
        match &self.cfg.spill {
            SpillPolicy::SpillTo(p) => Some(p),
            SpillPolicy::Disallow => None,
        }
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
            spill: SpillPolicy::SpillTo(dir.clone()),
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
}
