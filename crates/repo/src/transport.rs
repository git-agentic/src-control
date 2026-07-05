//! Object/ref transport between repos. `LocalTransport` works over a remote
//! `.sc/` directory on the same filesystem; the trait is the seam for future
//! SSH/HTTP transports.

use std::cell::RefCell;
use std::str::FromStr;

use scl_core::{Object, ObjectId, Store};

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lock::RepoLock;

/// A remote repo we can list refs on and exchange content-addressed objects with.
pub trait Transport {
    /// `(branch, tip)` for every `refs/heads/*` on the remote.
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>>;
    /// The branch the remote HEAD names.
    fn head_branch(&self) -> Result<String>;
    /// True if the remote already holds an object with this id.
    fn has_object(&self, id: &ObjectId) -> Result<bool>;
    /// Raw canonical `encode()` bytes of an object.
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>>;
    /// Write raw `encode()` bytes; verifies `ObjectId::of(bytes) == id`.
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()>;
    /// Set `refs/heads/<branch>` on the remote to `id` — compare-and-swap.
    ///
    /// `expected_old` is the tip the caller based its fast-forward check on
    /// (`None` = the branch must not exist yet). The implementation must
    /// revalidate under the remote's own lock and refuse with
    /// [`Error::NonFastForward`] when the ref moved in between, so two racing
    /// pushers cannot silently clobber each other's commits. Setting the ref
    /// to the value it already has succeeds regardless of `expected_old`.
    fn update_ref(&self, branch: &str, id: &ObjectId, expected_old: Option<&ObjectId>)
        -> Result<()>;

    /// Build a pack of every object reachable from `wants` but not already
    /// implied by `haves` (the receiver's closure). Returns `.pack` bytes.
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>>;

    /// Receive a pack: verify every record (BLAKE3) and write each object into
    /// the store. Returns the contained ids. Refs are the caller's job.
    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>>;
}

/// Transport over a remote `.sc/` directory on the local filesystem.
pub struct LocalTransport {
    layout: Layout,
    /// A store opened on the remote objects dir, so reads resolve loose
    /// (sharded or flat), compressed, and packed objects uniformly. Lazily
    /// mutated for its RAM cache; interior-mutable because the trait reads `&self`.
    store: RefCell<Store>,
}

impl LocalTransport {
    /// Open the repo whose root (the dir containing `.sc/`) is `root`.
    pub fn open(root: impl Into<std::path::PathBuf>) -> Result<LocalTransport> {
        let layout = Layout::at(root);
        if !layout.dot_sc.is_dir() {
            return Err(Error::NotARepo);
        }
        // Match the repo's store budget so a single large object never fails to resolve
        // (a blob bigger than the whole budget would BudgetExceed).
        let store = Store::open_persistent(layout.objects_dir(), crate::repo::DEFAULT_BUDGET)?;
        Ok(LocalTransport { layout, store: RefCell::new(store) })
    }
}

impl Transport for LocalTransport {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        let mut out = Vec::new();
        let dir = self.layout.refs_heads_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for e in entries {
            let e = e?;
            if e.file_type()?.is_file() {
                let name = e.file_name().to_string_lossy().into_owned();
                let text = std::fs::read_to_string(e.path())?;
                let id = ObjectId::from_str(text.trim())
                    .map_err(|_| Error::BadRef(format!("remote ref {name} has bad id")))?;
                out.push((name, id));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn head_branch(&self) -> Result<String> {
        crate::refs::current_branch(&self.layout)
    }

    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        Ok(self.store.borrow().contains(id))
    }

    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        Ok(self.store.borrow_mut().get(id)?.encode())
    }

    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if ObjectId::of(bytes) != *id {
            return Err(Error::CorruptObject(*id));
        }
        let got = self.store.borrow_mut().put(Object::decode(bytes)?)?;
        if got != *id {
            return Err(Error::CorruptObject(*id));
        }
        Ok(())
    }

    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        let _lock = RepoLock::acquire(&self.layout)?;
        // Revalidate inside the lock: the caller's fast-forward check ran
        // unlocked, so the ref may have moved since (two concurrent pushes).
        let current = crate::refs::read_branch_tip(&self.layout, branch)?;
        if current.as_ref() == Some(id) {
            return Ok(()); // already there — idempotent
        }
        if current.as_ref() != expected_old {
            return Err(Error::NonFastForward);
        }
        crate::refs::write_branch_tip(&self.layout, branch, id)
    }

    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>> {
        use std::collections::BTreeSet;
        let mut store = self.store.borrow_mut();
        // Reachable-from-wants minus reachable-from-haves, computed on this
        // (the remote) store. `haves` the remote doesn't have are skipped.
        let want_set = crate::reachable::reachable_objects(&mut *store, wants)?;
        let mut have_set: BTreeSet<ObjectId> = BTreeSet::new();
        for h in haves {
            if store.contains(h) {
                have_set.extend(crate::reachable::reachable_objects(&mut *store, &[*h])?);
            }
        }
        let send: Vec<(ObjectId, Vec<u8>)> = want_set
            .into_iter()
            .filter(|id| !have_set.contains(id))
            .map(|id| Ok((id, store.get(&id)?.encode())))
            .collect::<Result<Vec<_>>>()?;
        let (pack, _idx) = scl_core::pack::build_pack(&send)?;
        Ok(pack)
    }

    /// Receive a pack: verify every record (BLAKE3) and write each object into the store.
    /// Returns the ids of every object written. Ref updates are the caller's responsibility.
    ///
    /// # Verification
    ///
    /// `parse_pack` BLAKE3-verifies every record in the pack **before** any object is written.
    /// A corrupt or tampered pack is therefore rejected in full, with no objects written, and
    /// returns `Err`.
    ///
    /// # Non-transactional writes
    ///
    /// After the upfront verification passes, objects are written one-by-one. These writes are
    /// **not** atomic: if a later `store.put` fails (e.g. disk full), earlier objects are already
    /// durably stored and the call returns `Err`. This cannot corrupt the store — every written
    /// object is valid and uniquely identified by its own BLAKE3 hash — but a partially-applied
    /// pack is observable (`has_object` may return `true` for some ids and `false` for others).
    ///
    /// # Caller contract on `Err`
    ///
    /// Treat any `Err` return as "the pack was not fully applied". Do **not** update refs on
    /// failure. Any partially-written objects are unreferenced and will be reclaimed by `sc gc`.
    /// Retrying is safe because content-addressed `put` is idempotent.
    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>> {
        let mut store = self.store.borrow_mut();
        let mut ids = Vec::new();
        // parse_pack verifies every record's hash before we write anything.
        for (id, obj) in scl_core::pack::parse_pack(pack)? {
            let got = store.put(obj)?;
            // Defense in depth: parse_pack already verified each record's hash; this guards
            // against a future change that weakens that.
            if got != id {
                return Err(Error::CorruptObject(id));
            }
            ids.push(id);
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::Object;

    fn tmp_remote(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-xport-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(layout.objects_dir()).unwrap();
        std::fs::create_dir_all(layout.refs_heads_dir()).unwrap();
        crate::refs::write_head(&layout, "main").unwrap();
        layout
    }

    #[test]
    fn local_transport_objects_and_refs_roundtrip() {
        let layout = tmp_remote("rt");
        let t = LocalTransport::open(&layout.root).unwrap();

        let blob = Object::blob(b"hello".to_vec());
        let id = blob.id();
        let bytes = blob.encode();
        assert!(!t.has_object(&id).unwrap());
        t.put_object(&id, &bytes).unwrap();
        assert!(t.has_object(&id).unwrap());
        assert_eq!(t.get_object(&id).unwrap(), bytes);

        // corrupt put is rejected
        assert!(matches!(t.put_object(&id, b"not the bytes"), Err(Error::CorruptObject(_))));

        t.update_ref("main", &id, None).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), id)]);
        assert_eq!(t.head_branch().unwrap(), "main");

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn update_ref_is_compare_and_swap() {
        // Two pushers can both pass the fast-forward check against the same old
        // tip; the ref write itself must revalidate under the remote lock so
        // the second writer fails instead of silently clobbering the first.
        let layout = tmp_remote("cas");
        let t = LocalTransport::open(&layout.root).unwrap();
        let c1 = Object::blob(b"c1".to_vec()).id();
        let c2 = Object::blob(b"c2".to_vec()).id();
        let c3 = Object::blob(b"c3".to_vec()).id();

        // Create: expected None means "branch must not exist".
        t.update_ref("main", &c1, None).unwrap();
        // Creating again with expected None must fail (it exists now).
        assert!(matches!(t.update_ref("main", &c2, None), Err(Error::NonFastForward)));

        // Advance with the right expected old tip.
        t.update_ref("main", &c2, Some(&c1)).unwrap();

        // A raced writer still expecting c1 must fail, not clobber c2.
        assert!(matches!(t.update_ref("main", &c3, Some(&c1)), Err(Error::NonFastForward)));
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), c2)]);

        // Re-pushing the value already at the tip is fine (idempotent), even
        // with a stale expectation — the ref ends up exactly where asked.
        t.update_ref("main", &c2, Some(&c1)).unwrap();
        t.update_ref("main", &c2, Some(&c2)).unwrap();

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn transport_reads_object_larger_than_one_mib() {
        // A blob > 1 MiB would BudgetExceed under the old 1 MiB budget.
        let layout = tmp_remote("large");
        let big_bytes: Vec<u8> = vec![0xAB; (1 << 20) + 4096];
        let blob = Object::blob(big_bytes);
        let id = blob.id();
        let expected = blob.encode();
        {
            let mut s =
                scl_core::Store::open_persistent(layout.objects_dir(), crate::repo::DEFAULT_BUDGET)
                    .unwrap();
            s.put(Object::blob(vec![0xAB; (1 << 20) + 4096])).unwrap();
        }
        let t = LocalTransport::open(&layout.root).unwrap();
        let got = t.get_object(&id).expect("large object must transfer without BudgetExceeded");
        assert_eq!(got, expected);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn transport_reads_packed_remote_object() {
        let layout = tmp_remote("packed");
        // Write an object into the remote store, pack it, drop the loose copy.
        let id;
        {
            let mut s = scl_core::Store::open_persistent(layout.objects_dir(), 1 << 20).unwrap();
            id = s.put(Object::blob(b"remote-packed".to_vec())).unwrap();
            let _h = s.write_pack(&[id]).unwrap();
            s.delete(&id).unwrap();
        }
        let t = LocalTransport::open(&layout.root).unwrap();
        assert!(t.has_object(&id).unwrap());
        assert_eq!(t.get_object(&id).unwrap(), Object::blob(b"remote-packed".to_vec()).encode());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn get_pack_excludes_haves_and_put_pack_verifies() {
        let pid = std::process::id();
        let src_root =
            std::env::temp_dir().join(format!("scl-xport-bulk-{pid}"));
        let dst_root =
            std::env::temp_dir().join(format!("scl-xport-bulkdst-{pid}"));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&src_root).unwrap();
        std::fs::create_dir_all(&dst_root).unwrap();

        // Seed two reachable commits on the remote via a real repo.
        let remote_repo = crate::repo::Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("a.txt"), b"one").unwrap();
        let c1 = remote_repo.commit("t", "c1").unwrap();
        std::fs::write(src_root.join("a.txt"), b"two").unwrap();
        let c2 = remote_repo.commit("t", "c2").unwrap();

        let t = LocalTransport::open(&src_root).unwrap();
        // Want c2, already have c1: the pack must omit c1's objects but include c2.
        let pack = t.get_pack(&[c2], &[c1]).unwrap();
        let ids: Vec<_> = scl_core::pack::parse_pack(&pack).unwrap().into_iter().map(|(id, _)| id).collect();
        assert!(ids.contains(&c2));
        assert!(!ids.contains(&c1));

        // put_pack into a fresh empty remote writes + returns the ids.
        let _ = crate::repo::Repo::init(&dst_root).unwrap();
        let t2 = LocalTransport::open(&dst_root).unwrap();
        let written = t2.put_pack(&pack).unwrap();
        assert!(written.contains(&c2));
        assert!(t2.has_object(&c2).unwrap());

        // A tampered pack is rejected.
        let mut bad = pack.clone();
        let n = bad.len() - 1;
        bad[n] ^= 0xFF;
        assert!(t2.put_pack(&bad).is_err());

        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }
}
