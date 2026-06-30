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
    /// Set `refs/heads/<branch>` on the remote to `id`.
    fn update_ref(&self, branch: &str, id: &ObjectId) -> Result<()>;
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
        let store = Store::open_persistent(layout.objects_dir(), 1 << 20)?;
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

    fn update_ref(&self, branch: &str, id: &ObjectId) -> Result<()> {
        let _lock = RepoLock::acquire(&self.layout)?;
        crate::refs::write_branch_tip(&self.layout, branch, id)
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

        t.update_ref("main", &id).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), id)]);
        assert_eq!(t.head_branch().unwrap(), "main");

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
}
