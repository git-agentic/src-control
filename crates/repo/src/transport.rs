//! Object/ref transport between repos. `LocalTransport` works over a remote
//! `.sc/` directory on the same filesystem; the trait is the seam for future
//! SSH/HTTP transports.

use std::str::FromStr;

use scl_core::ObjectId;

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
}

impl LocalTransport {
    /// Open the repo whose root (the dir containing `.sc/`) is `root`.
    pub fn open(root: impl Into<std::path::PathBuf>) -> Result<LocalTransport> {
        let layout = Layout::at(root);
        if !layout.dot_sc.is_dir() {
            return Err(Error::NotARepo);
        }
        Ok(LocalTransport { layout })
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
        Ok(self.layout.objects_dir().join(id.to_hex()).exists())
    }

    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        let path = self.layout.objects_dir().join(id.to_hex());
        std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Core(scl_core::Error::NotFound(*id))
            } else {
                e.into()
            }
        })
    }

    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if ObjectId::of(bytes) != *id {
            return Err(Error::CorruptObject(*id));
        }
        let dir = self.layout.objects_dir();
        std::fs::create_dir_all(&dir)?;
        let final_path = dir.join(id.to_hex());
        if final_path.exists() {
            return Ok(());
        }
        let tmp = dir.join(format!("{}.{}.tmp", id.to_hex(), std::process::id()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &final_path)?;
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
}
