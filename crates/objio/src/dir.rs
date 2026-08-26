//! Local-directory `Bucket` — the test/demo backend behind `sc+wal://`.

use crate::{validate_key, Bucket, Error, Fetched, Result};
use std::path::{Path, PathBuf};

/// A local filesystem bucket implementation using a directory as the backing
/// store. Tags are blake3 hashes of content; compare-and-swap writes are
/// serialized via a spin-lock file to simulate S3 precondition semantics.
pub struct DirBucket {
    root: PathBuf,
}

fn tag_of(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

impl DirBucket {
    /// Open (creating if needed) a directory as a bucket.
    pub fn open(root: impl Into<PathBuf>) -> Result<DirBucket> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(DirBucket { root })
    }

    fn key_path(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        Ok(self.root.join(key))
    }

    /// Spin-acquire `<root>/.cas-lock`; bounded so a crashed holder surfaces
    /// as a loud error, not a hang.
    fn lock(&self) -> Result<CasLock> {
        let path = self.root.join(".cas-lock");
        for _ in 0..2000 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(CasLock { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Backend(format!(
            "cas lock stuck (stale {} ?)",
            path.display()
        )))
    }

    fn write_via_tmp(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

struct CasLock {
    path: PathBuf,
}
impl Drop for CasLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Bucket for DirBucket {
    fn get(&self, key: &str, cached_tag: Option<&str>) -> Result<Fetched> {
        let path = self.key_path(key)?;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Fetched::Absent),
            Err(e) => return Err(e.into()),
        };
        let tag = tag_of(&bytes);
        if cached_tag == Some(tag.as_str()) {
            return Ok(Fetched::Unchanged);
        }
        Ok(Fetched::New { bytes, tag })
    }

    fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let path = self.key_path(key)?;
        let _lock = self.lock()?;
        if path.exists() {
            return Ok(false);
        }
        self.write_via_tmp(&path, bytes)?;
        Ok(true)
    }

    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        expected_tag: Option<&str>,
    ) -> Result<Option<String>> {
        let path = self.key_path(key)?;
        let _lock = self.lock()?;
        let current = match std::fs::read(&path) {
            Ok(b) => Some(tag_of(&b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if current.as_deref() != expected_tag {
            return Ok(None);
        }
        self.write_via_tmp(&path, bytes)?;
        Ok(Some(tag_of(bytes)))
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
            let rd = match std::fs::read_dir(dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            for entry in rd {
                let entry = entry?;
                let p = entry.path();
                if p.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n == ".cas-lock" || n.contains(".tmp-")
                }) {
                    continue;
                }
                if p.is_dir() {
                    walk(&p, root, out)?;
                } else {
                    out.push(
                        p.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
            Ok(())
        }
        validate_key(prefix.trim_end_matches('/'))?;
        let mut out = Vec::new();
        walk(&self.root, &self.root, &mut out)?;
        out.retain(|k| k.starts_with(prefix));
        out.sort();
        Ok(out)
    }
}
