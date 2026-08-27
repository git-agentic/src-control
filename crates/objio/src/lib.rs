//! Object-storage access for sc bucket remotes (P36).
//!
//! Quarantine rule: object-store SDKs live here and only here — the rest of
//! the workspace sees the [`Bucket`] trait. Leaf crate: depends on no other
//! workspace crate (like `tlsio`).

mod dir;
pub use dir::DirBucket;
mod s3;
pub use s3::S3Bucket;

/// Errors from the object-storage bucket layer. Variants indicate key
/// validation failure, I/O errors from the backing store, or backend-specific
/// errors (e.g., lock starvation in the local directory backend).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bucket key rejected: {0}")]
    BadKey(String),
    #[error("bucket io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bucket backend: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Outcome of a conditional read.
pub enum Fetched {
    /// The caller's cached tag still matches — no bytes transferred.
    Unchanged,
    /// The key does not exist.
    Absent,
    /// Current value plus its tag (ETag / content hash).
    New { bytes: Vec<u8>, tag: String },
}

/// A flat key/value object store with the three primitives the WAL needs:
/// conditional read, create-if-absent, and compare-and-swap overwrite.
pub trait Bucket: Send {
    /// Conditional read. `cached_tag` matching the current value returns
    /// [`Fetched::Unchanged`] without transferring bytes.
    fn get(&self, key: &str, cached_tag: Option<&str>) -> Result<Fetched>;
    /// Create-only write (if-none-match). `Ok(false)` = key already exists;
    /// the existing value is never touched.
    fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool>;
    /// Compare-and-swap overwrite. `expected_tag: None` = create-new.
    /// `Ok(None)` = precondition failed (someone else won); `Ok(Some(tag))`
    /// = committed, with the new value's tag.
    fn put_if_tag(
        &self,
        key: &str,
        bytes: &[u8],
        expected_tag: Option<&str>,
    ) -> Result<Option<String>>;
    /// Keys under `prefix`, sorted.
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Reject traversal and absolute keys before any backend touches them.
pub(crate) fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.starts_with('/')
        || key.contains('\\')
        || key
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
        || key.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::BadKey(format!("{key:?}")));
    }
    Ok(())
}

/// Conformance checks every `Bucket` implementation must pass.
/// Panics on violation (test helper).
pub fn contract_suite(b: &dyn Bucket) {
    // absent key
    assert!(matches!(b.get("manifest", None).unwrap(), Fetched::Absent));
    // put_if_tag with expected None = create; returns the new tag
    let t1 = b
        .put_if_tag("manifest", b"v1", None)
        .unwrap()
        .expect("create succeeds");
    // create again must fail (precondition)
    assert!(b.put_if_tag("manifest", b"v1x", None).unwrap().is_none());
    // conditional get: matching tag => Unchanged; stale/no tag => New with same tag
    assert!(matches!(
        b.get("manifest", Some(&t1)).unwrap(),
        Fetched::Unchanged
    ));
    let Fetched::New { bytes, tag } = b.get("manifest", None).unwrap() else {
        panic!("expected New")
    };
    assert_eq!(bytes, b"v1");
    assert_eq!(tag, t1);
    // CAS: wrong tag refused, right tag succeeds and returns a new tag
    assert!(b
        .put_if_tag("manifest", b"v2", Some("bogus"))
        .unwrap()
        .is_none());
    let t2 = b
        .put_if_tag("manifest", b"v2", Some(&t1))
        .unwrap()
        .expect("cas succeeds");
    assert_ne!(t1, t2);
    // put_new: first write true, second false, content untouched
    assert!(b.put_new("log/1", b"entry-one").unwrap());
    assert!(!b.put_new("log/1", b"entry-two").unwrap());
    let Fetched::New { bytes, .. } = b.get("log/1", None).unwrap() else {
        panic!()
    };
    assert_eq!(bytes, b"entry-one");
    // list is prefix-scoped and sorted
    assert!(b.put_new("log/2", b"x").unwrap());
    assert_eq!(
        b.list("log/").unwrap(),
        vec!["log/1".to_string(), "log/2".to_string()]
    );
    assert_eq!(b.list("packs/").unwrap(), Vec::<String>::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_bucket_passes_contract() {
        let root = std::env::temp_dir().join(format!("scl-objio-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let b = DirBucket::open(&root).unwrap();
        contract_suite(&b);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }
}
