//! Object-storage access for sc bucket remotes (P36, P39).
//!
//! Quarantine rule: object-store SDKs live here and only here — the rest of
//! the workspace sees the [`Bucket`] trait. Leaf crate: depends on no other
//! workspace crate (like `tlsio`). The git backend ([`GitBucket`], the
//! `sc+git::` carrier) spawns the system `git` binary (`SC_GIT` overrides it);
//! it does not use `gix`, which stays quarantined in `gitio`.

mod dir;
pub use dir::DirBucket;
mod git;
pub use git::{redact, GitBucket};
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

/// A listed key with the metadata compaction needs (ADR-0057).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    /// Last-modified time as the bucket reports it (S3 `LastModified`, file mtime).
    pub modified: std::time::SystemTime,
}

/// A flat key/value object store with the three primitives the WAL needs:
/// conditional read, create-if-absent, and compare-and-swap overwrite; plus
/// the metadata listing and delete that compaction (ADR-0057) adds.
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
    /// Keys whose name starts with the raw string `prefix` (not a directory
    /// scope, so `packs/ab12.` matches `packs/ab12.pack`), with size and
    /// last-modified time, sorted by key.
    fn list_meta(&self, prefix: &str) -> Result<Vec<ObjectMeta>>;
    /// Whether `key` exists (a HEAD: needs read rights only, no listing).
    fn exists(&self, key: &str) -> Result<bool>;
    /// Remove `key`. Idempotent: an absent key is success.
    fn delete(&self, key: &str) -> Result<()>;
    /// Keys starting with the raw string `prefix`, each with the tag
    /// [`Bucket::get`] reports for its current value, sorted by key, from one
    /// listing and no value downloads. A backend that cannot list tags cheaply
    /// keeps this default error: compaction asks only a Git carrier for it,
    /// where the tag is the ref's object id and the listing already holds it.
    fn list_tags(&self, _prefix: &str) -> Result<Vec<(String, String)>> {
        Err(Error::Backend(
            "this backend cannot list keys with their tags".into(),
        ))
    }
    /// Remove each `(key, expected_tag)` whose key still holds that tag. A key
    /// that now holds another value (or is already gone) is left alone and is
    /// not an error; a key that still holds its expected tag but could not be
    /// removed is an error. Several keys go in one call so a backend can batch
    /// them. This default has no lease to check, so it deletes each key
    /// unconditionally (what the backends without conditional deletes do); a
    /// backend that can lease must override it (the Git carrier does).
    fn delete_leased(&self, items: &[(String, String)]) -> Result<()> {
        for (key, _) in items {
            self.delete(key)?;
        }
        Ok(())
    }
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
    // list_meta: raw string prefix, sorted, with size and a sane mtime
    assert!(b.put_new("packs/ab12.pack", b"12345").unwrap());
    assert!(b.put_new("packs/ab12.idx", b"1").unwrap());
    assert!(b.put_new("packs/ab34.pack", b"x").unwrap());
    let metas = b.list_meta("packs/ab12.").unwrap();
    assert_eq!(
        metas.iter().map(|m| m.key.as_str()).collect::<Vec<_>>(),
        vec!["packs/ab12.idx", "packs/ab12.pack"]
    );
    assert_eq!(metas[1].size, 5);
    let age = std::time::SystemTime::now()
        .duration_since(metas[1].modified)
        .unwrap_or_default();
    assert!(age < std::time::Duration::from_secs(3600));
    assert_eq!(b.list_meta("packs/").unwrap().len(), 3);
    assert!(b.list_meta("nothing/").unwrap().is_empty());
    assert!(b.exists("packs/ab12.pack").unwrap());
    assert!(!b.exists("packs/zz.pack").unwrap());
    // delete: removes, is idempotent, touches only its key
    b.delete("packs/ab12.pack").unwrap();
    b.delete("packs/ab12.pack").unwrap();
    assert!(matches!(
        b.get("packs/ab12.pack", None).unwrap(),
        Fetched::Absent
    ));
    assert_eq!(b.list_meta("packs/").unwrap().len(), 2);
    // a deleted key can be created again
    assert!(b.put_new("packs/ab12.pack", b"again").unwrap());
    // delete_leased: removes keys holding their expected tag, is idempotent,
    // touches only its keys. Whether a stale tag survives is up to the backend
    // (the default cannot lease), so that is checked in each lease-capable
    // backend's own tests.
    assert!(b.put_new("lease/a", b"1").unwrap());
    assert!(b.put_new("lease/b", b"2").unwrap());
    assert!(b.put_new("lease/keep", b"3").unwrap());
    let tag = |k: &str| match b.get(k, None).unwrap() {
        Fetched::New { tag, .. } => tag,
        _ => panic!("{k} should exist"),
    };
    let (ta, tb) = (tag("lease/a"), tag("lease/b"));
    b.delete_leased(&[("lease/a".into(), ta.clone()), ("lease/b".into(), tb)])
        .unwrap();
    assert_eq!(b.list("lease/").unwrap(), vec!["lease/keep".to_string()]);
    b.delete_leased(&[("lease/a".into(), ta)]).unwrap();
    b.delete_leased(&[]).unwrap();
    assert_eq!(b.list("lease/").unwrap(), vec!["lease/keep".to_string()]);
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
