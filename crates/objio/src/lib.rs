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
    /// [`Bucket::put_new`] for several keys at once: one outcome per item, in
    /// input order (`true` = created, `false` = the key already existed and was
    /// left untouched). Empty input is `Ok(vec![])`; a bad or duplicate key is
    /// refused before any write. An error may leave any subset of the keys created
    /// (orphans a compaction sweeps); a retry of the same items is safe because
    /// every key is create-only. A backend that can batch the round trips
    /// overrides this; the default is one `put_new` per item and stops at the
    /// first error.
    fn put_new_batch(&self, items: &[(&str, &[u8])]) -> Result<Vec<bool>> {
        check_batch(items.iter().map(|(k, _)| *k))?;
        items.iter().map(|(k, v)| self.put_new(k, v)).collect()
    }
    /// [`Bucket::exists`] for several keys at once, one answer per key in
    /// input order. Empty input is `Ok(vec![])`. The default is one `exists` per
    /// key.
    fn exists_batch(&self, keys: &[&str]) -> Result<Vec<bool>> {
        keys.iter().map(|k| self.exists(k)).collect()
    }
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
    /// them. A backend that cannot check a lease keeps this default, an error:
    /// a lease is never silently dropped by deleting unconditionally. Only the
    /// Git carrier overrides it, and compaction asks only a Git carrier for it
    /// (the other backends are deleted from with [`Bucket::delete`]).
    fn delete_leased(&self, _items: &[(String, String)]) -> Result<()> {
        Err(Error::Backend(
            "leased delete is not supported by this backend".into(),
        ))
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

/// Refuse a batch that holds a bad key or names a key twice, before any
/// backend writes anything.
pub(crate) fn check_batch<'a>(keys: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for k in keys {
        validate_key(k)?;
        if !seen.insert(k) {
            return Err(Error::Backend(format!("duplicate key {k:?} in a batch")));
        }
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
    // batches: empty is a no-op, outcomes come back in input order, an existing
    // key is reported false and keeps its value
    assert!(b.put_new_batch(&[]).unwrap().is_empty());
    assert!(b.exists_batch(&[]).unwrap().is_empty());
    assert_eq!(
        b.put_new_batch(&[
            ("batch/a", b"1".as_slice()),
            ("log/1", b"clobber".as_slice()),
            ("batch/b", b"2".as_slice()),
        ])
        .unwrap(),
        vec![true, false, true]
    );
    let Fetched::New { bytes, .. } = b.get("log/1", None).unwrap() else {
        panic!()
    };
    assert_eq!(bytes, b"entry-one");
    assert_eq!(
        b.exists_batch(&["batch/b", "batch/none", "batch/a", "log/1"])
            .unwrap(),
        vec![true, false, true, true]
    );
    // a repeated key is refused before anything is written
    assert!(b
        .put_new_batch(&[("batch/c", b"1".as_slice()), ("batch/c", b"2".as_slice())])
        .is_err());
    assert!(!b.exists("batch/c").unwrap());
    // a bad key is refused before anything is written
    assert!(b
        .put_new_batch(&[("batch/d", b"1".as_slice()), ("../x", b"2".as_slice())])
        .is_err());
    assert!(!b.exists("batch/d").unwrap());
}

/// Conformance checks for a backend that overrides [`Bucket::delete_leased`]
/// (only the Git carrier does): it removes keys holding their expected tag, is
/// idempotent, and touches only its keys. Whether a stale tag survives is
/// checked in that backend's own tests. Panics on violation (test helper).
pub fn leased_delete_suite(b: &dyn Bucket) {
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

    /// A backend that cannot check a lease must refuse, not delete without one.
    #[test]
    fn a_backend_without_leases_refuses_a_leased_delete_and_deletes_nothing() {
        let root = std::env::temp_dir().join(format!("scl-objio-nolease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let b = DirBucket::open(&root).unwrap();
        assert!(b.put_new("k", b"v").unwrap());
        let Fetched::New { tag, .. } = b.get("k", None).unwrap() else {
            panic!("k should exist")
        };
        let err = b.delete_leased(&[("k".into(), tag)]).unwrap_err();
        assert!(
            matches!(&err, Error::Backend(m) if m.contains("not supported")),
            "{err}"
        );
        assert!(b.exists("k").unwrap(), "a refused lease must not delete");
        assert!(b.list_tags("").is_err(), "no tagged listing either");
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }
}
