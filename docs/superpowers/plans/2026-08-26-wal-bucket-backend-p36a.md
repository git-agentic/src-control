# P36a: WAL Bucket Backend — objio + BucketTransport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An S3-compatible bucket (or a local directory standing in for one) becomes an sc remote — `sc remote add origin sc+s3://bucket/prefix` (or `sc+wal://<path>`) with clone/fetch/push, multi-writer safety via one compare-and-swapped manifest, and zero coordinator.

**Architecture:** New leaf crate `objio` (trait `Bucket` + `DirBucket` + `S3Bucket`) quarantines the S3 SDK exactly as `tlsio` quarantines rustls. In `scl-repo`, a `walfmt` module defines the versioned manifest/log-entry codec and a `bucket_transport` module implements the existing `Transport` trait over a `Bucket`, so `open_transport` dispatch gives clone/fetch/push for free — `sync.rs` is untouched. Spec: `docs/superpowers/specs/2026-08-26-wal-bucket-backend-design.md`. Checkpoints (P36b) and bucket-backed `sc serve` (P36c) are separate follow-on plans; the manifest carries a `checkpoint_seq` field from day one so P36b is format-compatible.

**Tech Stack:** Rust 2021 (workspace-inherited), `thiserror`, `blake3`, `hex`; `objio` additionally `aws-sdk-s3` + `aws-config` + `tokio` (current-thread runtime, confined inside the crate behind a sync API).

## Global Constraints

- Dependency direction: `repo → objio`; `objio` depends on **no workspace crate** (leaf, like `tlsio`). `core` never learns about buckets.
- New crate manifest inherits exactly `version`/`edition`/`license`/`publish` via `.workspace = true`, package name `scl-objio`, ends with `[lints] workspace = true` (house pattern, per `crates/tlsio/Cargo.toml`).
- Add deps with `cargo add`, never hand-guessed pins.
- Everything read from a bucket is untrusted: every decoded length is bounds-checked, `scl_core::MAX_OBJECT_SIZE` caps any single fetched value, unknown format versions fail closed.
- Errors: `thiserror` enums, lowercase messages, no trailing period; CLI converts with `?` into `anyhow`.
- Never silently drop data; CAS retry exhaustion and non-fast-forward fail loudly.
- Every test that touches disk cleans up and asserts the path is gone (`let _ = remove_dir_all` at setup, bare `.unwrap()` at teardown — house style per `crates/repo/src/sync.rs:615`).
- Public types/fns get doc comments explaining intent, not mechanics.
- Bucket keys are fixed internal strings (`manifest`, `log/<seq>`, `packs/<hash>.pack|.idx`); `DirBucket` still validates keys against path traversal.
- Partial-clone `filter` over bucket remotes is refused loudly (recorded deferred), never silently ignored.

---

### Task 1: `objio` crate — `Bucket` trait, `DirBucket`, contract tests

**Files:**
- Create: `crates/objio/Cargo.toml`
- Create: `crates/objio/src/lib.rs`
- Create: `crates/objio/src/dir.rs`
- Modify: `Cargo.toml` (workspace members)
- Test: in `#[cfg(test)] mod tests` inside `crates/objio/src/lib.rs` (shared contract fn) — house style is tests next to code

**Interfaces:**
- Consumes: nothing in-workspace (leaf).
- Produces (used by Tasks 2, 4, 5):
  - `scl_objio::Error` (thiserror enum), `scl_objio::Result<T>`
  - `pub enum Fetched { Unchanged, Absent, New { bytes: Vec<u8>, tag: String } }`
  - `pub trait Bucket: Send { fn get(&self, key: &str, cached_tag: Option<&str>) -> Result<Fetched>; fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool>; fn put_if_tag(&self, key: &str, bytes: &[u8], expected_tag: Option<&str>) -> Result<Option<String>>; fn list(&self, prefix: &str) -> Result<Vec<String>>; }`
  - `pub struct DirBucket; impl DirBucket { pub fn open(root: impl Into<PathBuf>) -> Result<DirBucket> }`
  - `pub fn contract_suite(b: &dyn Bucket)` — reusable conformance checks (pub so the S3 test reuses it)

- [ ] **Step 1: Scaffold the crate and register it**

```bash
mkdir -p crates/objio/src
```

`crates/objio/Cargo.toml`:
```toml
[package]
name = "scl-objio"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
thiserror = "2.0.18"

[lints]
workspace = true
```

Then `cargo add --package scl-objio blake3 hex` (tag computation), and edit root `Cargo.toml` members to:
```toml
members = ["crates/core", "crates/vfs", "crates/gitio", "crates/crypto", "crates/repo", "crates/cli", "crates/tlsio", "crates/objio", "apps/desktop/src-tauri"]
```

- [ ] **Step 2: Write the failing contract test**

In `crates/objio/src/lib.rs` (the trait/enum/error will not exist yet — that is the point):

```rust
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
```

And the contract body (in `lib.rs`, `pub` — Task 2's S3 test reuses it):

```rust
/// Conformance checks every `Bucket` implementation must pass.
/// Panics on violation (test helper).
pub fn contract_suite(b: &dyn Bucket) {
    // absent key
    assert!(matches!(b.get("manifest", None).unwrap(), Fetched::Absent));
    // put_if_tag with expected None = create; returns the new tag
    let t1 = b.put_if_tag("manifest", b"v1", None).unwrap().expect("create succeeds");
    // create again must fail (precondition)
    assert!(b.put_if_tag("manifest", b"v1x", None).unwrap().is_none());
    // conditional get: matching tag => Unchanged; stale/no tag => New with same tag
    assert!(matches!(b.get("manifest", Some(&t1)).unwrap(), Fetched::Unchanged));
    let Fetched::New { bytes, tag } = b.get("manifest", None).unwrap() else { panic!("expected New") };
    assert_eq!(bytes, b"v1");
    assert_eq!(tag, t1);
    // CAS: wrong tag refused, right tag succeeds and returns a new tag
    assert!(b.put_if_tag("manifest", b"v2", Some("bogus")).unwrap().is_none());
    let t2 = b.put_if_tag("manifest", b"v2", Some(&t1)).unwrap().expect("cas succeeds");
    assert_ne!(t1, t2);
    // put_new: first write true, second false, content untouched
    assert!(b.put_new("log/1", b"entry-one").unwrap());
    assert!(!b.put_new("log/1", b"entry-two").unwrap());
    let Fetched::New { bytes, .. } = b.get("log/1", None).unwrap() else { panic!() };
    assert_eq!(bytes, b"entry-one");
    // list is prefix-scoped and sorted
    assert!(b.put_new("log/2", b"x").unwrap());
    assert_eq!(b.list("log/").unwrap(), vec!["log/1".to_string(), "log/2".to_string()]);
    assert_eq!(b.list("packs/").unwrap(), Vec::<String>::new());
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p scl-objio`
Expected: compile FAIL — `Bucket`, `Fetched`, `DirBucket`, `contract_suite` not found.

- [ ] **Step 4: Implement `lib.rs` (error, trait, enum) and `dir.rs`**

`crates/objio/src/lib.rs`:
```rust
//! Object-storage access for sc bucket remotes (P36).
//!
//! Quarantine rule: object-store SDKs live here and only here — the rest of
//! the workspace sees the [`Bucket`] trait. Leaf crate: depends on no other
//! workspace crate (like `tlsio`).

mod dir;
pub use dir::DirBucket;

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
    fn put_if_tag(&self, key: &str, bytes: &[u8], expected_tag: Option<&str>) -> Result<Option<String>>;
    /// Keys under `prefix`, sorted.
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Reject traversal and absolute keys before any backend touches them.
pub(crate) fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.starts_with('/')
        || key.contains('\\')
        || key.split('/').any(|c| c.is_empty() || c == "." || c == "..")
        || key.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::BadKey(format!("{key:?}")));
    }
    Ok(())
}
```
(plus `contract_suite` from Step 2 and the test module).

`crates/objio/src/dir.rs` — tag is `hex(blake3(bytes))`; CAS is serialized by a spin-held lock file (local-machine simulation of the S3 precondition; real S3 needs no lock):
```rust
//! Local-directory `Bucket` — the test/demo backend behind `sc+wal://`.

use crate::{validate_key, Bucket, Error, Fetched, Result};
use std::path::{Path, PathBuf};

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
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(CasLock { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Backend(format!("cas lock stuck (stale {} ?)", path.display())))
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

    fn put_if_tag(&self, key: &str, bytes: &[u8], expected_tag: Option<&str>) -> Result<Option<String>> {
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
                    out.push(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
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
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p scl-objio`
Expected: PASS (`dir_bucket_passes_contract`).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/objio
git commit -m "feat(objio): leaf crate with Bucket trait, DirBucket, contract suite (P36a)"
```
(Cargo.lock is staged with the dep change — house rule.)

---

### Task 2: `S3Bucket` — S3-compatible backend behind the same trait

**Files:**
- Create: `crates/objio/src/s3.rs`
- Modify: `crates/objio/src/lib.rs` (add `mod s3; pub use s3::S3Bucket;`)
- Modify: `crates/objio/Cargo.toml` (via `cargo add`)
- Test: env-gated test in `crates/objio/src/s3.rs`

**Interfaces:**
- Consumes: `Bucket`, `Fetched`, `Error`, `Result`, `validate_key`, `contract_suite` from Task 1.
- Produces (used by Task 6): `pub struct S3Bucket; impl S3Bucket { pub fn open(bucket: &str, prefix: &str) -> Result<S3Bucket> }` — implements `Bucket`. Credentials/region/endpoint come from the SDK's standard chain (`AWS_*` env, config files, `AWS_ENDPOINT_URL_S3` for MinIO/R2); sc adds no credential surface.

- [ ] **Step 1: Add the SDK deps**

```bash
cargo add --package scl-objio aws-config aws-sdk-s3 tokio --features tokio/rt
```
(Exact feature flags: `tokio` needs only `rt`; if `cargo add` output shows `aws-config` requires the `behavior-version-latest` feature for `aws_config::load_from_env`, enable it — follow the SDK's own compile errors, do not guess pins.)

- [ ] **Step 2: Write the env-gated failing test**

In `crates/objio/src/s3.rs`:
```rust
#[cfg(test)]
mod tests {
    /// Live-backend parity: set SC_OBJIO_S3_BUCKET (and standard AWS_* env,
    /// e.g. AWS_ENDPOINT_URL_S3 for MinIO) to run; skipped otherwise so CI
    /// stays hermetic on DirBucket.
    #[test]
    fn s3_bucket_passes_contract_when_configured() {
        let Ok(bucket) = std::env::var("SC_OBJIO_S3_BUCKET") else {
            eprintln!("skipped: SC_OBJIO_S3_BUCKET not set");
            return;
        };
        let prefix = format!("scl-objio-contract-{}", std::process::id());
        let b = super::S3Bucket::open(&bucket, &prefix).unwrap();
        crate::contract_suite(&b);
    }
}
```

- [ ] **Step 3: Run to verify it fails to compile**

Run: `cargo test -p scl-objio`
Expected: compile FAIL — `S3Bucket` not found.

- [ ] **Step 4: Implement `S3Bucket`**

Shape (the SDK calls are the part to adapt to the compiler — semantics are fixed):
```rust
//! S3-compatible `Bucket` backend (AWS, MinIO, R2 via AWS_ENDPOINT_URL_S3).

use crate::{validate_key, Bucket, Error, Fetched, Result};

pub struct S3Bucket {
    rt: tokio::runtime::Runtime,
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl S3Bucket {
    /// Connect using the SDK's standard credential/region/endpoint chain.
    pub fn open(bucket: &str, prefix: &str) -> Result<S3Bucket> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Backend(format!("tokio runtime: {e}")))?;
        let conf = rt.block_on(aws_config::load_from_env());
        Ok(S3Bucket {
            client: aws_sdk_s3::Client::new(&conf),
            rt,
            bucket: bucket.to_string(),
            prefix: prefix.trim_matches('/').to_string(),
        })
    }

    fn full_key(&self, key: &str) -> Result<String> {
        validate_key(key)?;
        Ok(if self.prefix.is_empty() { key.to_string() } else { format!("{}/{key}", self.prefix) })
    }
}

impl Bucket for S3Bucket {
    fn get(&self, key: &str, cached_tag: Option<&str>) -> Result<Fetched> {
        let k = self.full_key(key)?;
        let mut req = self.client.get_object().bucket(&self.bucket).key(&k);
        if let Some(tag) = cached_tag {
            req = req.if_none_match(tag);
        }
        match self.rt.block_on(async {
            match req.send().await {
                Ok(out) => {
                    let tag = out.e_tag().unwrap_or_default().to_string();
                    let bytes = out.body.collect().await.map(|b| b.into_bytes().to_vec());
                    Ok(Some((bytes, tag)))
                }
                Err(e) => Err(e),
            }
        }) {
            Ok(Some((Ok(bytes), tag))) => Ok(Fetched::New { bytes, tag }),
            Ok(Some((Err(e), _))) => Err(Error::Backend(format!("s3 get body: {e}"))),
            Ok(None) => unreachable!(),
            Err(e) => {
                // 304 => Unchanged; NoSuchKey/404 => Absent; else Backend
                let raw = aws_sdk_s3::error::ProvideErrorMetadata::code(&e).unwrap_or_default().to_string();
                let http = e.raw_response().map(|r| r.status().as_u16());
                match (raw.as_str(), http) {
                    (_, Some(304)) => Ok(Fetched::Unchanged),
                    ("NoSuchKey", _) | (_, Some(404)) => Ok(Fetched::Absent),
                    _ => Err(Error::Backend(format!("s3 get {k}: {e}"))),
                }
            }
        }
    }

    fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let k = self.full_key(key)?;
        let req = self.client.put_object().bucket(&self.bucket).key(&k)
            .if_none_match("*")
            .body(bytes.to_vec().into());
        match self.rt.block_on(req.send()) {
            Ok(_) => Ok(true),
            Err(e) if e.raw_response().map(|r| r.status().as_u16()) == Some(412) => Ok(false),
            Err(e) => Err(Error::Backend(format!("s3 put_new {k}: {e}"))),
        }
    }

    fn put_if_tag(&self, key: &str, bytes: &[u8], expected_tag: Option<&str>) -> Result<Option<String>> {
        let k = self.full_key(key)?;
        let mut req = self.client.put_object().bucket(&self.bucket).key(&k).body(bytes.to_vec().into());
        req = match expected_tag {
            Some(tag) => req.if_match(tag),
            None => req.if_none_match("*"),
        };
        match self.rt.block_on(req.send()) {
            Ok(out) => Ok(Some(out.e_tag().unwrap_or_default().to_string())),
            Err(e) if e.raw_response().map(|r| r.status().as_u16()) == Some(412) => Ok(None),
            Err(e) => Err(Error::Backend(format!("s3 put_if_tag {k}: {e}"))),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let full = self.full_key(prefix.trim_end_matches('/'))?;
        let mut out = Vec::new();
        let mut cont: Option<String> = None;
        loop {
            let mut req = self.client.list_objects_v2().bucket(&self.bucket).prefix(format!("{full}/"));
            if let Some(c) = &cont {
                req = req.continuation_token(c);
            }
            let resp = self.rt.block_on(req.send()).map_err(|e| Error::Backend(format!("s3 list: {e}")))?;
            for obj in resp.contents() {
                if let Some(k) = obj.key() {
                    let rel = k.strip_prefix(&self.prefix).unwrap_or(k).trim_start_matches('/');
                    out.push(rel.to_string());
                }
            }
            match resp.next_continuation_token() {
                Some(c) => cont = Some(c.to_string()),
                None => break,
            }
        }
        out.sort();
        Ok(out)
    }
}
```
Adapt method/type names to the SDK the compiler presents (e.g. the exact error-inspection API); the **semantics table is the contract**: 304→`Unchanged`, 404/NoSuchKey→`Absent`, 412→`put_new false` / `put_if_tag None`. Important: S3 ETags for plain PUTs are quoted MD5 strings — treat them as opaque tags (never parse), which the trait already enforces.

- [ ] **Step 5: Verify compile + contract**

Run: `cargo test -p scl-objio` (compiles, s3 test self-skips).
If MinIO is available locally: `docker run -d --rm -p 9000:9000 -e MINIO_ROOT_USER=sc -e MINIO_ROOT_PASSWORD=scsecret1 --name scminio minio/minio server /data`, create a bucket `scl-test` with `mc`, then
`AWS_ACCESS_KEY_ID=sc AWS_SECRET_ACCESS_KEY=scsecret1 AWS_REGION=us-east-1 AWS_ENDPOINT_URL_S3=http://127.0.0.1:9000 SC_OBJIO_S3_BUCKET=scl-test cargo test -p scl-objio s3_bucket_passes_contract -- --nocapture` — Expected: PASS. Not required for the task to land (CI stays DirBucket-only).

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/objio
git commit -m "feat(objio): S3-compatible Bucket backend, env-gated live contract test (P36a)"
```

---

### Task 3: `walfmt` — manifest + log-entry codec in `repo`

**Files:**
- Modify: `crates/repo/Cargo.toml` (add `scl-objio = { version = "0.1.0", path = "../objio" }` — same shape as the `scl-tlsio` line at `crates/repo/Cargo.toml:17`)
- Modify: `crates/repo/src/lib.rs` (add `pub mod walfmt;` and `pub mod bucket_transport;` placeholder comes in Task 4 — here only `walfmt`)
- Modify: `crates/repo/src/error.rs` (two new variants)
- Create: `crates/repo/src/walfmt.rs`
- Test: `#[cfg(test)] mod tests` in `walfmt.rs`

**Interfaces:**
- Consumes: `scl_core::{ObjectId, MAX_OBJECT_SIZE}`.
- Produces (used by Tasks 4, 5):
  - `pub struct Manifest { pub head_seq: u64, pub checkpoint_seq: u64, pub head_branch: String }` with `pub fn encode(&self) -> Vec<u8>` / `pub fn decode(bytes: &[u8]) -> Result<Manifest>`
  - `pub struct RefUpdate { pub branch: String, pub old: Option<ObjectId>, pub new: ObjectId }`
  - `pub struct LogEntry { pub seq: u64, pub parent_seq: u64, pub packs: Vec<String>, pub updates: Vec<RefUpdate> }` with `encode`/`decode` same shape
  - `pub fn log_key(seq: u64) -> String` → `log/<seq zero-padded to 20>`; `pub fn pack_key(hash: &str) -> String` → `packs/<hash>.pack`; `pub fn idx_key(hash: &str) -> String` → `packs/<hash>.idx`
  - New error variants: `Error::Wal(String)` (`#[error("bucket wal: {0}")]`) and `Error::ObjIo(#[from] scl_objio::Error)` (`#[error("bucket: {0}")]`)

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::ObjectId;

    fn some_id(byte: u8) -> ObjectId {
        // Any real id: hash a one-byte payload. Use whatever constructor
        // refs::read_branch_tip uses to parse hex tips (check refs.rs:35 and
        // reuse the identical call) — or simplest: ObjectId::of(&[byte]).
        ObjectId::of(&[byte])
    }

    #[test]
    fn manifest_round_trips_and_rejects_garbage() {
        let m = Manifest { head_seq: 7, checkpoint_seq: 0, head_branch: "main".into() };
        let bytes = m.encode();
        let back = Manifest::decode(&bytes).unwrap();
        assert_eq!(back.head_seq, 7);
        assert_eq!(back.checkpoint_seq, 0);
        assert_eq!(back.head_branch, "main");
        // wrong magic, truncated, future version, trailing junk: all refused
        assert!(Manifest::decode(b"XXXX").is_err());
        assert!(Manifest::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut future = bytes.clone();
        future[4] = 0xFF; // bump version byte
        assert!(Manifest::decode(&future).is_err());
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(Manifest::decode(&junk).is_err());
    }

    #[test]
    fn log_entry_round_trips_with_and_without_old_tips() {
        let e = LogEntry {
            seq: 3,
            parent_seq: 2,
            packs: vec!["ab12".into()],
            updates: vec![
                RefUpdate { branch: "main".into(), old: Some(some_id(1)), new: some_id(2) },
                RefUpdate { branch: "feat".into(), old: None, new: some_id(3) },
            ],
        };
        let back = LogEntry::decode(&e.encode()).unwrap();
        assert_eq!(back.seq, 3);
        assert_eq!(back.parent_seq, 2);
        assert_eq!(back.packs, vec!["ab12".to_string()]);
        assert_eq!(back.updates.len(), 2);
        assert_eq!(back.updates[0].old, Some(some_id(1)));
        assert_eq!(back.updates[1].old, None);
        assert_eq!(back.updates[1].new, some_id(3));
    }

    #[test]
    fn decode_caps_hostile_lengths() {
        // a length prefix claiming 1 GiB must fail fast, not allocate
        let mut evil = Manifest { head_seq: 1, checkpoint_seq: 0, head_branch: "m".into() }.encode();
        let n = evil.len();
        evil[n - 2..].copy_from_slice(&[0xFF, 0xFF]); // corrupt branch length tail
        assert!(Manifest::decode(&evil).is_err());
    }

    #[test]
    fn keys_are_stable() {
        assert_eq!(log_key(7), "log/00000000000000000007");
        assert_eq!(pack_key("abcd"), "packs/abcd.pack");
        assert_eq!(idx_key("abcd"), "packs/abcd.idx");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo walfmt`
Expected: compile FAIL — module/types not found.

- [ ] **Step 3: Implement the codec**

`crates/repo/src/walfmt.rs`. Encoding rules (all little-endian, strict decode = every length bounds-checked against remaining input, entire buffer must be consumed):

- Manifest: `b"SCWM"` + `u32 version=1` + `u64 head_seq` + `u64 checkpoint_seq` + `u32 branch_len` + branch UTF-8. `branch_len` cap 4096.
- LogEntry: `b"SCWE"` + `u32 version=1` + `u64 seq` + `u64 parent_seq` + `u32 npacks` (cap 65536) + per pack (`u32 len` cap 128 + ASCII-hex string) + `u32 nupdates` (cap 65536) + per update (`u32 branch_len` cap 4096 + branch + `u8 has_old` (0/1 only) + optional 32 raw old bytes + 32 raw new bytes).

```rust
//! On-bucket WAL encoding (P36a). Versioned, strict, fail-closed: readers
//! refuse unknown versions and any length that overruns the buffer.

use crate::error::{Error, Result};
use scl_core::ObjectId;

const MANIFEST_MAGIC: &[u8; 4] = b"SCWM";
const ENTRY_MAGIC: &[u8; 4] = b"SCWE";
const VERSION: u32 = 1;
const MAX_NAME: usize = 4096;
const MAX_LIST: usize = 65536;

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.at < n {
            return Err(Error::Wal(format!("truncated at byte {}", self.at)));
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn string(&mut self, cap: usize) -> Result<String> {
        let n = self.u32()? as usize;
        if n > cap {
            return Err(Error::Wal(format!("length {n} exceeds cap {cap}")));
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error::Wal("non-utf8 name".into()))
    }
    fn id(&mut self) -> Result<ObjectId> {
        let raw: [u8; 32] = self.take(32)?.try_into().unwrap();
        Ok(ObjectId::from_bytes(raw)) // ← if no such constructor exists, check
        // how scl-core builds an ObjectId from raw digest bytes (grep
        // `impl ObjectId` in crates/core) and use that; ids are 32 raw bytes
        // on the wire here, never hex.
    }
    fn done(&self) -> Result<()> {
        if self.at != self.buf.len() {
            return Err(Error::Wal(format!("{} trailing bytes", self.buf.len() - self.at)));
        }
        Ok(())
    }
}

fn header<'a>(bytes: &'a [u8], magic: &[u8; 4], what: &str) -> Result<Cursor<'a>> {
    let mut c = Cursor { buf: bytes, at: 0 };
    if c.take(4)? != magic {
        return Err(Error::Wal(format!("not a {what} (bad magic)")));
    }
    let v = c.u32()?;
    if v != VERSION {
        return Err(Error::Wal(format!("{what} version {v} not supported (this build speaks {VERSION})")));
    }
    Ok(c)
}
```
then `Manifest`/`RefUpdate`/`LogEntry` structs with `encode` (mirror writes: `extend_from_slice(magic)`, `to_le_bytes`, …) and `decode` using the cursor, ending with `c.done()?`. Key helpers:
```rust
/// `log/<seq>` zero-padded so lexical order == numeric order.
pub fn log_key(seq: u64) -> String {
    format!("log/{seq:020}")
}
pub fn pack_key(hash: &str) -> String {
    format!("packs/{hash}.pack")
}
pub fn idx_key(hash: &str) -> String {
    format!("packs/{hash}.idx")
}
```
Error variants appended at the **end** of the enum in `crates/repo/src/error.rs` (house pattern — recent variants last, with rationale docs):
```rust
    /// P36a: the bucket WAL is untrusted input; decode/consistency failures
    /// are their own variant so callers can distinguish "bucket corrupt or
    /// newer-format" from transport errors.
    #[error("bucket wal: {0}")]
    Wal(String),
    #[error("bucket: {0}")]
    ObjIo(#[from] scl_objio::Error),
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo walfmt`
Expected: PASS (4 tests). If `ObjectId::from_bytes`/`ObjectId::of` names differ, fix to the real constructors found in `crates/core` — the test and impl must use the same ones.

- [ ] **Step 5: Commit**

```bash
git add Cargo.lock crates/repo
git commit -m "feat(repo): walfmt manifest/log-entry codec, strict versioned decode (P36a)"
```

---

### Task 4: `BucketTransport` read half — WAL view, refs, objects, `get_pack`

**Files:**
- Create: `crates/repo/src/bucket_transport.rs`
- Modify: `crates/repo/src/lib.rs` (`pub mod bucket_transport;`)
- Test: `#[cfg(test)] mod tests` in `bucket_transport.rs`

**Interfaces:**
- Consumes: Task 1 trait (`scl_objio::{Bucket, DirBucket, Fetched}`), Task 3 codec, `scl_core::pack::{parse_index, read_object_at, PackWriter, IndexEntry}`, `crate::reachable::{ObjectSource, reachable_objects}`, `scl_core::{Object, ObjectId, MAX_OBJECT_SIZE}`.
- Produces (used by Tasks 5, 6):
  - `pub struct BucketTransport` with `pub fn from_bucket(bucket: Box<dyn scl_objio::Bucket>) -> Result<BucketTransport>` (Task 6 adds `open(url)`)
  - internal `fn refresh(&self) -> Result<()>`, `fn view(&self) -> Ref<'_, Option<WalView>>`, `fn object_bytes(&self, id: &ObjectId) -> Result<Vec<u8>>`
  - read-half `Transport` methods compile (write half `todo!()`-free: Task 5 fills them — until then they return `Err(Error::Wal("write half lands in Task 5".into()))` so the crate stays warning-clean and honest)

- [ ] **Step 1: Write the failing test — seed a bucket by hand, read it back**

The test builds a tiny WAL directly with `walfmt` + `DirBucket` (no write half yet), packing objects from a scratch persistent `Store`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Transport;
    use crate::walfmt::{idx_key, log_key, pack_key, LogEntry, Manifest, RefUpdate};
    use scl_core::{Object, ObjectId};
    use scl_objio::{Bucket, DirBucket};

    /// Build pack+idx bytes for the given objects (reuses core's builder).
    fn pack_of(objects: &[(ObjectId, Vec<u8>)]) -> (String, Vec<u8>, Vec<u8>) {
        let (pack, idx) = scl_core::pack::build_pack(objects).unwrap();
        let hash = hex::encode(blake3::hash(&pack).as_bytes());
        (hash, pack, idx)
    }

    /// A minimal one-commit object set: blob → tree → snapshot, exactly as a
    /// real repo would store them. Reuse the object constructors the repo
    /// crate already uses in its own tests (see sync.rs tests for the
    /// canonical way to mint a commit); returns (tip, objects).
    fn tiny_history() -> (ObjectId, Vec<(ObjectId, Vec<u8>)>) {
        let root = std::env::temp_dir().join(format!("scl-bt-hist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"hello wal").unwrap();
        let tip = repo.commit("t", "c1").unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = crate::reachable::reachable_objects(&mut *store, &[tip]).unwrap();
        let objects = ids.iter().map(|id| (*id, store.get(id).unwrap().encode())).collect();
        drop(store);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        (tip, objects)
    }

    #[test]
    fn reads_refs_objects_and_packs_from_a_hand_built_wal() {
        let broot = std::env::temp_dir().join(format!("scl-bt-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let bucket = DirBucket::open(&broot).unwrap();

        let (tip, objects) = tiny_history();
        let (hash, pack, idx) = pack_of(&objects);
        assert!(bucket.put_new(&pack_key(&hash), &pack).unwrap());
        assert!(bucket.put_new(&idx_key(&hash), &idx).unwrap());
        let entry = LogEntry {
            seq: 1,
            parent_seq: 0,
            packs: vec![hash.clone()],
            updates: vec![RefUpdate { branch: "main".into(), old: None, new: tip }],
        };
        assert!(bucket.put_new(&log_key(1), &entry.encode()).unwrap());
        let m = Manifest { head_seq: 1, checkpoint_seq: 0, head_branch: "main".into() };
        bucket.put_if_tag("manifest", &m.encode(), None).unwrap().unwrap();

        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert_eq!(t.head_branch().unwrap(), "main");
        assert!(t.has_object(&tip).unwrap());
        let bytes = t.get_object(&tip).unwrap();
        assert_eq!(ObjectId::of(&bytes), tip);
        // get_pack: full closure with no haves reproduces every object
        let mut out = Vec::new();
        t.get_pack(&[tip], &[], None, &mut out).unwrap();
        let got = scl_core::pack::parse_pack(&out).unwrap();
        assert_eq!(got.len(), objects.len());
        // filter is refused loudly, not ignored
        let filt = vec!["src/".to_string()];
        assert!(t.get_pack(&[tip], &[], Some(&filt), &mut Vec::new()).is_err());
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
    }

    #[test]
    fn empty_bucket_lists_no_refs_and_head_branch_errors() {
        let broot = std::env::temp_dir().join(format!("scl-bt-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t.list_refs().unwrap(), Vec::<(String, ObjectId)>::new());
        assert!(t.head_branch().is_err());
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
    }

    #[test]
    fn off_chain_log_entries_are_ignored() {
        // manifest head=1; a stray log/2 (orphan from a crashed/losing pusher)
        // must not affect refs.
        let broot = std::env::temp_dir().join(format!("scl-bt-orphan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let bucket = DirBucket::open(&broot).unwrap();
        let (tip, objects) = tiny_history();
        let (hash, pack, idx) = pack_of(&objects);
        bucket.put_new(&pack_key(&hash), &pack).unwrap();
        bucket.put_new(&idx_key(&hash), &idx).unwrap();
        let e1 = LogEntry { seq: 1, parent_seq: 0, packs: vec![hash],
            updates: vec![RefUpdate { branch: "main".into(), old: None, new: tip }] };
        bucket.put_new(&log_key(1), &e1.encode()).unwrap();
        let orphan = LogEntry { seq: 2, parent_seq: 1, packs: vec![],
            updates: vec![RefUpdate { branch: "evil".into(), old: None, new: tip }] };
        bucket.put_new(&log_key(2), &orphan.encode()).unwrap();
        let m = Manifest { head_seq: 1, checkpoint_seq: 0, head_branch: "main".into() };
        bucket.put_if_tag("manifest", &m.encode(), None).unwrap().unwrap();

        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
    }
}
```
(`hex` and `blake3` are already deps of `scl-repo` — see `crates/repo/Cargo.toml:18-19`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo bucket_transport`
Expected: compile FAIL — `BucketTransport` not found.

- [ ] **Step 3: Implement the read half**

`crates/repo/src/bucket_transport.rs`:

```rust
//! A [`Transport`] over an object-store bucket (P36a): immutable packs +
//! parent-linked log entries, one CAS'd manifest as the sole commit point.
//! See ADR-0046 and docs/superpowers/specs/2026-08-26-wal-bucket-backend-design.md.

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::walfmt::{idx_key, log_key, pack_key, LogEntry, Manifest, RefUpdate};
use scl_core::pack::{parse_index, read_object_at, IndexEntry, PackWriter};
use scl_core::{Object, ObjectId};
use scl_objio::{Bucket, Fetched};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;

/// Reconstructed state of the WAL at one manifest tag.
struct WalView {
    tag: String,
    manifest: Manifest,
    /// branch -> tip, after replaying the parent chain oldest-first.
    refs: BTreeMap<String, ObjectId>,
    /// object id -> (pack hash, offset, length), from every on-chain pack's idx.
    index: BTreeMap<ObjectId, (String, u64, u64)>,
}

pub struct BucketTransport {
    bucket: Box<dyn Bucket>,
    view: RefCell<Option<WalView>>,
    /// Body bytes of the most recently used pack (walk locality).
    pack_cache: RefCell<Option<(String, Vec<u8>)>>,
    // Task 5 adds: staged objects + pending pack hashes.
}

/// Untrusted-length guard (P28 parity): refuse any WAL metadata value —
/// manifest, log entry, idx — larger than MAX_OBJECT_SIZE before decoding.
/// (Pack bodies may legitimately exceed it; their per-record lengths are
/// capped inside `parse_pack_reader`/`read_object_at` in core.)
fn capped(what: &str, bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.len() > scl_core::MAX_OBJECT_SIZE {
        return Err(Error::Wal(format!("{what} exceeds MAX_OBJECT_SIZE (256 MiB)")));
    }
    Ok(bytes)
}

impl BucketTransport {
    pub fn from_bucket(bucket: Box<dyn Bucket>) -> Result<BucketTransport> {
        let t = BucketTransport {
            bucket,
            view: RefCell::new(None),
            pack_cache: RefCell::new(None),
        };
        t.refresh()?;
        Ok(t)
    }

    /// One conditional GET of the manifest; on change, rebuild refs + index
    /// by walking parent links head -> 0 (seq numbers are claims; the chain
    /// is the truth — off-chain entries are garbage).
    fn refresh(&self) -> Result<()> {
        let cached_tag = self.view.borrow().as_ref().map(|v| v.tag.clone());
        match self.bucket.get("manifest", cached_tag.as_deref())? {
            Fetched::Unchanged => Ok(()),
            Fetched::Absent => {
                *self.view.borrow_mut() = None;
                Ok(())
            }
            Fetched::New { bytes, tag } => {
                let bytes = capped("manifest", bytes)?;
                let manifest = Manifest::decode(&bytes)?;
                let mut entries = Vec::new();
                let mut seq = manifest.head_seq;
                while seq != 0 {
                    let Fetched::New { bytes, .. } = self.bucket.get(&log_key(seq), None)? else {
                        return Err(Error::Wal(format!("log entry {seq} referenced by chain but absent")));
                    };
                    let e = LogEntry::decode(&capped("log entry", bytes)?)?;
                    if e.seq != seq {
                        return Err(Error::Wal(format!("log entry at {} claims seq {}", seq, e.seq)));
                    }
                    seq = e.parent_seq;
                    if e.parent_seq >= e.seq {
                        return Err(Error::Wal(format!("log entry {} has non-decreasing parent {}", e.seq, e.parent_seq)));
                    }
                    entries.push(e);
                }
                entries.reverse(); // oldest first
                let mut refs = BTreeMap::new();
                let mut index = BTreeMap::new();
                for e in &entries {
                    for u in &e.updates {
                        crate::refs::validate_incoming_branch(&u.branch)?; // see note below
                        refs.insert(u.branch.clone(), u.new);
                    }
                    for hash in &e.packs {
                        let Fetched::New { bytes, .. } = self.bucket.get(&idx_key(hash), None)? else {
                            return Err(Error::Wal(format!("pack {hash} on chain but idx absent")));
                        };
                        let bytes = capped("pack idx", bytes)?;
                        for IndexEntry { id, offset, length } in parse_index(&bytes)? {
                            index.insert(id, (hash.clone(), offset, length));
                        }
                    }
                }
                *self.view.borrow_mut() = Some(WalView { tag, manifest, refs, index });
                Ok(())
            }
        }
    }

    /// Canonical bytes of one object, via its pack (downloaded + cached).
    fn object_bytes(&self, id: &ObjectId) -> Result<Vec<u8>> {
        let (hash, offset, _len) = {
            let view = self.view.borrow();
            let view = view.as_ref().ok_or_else(|| Error::Wal("bucket remote is empty".into()))?;
            view.index.get(id).cloned().ok_or(Error::CorruptObject(*id))?
        };
        let mut cache = self.pack_cache.borrow_mut();
        if cache.as_ref().map(|(h, _)| h.as_str()) != Some(hash.as_str()) {
            let Fetched::New { bytes, .. } = self.bucket.get(&pack_key(&hash), None)? else {
                return Err(Error::Wal(format!("pack {hash} on chain but body absent")));
            };
            *cache = Some((hash.clone(), bytes));
        }
        let (_, pack) = cache.as_ref().unwrap();
        Ok(read_object_at(pack, offset, id)?.encode())
    }
}

/// `ObjectSource` over the bucket for reachability walks.
struct BucketSource<'a>(&'a BucketTransport);
impl crate::reachable::ObjectSource for BucketSource<'_> {
    fn get(&mut self, id: &ObjectId) -> Result<Object> {
        let bytes = self.0.object_bytes(id)?;
        Object::decode(&bytes).map_err(Into::into)
    }
}
```

Two adaptation notes for the implementer:
- `validate_incoming_branch`: `validate_branch_name` is `pub(crate)` at `crates/repo/src/repo.rs:1913` and re-exported crate-internally at `refs.rs:13` — call it as `crate::refs::validate_branch_name(&u.branch)?` (same-crate, so visibility is fine); the name in the sketch is a placeholder for exactly that call.
- If `read_object_at`'s `length` field or `Object::decode`'s error type differ in detail, follow the real signatures in `crates/core/src/pack.rs:202` and the object codec — the test pins behavior.

`Transport` impl, read methods (write half stubs return `Err(Error::Wal("bucket write half lands in Task 5".into()))` for now):
```rust
impl Transport for BucketTransport {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        self.refresh()?;
        Ok(self.view.borrow().as_ref()
            .map(|v| v.refs.iter().map(|(b, id)| (b.clone(), *id)).collect())
            .unwrap_or_default())
    }

    fn head_branch(&self) -> Result<String> {
        self.refresh()?;
        self.view.borrow().as_ref()
            .map(|v| v.manifest.head_branch.clone())
            .ok_or_else(|| Error::Remote("bucket remote is empty (no manifest)".into()))
    }

    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        self.refresh()?;
        Ok(self.view.borrow().as_ref().is_some_and(|v| v.index.contains_key(id)))
    }

    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.refresh()?;
        self.object_bytes(id)
    }

    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId], filter: Option<&[String]>, out: &mut dyn Write) -> Result<()> {
        if filter.is_some() {
            return Err(Error::InvalidArgument(
                "partial clone from bucket remotes is not supported yet; clone via a served remote".into(),
            ));
        }
        self.refresh()?;
        let mut src = BucketSource(self);
        // haves the bucket doesn't know can't shrink the pack — skip them.
        let known_haves: Vec<ObjectId> = {
            let view = self.view.borrow();
            haves.iter().copied()
                .filter(|h| view.as_ref().is_some_and(|v| v.index.contains_key(h)))
                .collect()
        };
        let have_set = crate::reachable::reachable_objects(&mut src, &known_haves)?;
        let want_set = crate::reachable::reachable_objects(&mut src, wants)?;
        let ids: Vec<ObjectId> = want_set.difference(&have_set).copied().collect();
        let mut writer = PackWriter::new(out, ids.len() as u32)?;
        for id in &ids {
            let bytes = self.object_bytes(id)?;
            writer.write_object(id, &bytes)?;
        }
        writer.finish()?; // idx discarded — transfer needs the body only
        Ok(())
    }

    fn put_object(&self, _id: &ObjectId, _bytes: &[u8]) -> Result<()> {
        Err(Error::Wal("bucket write half lands in Task 5".into()))
    }
    fn update_ref(&self, _branch: &str, _id: &ObjectId, _expected_old: Option<&ObjectId>) -> Result<()> {
        Err(Error::Wal("bucket write half lands in Task 5".into()))
    }
    fn put_pack(&self, _src: &mut dyn std::io::Read) -> Result<Vec<ObjectId>> {
        Err(Error::Wal("bucket write half lands in Task 5".into()))
    }
}
```
Add `pub mod bucket_transport;` to `crates/repo/src/lib.rs` alongside the other `pub mod` transport lines.

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo bucket_transport`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/repo
git commit -m "feat(repo): BucketTransport read half — WAL view, refs, objects, get_pack (P36a)"
```

---

### Task 5: `BucketTransport` write half — staging, `put_pack`, CAS `update_ref`

**Files:**
- Modify: `crates/repo/src/bucket_transport.rs`
- Test: extend `#[cfg(test)] mod tests` there

**Interfaces:**
- Consumes: Task 4's struct + view; `scl_core::pack::{build_pack, parse_pack_reader}`; `scl_objio::Bucket::{put_new, put_if_tag}`; `crate::walfmt`.
- Produces (used by Tasks 6, 7): the complete `Transport` impl. Commit protocol (fixed contract): flush staged objects → upload `packs/<hash>.pack`+`.idx` (`put_new`, exists = dedup success) → write `log/<seq>` (`put_new`, taken seq → next) → CAS `manifest` (`put_if_tag`). On CAS loss: if this branch's tip moved off `expected_old` → `Error::NonFastForward`; otherwise re-read and retry (fresh log entry, correct parent; the old entry becomes off-chain garbage). `MAX_CAS_RETRIES: u32 = 16`, exhaustion → `Error::Remote("manifest cas contention: gave up after 16 attempts")`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn push_via_trait_round_trips_into_a_fresh_bucket() {
        let broot = std::env::temp_dir().join(format!("scl-bt-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();

        let (tip, objects) = tiny_history();
        // exactly what sync::push does: pack, then CAS'd ref update
        let (pack, _idx) = scl_core::pack::build_pack(&objects).unwrap();
        let ids = t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        assert_eq!(ids.len(), objects.len());
        t.update_ref("main", &tip, None).unwrap();

        // a second transport sees it
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t2.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert_eq!(t2.head_branch().unwrap(), "main");
        assert!(t2.has_object(&tip).unwrap());
        drop((t, t2));
        std::fs::remove_dir_all(&broot).unwrap();
    }

    #[test]
    fn update_ref_honors_expected_old_semantics() {
        let broot = std::env::temp_dir().join(format!("scl-bt-cas-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (tip, objects) = tiny_history();
        let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
        t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        t.update_ref("main", &tip, None).unwrap();
        // stale expected_old (None while the branch exists) => NonFastForward
        let other = ObjectId::of(b"not the tip");
        assert!(matches!(t.update_ref("main", &other, None), Err(Error::NonFastForward)));
        // setting to the value it already has succeeds regardless of expected_old (trait doc)
        t.update_ref("main", &tip, None).unwrap();
        t.update_ref("main", &tip, Some(&other)).unwrap();
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
    }

    #[test]
    fn put_object_stages_and_update_ref_commits_them() {
        let broot = std::env::temp_dir().join(format!("scl-bt-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (tip, objects) = tiny_history();
        for (id, bytes) in &objects {
            t.put_object(id, bytes).unwrap();
        }
        // corrupt bytes are rejected at staging time
        assert!(t.put_object(&tip, b"garbage").is_err());
        t.update_ref("main", &tip, None).unwrap();
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert!(t2.has_object(&tip).unwrap());
        drop((t, t2));
        std::fs::remove_dir_all(&broot).unwrap();
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo bucket_transport`
Expected: the three new tests FAIL with `Error::Wal("bucket write half lands in Task 5")`.

- [ ] **Step 3: Implement**

Add fields to the struct:
```rust
    /// Objects staged by `put_object`, flushed into a pack at `update_ref`.
    staged: RefCell<Vec<(ObjectId, Vec<u8>)>>,
    /// Hashes of packs uploaded (put_pack / flushed staging) awaiting a
    /// manifest commit that references them.
    pending_packs: RefCell<Vec<String>>,
```
Upload helper + trait methods:
```rust
impl BucketTransport {
    /// Upload one pack (+idx) content-addressed by BLAKE3 of the pack bytes.
    /// Already-present keys are success (identical content — dedup).
    fn upload_pack(&self, objects: &[(ObjectId, Vec<u8>)]) -> Result<(String, Vec<ObjectId>)> {
        let (pack, idx) = scl_core::pack::build_pack(objects)?;
        let hash = hex::encode(blake3::hash(&pack).as_bytes());
        self.bucket.put_new(&pack_key(&hash), &pack)?;
        self.bucket.put_new(&idx_key(&hash), &idx)?;
        Ok((hash, objects.iter().map(|(id, _)| *id).collect()))
    }

    fn flush_staged(&self) -> Result<()> {
        let staged = std::mem::take(&mut *self.staged.borrow_mut());
        if staged.is_empty() {
            return Ok(());
        }
        let (hash, _) = self.upload_pack(&staged)?;
        self.pending_packs.borrow_mut().push(hash);
        Ok(())
    }
}
```
```rust
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if ObjectId::of(bytes) != *id {
            return Err(Error::CorruptObject(*id));
        }
        self.staged.borrow_mut().push((*id, bytes.to_vec()));
        Ok(())
    }

    fn put_pack(&self, src: &mut dyn std::io::Read) -> Result<Vec<ObjectId>> {
        // Spill + verify first (P25 invariant: never trust a live stream),
        // then rebuild deterministically — build_pack output is byte-stable
        // for the same objects in the same order (pinned in core), so the
        // rebuilt pack's hash names identical content identically.
        let mut objects: Vec<(ObjectId, Vec<u8>)> = Vec::new();
        scl_core::pack::parse_pack_reader(src, |id, obj| {
            objects.push((id, obj.encode()));
            Ok(())
        })?;
        let (hash, ids) = self.upload_pack(&objects)?;
        self.pending_packs.borrow_mut().push(hash);
        Ok(ids)
    }

    fn update_ref(&self, branch: &str, id: &ObjectId, expected_old: Option<&ObjectId>) -> Result<()> {
        self.flush_staged()?;
        const MAX_CAS_RETRIES: u32 = 16;
        for _ in 0..MAX_CAS_RETRIES {
            self.refresh()?;
            let (current, prev_tag, head_seq, checkpoint_seq, head_branch) = {
                let view = self.view.borrow();
                match view.as_ref() {
                    Some(v) => (
                        v.refs.get(branch).copied(),
                        Some(v.tag.clone()),
                        v.manifest.head_seq,
                        v.manifest.checkpoint_seq,
                        v.manifest.head_branch.clone(),
                    ),
                    None => (None, None, 0, 0, branch.to_string()),
                }
            };
            if current.as_ref() == Some(id) {
                self.pending_packs.borrow_mut().clear(); // already there — idempotent
                return Ok(());
            }
            if current.as_ref() != expected_old {
                return Err(Error::NonFastForward);
            }
            // claim a seq (collisions with orphans just advance)
            let entry = LogEntry {
                seq: 0, // set in the claim loop
                parent_seq: head_seq,
                packs: self.pending_packs.borrow().clone(),
                updates: vec![RefUpdate { branch: branch.to_string(), old: current, new: *id }],
            };
            let mut seq = head_seq + 1;
            let seq = loop {
                let mut e = LogEntry { seq, ..entry.clone() };
                e.seq = seq;
                if self.bucket.put_new(&log_key(seq), &e.encode())? {
                    break seq;
                }
                seq += 1;
            };
            let manifest = Manifest { head_seq: seq, checkpoint_seq, head_branch };
            if let Some(tag) = self.bucket.put_if_tag("manifest", &manifest.encode(), prev_tag.as_deref())? {
                // committed: refresh local view cheaply and clear pendings
                self.pending_packs.borrow_mut().clear();
                let _ = tag; // next refresh() re-reads; keeping it simple
                self.refresh()?;
                return Ok(());
            }
            // lost the CAS: our log entry is now off-chain garbage; loop
            // re-reads and either detects a moved tip (NonFastForward above)
            // or retries with a fresh entry under the new parent.
        }
        Err(Error::Remote("manifest cas contention: gave up after 16 attempts".into()))
    }
```
(`LogEntry` needs `Clone` — add `#[derive(Clone)]` to it and `RefUpdate` in `walfmt.rs`.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo bucket_transport`
Expected: PASS (all 6).

- [ ] **Step 5: Commit**

```bash
git add crates/repo
git commit -m "feat(repo): BucketTransport write half — staged packs + CAS'd manifest commit (P36a)"
```

---

### Task 6: URL schemes, `remote add` validation, end-to-end sync tests

**Files:**
- Modify: `crates/repo/src/bucket_transport.rs` (add `BucketUrl` + `BucketTransport::open`)
- Modify: `crates/repo/src/stdio_transport.rs:281-293` (`open_transport` dispatch)
- Modify: `crates/repo/src/lib.rs` (re-export `BucketTransport`, `BucketUrl`)
- Modify: `crates/cli/src/main.rs:3646-3652` (`run_remote` add-time validation)
- Test: extend `bucket_transport.rs` tests

**Interfaces:**
- Consumes: Tasks 1–5; `Repo::{clone_url, fetch, push, remote_add}` (unchanged).
- Produces: `pub struct BucketUrl { pub scheme: BucketScheme, pub bucket: String, pub prefix: String }`, `pub enum BucketScheme { Wal, S3 }`, `BucketUrl::parse(url: &str) -> Result<BucketUrl>`, `BucketTransport::open(url: &str) -> Result<BucketTransport>`. URL grammar: `sc+wal:///abs/path` or `sc+wal://rel/path` (everything after the scheme is the directory path), `sc+s3://<bucket>/<prefix…>` (first component bucket name, rest prefix; empty prefix allowed).

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn clone_push_fetch_round_trip_over_sc_wal_url() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-e2e-bucket-{pid}"));
        let a_root = std::env::temp_dir().join(format!("scl-bt-e2e-a-{pid}"));
        let b_root = std::env::temp_dir().join(format!("scl-bt-e2e-b-{pid}"));
        for d in [&broot, &a_root, &b_root] {
            let _ = std::fs::remove_dir_all(d);
        }
        std::fs::create_dir_all(&a_root).unwrap();
        let url = format!("sc+wal://{}", broot.display());

        // A: init, commit, add bucket remote, push (creates the bucket repo)
        let a = crate::repo::Repo::init(&a_root).unwrap();
        std::fs::write(a_root.join("f.txt"), b"one").unwrap();
        let tip1 = a.commit("t", "c1").unwrap();
        a.remote_add("origin", &url).unwrap();
        assert_eq!(a.push("origin").unwrap(), tip1);

        // B: clone from the bucket
        let b = crate::repo::Repo::clone_url(&url, &b_root).unwrap();
        assert_eq!(b.head_tip().unwrap(), Some(tip1));
        assert_eq!(std::fs::read(b_root.join("f.txt")).unwrap(), b"one");

        // B commits and pushes; A fetches and sees it
        std::fs::write(b_root.join("g.txt"), b"two").unwrap();
        let tip2 = b.commit("t", "c2").unwrap();
        b.push("origin").unwrap();
        drop(b);
        let fetched = a.fetch("origin").unwrap();
        assert!(fetched.iter().any(|(br, id)| br == "main" && *id == tip2));

        // stale push from A (still at tip1 + its own commit) => NonFastForward
        std::fs::write(a_root.join("h.txt"), b"three").unwrap();
        a.commit("t", "c3").unwrap();
        assert!(matches!(a.push("origin"), Err(Error::NonFastForward)));
        drop(a);
        for d in [&broot, &a_root, &b_root] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn bucket_url_parses_and_rejects() {
        let u = BucketUrl::parse("sc+s3://mybucket/team/repo").unwrap();
        assert!(matches!(u.scheme, BucketScheme::S3));
        assert_eq!(u.bucket, "mybucket");
        assert_eq!(u.prefix, "team/repo");
        let u = BucketUrl::parse("sc+s3://mybucket").unwrap();
        assert_eq!(u.prefix, "");
        let u = BucketUrl::parse("sc+wal:///tmp/x").unwrap();
        assert!(matches!(u.scheme, BucketScheme::Wal));
        assert!(BucketUrl::parse("sc+s3://").is_err());
        assert!(BucketUrl::parse("sc+s3://b\nad/x").is_err());
        assert!(BucketUrl::parse("http://nope").is_err());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo bucket_transport`
Expected: compile FAIL — `BucketUrl` not found.

- [ ] **Step 3: Implement URL parsing + dispatch**

In `bucket_transport.rs`:
```rust
pub enum BucketScheme {
    Wal,
    S3,
}

/// `sc+wal://<dir>` (local test/demo backend) or `sc+s3://<bucket>/<prefix>`.
pub struct BucketUrl {
    pub scheme: BucketScheme,
    pub bucket: String,
    pub prefix: String,
}

impl BucketUrl {
    pub fn parse(url: &str) -> Result<BucketUrl> {
        let (scheme, rest) = if let Some(r) = url.strip_prefix("sc+wal://") {
            (BucketScheme::Wal, r)
        } else if let Some(r) = url.strip_prefix("sc+s3://") {
            (BucketScheme::S3, r)
        } else {
            return Err(Error::InvalidArgument(format!("not an sc+wal:// or sc+s3:// url: {url}")));
        };
        if rest.is_empty() || rest.chars().any(|c| c == '\r' || c == '\n') {
            return Err(Error::InvalidArgument(format!("bad bucket url: {url}")));
        }
        Ok(match scheme {
            BucketScheme::Wal => BucketUrl { scheme, bucket: rest.to_string(), prefix: String::new() },
            BucketScheme::S3 => {
                let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
                if bucket.is_empty() {
                    return Err(Error::InvalidArgument(format!("bad bucket url: {url}")));
                }
                BucketUrl { scheme, bucket: bucket.to_string(), prefix: prefix.trim_matches('/').to_string() }
            }
        })
    }
}

impl BucketTransport {
    /// Open the right bucket backend for a bucket URL.
    pub fn open(url: &str) -> Result<BucketTransport> {
        let parsed = BucketUrl::parse(url)?;
        let bucket: Box<dyn Bucket> = match parsed.scheme {
            BucketScheme::Wal => Box::new(scl_objio::DirBucket::open(&parsed.bucket)?),
            BucketScheme::S3 => Box::new(scl_objio::S3Bucket::open(&parsed.bucket, &parsed.prefix)?),
        };
        BucketTransport::from_bucket(bucket)
    }
}
```
`open_transport` (`crates/repo/src/stdio_transport.rs`) gets one new arm **before** the local-path catch-all:
```rust
    } else if url.starts_with("sc+wal://") || url.starts_with("sc+s3://") {
        Ok(Box::new(crate::bucket_transport::BucketTransport::open(url)?))
```
`crates/repo/src/lib.rs` re-exports: `pub use bucket_transport::{BucketTransport, BucketUrl};` next to the existing transport re-exports. `crates/cli/src/main.rs` `run_remote` add-arm grows fail-fast validation exactly parallel to the `ssh://` line at `main.rs:3648-3650`:
```rust
                if url.starts_with("ssh://") {
                    scl_repo::SshUrl::parse(&url)?; // fail fast on malformed URLs
                }
                if url.starts_with("sc+wal://") || url.starts_with("sc+s3://") {
                    scl_repo::BucketUrl::parse(&url)?; // fail fast on malformed URLs
                }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo bucket_transport && cargo test -p scl-repo sync`
Expected: PASS, including the untouched sync suite (proves the dispatch change breaks nothing).

- [ ] **Step 5: Commit**

```bash
git add crates/repo crates/cli
git commit -m "feat: sc+wal:// and sc+s3:// bucket remotes wired into open_transport (P36a)"
```

---

### Task 7: Concurrency + crash-safety proof tests

**Files:**
- Test: extend `#[cfg(test)] mod tests` in `crates/repo/src/bucket_transport.rs`

**Interfaces:**
- Consumes: everything above; `std::thread`.
- Produces: the P36a acceptance evidence named in the spec (two-writer race, fleet hammer, crash debris).

- [ ] **Step 1: Write the three tests (they should pass immediately if Tasks 4–6 are correct — treat any failure as a real bug, not a test to weaken)**

```rust
    #[test]
    fn racing_pushes_same_branch_one_wins_one_gets_non_fast_forward() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-race-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        // seed: one commit on main
        let t0 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (base, objects) = tiny_history();
        let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
        t0.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        t0.update_ref("main", &base, None).unwrap();
        drop(t0);

        // two threads race an update from the same expected_old to different tips
        let mk_tip = |tag: &[u8]| {
            let obj = Object::blob(tag.to_vec()); // any distinct object works as a fake tip
            (obj.id(), obj.encode())
        };
        let results: Vec<crate::error::Result<()>> = std::thread::scope(|s| {
            let handles: Vec<_> = [b"racer-a".as_slice(), b"racer-b".as_slice()]
                .into_iter()
                .map(|tag| {
                    let broot = broot.clone();
                    s.spawn(move || {
                        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
                        let (tip, bytes) = mk_tip(tag);
                        t.put_object(&tip, &bytes).unwrap();
                        t.update_ref("main", &tip, Some(&base))
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let wins = results.iter().filter(|r| r.is_ok()).count();
        let nffs = results.iter().filter(|r| matches!(r, Err(Error::NonFastForward))).count();
        assert_eq!((wins, nffs), (1, 1), "exactly one winner and one clean refusal: {results:?}");
        std::fs::remove_dir_all(&broot).unwrap();
    }

    #[test]
    fn fleet_hammer_distinct_branches_all_land_without_coordinator() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-fleet-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        const N: usize = 8;
        std::thread::scope(|s| {
            for i in 0..N {
                let broot = broot.clone();
                s.spawn(move || {
                    let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
                    let obj = Object::blob(format!("agent-{i}").into_bytes());
                    t.put_object(&obj.id(), &obj.encode()).unwrap();
                    // distinct branches: contention is manifest-level only, so
                    // every one must eventually land via CAS retry.
                    t.update_ref(&format!("work-{i}"), &obj.id(), None).unwrap();
                });
            }
        });
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let refs = t.list_refs().unwrap();
        assert_eq!(refs.len(), N, "all {N} agent branches present: {refs:?}");
        drop(t);
        std::fs::remove_dir_all(&broot).unwrap();
    }

    #[test]
    fn crash_debris_before_the_cas_is_invisible_and_later_pushes_step_over_it() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-crash-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        let bucket = DirBucket::open(&broot).unwrap();
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let (tip, objects) = tiny_history();
        let (pack, _) = scl_core::pack::build_pack(&objects).unwrap();
        t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
        t.update_ref("main", &tip, None).unwrap();

        // simulate a pusher that died after pack + log entry, before the CAS:
        let orphan_obj = Object::blob(b"never committed".to_vec());
        let (opack, oidx) = scl_core::pack::build_pack(&[(orphan_obj.id(), orphan_obj.encode())]).unwrap();
        let ohash = hex::encode(blake3::hash(&opack).as_bytes());
        bucket.put_new(&pack_key(&ohash), &opack).unwrap();
        bucket.put_new(&idx_key(&ohash), &oidx).unwrap();
        bucket.put_new(&log_key(2), &LogEntry {
            seq: 2, parent_seq: 1, packs: vec![ohash],
            updates: vec![RefUpdate { branch: "doomed".into(), old: None, new: orphan_obj.id() }],
        }.encode()).unwrap();

        // invisible to readers…
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t2.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert!(!t2.has_object(&orphan_obj.id()).unwrap());
        // …and a live push steps over the claimed seq 2 (lands at 3+) and works.
        let next = Object::blob(b"after crash".to_vec());
        t2.put_object(&next.id(), &next.encode()).unwrap();
        t2.update_ref("recovered", &next.id(), None).unwrap();
        let t3 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let refs = t3.list_refs().unwrap();
        assert!(refs.contains(&("recovered".to_string(), next.id())));
        assert!(!refs.iter().any(|(b, _)| b == "doomed"));
        drop((t, t2, t3));
        std::fs::remove_dir_all(&broot).unwrap();
    }
```
Adaptation note: `Object::blob(...)`/`obj.id()` — use whatever constructor core's own tests use to mint a standalone blob object (grep `Object::` in `crates/core/src/store.rs` tests); the intent is "any distinct valid object".

- [ ] **Step 2: Run**

Run: `cargo test -p scl-repo bucket_transport -- --nocapture`
Expected: PASS (all 3 new + all prior). If the race test deadlocks or double-commits, the bug is in `update_ref`'s retry loop — fix the code, never the assertion.

- [ ] **Step 3: Full workspace check**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: PASS / no new warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/repo
git commit -m "test(repo): bucket WAL race, fleet-hammer, and crash-debris proofs (P36a)"
```

---

### Task 8: CLI integration test + docs (CLAUDE.md, ADR-0046, ROADMAP, THREAT-MODEL)

**Files:**
- Create: `crates/cli/tests/bucket_remote.rs`
- Create: `docs/adr/0046-wal-bucket-remotes.md`
- Modify: `CLAUDE.md` (dependency rule + quarantine + capability map)
- Modify: `ROADMAP.md` (Deferred entries)
- Modify: `docs/THREAT-MODEL.md` (bucket trust boundary)

**Interfaces:**
- Consumes: the shipped `sc` binary behavior from Tasks 1–7.
- Produces: the user-facing and agent-facing record; nothing downstream.

- [ ] **Step 1: Write the CLI integration test**

`crates/cli/tests/bucket_remote.rs`, following the harness in `crates/cli/tests/ssh_remote.rs:7-25` (module doc states the division of labor: wire correctness is proven in-crate; this file proves flag/URL plumbing end-to-end through the binary):

```rust
//! `sc+wal://` bucket remotes through the real binary. Wire/WAL correctness
//! is proven in scl-repo's bucket_transport tests; this exercises CLI
//! plumbing: remote add validation, push, clone, fetch.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sc(dir: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sc"));
    cmd.args(args).current_dir(dir);
    cmd.output().expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-bucket-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn bucket_clone_push_fetch_round_trip_and_url_validation() {
    let a = tmp("a");
    let bucket = tmp("bucket");
    let url = format!("sc+wal://{}", bucket.display());

    let out = sc(&a, &["init"]);
    assert!(out.status.success(), "{out:?}");
    std::fs::write(a.join("f.txt"), b"via cli").unwrap();
    assert!(sc(&a, &["commit", "-m", "c1"]).status.success());
    // malformed bucket URL is refused at add time
    let bad = sc(&a, &["remote", "add", "borig", "sc+s3://"]);
    assert!(!bad.status.success());
    assert!(sc(&a, &["remote", "add", "origin", &url]).status.success());
    assert!(sc(&a, &["push", "origin"]).status.success());

    let parent = tmp("bparent");
    let b = parent.join("b");
    let out = sc(&parent, &["clone", &url, b.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read(b.join("f.txt")).unwrap(), b"via cli");

    std::fs::write(b.join("g.txt"), b"round trip").unwrap();
    assert!(sc(&b, &["commit", "-m", "c2"]).status.success());
    assert!(sc(&b, &["push", "origin"]).status.success());
    let out = sc(&a, &["fetch", "origin"]);
    assert!(out.status.success(), "{out:?}");

    for d in [&a, &bucket, &parent] {
        std::fs::remove_dir_all(d).unwrap();
        assert!(!d.exists());
    }
}
```
(Adapt `commit -m`/`clone`/`fetch` argv to the real clap surface — check `sc --help` output or `crates/cli/tests/ssh_remote.rs`'s calls and mirror them exactly.)

- [ ] **Step 2: Run**

Run: `cargo test -p scl-cli --test bucket_remote`
Expected: PASS.

- [ ] **Step 3: Write ADR-0046 and update the standing docs**

- `docs/adr/0046-wal-bucket-remotes.md` — follow the house ADR shape (Status/Date/Phase/Context/Decision/Consequences/Alternatives, see ADR-0013). Decision: bucket = WAL of immutable packs + parent-linked log + one CAS'd manifest; `objio` leaf crate; both schemes; filter refused; alternatives: dumb ref-file-per-branch bucket (rejected: no atomic multi-ref, no log for fleets), Store-level backend (deferred: reopens P3/P8), walgit itself (git-protocol server — covered by P18, see `docs/research/walgit-evaluation.md`).
- `CLAUDE.md`:
  - Dependency rule sentence: adapters `{cli, desktop} → repo → {vfs, gitio, crypto} → core`, leaf edges `repo → tlsio` **and `repo → objio`** (`objio` depends on no workspace crate). Add the quarantine sentence: "**Object-store SDKs must stay quarantined in `objio`** — if you find yourself reaching for S3 elsewhere, add a function to `objio` instead."
  - Capability map: change "All 35 phases are built and tested" to 36 with row: `| P36 | P36a built: bucket WAL remotes (sc+wal://, sc+s3://) — immutable packs + CAS'd manifest, multi-writer safe, no coordinator; checkpoints (P36b) and bucket-backed serve (P36c) pending | [0046](docs/adr/0046-wal-bucket-remotes.md) |`
  - Standing boundaries: add "**Bucket remotes hold public content plaintext at rest** — bucket ACL is the perimeter (sealed content stays ciphertext, unchanged); partial-clone `filter` against bucket remotes is refused."
- `ROADMAP.md` → Deferred: bucket compaction/gc; leases; checkpoint fold (P36b, next); bucket-backed `sc serve` (P36c, next); partial clone from bucket remotes; static-bundle clone offload; native GCS backend; `S3Bucket` streaming (bodies currently buffered in RAM, `MAX_OBJECT_SIZE`-bounded per object but pack-sized per transfer).
- `docs/THREAT-MODEL.md`: new trust boundary — the bucket is untrusted storage with cooperative writers: write access = full authority over refs and history (fast-forward is cooperative); readers verify BLAKE3 per object, strict-decode the WAL fail-closed, cap lengths; sealed content remains E2E-sealed; public content confidentiality = bucket ACL.

- [ ] **Step 4: Full verification**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets && cargo run --bin sc -- demo --agents 4`
Expected: all green; demo still proves zero residue.

- [ ] **Step 5: Commit**

```bash
git add crates/cli CLAUDE.md ROADMAP.md docs
git commit -m "feat(cli)+docs: bucket remote integration test, ADR-0046, CLAUDE.md/ROADMAP/THREAT-MODEL for P36a"
```
