//! P33: local unchanged-detection cache for randomized protected paths.
//!
//! Randomized seals (ADR-0043) make re-encrypt-and-compare useless for
//! change detection, so commit/status/diff consult this `.sc`-local,
//! never-committed, never-transferred map instead:
//! `path -> (mtime_ns, size, keyed_tag, ciphertext blob id)`.
//! The tag is `blake3::keyed_hash(local_key, plaintext)` under a random
//! per-repo key (`.sc/local-key`, 0600), so the cache file alone leaks
//! nothing — it does not reintroduce the equality oracle this phase closes.
//! A lost/stale/corrupt cache degrades to spurious re-seals, never
//! incorrectness and never a hard error.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// Load (minting if absent) the per-repo random cache key. The key file is
/// the only hard-error surface here: if it can't be created/read, the cache
/// cannot be safely keyed, so surface it rather than running unkeyed.
///
/// Mirrors the serve-TLS key discipline (`crates/tlsio/src/identity.rs`):
/// the file is created 0600 from its first byte via `create_new`, so there
/// is never a window where the key sits at default permissions. A
/// concurrent minter losing the `create_new` race falls through to reading
/// the winner's file rather than erroring or clobbering it.
pub(crate) fn local_key(layout: &Layout) -> Result<[u8; 32]> {
    let path = layout.local_key_path();
    let hex_str = match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = scl_crypto::random_hex(32); // 32 random bytes -> 64 hex chars
            match write_key_0600(&path, s.as_bytes()) {
                Ok(()) => s,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Lost the create_new race to a concurrent minter: read
                    // their file instead of clobbering it.
                    std::fs::read_to_string(&path)?.trim().to_string()
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    };
    let bytes = hex::decode(&hex_str)
        .map_err(|_| Error::InvalidArgument("malformed .sc/local-key".into()))?;
    bytes
        .try_into()
        .map_err(|_| Error::InvalidArgument("malformed .sc/local-key".into()))
}

#[cfg(unix)]
fn write_key_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_key_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct CacheEntry {
    mtime_ns: u128,
    size: u64,
    tag: [u8; 32],
    blob_id: ObjectId,
}

/// Per-checkout unchanged-detection cache (main tree, one ws workspace, or
/// an ephemeral in-memory one for `sc work` temp checkouts).
///
/// The cache owns its `root`: the absolute base directory of the checkout it
/// serves, against which relative tree paths are resolved for the stat
/// (mtime+size) short-circuit. This is the P33 Task 7 design choice (over
/// threading an explicit worktree-root through `snapshot_files`): a stat cache
/// is inherently tied to one checkout, so it should carry that checkout's root
/// rather than have every `unchanged`/`record` caller pass an absolute path.
/// **Invariant:** the `root` passed at `open` must equal `layout.root` of the
/// checkout that `materialize`/`diff_worktree`/`snapshot_files` operate on —
/// the main tree opens with `layout.root`, a `sc ws`/`sc work` workspace with
/// its own checkout dir. A mismatched root only ever loses the stat
/// short-circuit (the keyed-tag comparison still proves unchanged-ness, and a
/// miss degrades to a spurious reseal) — never incorrectness.
pub(crate) struct ProtectedCache {
    key: [u8; 32],
    /// Absolute base dir of the served checkout; `root.join(rel)` is the file
    /// a relative tree path stats to.
    root: PathBuf,
    /// `None` => ephemeral: `save()` is a no-op.
    path: Option<PathBuf>,
    entries: BTreeMap<String, CacheEntry>,
}

impl ProtectedCache {
    pub(crate) fn open(key: [u8; 32], root: PathBuf, path: Option<PathBuf>) -> ProtectedCache {
        let mut entries = BTreeMap::new();
        if let Some(p) = &path {
            if let Ok(text) = std::fs::read_to_string(p) {
                for line in text.lines() {
                    // Format: `<mtime_ns> <size> <tag-hex> <blob-hex> <path>`
                    // (path last: it may contain spaces).
                    let mut it = line.splitn(5, ' ');
                    let parsed = (|| {
                        let mtime_ns: u128 = it.next()?.parse().ok()?;
                        let size: u64 = it.next()?.parse().ok()?;
                        let tag: [u8; 32] = hex::decode(it.next()?).ok()?.try_into().ok()?;
                        let blob_id = ObjectId::from_str(it.next()?).ok()?;
                        Some((it.next()?.to_string(), CacheEntry { mtime_ns, size, tag, blob_id }))
                    })();
                    match parsed {
                        Some((path, e)) => {
                            entries.insert(path, e);
                        }
                        None => {
                            eprintln!("warning: ignoring corrupt protected-cache line");
                            entries.clear();
                            break; // degrade to empty: spurious re-seals, never incorrectness
                        }
                    }
                }
            }
        }
        ProtectedCache { key, root, path, entries }
    }

    fn tag(&self, plaintext: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.key, plaintext).as_bytes()
    }

    fn stat(abs: &Path) -> Option<(u128, u64)> {
        let md = std::fs::metadata(abs).ok()?;
        let mtime = md.modified().ok()?;
        let ns = mtime.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos();
        Some((ns, md.len()))
    }

    /// The cached ciphertext blob id iff this exact plaintext is what last
    /// sealed at `rel`: stat hit (mtime+size unchanged) short-circuits;
    /// otherwise fall back to the keyed-tag comparison. The absolute file is
    /// resolved against the cache's own `root` (`root.join(rel)`).
    pub(crate) fn unchanged(&self, rel: &str, plaintext: &[u8]) -> Option<ObjectId> {
        let e = self.entries.get(rel)?;
        if let Some((mtime_ns, size)) = Self::stat(&self.root.join(rel)) {
            if mtime_ns == e.mtime_ns && size == e.size {
                return Some(e.blob_id);
            }
        }
        (self.tag(plaintext) == e.tag).then_some(e.blob_id)
    }

    /// Record that `plaintext` at `rel` seals to `blob_id`. The absolute file
    /// is resolved against the cache's own `root`. Missing stat (file vanished
    /// mid-operation) just skips the entry.
    pub(crate) fn record(&mut self, rel: &str, plaintext: &[u8], blob_id: ObjectId) {
        if let Some((mtime_ns, size)) = Self::stat(&self.root.join(rel)) {
            let tag = self.tag(plaintext);
            self.entries
                .insert(rel.to_string(), CacheEntry { mtime_ns, size, tag, blob_id });
        }
    }

    /// Durable atomic write via the shared `fsutil` helper (fsync temp +
    /// rename + fsync parent dir, no residue on failure); no-op for an
    /// ephemeral cache.
    pub(crate) fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let mut out = String::new();
        for (p, e) in &self.entries {
            out.push_str(&format!(
                "{} {} {} {} {}\n",
                e.mtime_ns,
                e.size,
                hex::encode(e.tag),
                e.blob_id.to_hex(),
                p
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        scl_core::fsutil::atomic_write_durable(path, out.as_bytes())?;
        Ok(())
    }

    /// Persist best-effort: on failure, log to stderr and swallow rather than
    /// propagate. Every ref-moving op that populates the cache saves through
    /// this AFTER its ref has moved (P33 Task 7), so cache trouble can never
    /// abort an operation that has already logically succeeded — a lost/stale
    /// cache only ever degrades to a spurious reseal next time, never to
    /// incorrectness.
    pub(crate) fn save_best_effort(&self) {
        if let Err(e) = self.save() {
            eprintln!("warning: failed to persist protected-cache: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-cache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".sc")).unwrap();
        Layout::at(&root)
    }

    fn cleanup(layout: &Layout) {
        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    #[test]
    fn local_key_is_minted_once_and_stable() {
        let layout = tmp("key");
        let k1 = local_key(&layout).unwrap();
        let k2 = local_key(&layout).unwrap();
        assert_eq!(k1, k2, "second read must return the same key");
        assert_ne!(k1, [0u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(layout.local_key_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be 0600");
        }
        cleanup(&layout);
    }

    #[test]
    fn stat_hit_tag_fallback_and_miss() {
        let layout = tmp("hits");
        let key = local_key(&layout).unwrap();
        let abs = layout.root.join("secret.txt");
        std::fs::write(&abs, b"v1").unwrap();
        let id = ObjectId::of(b"cipher-of-v1");

        let mut c =
            ProtectedCache::open(key, layout.root.clone(), Some(layout.protected_cache_path()));
        assert_eq!(c.unchanged("secret.txt", b"v1"), None, "empty cache misses");
        c.record("secret.txt", b"v1", id);

        // Stat hit: file untouched.
        assert_eq!(c.unchanged("secret.txt", b"v1"), Some(id));

        // Tag fallback: touch mtime without changing content.
        std::fs::write(&abs, b"v1").unwrap();
        assert_eq!(c.unchanged("secret.txt", b"v1"), Some(id));

        // Real change: miss.
        std::fs::write(&abs, b"v2").unwrap();
        assert_eq!(c.unchanged("secret.txt", b"v2"), None);
        cleanup(&layout);
    }

    #[test]
    fn save_load_roundtrip_and_corrupt_file_is_empty() {
        let layout = tmp("persist");
        let key = local_key(&layout).unwrap();
        let abs = layout.root.join("a b/spaced name.txt"); // path with spaces
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, b"v").unwrap();
        let id = ObjectId::of(b"c");

        let mut c =
            ProtectedCache::open(key, layout.root.clone(), Some(layout.protected_cache_path()));
        c.record("a b/spaced name.txt", b"v", id);
        c.save().unwrap();

        let c2 =
            ProtectedCache::open(key, layout.root.clone(), Some(layout.protected_cache_path()));
        assert_eq!(c2.unchanged("a b/spaced name.txt", b"v"), Some(id));

        // Corrupt file: degrades to empty, never errors.
        std::fs::write(layout.protected_cache_path(), b"garbage\nlines\n").unwrap();
        let c3 =
            ProtectedCache::open(key, layout.root.clone(), Some(layout.protected_cache_path()));
        assert_eq!(c3.unchanged("a b/spaced name.txt", b"v"), None);
        cleanup(&layout);
    }

    #[test]
    fn ephemeral_cache_never_touches_disk() {
        let layout = tmp("ephemeral");
        let key = local_key(&layout).unwrap();
        let abs = layout.root.join("f");
        std::fs::write(&abs, b"v").unwrap();
        let mut c = ProtectedCache::open(key, layout.root.clone(), None);
        c.record("f", b"v", ObjectId::of(b"c"));
        c.save().unwrap();
        assert!(!layout.protected_cache_path().exists());
        cleanup(&layout);
    }
}
