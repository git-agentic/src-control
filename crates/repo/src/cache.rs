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
//! Where the key file cannot be made owner-only (neither unix nor Windows, or
//! the Windows ACL call failed; #214) it is still written with default
//! permissions and a one-time warning is printed once the cache holds a
//! protected entry: see [`can_restrict_permissions`].
//!
//! **The keyed tag is the sole authority for a hit.** `mtime_ns`/`size` are
//! recorded for documentation (when the entry was observed) and as a
//! possible future input to a paths-only walk that doesn't already hold the
//! plaintext in RAM, but they are NEVER sufficient on their own: a bare
//! stat match is the classic git "racy stat" problem (an edit that lands
//! within the filesystem's mtime granularity and happens to keep the same
//! size is indistinguishable from no edit at all by stat alone), and every
//! `unchanged()` caller already has the plaintext in memory (`read_worktree`
//! loads all bytes before commit/diff), so there is no reason to trust a
//! cheaper, unsound signal — keyed blake3 over in-memory bytes runs at
//! GB/s.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// Whether `.sc/local-key` can be created readable by its owner only: unix
/// (`mode(0o600)`) and Windows (owner-only DACL, `winacl`), both from the first
/// byte. Elsewhere, or after a Windows ACL failure, the key keeps default
/// permissions and a warning is printed. Tests force `false` via
/// `force_unrestricted_for_test`.
fn can_restrict_permissions() -> bool {
    #[cfg(test)]
    if FORCE_UNRESTRICTED.with(|f| f.get()) {
        return false;
    }
    platform_can_restrict()
}

#[cfg(windows)]
fn platform_can_restrict() -> bool {
    !ACL_FAILED.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(not(windows))]
fn platform_can_restrict() -> bool {
    cfg!(unix)
}

/// Set once a Windows owner-only create failed and the key fell back to default
/// permissions, so the unrestricted warning fires.
#[cfg(windows)]
static ACL_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    static FORCE_UNRESTRICTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test seam: make this thread behave like a non-unix target.
#[cfg(test)]
pub(crate) fn force_unrestricted_for_test(on: bool) {
    FORCE_UNRESTRICTED.with(|f| f.set(on));
}

/// Print the unrestricted-key warning the first time `flag` is unset; `true`
/// iff it printed. The flag is a parameter so a test can use a private one.
fn warn_unrestricted_once(flag: &std::sync::atomic::AtomicBool) -> bool {
    if flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    eprintln!(
        "warning: this platform could not restrict .sc/local-key to its owner; other \
         local users may be able to read it and test guesses against the \
         protected-file cache tags (the protected plaintext checked out in the \
         working tree is equally readable by default)"
    );
    true
}

/// Warn (once per process) when a cache that holds protected entries is
/// backed by a key whose permissions could not be restricted.
fn warn_if_unrestricted(has_entries: bool) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if has_entries && !can_restrict_permissions() {
        warn_unrestricted_once(&WARNED);
    }
}

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

fn write_key_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    create_key_file(path)?.write_all(bytes)
}

#[cfg(unix)]
fn create_key_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Windows: owner-only DACL from the first byte; if that cannot be applied,
/// fall back to default (inherited) permissions plus the warning, never fail.
#[cfg(windows)]
fn create_key_file(path: &Path) -> std::io::Result<std::fs::File> {
    match crate::winacl::create_new_owner_only(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            let f = create_key_file_default(path)?;
            ACL_FAILED.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(f)
        }
        r => r,
    }
}

/// Default (inherited) permissions; see [`can_restrict_permissions`].
#[cfg(not(unix))]
fn create_key_file_default(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
use create_key_file_default as create_key_file;

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
/// serves, against which relative tree paths are resolved to record the
/// advisory mtime+size fields alongside each entry. This is the P33 Task 7
/// design choice (over threading an explicit worktree-root through
/// `snapshot_files`): the cache is inherently tied to one checkout, so it
/// should carry that checkout's root rather than have every
/// `unchanged`/`record` caller pass an absolute path. **Invariant:** the
/// `root` passed at `open` must equal `layout.root` of the checkout that
/// `materialize`/`diff_worktree`/`snapshot_files` operate on — the main tree
/// opens with `layout.root`, a `sc ws`/`sc work` workspace with its own
/// checkout dir. The keyed-tag comparison that decides every `unchanged()`
/// hit does not depend on `root` at all (it hashes the caller's in-memory
/// plaintext), so a mismatched root only ever loses the advisory stat
/// bookkeeping — never incorrectness. `save` resolves entries against `root`
/// too, so a mismatched root would also prune every entry at the next save (a
/// full re-seal, still never incorrect).
pub(crate) struct ProtectedCache {
    key: [u8; 32],
    /// Absolute base dir of the served checkout; `root.join(rel)` is the file
    /// a relative tree path stats to.
    root: PathBuf,
    /// `None` => ephemeral: `save()` is a no-op.
    path: Option<PathBuf>,
    entries: BTreeMap<String, CacheEntry>,
}

/// Whether `rel` under `root` is a regular file reached without crossing a
/// symlink, the only kind the worktree walker reads. Every component is checked
/// with `symlink_metadata`, so a file replaced by a symlink, or a directory
/// replaced by one, counts as gone.
fn is_plain_file(root: &Path, rel: &str) -> bool {
    let mut cur = root.to_path_buf();
    let mut comps = rel.split('/').peekable();
    while let Some(c) = comps.next() {
        cur.push(c);
        let Ok(md) = std::fs::symlink_metadata(&cur) else {
            return false;
        };
        let ft = md.file_type();
        let ok = if comps.peek().is_some() {
            ft.is_dir()
        } else {
            ft.is_file()
        };
        if !ok {
            return false;
        }
    }
    true
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
                        Some((
                            it.next()?.to_string(),
                            CacheEntry {
                                mtime_ns,
                                size,
                                tag,
                                blob_id,
                            },
                        ))
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
        if path.is_some() {
            warn_if_unrestricted(!entries.is_empty());
        }
        ProtectedCache {
            key,
            root,
            path,
            entries,
        }
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
    /// sealed at `rel`, decided ENTIRELY by the keyed-tag comparison — never
    /// by a bare mtime+size stat match. A stat-only hit is the classic git
    /// "racy stat" problem: an edit that keeps the same file size and lands
    /// within the filesystem's mtime granularity is indistinguishable from
    /// no edit at all by stat alone, and misreading it as unchanged would
    /// silently carry the OLD ciphertext into the commit, dropping the
    /// user's edit — exactly the incorrectness this cache must never cause.
    /// Every caller already holds `plaintext` in memory before this is
    /// called, so the keyed tag is cheap enough to be the sole authority.
    pub(crate) fn unchanged(&self, rel: &str, plaintext: &[u8]) -> Option<ObjectId> {
        let e = self.entries.get(rel)?;
        (self.tag(plaintext) == e.tag).then_some(e.blob_id)
    }

    /// Record that `plaintext` at `rel` seals to `blob_id`. The absolute file
    /// is resolved against the cache's own `root`. Missing stat (file vanished
    /// mid-operation) just skips the entry.
    pub(crate) fn record(&mut self, rel: &str, plaintext: &[u8], blob_id: ObjectId) {
        if let Some((mtime_ns, size)) = Self::stat(&self.root.join(rel)) {
            let tag = self.tag(plaintext);
            self.entries.insert(
                rel.to_string(),
                CacheEntry {
                    mtime_ns,
                    size,
                    tag,
                    blob_id,
                },
            );
        }
    }

    /// Durable atomic write via the shared `fsutil` helper (fsync temp +
    /// rename + fsync parent dir, no residue on failure); no-op for an
    /// ephemeral cache.
    ///
    /// Entries whose file is gone from the checkout (deleted, renamed, or
    /// outside the sparse view) are left out, so the file stays bounded by the
    /// protected files actually on disk instead of growing for the life of the
    /// repo. A lookup always compares the keyed tag of plaintext read from the
    /// file, so an entry for an absent file can never be consulted; dropping it
    /// at worst costs one re-seal if the path returns. Sealing is randomized,
    /// so that re-seal yields a new blob id for unchanged content.
    pub(crate) fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        warn_if_unrestricted(!self.entries.is_empty());
        let mut out = String::new();
        for (p, e) in &self.entries {
            if !is_plain_file(&self.root, p) {
                continue;
            }
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

    /// Windows: the production create path leaves a DACL with exactly one ACE,
    /// the current user's, and nothing inherited (read back with `icacls`).
    #[cfg(windows)]
    #[test]
    fn local_key_dacl_is_owner_only_on_windows() {
        let layout = tmp("acl");
        let key = local_key(&layout).unwrap();
        assert_eq!(key, local_key(&layout).unwrap(), "owner can still read it");
        assert!(
            can_restrict_permissions(),
            "ACL path must not have fallen back"
        );

        let path = layout.local_key_path();
        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls failed: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let acl = text.replace(path.to_str().unwrap(), "");
        let aces: Vec<&str> = acl.lines().filter(|l| l.contains(":(")).collect();
        let user = std::env::var("USERNAME").unwrap().to_lowercase();
        assert_eq!(aces.len(), 1, "exactly one ACE expected:\n{text}");
        let ace = aces[0].trim().to_lowercase();
        assert!(
            ace.contains(&format!("\\{user}:(")) && ace.contains("(f)") && !ace.contains("(i)"),
            "ACE must be an explicit full-control grant to {user}:\n{text}"
        );
        cleanup(&layout);
    }

    #[test]
    fn unrestricted_key_still_persists_and_hits() {
        force_unrestricted_for_test(true);
        let layout = tmp("unrestricted");
        let key = local_key(&layout).unwrap();
        assert_eq!(key, local_key(&layout).unwrap(), "key persisted");
        assert!(layout.local_key_path().exists());

        let abs = layout.root.join("secret.txt");
        std::fs::write(&abs, b"v1").unwrap();
        let id = ObjectId::of(b"cipher-of-v1");
        let mut c = ProtectedCache::open(
            key,
            layout.root.clone(),
            Some(layout.protected_cache_path()),
        );
        c.record("secret.txt", b"v1", id);
        c.save().unwrap();
        assert!(layout.protected_cache_path().exists(), "cache persisted");
        let c = ProtectedCache::open(
            key,
            layout.root.clone(),
            Some(layout.protected_cache_path()),
        );
        assert_eq!(c.unchanged("secret.txt", b"v1"), Some(id), "hit survives");
        force_unrestricted_for_test(false);
        cleanup(&layout);
    }

    #[test]
    fn unrestricted_warning_prints_once() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        assert!(warn_unrestricted_once(&flag));
        assert!(!warn_unrestricted_once(&flag));
    }

    #[test]
    fn tag_is_authoritative_for_hits_and_misses() {
        let layout = tmp("hits");
        let key = local_key(&layout).unwrap();
        let abs = layout.root.join("secret.txt");
        std::fs::write(&abs, b"v1").unwrap();
        let id = ObjectId::of(b"cipher-of-v1");

        let mut c = ProtectedCache::open(
            key,
            layout.root.clone(),
            Some(layout.protected_cache_path()),
        );
        assert_eq!(c.unchanged("secret.txt", b"v1"), None, "empty cache misses");
        c.record("secret.txt", b"v1", id);

        // Untouched file, same plaintext: hit.
        assert_eq!(c.unchanged("secret.txt", b"v1"), Some(id));

        // Touch mtime without changing content: still a hit (tag matches).
        std::fs::write(&abs, b"v1").unwrap();
        assert_eq!(c.unchanged("secret.txt", b"v1"), Some(id));

        // Real change: miss.
        std::fs::write(&abs, b"v2").unwrap();
        assert_eq!(c.unchanged("secret.txt", b"v2"), None);
        cleanup(&layout);
    }

    /// Regression for the racy-stat data-loss finding: same-length content
    /// written back with the SAME recorded mtime (the classic git "racy
    /// stat" condition — an edit that lands within the filesystem's mtime
    /// granularity) must still miss, because a stat-only hit would silently
    /// carry the old ciphertext and drop the user's edit from the commit.
    #[test]
    fn racy_stat_same_size_same_mtime_still_misses() {
        let layout = tmp("racy");
        let key = local_key(&layout).unwrap();
        let abs = layout.root.join("secret.txt");
        std::fs::write(&abs, b"aaaa").unwrap();
        let id = ObjectId::of(b"cipher-of-aaaa");
        let original_mtime = std::fs::metadata(&abs).unwrap().modified().unwrap();

        let mut c = ProtectedCache::open(
            key,
            layout.root.clone(),
            Some(layout.protected_cache_path()),
        );
        c.record("secret.txt", b"aaaa", id);

        // Overwrite with same-length content, then force the racy condition
        // by resetting mtime back to what was recorded.
        std::fs::write(&abs, b"bbbb").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&abs)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        assert_eq!(
            c.unchanged("secret.txt", b"bbbb"),
            None,
            "racy stat (same mtime, same size, different content) must not be misread as unchanged"
        );
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

        let mut c = ProtectedCache::open(
            key,
            layout.root.clone(),
            Some(layout.protected_cache_path()),
        );
        c.record("a b/spaced name.txt", b"v", id);
        c.save().unwrap();

        let c2 = ProtectedCache::open(
            key,
            layout.root.clone(),
            Some(layout.protected_cache_path()),
        );
        assert_eq!(c2.unchanged("a b/spaced name.txt", b"v"), Some(id));

        // Corrupt file: degrades to empty, never errors.
        std::fs::write(layout.protected_cache_path(), b"garbage\nlines\n").unwrap();
        let c3 = ProtectedCache::open(
            key,
            layout.root.clone(),
            Some(layout.protected_cache_path()),
        );
        assert_eq!(c3.unchanged("a b/spaced name.txt", b"v"), None);
        cleanup(&layout);
    }

    #[test]
    fn save_drops_entries_for_files_no_longer_on_disk() {
        let layout = tmp("prune");
        let key = local_key(&layout).unwrap();
        let open = || {
            ProtectedCache::open(
                key,
                layout.root.clone(),
                Some(layout.protected_cache_path()),
            )
        };
        for f in ["keep", "gone", "moved"] {
            std::fs::write(layout.root.join(f), b"v").unwrap();
        }
        let id = ObjectId::of(b"c");
        let mut c = open();
        for f in ["keep", "gone", "moved"] {
            c.record(f, b"v", id);
        }
        c.save().unwrap();
        assert_eq!(open().entries.len(), 3);

        std::fs::remove_file(layout.root.join("gone")).unwrap();
        std::fs::rename(layout.root.join("moved"), layout.root.join("moved-to")).unwrap();
        // A directory at a cached path is not a protected file either.
        std::fs::create_dir(layout.root.join("gone")).unwrap();
        let mut c = open();
        c.record("moved-to", b"v", id);
        c.save().unwrap();

        let after = open();
        assert_eq!(after.unchanged("keep", b"v"), Some(id));
        assert_eq!(after.unchanged("moved-to", b"v"), Some(id));
        assert_eq!(after.unchanged("gone", b"v"), None);
        assert_eq!(after.unchanged("moved", b"v"), None);
        assert_eq!(after.entries.len(), 2, "dead entries are pruned on save");
        cleanup(&layout);
    }

    #[cfg(unix)]
    #[test]
    fn save_drops_entries_behind_a_symlink() {
        let layout = tmp("prune-symlink");
        let key = local_key(&layout).unwrap();
        let open = || {
            ProtectedCache::open(
                key,
                layout.root.clone(),
                Some(layout.protected_cache_path()),
            )
        };
        std::fs::create_dir(layout.root.join("d")).unwrap();
        std::fs::write(layout.root.join("d/inner"), b"v").unwrap();
        std::fs::write(layout.root.join("file"), b"v").unwrap();
        std::fs::write(layout.root.join("target"), b"v").unwrap();
        let id = ObjectId::of(b"c");
        let mut c = open();
        c.record("d/inner", b"v", id);
        c.record("file", b"v", id);
        c.save().unwrap();
        assert_eq!(open().entries.len(), 2);

        // The file becomes a symlink to an existing file, and its parent
        // directory becomes a symlink to a directory that still holds `inner`.
        std::fs::remove_file(layout.root.join("file")).unwrap();
        std::os::unix::fs::symlink("target", layout.root.join("file")).unwrap();
        std::fs::rename(layout.root.join("d"), layout.root.join("real-d")).unwrap();
        std::os::unix::fs::symlink("real-d", layout.root.join("d")).unwrap();
        open().save().unwrap();
        assert_eq!(
            open().entries.len(),
            0,
            "the walker never reads through a symlink"
        );
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
