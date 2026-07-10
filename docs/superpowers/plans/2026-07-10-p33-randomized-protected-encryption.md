# P33: Randomized Protected-Path Encryption — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the convergent-equality oracle (ADR-0014) — all new protected content seals under a fresh random DEK + nonce, old convergent ciphertext stays readable forever, and a per-checkout stat cache keeps unchanged content from re-sealing.

**Architecture:** A `RANDOMIZED` perms bit tags the new format at the tree-entry level; the blob layout (`nonce(24) ‖ ct`) and `decrypt_path` are unchanged, so dual-read needs zero read-path code. The single production seal choke point (`protect::encrypt_protected`) flips to random seals, and a format-dispatched carry decision in `snapshot_files`/`diff_worktree` keeps unchanged content quiet: convergent priors use the existing re-encrypt-and-compare trick, randomized priors use a `.sc`-local stat cache + BLAKE3 keyed-tag fallback. `sc rewrap` eagerly upgrades convergent blobs at the tip.

**Tech Stack:** Rust (stable, edition 2021). No new dependencies — `blake3` and `hex` are already workspace deps of `scl-repo`; randomness reaches `crates/repo` via `scl_crypto` re-exports (RustCrypto quarantine holds).

**Spec:** `docs/superpowers/specs/2026-07-10-p33-randomized-protected-encryption-design.md` (read it first). Issue #40; decisions locked on #30.

## Global Constraints

- **RustCrypto quarantine:** all crypto code stays in `crates/crypto`. `crates/repo` may use `blake3` (already a dep, cf. `serve_tokens.rs`) and `scl_crypto::*` re-exports only.
- **No format break:** no snapshot-tag bump. A pre-P33 store must decode and behave byte-for-byte as today (zero `RANDOMIZED` bits ⇒ all-convergent behavior).
- **Commit needs only public keys.** Decrypt-and-compare is forbidden in commit/status/diff.
- **Degradation rule:** lost/stale/corrupt cache ⇒ spurious re-seals, never incorrectness, never a hard error.
- **Green at every task boundary:** `cargo test` passes after each task. Task order is load-bearing — the dispatch machinery (Tasks 4–5) must land before the seal flip (Task 6), or every commit would mass-re-seal.
- **Tests:** colocated `#[cfg(test)] mod tests`; disk-touching tests clean up and assert the path is gone. Reuse each file's existing test helpers (e.g. `worktree.rs`'s `tmp_objects`, `repo.rs`'s repo-builder helpers) instead of inventing parallel ones.
- **Errors:** per-crate `thiserror` enums; convert with `?`.
- Commit messages end with:
  `Claude-Session: https://claude.ai/code/session_01LhadyW9scQL95h3ag9yySB`

---

### Task 1: `RANDOMIZED` perms bit in `scl-core`

**Files:**
- Modify: `crates/core/src/object.rs:23` (beside `PROTECTED`)
- Modify: `crates/core/src/lib.rs:29` (re-export)

**Interfaces:**
- Produces: `scl_core::RANDOMIZED: u8 = 0b0000_0010`. Every later task tests format with `perms & RANDOMIZED != 0` and mints new seals as `PROTECTED | RANDOMIZED`.

- [ ] **Step 1: Write the failing test** in `crates/core/src/object.rs`'s existing `mod tests`:

```rust
#[test]
fn randomized_bit_is_distinct_from_protected() {
    assert_eq!(PROTECTED & RANDOMIZED, 0, "flags must not overlap");
    assert_ne!(RANDOMIZED, 0);
    // A randomized entry is always also protected.
    let perms = PROTECTED | RANDOMIZED;
    assert!(perms & PROTECTED != 0 && perms & RANDOMIZED != 0);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p scl-core randomized_bit -- --nocapture`
Expected: FAIL — `cannot find value RANDOMIZED`.

- [ ] **Step 3: Implement** — in `crates/core/src/object.rs`, directly below `pub const PROTECTED: u8 = 0b0000_0001;`:

```rust
/// Perms flag: this PROTECTED entry was sealed with a fresh random DEK+nonce
/// (P33) rather than convergently. Always set together with `PROTECTED`.
/// Format identification for dual-read lives here, in the tree entry, so no
/// caller ever needs to fetch blob bytes to know the seal format.
pub const RANDOMIZED: u8 = 0b0000_0010;
```

Add `RANDOMIZED` to the `pub use` list in `crates/core/src/lib.rs:29`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p scl-core`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/object.rs crates/core/src/lib.rs
git commit -m "P33: add RANDOMIZED perms flag to scl-core"
```

---

### Task 2: `encrypt_path_randomized` in `scl-crypto`

**Files:**
- Modify: `crates/crypto/src/envelope.rs` (below `encrypt_path`, ~line 168)
- Modify: `crates/crypto/src/lib.rs` (export)

**Interfaces:**
- Consumes: existing `decrypt_path`, `PATH_AAD`, `DEK_LEN`, `NONCE_LEN`.
- Produces: `pub fn encrypt_path_randomized(plaintext: &[u8]) -> (Vec<u8>, Zeroizing<[u8; 32]>)` and `pub fn encrypt_path_randomized_with_rng<R: RngCore + CryptoRng>(plaintext: &[u8], rng: &mut R) -> (Vec<u8>, Zeroizing<[u8; 32]>)`. Blob layout identical to `encrypt_path` (`nonce(24) ‖ ct`, same `PATH_AAD`) so the existing `decrypt_path` opens both.

- [ ] **Step 1: Write the failing tests** in `envelope.rs`'s `mod tests`:

```rust
#[test]
fn randomized_seal_roundtrips_and_closes_the_oracle() {
    let pt = b"the database password is hunter2";
    let (blob1, dek1) = encrypt_path_randomized(pt);
    let (blob2, dek2) = encrypt_path_randomized(pt);
    // THE phase invariant: same plaintext, different ciphertext bytes.
    assert_ne!(blob1, blob2, "equality oracle must be closed");
    assert_ne!(dek1.as_slice(), dek2.as_slice());
    // Dual-read: the unchanged decrypt_path opens a randomized blob.
    assert_eq!(&decrypt_path(&blob1, &dek1).unwrap()[..], pt);
    assert_eq!(&decrypt_path(&blob2, &dek2).unwrap()[..], pt);
}

#[test]
fn randomized_seal_is_deterministic_under_a_seeded_rng() {
    let mut r1 = rng(7);
    let mut r2 = rng(7);
    let (b1, _) = encrypt_path_randomized_with_rng(b"x", &mut r1);
    let (b2, _) = encrypt_path_randomized_with_rng(b"x", &mut r2);
    assert_eq!(b1, b2);
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p scl-crypto randomized_seal -- --nocapture`
Expected: FAIL — function not found.

- [ ] **Step 3: Implement** in `envelope.rs`, after `encrypt_path` (note the doc comment on `encrypt_path` should also gain one line: "Legacy convergent format — kept for dual-read comparison only; new seals use `encrypt_path_randomized` (P33)."):

```rust
/// Randomized file encryption (P33): fresh random DEK + random nonce per
/// seal, so identical plaintext yields different ciphertext every time —
/// the ADR-0014 equality oracle is closed for content sealed this way.
/// Blob layout and AAD are identical to `encrypt_path` (`nonce ‖ ct`,
/// `PATH_AAD`), so `decrypt_path` opens both formats unchanged (dual-read).
pub fn encrypt_path_randomized(plaintext: &[u8]) -> (Vec<u8>, Zeroizing<[u8; DEK_LEN]>) {
    encrypt_path_randomized_with_rng(plaintext, &mut OsRng)
}

/// `encrypt_path_randomized` with a caller-supplied RNG (deterministic in tests).
pub fn encrypt_path_randomized_with_rng<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    rng: &mut R,
) -> (Vec<u8>, Zeroizing<[u8; DEK_LEN]>) {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    rng.fill_bytes(dek.as_mut_slice());
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).expect("32-byte DEK");
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: PATH_AAD,
            },
        )
        .expect("aead encrypt is infallible for valid inputs");

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    (blob, dek)
}
```

Export both from `crates/crypto/src/lib.rs` in the existing `pub use envelope::{...}` list.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p scl-crypto`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add crates/crypto/src/envelope.rs crates/crypto/src/lib.rs
git commit -m "P33: randomized path seal (fresh DEK+nonce, dual-read layout)"
```

---

### Task 3: `cache.rs` — local key + per-checkout unchanged-detection cache

**Files:**
- Create: `crates/repo/src/cache.rs`
- Modify: `crates/repo/src/lib.rs` (add `pub(crate) mod cache;` — match the file's existing mod-list style)
- Modify: `crates/repo/src/layout.rs` (three path helpers)

**Interfaces:**
- Consumes: `scl_crypto::random_hex` (for key minting), `blake3::keyed_hash`, `hex`.
- Produces (all `pub(crate)`, used by Tasks 4, 5, 7, 8, 10):
  - `cache::local_key(layout: &Layout) -> Result<[u8; 32]>` — reads `.sc/local-key` (64 hex chars), lazily minting it 0600 if absent; hard error only on create/permission failure.
  - `struct ProtectedCache` with:
    - `ProtectedCache::open(key: [u8; 32], path: Option<PathBuf>) -> ProtectedCache` — loads entries if the file exists; a corrupt file is treated as empty (stderr warning); `path: None` = ephemeral in-memory cache (used by `sc work`).
    - `fn unchanged(&self, rel: &str, abs: &Path, plaintext: &[u8]) -> Option<ObjectId>` — stat hit (mtime+size) or keyed-tag match returns the cached ciphertext blob id.
    - `fn record(&mut self, rel: &str, abs: &Path, plaintext: &[u8], blob_id: ObjectId)`
    - `fn save(&self) -> Result<()>` — atomic (write temp sibling + rename); no-op when `path` is `None`.
  - `Layout::local_key_path()` → `.sc/local-key`; `Layout::protected_cache_path()` → `.sc/protected-cache`; `Layout::ws_cache_path(i: usize)` → `.sc/ws/cache-<i>` (beside the checkout dir, NOT inside `.sc/ws/<i>/` — a file inside the checkout would be harvested as an untracked working file).

- [ ] **Step 1: Add the Layout helpers** (no test needed — pure path joins, mirror the style of `sparse_path()` at `layout.rs:78`):

```rust
/// `.sc/local-key` — per-repo random key for the P33 unchanged-detection
/// cache's keyed hashes. Never committed, never transferred.
pub fn local_key_path(&self) -> PathBuf {
    self.dot_sc.join("local-key")
}

/// `.sc/protected-cache` — the main working tree's P33 stat cache.
pub fn protected_cache_path(&self) -> PathBuf {
    self.dot_sc.join("protected-cache")
}

/// `.sc/ws/cache-<i>` — workspace `i`'s P33 stat cache. Lives BESIDE the
/// checkout dir (`.sc/ws/<i>/`), never inside it, so harvest's worktree
/// read can't pick it up as an untracked file.
pub fn ws_cache_path(&self, i: usize) -> PathBuf {
    self.dot_sc.join("ws").join(format!("cache-{i}"))
}
```

- [ ] **Step 2: Write the failing tests** — create `crates/repo/src/cache.rs` with the tests first (module skeleton + `mod tests`). Use a tempdir pattern like `worktree.rs`'s `tmp_objects`:

```rust
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

        let mut c = ProtectedCache::open(key, Some(layout.protected_cache_path()));
        assert_eq!(c.unchanged("secret.txt", &abs, b"v1"), None, "empty cache misses");
        c.record("secret.txt", &abs, b"v1", id);

        // Stat hit: file untouched.
        assert_eq!(c.unchanged("secret.txt", &abs, b"v1"), Some(id));

        // Tag fallback: touch mtime without changing content.
        std::fs::write(&abs, b"v1").unwrap();
        assert_eq!(c.unchanged("secret.txt", &abs, b"v1"), Some(id));

        // Real change: miss.
        std::fs::write(&abs, b"v2").unwrap();
        assert_eq!(c.unchanged("secret.txt", &abs, b"v2"), None);
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

        let mut c = ProtectedCache::open(key, Some(layout.protected_cache_path()));
        c.record("a b/spaced name.txt", &abs, b"v", id);
        c.save().unwrap();

        let c2 = ProtectedCache::open(key, Some(layout.protected_cache_path()));
        assert_eq!(c2.unchanged("a b/spaced name.txt", &abs, b"v"), Some(id));

        // Corrupt file: degrades to empty, never errors.
        std::fs::write(layout.protected_cache_path(), b"garbage\nlines\n").unwrap();
        let c3 = ProtectedCache::open(key, Some(layout.protected_cache_path()));
        assert_eq!(c3.unchanged("a b/spaced name.txt", &abs, b"v"), None);
        cleanup(&layout);
    }

    #[test]
    fn ephemeral_cache_never_touches_disk() {
        let layout = tmp("ephemeral");
        let key = local_key(&layout).unwrap();
        let abs = layout.root.join("f");
        std::fs::write(&abs, b"v").unwrap();
        let mut c = ProtectedCache::open(key, None);
        c.record("f", &abs, b"v", ObjectId::of(b"c"));
        c.save().unwrap();
        assert!(!layout.protected_cache_path().exists());
        cleanup(&layout);
    }
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p scl-repo cache:: -- --nocapture`
Expected: FAIL to compile — types not defined.

- [ ] **Step 4: Implement the module**:

```rust
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

use scl_core::ObjectId;

use crate::error::Result;
use crate::layout::Layout;

/// Load (minting if absent) the per-repo random cache key. The key file is
/// the only hard-error surface here: if it can't be created/read, the cache
/// cannot be safely keyed, so surface it rather than running unkeyed.
pub(crate) fn local_key(layout: &Layout) -> Result<[u8; 32]> {
    let path = layout.local_key_path();
    let hex_str = match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = scl_crypto::random_hex(32); // 32 random bytes -> 64 hex chars
            // Mirror the serve-TLS key discipline: 0600 before content matters.
            std::fs::write(&path, &s)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            s
        }
        Err(e) => return Err(e.into()),
    };
    let bytes = hex::decode(&hex_str)
        .map_err(|_| crate::error::Error::Corrupt("malformed .sc/local-key".into()))?;
    bytes
        .try_into()
        .map_err(|_| crate::error::Error::Corrupt("malformed .sc/local-key".into()))
}
```

> NOTE: check `scl_crypto::random_hex`'s contract at `crates/crypto/src/lib.rs:37` — if `random_hex(32)` returns 32 hex *chars* (16 bytes) rather than 64, pass 64 or add a `random_bytes(n)` helper to `scl-crypto` instead. The test (`k1 != [0u8;32]`, 32-byte decode) will catch a mismatch. If `Error::Corrupt` doesn't exist in `crates/repo/src/error.rs`, use the closest existing variant (e.g. `Error::InvalidArgument`) — do not add a new variant for this.

```rust
#[derive(Clone, Copy, Debug, PartialEq)]
struct CacheEntry {
    mtime_ns: u128,
    size: u64,
    tag: [u8; 32],
    blob_id: ObjectId,
}

/// Per-checkout unchanged-detection cache (main tree, one ws workspace, or
/// an ephemeral in-memory one for `sc work` temp checkouts).
pub(crate) struct ProtectedCache {
    key: [u8; 32],
    /// `None` => ephemeral: `save()` is a no-op.
    path: Option<PathBuf>,
    entries: BTreeMap<String, CacheEntry>,
}

impl ProtectedCache {
    pub(crate) fn open(key: [u8; 32], path: Option<PathBuf>) -> ProtectedCache {
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
                        let blob_id = ObjectId::from_hex(it.next()?).ok()?;
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
        ProtectedCache { key, path, entries }
    }

    fn tag(&self, plaintext: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.key, plaintext).as_bytes()
    }

    fn stat(abs: &Path) -> Option<(u128, u64)> {
        let md = std::fs::metadata(abs).ok()?;
        let mtime = md.modified().ok()?;
        let ns = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        Some((ns, md.len()))
    }

    /// The cached ciphertext blob id iff this exact plaintext is what last
    /// sealed at `rel`: stat hit (mtime+size unchanged) short-circuits;
    /// otherwise fall back to the keyed-tag comparison.
    pub(crate) fn unchanged(&self, rel: &str, abs: &Path, plaintext: &[u8]) -> Option<ObjectId> {
        let e = self.entries.get(rel)?;
        if let Some((mtime_ns, size)) = Self::stat(abs) {
            if mtime_ns == e.mtime_ns && size == e.size {
                return Some(e.blob_id);
            }
        }
        (self.tag(plaintext) == e.tag).then_some(e.blob_id)
    }

    /// Record that `plaintext` at `rel` seals to `blob_id`. Missing stat
    /// (file vanished mid-operation) just skips the entry.
    pub(crate) fn record(&mut self, rel: &str, abs: &Path, plaintext: &[u8], blob_id: ObjectId) {
        if let Some((mtime_ns, size)) = Self::stat(abs) {
            let tag = self.tag(plaintext);
            self.entries
                .insert(rel.to_string(), CacheEntry { mtime_ns, size, tag, blob_id });
        }
    }

    /// Atomic write (temp sibling + rename); no-op for an ephemeral cache.
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
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
```

> NOTE: check `ObjectId`'s hex API in `crates/core` — `refs.rs` serializes branch tips to hex; use exactly the same to/from helpers it uses (adjust `to_hex`/`from_hex` names to what exists).

- [ ] **Step 5: Run to verify they pass**

Run: `cargo test -p scl-repo cache::`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/repo/src/cache.rs crates/repo/src/lib.rs crates/repo/src/layout.rs
git commit -m "P33: per-checkout protected-path stat cache + local key"
```

---

### Task 4: Format dispatch in `diff_worktree` and `diff_unified`

**Files:**
- Modify: `crates/repo/src/worktree.rs:477-529` (`diff_worktree`)
- Modify: `crates/repo/src/repo.rs:881-891` (`diff_unified`'s protected arm)
- Modify: every `diff_worktree` caller (grep `diff_worktree(` — status, dirty-tree preflights in switch/merge/rebase, `harvest_workspace` at `workspace.rs:85`, ws probes) to pass the new parameter.

**Interfaces:**
- Consumes: `RANDOMIZED` (Task 1), `ProtectedCache::unchanged` (Task 3).
- Produces: `diff_worktree(layout, store, head_root, protection, sparse, cache: Option<&ProtectedCache>)` — the new trailing parameter. Main-tree callers pass `Some(&cache)` where they already have a `Repo` (open via `cache::local_key(self.layout())` + `ProtectedCache::open(key, Some(self.layout().protected_cache_path()))`); `harvest_workspace` passes the workspace cache its caller threads in (Task 7 wires ws/`sc work`; until then pass `None` there).

Behavior for a `PROTECTED` HEAD entry with disk bytes present:
- `RANDOMIZED` bit clear → today's convergent re-encrypt-and-compare (unchanged code).
- `RANDOMIZED` bit set → `cache.unchanged(path, abs, bytes)`: `Some(id)` equal to the HEAD id ⇒ clean; `Some(other)`/`None`/no cache ⇒ modified (spurious-but-safe).

- [ ] **Step 1: Write the failing test** in `worktree.rs`'s `mod tests` (adapt to the file's helpers — `tmp_objects` exists at `worktree.rs:672`):

```rust
#[test]
fn diff_dispatches_randomized_entries_through_the_cache() {
    let (layout, mut store) = tmp_objects("p33-diff");
    // Build a HEAD tree with one RANDOMIZED protected entry whose plaintext
    // sits on disk, exactly as an authorized checkout leaves it.
    let pt = b"top secret".to_vec();
    let (cipher, _dek) = scl_crypto::encrypt_path_randomized(&pt);
    let blob = Object::blob(cipher.clone());
    let blob_id = blob.id();
    store.put(blob).unwrap();
    let root = write_tree_with_perms_into(
        &mut store,
        &[("secret/x".to_string(), cipher, FileMode::FILE, PROTECTED | scl_core::RANDOMIZED)],
    );
    let abs = layout.root.join("secret/x");
    std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
    std::fs::write(&abs, &pt).unwrap();

    let key = crate::cache::local_key(&layout).unwrap();
    let mut cache = crate::cache::ProtectedCache::open(key, None);

    // No cache entry: spurious-but-safe MODIFIED.
    let d = diff_worktree(&layout, &mut store, Some(root), &Protection::default(),
                          &Sparse::default(), Some(&cache)).unwrap();
    assert_eq!(d.modified, vec!["secret/x"]);

    // Recorded: provably clean.
    cache.record("secret/x", &abs, &pt, blob_id);
    let d = diff_worktree(&layout, &mut store, Some(root), &Protection::default(),
                          &Sparse::default(), Some(&cache)).unwrap();
    assert!(d.modified.is_empty() && d.added.is_empty() && d.deleted.is_empty());

    // Genuine edit: modified again (tag mismatch).
    std::fs::write(&abs, b"edited").unwrap();
    let d = diff_worktree(&layout, &mut store, Some(root), &Protection::default(),
                          &Sparse::default(), Some(&cache)).unwrap();
    assert_eq!(d.modified, vec!["secret/x"]);

    std::fs::remove_dir_all(&layout.root).unwrap();
    assert!(!layout.root.exists());
}
```

(If no `write_tree_with_perms_into` helper exists in these tests, build the tree the way the file's existing protected-diff tests do — grep `PROTECTED` in `worktree.rs`'s test mod and copy that construction.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p scl-repo diff_dispatches_randomized -- --nocapture`
Expected: FAIL to compile (extra argument).

- [ ] **Step 3: Implement.** In `diff_worktree`, add the parameter and replace the protected arm (`worktree.rs:501-506`):

```rust
let disk_id = if perms & PROTECTED != 0 {
    if perms & scl_core::RANDOMIZED == 0 {
        // Convergent (legacy) entry: re-encryption yields the same id
        // as the commit did — still exact, no cache needed.
        Object::blob(scl_crypto::encrypt_path(bytes).0).id()
    } else {
        // Randomized entry (P33): re-encrypting proves nothing. The
        // stat cache (stat hit, then keyed-tag fallback) is the only
        // public-key-free unchanged proof; a missing entry reports
        // modified — spurious-but-safe, never incorrect.
        let abs = safe_join(&layout.root, p)?;
        match cache.and_then(|c| c.unchanged(p, &abs, bytes)) {
            Some(id) => id,
            None => {
                diff.modified.push(p.clone());
                continue;
            }
        }
    }
} else {
    Object::blob(bytes.clone()).id()
};
```

Extend the doc comment's protected-path paragraph to describe the two formats. In `diff_unified` (`repo.rs:881-891`), apply the same dispatch: convergent → existing compare; randomized → open the main-tree cache (`cache::local_key` + `ProtectedCache::open(key, Some(self.layout().protected_cache_path()))` at the top of the function) and report `protected file changed: {path} (content not shown)` when `unchanged` misses or disagrees. Update all `diff_worktree` callers: `Repo` methods construct the main-tree cache; `workspace.rs:85` passes `None` for now (Task 7 threads the real one).

- [ ] **Step 4: Run the full crate suite**

Run: `cargo test -p scl-repo`
Expected: PASS — no existing test regresses (no `RANDOMIZED` entries exist yet anywhere else, so every existing path takes the convergent arm).

- [ ] **Step 5: Commit**

```bash
git add -A crates/repo
git commit -m "P33: format-dispatched unchanged detection in status/diff"
```

---

### Task 5: Format-dispatched carry in `snapshot_files` (commit path)

**Files:**
- Modify: `crates/repo/src/repo.rs:339-360` (the plain/protected split + encrypt block inside `snapshot_files`) and the function signature at `repo.rs:256`
- Modify: all `snapshot_files` callers (grep `snapshot_files(` — `commit`, `amend`, `assemble_completion_snapshot`, `harvest_workspace` at `workspace.rs:100`, and any replay-side callers) to pass the new parameter.

**Interfaces:**
- Consumes: `RANDOMIZED`, `ProtectedCache` (Tasks 1, 3).
- Produces: `snapshot_files(..., sparse: &Sparse, cache: Option<&mut ProtectedCache>, author, message)` — one new parameter, threaded explicitly like `sparse` (the P24 anti-ambient discipline). Main-tree callers open + pass the main cache and call `cache.save()` after the commit succeeds; `harvest_workspace` threads its caller's cache (Task 7).

Per-protected-path commit rule (the spec §3 table):
1. Prior tip entry convergent → convergent-compare; equal ⇒ **carry** prior ciphertext + perms verbatim (stays convergent, no cache needed); else seal.
2. Prior tip entry randomized → `cache.unchanged` hit matching the prior blob id ⇒ carry; else seal.
3. No prior entry ⇒ seal.

Carried entries reuse the existing absent-path carry mechanics (fetch ciphertext from store, push with source perms, `fresh_wrapped.entry(blob_id).or_insert_with(prior wraps)`). Sealed entries go through `encrypt_protected` exactly as today. After sealing, `record` each sealed path's new blob id (recompute `Object::blob(cipher).id()` from the returned entries) and each carried randomized path (refresh stat) into the cache.

- [ ] **Step 1: Write the failing test** in `repo.rs`'s `mod tests`, using the file's existing persistent-repo + protect helpers (grep `fn protect` / `sc protect`-style tests, e.g. ones that call `repo.protect(...)` then `repo.commit(...)`; mirror their setup):

```rust
#[test]
fn commit_carries_unchanged_convergent_content_without_reseal() {
    // A pre-P33 store: protect + commit mints CONVERGENT entries (until
    // Task 6 flips the seal, new commits still mint convergent too — this
    // test pins the carry rule either way by asserting blob-id stability).
    let (repo, _tmp) = test_repo_with_identity("p33-carry"); // adapt to existing helper
    write_file(&repo, "secret/db.txt", b"hunter2");
    repo.protect("secret/", &[recipient_pk()]).unwrap();
    let c1 = repo.commit("alice", "one").unwrap();
    let id1 = blob_id_at(&repo, c1, "secret/db.txt");

    // Unrelated edit; protected file untouched.
    write_file(&repo, "readme.md", b"hello");
    let c2 = repo.commit("alice", "two").unwrap();
    let id2 = blob_id_at(&repo, c2, "secret/db.txt");
    assert_eq!(id1, id2, "unchanged protected content must carry, not re-seal");
}
```

Add a second test for the randomized arm — build a tip whose protected entry is `PROTECTED | RANDOMIZED` (seal with `encrypt_path_randomized`, write the tree via the low-level helpers as in Task 4's test), materialize the plaintext, record it in the main cache, run `commit`, and assert the blob id is carried on a cache hit and re-sealed (different id, still decryptable) after the cache file is deleted:

```rust
#[test]
fn commit_randomized_carry_via_cache_and_reseal_on_lost_cache() {
    // ...setup as described above...
    let c2 = repo.commit("alice", "unrelated").unwrap();
    assert_eq!(blob_id_at(&repo, c2, "secret/x"), randomized_id, "cache hit carries");

    std::fs::remove_file(repo.layout().protected_cache_path()).unwrap();
    write_file(&repo, "readme.md", b"more");
    let c3 = repo.commit("alice", "unrelated2").unwrap();
    let id3 = blob_id_at(&repo, c3, "secret/x");
    assert_ne!(id3, randomized_id, "lost cache degrades to a spurious re-seal");
    // Never incorrectness: the new blob still decrypts to the same plaintext.
    assert_eq!(decrypt_at(&repo, c3, "secret/x", &identity()), b"top secret");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p scl-repo commit_carries_unchanged commit_randomized_carry -- --nocapture`
Expected: FAIL (compile error on the new param, then assertion).

- [ ] **Step 3: Implement.** Inside `snapshot_files`, after the plain/protected split (`repo.rs:341-348`) and the scanner gate, insert the dispatch before `encrypt_protected`:

```rust
// P33 format-dispatched carry: decide per protected path whether the tip
// already holds this exact content (carry the prior ciphertext id — quiet
// history) or it must be sealed fresh (randomized). Convergent priors use
// the exact re-encrypt-and-compare proof; randomized priors use the local
// stat cache (stat hit, then keyed tag). This dispatch is what makes the
// upgrade non-mandatory: unchanged legacy content stays convergent forever.
let tip_entries: BTreeMap<String, (ObjectId, scl_core::FileMode, u8)> = match tip {
    Some(t) => {
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let parent_root = store.get_snapshot(&t)?.root;
        if partial {
            worktree::tree_file_entries_with_perms_sparse(&mut store, parent_root, sparse)?
        } else {
            worktree::tree_file_entries_with_perms(&mut store, parent_root)?
        }
    }
    None => BTreeMap::new(),
};
let mut to_seal: Vec<ProtectedFile> = Vec::new();
let mut sealed_plaintexts: Vec<(String, Vec<u8>)> = Vec::new();
for (path, bytes, mode, granted) in protected {
    let carried = tip_entries.get(&path).and_then(|(blob_id, _m, perms)| {
        if perms & scl_core::PROTECTED == 0 {
            return None;
        }
        let unchanged = if perms & scl_core::RANDOMIZED == 0 {
            Object::blob(scl_crypto::encrypt_path(&bytes).0).id() == *blob_id
        } else {
            let abs = worktree::safe_join(&self.layout.root, &path).ok()?;
            cache
                .as_deref()
                .and_then(|c| c.unchanged(&path, &abs, &bytes))
                == Some(*blob_id)
        };
        unchanged.then_some((*blob_id, *perms))
    });
    match carried {
        Some((blob_id, perms)) => {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let cipher = match store.get(&blob_id)? {
                Object::Blob(b) => b.to_vec(),
                _ => {
                    to_seal.push((path, bytes, mode, granted));
                    continue;
                }
            };
            all.push((path.clone(), cipher, mode, perms));
            if let Some(prior_wks) = protection.wrapped.get(&blob_id) {
                fresh_wrapped
                    .entry(blob_id)
                    .or_insert_with(|| prior_wks.clone());
            }
        }
        None => {
            sealed_plaintexts.push((path.clone(), bytes.clone()));
            to_seal.push((path, bytes, mode, granted));
        }
    }
}
let (protected_all, sealed_wrapped) = crate::protect::encrypt_protected(to_seal)?;
// Record every freshly sealed path (its new blob id) and refresh carried
// randomized paths in the cache; the caller saves after the commit lands.
if let Some(c) = cache.as_deref_mut() {
    for (path, cipher, _mode, _perms) in &protected_all {
        if let Some((_, pt)) = sealed_plaintexts.iter().find(|(p, _)| p == path) {
            if let Ok(abs) = worktree::safe_join(&self.layout.root, path) {
                c.record(path, &abs, pt, Object::blob(cipher.clone()).id());
            }
        }
    }
}
all.extend(protected_all);
fresh_wrapped.extend(sealed_wrapped);
```

> Anchoring notes for the implementer: `all`/`fresh_wrapped` are declared at `repo.rs:357-359` — restructure that block so `all` starts from `plain` (as today) and the dispatch above replaces the single `encrypt_protected(protected)` call. `partial`/`promisor` are computed at `repo.rs:418-419` — hoist that pair above the dispatch (it's needed earlier now). `ProtectedFile` is the existing alias used at `repo.rs:342`. The `?` inside the `and_then` closure won't compile — use explicit `match`/`if let` there instead (the code above marks the one spot with `.ok()?` inside a closure returning `Option`, which is fine; `store.get(...)?` in the outer loop is fine).
>
> **Error-path discipline:** if the commit later fails (scanner already ran; tree-write or ref-move errors), the cache was mutated in memory but `save()` never runs — entries stay stale, which the degradation rule already covers (stale = spurious re-seal next time or a stat mismatch falling to tag compare; a *recorded-but-unlanded* blob id would only be returned on a later hit if that exact plaintext seals again, in which case the id is present in the store anyway — content-addressed stores make this benign). Do NOT save the cache inside `snapshot_files`; the committing caller saves only after the ref moves.

Thread the parameter through every caller. In `Repo::commit`/`amend`/`assemble_completion_snapshot`:

```rust
let key = crate::cache::local_key(&self.layout)?;
let mut cache =
    crate::cache::ProtectedCache::open(key, Some(self.layout.protected_cache_path()));
let id = self.snapshot_files(files, ..., sparse, Some(&mut cache), author, message)?;
// only after the ref actually moved:
cache.save()?;
```

`workspace.rs:100` (`harvest_workspace`) passes `None` in this task; Task 7 threads the real per-workspace cache.

- [ ] **Step 4: Run the full crate suite**

Run: `cargo test -p scl-repo`
Expected: PASS — existing behavior unchanged (all existing protected entries are convergent; the convergent-compare carry produces the same blob ids the re-seal used to).

- [ ] **Step 5: Commit**

```bash
git add -A crates/repo
git commit -m "P33: format-dispatched carry in the commit pipeline"
```

---

### Task 6: Flip `encrypt_protected` to randomized seals

**Files:**
- Modify: `crates/repo/src/protect.rs:125-153` (`encrypt_protected`)
- Modify: any test that asserts convergent behavior of *new* seals (see Step 4)

**Interfaces:**
- Consumes: `encrypt_path_randomized` (Task 2), `RANDOMIZED` (Task 1).
- Produces: `encrypt_protected` unchanged in signature, but every returned entry now carries perms `PROTECTED | RANDOMIZED` and a fresh random seal. This is the single choke point — its three callers (`repo.rs:359` commit [now via Task 5's `to_seal`], `repo.rs:1217` merge completion, `replay.rs:222` replay) all switch at once.

- [ ] **Step 1: Write the failing test** in `protect.rs`'s `mod tests`:

```rust
#[test]
fn encrypt_protected_seals_randomized() {
    let (_sk, pk) = scl_crypto::generate_keypair();
    let f = |v: &[u8]| {
        encrypt_protected(vec![(
            "secret/x".into(), v.to_vec(), FileMode::FILE, vec![pk.to_bytes()],
        )])
        .unwrap()
    };
    let (a1, _) = f(b"same");
    let (a2, _) = f(b"same");
    assert_ne!(a1[0].1, a2[0].1, "two seals of one plaintext must differ (oracle closed)");
    assert_eq!(a1[0].3, scl_core::PROTECTED | scl_core::RANDOMIZED);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p scl-repo encrypt_protected_seals_randomized -- --nocapture`
Expected: FAIL — identical ciphertext, perms == `PROTECTED`.

- [ ] **Step 3: Implement.** In `encrypt_protected`, change two lines:

```rust
let (blob_bytes, dek) = scl_crypto::encrypt_path_randomized(&bytes);
```

and

```rust
all.push((path, blob_bytes, mode, scl_core::PROTECTED | scl_core::RANDOMIZED));
```

Update the function's doc comment: "Randomized encryption (P33, ADR-0043): each file seals under a fresh random DEK+nonce…". Also update `reuse_prior_wraps`'s doc comment (`protect.rs:155-172`): prior-wrap reuse now only fires for carried (id-stable) blobs — a freshly randomized blob id is never in `prior`; the function stays for exactly the carried case.

- [ ] **Step 4: Run the full workspace suite and fix convergence-assuming tests**

Run: `cargo test`
Expected: the new test passes; a small set of existing tests that assert *new-seal* convergence may fail (e.g. tests asserting two commits of identical protected content share a blob id, or dedup-across-paths). For each failure, decide by the spec:
- Unchanged-content id-stability tests → should still PASS via Task 5's carry; if one fails, the carry dispatch has a bug — fix the dispatch, not the test.
- Genuine new-seal convergence assertions (same plaintext at two paths dedups; re-protect mints identical ciphertext) → the spec deliberately breaks these (accepted cost 4c). Invert/rename the assertions to pin the NEW behavior (e.g. `identical_plaintext_at_two_paths_no_longer_dedups`).

- [ ] **Step 5: Commit**

```bash
git add -A crates/repo
git commit -m "P33: all new protected seals are randomized (oracle closed)"
```

---

### Task 7: Cache population at materialization sites

**Files:**
- Modify: `crates/repo/src/worktree.rs:573-664` (`materialize` — new `cache` param, record on decrypted writes)
- Modify: every `materialize` caller (grep `materialize(` in `repo.rs` [switch, merge/pick/rebase completion + aborts, sparse set/disable], `workspace.rs:51`, `ws.rs:239`)
- Modify: `crates/repo/src/workspace.rs:39-119` (`materialize_workspace` + `harvest_workspace` gain a `cache` param)
- Modify: `crates/repo/src/ws.rs` (fork opens `.sc/ws/cache-<i>` per workspace and saves it; harvest opens/passes/saves the same; abandon/teardown removes the cache file with the workspace)
- Modify: the `sc work` session driver in `workspace.rs` (ephemeral `ProtectedCache::open(key, None)` per temp checkout, threaded fork→harvest)

**Interfaces:**
- Consumes: `ProtectedCache::record` (Task 3).
- Produces: `materialize(layout, store, target_root, old_root, protection, identity, sparse, cache: Option<&mut ProtectedCache>)`. Inside the protected-decrypt arm (`worktree.rs:634-641`), after `std::fs::write(&full, &pt[..])?`:

```rust
if let Some(c) = cache.as_deref_mut() {
    c.record(path, &full, &pt[..], *blob_id);
}
```

Callers:
- `Repo::switch` / sparse set/disable / merge-pick-rebase completion materializations: open the main cache, pass `Some(&mut cache)`, `cache.save()?` after the materialize succeeds.
- `materialize_workspace` (ws fork, `ws.rs:239`): open `ProtectedCache::open(key, Some(layout.ws_cache_path(i)))`, pass it down, save after.
- `harvest_workspace` (`workspace.rs:66`): new param `cache: Option<&mut ProtectedCache>`; pass it to both `diff_worktree` (`:85`, replacing Task 4's `None`) and `snapshot_files` (`:100`, replacing Task 5's `None`). `sc ws harvest` opens the workspace's persistent cache; `sc work` threads its ephemeral one.
- `ws_abandon`/teardown: remove `.sc/ws/cache-<i>` alongside the workspace dir.

- [ ] **Step 1: Write the failing test** in `worktree.rs`'s `mod tests`: materialize a tree containing one `PROTECTED | RANDOMIZED` entry with a valid wrap for a test identity, passing a cache; assert the cache proves the file unchanged afterwards:

```rust
#[test]
fn materialize_populates_the_cache_for_decrypted_files() {
    // build store+tree as in Task 4's test, with a real wrap for `sk`
    let key = crate::cache::local_key(&layout).unwrap();
    let mut cache = crate::cache::ProtectedCache::open(key, None);
    let skipped = materialize(&layout, &mut store, root, None, &prot, Some(&sk),
                              &Sparse::default(), Some(&mut cache)).unwrap();
    assert!(skipped.is_empty());
    let abs = layout.root.join("secret/x");
    assert_eq!(cache.unchanged("secret/x", &abs, b"top secret"), Some(blob_id));
    // cleanup + assert gone
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p scl-repo materialize_populates` → FAIL to compile.

- [ ] **Step 3: Implement** the parameter + record call + all caller threading described above.

- [ ] **Step 4: Add the ws end-to-end regression** in `ws.rs`'s `mod tests` (this is the false-conflict hazard the per-workspace cache exists to prevent — mirror the structure of the existing harvest tests around `ws.rs:900-1200`):

```rust
#[test]
fn untouched_protected_files_do_not_conflict_across_workspaces() {
    // repo with a protected file, committed (now RANDOMIZED); identity known.
    // fork 2 workspaces WITH identity; edit only workspace 1's PLAIN file;
    // edit only workspace 2's OTHER plain file; harvest both.
    // Assert: both land cleanly (no work-<i> fallback), and the landed
    // snapshots' secret/x blob id equals the base's (carried, not re-sealed).
}
```

Write it fully (setup helpers exist in that test mod — reuse them).

- [ ] **Step 5: Run the full crate suite** — `cargo test -p scl-repo` → PASS.

- [ ] **Step 6: Commit**

```bash
git add -A crates/repo
git commit -m "P33: populate protected-cache at every plaintext materialization"
```

---

### Task 8: Cache population in `sc resolve`

**Files:**
- Modify: `crates/repo/src/conflicts.rs` (the `resolve` write path — grep `fn resolve` / where it writes the chosen side's content to the working file)

**Interfaces:**
- Consumes: `ProtectedCache::record`.
- Produces: after `resolve --ours|--theirs` writes a protected path's decrypted content, the main-tree cache records it (so completion carries instead of re-sealing when the chosen side's content equals a parent's). Plain paths: no cache involvement.

- [ ] **Step 1: Write the failing test** in `conflicts.rs`'s test mod: set up a protected conflict (reuse the existing P23 test scaffolding in that file), `resolve --ours` with identity, then assert the main cache holds an entry for the path (`unchanged(path, abs, ours_plaintext)` returns the ours-side blob id).

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement:** in the resolve arm that writes decrypted protected content, open the main cache, `record(path, abs, plaintext, chosen_side_blob_id)`, `save()`.

- [ ] **Step 4: Run** `cargo test -p scl-repo` → PASS.

- [ ] **Step 5: Commit** — `git commit -m "P33: sc resolve records resolved protected content in the cache"`.

---

### Task 9: Merge/replay semantics over mixed trees (tests + the identical-edit conflict)

**Files:**
- Modify: `crates/repo/src/merge.rs` (tests), `crates/repo/src/replay.rs` (tests)
- Production changes expected: NONE (id fast paths and diff3-with-identity already handle it) — this task pins that claim with tests and fixes whatever falls out.

**Interfaces:**
- Consumes: everything above.
- Produces: pinned behavior later tasks and the demo rely on.

- [ ] **Step 1: Write the tests** (in `merge.rs`'s P15 test section, reusing `enc_file`/`tree_with_perms` at `merge.rs:765-782`; add a randomized twin of `enc_file`):

```rust
/// Randomized twin of `enc_file` (P33).
fn enc_file_rand(prot: &mut Protection, pk: &scl_crypto::PublicKey, content: &[u8]) -> Vec<u8> {
    let (cipher, dek) = scl_crypto::encrypt_path_randomized(content);
    let id = Object::blob(cipher.clone()).id();
    prot.wrapped.entry(id).or_default().push(scl_crypto::wrap_dek_for(&dek, pk));
    cipher
}

#[test]
fn identical_independent_edits_now_conflict_and_resolve_with_identity() {
    // base: secret/a.txt = "v1" (randomized). ours and theirs BOTH edit it
    // to "v2" — independently, so two different ciphertexts/ids.
    // Assert: three_way_files WITHOUT identity reports the protected
    // conflict/needs-identity outcome (match the existing content-divergent
    // test's expected error/conflict shape); WITH identity it merges
    // cleanly (diff3 of identical plaintexts) and the result decrypts to "v2".
}

#[test]
fn mixed_convergent_and_randomized_tree_merges_by_id_fast_paths() {
    // base holds one convergent entry (enc_file) and one randomized entry
    // (enc_file_rand). ours edits only the plain file; theirs edits only the
    // convergent entry. Assert the merge is clean without identity, the
    // untouched randomized entry carries its exact blob id AND its
    // PROTECTED|RANDOMIZED perms, and the convergent entry takes theirs' id.
}
```

Write both fully against the existing test patterns (`protected_id_fast_paths_need_no_identity` at `merge.rs:785` is the template — copy its structure).

- [ ] **Step 2: Run** — `cargo test -p scl-repo identical_independent mixed_convergent -- --nocapture`. Expected: ideally PASS (the machinery is format-agnostic). If the perms byte is dropped anywhere in the merge carry (fast-path arms in `three_way_files`), fix it to carry the source entry's perms verbatim.

- [ ] **Step 3: Add a replay twin** in `replay.rs` tests: cherry-pick a commit touching a randomized protected path onto a branch where it's unchanged (fast path, no identity) and where it diverged (needs identity). Mirror the file's existing P15 replay-protected tests.

- [ ] **Step 4: Run the full suite** — `cargo test` → PASS.

- [ ] **Step 5: Commit** — `git commit -m "P33: pin merge/replay behavior over mixed convergent+randomized trees"`.

---

### Task 10: `sc rewrap` eager convergent→randomized upgrade

**Files:**
- Modify: `crates/repo/src/rewrap.rs` (paths half, `rewrap.rs:125-201`, and the commit tail)
- Modify: `crates/cli/src/main.rs` (rewrap output — grep `blobs_rewrapped` for the print site)

**Interfaces:**
- Consumes: `encrypt_path_randomized`, `RANDOMIZED`, `decrypt_path`, `ProtectedCache`.
- Produces: `RewrapReport` gains `pub blobs_resealed: usize`. Rewrap behavior per protected entry:
  - Randomized entry → wrap-replacement only (existing code, ciphertext id unchanged).
  - Convergent entry → decrypt with the unwrapped DEK, re-seal via `encrypt_path_randomized`, store the new blob, retarget the tree entry to the new id with perms `PROTECTED | RANDOMIZED`, fresh wraps for `granted + escrow` under the NEW id, drop the OLD id's `protection.wrapped` entry, record the path in the main-tree cache, count in `blobs_resealed`.
  - The commit tail rebuilds the root tree when any blob was re-sealed (collect every tree entry's `(path, bytes, mode, perms)` — bytes from the store — apply the id/perms replacements, `self.vfs.write_tree_with_perms(&all)`), and the snapshot uses the new root. When `blobs_resealed == 0` the root is untouched (policy-only, exactly as P17 — a second rewrap converges back to tree-identical).

- [ ] **Step 1: Write the failing test** in `rewrap.rs`'s test mod (reuse its existing scaffolding):

```rust
#[test]
fn rewrap_upgrades_convergent_blobs_and_second_run_is_policy_only() {
    // repo with a CONVERGENT protected entry at the tip (build pre-P33-style:
    // seal via encrypt_path + PROTECTED perms, or reuse a fixture committed
    // before Task 6 semantics via the low-level tree helpers).
    let r1 = repo.rewrap(&identity, &[], &known, false).unwrap();
    assert_eq!(r1.blobs_resealed, 1);
    let tip1 = repo.head_tip().unwrap().unwrap();
    // entry is now randomized, new id, decrypts to the same plaintext:
    let (id1, perms1) = entry_at(&repo, tip1, "secret/x");
    assert!(perms1 & scl_core::RANDOMIZED != 0);
    assert_eq!(decrypt_at(&repo, tip1, "secret/x", &identity), b"top secret");

    let r2 = repo.rewrap(&identity, &[], &known, false).unwrap();
    assert_eq!(r2.blobs_resealed, 0, "second rewrap is policy-only again");
    if let Some(c2) = r2.commit {
        let tip2 = repo.head_tip().unwrap().unwrap();
        assert_eq!(entry_at(&repo, tip2, "secret/x").0, id1, "ciphertext id stable");
    }
}
```

Also extend an existing skip-and-report test to cover a convergent blob the identity cannot open: it lands in `skipped`, everything else still upgrades, exit stays non-zero (existing semantics).

- [ ] **Step 2: Run to verify it fails** — `cargo test -p scl-repo rewrap_upgrades -- --nocapture` → FAIL (`blobs_resealed` not found).

- [ ] **Step 3: Implement.** In the paths loop after `unwrap_dek_with` succeeds (`rewrap.rs:166-172`), branch on the format:

```rust
if perms & scl_core::RANDOMIZED == 0 {
    // Convergent (pre-P33): eager upgrade. Decrypt with the DEK we just
    // unwrapped, re-seal randomized, retarget tree + wraps to the new id.
    let cipher = { /* store.get(&blob_id) -> Object::Blob bytes */ };
    let pt = match scl_crypto::decrypt_path(&cipher, &dek) {
        Ok(p) => p,
        Err(e) => {
            skipped.push((format!("path {path}"), format!("ciphertext failed to open: {e}")));
            continue;
        }
    };
    if dry_run { blobs_resealed += 1; continue; }
    let (new_cipher, new_dek) = scl_crypto::encrypt_path_randomized(&pt);
    let new_id = { /* store.put(Object::blob(new_cipher.clone()))? */ };
    let mut new_wks: Vec<WrappedKey> = target_pks
        .iter()
        .map(|pk| scl_crypto::wrap_dek_for(&new_dek, pk))
        .collect();
    new_wks.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
    protection.wrapped.remove(&blob_id);
    protection.wrapped.insert(new_id, new_wks);
    retargets.insert(path.clone(), (new_id, scl_core::PROTECTED | scl_core::RANDOMIZED));
    main_cache.record(&path, &self.layout().root.join(&path), &pt, new_id);
    blobs_resealed += 1;
    continue;
}
// randomized: existing wrap-replacement code, unchanged
```

(`target_pks` already exists in the loop at `rewrap.rs:184-194` — hoist its construction above the branch so both arms share it. `retargets: BTreeMap<String, (ObjectId, u8)>` is new, declared beside `blobs_rewrapped`. `main_cache` is opened once before the loop and `save()`d only when the commit lands.)

In the commit tail: when `retargets` is non-empty, rebuild the root — walk `entries` again, for each path fetch bytes from the store (new blob for retargeted paths), apply retargeted perms, `write_tree_with_perms`, and build the snapshot on the new root. Update the emptiness check (`rewrap.rs:206`) to also consider `blobs_resealed`. In the CLI print site, add: `re-sealed {n} convergent blob(s) → randomized` when `blobs_resealed > 0`.

- [ ] **Step 4: Run** — `cargo test -p scl-repo rewrap` then `cargo test` → PASS.

- [ ] **Step 5: Commit** — `git commit -m "P33: sc rewrap eagerly re-seals convergent blobs randomized"`.

---

### Task 11: Demo — `demo/run_randomized_demo.sh`

**Files:**
- Create: `demo/run_randomized_demo.sh` (copy the header/conventions of `demo/run_rewrap_demo.sh` — build once, `set -euo pipefail`, temp workdir, run-twice loop, zero-residue asserts)

**Interfaces:** consumes the finished CLI. The demo must prove, in order:
1. **Oracle closed:** commit the same plaintext at two protected paths, and the same plaintext twice across two commits (edit away, edit back); extract blob ids via `sc log --json`/object inspection and assert all ciphertext ids differ.
2. **Quiet history:** an unrelated commit does NOT change an untouched protected file's blob id (cache carry).
3. **Dual-read:** a repo fixture with a convergent (pre-P33) entry still decrypts; `sc rewrap` upgrades it (`re-sealed 1 convergent blob(s)`), plaintext identical after; a second `sc rewrap` prints no re-seal line.
4. **Old history still decrypts** after the upgrade (check out the pre-rewrap commit, decrypt).
5. Zero `.sc/tmp` residue; the workdir is removed; run the whole script twice.

For the convergent fixture: keep a tiny `sc`-driven pre-seed impossible post-Task-6, so build it with a rust test-utility or simply commit the fixture repo bytes… **Do neither** — instead drive the upgrade path end to end: initialize the repo with the CURRENT binary, then flip one committed protected entry to convergent form using a small hidden debug command? Also no. The honest MVP: the demo proves oracle-closure, quiet history, rewrap idempotence (steps 1, 2, second half of 3, 5) with the current binary, and **dual-read of genuinely old stores is pinned by unit tests** (Tasks 4–6, 9, 10 all build convergent fixtures via the library). State this split in a comment at the top of the demo.

- [ ] **Step 1: Write the script** (full content, following `run_rewrap_demo.sh`'s skeleton).
- [ ] **Step 2: Run it twice** — `bash demo/run_randomized_demo.sh && bash demo/run_randomized_demo.sh` → both green, zero residue.
- [ ] **Step 3: Run every existing protected demo** — `bash demo/run_protected_merge_demo.sh && bash demo/run_revoke_demo.sh && bash demo/run_rewrap_demo.sh && bash demo/run_lifecycle_demo.sh && bash demo/run_merge_ergonomics_demo.sh && bash demo/run_ws_demo.sh` → all green.
- [ ] **Step 4: Commit** — `git commit -m "P33: randomized-encryption demo (oracle closed, quiet history, rewrap upgrade)"`.

---

### Task 12: Docs — ADR-0043, THREAT-MODEL, CLAUDE.md, ARCHITECTURE.md

**Files:**
- Create: `docs/adr/0043-randomized-protected-encryption.md` (follow the ADR template in `docs/adr/README.md` / recent ADRs' structure: Status/Date/Phase, Context, Decision, Consequences, Alternatives)
- Modify: `THREAT-MODEL.md` (the convergent-equality entry: superseded for new content, still true for pre-P33 history until rewrapped)
- Modify: `CLAUDE.md` (a "Phase 33 is built" section in the established voice: what shipped, the format-dispatch rule, the cache, accepted costs 4a–c, boundaries; update the `sc rewrap` command comment; move the P28 "randomized protected mode" follow-on out of Remaining follow-ons, add rotate-for-paths)
- Modify: `ARCHITECTURE.md` (the protected-path encryption section: randomized-write/dual-read posture)
- Modify: `docs/adr/0014-*.md` — add a one-line pointer: "Superseded for newly sealed content by ADR-0043 (P33); convergent dual-read retained."

**Content requirements for ADR-0043** (each gets a paragraph):
- The format change (RANDOMIZED perms bit; blob layout/AAD unchanged; why the tag lives in the tree entry, not the blob).
- Dual-read posture (no tag bump, no migration; the format-dispatched commit rule and why cache-only dispatch would have mass-migrated).
- Cache design and why it doesn't reintroduce the oracle (keyed PRF under a never-traveling local key; degradation rule).
- Accepted costs 4a–c verbatim from #40, plus the rewrap tree-identity change.
- P15/P17 semantic adjustments; the ws per-workspace cache rationale (false-conflict hazard).
- Unlocked follow-on: rotate-for-paths (ADR-0019's objection dissolves for randomized content) — recorded, not built.

- [ ] **Step 1: Write ADR-0043.**
- [ ] **Step 2: Update THREAT-MODEL.md, CLAUDE.md, ARCHITECTURE.md, ADR-0014 pointer.**
- [ ] **Step 3: Self-check** — grep CLAUDE.md for "randomized" to make sure the P28 accepted-boundary line ("convergent encryption stays equality-confirmable") is updated to point at P33.
- [ ] **Step 4: Commit** — `git commit -m "P33: ADR-0043 + THREAT-MODEL/CLAUDE.md/ARCHITECTURE.md updates"`.

---

### Task 13: Full validation sweep

- [ ] **Step 1:** `cargo test` (whole workspace) → PASS.
- [ ] **Step 2:** `cargo clippy --workspace` → no new warnings.
- [ ] **Step 3:** Run ALL demos listed in CLAUDE.md's Commands section (there are ~20 `demo/run_*.sh` scripts — run each once; protected-related ones twice). Expected: all green, zero residue.
- [ ] **Step 4:** Equality-oracle end check: `cargo test -p scl-crypto randomized_seal_roundtrips_and_closes_the_oracle -p scl-repo encrypt_protected_seals_randomized` → PASS.
- [ ] **Step 5:** Final commit if anything moved; then hand off to the finishing-a-development-branch flow (PR per repo convention — squash-merged).

---

## Self-Review Notes (already applied)

- **Spec coverage:** §1→Task 2, §2→Task 1, §3→Tasks 3+5, §4→Task 4, §5→Tasks 7+8, §6→Task 9, §7→Task 10, §9 error handling→Tasks 3/5/10 inline, §10→Tasks 11–13. The `sc work` ephemeral cache (spec §5 by implication of "per-checkout") is Task 7.
- **Ordering is load-bearing:** dispatch (4–5) before the flip (6); anything reordered mass-re-seals and breaks the suite.
- **Known adaptation points** are marked with `NOTE:` blocks (ObjectId hex API, `random_hex` contract, error variant, test-helper names) — resolve them by reading the named anchor, not by inventing new surface.
