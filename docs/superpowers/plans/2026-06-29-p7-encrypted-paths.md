# P7 — Encrypted Paths Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc protect <prefix> --to <recipients>` makes a subtree read-confidential — files are convergently encrypted so only authorized recipients decrypt them; an unauthorized clone gets ciphertext it can't read.

**Architecture:** Encrypted file = a plain `Blob` of `nonce‖ciphertext` (stable, content-addressed) with a `PROTECTED` perms bit; per-recipient wrapped DEKs live in a snapshot-side `Protection` policy. `scl-crypto` gains convergent `encrypt_path`/`decrypt_path` + exposed `wrap_dek`/`unwrap_dek`. `scl-repo` auto-encrypts protected paths on commit (scanner-exempt), decrypts on checkout (skipping unauthorized), and does policy-only grant/revoke.

**Tech Stack:** Rust 2021; reuses `scl-core`/`scl-crypto`/`scl-repo`. No new deps.

**Source spec:** `docs/superpowers/specs/2026-06-29-p7-encrypted-paths-design.md` · **ADR:** 0014 (firm to Accepted at the end).

## Global Constraints

- `core` stays crypto-free: `Protection` is pure data (strings, `[u8;32]` pubkeys, the existing `WrappedKey`). No `regex`/crypto deps in `core`.
- Encrypted object = a normal `Blob` whose bytes are `nonce(24)‖ciphertext`; the tree entry sets `PROTECTED` in its `perms` byte. No new object kind.
- Convergent: `DEK = HKDF-SHA256(ikm=BLAKE3(plaintext), info="scl-path-dek-v1")`, nonce `= HKDF(... info="scl-path-nonce-v1")[..24]`, AAD `= b"scl-path-v1"`. Identical plaintext → identical blob bytes → stable id.
- Plaintext + DEK are `Zeroizing`; plaintext is never written to disk except via an authorized decrypt at checkout.
- Adding `Snapshot.protection` is a deliberate format break (snapshot ids change), as with the secrets registry. Stage `Cargo.lock` if any dep is added (none expected).
- Every new behavior ships with a test.

---

## Execution prerequisites

- Branch off `main`: `git checkout -b p7-encrypted-paths`. Baseline-commit the spec+plan.
- Tasks 1 & 2 are independent foundations (each green per-crate). After Task 1 the workspace won't fully build until Task 3 fixes downstream `Snapshot` literals — scope Task 1's verification to `cargo test -p scl-core`. Full `cargo test` + clippy after Task 3 onward.

## File structure

**Modify:** `crates/core/src/object.rs`, `crates/core/src/lib.rs`; `crates/crypto/src/{envelope.rs, lib.rs}`; `crates/vfs/src/lib.rs`, `crates/gitio/src/lib.rs`; `crates/repo/src/{repo.rs, worktree.rs, error.rs, lib.rs, reachable.rs}`; `crates/cli/src/main.rs`; `docs/adr/0014-*.md`, `docs/adr/README.md`.
**Create:** `crates/repo/src/protect.rs` (policy helpers); `demo/run_protect_demo.sh`.

---

## Task 1: `core` — PROTECTED bit + `Protection` policy on `Snapshot`

**Files:** Modify `crates/core/src/object.rs`, `crates/core/src/lib.rs`.

**Interfaces:**
- Produces: `pub const PROTECTED: u8 = 0b0000_0001;`; `pub struct ProtectPrefix { prefix: String, recipients: Vec<[u8;32]> }`; `pub struct Protection { prefixes: Vec<ProtectPrefix>, wrapped: BTreeMap<ObjectId, Vec<WrappedKey>> }` (derives `Default`, `Clone`, `PartialEq`, `Eq`, `Debug`); `Snapshot.protection: Protection`.

- [ ] **Step 1: Add the constant + policy types**

In `crates/core/src/object.rs`, near `TreeEntry`, add:

```rust
/// Perms-byte bit: this blob entry holds a `nonce‖ciphertext` envelope (an
/// encrypted file), not plaintext. Set on protected-path entries (P7).
pub const PROTECTED: u8 = 0b0000_0001;

/// A protected path prefix and the recipient public keys its files are
/// encrypted for (used at commit time to wrap new files' DEKs).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProtectPrefix {
    pub prefix: String,
    pub recipients: Vec<[u8; 32]>,
}

/// Per-snapshot encrypted-path policy: which prefixes are protected (+ for whom),
/// and the per-recipient wrapped DEKs keyed by the ciphertext blob's id.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Protection {
    pub prefixes: Vec<ProtectPrefix>,
    pub wrapped: std::collections::BTreeMap<ObjectId, Vec<WrappedKey>>,
}
```

- [ ] **Step 2: Add the field to `Snapshot`**

Add `pub protection: Protection,` to the `Snapshot` struct (after `secrets`), with a doc line: "Encrypted-path policy (P7): protected prefixes + per-ciphertext wrapped DEKs. Canonical encoding (sorted prefixes + ordered map) keeps the id order-independent."

- [ ] **Step 3: Encode the policy**

In `Object::encode`, in the `Snapshot` arm, after the `secrets` loop, add:

```rust
                // protection: prefixes (sorted by prefix) then wrapped map.
                let mut prefixes = s.protection.prefixes.clone();
                prefixes.sort_by(|a, b| a.prefix.cmp(&b.prefix));
                w.u32(prefixes.len() as u32);
                for p in &prefixes {
                    w.str(&p.prefix);
                    w.u32(p.recipients.len() as u32);
                    for r in &p.recipients {
                        w.raw(r); // 32 bytes
                    }
                }
                w.u32(s.protection.wrapped.len() as u32);
                for (id, wks) in &s.protection.wrapped {
                    w.id(id);
                    w.u32(wks.len() as u32);
                    for k in wks {
                        w.str(&k.recipient_id);
                        w.bytes(&k.wrapped_dek);
                    }
                }
```

(`w.raw` writes raw bytes; the 32-byte length is fixed so no length prefix is needed — decode reads exactly 32.)

- [ ] **Step 4: Decode the policy**

In `Object::decode`, in the `TAG_SNAPSHOT` arm, after building `secrets` and before constructing the `Snapshot`, add:

```rust
                let np2 = r.u32()?;
                let mut prefixes = Vec::with_capacity(np2 as usize);
                for _ in 0..np2 {
                    let prefix = r.str()?;
                    let nr = r.u32()?;
                    let mut recipients = Vec::with_capacity(nr as usize);
                    for _ in 0..nr {
                        let mut rk = [0u8; 32];
                        rk.copy_from_slice(r.take(32)?);
                        recipients.push(rk);
                    }
                    prefixes.push(ProtectPrefix { prefix, recipients });
                }
                let nw = r.u32()?;
                let mut wrapped = std::collections::BTreeMap::new();
                for _ in 0..nw {
                    let id = r.id()?;
                    let nk = r.u32()?;
                    let mut wks = Vec::with_capacity(nk as usize);
                    for _ in 0..nk {
                        let recipient_id = r.str()?;
                        let wrapped_dek = r.bytes()?;
                        wks.push(WrappedKey { recipient_id, wrapped_dek });
                    }
                    wrapped.insert(id, wks);
                }
                let protection = Protection { prefixes, wrapped };
```

Then add `protection` to the `Snapshot { … }` construction. (`r.take(n)` is the existing reader primitive returning `&[u8]`; if its name differs, use the existing fixed-length read used by `r.id()`.)

- [ ] **Step 5: Export + update core tests**

In `crates/core/src/lib.rs`, export `PROTECTED`, `Protection`, `ProtectPrefix` from the object module. Update the existing `Snapshot` literals in `object.rs` tests to add `protection: Protection::default()`. Add a roundtrip test:

```rust
    #[test]
    fn snapshot_with_protection_roundtrips_canonically() {
        let root = Object::blob(b"r".to_vec()).id();
        let cid = Object::blob(b"ct".to_vec()).id();
        let mut wrapped = std::collections::BTreeMap::new();
        wrapped.insert(cid, vec![WrappedKey { recipient_id: "rid".into(), wrapped_dek: vec![7; 80] }]);
        let prot = Protection {
            prefixes: vec![ProtectPrefix { prefix: "secrets/".into(), recipients: vec![[9u8; 32]] }],
            wrapped,
        };
        let snap = Object::Snapshot(Snapshot {
            root, parents: vec![], author: "a".into(), timestamp: 0, message: "m".into(),
            secrets: std::collections::BTreeMap::new(), protection: prot,
        });
        assert_eq!(snap, Object::decode(&snap.encode()).unwrap());
    }
```

- [ ] **Step 6: Run + commit**

Run: `cargo test -p scl-core`
Expected: PASS. (Workspace build breaks downstream — fixed in Task 3.)

```bash
git add crates/core/src/object.rs crates/core/src/lib.rs
git commit -m "feat(core): PROTECTED perms bit + Protection policy on Snapshot"
```

---

## Task 2: `scl-crypto` — convergent `encrypt_path`/`decrypt_path` + exposed wrap/unwrap

**Files:** Modify `crates/crypto/src/envelope.rs`, `crates/crypto/src/lib.rs`.

**Interfaces:**
- Produces: `encrypt_path(plaintext: &[u8]) -> (Vec<u8>, Zeroizing<[u8;32]>)`; `decrypt_path(blob: &[u8], dek: &[u8;32]) -> Result<Zeroizing<Vec<u8>>>`; `wrap_dek_for(dek: &[u8;32], recipient: &PublicKey) -> WrappedKey`; `unwrap_dek_with(wrapped: &WrappedKey, identity: &SecretKey) -> Result<Zeroizing<[u8;32]>>`; `PublicKey::from_bytes([u8;32]) -> PublicKey` (needed by commit to rewrap from policy-stored pubkeys).

- [ ] **Step 1: Add the convergent API + public wrap/unwrap (with tests)**

In `crates/crypto/src/envelope.rs`, add (the file already has `DEK_LEN=32`, `NONCE_LEN=24`, `XChaCha20Poly1305`, `Hkdf<Sha256>`, `blake3`, `Zeroizing` in scope; reuse them). Note the existing private `wrap_dek(dek, recipient, rng)` and `unwrap_dek(blob, identity)` — add public wrappers with the spec's signatures that delegate to them:

```rust
const PATH_AAD: &[u8] = b"scl-path-v1";

/// Convergent file encryption: the data key and nonce are derived from the
/// plaintext, so identical plaintext yields identical `nonce‖ciphertext` bytes
/// (stable content-addressed id, perfect dedup). Returns the blob bytes and the
/// DEK (to be wrapped per recipient and stored in the snapshot policy).
pub fn encrypt_path(plaintext: &[u8]) -> (Vec<u8>, Zeroizing<[u8; DEK_LEN]>) {
    let ikm = blake3::hash(plaintext);
    let hk = Hkdf::<Sha256>::new(None, ikm.as_bytes());
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    hk.expand(b"scl-path-dek-v1", dek.as_mut_slice()).expect("32-byte okm");
    let mut nonce = [0u8; NONCE_LEN];
    hk.expand(b"scl-path-nonce-v1", &mut nonce).expect("24-byte okm");

    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).expect("32-byte DEK");
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: PATH_AAD })
        .expect("aead encrypt is infallible for valid inputs");

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    (blob, dek)
}

/// Decrypt a `nonce‖ciphertext` blob with its DEK (AEAD-verified).
pub fn decrypt_path(blob: &[u8], dek: &[u8; DEK_LEN]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| Error::Decrypt)?;
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: PATH_AAD })
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(pt))
}

/// Wrap a DEK for `recipient` (X25519→HKDF→AEAD); the wrap uses a random
/// ephemeral key, so the wrapped bytes vary — but they live in the snapshot
/// policy, NOT in the content-addressed blob, so dedup is unaffected.
pub fn wrap_dek_for(dek: &[u8; DEK_LEN], recipient: &PublicKey) -> WrappedKey {
    wrap_dek(dek.as_slice(), recipient, &mut OsRng)
}

/// Unwrap a DEK from a `WrappedKey` with `identity` (errors if not the recipient).
pub fn unwrap_dek_with(wrapped: &WrappedKey, identity: &SecretKey) -> Result<Zeroizing<[u8; DEK_LEN]>> {
    unwrap_dek(&wrapped.wrapped_dek, identity)
}
```

> Naming: the public functions are `wrap_dek_for` / `unwrap_dek_with` to avoid colliding with the existing private `wrap_dek`/`unwrap_dek`. (Use these names consistently in later tasks.)
>
> Also add a public `impl PublicKey { pub fn from_bytes(b: [u8;32]) -> PublicKey }` in `key.rs` (wraps `x25519_dalek::PublicKey::from(b)`), exported from `lib.rs` — commit (Task 4) reconstructs recipient `PublicKey`s from the 32-byte values stored in the policy. Add a test that `PublicKey::from_bytes(pk.to_bytes()) == pk` (round-trip).

Add tests in `envelope.rs`:

```rust
    #[test]
    fn encrypt_path_is_convergent_and_roundtrips() {
        let pt = b"the database password is hunter2";
        let (blob1, dek1) = encrypt_path(pt);
        let (blob2, _dek2) = encrypt_path(pt);
        assert_eq!(blob1, blob2, "same plaintext -> identical bytes (convergent)");
        let out = decrypt_path(&blob1, &dek1).unwrap();
        assert_eq!(&out[..], pt);
        let (blob3, _) = encrypt_path(b"different");
        assert_ne!(blob1, blob3);
    }

    #[test]
    fn decrypt_path_rejects_tamper_and_wrong_key() {
        let (mut blob, dek) = encrypt_path(b"secret");
        let n = blob.len();
        blob[n - 1] ^= 0xFF;
        assert!(decrypt_path(&blob, &dek).is_err());
        let (good, _) = encrypt_path(b"secret");
        let wrong = [0u8; 32];
        assert!(decrypt_path(&good, &wrong).is_err());
    }

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        use crate::key::generate_keypair_with_rng;
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        let (sk, pk) = generate_keypair_with_rng(&mut ChaCha20Rng::seed_from_u64(1));
        let (_blob, dek) = encrypt_path(b"x");
        let wk = wrap_dek_for(&dek, &pk);
        let got = unwrap_dek_with(&wk, &sk).unwrap();
        assert_eq!(got.as_slice(), dek.as_slice());
        let (other_sk, _) = generate_keypair_with_rng(&mut ChaCha20Rng::seed_from_u64(2));
        assert!(unwrap_dek_with(&wk, &other_sk).is_err());
    }
```

- [ ] **Step 2: Export**

In `crates/crypto/src/lib.rs`, add to the envelope re-export: `encrypt_path, decrypt_path, wrap_dek_for, unwrap_dek_with`.

- [ ] **Step 3: Run + commit**

Run: `cargo test -p scl-crypto`
Expected: PASS (existing + 3 new).

```bash
git add crates/crypto/src/envelope.rs crates/crypto/src/lib.rs
git commit -m "feat(crypto): convergent encrypt_path/decrypt_path + public wrap/unwrap DEK"
```

---

## Task 3: Compile-fix downstream + carry `Protection` through `fork`/`commit`

**Files:** Modify `crates/vfs/src/lib.rs`, `crates/gitio/src/lib.rs`, `crates/repo/src/repo.rs`, `crates/repo/src/reachable.rs`.

**Interfaces:**
- Consumes: `scl_core::Protection` (Task 1).
- Produces: `Worktree` carries a `protection: Protection`; `Repo::commit_snapshot` takes a `protection` (or threads the current tip's). `reachable_objects` includes protected-blob ids (already covered as tree blobs) — confirm no change needed.

- [ ] **Step 1: Add `protection: Protection::default()` to every `Snapshot` literal**

Search the workspace for `Snapshot {` and add the field. Known sites: `crates/vfs/src/lib.rs` (`commit_files`, `commit`, the `write_tree` test), `crates/gitio/src/lib.rs` (import), `crates/repo/src/repo.rs` (`commit_snapshot`), and test literals in `repo.rs`/`merge.rs`/`reachable.rs`. Use `protection: scl_core::Protection::default()` (or `Default::default()` where the type is inferable).

- [ ] **Step 2: Thread protection through `Worktree` + repo commit**

In `crates/vfs/src/lib.rs`, add `protection: Protection` to `Worktree`, populate it in `Repo::fork` from the base snapshot (`snap.protection`), and write it in `Worktree::commit`'s `Snapshot` literal. Add `Protection` to the `scl_core` import. In `crates/repo/src/repo.rs`, `commit_snapshot` currently builds the `Snapshot`; give it a `protection: Protection` parameter (callers pass the carried-forward policy — `commit` passes the tip's protection, secret ops pass the tip's, etc.). Update the existing callers accordingly.

> Keep this task mechanical: the policy is just carried forward unchanged; commit-time *encryption* is Task 4. `commit` for now passes `tip`'s protection through unchanged (a clean working tree under no protected prefix produces an identical policy).

- [ ] **Step 3: Build the whole workspace + run all tests**

Run: `cargo test` then `cargo clippy --workspace --all-targets`
Expected: green + clean. (Behavior unchanged; this task only restores the build and carries the policy.)

- [ ] **Step 4: Commit**

```bash
git add crates/vfs/src/lib.rs crates/gitio/src/lib.rs crates/repo/src/repo.rs crates/repo/src/reachable.rs
git commit -m "refactor(repo,vfs,gitio): carry Protection policy through fork/commit"
```

---

## Task 4: Commit-time encryption under protected prefixes + scanner bypass

**Files:** Create `crates/repo/src/protect.rs`; modify `crates/repo/src/repo.rs`, `crates/repo/src/lib.rs`.

**Interfaces:**
- Consumes: `scl_crypto::{encrypt_path, wrap_dek_for, PublicKey}`; `scl_core::{PROTECTED, Protection, ProtectPrefix, WrappedKey, Object, FileMode}`.
- Produces: `protect::is_protected(prefixes, path) -> Option<&ProtectPrefix>`; a commit path that, for protected files, stores a `PROTECTED` ciphertext blob + populates `policy.wrapped`; `scan_files` skips protected paths.

- [ ] **Step 1: Prefix matching helper + tests**

Create `crates/repo/src/protect.rs`:

```rust
//! Encrypted-path policy helpers.

use scl_core::{ProtectPrefix, Protection};

/// The protecting prefix rule for `path`, if any (longest-prefix wins).
pub fn matching_prefix<'a>(protection: &'a Protection, path: &str) -> Option<&'a ProtectPrefix> {
    protection
        .prefixes
        .iter()
        .filter(|p| path == p.prefix.trim_end_matches('/') || path.starts_with(&p.prefix))
        .max_by_key(|p| p.prefix.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prot(prefixes: &[&str]) -> Protection {
        Protection {
            prefixes: prefixes.iter().map(|p| ProtectPrefix { prefix: p.to_string(), recipients: vec![] }).collect(),
            wrapped: Default::default(),
        }
    }

    #[test]
    fn matches_under_prefix_longest_wins() {
        let p = prot(&["secrets/", "secrets/prod/"]);
        assert_eq!(matching_prefix(&p, "secrets/prod/db").unwrap().prefix, "secrets/prod/");
        assert_eq!(matching_prefix(&p, "secrets/x").unwrap().prefix, "secrets/");
        assert!(matching_prefix(&p, "src/main.rs").is_none());
    }
}
```

Declare `pub mod protect;` in `crates/repo/src/lib.rs`.

- [ ] **Step 2: Encrypt protected files in `commit`**

In `crates/repo/src/repo.rs` `commit`: the current flow reads the working tree (`read_worktree`), runs `scan_files`, then `write_tree`. Change it so protected files are encrypted and excluded from the scanner. Concretely, compute the carried-forward protection (start from the tip's), then partition working files:

```rust
        let files = worktree::read_worktree(&self.layout)?;
        let tip = self.head_tip()?;
        let mut protection = match tip {
            Some(t) => self.snapshot(&t)?.protection,
            None => scl_core::Protection::default(),
        };
        // NOTE: `self.snapshot(&id) -> Result<Snapshot>` is a small pub(crate)
        // helper (lock store, `get_snapshot`); add it here if not already present
        // (it's reused by Task 5/6).

        // Split protected vs plaintext by the carried prefix rules.
        let (protected, plain): (Vec<_>, Vec<_>) = files
            .into_iter()
            .partition(|(path, _, _)| crate::protect::matching_prefix(&protection, path).is_some());

        // Scan only the plaintext files (protected files are encrypted on purpose).
        let report = self.scan_files(&plain)?;
        if !report.is_empty() {
            return Err(Error::SecretDetected(report));
        }

        // Encrypt protected files; collect their tree entries + fresh wrapped DEKs.
        let mut all: Vec<(String, Vec<u8>, FileMode, u8)> = plain
            .into_iter()
            .map(|(p, b, m)| (p, b, m, 0u8))
            .collect();
        let mut fresh_wrapped: std::collections::BTreeMap<ObjectId, Vec<scl_core::WrappedKey>> = Default::default();
        for (path, bytes, mode) in protected {
            let rule = crate::protect::matching_prefix(&protection, &path).expect("partitioned protected");
            let (blob_bytes, dek) = scl_crypto::encrypt_path(&bytes);
            let blob_id = scl_core::Object::blob(blob_bytes.clone()).id();
            let wks: Vec<scl_core::WrappedKey> = rule
                .recipients
                .iter()
                .map(|pk| scl_crypto::wrap_dek_for(&dek, &scl_crypto::PublicKey::from_bytes(*pk)))
                .collect();
            fresh_wrapped.insert(blob_id, wks);
            all.push((path, blob_bytes, mode, scl_core::PROTECTED));
        }

        // Build the tree with per-entry perms (PROTECTED on encrypted blobs).
        let root = self.vfs.write_tree_with_perms(&all)?;

        // Rebuild policy.wrapped: keep only ids in this commit; prefer fresh wraps,
        // else carry forward existing wraps for unchanged protected blobs.
        let mut new_wrapped = std::collections::BTreeMap::new();
        for (id, wks) in fresh_wrapped {
            new_wrapped.insert(id, wks);
        }
        // (unchanged protected files re-encrypt to the same id via convergence, so
        // fresh_wrapped already covers them; carry nothing stale.)
        protection.wrapped = new_wrapped;

        // ... existing merge_head / secrets / parents handling, then:
        self.commit_snapshot(root, parents, secrets, protection, author, message)
```

This requires a `vfs` helper that builds a tree from `(path, bytes, mode, perms)` tuples. Add to `crates/vfs/src/lib.rs`:

```rust
    /// Like `write_tree`, but each file carries an explicit `perms` byte (e.g.
    /// `scl_core::PROTECTED` for encrypted blobs).
    pub fn write_tree_with_perms(&self, files: &[(String, Vec<u8>, FileMode, u8)]) -> Result<ObjectId> {
        let mut map: BTreeMap<String, (ObjectId, FileMode, u8)> = BTreeMap::new();
        {
            let mut store = self.store.lock().unwrap();
            for (path, bytes, mode, perms) in files {
                let id = store.put(Object::blob(bytes.clone()))?;
                map.insert(normalize(path), (id, *mode, *perms));
            }
        }
        self.build_tree_perms(&map)
    }
```

…where `build_tree_perms` mirrors the existing `build_tree`/`build_subtree` but threads the `perms` byte into each `TreeEntry` (the existing builder sets `perms: 0`; add a parallel path or extend the existing builder to take perms — simplest: generalize `build_subtree` to read perms from the map, defaulting subtree entries to 0). Keep `write_tree` working (it can delegate with `perms = 0`).

- [ ] **Step 3: Update `commit_snapshot` signature**

`commit_snapshot` now takes `protection: Protection` (from Task 3 Step 2). Confirm `commit` passes the computed `protection`; secret ops / merge finalize pass the tip's protection unchanged.

- [ ] **Step 4: Tests**

Add to `repo.rs` tests (helper: protect via direct policy injection or via the `protect` method from Task 6 — for this task, set the policy by committing through a small helper that writes a `ProtectPrefix`). Minimal approach: test the commit path by pre-seeding a prefix rule into the tip's protection. Simplest is to defer the full e2e to Task 6 and here test the encryption mechanics:

```rust
    #[test]
    fn commit_encrypts_files_under_a_protected_prefix() {
        let root = tmp_root("p7-commit");
        let repo = Repo::init(&root).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        // Seed a protected prefix by committing a policy directly (test seam):
        repo.test_set_protected_prefix("secret/", &[pk]).unwrap(); // see Task 6 for the real `protect`
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let cid = repo.commit("me", "add secret").unwrap();
        // The committed blob under secret/ is ciphertext, and policy has a wrapped DEK.
        let snap = { let a = repo.vfs_handle().store(); let mut s = a.lock().unwrap(); s.get_snapshot(&cid).unwrap() };
        assert_eq!(snap.protection.wrapped.len(), 1);
        // The stored blob bytes are not the plaintext.
        let entry_id = *snap.protection.wrapped.keys().next().unwrap();
        let blob = { let a = repo.vfs_handle().store(); let mut s = a.lock().unwrap(); s.get(&entry_id).unwrap() };
        if let scl_core::Object::Blob(b) = blob { assert_ne!(&b[..], b"hunter2"); } else { panic!() }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
```

> Provide a small `pub(crate)` test seam `test_set_protected_prefix` OR build Task 6's `protect` first and use it. Implementer's choice: if `protect` (Task 6) is simple enough, write it now and use it here instead of a seam. Either way the assertion (protected file stored as ciphertext + policy populated) is the contract.

- [ ] **Step 5: Run + commit**

Run: `cargo test -p scl-repo && cargo clippy -p scl-repo`
Expected: green + clean.

```bash
git add crates/repo/src/protect.rs crates/repo/src/repo.rs crates/repo/src/lib.rs crates/vfs/src/lib.rs
git commit -m "feat(repo): encrypt protected paths on commit (scanner-exempt)"
```

---

## Task 5: Checkout decryption (skip unauthorized)

**Files:** Modify `crates/repo/src/worktree.rs`, `crates/repo/src/repo.rs`.

**Interfaces:**
- Consumes: `scl_crypto::{decrypt_path, unwrap_dek_with, SecretKey}`; `scl_core::{PROTECTED, Protection}`; the snapshot's `protection`.
- Produces: `worktree::materialize(layout, store, target_root, old_root, protection, identity: Option<&SecretKey>) -> Result<Vec<String>>` (returns skipped protected paths); `Repo::checkout/switch` pass the resolved identity and report skips.

- [ ] **Step 1: Decrypt PROTECTED entries in `materialize`**

`materialize` currently writes each target blob's bytes to disk. Change its signature to also take the snapshot `protection` and an optional `identity`, and for an entry whose `perms & PROTECTED != 0`:
- find `protection.wrapped[blob_id]`; for the identity, `unwrap_dek_with` the matching `WrappedKey`; on success `decrypt_path(blob_bytes, &dek)` and write the plaintext.
- if there's no identity, or no wrapped key unwraps → **skip** the file (don't write), and push its path to a `skipped: Vec<String>` returned to the caller.

`tree_file_entries` already returns `(ObjectId, FileMode)` per path — extend it (or add a sibling) to also return the `perms` byte so `materialize` knows which entries are protected. (The `TreeEntry` has `perms`; thread it through the walk.)

- [ ] **Step 2: Thread identity through `checkout`/`switch`**

`Repo::switch` and any checkout entry point gain an optional identity (resolved by the CLI). Pass it + the target snapshot's `protection` to `materialize`; surface the returned skipped list to the caller.

- [ ] **Step 3: Tests**

```rust
    #[test]
    fn authorized_checkout_decrypts_unauthorized_skips() {
        let root = tmp_root("p7-checkout");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap(); // Task 6
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        repo.branch("other").unwrap();
        // Switch away (clears worktree) then back as alice → decrypts.
        repo.switch_with_identity("other", Some(&alice_sk)).unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        assert_eq!(std::fs::read(root.join("secret/db.txt")).unwrap(), b"hunter2");
        // As mallory → skipped (file absent).
        repo.switch_with_identity("other", Some(&mallory_sk)).unwrap();
        let skipped = repo.switch_with_identity("main", Some(&mallory_sk)).unwrap();
        assert!(skipped.contains(&"secret/db.txt".to_string()));
        assert!(!root.join("secret/db.txt").exists());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
```

> `switch_with_identity(name, Option<&SecretKey>) -> Result<Vec<String>>` returns the skipped list; keep the existing `switch(name)` as `switch_with_identity(name, resolved_default_identity)` or a thin wrapper. Implementer picks the exact shape; the contract is: authorized decrypts, unauthorized skips and is reported.

- [ ] **Step 4: Run + commit**

Run: `cargo test -p scl-repo && cargo clippy -p scl-repo`

```bash
git add crates/repo/src/worktree.rs crates/repo/src/repo.rs
git commit -m "feat(repo): decrypt protected files on checkout; skip unauthorized"
```

---

## Task 6: `protect` / `grant` / `revoke`

**Files:** Modify `crates/repo/src/repo.rs`, `crates/repo/src/error.rs`.

**Interfaces:**
- Consumes: `scl_crypto::{encrypt_path, wrap_dek_for, unwrap_dek_with, PublicKey, SecretKey, RecipientId}`; `protect::matching_prefix`.
- Produces: `Repo::{protect(prefix, &[PublicKey], identity: Option<&SecretKey>), grant(prefix, authorized: &SecretKey, new: &PublicKey), revoke(prefix, &RecipientId), protected_prefixes() -> Vec<(String, Vec<RecipientId>)>}`; `Error::{NotProtected(String), NotAuthorized(String)}`.

- [ ] **Step 1: Error variants**

In `crates/repo/src/error.rs` add `NotProtected(String)` and `NotAuthorized(String)`.

- [ ] **Step 2: `protect`**

`protect(prefix, recipients, identity)`: load the tip's protection; add/replace the `ProtectPrefix { prefix, recipients: recipients.iter().map(|p| p.to_bytes()).collect() }`; then run a normal `commit` (which now encrypts matching working-tree files under the new rule). If the working tree has no matching files yet, the rule is still recorded for future commits. Returns the new snapshot id.

- [ ] **Step 3: `grant` (policy-only)**

`grant(prefix, authorized, new)`: load the tip's protection; for each `(blob_id, wks)` in `protection.wrapped` whose blob is referenced by a tree path under `prefix` (walk the tip tree, collect PROTECTED entry ids under the prefix), recover the DEK via `unwrap_dek_with(wks_entry, authorized)` (the authorized key must currently be a recipient → else `NotAuthorized`), `wrap_dek_for(&dek, new)`, append to that blob's `wks` (dedup by recipient_id); add `new.to_bytes()` to the prefix's recipients. Commit a snapshot with the SAME root tree (no file changes) and the updated policy. Assert in a test that no blob/tree id changed.

- [ ] **Step 4: `revoke`**

`revoke(prefix, recipient_id)`: drop that `recipient_id` from every `wks` under the prefix and from the prefix's recipients; commit same-tree + updated policy.

- [ ] **Step 5: `protected_prefixes` + tests**

`protected_prefixes()` returns `(prefix, [recipient_id])` for display. Tests:

```rust
    #[test]
    fn grant_adds_recipient_without_changing_file_objects() {
        let root = tmp_root("p7-grant");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let root1 = repo.snapshot(&c1).unwrap().root;
        let c2 = repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        let snap2 = repo.snapshot(&c2).unwrap();
        assert_eq!(snap2.root, root1, "grant must not change the file tree");
        // bob now has a wrapped DEK for the protected blob.
        let any = snap2.protection.wrapped.values().next().unwrap();
        assert_eq!(any.len(), 2, "alice + bob");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
```

(`snapshot(&id)` is a small `pub(crate)` helper returning the decoded `Snapshot`; add it if not present.)

- [ ] **Step 6: Run + commit**

Run: `cargo test -p scl-repo && cargo clippy -p scl-repo`

```bash
git add crates/repo/src/repo.rs crates/repo/src/error.rs
git commit -m "feat(repo): protect / grant / revoke encrypted-path policy ops"
```

---

## Task 7: CLI + ADR + headline demo

**Files:** Modify `crates/cli/src/main.rs`; create `demo/run_protect_demo.sh`; modify `docs/adr/0014-*.md`, `docs/adr/README.md`.

**Interfaces:**
- Consumes: `Repo::{protect, grant, revoke, protected_prefixes, switch_with_identity}`; the Phase-2 `resolve_identity_path`/`load_recipients`/`FileKeyProvider` CLI helpers.

- [ ] **Step 1: Subcommands**

Add to `Cmd`: `Protect { prefix: Option<String>, to: Vec<String> (value_delimiter ','), list: bool }`, `Grant { prefix: String, to: Vec<String>, identity: Option<PathBuf> }`, `Revoke { prefix: String, recipient_id: String }`. Add match arms.

- [ ] **Step 2: Handlers**

```rust
fn run_protect(prefix: Option<String>, to: Vec<String>, list: bool) -> Result<()> {
    let repo = open_repo()?;
    if list || prefix.is_none() {
        for (p, recips) in repo.protected_prefixes()? {
            println!("{p}  ({} recipient(s))", recips.len());
        }
        return Ok(());
    }
    let prefix = prefix.unwrap();
    let dir = load_recipients(&repo.layout().dot_sc.join("recipients.toml"))?;
    let pks = resolve_names(&dir, &to)?;
    let id = repo.protect(&prefix, &pks, None)?;
    println!("protected {prefix} for {} recipient(s): {}", to.len(), id.short());
    Ok(())
}

fn run_grant(prefix: String, to: Vec<String>, identity: Option<PathBuf>) -> Result<()> {
    let repo = open_repo()?;
    let dir = load_recipients(&repo.layout().dot_sc.join("recipients.toml"))?;
    let pks = resolve_names(&dir, &to)?;
    let sk = load_identity(identity)?;
    for pk in &pks { repo.grant(&prefix, &sk, pk)?; }
    println!("granted {prefix} to {} recipient(s)", to.len());
    Ok(())
}

fn run_revoke(prefix: String, recipient_id: String) -> Result<()> {
    let repo = open_repo()?;
    let rid = scl_crypto::RecipientId::from_hex(&recipient_id).map_err(|_| anyhow::anyhow!("bad recipient id"))?;
    repo.revoke(&prefix, &rid)?;
    println!("revoked {recipient_id} from {prefix}");
    Ok(())
}
```

Wire `switch`/`checkout` to resolve the identity (`resolve_identity_path` → `FileKeyProvider`) and print any skipped protected files: after a switch, `for p in skipped { eprintln!("skipped (no key): {p}"); }`.

- [ ] **Step 3: Build, suite, smoke**

`cargo test` (green), `cargo clippy --workspace --all-targets` (clean). Manual: `sc init`, `sc keygen --out id`, add the pubkey to `.sc/recipients.toml` as `alice`, `sc protect secret/ --to alice`, write `secret/x`, `sc commit`, confirm the stored blob is ciphertext; `sc switch` round-trip with `SC_IDENTITY=id` decrypts; without it skips.

- [ ] **Step 4: Headline demo**

Create `demo/run_protect_demo.sh` (self-checking): init A, keygen alice, protect `secret/`, commit a secret file, clone to B (P6), then in B **without** alice's key `sc switch`/checkout → assert `secret/x` is ABSENT from B's working tree but its ciphertext blob IS in `B/.sc/objects`; with alice's key it decrypts. `chmod +x`; run it; expect the success line.

- [ ] **Step 5: Firm ADR-0014**

`docs/adr/0014-*.md`: Status Proposed → Accepted; append an "As built (P7)" note (split envelope = PROTECTED blob + policy-side wrapped DEKs; `encrypt_path`/`decrypt_path`; persisted prefix rules + commit auto-encryption + scanner bypass; pubkeys-in-policy; skip-on-unauthorized checkout; policy-only grant/revoke). Mark 0014 Accepted in `docs/adr/README.md`.

- [ ] **Step 6: Commit**

```bash
git add crates/cli/src/main.rs demo/run_protect_demo.sh docs/adr/0014-per-file-permissions-encrypted-paths.md docs/adr/README.md
git commit -m "feat(cli): sc protect/grant/revoke + encrypted-path checkout; accept ADR-0014"
```

---

## Done criteria

- `cargo test` green; `cargo clippy --workspace --all-targets` clean.
- A file under a protected prefix commits as a `PROTECTED` ciphertext blob (`nonce‖ciphertext`); identical plaintext → identical blob id (convergent dedup).
- Authorized checkout decrypts protected files; unauthorized checkout **skips** them (absent from the working tree, reported), never writing ciphertext or plaintext for non-recipients.
- `grant` adds a recipient with **no change to any blob/tree id** (policy-only); `revoke` removes access.
- The P5 scanner does not reject a secret-looking file under a protected prefix.
- Headline: a clone held by a non-recipient has the protected file as ciphertext in `.sc/objects` but absent from the checkout; the recipient decrypts it. `demo/run_protect_demo.sh` passes.
- Phase 1–6 flows still pass; ADR-0014 Accepted.
```
