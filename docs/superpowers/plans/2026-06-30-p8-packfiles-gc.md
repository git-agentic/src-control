# P8 — Packfiles, GC, loose-object refinements + bulk-pack transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give persistent (`.sc/`) repos bounded object-store growth and space reclamation via a packfile format, an `sc gc` command, sharded + zstd-compressed loose storage, and bulk-pack transfer over the P6 `Transport`.

**Architecture:** `core` owns all on-disk object resolution: the pack format (a pure `pack` module), a pack-aware `Store` read path, sharded+zstd loose objects with read-both back-compat, and new `Store` methods (`delete`, `list_loose`, `loose_mtime`, `write_pack`). `repo` owns `gc` orchestration (gather a full safe root set → existing `reachable_objects` walk → repack → prune) plus the bulk-pack `Transport` methods. `cli` adds `sc gc` and rewires push/fetch/clone to move packs.

**Tech Stack:** Rust 2021, `blake3` (content addressing — unchanged), `zstd` (new — object payload compression), `thiserror` (per-crate errors), `clap` (CLI). Tests are `#[cfg(test)] mod tests` next to the code.

## Global Constraints

- **Edition 2021**, inherited via `[workspace.package]`. Pin deps to latest stable with `cargo add` — never hand-edit version guesses. **Stage `Cargo.lock` in the same commit as any dep change.**
- **Dependency rule (strict):** `cli → repo → {vfs, gitio, crypto} → core`. `core` must never depend on git/worktrees/crypto. **`zstd` goes in `core` only** (core may take ordinary deps; the quarantine bars only `gix`/RustCrypto from leaking out of `gitio`/`crypto`). `repo` must not depend on `gitio`.
- **Content-addressing invariant is unchanged:** an object's id is `BLAKE3(canonical encode())`. Packing and zstd are storage-layout only — every disk read decompresses to the canonical bytes and BLAKE3-verifies them against the id before decoding. A mismatch is an error, never a silent skip.
- **Mode-scoped disk invariant:** GC and packs are **persistent-only**. Ephemeral mode (`Backend::Ephemeral`) keeps its existing flat+raw spill behavior untouched, removed on `Drop` (zero residue). Do not add packing/sharding/zstd to the spill path.
- **Single-writer lock:** `gc` runs under `RepoLock::acquire(&layout)` and refuses to run without it. Deletions happen only after the new pack is durably written + verified.
- Every public type/fn gets a doc comment explaining intent. Every new behavior ships with a test that cleans up any disk it touches.

---

## File map

**core (new):**
- `crates/core/src/pack.rs` — pure pack/idx encode + decode + per-record verify (Task 2).

**core (modified):**
- `crates/core/src/error.rs` — add `PackCorrupt`, `BadPackIndex` (Task 2).
- `crates/core/src/lib.rs` — `pub mod pack;` + re-exports (Tasks 1–3).
- `crates/core/src/store.rs` — sharded+zstd loose layout, `delete`/`list_loose`/`loose_mtime` (Task 1); pack index + pack-aware read + `write_pack`/`delete_pack`/`pack_hashes`/`reload_packs` (Task 3).
- `crates/core/Cargo.toml` — add `zstd` (Task 1).

**repo (new):**
- `crates/repo/src/gc.rs` — root-set gathering + the gc algorithm + `GcStats` (Task 5).

**repo (modified):**
- `crates/repo/src/refs.rs` — `list_heads`, `list_remote_tips` (Task 4).
- `crates/repo/src/lib.rs` — `pub mod gc;` + re-export `GcStats` (Task 5).
- `crates/repo/src/transport.rs` — pack/shard-aware reads; `get_pack`/`put_pack` (Tasks 6–7).
- `crates/repo/src/repo.rs` — `Repo::gc` (Task 5); rewire `push`/`fetch`/`clone_to`/`transfer_objects` to bulk pack (Task 8).

**cli (modified):**
- `crates/cli/src/main.rs` — `Cmd::Gc` + `run_gc` + duration parse (Task 9).

**demo (modified):**
- `demo/run_repo_demo.sh` — show gc reclaiming space (Task 10).

---

## Task 1: Sharded + zstd loose objects (with read-both back-compat)

Move persistent loose objects to `objects/<aa>/<rest-of-hex>`, store `zstd(encode())` as the file payload, and add the loose-object operations GC needs. The read path resolves sharded **or** legacy flat files, and decompresses **or** falls back to raw bytes (legacy uncompressed). Ephemeral spill is untouched.

**Files:**
- Modify: `crates/core/Cargo.toml`
- Modify: `crates/core/src/store.rs`
- Test: `crates/core/src/store.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: existing `Store`, `Backend::Persistent(PathBuf)`, `Object::{encode,decode,blob_size,id}`, `ObjectId::{to_hex,from_str}`.
- Produces (used by Tasks 3/5/6):
  - `Store::loose_path(&self, id: &ObjectId) -> Option<PathBuf>` (private helper; sharded path under the persistent dir)
  - `Store::delete(&mut self, id: &ObjectId) -> Result<()>` — remove a loose file (sharded or flat); no-op if absent; never touches packs.
  - `Store::list_loose(&self) -> Result<Vec<ObjectId>>` — every loose object id (sharded + legacy flat).
  - `Store::loose_mtime(&self, id: &ObjectId) -> Result<Option<std::time::SystemTime>>`.

- [ ] **Step 1: Add the zstd dependency**

Run:
```bash
cd crates/core && cargo add zstd && cd ../..
```
Expected: `Cargo.toml` gains `zstd = "<latest>"`; `Cargo.lock` updated.

- [ ] **Step 2: Write the failing test for sharded write + read**

Add to `crates/core/src/store.rs` tests (reuse the existing `temp_objects_dir` helper there):

```rust
#[test]
fn persistent_writes_sharded_compressed_and_reads_back() {
    let dir = temp_objects_dir("shard");
    let _ = std::fs::remove_dir_all(&dir);
    let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
    let id = s.put(Object::blob(b"hello sharded world".to_vec())).unwrap();
    // File lives at objects/<aa>/<rest>, NOT objects/<hex>.
    let hex = id.to_hex();
    let sharded = dir.join(&hex[..2]).join(&hex[2..]);
    assert!(sharded.exists(), "expected sharded path {sharded:?}");
    assert!(!dir.join(&hex).exists(), "must not write flat path");
    // Payload is compressed, not the raw canonical bytes.
    let on_disk = std::fs::read(&sharded).unwrap();
    assert_ne!(on_disk, Object::blob(b"hello sharded world".to_vec()).encode());
    // Reopen (empty RAM cache) and read back through decompress+verify.
    let mut s2 = Store::open_persistent(&dir, 1 << 20).unwrap();
    assert_eq!(s2.get(&id).unwrap().encode(), Object::blob(b"hello sharded world".to_vec()).encode());
    drop((s, s2));
    std::fs::remove_dir_all(&dir).unwrap();
}
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `cargo test -p scl-core persistent_writes_sharded_compressed_and_reads_back`
Expected: FAIL (object written to flat `objects/<hex>`, uncompressed).

- [ ] **Step 4: Implement sharded+zstd write/read + the loose helpers**

In `crates/core/src/store.rs`:

Add near the top (after the `use` block):
```rust
/// zstd level for on-disk object payloads. 3 is the zstd default: fast, solid
/// ratio. The level is a storage detail — it never affects the content address,
/// which is BLAKE3 of the *decompressed* canonical bytes.
const COMPRESSION_LEVEL: i32 = 3;
```

Add these methods inside `impl Store` (near the other persistent helpers):
```rust
/// The sharded loose path `objects/<aa>/<rest>` for `id`, or `None` in
/// ephemeral mode (which has no persistent objects dir).
fn loose_path(&self, id: &ObjectId) -> Option<PathBuf> {
    let dir = self.persistent_dir()?;
    let hex = id.to_hex();
    Some(dir.join(&hex[..2]).join(&hex[2..]))
}

/// The legacy flat path `objects/<hex>` (pre-P8 repos), or `None` in ephemeral.
fn flat_path(&self, id: &ObjectId) -> Option<PathBuf> {
    Some(self.persistent_dir()?.join(id.to_hex()))
}

/// The on-disk loose file for `id` if one exists (sharded preferred, then the
/// legacy flat location), or `None`.
fn existing_loose_path(&self, id: &ObjectId) -> Option<PathBuf> {
    if let Some(p) = self.loose_path(id) {
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(p) = self.flat_path(id) {
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Remove a loose object file (sharded or legacy flat) **and** drop any RAM /
/// spill-map copy, so the object is truly gone unless a pack still holds it (in
/// which case `get` rehydrates from the pack on demand). Without the RAM drop,
/// `contains`/`get` would keep serving a pruned object from cache within a
/// process. Absent on disk is success. Never removes packed objects — pack
/// removal is `delete_pack`'s job.
pub fn delete(&mut self, id: &ObjectId) -> Result<()> {
    if let Some(p) = self.existing_loose_path(id) {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    if let Some(r) = self.resident.remove(id) {
        self.resident_blob_bytes -= r.blob_size;
    }
    self.spilled.remove(id);
    Ok(())
}

/// mtime of `id`'s loose file (sharded or flat), or `None` if not loose.
pub fn loose_mtime(&self, id: &ObjectId) -> Result<Option<std::time::SystemTime>> {
    match self.existing_loose_path(id) {
        Some(p) => Ok(Some(std::fs::metadata(&p)?.modified()?)),
        None => Ok(None),
    }
}

/// Every loose object id under the persistent objects dir: sharded
/// `<aa>/<rest>` plus legacy flat `<hex>`. Skips `pack/`, tmp files, and any
/// name that isn't a 64-char hex id. Empty in ephemeral mode.
pub fn list_loose(&self) -> Result<Vec<ObjectId>> {
    let mut out = Vec::new();
    let Some(dir) = self.persistent_dir() else { return Ok(out) };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::Io(e)),
    };
    for e in entries {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let ft = e.file_type()?;
        if ft.is_dir() {
            // A 2-hex shard directory; its children are the id's remaining hex.
            if name.len() != 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue; // e.g. "pack"
            }
            for c in std::fs::read_dir(e.path())? {
                let c = c?;
                let rest = c.file_name().to_string_lossy().into_owned();
                if let Ok(id) = format!("{name}{rest}").parse::<ObjectId>() {
                    out.push(id);
                }
            }
        } else if let Ok(id) = name.parse::<ObjectId>() {
            out.push(id); // legacy flat file
        }
    }
    Ok(out)
}
```

Replace `write_object_file` so it shards + compresses:
```rust
/// Write `zstd(encode())` to the sharded `objects/<aa>/<rest>` idempotently
/// (tmp + rename). Creates the shard directory.
fn write_object_file(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
    let path = self.loose_path(id).expect("persistent backend");
    if path.exists() {
        return Ok(());
    }
    let shard = path.parent().expect("sharded path has a parent");
    std::fs::create_dir_all(shard)?;
    let compressed = zstd::encode_all(std::io::Cursor::new(bytes), COMPRESSION_LEVEL)
        .map_err(Error::Io)?;
    // Per-process tmp name so a concurrent writer can't clobber our staging file.
    let tmp = shard.join(format!("{}.{}.tmp", id.to_hex(), std::process::id()));
    std::fs::write(&tmp, &compressed)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}
```

Replace `read_object_file` so it resolves sharded-or-flat and decompresses-or-raw:
```rust
/// Read + verify + decode a loose object. Tries the sharded path then the
/// legacy flat path; tries zstd-decompress then falls back to treating the
/// bytes as a raw (pre-P8 uncompressed) canonical encoding. Either way the
/// final canonical bytes are BLAKE3-verified against `id`.
fn read_object_file(&self, id: &ObjectId) -> Result<Object> {
    let path = self.existing_loose_path(id).ok_or(Error::NotFound(*id))?;
    let raw = std::fs::read(&path)?;
    let canonical = match zstd::decode_all(std::io::Cursor::new(&raw)) {
        Ok(d) => d,
        Err(_) => raw, // legacy uncompressed loose file
    };
    if ObjectId::of(&canonical) != *id {
        return Err(Error::Malformed(format!("object {id} failed hash verification on read")));
    }
    Object::decode(&canonical)
}
```

Update the idempotence checks in `put`, `get`, and `contains` that currently test `dir.join(id.to_hex()).exists()` to use the sharded-or-flat resolution. Concretely:

In `put`, replace:
```rust
        if let Some(dir) = self.persistent_dir() {
            if dir.join(id.to_hex()).exists() {
                return Ok(id);
            }
        }
```
with:
```rust
        if self.persistent_dir().is_some() && self.existing_loose_path(&id).is_some() {
            // Already durable on disk (e.g. evicted from RAM); don't re-admit.
            return Ok(id);
        }
```

In `contains`, replace:
```rust
        if let Some(dir) = self.persistent_dir() {
            return dir.join(id.to_hex()).exists();
        }
        false
```
with:
```rust
        self.existing_loose_path(id).is_some()
```

- [ ] **Step 5: Run the new test + the full core suite**

Run: `cargo test -p scl-core`
Expected: PASS — including the existing `persistent_*` tests (they reopen and read back, which now goes through the sharded/compressed path) and the new sharded test.

- [ ] **Step 6: Write + run the legacy-flat back-compat test**

```rust
#[test]
fn reads_legacy_flat_uncompressed_object() {
    let dir = temp_objects_dir("legacy");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Simulate a pre-P8 repo: raw canonical bytes at flat objects/<hex>.
    let obj = Object::blob(b"legacy".to_vec());
    let id = obj.id();
    std::fs::write(dir.join(id.to_hex()), obj.encode()).unwrap();
    let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
    assert!(s.contains(&id));
    assert_eq!(s.get(&id).unwrap().encode(), obj.encode());
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}
```
Run: `cargo test -p scl-core reads_legacy_flat_uncompressed_object`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/core/Cargo.toml Cargo.lock crates/core/src/store.rs
git commit -m "feat(core): sharded + zstd loose objects with legacy-flat read-back"
```

---

## Task 2: Packfile format module (`pack.rs`)

A pure module: encode many objects into a self-delimiting `.pack` body + a sorted `.idx`, and decode/verify both. No filesystem, no `Store` coupling.

**Files:**
- Create: `crates/core/src/pack.rs`
- Modify: `crates/core/src/error.rs`
- Modify: `crates/core/src/lib.rs`
- Test: `crates/core/src/pack.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `Object::{encode,decode}`, `ObjectId::{of,as_bytes,from_bytes}`, `Error`.
- Produces (used by Tasks 3/7):
  - `pack::build_pack(objects: &[(ObjectId, Vec<u8>)]) -> Result<(Vec<u8>, Vec<u8>)>` returning `(pack_bytes, idx_bytes)`.
  - `pack::parse_index(idx: &[u8]) -> Result<Vec<pack::IndexEntry>>` with `IndexEntry { id: ObjectId, offset: u64, length: u64 }`.
  - `pack::read_object_at(pack: &[u8], offset: u64, id: &ObjectId) -> Result<Object>`.
  - `pack::parse_pack(pack: &[u8]) -> Result<Vec<(ObjectId, Object)>>`.

- [ ] **Step 1: Add the new error variants**

In `crates/core/src/error.rs`, add to `enum Error` (before the `Io` arm):
```rust
    #[error("corrupt packfile: {0}")]
    PackCorrupt(String),

    #[error("bad pack index: {0}")]
    BadPackIndex(String),
```

- [ ] **Step 2: Write the failing roundtrip + corruption tests**

Create `crates/core/src/pack.rs` with only the tests first (module body added in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Object;

    fn enc(o: &Object) -> (crate::id::ObjectId, Vec<u8>) {
        (o.id(), o.encode())
    }

    #[test]
    fn build_then_read_each_object_back() {
        let a = Object::blob(b"alpha".to_vec());
        let b = Object::blob(b"bravo bravo".to_vec());
        let objs = vec![enc(&a), enc(&b)];
        let (pack, idx) = build_pack(&objs).unwrap();
        let entries = parse_index(&idx).unwrap();
        assert_eq!(entries.len(), 2);
        // Index is sorted by id; binary-searchable.
        assert!(entries.windows(2).all(|w| w[0].id < w[1].id));
        for (id, want) in [enc(&a), enc(&b)] {
            let e = entries.iter().find(|e| e.id == id).unwrap();
            let got = read_object_at(&pack, e.offset, &id).unwrap();
            assert_eq!(got.encode(), want);
        }
        // parse_pack recovers every object standalone (no idx).
        let all = parse_pack(&pack).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn flipped_pack_byte_fails_verification() {
        let a = Object::blob(b"alpha".to_vec());
        let (mut pack, idx) = build_pack(&[enc(&a)]).unwrap();
        let last = pack.len() - 1;
        pack[last] ^= 0xFF; // corrupt the compressed payload
        let e = parse_index(&idx).unwrap().pop().unwrap();
        let err = read_object_at(&pack, e.offset, &e.id).unwrap_err();
        assert!(matches!(err, crate::error::Error::Malformed(_) | crate::error::Error::PackCorrupt(_)), "got {err:?}");
    }

    #[test]
    fn bad_index_magic_rejected() {
        let err = parse_index(b"XXXXnot an index").unwrap_err();
        assert!(matches!(err, crate::error::Error::BadPackIndex(_)), "got {err:?}");
    }
}
```

- [ ] **Step 3: Run to confirm failure**

Run: `cargo test -p scl-core pack::`
Expected: FAIL to compile (module body missing).

- [ ] **Step 4: Implement the module body**

Put this above the `#[cfg(test)]` block in `crates/core/src/pack.rs`:

```rust
//! Packfile format: many objects' canonical encodings concatenated into one
//! self-delimiting `.pack` body, plus a sorted `.idx` mapping `ObjectId` to a
//! record offset for O(log n) random access.
//!
//! A `.pack` record is `u32_le(compressed_len) ++ zstd(canonical encode())`.
//! Because each record carries its own length, a `.pack` is parseable without
//! its index (used on transfer); the `.idx` is a read accelerator only.
//!
//! Nothing here touches the filesystem or the `Store`. Packing is a storage
//! layout change: every object read out of a pack is decompressed and
//! BLAKE3-verified against its id before decoding, so the content-addressing
//! invariant holds exactly as for loose objects.

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::Object;

const PACK_MAGIC: &[u8; 4] = b"SCPK";
const IDX_MAGIC: &[u8; 4] = b"SCIX";
const FORMAT_VERSION: u32 = 1;
/// zstd level for packed payloads (matches the loose-object level).
const COMPRESSION_LEVEL: i32 = 3;

/// One `.idx` row: an object id and where its record begins in the `.pack`.
#[derive(Clone, Copy, Debug)]
pub struct IndexEntry {
    pub id: ObjectId,
    /// Byte offset of the record's `u32` length prefix within the `.pack`.
    pub offset: u64,
    /// Length of the compressed payload (excludes the 4-byte length prefix).
    pub length: u64,
}

/// Build `(pack_bytes, idx_bytes)` from `(id, canonical encode())` pairs. The
/// index is sorted by id for binary search; the pack preserves input order.
pub fn build_pack(objects: &[(ObjectId, Vec<u8>)]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pack = Vec::new();
    pack.extend_from_slice(PACK_MAGIC);
    pack.extend_from_slice(&FORMAT_VERSION.to_le_bytes());

    let mut entries: Vec<IndexEntry> = Vec::with_capacity(objects.len());
    for (id, canonical) in objects {
        let compressed = zstd::encode_all(std::io::Cursor::new(canonical), COMPRESSION_LEVEL)
            .map_err(Error::Io)?;
        let offset = pack.len() as u64;
        pack.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        pack.extend_from_slice(&compressed);
        entries.push(IndexEntry { id: *id, offset, length: compressed.len() as u64 });
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));

    let mut idx = Vec::new();
    idx.extend_from_slice(IDX_MAGIC);
    idx.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    idx.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for e in &entries {
        idx.extend_from_slice(e.id.as_bytes());
        idx.extend_from_slice(&e.offset.to_le_bytes());
        idx.extend_from_slice(&e.length.to_le_bytes());
    }
    Ok((pack, idx))
}

/// Parse a `.idx` into ascending-by-id entries. Rejects a bad magic/version,
/// truncation, or a non-ascending order (which would break binary search).
pub fn parse_index(idx: &[u8]) -> Result<Vec<IndexEntry>> {
    if idx.len() < 16 || &idx[..4] != IDX_MAGIC {
        return Err(Error::BadPackIndex("missing magic".into()));
    }
    let ver = u32::from_le_bytes(idx[4..8].try_into().unwrap());
    if ver != FORMAT_VERSION {
        return Err(Error::BadPackIndex(format!("unsupported version {ver}")));
    }
    let count = u64::from_le_bytes(idx[8..16].try_into().unwrap()) as usize;
    const ROW: usize = 32 + 8 + 8;
    if idx.len() != 16 + count * ROW {
        return Err(Error::BadPackIndex("length does not match count".into()));
    }
    let mut out = Vec::with_capacity(count);
    let mut prev: Option<ObjectId> = None;
    for i in 0..count {
        let base = 16 + i * ROW;
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&idx[base..base + 32]);
        let id = ObjectId::from_bytes(id_bytes);
        if let Some(p) = prev {
            if !(p < id) {
                return Err(Error::BadPackIndex("entries not strictly ascending".into()));
            }
        }
        prev = Some(id);
        let offset = u64::from_le_bytes(idx[base + 32..base + 40].try_into().unwrap());
        let length = u64::from_le_bytes(idx[base + 40..base + 48].try_into().unwrap());
        out.push(IndexEntry { id, offset, length });
    }
    Ok(out)
}

/// Read the record at `offset` from `pack`, decompress, verify it hashes to
/// `id`, and decode it.
pub fn read_object_at(pack: &[u8], offset: u64, id: &ObjectId) -> Result<Object> {
    let off = offset as usize;
    if off + 4 > pack.len() {
        return Err(Error::PackCorrupt(format!("offset {offset} past end")));
    }
    let len = u32::from_le_bytes(pack[off..off + 4].try_into().unwrap()) as usize;
    let start = off + 4;
    let end = start + len;
    if end > pack.len() {
        return Err(Error::PackCorrupt(format!("record at {offset} runs past end")));
    }
    decompress_and_decode(&pack[start..end], id)
}

/// Decompress one record payload, verify against `id`, decode.
fn decompress_and_decode(payload: &[u8], id: &ObjectId) -> Result<Object> {
    let canonical = zstd::decode_all(std::io::Cursor::new(payload))
        .map_err(|e| Error::PackCorrupt(format!("zstd decode failed: {e}")))?;
    if ObjectId::of(&canonical) != *id {
        return Err(Error::Malformed(format!("packed object {id} failed hash verification")));
    }
    Object::decode(&canonical)
}

/// Parse a standalone `.pack` (no index) into `(id, Object)` pairs, verifying
/// every record. Used when receiving a pack over a transport.
pub fn parse_pack(pack: &[u8]) -> Result<Vec<(ObjectId, Object)>> {
    if pack.len() < 8 || &pack[..4] != PACK_MAGIC {
        return Err(Error::PackCorrupt("missing magic".into()));
    }
    let ver = u32::from_le_bytes(pack[4..8].try_into().unwrap());
    if ver != FORMAT_VERSION {
        return Err(Error::PackCorrupt(format!("unsupported version {ver}")));
    }
    let mut out = Vec::new();
    let mut pos = 8usize;
    while pos < pack.len() {
        if pos + 4 > pack.len() {
            return Err(Error::PackCorrupt("truncated record length".into()));
        }
        let len = u32::from_le_bytes(pack[pos..pos + 4].try_into().unwrap()) as usize;
        let start = pos + 4;
        let end = start + len;
        if end > pack.len() {
            return Err(Error::PackCorrupt("record runs past end".into()));
        }
        let canonical = zstd::decode_all(std::io::Cursor::new(&pack[start..end]))
            .map_err(|e| Error::PackCorrupt(format!("zstd decode failed: {e}")))?;
        let id = ObjectId::of(&canonical);
        let obj = Object::decode(&canonical)?;
        out.push((id, obj));
        pos = end;
    }
    Ok(out)
}
```

Add to `crates/core/src/lib.rs`:
```rust
pub mod pack;
```
and extend the `error` re-export note is unnecessary (variants live on `Error`, already re-exported). No new `pub use` needed for `pack` beyond the module.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p scl-core pack::`
Expected: PASS (all three).

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/pack.rs crates/core/src/error.rs crates/core/src/lib.rs
git commit -m "feat(core): packfile format module (build/parse/verify pack + idx)"
```

---

## Task 3: Pack-aware Store (read path, `write_pack`, pack lifecycle)

Teach `Store` about packs: load `objects/pack/*.idx` on open, resolve a `get` miss through the pack index, and add `write_pack` / `delete_pack` / `pack_hashes` / `reload_packs`.

**Files:**
- Modify: `crates/core/src/store.rs`
- Test: `crates/core/src/store.rs` tests

**Interfaces:**
- Consumes: Task 2 `pack::{build_pack, parse_index, read_object_at, IndexEntry}`; Task 1 loose helpers.
- Produces (used by Task 5/6/7):
  - `Store::write_pack(&mut self, ids: &[ObjectId]) -> Result<String>` — read those objects, write `<hash>.pack`/`.idx` under `objects/pack/`, refresh the in-memory index, return the pack hash (hex of `BLAKE3(pack_bytes)`).
  - `Store::pack_hashes(&self) -> Vec<String>` — hashes of currently-loaded packs.
  - `Store::delete_pack(&mut self, hash: &str) -> Result<()>` — remove `<hash>.pack`/`.idx` and drop its index entries.
  - `Store::reload_packs(&mut self) -> Result<()>` — rescan `objects/pack/*.idx`.
  - `Store::is_packed(&self, id: &ObjectId) -> bool`.

- [ ] **Step 1: Write the failing test (pack then read after loose delete)**

```rust
#[test]
fn write_pack_then_read_after_loose_deleted() {
    let dir = temp_objects_dir("pack");
    let _ = std::fs::remove_dir_all(&dir);
    let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
    let a = s.put(Object::blob(b"packed-a".to_vec())).unwrap();
    let b = s.put(Object::blob(b"packed-b".to_vec())).unwrap();
    let hash = s.write_pack(&[a, b]).unwrap();
    assert!(s.pack_hashes().contains(&hash));
    assert!(s.is_packed(&a) && s.is_packed(&b));
    // Delete the loose copies; the object must still be readable from the pack.
    s.delete(&a).unwrap();
    s.delete(&b).unwrap();
    assert!(s.list_loose().unwrap().is_empty());
    // Reopen so RAM cache is cold: read must come from the pack.
    let mut s2 = Store::open_persistent(&dir, 1 << 20).unwrap();
    assert_eq!(s2.get(&a).unwrap().encode(), Object::blob(b"packed-a".to_vec()).encode());
    assert!(s2.contains(&b));
    drop((s, s2));
    std::fs::remove_dir_all(&dir).unwrap();
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-core write_pack_then_read_after_loose_deleted`
Expected: FAIL (no `write_pack`).

- [ ] **Step 3: Add the pack index state + methods**

In `crates/core/src/store.rs`:

Add a field to `struct Store` and a small location type:
```rust
/// Where a packed object lives: which pack file + its record offset.
#[derive(Clone)]
struct PackLoc {
    pack_path: PathBuf,
    offset: u64,
}
```
Add to `struct Store`:
```rust
    /// id -> pack location, union over all loaded packs (persistent only).
    pack_index: HashMap<ObjectId, PackLoc>,
```
Initialize `pack_index: HashMap::new(),` in both `Store::new`'s struct literal.

In `open_persistent`, after constructing the store, scan packs:
```rust
    pub fn open_persistent(objects_dir: impl Into<PathBuf>, budget_bytes: usize) -> Result<Self> {
        let dir = objects_dir.into();
        std::fs::create_dir_all(&dir)?;
        let mut store = Store::new(StoreConfig {
            budget_bytes,
            backend: Backend::Persistent(dir),
        });
        store.reload_packs()?;
        Ok(store)
    }
```

Add the pack methods inside `impl Store`:
```rust
/// `objects/pack` directory, or `None` in ephemeral mode.
fn pack_dir(&self) -> Option<PathBuf> {
    Some(self.persistent_dir()?.join("pack"))
}

/// Rescan `objects/pack/*.idx`, rebuilding the in-memory id->location map.
pub fn reload_packs(&mut self) -> Result<()> {
    self.pack_index.clear();
    let Some(pack_dir) = self.pack_dir() else { return Ok(()) };
    let entries = match std::fs::read_dir(&pack_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::Io(e)),
    };
    for e in entries {
        let e = e?;
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("idx") {
            continue;
        }
        let pack_path = path.with_extension("pack");
        if !pack_path.exists() {
            continue; // orphan idx; ignore
        }
        let idx_bytes = std::fs::read(&path)?;
        for ie in crate::pack::parse_index(&idx_bytes)? {
            self.pack_index
                .entry(ie.id)
                .or_insert(PackLoc { pack_path: pack_path.clone(), offset: ie.offset });
        }
    }
    Ok(())
}

pub fn is_packed(&self, id: &ObjectId) -> bool {
    self.pack_index.contains_key(id)
}

/// Hashes (file stems) of currently-loaded packs.
pub fn pack_hashes(&self) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for loc in self.pack_index.values() {
        if let Some(stem) = loc.pack_path.file_stem().and_then(|s| s.to_str()) {
            set.insert(stem.to_string());
        }
    }
    set.into_iter().collect()
}

/// Read a packed object: seek to its record and decompress+verify+decode.
fn read_pack_object(&self, id: &ObjectId) -> Result<Object> {
    let loc = self.pack_index.get(id).ok_or(Error::NotFound(*id))?;
    // Read just the record: 4-byte length prefix then the compressed payload.
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(&loc.pack_path)?;
    f.seek(SeekFrom::Start(loc.offset))?;
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    f.read_exact(&mut payload)?;
    // Reuse the pure reader by framing the record as a 1-record slice.
    let mut framed = Vec::with_capacity(4 + len);
    framed.extend_from_slice(&len_buf);
    framed.extend_from_slice(&payload);
    crate::pack::read_object_at(&framed, 0, id)
}

/// Read every named object's canonical bytes, write a `<hash>.pack`/`.idx`
/// under `objects/pack/`, refresh the index, and return the pack hash.
pub fn write_pack(&mut self, ids: &[ObjectId]) -> Result<String> {
    let mut objects: Vec<(ObjectId, Vec<u8>)> = Vec::with_capacity(ids.len());
    for id in ids {
        objects.push((*id, self.get(id)?.encode()));
    }
    let (pack_bytes, idx_bytes) = crate::pack::build_pack(&objects)?;
    let hash = hex::encode(blake3::hash(&pack_bytes).as_bytes());
    let pack_dir = self.pack_dir().expect("persistent backend");
    std::fs::create_dir_all(&pack_dir)?;
    write_atomic(&pack_dir.join(format!("{hash}.pack")), &pack_bytes)?;
    write_atomic(&pack_dir.join(format!("{hash}.idx")), &idx_bytes)?;
    self.reload_packs()?;
    Ok(hash)
}

/// Remove a pack's `.pack` + `.idx` and forget its index entries.
pub fn delete_pack(&mut self, hash: &str) -> Result<()> {
    if let Some(pack_dir) = self.pack_dir() {
        for ext in ["pack", "idx"] {
            let p = pack_dir.join(format!("{hash}.{ext}"));
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }
    self.reload_packs()
}
```

Add a free helper near the bottom of the file (above `#[cfg(test)]`):
```rust
/// Atomic write via a per-process tmp sibling + rename.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
```

Wire the pack read into `get` and `contains`. In `get`, after the persistent loose branch and before the final `Err(Error::NotFound(*id))`, the persistent branch currently returns from `read_object_file`. Change the persistent block so a loose miss falls through to packs:
```rust
        // Persistent backend: load any object kind from disk (loose, else pack).
        if self.persistent_dir().is_some() {
            let obj = match self.existing_loose_path(id) {
                Some(_) => self.read_object_file(id)?,
                None => self.read_pack_object(id)?,
            };
            let blob_size = obj.blob_size();
            if blob_size > 0 {
                self.ensure_capacity(blob_size, id)?;
                self.resident_blob_bytes += blob_size;
            }
            self.rehydrations += 1;
            let t = self.tick();
            self.resident.insert(*id, Resident { obj: obj.clone(), blob_size, last_used: t });
            return Ok(obj);
        }
```

In `contains`, extend the persistent check to include packs:
```rust
        self.existing_loose_path(id).is_some() || self.pack_index.contains_key(id)
```

- [ ] **Step 4: Run the test + full suite**

Run: `cargo test -p scl-core`
Expected: PASS (new pack test + all prior tests).

- [ ] **Step 5: Write + run the superseded-pack lifecycle test**

```rust
#[test]
fn delete_pack_forgets_its_objects() {
    let dir = temp_objects_dir("delpack");
    let _ = std::fs::remove_dir_all(&dir);
    let mut s = Store::open_persistent(&dir, 1 << 20).unwrap();
    let a = s.put(Object::blob(b"x".to_vec())).unwrap();
    let hash = s.write_pack(&[a]).unwrap();
    s.delete(&a).unwrap(); // drop loose copy; only the pack has it now
    assert!(s.contains(&a));
    s.delete_pack(&hash).unwrap();
    assert!(!s.is_packed(&a));
    assert!(!s.contains(&a));
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}
```
Run: `cargo test -p scl-core delete_pack_forgets_its_objects`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/store.rs
git commit -m "feat(core): pack-aware store read path + write_pack/delete_pack lifecycle"
```

---

## Task 4: Root-set enumeration helpers

`gc` needs every ref tip. Add `list_heads` and `list_remote_tips` to `refs.rs` (no API enumerates them today).

**Files:**
- Modify: `crates/repo/src/refs.rs`
- Test: `crates/repo/src/refs.rs` tests

**Interfaces:**
- Consumes: `Layout::{refs_heads_dir, refs_remotes_dir}`, `ObjectId::from_str`.
- Produces (used by Task 5):
  - `refs::list_heads(layout: &Layout) -> Result<Vec<(String, ObjectId)>>`
  - `refs::list_remote_tips(layout: &Layout) -> Result<Vec<(String, String, ObjectId)>>` — `(remote, branch, tip)`.

- [ ] **Step 1: Write the failing test**

Add to `crates/repo/src/refs.rs` tests:
```rust
#[test]
fn lists_all_heads_and_remote_tips() {
    let layout = tmp_layout("listall");
    write_head(&layout, "main").unwrap();
    let a = ObjectId::of(b"a");
    let b = ObjectId::of(b"b");
    let c = ObjectId::of(b"c");
    write_branch_tip(&layout, "main", &a).unwrap();
    write_branch_tip(&layout, "feature", &b).unwrap();
    write_remote_tip(&layout, "origin", "main", &c).unwrap();

    let mut heads = list_heads(&layout).unwrap();
    heads.sort();
    assert_eq!(heads, vec![("feature".to_string(), b), ("main".to_string(), a)]);

    let remotes = list_remote_tips(&layout).unwrap();
    assert_eq!(remotes, vec![("origin".to_string(), "main".to_string(), c)]);
    std::fs::remove_dir_all(&layout.root).unwrap();
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-repo lists_all_heads_and_remote_tips`
Expected: FAIL (functions undefined).

- [ ] **Step 3: Implement**

Add to `crates/repo/src/refs.rs` (public fns):
```rust
/// `(branch, tip)` for every `refs/heads/*`. Skips temp files and unreadable
/// names; a malformed ref body is an error.
pub fn list_heads(layout: &Layout) -> Result<Vec<(String, ObjectId)>> {
    let mut out = Vec::new();
    let dir = layout.refs_heads_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for e in entries {
        let e = e?;
        if !e.file_type()?.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.contains(".tmp") {
            continue;
        }
        let text = std::fs::read_to_string(e.path())?;
        let id = ObjectId::from_str(text.trim())
            .map_err(|_| Error::BadRef(format!("head {name} has bad id")))?;
        out.push((name, id));
    }
    Ok(out)
}

/// `(remote, branch, tip)` for every `refs/remotes/<remote>/<branch>`.
pub fn list_remote_tips(layout: &Layout) -> Result<Vec<(String, String, ObjectId)>> {
    let mut out = Vec::new();
    let root = layout.refs_remotes_dir();
    let remotes = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for r in remotes {
        let r = r?;
        if !r.file_type()?.is_dir() {
            continue;
        }
        let remote = r.file_name().to_string_lossy().into_owned();
        for b in std::fs::read_dir(r.path())? {
            let b = b?;
            if !b.file_type()?.is_file() {
                continue;
            }
            let branch = b.file_name().to_string_lossy().into_owned();
            if branch.contains(".tmp") {
                continue;
            }
            let text = std::fs::read_to_string(b.path())?;
            let id = ObjectId::from_str(text.trim())
                .map_err(|_| Error::BadRef(format!("remote ref {remote}/{branch} has bad id")))?;
            out.push((remote, branch, id));
        }
    }
    Ok(out)
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p scl-repo lists_all_heads_and_remote_tips`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/refs.rs
git commit -m "feat(repo): enumerate all branch tips and remote-tracking tips"
```

---

## Task 5: GC algorithm + `Repo::gc`

The heart of P8: under the lock, gather the full safe root set, walk reachability, repack, drop redundant loose copies, prune old unreachable loose objects, and drop superseded packs.

**Files:**
- Create: `crates/repo/src/gc.rs`
- Modify: `crates/repo/src/lib.rs`
- Modify: `crates/repo/src/repo.rs`
- Test: `crates/repo/src/gc.rs` tests

**Interfaces:**
- Consumes: Task 3 `Store::{write_pack, delete, list_loose, loose_mtime, pack_hashes, delete_pack}`; Task 4 `refs::{list_heads, list_remote_tips}`; `refs::head_tip`; `merge_state::read_merge_head`; `reachable::reachable_objects`; `RepoLock`.
- Produces (used by Task 9):
  - `gc::GcStats { packed: usize, loose_pruned: usize, loose_kept: usize, packs_removed: usize }`
  - `gc::run(layout: &Layout, store: &mut Store, grace: std::time::Duration) -> Result<GcStats>`
  - `Repo::gc(&self, grace: std::time::Duration) -> Result<GcStats>`

- [ ] **Step 1: Write the failing reachability test**

Create `crates/repo/src/gc.rs` with tests first. This builds a real persistent repo via `Repo`, makes a reachable commit and a dangling object, and checks gc outcomes. Use a zero grace so the dangling object is immediately prunable:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::Object;
    use std::time::Duration;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("scl-gc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn gc_packs_reachable_and_prunes_old_dangling() {
        let root = tmp_root("basic");
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"reachable").unwrap();
        let snap = repo.commit("t", "c1").unwrap();

        // A dangling blob: put it straight into the store, referenced by no ref.
        let dangling = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            s.put(Object::blob(b"dangling-and-old".to_vec())).unwrap()
        };

        let stats = repo.gc(Duration::from_secs(0)).unwrap();
        assert!(stats.packed >= 1);
        assert!(stats.loose_pruned >= 1);

        let arc = repo.vfs().store();
        let mut s = arc.lock().unwrap();
        // Reachable snapshot survives (now from the pack); dangling is gone.
        assert!(s.contains(&snap));
        assert!(!s.contains(&dangling));
        drop(s);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
```

This needs `Repo::vfs()` access to the store. If `Repo` exposes the store only via `self.vfs.store()` internally, add a small accessor in `repo.rs`:
```rust
/// The underlying VFS handle (objects live behind its `Store`). Test/gc use.
pub fn vfs(&self) -> &scl_vfs::Repo {
    &self.vfs
}
```
(Confirm the field name is `vfs` by reading `repo.rs`; adjust if different.)

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-repo gc_packs_reachable_and_prunes_old_dangling`
Expected: FAIL (no `gc` module / `Repo::gc`).

- [ ] **Step 3: Implement the gc module**

Put this above the tests in `crates/repo/src/gc.rs`:
```rust
//! Reachability-based garbage collection for persistent repos.
//!
//! Under the single-writer lock: gather the full safe root set, walk every
//! object reachable from it, consolidate the reachable set into one fresh
//! packfile, delete the now-redundant loose copies, prune unreachable loose
//! objects older than a grace window, and drop superseded packs.
//!
//! Safety: a reachable object is never dropped. Deletions happen only after the
//! new pack is durably written. The grace window protects *loose* objects
//! (recently written, possibly staged); a *packed* unreachable object is
//! dropped without grace because it survived a prior gc (it was reachable then,
//! and is old now) — mirroring git's loose-vs-packed pruning model.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use scl_core::{ObjectId, Store};

use crate::error::Result;
use crate::layout::Layout;
use crate::{merge_state, reachable, refs};

/// What a gc pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcStats {
    pub packed: usize,
    pub loose_pruned: usize,
    pub loose_kept: usize,
    pub packs_removed: usize,
}

/// The full safe root set: all branch tips + resolved HEAD + all
/// remote-tracking tips + an in-progress merge's other parent.
fn roots(layout: &Layout) -> Result<Vec<ObjectId>> {
    let mut set: BTreeSet<ObjectId> = BTreeSet::new();
    for (_, id) in refs::list_heads(layout)? {
        set.insert(id);
    }
    if let Some(id) = refs::head_tip(layout)? {
        set.insert(id);
    }
    for (_, _, id) in refs::list_remote_tips(layout)? {
        set.insert(id);
    }
    if let Some(id) = merge_state::read_merge_head(layout)? {
        set.insert(id);
    }
    Ok(set.into_iter().collect())
}

/// Run a gc pass. Caller must already hold the repo lock.
pub fn run(layout: &Layout, store: &mut Store, grace: Duration) -> Result<GcStats> {
    let mut stats = GcStats::default();
    let roots = roots(layout)?;
    let reachable: BTreeSet<ObjectId> = reachable::reachable_objects(store, &roots)?;

    // 1. Repack the entire reachable set into one fresh pack (skip if empty).
    let new_hash = if reachable.is_empty() {
        None
    } else {
        let ids: Vec<ObjectId> = reachable.iter().copied().collect();
        let hash = store.write_pack(&ids)?;
        stats.packed = ids.len();
        Some(hash)
    };

    // 2/3. Walk loose objects: delete reachable (now packed) immediately; prune
    //      unreachable past the grace window; keep recent unreachable.
    let now = SystemTime::now();
    for id in store.list_loose()? {
        if reachable.contains(&id) {
            store.delete(&id)?; // safely preserved in the new pack
            continue;
        }
        let old_enough = match store.loose_mtime(&id)? {
            Some(mtime) => now.duration_since(mtime).map(|age| age >= grace).unwrap_or(false),
            None => false,
        };
        if old_enough {
            store.delete(&id)?;
            stats.loose_pruned += 1;
        } else {
            stats.loose_kept += 1;
        }
    }

    // 4. Drop superseded packs: the new pack holds the whole reachable set, so
    //    every other pack is redundant for reachable objects (and any object it
    //    holds that is now unreachable is intentionally reclaimed).
    if let Some(keep) = new_hash {
        for hash in store.pack_hashes() {
            if hash != keep {
                store.delete_pack(&hash)?;
                stats.packs_removed += 1;
            }
        }
    }
    Ok(stats)
}
```

Add to `crates/repo/src/lib.rs`:
```rust
pub mod gc;
```
and add to the re-export block:
```rust
pub use gc::GcStats;
```

Add `Repo::gc` in `crates/repo/src/repo.rs`. **Do not re-acquire `RepoLock` here** — an open `Repo` already holds the single-writer lock for its whole lifetime (the `_lock` field, taken in `open_layout`). Acquiring it again would self-deadlock with `Error::Locked`. Just lock the store mutex and delegate:
```rust
/// Garbage-collect this repo: pack the reachable set and prune unreachable
/// loose objects older than `grace`. Persistent repos only. The open `Repo`
/// already holds the single-writer lock, so the whole pass is serialized
/// against other writers.
pub fn gc(&self, grace: std::time::Duration) -> Result<crate::gc::GcStats> {
    let store_arc = self.vfs.store();
    let mut store = store_arc.lock().unwrap();
    crate::gc::run(&self.layout, &mut store, grace)
}
```

- [ ] **Step 4: Run the basic test + full repo suite**

Run: `cargo test -p scl-repo`
Expected: PASS (the gc basic test and all existing repo tests).

- [ ] **Step 5: Add root-set protection tests (recent-kept, remote ref, MERGE_HEAD)**

Append to `gc.rs` tests:
```rust
#[test]
fn gc_keeps_recent_dangling_within_grace() {
    let root = tmp_root("recent");
    let repo = crate::repo::Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"x").unwrap();
    repo.commit("t", "c1").unwrap();
    let dangling = {
        let arc = repo.vfs().store();
        let mut s = arc.lock().unwrap();
        s.put(Object::blob(b"fresh-dangling".to_vec())).unwrap()
    };
    // Big grace window: the just-written dangling object must be kept.
    let stats = repo.gc(Duration::from_secs(3600)).unwrap();
    assert_eq!(stats.loose_pruned, 0);
    assert!(stats.loose_kept >= 1);
    let arc = repo.vfs().store();
    let mut s = arc.lock().unwrap();
    assert!(s.contains(&dangling));
    drop(s);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn gc_protects_objects_reachable_only_via_remote_ref() {
    let root = tmp_root("remoteref");
    let repo = crate::repo::Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"base").unwrap();
    let base = repo.commit("t", "c1").unwrap();
    // Make a second commit, point a remote-tracking ref at it, then move the
    // local branch back so the second commit is reachable ONLY via the remote ref.
    std::fs::write(root.join("a.txt"), b"more").unwrap();
    let second = repo.commit("t", "c2").unwrap();
    refs::write_remote_tip(repo.layout(), "origin", "main", &second).unwrap();
    refs::write_branch_tip(repo.layout(), "main", &base).unwrap();

    repo.gc(Duration::from_secs(0)).unwrap();
    let arc = repo.vfs().store();
    let mut s = arc.lock().unwrap();
    assert!(s.contains(&second), "remote-tracking ref must protect its commit");
    drop(s);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn gc_protects_merge_head() {
    let root = tmp_root("mergehead");
    let repo = crate::repo::Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"base").unwrap();
    let base = repo.commit("t", "c1").unwrap();
    std::fs::write(root.join("a.txt"), b"theirs").unwrap();
    let theirs = repo.commit("t", "c2").unwrap();
    // Point the branch back to base; record `theirs` only via MERGE_HEAD.
    refs::write_branch_tip(repo.layout(), "main", &base).unwrap();
    merge_state::write(repo.layout(), &theirs, &["a.txt".into()]).unwrap();

    repo.gc(Duration::from_secs(0)).unwrap();
    let arc = repo.vfs().store();
    let mut s = arc.lock().unwrap();
    assert!(s.contains(&theirs), "MERGE_HEAD must protect the in-progress other parent");
    drop(s);
    std::fs::remove_dir_all(&root).unwrap();
}
```
Run: `cargo test -p scl-repo gc_`
Expected: PASS (all gc tests).

- [ ] **Step 6: Add the idempotence + single-writer-lock tests**

```rust
#[test]
fn gc_is_idempotent() {
    let root = tmp_root("idem");
    let repo = crate::repo::Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"x").unwrap();
    repo.commit("t", "c1").unwrap();
    repo.gc(Duration::from_secs(0)).unwrap();
    let second = repo.gc(Duration::from_secs(0)).unwrap();
    assert_eq!(second.loose_pruned, 0);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn open_repo_holds_single_writer_lock_during_gc() {
    let root = tmp_root("held");
    let repo = crate::repo::Repo::init(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"x").unwrap();
    repo.commit("t", "c1").unwrap();
    // A second open on the same repo is refused: the open `Repo` already holds
    // the single-writer lock, so gc always runs serialized against other writers.
    assert!(matches!(crate::repo::Repo::open(&root), Err(crate::error::Error::Locked(_))));
    repo.gc(Duration::from_secs(0)).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}
```
Run: `cargo test -p scl-repo gc_ open_repo_holds`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/repo/src/gc.rs crates/repo/src/lib.rs crates/repo/src/repo.rs
git commit -m "feat(repo): sc gc — reachability repack + grace-window prune under lock"
```

---

## Task 6: Make Transport reads pack/shard/zstd-aware

`LocalTransport::has_object`/`get_object` read the remote's flat `objects/<hex>` directly — broken once the remote shards/compresses/packs. Resolve through a `Store` opened on the remote objects dir.

**Files:**
- Modify: `crates/repo/src/transport.rs`
- Test: `crates/repo/src/transport.rs` tests

**Interfaces:**
- Consumes: `Store::{open_persistent, contains, get}`, Task 1/3 read path.
- Produces: unchanged `Transport` read semantics, now pack/shard-aware.

- [ ] **Step 1: Write the failing test (remote object lives only in a pack)**

Add to `crates/repo/src/transport.rs` tests:
```rust
#[test]
fn transport_reads_packed_remote_object() {
    let layout = tmp_remote("packed");
    // Write an object into the remote store, pack it, drop the loose copy.
    let id;
    {
        let mut s = scl_core::Store::open_persistent(layout.objects_dir(), 1 << 20).unwrap();
        id = s.put(Object::blob(b"remote-packed".to_vec())).unwrap();
        let _h = s.write_pack(&[id]).unwrap();
        s.delete(&id).unwrap();
    }
    let t = LocalTransport::open(&layout.root).unwrap();
    assert!(t.has_object(&id).unwrap());
    assert_eq!(t.get_object(&id).unwrap(), Object::blob(b"remote-packed".to_vec()).encode());
    std::fs::remove_dir_all(&layout.root).unwrap();
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-repo transport_reads_packed_remote_object`
Expected: FAIL (`get_object` reads flat path; object is only in a pack).

- [ ] **Step 3: Give `LocalTransport` a remote `Store` and route reads through it**

In `crates/repo/src/transport.rs`, change the struct + open + read methods:
```rust
use std::cell::RefCell;
use scl_core::Store;

/// Transport over a remote `.sc/` directory on the local filesystem.
pub struct LocalTransport {
    layout: Layout,
    /// A store opened on the remote objects dir, so reads resolve loose
    /// (sharded or flat), compressed, and packed objects uniformly. Lazily
    /// mutated for its RAM cache; interior-mutable because the trait reads `&self`.
    store: RefCell<Store>,
}

impl LocalTransport {
    pub fn open(root: impl Into<std::path::PathBuf>) -> Result<LocalTransport> {
        let layout = Layout::at(root);
        if !layout.dot_sc.is_dir() {
            return Err(Error::NotARepo);
        }
        let store = Store::open_persistent(layout.objects_dir(), 1 << 20)?;
        Ok(LocalTransport { layout, store: RefCell::new(store) })
    }
}
```
Replace `has_object` and `get_object`:
```rust
    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        Ok(self.store.borrow().contains(id))
    }

    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        Ok(self.store.borrow_mut().get(id)?.encode())
    }
```
`put_object` still writes through the store so new remote objects use the sharded+zstd layout. Replace it:
```rust
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if ObjectId::of(bytes) != *id {
            return Err(Error::CorruptObject(*id));
        }
        let got = self.store.borrow_mut().put(Object::decode(bytes)?)?;
        if got != *id {
            return Err(Error::CorruptObject(*id));
        }
        Ok(())
    }
```
Add the needed imports at the top if missing: `use scl_core::Object;`.

- [ ] **Step 4: Run the test + transport suite**

Run: `cargo test -p scl-repo transport`
Expected: PASS — including the existing `local_transport_objects_and_refs_roundtrip` (now backed by a store).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/transport.rs
git commit -m "feat(repo): transport reads resolve packed/sharded/compressed remote objects"
```

---

## Task 7: Bulk-pack transport methods (`get_pack` / `put_pack`)

Add the two bulk methods to the `Transport` trait and `LocalTransport`.

**Files:**
- Modify: `crates/repo/src/transport.rs`
- Test: `crates/repo/src/transport.rs` tests

**Interfaces:**
- Consumes: `reachable::reachable_objects`, `pack::{build_pack, parse_pack}`, the remote `Store`.
- Produces (used by Task 8):
  - `Transport::get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>>`
  - `Transport::put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>>`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn get_pack_excludes_haves_and_put_pack_verifies() {
    let layout = tmp_remote("bulk");
    // Seed two reachable commits on the remote via a real repo.
    let remote_repo = crate::repo::Repo::init(&layout.root).unwrap();
    std::fs::write(layout.root.join("a.txt"), b"one").unwrap();
    let c1 = remote_repo.commit("t", "c1").unwrap();
    std::fs::write(layout.root.join("a.txt"), b"two").unwrap();
    let c2 = remote_repo.commit("t", "c2").unwrap();

    let t = LocalTransport::open(&layout.root).unwrap();
    // Want c2, already have c1: the pack must omit c1's objects but include c2.
    let pack = t.get_pack(&[c2], &[c1]).unwrap();
    let ids: Vec<_> = scl_core::pack::parse_pack(&pack).unwrap().into_iter().map(|(id, _)| id).collect();
    assert!(ids.contains(&c2));
    assert!(!ids.contains(&c1));

    // put_pack into a fresh empty remote writes + returns the ids.
    let dst = tmp_remote("bulkdst");
    let _ = crate::repo::Repo::init(&dst.root).unwrap();
    let t2 = LocalTransport::open(&dst.root).unwrap();
    let written = t2.put_pack(&pack).unwrap();
    assert!(written.contains(&c2));
    assert!(t2.has_object(&c2).unwrap());

    // A tampered pack is rejected.
    let mut bad = pack.clone();
    let n = bad.len() - 1;
    bad[n] ^= 0xFF;
    assert!(t2.put_pack(&bad).is_err());

    std::fs::remove_dir_all(&layout.root).unwrap();
    std::fs::remove_dir_all(&dst.root).unwrap();
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-repo get_pack_excludes_haves_and_put_pack_verifies`
Expected: FAIL (methods undefined).

- [ ] **Step 3: Add the trait methods + default-free impl**

In `crates/repo/src/transport.rs`, extend the `trait Transport` with:
```rust
    /// Build a pack of every object reachable from `wants` but not already
    /// implied by `haves` (the receiver's closure). Returns `.pack` bytes.
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>>;

    /// Receive a pack: verify every record (BLAKE3) and write each object into
    /// the store. Returns the contained ids. Refs are the caller's job.
    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>>;
```

Implement for `LocalTransport`:
```rust
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>> {
        use std::collections::BTreeSet;
        let mut store = self.store.borrow_mut();
        // Reachable-from-wants minus reachable-from-haves, computed on this
        // (the remote) store. `haves` the remote doesn't have are skipped.
        let want_set = crate::reachable::reachable_objects(&mut *store, wants)?;
        let mut have_set: BTreeSet<ObjectId> = BTreeSet::new();
        for h in haves {
            if store.contains(h) {
                have_set.extend(crate::reachable::reachable_objects(&mut *store, &[*h])?);
            }
        }
        let send: Vec<(ObjectId, Vec<u8>)> = want_set
            .into_iter()
            .filter(|id| !have_set.contains(id))
            .map(|id| Ok((id, store.get(&id)?.encode())))
            .collect::<Result<Vec<_>>>()?;
        let (pack, _idx) = scl_core::pack::build_pack(&send)?;
        Ok(pack)
    }

    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>> {
        let mut store = self.store.borrow_mut();
        let mut ids = Vec::new();
        // parse_pack verifies every record's hash before we write anything.
        for (id, obj) in scl_core::pack::parse_pack(pack)? {
            let got = store.put(obj)?;
            if got != id {
                return Err(Error::CorruptObject(id));
            }
            ids.push(id);
        }
        Ok(ids)
    }
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p scl-repo get_pack_excludes_haves_and_put_pack_verifies`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/transport.rs
git commit -m "feat(repo): bulk-pack transport methods get_pack/put_pack"
```

---

## Task 8: Rewire push/fetch/clone to bulk pack

Replace the object-at-a-time loops in `push`, `transfer_objects` (clone/fetch) with single `put_pack`/`get_pack` calls.

**Files:**
- Modify: `crates/repo/src/repo.rs`
- Test: existing `clone_*`, `fetch_*`, `push_*` tests in `repo.rs` must still pass; add a bulk-closure test.

**Interfaces:**
- Consumes: Task 7 `Transport::{get_pack, put_pack}`.
- Produces: unchanged public `push`/`fetch`/`clone_to` behavior.

- [ ] **Step 1: Replace push's per-object loop**

In `crates/repo/src/repo.rs` `push`, replace the transfer block:
```rust
        // Transfer objects the remote lacks, then advance the remote ref.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let ids = reachable::reachable_objects(&mut *store, &[local_tip])?;
            for id in ids {
                if !transport.has_object(&id)? {
                    let bytes = store.get(&id)?.encode();
                    transport.put_object(&id, &bytes)?;
                }
            }
        }
        transport.update_ref(&branch, &local_tip)?;
```
with a bulk build-and-send (the client builds the pack from its own store, so reuse `build_pack` over the objects the remote lacks):
```rust
        // Build one pack of the objects the remote lacks, send it in bulk, then
        // advance the remote ref.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let mut send: Vec<(ObjectId, Vec<u8>)> = Vec::new();
            for id in reachable::reachable_objects(&mut *store, &[local_tip])? {
                if !transport.has_object(&id)? {
                    send.push((id, store.get(&id)?.encode()));
                }
            }
            if !send.is_empty() {
                let (pack, _idx) = scl_core::pack::build_pack(&send)?;
                transport.put_pack(&pack)?;
            }
        }
        transport.update_ref(&branch, &local_tip)?;
```

- [ ] **Step 2: Replace `transfer_objects` (clone/fetch) with a bulk fetch**

Replace the `transfer_objects` free fn body:
```rust
fn transfer_objects(
    transport: &impl Transport,
    store: &mut Store,
    tips: &[ObjectId],
) -> Result<()> {
    // Tell the remote what we already have so it omits those objects.
    let haves: Vec<ObjectId> = tips.iter().copied().filter(|id| store.contains(id)).collect();
    let pack = transport.get_pack(tips, &haves)?;
    // parse_pack verifies every record; write each object into the local store.
    for (id, obj) in scl_core::pack::parse_pack(&pack)? {
        let got = store.put(obj)?;
        if got != id {
            return Err(Error::CorruptObject(id));
        }
    }
    Ok(())
}
```
Confirm `use scl_core::pack;` is reachable via `scl_core::pack::...` (fully-qualified above; no new `use` needed). Confirm `ObjectId` is already imported in `repo.rs` (it is, used throughout).

- [ ] **Step 3: Run the existing transfer tests**

Run: `cargo test -p scl-repo clone_ fetch_ push_`
Expected: PASS — `clone_copies_objects_refs_head_and_worktree`, `clone_preserves_committed_secret_decryptable_only_with_key`, `fetch_updates_remote_tracking_then_merge_integrates`, `push_fast_forward_advances_remote_and_rejects_non_ff`, `push_creates_a_new_remote_branch`.

- [ ] **Step 4: Add a closure-correctness test**

Add to `repo.rs` tests:
```rust
#[test]
fn push_then_clone_via_pack_roundtrips_history() {
    let origin = std::env::temp_dir().join(format!("scl-bulk-origin-{}", std::process::id()));
    let work = std::env::temp_dir().join(format!("scl-bulk-work-{}", std::process::id()));
    let clone = std::env::temp_dir().join(format!("scl-bulk-clone-{}", std::process::id()));
    for p in [&origin, &work, &clone] { let _ = std::fs::remove_dir_all(p); }

    // origin is an empty remote; work pushes two commits to it.
    Repo::init(&origin).unwrap();
    let w = Repo::init(&work).unwrap();
    w.remote_add("origin", &origin.display().to_string()).unwrap();
    std::fs::write(work.join("a.txt"), b"one").unwrap();
    w.commit("t", "c1").unwrap();
    std::fs::write(work.join("a.txt"), b"two").unwrap();
    let tip = w.commit("t", "c2").unwrap();
    w.push("origin").unwrap();

    // Clone the origin elsewhere; HEAD tip + its objects must be present.
    let c = Repo::clone_to(&origin, &clone).unwrap();
    assert_eq!(c.head_tip().unwrap(), Some(tip));

    for p in [&origin, &work, &clone] { std::fs::remove_dir_all(p).unwrap(); }
}
```
Run: `cargo test -p scl-repo push_then_clone_via_pack_roundtrips_history`
Expected: PASS.

- [ ] **Step 5: Run the whole workspace**

Run: `cargo test`
Expected: PASS across all crates.

- [ ] **Step 6: Commit**

```bash
git add crates/repo/src/repo.rs
git commit -m "feat(repo): push/clone/fetch transfer objects as a single pack"
```

---

## Task 9: `sc gc` CLI command

Expose `sc gc [--prune-expire <DURATION>]` (default 24h).

**Files:**
- Modify: `crates/cli/src/main.rs`
- Test: a CLI-level smoke test is covered by Task 10's demo; unit-test the duration parser here.

**Interfaces:**
- Consumes: `Repo::gc`, `GcStats`.
- Produces: `sc gc` subcommand.

- [ ] **Step 1: Write the failing duration-parser test**

Add to `crates/cli/src/main.rs` (add a `#[cfg(test)] mod tests` if none exists):
```rust
#[cfg(test)]
mod tests {
    use super::parse_duration;
    use std::time::Duration;

    #[test]
    fn parses_suffixed_durations() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(24 * 3600));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(7 * 86400));
        assert!(parse_duration("nope").is_err());
    }
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p scl-cli parses_suffixed_durations`
Expected: FAIL (`parse_duration` undefined).

- [ ] **Step 3: Implement the parser + command**

Add the parser near the other free fns in `main.rs`:
```rust
/// Parse a duration like `24h`, `30m`, `45s`, `7d` into a `std::time::Duration`.
/// Bare-number (no suffix) is rejected to avoid ambiguity.
fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => anyhow::bail!("duration needs a unit suffix s/m/h/d, got {s:?}"),
    };
    let n: u64 = num.parse().map_err(|_| anyhow::anyhow!("bad duration number: {s:?}"))?;
    Ok(std::time::Duration::from_secs(n * mult))
}
```

Add a variant to the `Cmd` enum (the top-level `#[derive(Subcommand)]`):
```rust
    /// Garbage-collect: pack reachable objects, prune unreachable ones.
    Gc {
        /// Prune unreachable loose objects older than this (e.g. 24h, 7d).
        #[arg(long, default_value = "24h")]
        prune_expire: String,
    },
```

Add the dispatch arm in `main` alongside the others:
```rust
        Cmd::Gc { prune_expire } => run_gc(&prune_expire),
```

Add the handler:
```rust
fn run_gc(prune_expire: &str) -> Result<()> {
    let grace = parse_duration(prune_expire)?;
    let repo = scl_repo::Repo::open(".")?;
    let stats = repo.gc(grace)?;
    println!(
        "gc: packed {} object(s), pruned {} loose, kept {} recent, removed {} old pack(s)",
        stats.packed, stats.loose_pruned, stats.loose_kept, stats.packs_removed
    );
    Ok(())
}
```

- [ ] **Step 4: Run the parser test + build**

Run: `cargo test -p scl-cli parses_suffixed_durations && cargo build -p scl-cli`
Expected: PASS + clean build.

- [ ] **Step 5: Manual smoke check**

Run:
```bash
cd "$(mktemp -d)" && cargo run --quiet --bin sc -- init && echo hi > a.txt && cargo run --quiet --bin sc -- commit -m c1 && cargo run --quiet --bin sc -- gc && cd - >/dev/null
```
Expected: prints a `gc: packed N object(s)...` line with no error.

- [ ] **Step 6: Commit**

```bash
git add crates/cli/src/main.rs
git commit -m "feat(cli): sc gc command with --prune-expire duration"
```

---

## Task 10: Extend the repo demo to prove reclamation

Show `.sc/` shrinking after gc reclaims abandoned objects, keeping the demo honest.

**Files:**
- Modify: `demo/run_repo_demo.sh`
- Test: run the script.

**Interfaces:**
- Consumes: `sc init/commit/gc`.

- [ ] **Step 1: Read the current demo script**

Run: `sed -n '1,80p' demo/run_repo_demo.sh`
Expected: understand how it builds a temp repo and what it prints (so the gc section matches its style).

- [ ] **Step 2: Append a gc reclamation section**

Add near the end of `demo/run_repo_demo.sh`, before any final cleanup, matching the script's existing variable names for the repo dir (shown here as `$REPO` — adjust to the script's actual variable):
```bash
echo
echo "== GC reclamation =="
# Create abandoned objects: commit a large file, then overwrite + recommit so the
# original blob becomes unreachable.
head -c 1048576 /dev/urandom > "$REPO/big.bin"
( cd "$REPO" && sc commit -m "add big.bin" >/dev/null )
head -c 1048576 /dev/urandom > "$REPO/big.bin"
( cd "$REPO" && sc commit -m "replace big.bin" >/dev/null )

before=$(du -sk "$REPO/.sc/objects" | cut -f1)
echo "objects size before gc: ${before} KiB"
# Zero grace so the just-abandoned blob is immediately collectable in the demo.
( cd "$REPO" && sc gc --prune-expire 0s )
after=$(du -sk "$REPO/.sc/objects" | cut -f1)
echo "objects size after gc:  ${after} KiB"
if [ "$after" -lt "$before" ]; then
  echo "OK: gc reclaimed space"
else
  echo "WARN: gc did not shrink objects (small repo / fs rounding)"
fi
```
Note: `--prune-expire 0s` is accepted by the parser (`0 * 1 = 0s`), making the demo deterministic.

- [ ] **Step 3: Run the demo**

Run: `bash demo/run_repo_demo.sh`
Expected: runs to completion, prints before/after sizes, and `OK: gc reclaimed space`.

- [ ] **Step 4: Commit**

```bash
git add demo/run_repo_demo.sh
git commit -m "docs(demo): show sc gc reclaiming space in the repo demo"
```

---

## Task 11: Accept ADR-0015 + sync ARCHITECTURE/CLAUDE

Flip the ADR to Accepted and record the shipped surface, per the project's "keep ADRs/ARCHITECTURE in sync" convention.

**Files:**
- Modify: `docs/adr/0015-packfiles-and-gc.md`
- Modify: `ARCHITECTURE.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Flip ADR status**

In `docs/adr/0015-packfiles-and-gc.md`, change `- **Status:** Proposed` to `- **Status:** Accepted`. Add a one-line note that the grace window protects loose objects only and that the safe root set includes remote-tracking refs + MERGE_HEAD (the two clarifications this build locked in beyond the original text).

- [ ] **Step 2: Update ARCHITECTURE + CLAUDE commands**

In `CLAUDE.md`, under the persistent-repo commands block, add:
```sh
cargo run --bin sc -- gc                      # pack reachable objects + prune unreachable
cargo run --bin sc -- gc --prune-expire 7d    # custom grace window
```
In `ARCHITECTURE.md`, add a short paragraph (or bullet) noting Phase 8 is built: packfiles + `sc gc` + sharded/zstd loose objects + bulk-pack transfer; remaining follow-ons drop "packfiles/gc".

- [ ] **Step 3: Run the full suite once more**

Run: `cargo test`
Expected: PASS workspace-wide.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0015-packfiles-and-gc.md ARCHITECTURE.md CLAUDE.md
git commit -m "docs: accept ADR-0015 and record P8 packfiles/gc as built"
```

---

## Self-review notes (already reconciled)

- **Spec coverage:** packfile format → Task 2/3; pack-aware reads → Task 3; `sc gc` reachability+prune+grace → Task 5/9; full safe root set → Task 4/5; sharding+zstd+read-both → Task 1; `delete`/`list_loose` → Task 1; bulk-pack transfer (get_pack/put_pack + push/fetch/clone) → Task 7/8; transport read-path fix → Task 6; demo reclamation → Task 10; ADR/docs sync → Task 11. No spec section is unmapped.
- **Type consistency:** `write_pack -> String` (hash), `pack_hashes -> Vec<String>`, `delete_pack(&str)`, `GcStats{packed,loose_pruned,loose_kept,packs_removed}`, `gc::run(layout,store,Duration)`, `Repo::gc(Duration)`, `get_pack(wants,haves)`/`put_pack(pack)` are used identically everywhere they appear.
- **Open verification for the implementer:** Task 5 assumes `Repo` holds its store as a field named `vfs` (`scl_vfs::Repo`) — the `vfs()` accessor and `self.vfs.store()` calls match the existing `repo.rs` usage at lines ~802/843/870. Confirm the field name when adding `vfs()`; if it differs, adjust the accessor only.
