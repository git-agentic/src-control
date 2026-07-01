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
        // Each record: [id:32][compressed_len:4][compressed_data:N].
        // The index offset points to `compressed_len` so that `read_object_at`
        // (which reads the length at `offset`) requires no format-aware changes.
        pack.extend_from_slice(id.as_bytes());
        let offset = pack.len() as u64; // position of compressed_len
        pack.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        pack.extend_from_slice(&compressed);
        entries.push(IndexEntry { id: *id, offset, length: compressed.len() as u64 });
    }
    entries.sort_by_key(|e| e.id);

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
    let expected = count
        .checked_mul(ROW)
        .and_then(|n| n.checked_add(16))
        .ok_or_else(|| Error::BadPackIndex("entry count overflow".into()))?;
    if idx.len() != expected {
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
            if p >= id {
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
        // Record layout: [id:32][compressed_len:4][compressed_data:N].
        if pos + 32 > pack.len() {
            return Err(Error::PackCorrupt("truncated record id".into()));
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&pack[pos..pos + 32]);
        let expected_id = ObjectId::from_bytes(id_bytes);
        pos += 32;

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
        let actual_id = ObjectId::of(&canonical);
        if actual_id != expected_id {
            return Err(Error::PackCorrupt(format!(
                "hash mismatch: expected {expected_id}, got {actual_id}"
            )));
        }
        let obj = Object::decode(&canonical)?;
        out.push((actual_id, obj));
        pos = end;
    }
    Ok(out)
}

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

    #[test]
    fn parse_index_rejects_overflowing_count() {
        // Magic b"SCIX", version 1 LE, count = 2^60 — count * 48 wraps to 0 on u64,
        // so unchecked arithmetic would pass the length check then panic.
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(b"SCIX");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000_0000_0000_0000u64.to_le_bytes());
        let err = parse_index(&bytes).unwrap_err();
        assert!(matches!(err, crate::error::Error::BadPackIndex(_)), "got {err:?}");
    }
}
