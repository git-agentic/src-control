//! `scl-core` — content-addressed object store and snapshot model.
//!
//! This crate knows nothing about Git or worktrees. It provides immutable,
//! BLAKE3-addressed objects (blobs, trees, snapshots, secrets) and a [`Store`]
//! that bounds resident blob memory with LRU eviction and optional spill.

pub mod error;
pub mod fsutil;
pub mod id;
pub mod object;
pub mod pack;
pub mod store;

/// Default for the largest single object (decoded/decompressed canonical
/// bytes) this system accepts from an untrusted source. The live value is
/// [`max_object_size`]; this is what it is when nothing configured it.
/// 256 MiB comfortably exceeds any legitimate single object in this system
/// (blobs, trees, snapshots, secrets) while still bounding a malicious
/// peer's ability to force multi-GB allocations from a few header bytes.
pub const DEFAULT_MAX_OBJECT_SIZE: usize = 256 * 1024 * 1024;

/// Hard floor for the operator-set object cap (1 MiB): below this the
/// 1 MiB default pack chunk and ordinary snapshots stop fitting a frame.
pub const MIN_MAX_OBJECT_SIZE: usize = 1024 * 1024;

/// Hard ceiling for the operator-set object cap (1 GiB). Compile-time, so no
/// flag or env value can make a hostile peer's allocation claim unbounded.
pub const MAX_MAX_OBJECT_SIZE: usize = 1024 * 1024 * 1024;

static MAX_OBJECT_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// The process-wide cap on one untrusted object (ADR-0039 addendum, #213):
/// a pack record's compressed payload and decompressed output, a wire frame
/// body, a by-id reply object, and the `SC_PACK_CHUNK` clamp. The single
/// source for every untrusted-length guard; never inline a number. Defaults
/// to [`DEFAULT_MAX_OBJECT_SIZE`] until [`set_max_object_size`] runs.
pub fn max_object_size() -> usize {
    MAX_OBJECT_SIZE
        .get()
        .copied()
        .unwrap_or(DEFAULT_MAX_OBJECT_SIZE)
}

/// Set the process-wide object cap, once, at startup. Rejects (never clamps)
/// a value outside [`MIN_MAX_OBJECT_SIZE`]..=[`MAX_MAX_OBJECT_SIZE`]. Setting
/// the same value again is a no-op; a different value after one was fixed
/// is an error, since guards already running would disagree.
pub fn set_max_object_size(n: usize) -> std::result::Result<(), String> {
    check_object_size_bounds(n)?;
    let cur = *MAX_OBJECT_SIZE.get_or_init(|| n);
    if cur == n {
        Ok(())
    } else {
        Err(format!("max object size is already fixed at {cur} bytes"))
    }
}

fn check_object_size_bounds(n: usize) -> std::result::Result<(), String> {
    if (MIN_MAX_OBJECT_SIZE..=MAX_MAX_OBJECT_SIZE).contains(&n) {
        Ok(())
    } else {
        Err(format!(
            "max object size {n} bytes is outside the allowed range {MIN_MAX_OBJECT_SIZE} (1 MiB) to {MAX_MAX_OBJECT_SIZE} (1 GiB)"
        ))
    }
}

/// Parse an object-size setting: plain bytes, or a number with a `KiB`,
/// `MiB` or `GiB` suffix (case-insensitive). Applies the same hard bounds as
/// [`set_max_object_size`]; an out-of-range value is an error, not clamped.
pub fn parse_object_size(s: &str) -> std::result::Result<usize, String> {
    let t = s.trim();
    let lower = t.to_ascii_lowercase();
    let (digits, mult) = if let Some(d) = lower.strip_suffix("kib") {
        (d, 1usize << 10)
    } else if let Some(d) = lower.strip_suffix("mib") {
        (d, 1 << 20)
    } else if let Some(d) = lower.strip_suffix("gib") {
        (d, 1 << 30)
    } else {
        (lower.as_str(), 1)
    };
    let n = digits
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| {
            format!("invalid object size {s:?}: expected bytes or a KiB/MiB/GiB suffix, e.g. 64MiB")
        })?;
    check_object_size_bounds(n)?;
    Ok(n)
}

/// Read exactly `len` bytes, growing the buffer as bytes actually arrive
/// rather than pre-allocating `len`: `len` is a peer's claim, and a hostile
/// peer must not get a `len`-sized allocation for a few header bytes. The
/// caller still checks `len` against [`max_object_size`] first.
pub fn read_exact_vec(r: &mut impl std::io::Read, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(len.min(1 << 20));
    let got = r.by_ref().take(len as u64).read_to_end(&mut buf)?;
    if got < len {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(buf)
}

pub use error::{Error, Result};
pub use id::ObjectId;
pub use object::{
    BranchManifest, EntryKind, FileMode, Object, ProtectPrefix, Protection, RecipientEntry,
    RecipientState, SealedObj, Secret, SignatureObj, Snapshot, Transcript, Tree, TreeEntry,
    WrappedKey, PROTECTED, RANDOMIZED,
};
pub use store::{Backend, SpillPolicy, Store, StoreConfig, StoreStats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_object_size_accepts_bytes_and_suffixes() {
        assert_eq!(parse_object_size("1048576").unwrap(), MIN_MAX_OBJECT_SIZE);
        assert_eq!(parse_object_size("1MiB").unwrap(), MIN_MAX_OBJECT_SIZE);
        assert_eq!(parse_object_size("1024kib").unwrap(), MIN_MAX_OBJECT_SIZE);
        assert_eq!(
            parse_object_size(" 256 MiB ").unwrap(),
            DEFAULT_MAX_OBJECT_SIZE
        );
        assert_eq!(parse_object_size("1GiB").unwrap(), MAX_MAX_OBJECT_SIZE);
    }

    #[test]
    fn parse_object_size_rejects_out_of_range_and_garbage_without_clamping() {
        for bad in [
            "0",
            "1048575",
            "1023KiB",
            "1025MiB",
            "2GiB",
            "18446744073709551615GiB", // multiplication overflow
            "",
            "MiB",
            "-1",
            "12XB",
            "1.5GiB",
        ] {
            assert!(parse_object_size(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(parse_object_size("2GiB")
            .unwrap_err()
            .contains("allowed range"));
    }

    #[test]
    fn set_max_object_size_rejects_out_of_range_values() {
        assert!(set_max_object_size(MIN_MAX_OBJECT_SIZE - 1).is_err());
        assert!(set_max_object_size(MAX_MAX_OBJECT_SIZE + 1).is_err());
        // Rejection never fixes the setting, so the default still applies.
        assert_eq!(max_object_size(), DEFAULT_MAX_OBJECT_SIZE);
    }

    #[test]
    fn read_exact_vec_reads_len_and_errors_on_short_input() {
        assert_eq!(read_exact_vec(&mut &b"abcdef"[..], 4).unwrap(), b"abcd");
        let err = read_exact_vec(&mut &b"abc"[..], 4).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
