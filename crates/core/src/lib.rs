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

/// Hard floor for the operator-set object cap (2 MiB). A default peer sends
/// pack chunk frames of `CHUNK_SIZE` (1 MiB) plus a tag byte, which a
/// 1 MiB cap would refuse, so anything lower cannot talk to a default peer.
pub const MIN_MAX_OBJECT_SIZE: usize = 2 * 1024 * 1024;

/// What to tell an operator whose receiver refused an object: there is no
/// negotiation, and each receiver applies its own cap to what it accepts.
pub const OBJECT_SIZE_HINT: &str = "only the receiving side's cap applies: raise SC_MAX_OBJECT_SIZE (or `sc serve --max-object-size` on a server) on the side that is refusing";

/// Hard ceiling for the operator-set object cap (1 GiB). Compile-time, so no
/// flag or env value can make a hostile peer's allocation claim unbounded.
pub const MAX_MAX_OBJECT_SIZE: usize = 1024 * 1024 * 1024;

static MAX_OBJECT_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// The process-wide cap on one untrusted object (ADR-0039 addendum, #213):
/// a pack record's compressed payload and decompressed output, a wire frame
/// body, a by-id reply object, and the `SC_PACK_CHUNK` clamp. The single
/// source for every untrusted-length guard; never inline a number. Defaults
/// to [`DEFAULT_MAX_OBJECT_SIZE`]; the first call here or to
/// [`set_max_object_size`] fixes the value for the process.
pub fn max_object_size() -> usize {
    // The first read fixes the value, so a later `set_max_object_size` cannot
    // disagree with guards that already ran.
    *MAX_OBJECT_SIZE.get_or_init(|| DEFAULT_MAX_OBJECT_SIZE)
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
            "max object size {n} bytes is outside the allowed range {MIN_MAX_OBJECT_SIZE} (2 MiB) to {MAX_MAX_OBJECT_SIZE} (1 GiB)"
        ))
    }
}

/// Parse a byte-size setting: plain bytes, or a number with a `KiB`, `MiB` or
/// `GiB` suffix (case-insensitive). No range check; callers apply their own
/// bounds (see [`parse_object_size`]).
pub fn parse_byte_size(s: &str) -> std::result::Result<u64, String> {
    let t = s.trim();
    let lower = t.to_ascii_lowercase();
    let (digits, mult) = if let Some(d) = lower.strip_suffix("kib") {
        (d, 1u64 << 10)
    } else if let Some(d) = lower.strip_suffix("mib") {
        (d, 1 << 20)
    } else if let Some(d) = lower.strip_suffix("gib") {
        (d, 1 << 30)
    } else {
        (lower.as_str(), 1)
    };
    digits
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| {
            format!("invalid size {s:?}: expected bytes or a KiB/MiB/GiB suffix, e.g. 64MiB")
        })
}

/// Parse an object-size setting: [`parse_byte_size`] plus the same hard
/// bounds as [`set_max_object_size`]; an out-of-range value is an error, not
/// clamped.
pub fn parse_object_size(s: &str) -> std::result::Result<usize, String> {
    let n = usize::try_from(parse_byte_size(s)?)
        .map_err(|_| format!("invalid object size {s:?}: too large"))?;
    check_object_size_bounds(n)?;
    Ok(n)
}

/// Floor of a buffer growth step in the incremental readers below. Peak
/// over-allocation past the bytes actually received is at most
/// `max(READ_STEP, received / 8)`.
const READ_STEP: usize = 8 * 1024 * 1024;

/// Size of the next growth step once `filled` bytes are in hand: geometric up
/// to [`READ_STEP`] (cheap for small objects), then `max(READ_STEP, filled/8)`,
/// so total copying stays linear even on an allocator that always copies on
/// growth, while over-allocation stays within 12.5% (or one `READ_STEP`).
fn next_step(filled: usize) -> usize {
    if filled < READ_STEP {
        filled.clamp(64 * 1024, READ_STEP)
    } else {
        READ_STEP.max(filled / 8)
    }
}

/// Read from `r` until EOF or `limit` bytes, whichever is first, growing the
/// buffer by `reserve_exact` steps (see [`next_step`]) as bytes arrive.
/// `first_step` sizes the first allocation (the caller's best guess). The
/// capacity never exceeds the bytes read by more than `max(8 MiB, 12.5%)`, so
/// a hostile length or decompression bomb cannot buy a `limit`-sized
/// allocation without supplying the bytes.
pub fn read_limited(
    r: &mut impl std::io::Read,
    limit: usize,
    first_step: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut filled = 0;
    while filled < limit {
        if filled == buf.len() {
            let want = if filled == 0 {
                first_step.clamp(1, READ_STEP)
            } else {
                next_step(filled)
            };
            let step = want.min(limit - filled);
            buf.reserve_exact(step);
            buf.resize(filled + step, 0);
        }
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Read exactly `len` bytes via [`read_limited`]: `len` is a peer's claim, so
/// the buffer follows the bytes that arrive. The caller still checks `len`
/// against [`max_object_size`] first. A short read is `UnexpectedEof`.
pub fn read_exact_vec(r: &mut impl std::io::Read, len: usize) -> std::io::Result<Vec<u8>> {
    let buf = read_limited(r, len, len)?;
    if buf.len() < len {
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
        assert_eq!(parse_object_size("2097152").unwrap(), MIN_MAX_OBJECT_SIZE);
        assert_eq!(parse_object_size("2MiB").unwrap(), MIN_MAX_OBJECT_SIZE);
        assert_eq!(parse_object_size("2048kib").unwrap(), MIN_MAX_OBJECT_SIZE);
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
            "2097151",
            "2047KiB",
            "1MiB",
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
    fn parse_byte_size_accepts_suffixes_without_bounds() {
        assert_eq!(parse_byte_size("0"), Ok(0));
        assert_eq!(parse_byte_size(" 3kib "), Ok(3 << 10));
        assert_eq!(parse_byte_size("16GiB"), Ok(16 << 30));
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("-1").is_err());
        assert!(parse_byte_size("1.5MiB").is_err());
        assert!(parse_byte_size("99999999999999999999GiB").is_err());
    }

    #[test]
    fn set_max_object_size_rejects_out_of_range_values() {
        assert!(set_max_object_size(MIN_MAX_OBJECT_SIZE - 1).is_err());
        assert!(set_max_object_size(MAX_MAX_OBJECT_SIZE + 1).is_err());
        // Rejection never fixes the setting, so the default still applies.
        assert_eq!(max_object_size(), DEFAULT_MAX_OBJECT_SIZE);
    }

    #[test]
    fn read_limited_never_over_allocates_by_more_than_one_step() {
        // An endless reader (a decompression bomb's shape): stops at the
        // limit, and the capacity is within one step of the bytes read.
        let slack = |n: usize| READ_STEP.max(n / 8);
        // Past the 12.5% regime (limit / 8 > READ_STEP).
        let limit = 12 * READ_STEP + 12_345;
        let v = read_limited(&mut std::io::repeat(0), limit, 4096).unwrap();
        assert_eq!(v.len(), limit);
        assert!(
            v.capacity() <= limit + slack(limit),
            "cap {} for {limit}",
            v.capacity()
        );
        let limit = 3 * READ_STEP + 12_345;
        let v = read_limited(&mut std::io::repeat(0), limit, 4096).unwrap();
        assert!(v.capacity() <= limit + slack(limit), "cap {}", v.capacity());
        // A claimed length with all bytes present: also within one step
        // (in fact exact, since the last step is the remainder).
        let src = vec![9u8; 2 * READ_STEP + 7];
        let v = read_exact_vec(&mut &src[..], src.len()).unwrap();
        assert_eq!(v, src);
        assert!(v.capacity() <= src.len() + slack(src.len()));
        // A small claim allocates about the claim, not a step.
        let v = read_exact_vec(&mut &b"abcdef"[..], 4).unwrap();
        assert!(v.capacity() < 1024);
    }

    #[test]
    fn read_limited_handles_short_reads_and_eof_before_the_limit() {
        struct Dribble<'a>(&'a [u8]);
        impl std::io::Read for Dribble<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.len().min(out.len()).min(1000);
                out[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let src: Vec<u8> = (0..(READ_STEP + 5000)).map(|i| i as u8).collect();
        let got = read_limited(&mut Dribble(&src), usize::MAX / 2, 10).unwrap();
        assert_eq!(got, src);
        assert!(read_exact_vec(&mut Dribble(&src), src.len() + 1).is_err());
    }

    #[test]
    fn read_exact_vec_reads_len_and_errors_on_short_input() {
        assert_eq!(read_exact_vec(&mut &b"abcdef"[..], 4).unwrap(), b"abcd");
        let err = read_exact_vec(&mut &b"abc"[..], 4).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
