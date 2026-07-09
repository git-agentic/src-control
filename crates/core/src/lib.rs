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

/// The largest single object (decoded/decompressed canonical bytes) this
/// system will accept from an untrusted source — a pack record's compressed
/// payload, its decompressed output, or a wire frame body. This is the
/// single anchor for every untrusted-length DoS guard added in P28: caps are
/// expressed relative to this constant rather than re-picked ad hoc at each
/// call site, so one number bounds "how big can one object get" everywhere.
/// 256 MiB comfortably exceeds any legitimate single object in this system
/// (blobs, trees, snapshots, secrets) while still bounding a malicious
/// peer's ability to force multi-GB allocations from a few header bytes.
pub const MAX_OBJECT_SIZE: usize = 256 * 1024 * 1024; // 256 MiB

pub use error::{Error, Result};
pub use id::ObjectId;
pub use object::{
    EntryKind, FileMode, Object, ProtectPrefix, Protection, RecipientEntry, RecipientState,
    Secret, SignatureObj, Snapshot, Tree, TreeEntry, WrappedKey, PROTECTED,
};
pub use store::{Backend, SpillPolicy, Store, StoreConfig, StoreStats};
