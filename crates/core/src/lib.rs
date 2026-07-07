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

pub use error::{Error, Result};
pub use id::ObjectId;
pub use object::{
    EntryKind, FileMode, Object, ProtectPrefix, Protection, RecipientEntry, RecipientState,
    Secret, Snapshot, Tree, TreeEntry, WrappedKey, PROTECTED,
};
pub use store::{Backend, SpillPolicy, Store, StoreConfig, StoreStats};
