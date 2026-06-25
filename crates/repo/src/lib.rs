//! `scl-repo` — the durable on-disk repository: `.sc/` layout, refs/HEAD,
//! named branches, a git-like working tree, and commit/secret orchestration.

pub mod diff3;
pub mod error;
pub mod layout;
pub mod lock;
pub mod refs;
pub mod repo;
pub mod secrets;
pub mod worktree;

pub use error::{Error, Result};
pub use repo::{Repo, Status};
pub use secrets::SecretInfo;
pub use worktree::Diff;
