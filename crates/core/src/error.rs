use crate::id::ObjectId;

/// Errors returned by the content-addressed store and snapshot model.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("object {0} not found")]
    NotFound(ObjectId),

    #[error("path not found in tree: {0}")]
    PathNotFound(String),

    #[error(
        "memory budget exceeded: need {needed} more bytes but only {available} reclaimable \
         under a {budget}-byte blob budget (raise the budget, or enable spill in ephemeral mode)"
    )]
    BudgetExceeded {
        needed: usize,
        available: usize,
        budget: usize,
    },

    #[error("object {0} has wrong kind, expected {1}")]
    WrongKind(ObjectId, &'static str),

    #[error("malformed object: {0}")]
    Malformed(String),

    #[error("corrupt packfile: {0}")]
    PackCorrupt(String),

    #[error("bad pack index: {0}")]
    BadPackIndex(String),

    /// A tree path that must never be written under a checkout (traversal,
    /// NUL, the `.sc` control directory or an alias of it, and on Windows a
    /// separator or drive marker); see [`crate::check_tree_path`].
    #[error("unsafe path in tree: {path:?}: {reason}")]
    UnsafePath {
        path: String,
        reason: crate::pathname::PathRefusal,
    },

    #[error("backend io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
