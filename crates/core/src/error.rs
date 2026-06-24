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
         under a {budget}-byte blob budget (enable spill to grow beyond RAM)"
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

    #[error("spill backend io error: {0}")]
    Spill(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
