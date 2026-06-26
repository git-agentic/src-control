//! Errors for the persistent repository layer.

use scl_core::ObjectId;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a src-control repo (no .sc directory at or above the working dir)")]
    NotARepo,
    #[error("a repo already exists at {0}")]
    RepoExists(String),
    #[error("repo is locked by another process (remove {0} if stale)")]
    Locked(String),
    #[error("object {0} is corrupt (failed hash verification on read)")]
    CorruptObject(ObjectId),
    #[error("malformed ref: {0}")]
    BadRef(String),
    #[error("bad config: {0}")]
    BadConfig(String),
    #[error("branch not found: {0}")]
    NoSuchBranch(String),
    #[error("secret not found: {0}")]
    NoSuchSecret(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("operation requires at least one commit (branch is unborn)")]
    Unborn,
    #[error("a merge is already in progress (resolve and `sc commit`, or `sc merge --abort`)")]
    MergeInProgress,
    #[error("merge produced {0} conflict(s); resolve the marked files then `sc commit`")]
    MergeConflicts(usize),
    #[error("already up to date")]
    UpToDate,
    #[error("{0}")]
    SecretDetected(crate::scanner::ScanReport),
    #[error("non-fast-forward: the remote has commits you don't have; fetch + merge first")]
    NonFastForward,
    #[error("no such remote: {0}")]
    NoSuchRemote(String),
    #[error("remote already exists: {0}")]
    RemoteExists(String),
    #[error("no common ancestor between the branches")]
    NoCommonAncestor,
    #[error("secret {0} changed differently on both branches; resolve with `sc secret` then retry")]
    SecretMergeConflict(String),
    #[error(transparent)]
    Core(#[from] scl_core::Error),
    #[error(transparent)]
    Vfs(#[from] scl_vfs::Error),
    #[error(transparent)]
    Crypto(#[from] scl_crypto::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
