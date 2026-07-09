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
    #[error("no protected prefix matches: {0}")]
    NotProtected(String),
    #[error("identity is not authorized for protected prefix: {0}")]
    NotAuthorized(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("operation requires at least one commit (branch is unborn)")]
    Unborn,
    #[error("a merge is already in progress (resolve and `sc commit`, or `sc merge --abort`)")]
    MergeInProgress,
    #[error("nothing to undo")]
    NothingToUndo,
    #[error("merge produced {0} conflict(s); resolve the marked files then `sc commit`")]
    MergeConflicts(usize),
    #[error("a cherry-pick is already in progress (resolve the marked files then `sc commit`)")]
    PickInProgress,
    #[error("a rebase is already in progress (resolve and `sc rebase --continue`, or `sc rebase --abort`)")]
    RebaseInProgress,
    #[error("cherry-pick produced {0} conflict(s); resolve the marked files then `sc commit`")]
    PickConflicts(usize),
    #[error("protected path {0} changed on both sides; re-run with --identity <key> to merge its content")]
    ProtectedMergeNeedsIdentity(String),
    #[error("{0} sits under a path this partial clone never fetched; cannot commit content there — run `sc backfill` to fetch that subtree first")]
    GappedPathContent(String),
    #[error("{0} lies outside this partial clone's fetch filter; run `sc backfill {0}` to fetch it first")]
    GapOutsideFilter(String),
    /// A dedicated, non-path-shaped refusal for an operation that isn't
    /// supported on a partial clone at all (merge, cherry-pick/rebase
    /// replay, `sc ws harvest`, `sc work`) — distinct from
    /// [`Error::GapOutsideFilter`], whose `{0}` is a real path fed into `sc
    /// backfill <path>`. Feeding these guards' free-text operation
    /// descriptions through `GapOutsideFilter` produced a garbled,
    /// non-actionable message (P27 Task 5 review); this variant's `{0}` is
    /// just the operation name and the message never implies a bare
    /// `sc backfill` with no prefix would fix it — these operations need a
    /// full clone (or a full backfill of every prefix), not one path.
    #[error("{0} is not supported on a partial clone; run `sc backfill --all` to convert to a full clone first")]
    PartialCloneUnsupported(String),
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
    #[error("wire protocol error: {0}")]
    Protocol(String),
    #[error("connection to remote lost: {0}")]
    ConnectionLost(String),
    #[error("remote error: {0}")]
    Remote(String),
    #[error(
        "secret {0} changed differently on both branches; resolve with `sc secret` then retry"
    )]
    SecretMergeConflict(String),
    /// Refused to replay a merge commit. Field 1 is the full, call-site-
    /// contextualized message: `cherry_pick`'s `replay_commit` guard points
    /// at `--mainline <N>` (a real remedy there); rebase's merge-in-range
    /// pre-scan has no such flag (rebase replays a whole linear range, not
    /// one commit), so it names rebase and suggests linearizing/dropping the
    /// commit instead (P19 review fix — the two call sites share one
    /// variant, contextualized like `ProtectedMergeNeedsIdentity`/
    /// `NotAuthorized` are in `replay.rs`'s rebase fold).
    #[error("{1}")]
    CannotReplayMerge(ObjectId, String),
    #[error(transparent)]
    Core(#[from] scl_core::Error),
    #[error(transparent)]
    Vfs(#[from] scl_vfs::Error),
    #[error(transparent)]
    Crypto(#[from] scl_crypto::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The server rejected a mutating verb because the connection is read-only
    /// (`--read-only` or an `ro`-scope token). P29.
    #[error("server is read-only")]
    ReadOnly,
}

pub type Result<T> = std::result::Result<T, Error>;
