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
    /// The named branch is private and the caller either provided no identity
    /// or one that is not a recipient of the branch KEK (P34, ADR-0044).
    #[error("branch {0} is private; provide a recipient --identity to access it")]
    PrivateNoAccess(String),
    /// An operation that is not supported on a private branch (P34). `{0}` is
    /// the operation name; the covering flows are `sc branch publish` (make
    /// it public) or performing the operation on a public branch.
    #[error("{0} is not supported on a private branch (publish it first: `sc branch publish`)")]
    PrivateUnsupported(String),
    /// Integrating FROM a private branch INTO a public one is always refused:
    /// decrypting sealed content into public objects is publishing, and the
    /// only sanctioned path to that is the one loudly-named command (P34).
    #[error("cannot integrate private branch {0} into a public branch; use `sc branch publish {0}` to make it public first")]
    PrivateIntegration(String),
    /// A `sc branch grant/revoke/publish` target that is not a private branch.
    #[error("branch {0} is not private")]
    NotPrivateBranch(String),
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
    #[error("TLS: {0}")]
    Tls(#[from] scl_tlsio::Error),
    #[error(
        "sc+https server key for {host} does not match the pinned fingerprint ({file})\n  \
         pinned: {pinned}\n  server: {seen}\n\
         If the server key legitimately changed, remove that host's line from the pin file \
         and reconnect (the next connect re-pins); verify with `sc serve fingerprint` on the server."
    )]
    TlsPinMismatch {
        host: String,
        file: String,
        pinned: String,
        seen: String,
    },
    #[error(
        "sc+https host {0} is not pinned and SC_HTTPS_STRICT=1 refuses unknown hosts; \
         pre-pin with SC_HTTPS_FINGERPRINT=sha256:<hex> or connect once without SC_HTTPS_STRICT"
    )]
    TlsStrictUnknownHost(String),
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
    /// The server aborted an incoming pack mid-stream because it exceeded the
    /// operator's `--max-pack-size` cap (P31). Payload is the server's own
    /// human-readable limit text, carried verbatim across the wire.
    #[error("pack exceeds the server's --max-pack-size limit: {0}")]
    PackTooLarge(String),
    /// The server refused the connection at accept time because
    /// `--max-connections` was reached (P31). Retryable.
    #[error("server busy (connection limit reached); retry later")]
    ServerBusy,
}

pub type Result<T> = std::result::Result<T, Error>;
