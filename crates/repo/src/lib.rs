//! `scl-repo` — the durable on-disk repository: `.sc/` layout, refs/HEAD,
//! named branches, a git-like working tree, and commit/secret orchestration.

pub mod diff3;
pub mod scanner;
pub mod textdiff;
pub mod scanner_patterns;
pub mod error;
pub mod gc;
pub mod ignore;
pub mod git_marks;
pub mod layout;
pub mod lock;
pub mod merge;
pub mod merge_state;
pub mod oplog;
pub mod pick_state;
pub mod protect;
pub mod protect_ops;
pub mod reachable;
pub mod refs;
pub mod remote;
pub mod repo;
pub mod secrets;
pub mod stdio_transport;
pub mod sync;
pub mod transport;
pub mod wire;
pub mod workspace;
pub mod worktree;

pub use error::{Error, Result};
pub use gc::GcStats;
pub use git_marks::MarksStore;
pub use oplog::{OpRecord, UndoOutcome};
pub use remote::{RemoteConfig, RemoteKind};
pub use repo::{Repo, Status};
pub use scanner::ScanReport;
pub use secrets::SecretInfo;
pub use stdio_transport::{open_transport, SshUrl, StdioTransport};
pub use workspace::{HarvestResult, WorkOptions, WorkspaceOutcome};
pub use worktree::Diff;
