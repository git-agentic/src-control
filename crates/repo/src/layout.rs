//! On-disk `.sc/` directory layout.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Resolved paths for a repo rooted at the directory containing `.sc/`.
#[derive(Clone, Debug)]
pub struct Layout {
    pub root: PathBuf,
    pub dot_sc: PathBuf,
}

impl Layout {
    /// The directory containing `.sc` for `root`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let dot_sc = root.join(".sc");
        Layout { root, dot_sc }
    }

    /// Search `start` and its ancestors for a `.sc/` directory.
    pub fn discover(start: impl AsRef<Path>) -> Result<Layout> {
        let mut cur = Some(start.as_ref().to_path_buf());
        while let Some(dir) = cur {
            if dir.join(".sc").is_dir() {
                return Ok(Layout::at(dir));
            }
            cur = dir.parent().map(|p| p.to_path_buf());
        }
        Err(Error::NotARepo)
    }

    /// `.sc/objects` — the loose content-addressed object store.
    pub fn objects_dir(&self) -> PathBuf {
        self.dot_sc.join("objects")
    }
    /// `.sc/refs/heads` — the directory holding one file per branch.
    pub fn refs_heads_dir(&self) -> PathBuf {
        self.dot_sc.join("refs").join("heads")
    }
    /// `.sc/HEAD` — the symbolic ref naming the current branch.
    pub fn head_path(&self) -> PathBuf {
        self.dot_sc.join("HEAD")
    }
    /// `.sc/lock` — the single-writer lock file.
    pub fn lock_path(&self) -> PathBuf {
        self.dot_sc.join("lock")
    }
    /// `.sc/refs/heads/<branch>` — the ref file for a named branch.
    pub fn ref_path(&self, branch: &str) -> PathBuf {
        self.refs_heads_dir().join(branch)
    }

    /// `.sc/refs/remotes` — remote-tracking refs, one dir per remote.
    pub fn refs_remotes_dir(&self) -> PathBuf {
        self.dot_sc.join("refs").join("remotes")
    }
    /// `.sc/refs/remotes/<remote>/<branch>` — a remote-tracking ref file.
    pub fn remote_ref_path(&self, remote: &str, branch: &str) -> PathBuf {
        self.refs_remotes_dir().join(remote).join(branch)
    }
    /// `.sc/config` — remotes and other repo config.
    pub fn config_path(&self) -> PathBuf {
        self.dot_sc.join("config")
    }
    /// `.sc/oplog` — the append-only operation log.
    pub fn oplog_path(&self) -> PathBuf {
        self.dot_sc.join("oplog")
    }
    /// `.sc/signatures` — the append-only snapshot-signature index (P22):
    /// one `<snapshot-hex> <sig-object-hex>` line per indexed signature.
    pub fn signatures_path(&self) -> PathBuf {
        self.dot_sc.join("signatures")
    }
    /// `.sc/sparse` — the sparse-checkout prefix spec (P24): one prefix per
    /// line. Absent means full materialization (no sparseness).
    pub fn sparse_path(&self) -> PathBuf {
        self.dot_sc.join("sparse")
    }
    /// `.sc/transcripts` — the append-only snapshot->transcript index (P30):
    /// one `<snapshot-hex> <transcript-hex>` line per attachment
    /// (one-to-many — a snapshot can have multiple transcripts).
    pub fn transcripts_path(&self) -> PathBuf {
        self.dot_sc.join("transcripts")
    }
    /// `.sc/tmp` — scratch space for transient files (P25 streaming pack
    /// transfer: spilled sender/receiver pack bodies). Never durable state —
    /// safe to delete at any time; callers that write here are responsible
    /// for their own RAII cleanup (see `transport::TempPackGuard`).
    pub fn tmp_dir(&self) -> PathBuf {
        self.dot_sc.join("tmp")
    }
    /// `.sc/serve-tls/` — the server's TLS identity (`cert.pem` + `key.pem`),
    /// auto-minted on first `sc serve --http … --tls` (P32). The key IS the
    /// identity: it is regenerated only when missing.
    pub fn serve_tls_dir(&self) -> PathBuf {
        self.dot_sc.join("serve-tls")
    }
    /// `.sc/promisor` — the partial-clone marker (P27): line 1 `origin
    /// <url>`, then one fetch-filter prefix per line. Absent means a full
    /// clone (every object was fetched, nothing is a promised gap).
    pub fn promisor_path(&self) -> PathBuf {
        self.dot_sc.join("promisor")
    }
    /// `.sc/serve-tokens.toml` — server access-control tokens (P29): each entry is
    /// `{label, hash = BLAKE3(raw token), scope}`. Presence of ≥1 entry turns on
    /// bearer auth for `sc serve --http`. Distinct from `recipients.toml`
    /// (encryption/signing trust); this is server access control.
    pub fn serve_tokens_path(&self) -> PathBuf {
        self.dot_sc.join("serve-tokens.toml")
    }

    /// `.sc/local-key` — per-repo random key for the P33 unchanged-detection
    /// cache's keyed hashes. Never committed, never transferred.
    pub fn local_key_path(&self) -> PathBuf {
        self.dot_sc.join("local-key")
    }

    /// `.sc/protected-cache` — the main working tree's P33 stat cache.
    pub fn protected_cache_path(&self) -> PathBuf {
        self.dot_sc.join("protected-cache")
    }

    /// `.sc/ws/cache-<i>` — workspace `i`'s P33 stat cache. Lives BESIDE the
    /// checkout dir (`.sc/ws/<i>/`), never inside it, so harvest's worktree
    /// read can't pick it up as an untracked file.
    pub fn ws_cache_path(&self, i: usize) -> PathBuf {
        self.dot_sc.join("ws").join(format!("cache-{i}"))
    }
}
