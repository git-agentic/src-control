//! Durable agent-workspace sessions (P20): `sc ws fork/list/abandon`.
//!
//! Unlike `sc work` (P13), a `sc ws` session is not a single blocking call —
//! it survives the process exiting. `sc ws fork` materializes N checkouts
//! under `.sc/ws/<i>/` and persists a manifest (`.sc/ws/session.toml`)
//! recording the base snapshot/branch and each workspace's directory and
//! liveness; a later `sc ws` invocation (possibly a different process, even a
//! different day) reads that manifest back. Fork does not touch the user's
//! working tree, HEAD, or the current branch, and a session is NOT a blocking
//! state for other operations — only harvest (a later task) refuses to run
//! during an in-progress merge/pick/rebase, mirroring `sc work`'s harvest
//! path, not fork itself.
//!
//! Manifest storage is TOML via `serde` (already a `scl-repo` dependency,
//! same as `.sc/config`'s `RemoteConfig` in `remote.rs`) — `ObjectId` has no
//! `serde` impl, so it round-trips through its hex string, mirroring how
//! `rebase_state.rs` stores ids as hex text. Key material is NEVER stored
//! here (same discipline as `REBASE_STATE`/`PICK_STATE`): `ws_fork` takes an
//! identity only to decrypt protected paths at materialization time, and it
//! is never written to the manifest.

use std::path::PathBuf;
use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::refs;
use crate::repo::Repo;
use crate::worktree;

/// One workspace's manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsEntry {
    /// The workspace's 1-based position among the session's forks.
    pub index: u32,
    /// `.sc/ws/<index>/`, absolute.
    pub dir: PathBuf,
    /// False once harvested or abandoned; the entry is kept (not removed)
    /// so `sc ws list` can still show what happened to it.
    pub live: bool,
    /// Set only when this entry's resolution was `Landed` (or the
    /// idempotent `UpToDate` no-op landing) — the tip it merged onto the
    /// landing branch. `None` for a manual `ws_abandon`, an `Unchanged`
    /// resolution, or a `FallbackBranch`. Lets `sc ws list` tell a true
    /// landing apart from a plain abandon, and — by checking whether this
    /// tip is still an ancestor of the landing branch — a landing that was
    /// since undone (P21).
    pub landed_tip: Option<ObjectId>,
}

/// An unfinished `sc ws refresh` (ADR-0056): where it was moving the session and,
/// per workspace, the two snapshots it was turning one into the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRefresh {
    /// The tip the session is being moved to.
    pub target: ObjectId,
    /// The branch `target` is the tip of (becomes `base_branch` on completion).
    pub branch: String,
    /// One entry per workspace that was live when the refresh began.
    pub workspaces: Vec<PendingWs>,
    /// Pids of the `sc` processes that have written for this refresh (the first
    /// attempt and each retry). A killed writer's staging files are removed only
    /// under one of these pids.
    pub writers: Vec<u32>,
}

/// One workspace of a [`PendingRefresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWs {
    pub index: u32,
    /// The checkout as the refresh read it (parent: the old base).
    pub candidate: ObjectId,
    /// What the checkout becomes: the candidate replayed onto `target`.
    pub result: ObjectId,
}

/// The session manifest (`.sc/ws/session.toml`). Never stores key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsSession {
    /// `None` for the unnamed session (`.sc/ws`), `Some(name)` for a named one
    /// (`.sc/ws-<name>`, ADR-0056). Derived from where the manifest lives and
    /// never stored in it, so the format is unchanged.
    pub name: Option<String>,
    /// The snapshot every workspace was forked from.
    pub base_snapshot: ObjectId,
    /// The branch `base_snapshot` was the tip of at fork time (display only).
    pub base_branch: String,
    /// The author recorded on any commit a later harvest produces.
    pub author: String,
    /// The host repo's sparse-checkout prefixes AT FORK TIME (empty = full),
    /// recorded so a later `sc ws harvest` diffs and commits against the view
    /// each workspace was actually given — never the host's possibly-since-
    /// changed live spec (P24 final-review fix, Critical 1). A workspace was
    /// materialized under this exact spec (`materialize_workspace` in
    /// `ws_fork`); if the host's `.sc/sparse` changes before harvest, the
    /// workspace itself does not silently reinterpret what it was shown.
    /// `#[serde(default)]` on the TOML side lets a pre-P24-final-review
    /// manifest (no `sparse` key) parse as empty/full, matching that
    /// manifest's actual behavior (sparse checkouts didn't exist yet).
    pub sparse: Vec<String>,
    /// Set while a `sc ws refresh` is writing its checkouts, cleared when it
    /// completes. A set marker means the checkouts may hold a mix of old and
    /// refreshed files, so harvest and run refuse until refresh is run again
    /// (ADR-0056); it records what the refresh was writing, so the retry can
    /// finish it. Absent from older manifests.
    pub pending_refresh: Option<PendingRefresh>,
    pub workspaces: Vec<WsEntry>,
}

pub(crate) fn ws_dir(layout: &Layout, name: Option<&str>) -> PathBuf {
    layout.ws_root(name)
}

fn manifest_path(layout: &Layout, name: Option<&str>) -> PathBuf {
    ws_dir(layout, name).join("session.toml")
}

/// The prefix of a session's fallback branches and `SC_WORKSPACE` label:
/// `work` for the unnamed session (unchanged), the session name otherwise,
/// matching `sc work --name`.
pub(crate) fn label_prefix(name: Option<&str>) -> &str {
    name.unwrap_or("work")
}

/// `<session root>/running-<i>`: written (with the pid of the `sc` process
/// that owns the command) while a `sc ws run` command is live in workspace `i`,
/// so harvest and abandon, which now work while the command runs, can refuse
/// instead of landing a half-written checkout or deleting it under the agent.
/// Beside the checkout dir, never inside it, like the stat cache.
fn running_path(layout: &Layout, name: Option<&str>, i: u32) -> PathBuf {
    ws_dir(layout, name).join(format!("running-{i}"))
}

/// Refuse if a `sc ws run` command is still live in workspace `i`. The marker
/// names the `sc` process and, once spawned, its child (an orphaned child keeps
/// the workspace busy after `sc` is killed). It is cleared only when every
/// recorded pid is provably dead (the repo lock's probe); an unreadable or
/// empty marker counts as busy.
pub(crate) fn ensure_idle(layout: &Layout, name: Option<&str>, i: u32) -> Result<()> {
    let path = running_path(layout, name, i);
    if path.exists() {
        let pids: Vec<u32> = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .collect();
        if pids.is_empty() || !pids.iter().all(|&p| crate::lock::pid_is_dead(p)) {
            return Err(Error::InvalidArgument(format!(
                "workspace {i} has a `sc ws run` command still running ({}); \
                 wait for it to exit",
                path.display()
            )));
        }
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

/// A session name is a branch-name component (its fallback branches are
/// `<name>-<i>`) and a directory name under `.sc/`, so it takes the branch-name
/// grammar.
fn validate_session_name(name: &str) -> Result<()> {
    crate::repo::validate_branch_name(name)
        .map_err(|_| Error::InvalidArgument(format!("invalid session name: {name:?}")))
}

fn bad(msg: impl Into<String>) -> Error {
    Error::BadRef(format!("session.toml: {}", msg.into()))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EntryToml {
    index: u32,
    dir: String,
    live: bool,
    // Backward-parse pattern (matches `rebase_state.rs`'s counters): absent
    // in pre-P21 manifests, defaults to `None`.
    #[serde(default)]
    landed_tip: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionToml {
    base_snapshot: String,
    base_branch: String,
    author: String,
    // Absent in pre-P24-final-review manifests, defaults to empty (full
    // checkout) — matches those manifests' actual pre-sparse-checkout
    // behavior.
    #[serde(default)]
    sparse: Vec<String>,
    #[serde(default)]
    pending_refresh: Option<PendingToml>,
    #[serde(default)]
    workspace: Vec<EntryToml>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingToml {
    target: String,
    branch: String,
    #[serde(default)]
    writers: Vec<u32>,
    #[serde(default)]
    workspace: Vec<PendingWsToml>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingWsToml {
    index: u32,
    candidate: String,
    result: String,
}

impl From<&WsSession> for SessionToml {
    fn from(s: &WsSession) -> Self {
        SessionToml {
            base_snapshot: s.base_snapshot.to_hex(),
            base_branch: s.base_branch.clone(),
            author: s.author.clone(),
            sparse: s.sparse.clone(),
            pending_refresh: s.pending_refresh.as_ref().map(|p| PendingToml {
                target: p.target.to_hex(),
                branch: p.branch.clone(),
                writers: p.writers.clone(),
                workspace: p
                    .workspaces
                    .iter()
                    .map(|w| PendingWsToml {
                        index: w.index,
                        candidate: w.candidate.to_hex(),
                        result: w.result.to_hex(),
                    })
                    .collect(),
            }),
            workspace: s
                .workspaces
                .iter()
                .map(|e| EntryToml {
                    index: e.index,
                    dir: e.dir.display().to_string(),
                    live: e.live,
                    landed_tip: e.landed_tip.map(|t| t.to_hex()),
                })
                .collect(),
        }
    }
}

impl SessionToml {
    fn into_session(raw: SessionToml, name: Option<&str>) -> Result<WsSession> {
        let base_snapshot = ObjectId::from_str(&raw.base_snapshot)
            .map_err(|_| bad(format!("bad base_snapshot: {}", raw.base_snapshot)))?;
        let workspaces = raw
            .workspace
            .into_iter()
            .map(|e| {
                let landed_tip = e
                    .landed_tip
                    .map(|t| {
                        ObjectId::from_str(&t).map_err(|_| bad(format!("bad landed_tip: {t}")))
                    })
                    .transpose()?;
                Ok(WsEntry {
                    index: e.index,
                    dir: PathBuf::from(e.dir),
                    live: e.live,
                    landed_tip,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let id = |what: &str, t: &str| {
            ObjectId::from_str(t).map_err(|_| bad(format!("bad pending_refresh {what}: {t}")))
        };
        let pending_refresh = raw
            .pending_refresh
            .map(|p| -> Result<PendingRefresh> {
                Ok(PendingRefresh {
                    target: id("target", &p.target)?,
                    branch: p.branch,
                    writers: p.writers,
                    workspaces: p
                        .workspace
                        .iter()
                        .map(|w| {
                            Ok(PendingWs {
                                index: w.index,
                                candidate: id("candidate", &w.candidate)?,
                                result: id("result", &w.result)?,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                })
            })
            .transpose()?;
        Ok(WsSession {
            name: name.map(str::to_string),
            base_snapshot,
            base_branch: raw.base_branch,
            author: raw.author,
            sparse: raw.sparse,
            pending_refresh,
            workspaces,
        })
    }
}

/// Read one session's manifest (`None` = the unnamed session), if open.
pub(crate) fn read_manifest(layout: &Layout, name: Option<&str>) -> Result<Option<WsSession>> {
    if let Some(n) = name {
        // `--session` reaches here unchecked; a `..` must not leave `.sc/`.
        validate_session_name(n)?;
    }
    match std::fs::read_to_string(manifest_path(layout, name)) {
        Ok(text) => {
            let raw: SessionToml =
                toml::from_str(&text).map_err(|e| bad(format!("malformed: {e}")))?;
            SessionToml::into_session(raw, name).map(Some)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Every open session: the unnamed one first, then named ones by name. A
/// `.sc/ws-*` directory with no manifest is crash residue and is skipped.
/// `pub(crate)` so `gc.rs` can root every base snapshot without a `Repo`.
pub(crate) fn list_sessions(layout: &Layout) -> Result<Vec<WsSession>> {
    let mut out: Vec<WsSession> = read_manifest(layout, None)?.into_iter().collect();
    let mut names = Vec::new();
    for e in std::fs::read_dir(&layout.dot_sc)? {
        let e = e?;
        let file = e.file_name();
        // A stray file or oddly named entry must not break gc or `ws list`.
        if let Some(n) = file.to_str().and_then(|f| f.strip_prefix("ws-")) {
            if e.path().is_dir() && validate_session_name(n).is_ok() {
                names.push(n.to_string());
            }
        }
    }
    names.sort();
    for n in names {
        out.extend(read_manifest(layout, Some(&n))?);
    }
    Ok(out)
}

/// The open session called `name`, or an error naming what is open instead.
pub(crate) fn open_session(layout: &Layout, name: Option<&str>) -> Result<WsSession> {
    if let Some(s) = read_manifest(layout, name)? {
        return Ok(s);
    }
    let open: Vec<String> = list_sessions(layout)?
        .iter()
        .map(|s| s.name.clone().unwrap_or_else(|| "(unnamed)".into()))
        .collect();
    Err(Error::InvalidArgument(match (name, open.is_empty()) {
        (_, true) => "no workspace session open".into(),
        (None, false) => format!(
            "no unnamed workspace session open (open: {}); pass --session <name>",
            open.join(", ")
        ),
        (Some(n), false) => format!(
            "no workspace session named '{n}' open (open: {})",
            open.join(", ")
        ),
    }))
}

/// Write the session manifest atomically. The parent dir must already exist
/// (fork/abandon create it before the first write).
pub(crate) fn write_manifest(layout: &Layout, session: &WsSession) -> Result<()> {
    let raw: SessionToml = session.into();
    let text = toml::to_string(&raw).map_err(|e| Error::BadConfig(e.to_string()))?;
    let path = manifest_path(layout, session.name.as_deref());
    scl_core::fsutil::atomic_write_durable(&path, text.as_bytes())?;
    Ok(())
}

impl Repo {
    /// Fork `agents` durable workspaces from HEAD: `.sc/ws/<1..agents>/` are
    /// materialized (same P7-aware call `sc work`'s temp checkouts use) and a
    /// manifest is written last, so a crash mid-fork never announces a
    /// half-built session. Refuses if a session is already open (abandon it
    /// first) or the branch is unborn. Never touches HEAD, the current
    /// branch, or the user's working tree.
    pub fn ws_fork(
        &self,
        name: Option<&str>,
        agents: u32,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsSession> {
        self.refuse_on_private("sc ws fork")?;
        if agents == 0 {
            return Err(Error::InvalidArgument("agents must be >= 1".into()));
        }
        if let Some(n) = name {
            validate_session_name(n)?;
        }
        if let Some(existing) = read_manifest(self.layout(), name)? {
            let (which, abandon) = match name {
                None => (String::new(), "sc ws abandon".to_string()),
                Some(n) => (format!(" '{n}'"), format!("sc ws abandon --session {n}")),
            };
            return Err(Error::InvalidArgument(format!(
                "a workspace session{which} is already open ({} workspace(s) forked from branch {} @ {}); \
                 run `{abandon}` first",
                existing.workspaces.len(),
                existing.base_branch,
                existing.base_snapshot.short(),
            )));
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let branch = refs::current_branch(self.layout())?;
        // A durable `sc ws` workspace inherits the host repo's sparse view
        // (P24 Task 4) — unlike `sc work`'s one-shot ephemeral agents, a
        // durable session is closer to a second working tree for the same
        // repo, so it should see the same narrowed checkout the user does.
        let sparse = self.sparse_spec()?;
        // On a partial clone the workspaces see the host's view and nothing
        // more (ADR-0050): fill its closure first (lazy, online clones), or
        // fail with the gap error before any checkout is written.
        let tip_root = self.snapshot(&tip)?.root;
        self.ensure_view(tip_root, &sparse)?;
        // `ensure_view` fills only when it can; on a non-lazy or offline clone
        // the view may still hold a gap. Check presence against the HOST's
        // layout now: a workspace's own layout is not a partial clone, so its
        // materialize would not, and the gap would surface mid-write.
        {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            crate::worktree::preflight_view(self.layout(), &mut store, tip_root, &sparse)?;
        }

        let root = ws_dir(self.layout(), name);
        // No manifest proves any .sc/ws content is crash residue from a
        // killed fork — always safe to clear before materializing.
        let _ = std::fs::remove_dir_all(&root);
        // Per-workspace P33 cache key (host's `.sc/local-key`), minted once.
        let key = crate::cache::local_key(self.layout())?;
        let mut workspaces = Vec::with_capacity(agents as usize);
        for i in 1..=agents {
            let dir = root.join(i.to_string());
            // Persistent per-workspace cache (P33 Task 7): `root` is THIS
            // checkout dir, file at `.sc/ws/cache-<i>` (beside the checkout,
            // under `ws_dir`, so the whole-session teardown removes it too).
            // Records every randomized protected path decrypted at fork so a
            // later `sc ws harvest` (a separate invocation) carries the base
            // blob instead of re-sealing an untouched file.
            let mut cache = crate::cache::ProtectedCache::open(
                key,
                dir.clone(),
                Some(self.layout().ws_cache_path(name, i as usize)),
            );
            if let Err(e) = crate::workspace::materialize_workspace(
                self,
                tip,
                &dir,
                identity,
                &sparse,
                Some(&mut cache),
            ) {
                // Nothing announced yet (no manifest written) — tear down
                // whatever partial checkouts exist so a failed fork leaves
                // no residue under .sc/ws.
                let _ = std::fs::remove_dir_all(&root);
                return Err(e);
            }
            cache.save_best_effort();
            workspaces.push(WsEntry {
                index: i,
                dir,
                live: true,
                landed_tip: None,
            });
        }

        let session = WsSession {
            name: name.map(str::to_string),
            base_snapshot: tip,
            base_branch: branch,
            author: author.to_string(),
            sparse: sparse.prefixes().to_vec(),
            pending_refresh: None,
            workspaces,
        };
        write_manifest(self.layout(), &session)?;
        Ok(session)
    }

    /// The manifest of session `name` (`None` = the unnamed one), if open.
    pub fn ws_session(&self, name: Option<&str>) -> Result<Option<WsSession>> {
        read_manifest(self.layout(), name)
    }

    /// Every open session, the unnamed one first, then named ones by name.
    pub fn ws_sessions(&self) -> Result<Vec<WsSession>> {
        list_sessions(self.layout())
    }

    /// True if `entry`'s checkout has diverged from the session's base
    /// snapshot. Mirrors `harvest_workspace`'s diff check exactly (repeated,
    /// not extracted — `harvest_workspace` diffs against the harvest's own
    /// `tip` argument, not a manifest, and the two call sites have no shared
    /// caller worth threading a helper through for five lines). Re-reads and
    /// re-parses the manifest on every call; callers that already hold a
    /// loaded `WsSession` (e.g. `sc ws list`'s and `ws_harvest`'s per-entry
    /// loops) should call [`Self::ws_changed_for`] instead (P21).
    pub fn ws_changed(&self, name: Option<&str>, entry: &WsEntry) -> Result<bool> {
        let session = open_session(self.layout(), name)?;
        self.ws_changed_for(&session, entry)
    }

    /// Like [`Self::ws_changed`], but takes an already-loaded `session`
    /// instead of re-reading and re-parsing `session.toml` — a `sc ws list`
    /// over N workspaces used to parse the manifest N times for one listing
    /// (P21).
    pub fn ws_changed_for(&self, session: &WsSession, entry: &WsEntry) -> Result<bool> {
        let base = self.snapshot(&session.base_snapshot)?;
        let ws = Layout::at(&entry.dir);
        // Sparse-aware (P24 Task 4). Uses the session's own FORK-TIME spec,
        // not the host's current one (P24 final-review fix, Critical 1): the
        // workspace was materialized under `session.sparse`, and a `sparse
        // set`/`disable` on the host between fork and this check must not
        // reinterpret an unmaterialized out-of-sparse path as a deletion.
        let sparse = crate::sparse::Sparse::new(session.sparse.clone());
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        // The workspace's own persistent P33 cache, read-only (this is a
        // status/list/preflight query, never a harvest, so nothing is
        // recorded or saved back) — same open-call shape as `ws_harvest`
        // (below), rooted at the workspace's own checkout dir so an
        // untouched RANDOMIZED protected path is recognized as unchanged
        // instead of always reporting modified. Degrades to `None` (never
        // errors) if the host's cache key can't be loaded/minted: this must
        // stay a non-fatal query path, and a lost cache only ever costs the
        // stat/tag short-circuit, never correctness.
        let cache = crate::cache::local_key(self.layout()).ok().map(|key| {
            crate::cache::ProtectedCache::open(
                key,
                entry.dir.clone(),
                Some(
                    self.layout()
                        .ws_cache_path(session.name.as_deref(), entry.index as usize),
                ),
            )
        });
        let d = worktree::diff_worktree(
            &ws,
            &mut store,
            Some(base.root),
            &base.protection,
            &sparse,
            cache.as_ref(),
        )?;
        Ok(!(d.added.is_empty() && d.modified.is_empty() && d.deleted.is_empty()))
    }

    /// A human-readable status for `sc ws list`: `"changed"`/`"unchanged"`
    /// for a live entry, `"abandoned"` for a manual `ws_abandon` or a
    /// resolution that never landed (`Unchanged`/`FallbackBranch`), and —
    /// truthfully distinguishing the case that used to also print
    /// "abandoned" — `"landed"` or `"landed (undone by sc undo)"` for a
    /// resolved entry that landed a merge, depending on whether
    /// `entry.landed_tip` is still an ancestor of `session.base_branch`'s
    /// current tip (P21). Missing landing-branch tip (deleted/unborn) is
    /// treated as undone.
    ///
    /// Known limitation: the manifest doesn't record which branch each
    /// entry actually landed onto (`ws_harvest`'s `--into` can differ from
    /// `base_branch`), so a workspace harvested with `--into <other>` is
    /// ancestry-checked against `base_branch` regardless — it can
    /// misreport "undone" for a landing that is intact on `<other>`. Out
    /// of scope for this pass: storing a per-entry landing branch is a
    /// manifest schema change beyond a label fix, and the common case
    /// (default landing branch) is unaffected.
    pub fn ws_status_label(&self, session: &WsSession, entry: &WsEntry) -> Result<String> {
        if entry.live {
            return Ok(if self.ws_changed_for(session, entry)? {
                "changed".to_string()
            } else {
                "unchanged".to_string()
            });
        }
        match entry.landed_tip {
            None => Ok("abandoned".to_string()),
            Some(landed_tip) => {
                let current = refs::read_branch_tip(self.layout(), &session.base_branch)?;
                let still_landed = match current {
                    Some(tip) => {
                        let store_arc = self.vfs().store();
                        let mut store = store_arc.lock().unwrap();
                        crate::merge::is_ancestor(&mut store, landed_tip, tip)?
                    }
                    None => false,
                };
                Ok(if still_landed {
                    "landed".to_string()
                } else {
                    "landed (undone by sc undo)".to_string()
                })
            }
        }
    }

    /// Abandon one workspace (`Some(index)`) or the whole session (`None`):
    /// removes the checkout dir(s) and rewrites the manifest, or removes
    /// `.sc/ws/` entirely once no live workspace remains. Returns the
    /// remaining live count. No oplog record — fork never touched a ref.
    pub fn ws_abandon(&self, name: Option<&str>, index: Option<u32>) -> Result<usize> {
        let mut session = open_session(self.layout(), name)?;
        // Refuse before removing anything if an agent command is live.
        for e in session
            .workspaces
            .iter()
            .filter(|e| e.live && index.is_none_or(|i| i == e.index))
        {
            ensure_idle(self.layout(), name, e.index)?;
        }
        match index {
            Some(i) => {
                let entry = session
                    .workspaces
                    .iter_mut()
                    .find(|e| e.index == i)
                    .ok_or_else(|| Error::InvalidArgument(format!("no such workspace: {i}")))?;
                if entry.live {
                    let _ = std::fs::remove_dir_all(&entry.dir);
                    // Drop the workspace's P33 stat cache too (sibling file,
                    // not under the checkout dir) — P33 Task 7 item 3.
                    let _ = std::fs::remove_file(
                        self.layout().ws_cache_path(name, entry.index as usize),
                    );
                    entry.live = false;
                }
            }
            None => {
                for e in &mut session.workspaces {
                    e.live = false;
                }
            }
        }
        let remaining = session.workspaces.iter().filter(|e| e.live).count();
        if remaining == 0 {
            let _ = std::fs::remove_dir_all(ws_dir(self.layout(), name));
        } else {
            write_manifest(self.layout(), &session)?;
        }
        Ok(remaining)
    }

    /// Run a command in one workspace checkout. Convenience over
    /// [`Self::ws_run_plan`] + [`WsRunPlan::run`] that keeps this `Repo` (and so
    /// the single-writer lock) alive for the child's lifetime; the CLI drops the
    /// repo between the two so other sessions stay usable meanwhile (ADR-0056).
    pub fn ws_run(
        &self,
        name: Option<&str>,
        index: u32,
        cmd: &[String],
        with_secrets: bool,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<i32> {
        self.ws_run_plan(name, index, with_secrets, identity)?
            .run(cmd)
    }

    /// Resolve everything `ws_run` needs from the repo (the live workspace's
    /// dir, its `SC_WORKSPACE` label and, with `with_secrets`, the decrypted
    /// secret environment) so the caller can release the repo lock before
    /// spawning the possibly long-running command. The workspace must be live
    /// and the session open. No oplog record, no harvest, no manifest rewrite.
    pub fn ws_run_plan(
        &self,
        name: Option<&str>,
        index: u32,
        with_secrets: bool,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsRunPlan> {
        let session = open_session(self.layout(), name)?;
        // A command could delete a file the unfinished refresh wrote, a deletion
        // its retry could not see against the old base.
        if session.pending_refresh.is_some() {
            return Err(Error::InvalidArgument(format!(
                "a `sc ws refresh` did not finish; run `sc ws refresh{}` before `sc ws run`",
                name.map(|n| format!(" --session {n}")).unwrap_or_default()
            )));
        }
        let entry = session
            .workspaces
            .iter()
            .find(|e| e.index == index && e.live)
            .ok_or_else(|| Error::InvalidArgument(format!("no such workspace: {index}")))?;

        // Build secret env vars if requested (strict mode, mirroring `sc work`).
        let envs = if with_secrets {
            let sk = identity.ok_or_else(|| {
                Error::InvalidArgument("--with-secrets requires an identity".into())
            })?;
            self.secret_env(sk, /*strict=*/ true)?
        } else {
            Vec::new()
        };
        // Mark the workspace busy until the command ends (see `running_path`).
        // The marker names this process, which outlives the repo handle: the
        // CLI keeps running the command after dropping the lock.
        ensure_idle(self.layout(), name, index)?;
        let marker = running_path(self.layout(), name, index);
        // Exclusive, so two plans for one workspace cannot both hold it.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(mut f) => {
                if let Err(e) =
                    std::io::Write::write_all(&mut f, std::process::id().to_string().as_bytes())
                {
                    // An empty marker would read as busy forever.
                    let _ = std::fs::remove_file(&marker);
                    return Err(e.into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::InvalidArgument(format!(
                    "workspace {index} has a `sc ws run` command still running ({}); \
                     wait for it to exit",
                    marker.display()
                )))
            }
            Err(e) => return Err(e.into()),
        }
        Ok(WsRunPlan {
            marker,
            dir: entry.dir.clone(),
            // Label matches the fallback-branch namespace a harvest would mint
            // (P13 parity: label == branch name).
            label: format!("{}-{}", label_prefix(name), entry.index),
            envs,
        })
    }

    /// Read-only conflict probe: would merging `theirs` into `ours` land
    /// clean? Composes the same primitives the real merge uses (`three_way` +
    /// `merge_secrets`) but touches neither the working tree nor any ref —
    /// this is what guarantees "no conflict markers land unattended"
    /// (ADR-0030). Identity/authorization shortfalls on protected paths count
    /// as NOT clean (fallback), not errors.
    ///
    /// The follow-up `merge_secrets` call mirrors `three_way`'s own internal
    /// call (same base/ours/theirs registries) and is therefore provably
    /// dead once `three_way` has already returned `Ok`: `three_way` computes
    /// `merge_secrets` *before* the file merge and propagates
    /// `Error::SecretMergeConflict` via `?`, so a secret-only conflict
    /// surfaces through the outer `Err(e) => Err(e)` arm, not this inner
    /// match. That is not a probe/merge disagreement: `merge_with_identity`
    /// (repo.rs:900) calls `three_way` the same way, so a secret-only
    /// conflict is a hard `Err` there too — probe and real merge agree.
    fn would_merge_cleanly(
        &self,
        ours: ObjectId,
        theirs: ObjectId,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<bool> {
        // Partial-clone merge guard (P27 Task 5 review Important fix): this
        // probe calls `three_way` directly, bypassing
        // `merge_with_identity`'s own partial-clone refusal — a partial
        // clone landed here at the raw corruption-shaped `NotFound` the
        // guard exists to eliminate. Refuse loudly with the same dedicated
        // error `merge_with_identity` uses, before ever touching
        // `three_way`; propagated via `?` at the call site in `ws_harvest`,
        // this is a hard `Err`, never silently folded into the "not clean"
        // fallback path.
        if self.promisor()?.is_some() {
            return self.would_merge_cleanly_partial(ours, theirs, identity);
        }
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        if crate::merge::is_ancestor(&mut store, theirs, ours)? {
            return Ok(true); // nothing to add -> ff-ish no-op
        }
        if crate::merge::is_ancestor(&mut store, ours, theirs)? {
            return Ok(true); // pure ff
        }
        let Some(base) = crate::merge::merge_base(&mut store, ours, theirs)? else {
            return Ok(false);
        };
        // Mirrors merge_with_identity's three_way call (repo.rs:900) exactly:
        // same base/ours/theirs, same identity threading.
        match crate::merge::three_way(&mut store, base, ours, theirs, identity) {
            Ok(m) if !m.conflicts.is_empty() => Ok(false),
            Ok(_) => {
                // Secrets can conflict independently of files (see doc comment
                // above: this call is dead in practice, kept for parity with
                // three_way's own internal check).
                let base_snap = store.get_snapshot(&base)?;
                let ours_snap = store.get_snapshot(&ours)?;
                let theirs_snap = store.get_snapshot(&theirs)?;
                match crate::merge::merge_secrets(
                    &base_snap.secrets,
                    &ours_snap.secrets,
                    &theirs_snap.secrets,
                ) {
                    Ok(_) => Ok(true),
                    Err(Error::SecretMergeConflict(_)) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            // A file/directory collision (ADR-0049) is not a clean merge: this
            // workspace falls back to a `work-<i>` branch like any conflict.
            Err(Error::ProtectedMergeNeedsIdentity(_))
            | Err(Error::NotAuthorized(_))
            | Err(Error::PathCollision(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// [`Self::would_merge_cleanly`] on a partial clone: the same question,
    /// answered with the tree-recursive engine (ADR-0049), which reads only
    /// where the sides differ and fills what it needs by id on a lazy, online
    /// clone. Any conflict, in the view or not, is "not clean": the workspace
    /// then falls back to a `work-<i>` branch like on a full clone.
    fn would_merge_cleanly_partial(
        &self,
        ours: ObjectId,
        theirs: ObjectId,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<bool> {
        let (base_snap, ours_snap, theirs_snap) = {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            if crate::merge::is_ancestor(&mut store, theirs, ours)?
                || crate::merge::is_ancestor(&mut store, ours, theirs)?
            {
                return Ok(true); // a no-op or a pure fast-forward
            }
            let Some(base) = crate::merge::merge_base(&mut store, ours, theirs)? else {
                return Ok(false);
            };
            (
                store.get_snapshot(&base)?,
                store.get_snapshot(&ours)?,
                store.get_snapshot(&theirs)?,
            )
        };
        match crate::merge::merge_secrets(
            &base_snap.secrets,
            &ours_snap.secrets,
            &theirs_snap.secrets,
        ) {
            Ok(_) => {}
            Err(Error::SecretMergeConflict(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
        match self.tree_merge_filled(
            Some((base_snap.root, &base_snap.protection)),
            (ours_snap.root, &ours_snap.protection),
            (theirs_snap.root, &theirs_snap.protection),
            identity,
        ) {
            Ok((done, _)) => Ok(done.merge.conflicts.is_empty()),
            Err(Error::ProtectedMergeNeedsIdentity(_))
            | Err(Error::NotAuthorized(_))
            | Err(Error::PathCollision(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Harvest every live workspace in the open session, landing clean
    /// results cumulatively onto the checked-out landing branch and falling
    /// back to a `work-<i>` branch on conflict, scanner rejection, or an
    /// authorization shortfall. Refuses while a merge/pick/rebase is in
    /// progress. The landing branch (`into`, default the session's base
    /// branch) must be the currently-checked-out branch — the merge
    /// machinery `ws_harvest` reuses whole is head-centric, and reusing it
    /// whole (rather than re-deriving a headless variant) is the point.
    ///
    /// Live workspaces are processed ascending by index so results land in a
    /// deterministic, cumulative order (a later workspace's probe/merge sees
    /// every earlier landing already folded into the landing branch's tip).
    /// The manifest is rewritten after each workspace resolves, so a crash
    /// mid-harvest loses nothing: resolved workspaces are torn down and
    /// recorded, live ones are untouched. Once no live workspace remains,
    /// `.sc/ws/` is removed entirely (the session has ended).
    ///
    /// Landing is at-least-once, not exactly-once: a kill -9 between a
    /// candidate branch landing (the ref-moving `merge_with_identity` call)
    /// and `resolve_and_teardown`'s manifest rewrite leaves the workspace
    /// still marked live, with its checkout dir and content untouched. The
    /// next `sc ws harvest` re-runs that workspace through the full
    /// pipeline, re-minting an IDENTICAL candidate commit (same parent,
    /// tree, author, message — and timestamp, if retried within the same
    /// wall-clock second), which is already reachable from the landing
    /// branch. `merge_with_identity` then returns `Err(UpToDate)` instead of
    /// minting a second merge commit, and that's resolved as an idempotent
    /// no-op `Landed` at the existing tip, not an error — content-safe by
    /// construction (no new commit, no duplicate content), not merely by
    /// accident.
    pub fn ws_harvest(
        &self,
        name: Option<&str>,
        into: Option<&str>,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<Vec<WsHarvestOutcome>> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let mut session = open_session(self.layout(), name)?;
        if session.pending_refresh.is_some() {
            return Err(Error::InvalidArgument(format!(
                "a `sc ws refresh` did not finish and the checkouts may hold a mix of old and \
                 refreshed files; run `sc ws refresh{}` to finish it (or abandon the session)",
                name.map(|n| format!(" --session {n}")).unwrap_or_default()
            )));
        }

        let landing = into.unwrap_or(&session.base_branch).to_string();
        let current = refs::current_branch(self.layout())?;
        if current != landing {
            return Err(Error::InvalidArgument(format!(
                "landing branch '{landing}' is not checked out; run `sc switch {landing}` first"
            )));
        }

        let mut live_indices: Vec<u32> = session
            .workspaces
            .iter()
            .filter(|e| e.live)
            .map(|e| e.index)
            .collect();
        live_indices.sort_unstable();
        // A workspace whose `sc ws run` command is still live is mid-edit:
        // refuse before reading or minting anything.
        for &i in &live_indices {
            ensure_idle(self.layout(), name, i)?;
        }

        // Preflight: if any live workspace actually diverged, a candidate
        // branch is about to be minted for it and landed via
        // `merge_with_identity`, whose own dirty-tree guard fires only
        // *after* `harvest_workspace` has already created that branch — with
        // no CLI command to delete a stray branch, that guard tripping mid-
        // loop leaves permanent residue. Run the same check here, up front,
        // before any `harvest_workspace` call, so a dirty landing tree is
        // refused before anything is minted. A session where every live
        // workspace is unchanged never merges anything, so it still harvests
        // (and ends) even with a dirty tree.
        let any_changed = session
            .workspaces
            .iter()
            .filter(|e| e.live)
            .map(|e| self.ws_changed_for(&session, e))
            .collect::<Result<Vec<bool>>>()?
            .into_iter()
            .any(|changed| changed);
        if any_changed {
            let dirty = self.status()?;
            if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
                return Err(Error::InvalidArgument(
                    "working tree has uncommitted changes; commit before harvesting".into(),
                ));
            }
        }

        // Per-workspace P33 cache key (host's `.sc/local-key`), minted once.
        let key = crate::cache::local_key(self.layout())?;
        let mut outcomes = Vec::with_capacity(live_indices.len());
        for i in live_indices {
            let dir = session
                .workspaces
                .iter()
                .find(|e| e.index == i)
                .expect("index came from this session's own live list")
                .dir
                .clone();
            let entry = WsEntry {
                index: i,
                dir: dir.clone(),
                live: true,
                landed_tip: None,
            };

            // Step 1: unchanged workspaces resolve with no branch created.
            if !self.ws_changed_for(&session, &entry)? {
                resolve_and_teardown(self.layout(), &mut session, i, &dir, None)?;
                outcomes.push(WsHarvestOutcome::Unchanged { index: i });
                continue;
            }

            // Step 2: pick a fallback candidate branch name, suffixed on
            // collision (a prior harvest or a pre-existing branch of the
            // same name).
            let base = format!("{}-{i}", label_prefix(name));
            let mut branch = base.clone();
            let mut suffix = 2;
            while refs::resolve_tip(self.layout(), &branch)?.is_some() {
                branch = format!("{base}-{suffix}");
                suffix += 1;
            }

            // Step 3: run the workspace through the full commit pipeline
            // (scanner gate, protected-path re-encryption) onto the
            // candidate branch. `tip` is the candidate's parent, which per
            // P13's contract is the session's base snapshot, not the
            // landing branch's current (possibly since-advanced) tip.
            let msg = match name {
                None => format!("ws-{i} harvest"),
                Some(n) => format!("ws {n}-{i} harvest"),
            };
            // The session's fork-time spec, not the host's current one (P24
            // final-review fix, Critical 1) — same reasoning as
            // `ws_changed_for` above, now threaded into the commit carry too
            // via `harvest_workspace` -> `snapshot_files`.
            let fork_time_sparse = crate::sparse::Sparse::new(session.sparse.clone());
            // The workspace's persistent P33 cache (`root` = this checkout dir,
            // file at `.sc/ws/cache-<i>`), threaded through the harvest so an
            // untouched randomized protected path carries the base blob instead
            // of re-sealing. Saved best-effort right after harvest: if the entry
            // resolves (teardown removes the cache file too), the save is
            // immediately undone; if it stays live (Rejected/FallbackBranch),
            // the next harvest gets a warm cache.
            let mut cache = crate::cache::ProtectedCache::open(
                key,
                dir.clone(),
                Some(self.layout().ws_cache_path(name, i as usize)),
            );
            let harvested = crate::workspace::harvest_workspace(
                self,
                session.base_snapshot,
                &dir,
                &branch,
                author,
                &msg,
                &fork_time_sparse,
                Some(&mut cache),
            )?;
            cache.save_best_effort();
            match harvested {
                crate::workspace::HarvestResult::Rejected(report) => {
                    // DESIGN DECISION (spec precision note, Task 5): a
                    // scanner-rejected workspace stays LIVE so the offending
                    // file can be fixed in place and re-harvested, unlike
                    // P13's one-shot `sc work` which treats rejection as
                    // terminal. No candidate branch was created
                    // (`harvest_workspace` never calls `write_branch_tip` on
                    // the `SecretDetected` path), so nothing to clean up; the
                    // manifest is untouched for this entry.
                    outcomes.push(WsHarvestOutcome::Rejected {
                        index: i,
                        report: report.to_string(),
                    });
                }
                crate::workspace::HarvestResult::Unchanged => {
                    // Unreachable in practice: `ws_changed_for` already
                    // confirmed a diff above, and `harvest_workspace`
                    // re-diffs moments later against the SAME persisted
                    // cache state (same `tip` argument, same per-workspace
                    // cache, no intervening write) — the two checks cannot
                    // disagree. Kept for match exhaustiveness, not as a
                    // reachable panic guard.
                    resolve_and_teardown(self.layout(), &mut session, i, &dir, None)?;
                    outcomes.push(WsHarvestOutcome::Unchanged { index: i });
                }
                crate::workspace::HarvestResult::Committed(id) => {
                    let current_tip =
                        refs::read_branch_tip(self.layout(), &landing)?.ok_or(Error::Unborn)?;
                    // The candidate branch exists only to be landed or kept for
                    // a conflict. A failing probe leaves the workspace live for
                    // a retry, which would mint another candidate: remove this
                    // one first.
                    let clean = match self.would_merge_cleanly(current_tip, id, identity) {
                        Ok(clean) => clean,
                        Err(e) => {
                            let _ = refs::delete_branch(self.layout(), &branch);
                            return Err(e);
                        }
                    };
                    if clean {
                        // The second tuple element on `Ok` is skipped
                        // protected paths (missing-identity skips), not
                        // conflicts, and is intentionally not inspected here.
                        match self.merge_with_identity(&branch, author, identity) {
                            Ok((merged, _skipped)) => {
                                // The candidate ref served its purpose
                                // (merge_with_identity resolved by branch
                                // name, not object id).
                                refs::delete_branch(self.layout(), &branch)?;
                                resolve_and_teardown(
                                    self.layout(),
                                    &mut session,
                                    i,
                                    &dir,
                                    Some(merged),
                                )?;
                                outcomes.push(WsHarvestOutcome::Landed {
                                    index: i,
                                    merged_tip: merged,
                                });
                            }
                            Err(Error::UpToDate) => {
                                // The candidate is already an ancestor of the
                                // landing tip. Reproduced by: land ws-i
                                // normally, then kill -9 between the branch
                                // ref update and the manifest rewrite that
                                // resolves the entry — a re-harvest of the
                                // same workspace at the same clock second
                                // re-mints an IDENTICAL candidate id (same
                                // parent, same tree, same author/message/
                                // timestamp), which is already reachable from
                                // `landing`. This is not a conflict or a
                                // probe/merge disagreement: the work IS
                                // already in the landing history, so this is
                                // a successful no-op resolution, not an
                                // error.
                                refs::delete_branch(self.layout(), &branch)?;
                                resolve_and_teardown(
                                    self.layout(),
                                    &mut session,
                                    i,
                                    &dir,
                                    Some(current_tip),
                                )?;
                                outcomes.push(WsHarvestOutcome::Landed {
                                    index: i,
                                    merged_tip: current_tip,
                                });
                            }
                            Err(e) => {
                                // The probe promised a clean merge.
                                // `merge_with_identity` returns `Ok` only
                                // when the merge is actually clean (a real
                                // conflict is `Err(MergeConflicts(_))`,
                                // raised *after* writing markers to disk;
                                // `Err(UpToDate)` is handled above) — so a
                                // disagreement here means our own mirroring
                                // of three_way's parameters is wrong, not a
                                // normal user-facing conflict. Bail loudly
                                // before any teardown.
                                if !matches!(e, Error::MergeConflicts(_)) {
                                    // Refused before any write (a gap, a policy
                                    // error): the workspace stays live, so drop
                                    // the candidate rather than leak one per
                                    // retry. A real conflict keeps it: its
                                    // markers are on disk.
                                    let _ = refs::delete_branch(self.layout(), &branch);
                                }
                                return Err(if matches!(e, Error::MergeConflicts(_)) {
                                    Error::BadRef(format!(
                                        "ws harvest: probe predicted a clean merge of {branch} \
                                         into {landing}, but merge_with_identity found conflicts \
                                         ({e}) — this is a probe/merge disagreement bug, not a \
                                         normal conflict. Conflict markers ARE on disk in \
                                         {landing}'s working tree and a merge is now in progress: \
                                         resolve the markers then `sc commit` to complete the \
                                         landing (the next `sc ws harvest` is guarded meanwhile by \
                                         the merge-in-progress check)"
                                    ))
                                } else {
                                    e
                                });
                            }
                        }
                    } else {
                        // Keep the candidate branch for manual resolution.
                        resolve_and_teardown(self.layout(), &mut session, i, &dir, None)?;
                        outcomes.push(WsHarvestOutcome::FallbackBranch { index: i, branch });
                    }
                }
            }
        }

        if session.workspaces.iter().all(|e| !e.live) {
            let _ = std::fs::remove_dir_all(ws_dir(self.layout(), name));
        }

        Ok(outcomes)
    }
}

/// Mark workspace `i` resolved (`live = false`), tear down its checkout dir,
/// and persist the manifest — the shared tail of every non-`Rejected`
/// `ws_harvest` outcome, so a crash right after this point has already
/// recorded the resolution durably. `landed_tip` is `Some` only for a
/// `Landed` (or idempotent `UpToDate` no-op landing) resolution — recorded
/// so `sc ws list` can later tell a true landing apart from a plain abandon,
/// and (via ancestry against the landing branch's current tip) a landing
/// that was since undone (P21).
fn resolve_and_teardown(
    layout: &Layout,
    session: &mut WsSession,
    index: u32,
    dir: &std::path::Path,
    landed_tip: Option<ObjectId>,
) -> Result<()> {
    if let Some(entry) = session.workspaces.iter_mut().find(|e| e.index == index) {
        entry.live = false;
        entry.landed_tip = landed_tip;
    }
    // Manifest first, then dir removal: a crash between the two leaves the
    // entry already recorded `live = false` with a dir that still happens to
    // exist (harmless, cleaned up by a future `sc ws fork`'s root removal or
    // left as inert residue) rather than `live = true` pointing at a dir that
    // is already gone (which would wedge a later `ws_changed`/harvest on an
    // io error with no recorded recovery path).
    write_manifest(layout, session)?;
    let _ = std::fs::remove_dir_all(dir);
    // Drop this workspace's P33 stat cache alongside its checkout dir (P33
    // Task 7 item 3): the cache file lives beside the dir, not inside it, so
    // removing the dir doesn't remove it.
    let _ = std::fs::remove_file(layout.ws_cache_path(session.name.as_deref(), index as usize));
    Ok(())
}

/// A resolved `sc ws run`: where to run, the `SC_WORKSPACE` label, and any
/// injected secrets. Holds no repo handle, so running it does not hold the
/// repo lock.
pub struct WsRunPlan {
    /// The `running-<i>` marker; removed when the plan is dropped.
    marker: PathBuf,
    dir: PathBuf,
    label: String,
    envs: Vec<(String, std::ffi::OsString)>,
}

impl WsRunPlan {
    /// Spawn `cmd` in the workspace dir with `SC_WORKSPACE` and
    /// `SC_WORKSPACE_DIR` set and return its exit code.
    pub fn run(self, cmd: &[String]) -> Result<i32> {
        let (exe, args) = cmd
            .split_first()
            .ok_or_else(|| Error::InvalidArgument("empty command".into()))?;
        let mut command = std::process::Command::new(exe);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("SC_WORKSPACE", &self.label)
            .env("SC_WORKSPACE_DIR", &self.dir);
        for (k, v) in &self.envs {
            command.env(k, v);
        }
        let mut child = command.spawn()?;
        // Record the child too: if `sc` is killed first, the orphan keeps the
        // workspace busy. Best effort; the parent pid is already in the file.
        if let Err(e) = scl_core::fsutil::atomic_write_durable(
            &self.marker,
            format!("{} {}", std::process::id(), child.id()).as_bytes(),
        ) {
            eprintln!(
                "warning: could not record the command's pid ({e}); the workspace is \
                 protected from harvest and abandon only while `sc` itself runs"
            );
        }
        Ok(child.wait()?.code().unwrap_or(1))
    }
}

impl Drop for WsRunPlan {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.marker);
    }
}

/// Outcome of harvesting one live workspace.
#[derive(Debug)]
pub enum WsHarvestOutcome {
    /// Landed cleanly onto the landing branch at `merged_tip`.
    Landed { index: u32, merged_tip: ObjectId },
    /// Conflicted (or an authorization shortfall on a protected path); kept
    /// as its own branch for manual resolution via `sc merge <branch>`.
    FallbackBranch { index: u32, branch: String },
    /// The checkout never diverged from the session's base snapshot.
    Unchanged { index: u32 },
    /// The P5 scanner found plaintext secrets; the workspace stays live so
    /// the offending file can be fixed in place and re-harvested.
    Rejected { index: u32, report: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("scl-ws-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn init(root: &std::path::Path) -> Repo {
        let repo = Repo::init(root).unwrap();
        std::fs::write(root.join("a.txt"), "base\n").unwrap();
        repo.commit("t", "base").unwrap();
        repo
    }

    #[test]
    fn fork_creates_session_and_checkouts() {
        let root = tmp_root("fork");
        let repo = init(&root);
        let tip = repo.head_tip().unwrap().unwrap();

        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        assert_eq!(session.base_snapshot, tip);
        assert_eq!(session.base_branch, "main");
        assert_eq!(session.workspaces.len(), 2);
        for entry in &session.workspaces {
            assert!(entry.live);
            assert_eq!(
                std::fs::read_to_string(entry.dir.join("a.txt")).unwrap(),
                "base\n"
            );
        }

        let err = repo.ws_fork(None, 1, "t", None).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => assert!(
                msg.contains("workspace session is already open"),
                "message must name the open session: {msg}"
            ),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ws_fork_inherits_sparse() {
        // P24 Task 4: a durable `sc ws` workspace inherits the host repo's
        // sparse view — unlike `sc work`'s one-shot ephemeral agents, which
        // stay full (unchanged, out of this task's scope).
        let root = tmp_root("fork-sparse");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v1").unwrap();
        std::fs::write(root.join("docs/x"), b"doc v1").unwrap();
        repo.commit("t", "base").unwrap();

        repo.set_sparse(&["src/".into()], None).unwrap();
        assert!(!root.join("docs/x").exists());

        let session = repo.ws_fork(None, 1, "t", None).unwrap();
        let entry = &session.workspaces[0];
        assert!(
            entry.dir.join("src/a.txt").exists(),
            "in-sparse file must materialize"
        );
        assert!(
            !entry.dir.join("docs/x").exists(),
            "out-of-sparse file must not materialize"
        );

        // Harvest carries the untouched out-of-sparse subtree verbatim.
        std::fs::write(entry.dir.join("src/a.txt"), b"a v2").unwrap();
        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            WsHarvestOutcome::Landed { index: 1, .. } => {}
            other => panic!("expected Landed(1), got {other:?}"),
        }
        let tip = repo.head_tip().unwrap().unwrap();
        let snap = repo.snapshot(&tip).unwrap();
        let entries = {
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap()
        };
        assert!(
            entries.contains_key("docs/x"),
            "harvest must carry the out-of-sparse subtree"
        );
        let blob = entries.get("docs/x").map(|(id, _, _)| *id).unwrap();
        let bytes = {
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            match s.get(&blob).unwrap() {
                scl_core::Object::Blob(b) => b,
                _ => panic!("expected blob"),
            }
        };
        assert_eq!(&*bytes, b"doc v1", "carried content must be unchanged");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ws_harvest_uses_fork_time_sparse_not_ambient() {
        // P24 final-review fix, Critical 1: a `sc ws` workspace is
        // materialized under the host's sparse spec AT FORK TIME. If the
        // host's spec changes before harvest (a legitimate P20 action — ws
        // sessions span invocations by design), harvest must still diff and
        // commit against the FORK-TIME view, not the host's new live one —
        // otherwise the never-materialized `docs/` subtree reads as a user
        // deletion and is silently dropped from the branch tip.
        let root = tmp_root("harvest-fork-time-sparse");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v1").unwrap();
        std::fs::write(root.join("docs/x.txt"), b"doc v1").unwrap();
        repo.commit("t", "base").unwrap();

        // 1. Narrow to src/ and fork — the workspace only ever sees src/.
        repo.set_sparse(&["src/".into()], None).unwrap();
        let session = repo.ws_fork(None, 1, "t", None).unwrap();
        let entry = &session.workspaces[0];
        assert!(entry.dir.join("src/a.txt").exists());
        assert!(!entry.dir.join("docs/x.txt").exists());

        // 2. Legitimately change the host spec before harvest: disable
        // sparse entirely. This re-materializes docs/x.txt on the HOST's own
        // working tree, but must not affect what the already-forked
        // workspace is diffed/committed against.
        repo.disable_sparse(None).unwrap();
        assert!(
            root.join("docs/x.txt").exists(),
            "host disable re-lays its own tree"
        );

        // 3. Make an in-sparse edit in the workspace (the only kind of edit
        // this workspace was ever capable of making).
        std::fs::write(entry.dir.join("src/a.txt"), b"a v2").unwrap();

        // 4. Harvest. The workspace's absent docs/x.txt must be carried
        // (never materialized, not a user deletion), not committed as a
        // deletion.
        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            WsHarvestOutcome::Landed { index: 1, .. } => {}
            other => panic!("expected Landed(1), got {other:?}"),
        }

        let tip = repo.head_tip().unwrap().unwrap();
        let snap = repo.snapshot(&tip).unwrap();
        let entries = {
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap()
        };
        assert!(
            entries.contains_key("docs/x.txt"),
            "docs/x.txt must SURVIVE the harvest — it was never given to the \
             workspace, so its absence there is not a deletion"
        );
        let blob = entries.get("docs/x.txt").map(|(id, _, _)| *id).unwrap();
        let bytes = {
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            match s.get(&blob).unwrap() {
                scl_core::Object::Blob(b) => b,
                _ => panic!("expected blob"),
            }
        };
        assert_eq!(
            &*bytes, b"doc v1",
            "carried content must be byte-identical, unchanged"
        );

        // The in-sparse edit landed correctly too.
        let a_blob = entries.get("src/a.txt").map(|(id, _, _)| *id).unwrap();
        let a_bytes = {
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            match s.get(&a_blob).unwrap() {
                scl_core::Object::Blob(b) => b,
                _ => panic!("expected blob"),
            }
        };
        assert_eq!(&*a_bytes, b"a v2", "the workspace's real edit must land");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fork_clears_manifestless_crash_residue() {
        let root = tmp_root("fork-residue");
        let repo = init(&root);
        let tip = repo.head_tip().unwrap().unwrap();

        // Simulate a kill -9 mid-fork: a workspace dir exists with a stray
        // file but no manifest was ever written to announce the session.
        let ws_root = ws_dir(repo.layout(), None);
        std::fs::create_dir_all(ws_root.join("1")).unwrap();
        std::fs::write(ws_root.join("1").join("residue.txt"), "stale\n").unwrap();
        assert!(repo.ws_session(None).unwrap().is_none());

        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        assert_eq!(session.base_snapshot, tip);
        assert_eq!(session.workspaces.len(), 2);

        // Neither freshly forked workspace shows the residue as a change.
        for entry in &session.workspaces {
            assert!(
                !repo.ws_changed(None, entry).unwrap(),
                "residue must not leak into a freshly forked workspace"
            );
        }

        // The stray file is gone everywhere under .sc/ws.
        for entry in walkdir_files(&ws_root) {
            assert_ne!(
                entry.file_name().unwrap().to_str(),
                Some("residue.txt"),
                "crash residue must be cleared before materializing: {entry:?}"
            );
        }

        // Harvesting the untouched workspaces lands nothing and leaves the
        // base branch tip unchanged.
        let base_before = repo.head_tip().unwrap().unwrap();
        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        assert!(outcomes
            .iter()
            .all(|o| matches!(o, WsHarvestOutcome::Unchanged { .. })));
        assert!(repo.ws_session(None).unwrap().is_none());
        assert_eq!(repo.head_tip().unwrap().unwrap(), base_before);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn walkdir_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(walkdir_files(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    #[test]
    fn session_survives_process_boundary() {
        let root = tmp_root("boundary");
        {
            let repo = init(&root);
            repo.ws_fork(None, 2, "t", None).unwrap();
        } // repo (and its lock) dropped: simulates the process exiting

        let repo = Repo::open(&root).unwrap();
        let session = repo
            .ws_session(None)
            .unwrap()
            .expect("manifest must survive reopen");
        assert_eq!(session.workspaces.len(), 2);
        for entry in &session.workspaces {
            assert!(
                !repo.ws_changed(None, entry).unwrap(),
                "freshly forked checkout must be unchanged"
            );
        }

        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited\n").unwrap();
        assert!(repo.ws_changed(None, &session.workspaces[0]).unwrap());
        assert!(!repo.ws_changed(None, &session.workspaces[1]).unwrap());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn abandon_one_and_all() {
        let root = tmp_root("abandon");
        let repo = init(&root);
        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        let dir1 = session.workspaces[0].dir.clone();
        let dir2 = session.workspaces[1].dir.clone();

        let remaining = repo.ws_abandon(None, Some(1)).unwrap();
        assert_eq!(remaining, 1);
        assert!(!dir1.exists());
        let after = repo.ws_session(None).unwrap().expect("session still open");
        let e1 = after.workspaces.iter().find(|e| e.index == 1).unwrap();
        assert!(!e1.live);
        assert!(dir2.exists());

        let remaining = repo.ws_abandon(None, None).unwrap();
        assert_eq!(remaining, 0);
        assert!(!dir2.exists());
        assert!(repo.ws_session(None).unwrap().is_none());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn manifest_never_stores_key_material() {
        let root = tmp_root("keymat");
        let repo = init(&root);
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("a.txt", &[pk], None).unwrap();
        // Recommit under protection so the workspace materializes a
        // protected path decrypted by `sk`.
        std::fs::write(root.join("a.txt"), "still base\n").unwrap();
        repo.commit("t", "protect a.txt").unwrap();

        repo.ws_fork(None, 1, "t", Some(&sk)).unwrap();
        let text = std::fs::read_to_string(manifest_path(repo.layout(), None)).unwrap();
        assert!(
            !text.contains("scl-sk"),
            "manifest must never contain key material: {text}"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn untouched_protected_files_do_not_conflict_across_workspaces() {
        // P33 Task 7 Step 4 — the false-conflict hazard the per-workspace
        // cache exists to prevent. Two workspaces forked WITH identity, each
        // editing a different PLAIN file, both leaving a RANDOMIZED protected
        // file untouched. Both must land cleanly (no `work-<i>` fallback) AND
        // carry the base's EXACT protected blob id. Without a per-workspace
        // cache, harvest would re-seal the untouched randomized path to a
        // fresh ciphertext id (a randomized seal differs every time), which
        // the merge would then adopt as a spurious "change".
        let root = tmp_root("ws-untouched-protected");
        let repo = init(&root);
        std::fs::write(root.join("p1.txt"), "one\n").unwrap();
        std::fs::write(root.join("p2.txt"), "two\n").unwrap();
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x"), "the secret\n").unwrap();
        repo.commit("t", "add plain + protected").unwrap();
        let base = repo.head_tip().unwrap().unwrap();

        // Base's protected blob id, and PROOF it is RANDOMIZED — otherwise a
        // convergent carry-by-re-encrypt would pass this test without ever
        // touching the cache (the whole point of the regression).
        let base_secret_id = {
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            let base_root = s.get_snapshot(&base).unwrap().root;
            let entries = worktree::tree_file_entries_with_perms(&mut s, base_root).unwrap();
            let (id, _mode, perms) = *entries.get("secret/x").expect("protected file present");
            assert!(
                perms & scl_core::PROTECTED != 0 && perms & scl_core::RANDOMIZED != 0,
                "the protected file must be RANDOMIZED for this regression to exercise the cache"
            );
            id
        };

        // Fork two workspaces WITH identity: the protected file materializes
        // decrypted AND is recorded in each workspace's own cache at fork.
        let session = repo.ws_fork(None, 2, "t", Some(&sk)).unwrap();
        let dir1 = session.workspaces[0].dir.clone();
        let dir2 = session.workspaces[1].dir.clone();
        // Each workspace edits ONLY its own plain file; secret/x is untouched.
        std::fs::write(dir1.join("p1.txt"), "one edited\n").unwrap();
        std::fs::write(dir2.join("p2.txt"), "two edited\n").unwrap();

        let outcomes = repo.ws_harvest(None, None, "t", Some(&sk)).unwrap();
        assert_eq!(outcomes.len(), 2);
        for o in &outcomes {
            let merged_tip = match o {
                WsHarvestOutcome::Landed { merged_tip, .. } => *merged_tip,
                other => panic!("expected Landed (no work-<i> fallback), got {other:?}"),
            };
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            let mroot = s.get_snapshot(&merged_tip).unwrap().root;
            let entries = worktree::tree_file_entries_with_perms(&mut s, mroot).unwrap();
            let (id, _m, _p) = *entries.get("secret/x").unwrap();
            assert_eq!(
                id, base_secret_id,
                "an untouched randomized protected file must carry the base blob id, not re-seal"
            );
        }

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_live_workspace_cache_is_pruned_when_a_protected_file_is_deleted() {
        // #204 through the ws path: the cache file at `.sc/ws/cache-<i>` only
        // outlives a harvest while the workspace stays live, so a scanner
        // rejection keeps it open. The deleted protected file's entry must be
        // gone from the saved cache; the surviving one stays.
        let root = tmp_root("ws-cache-prune");
        let repo = init(&root);
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/keep"), "kept\n").unwrap();
        std::fs::write(root.join("secret/gone"), "doomed\n").unwrap();
        repo.commit("t", "add protected").unwrap();

        let session = repo.ws_fork(None, 1, "t", Some(&sk)).unwrap();
        let dir = session.workspaces[0].dir.clone();
        let cache_file = repo.layout().ws_cache_path(None, 1);
        let cached = |name: &str| {
            std::fs::read_to_string(&cache_file)
                .unwrap()
                .lines()
                .any(|l| l.ends_with(&format!(" {name}")))
        };
        assert!(cached("secret/keep") && cached("secret/gone"), "setup");

        std::fs::remove_file(dir.join("secret/gone")).unwrap();
        // An AWS-style key id trips the P5 scanner, so the workspace stays live.
        std::fs::write(dir.join("leak.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let outcomes = repo.ws_harvest(None, None, "t", Some(&sk)).unwrap();
        assert!(
            matches!(outcomes[0], WsHarvestOutcome::Rejected { index: 1, .. }),
            "got {outcomes:?}"
        );

        assert!(cached("secret/keep"), "a surviving file keeps its entry");
        assert!(!cached("secret/gone"), "the deleted file's entry is pruned");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists(), "test must leave no residue");
    }

    #[test]
    fn ws_changed_for_ignores_untouched_randomized_protected_file() {
        // P33 Task 7 (ws_changed_for arm): before this fix, `ws_changed_for`
        // always passed `None` for the cache, so a RANDOMIZED protected
        // path — never bit-for-bit reproducible by re-encrypting the same
        // plaintext — always compared as "different" even when genuinely
        // untouched, reporting the workspace "changed" for no real edit.
        // With the workspace's own persistent cache threaded in (recorded
        // at fork time, same as `harvest_workspace` uses), an untouched
        // randomized protected file must resolve as unchanged.
        let root = tmp_root("ws-changed-for-randomized");
        let repo = init(&root);
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x"), "the secret\n").unwrap();
        repo.commit("t", "add protected").unwrap();
        let base = repo.head_tip().unwrap().unwrap();

        // Confirm RANDOMIZED, mirroring the sibling harvest-level regression
        // — otherwise this test would pass even without the fix.
        {
            let a = repo.vfs().store();
            let mut s = a.lock().unwrap();
            let base_root = s.get_snapshot(&base).unwrap().root;
            let entries = worktree::tree_file_entries_with_perms(&mut s, base_root).unwrap();
            let (_id, _mode, perms) = *entries.get("secret/x").expect("protected file present");
            assert!(
                perms & scl_core::PROTECTED != 0 && perms & scl_core::RANDOMIZED != 0,
                "the protected file must be RANDOMIZED for this regression to exercise the cache"
            );
        }

        // Fork WITH identity so the protected file materializes decrypted
        // and is recorded in the workspace's own cache at fork time; leave
        // it completely untouched.
        let session = repo.ws_fork(None, 1, "t", Some(&sk)).unwrap();
        assert!(
            !repo
                .ws_changed_for(&session, &session.workspaces[0])
                .unwrap(),
            "an untouched RANDOMIZED protected file must not report the workspace as changed"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_roots_ws_base_snapshot() {
        let root = tmp_root("gcroot");
        let repo = init(&root);
        let base = repo.head_tip().unwrap().unwrap();

        // Build `tip` as a snapshot object put directly into the store
        // (never through `repo.commit`), so it is reachable from no ref AND
        // referenced by no oplog record — the only thing keeping it alive is
        // the open ws session's manifest. Mirrors gc.rs's
        // `gc_protects_rebase_acc_tip_and_rebase_decided_root` test shape.
        let tip = {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            let base_snap = s.get_snapshot(&base).unwrap();
            s.put(scl_core::Object::Snapshot(scl_core::Snapshot {
                root: base_snap.root,
                parents: vec![base],
                author: "t".into(),
                timestamp: base_snap.timestamp,
                message: "standalone".into(),
                secrets: Default::default(),
                protection: Default::default(),
            }))
            .unwrap()
        };
        // Point the branch at `tip` (bypassing `commit`/oplog) just long
        // enough for `ws_fork` to read it as HEAD, then rewind to `base`.
        crate::refs::write_branch_tip(repo.layout(), "main", &tip).unwrap();
        repo.ws_fork(None, 1, "t", None).unwrap();
        crate::refs::write_branch_tip(repo.layout(), "main", &base).unwrap();

        repo.gc(std::time::Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(
            s.contains(&tip),
            "an open session's base snapshot must survive gc"
        );
        drop(s);

        repo.ws_abandon(None, None).unwrap();
        repo.gc(std::time::Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(
            !s.contains(&tip),
            "once the session is abandoned, the base snapshot may be pruned"
        );
        drop(s);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ws_run_sets_env_and_cwd() {
        let root = tmp_root("ws_run_env");
        let repo = init(&root);
        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        let entry = &session.workspaces[1]; // work-2

        // Run a command that writes SC_WORKSPACE and pwd to files.
        let exit = repo
            .ws_run(
                None,
                entry.index,
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo \"$SC_WORKSPACE\" > env.txt; pwd > cwd.txt".to_string(),
                ],
                false,
                None,
            )
            .unwrap();

        assert_eq!(exit, 0);

        // Check SC_WORKSPACE holds the label "work-2".
        let env_content = std::fs::read_to_string(entry.dir.join("env.txt")).unwrap();
        assert_eq!(env_content.trim(), "work-2");

        // Check pwd matches the workspace dir (canonicalize both to handle symlinks).
        let cwd_content = std::fs::read_to_string(entry.dir.join("cwd.txt")).unwrap();
        let expected_dir = std::fs::canonicalize(&entry.dir).unwrap();
        let actual_dir = std::fs::canonicalize(cwd_content.trim()).unwrap();
        assert_eq!(actual_dir, expected_dir);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ws_run_with_secrets_injects() {
        let root = tmp_root("ws_run_secrets");
        let repo = init(&root);
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("DEMO_TOKEN", b"tok-123", &[pk]).unwrap();

        let session = repo.ws_fork(None, 1, "t", Some(&sk)).unwrap();
        let entry = &session.workspaces[0];

        let exit = repo
            .ws_run(
                None,
                entry.index,
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "printf %s \"$DEMO_TOKEN\" > tok.txt".to_string(),
                ],
                true,
                Some(&sk),
            )
            .unwrap();

        assert_eq!(exit, 0);

        // Verify the decrypted secret value was written to the file.
        let tok_content = std::fs::read_to_string(entry.dir.join("tok.txt")).unwrap();
        assert_eq!(tok_content, "tok-123");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ws_run_bad_index_errors() {
        let root = tmp_root("ws_run_bad");
        let repo = init(&root);
        let _session = repo.ws_fork(None, 2, "t", None).unwrap();

        // Non-existent workspace index.
        let err = repo
            .ws_run(
                None,
                999,
                &["sh".to_string(), "-c".to_string(), "true".to_string()],
                false,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
        assert!(err.to_string().contains("no such workspace: 999"));

        // Abandon workspace 1, then try to run in it.
        repo.ws_abandon(None, Some(1)).unwrap();
        let err = repo
            .ws_run(
                None,
                1,
                &["sh".to_string(), "-c".to_string(), "true".to_string()],
                false,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
        assert!(err.to_string().contains("no such workspace: 1"));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_lands_clean_results_cumulatively() {
        let root = tmp_root("harvest-clean");
        let repo = init(&root);
        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        std::fs::write(session.workspaces[1].dir.join("b.txt"), "new-b\n").unwrap();

        let oplog_before = repo.oplog().unwrap().len();
        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes.len(), 2);
        match &outcomes[0] {
            WsHarvestOutcome::Landed { index: 1, .. } => {}
            other => panic!("expected Landed(1), got {other:?}"),
        }
        match &outcomes[1] {
            WsHarvestOutcome::Landed { index: 2, .. } => {}
            other => panic!("expected Landed(2), got {other:?}"),
        }

        // main's tip contains BOTH edits.
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "edited-a\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("b.txt")).unwrap(),
            "new-b\n"
        );

        // Exactly 2 new oplog records (one per landing).
        let oplog_after = repo.oplog().unwrap().len();
        assert_eq!(oplog_after - oplog_before, 2);

        // No work-1/work-2 branches remain (candidate refs deleted after landing).
        assert!(crate::refs::read_branch_tip(repo.layout(), "work-1")
            .unwrap()
            .is_none());
        assert!(crate::refs::read_branch_tip(repo.layout(), "work-2")
            .unwrap()
            .is_none());

        // Session ended.
        assert!(repo.ws_session(None).unwrap().is_none());
        assert!(!repo.layout().dot_sc.join("ws").exists());

        // sc undo reverts ONLY the second landing: a.txt edit still present,
        // b.txt edit gone.
        repo.undo().unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "edited-a\n"
        );
        assert!(!root.join("b.txt").exists());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_file_directory_collision_falls_back_instead_of_aborting() {
        // ws-1 adds a FILE `n`; ws-2 adds a DIRECTORY `n/` with a file in it.
        // Landing ws-1 first makes ws-2's merge a file/directory collision
        // (ADR-0049): it falls back to `work-2` like any conflict, and the
        // harvest of the other workspaces is not aborted.
        let root = tmp_root("harvest-file-dir-collision");
        let repo = init(&root);
        std::fs::write(root.join("keep.txt"), "k\n").unwrap();
        repo.commit("t", "base").unwrap();

        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("n"), "file\n").unwrap();
        std::fs::create_dir_all(session.workspaces[1].dir.join("n")).unwrap();
        std::fs::write(session.workspaces[1].dir.join("n/child"), "nested\n").unwrap();

        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(
            matches!(&outcomes[0], WsHarvestOutcome::Landed { index: 1, .. }),
            "got {:?}",
            outcomes[0]
        );
        assert!(
            matches!(&outcomes[1], WsHarvestOutcome::FallbackBranch { index: 2, branch } if branch == "work-2"),
            "got {:?}",
            outcomes[1]
        );
        assert_eq!(std::fs::read_to_string(root.join("n")).unwrap(), "file\n");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_conflict_falls_back_without_touching_anything() {
        let root = tmp_root("harvest-conflict");
        let repo = init(&root);
        std::fs::write(root.join("x.txt"), "base-x\n").unwrap();
        repo.commit("t", "add x").unwrap();

        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        std::fs::write(session.workspaces[1].dir.join("x.txt"), "ws2-x\n").unwrap();

        // A conflicting x.txt change lands on main AFTER fork, so ws-2's
        // eventual merge (base = the fork-time tip) conflicts on x.txt.
        std::fs::write(root.join("x.txt"), "main-x\n").unwrap();
        repo.commit("t", "conflict x on main").unwrap();

        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes.len(), 2);
        match &outcomes[0] {
            WsHarvestOutcome::Landed { index: 1, .. } => {}
            other => panic!("expected Landed(1), got {other:?}"),
        }
        match &outcomes[1] {
            WsHarvestOutcome::FallbackBranch { index: 2, branch } => {
                assert_eq!(branch, "work-2");
            }
            other => panic!("expected FallbackBranch(2, \"work-2\"), got {other:?}"),
        }

        // main tip contains ws-1's edit and NOT ws-2's.
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "edited-a\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("x.txt")).unwrap(),
            "main-x\n"
        );

        // work-2 branch exists with ws-2's commit.
        assert!(crate::refs::read_branch_tip(repo.layout(), "work-2")
            .unwrap()
            .is_some());

        // NO conflict markers anywhere in main's working tree.
        for entry in std::fs::read_dir(&root).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_file() {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    assert!(
                        !content.contains("<<<<<<<"),
                        "unexpected conflict marker in {:?}",
                        entry.path()
                    );
                }
            }
        }
        assert!(!crate::merge_state::in_progress(repo.layout()));

        // Session ended.
        assert!(repo.ws_session(None).unwrap().is_none());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_requires_landing_branch_checked_out() {
        let root = tmp_root("harvest-notcheckedout");
        let repo = init(&root);
        repo.branch("other").unwrap();
        let session = repo.ws_fork(None, 1, "t", None).unwrap();
        repo.switch("other").unwrap();

        let err = repo.ws_harvest(None, None, "t", None).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => {
                assert!(
                    msg.contains("main"),
                    "message must name the landing branch: {msg}"
                );
                assert!(
                    msg.contains("sc switch"),
                    "message must suggest sc switch: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        // Session still open; nothing moved.
        let after = repo
            .ws_session(None)
            .unwrap()
            .expect("session must still be open");
        assert_eq!(after.workspaces.len(), session.workspaces.len());
        assert!(after.workspaces[0].live);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_respects_into_and_collision_suffix() {
        let root = tmp_root("harvest-collision");
        let repo = init(&root);
        std::fs::write(root.join("x.txt"), "base-x\n").unwrap();
        repo.commit("t", "add x").unwrap();

        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        std::fs::write(session.workspaces[1].dir.join("x.txt"), "ws2-x\n").unwrap();
        std::fs::write(root.join("x.txt"), "main-x\n").unwrap();
        repo.commit("t", "conflict x on main").unwrap();

        // Pre-create branch "work-2" so ws-2's fallback must suffix.
        repo.branch("work-2").unwrap();

        // --into with the checked-out branch name behaves as default.
        let outcomes = repo.ws_harvest(None, Some("main"), "t", None).unwrap();
        match &outcomes[1] {
            WsHarvestOutcome::FallbackBranch { index: 2, branch } => {
                assert_eq!(branch, "work-2-2");
            }
            other => panic!("expected FallbackBranch(2, \"work-2-2\"), got {other:?}"),
        }

        // --into a non-checked-out branch errors.
        let _session2 = repo.ws_fork(None, 1, "t", None).unwrap();
        let err = repo
            .ws_harvest(None, Some("nonexistent-branch"), "t", None)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_guards_and_dirty_tree() {
        let root = tmp_root("harvest-guards");
        let repo = init(&root);
        let session = repo.ws_fork(None, 1, "t", None).unwrap();

        // (a) merge/pick/rebase in progress -> typed errors.
        crate::merge_state::write(repo.layout(), &ObjectId::of(b"theirs"), &[], None).unwrap();
        assert!(matches!(
            repo.ws_harvest(None, None, "t", None),
            Err(Error::MergeInProgress)
        ));
        crate::merge_state::clear(repo.layout()).unwrap();

        crate::pick_state::write(repo.layout(), &ObjectId::of(b"picked"), &[], None, None).unwrap();
        assert!(matches!(
            repo.ws_harvest(None, None, "t", None),
            Err(Error::PickInProgress)
        ));
        crate::pick_state::clear(repo.layout()).unwrap();

        let st = crate::rebase_state::RebaseState {
            branch: "main".into(),
            original_tip: ObjectId::of(b"orig"),
            target: "other".into(),
            acc_tip: ObjectId::of(b"acc"),
            conflicted: ObjectId::of(b"conflicted"),
            remaining: vec![],
            total: 1,
            author: "t".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        };
        crate::rebase_state::write(repo.layout(), &st).unwrap();
        assert!(matches!(
            repo.ws_harvest(None, None, "t", None),
            Err(Error::RebaseInProgress)
        ));
        crate::rebase_state::clear(repo.layout()).unwrap();

        // (b) dirty user working tree -> InvalidArgument, caught by the
        // up-front preflight (not merge_with_identity's own dirty guard) so
        // no candidate branch is ever minted for the live, changed workspace.
        // Session intact.
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "ws-edit\n").unwrap();
        std::fs::write(root.join("a.txt"), "dirty-uncommitted\n").unwrap();
        let err = repo.ws_harvest(None, None, "t", None).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        let after = repo
            .ws_session(None)
            .unwrap()
            .expect("session must still be open");
        assert!(
            after.workspaces[0].live,
            "workspace must remain live after the abort"
        );

        // No stray work-1 branch: the preflight refused before
        // `harvest_workspace` ever ran.
        assert!(
            crate::refs::read_branch_tip(repo.layout(), "work-1")
                .unwrap()
                .is_none(),
            "preflight must refuse before any candidate branch is minted"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_partial_leaves_session_open() {
        let root = tmp_root("harvest-partial");
        let repo = init(&root);
        let session = repo.ws_fork(None, 2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        // An AWS-style key id trips the P5 scanner in ws-2's checkout.
        std::fs::write(
            session.workspaces[1].dir.join("leak.txt"),
            "AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();

        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes.len(), 2);
        match &outcomes[0] {
            WsHarvestOutcome::Landed { index: 1, .. } => {}
            other => panic!("expected Landed(1), got {other:?}"),
        }
        match &outcomes[1] {
            WsHarvestOutcome::Rejected { index: 2, .. } => {}
            other => panic!("expected Rejected(2), got {other:?}"),
        }

        // ws-2 stays LIVE (rejected != resolved); session still open with
        // ws-2 only.
        let after = repo
            .ws_session(None)
            .unwrap()
            .expect("session must still be open");
        assert_eq!(after.workspaces.len(), 2);
        let e1 = after.workspaces.iter().find(|e| e.index == 1).unwrap();
        let e2 = after.workspaces.iter().find(|e| e.index == 2).unwrap();
        assert!(!e1.live, "ws-1 landed and should be resolved");
        assert!(e2.live, "ws-2 was rejected and must stay live");

        // Vocabulary (P21): a resolved entry that actually landed a merge
        // reports "landed", not the generic "abandoned" a manual
        // `ws_abandon` would show. ws-2 stayed live, so its label is the
        // live changed/unchanged vocabulary — it still has the leaked file,
        // so "changed".
        assert_eq!(repo.ws_status_label(&after, e1).unwrap(), "landed");
        assert_eq!(repo.ws_status_label(&after, e2).unwrap(), "changed");

        // sc undo reverts ws-1's landing. The manifest still records ws-1
        // as resolved (`live = false`) — the session stays open because
        // ws-2 is still live — but ws-1's landed tip is no longer an
        // ancestor of the landing branch's tip. `sc ws list` must say so
        // truthfully instead of the misleading generic "abandoned".
        repo.undo().unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "base\n"
        );
        let after_undo = repo
            .ws_session(None)
            .unwrap()
            .expect("ws-2 still live keeps the session open");
        let e1_after_undo = after_undo.workspaces.iter().find(|e| e.index == 1).unwrap();
        assert_eq!(
            repo.ws_status_label(&after_undo, e1_after_undo).unwrap(),
            "landed (undone by sc undo)"
        );

        // Fixing the file then re-harvesting completes and ends the session.
        std::fs::remove_file(e2.dir.join("leak.txt")).unwrap();
        let outcomes2 = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes2.len(), 1);
        match &outcomes2[0] {
            WsHarvestOutcome::Unchanged { index: 2 } => {}
            other => panic!("expected Unchanged(2) once the leak is removed, got {other:?}"),
        }
        assert!(repo.ws_session(None).unwrap().is_none());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_reharvest_after_crash_window_is_idempotent() {
        let root = tmp_root("harvest-reharvest");
        let repo = init(&root);
        let session = repo.ws_fork(None, 1, "t", None).unwrap();
        let dir = session.workspaces[0].dir.clone();
        std::fs::write(dir.join("a.txt"), "edited-a\n").unwrap();

        // Both harvests mint a commit from the same parent/tree/author/message;
        // only the timestamp can differ. Pin the clock (this thread only) so
        // the re-minted candidate id matches regardless of load.
        crate::repo::TEST_NOW.with(|c| c.set(Some(1_700_000_000)));

        let outcomes = repo.ws_harvest(None, None, "t", None).unwrap();
        let landed_tip = match &outcomes[0] {
            WsHarvestOutcome::Landed {
                index: 1,
                merged_tip,
            } => *merged_tip,
            other => panic!("expected Landed(1), got {other:?}"),
        };
        assert!(
            repo.ws_session(None).unwrap().is_none(),
            "session must have ended"
        );

        // Simulate a kill -9 between the candidate branch landing and the
        // manifest rewrite that would have resolved the entry: re-mark ws-1
        // live and restore its checkout dir with identical content, so a
        // re-harvest re-mints an identical candidate id (same parent, tree,
        // author, message, and the pinned timestamp).
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "edited-a\n").unwrap();
        let crashed = WsSession {
            name: None,
            base_snapshot: session.base_snapshot,
            base_branch: session.base_branch.clone(),
            author: session.author.clone(),
            sparse: session.sparse.clone(),
            pending_refresh: None,
            workspaces: vec![WsEntry {
                index: 1,
                dir: dir.clone(),
                live: true,
                landed_tip: None,
            }],
        };
        write_manifest(repo.layout(), &crashed).unwrap();

        // Re-harvest: no error, resolves as a no-op Landed at the existing
        // tip, and leaves no stray branch behind.
        let outcomes2 = repo.ws_harvest(None, None, "t", None).unwrap();
        assert_eq!(outcomes2.len(), 1);
        match &outcomes2[0] {
            WsHarvestOutcome::Landed {
                index: 1,
                merged_tip,
            } => {
                assert_eq!(
                    *merged_tip, landed_tip,
                    "re-harvest of an already-landed workspace must resolve to the existing landing tip"
                );
            }
            other => panic!("expected Landed(1), got {other:?}"),
        }
        assert!(
            crate::refs::read_branch_tip(repo.layout(), "work-1")
                .unwrap()
                .is_none(),
            "no stray candidate branch after the UpToDate no-op resolution"
        );
        assert!(repo.ws_session(None).unwrap().is_none());

        crate::repo::TEST_NOW.with(|c| c.set(None));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ---- Named and concurrent sessions (ADR-0056) -------------------------

    /// Fork a one-workspace session called `name` and write `file` in it.
    fn fork_and_edit(repo: &Repo, name: Option<&str>, file: &str, content: &str) -> WsEntry {
        let session = repo.ws_fork(name, 1, "t", None).unwrap();
        let entry = session.workspaces[0].clone();
        std::fs::write(entry.dir.join(file), content).unwrap();
        entry
    }

    #[test]
    fn named_and_unnamed_sessions_coexist_in_separate_roots() {
        let root = tmp_root("named-coexist");
        let repo = init(&root);

        let plain = repo.ws_fork(None, 1, "t", None).unwrap();
        let a = repo.ws_fork(Some("a"), 2, "t", None).unwrap();
        let b = repo.ws_fork(Some("b"), 1, "t", None).unwrap();

        // The unnamed session keeps the original layout; named ones sit beside it.
        let dot = &repo.layout().dot_sc;
        assert_eq!(plain.workspaces[0].dir, dot.join("ws/1"));
        assert_eq!(a.workspaces[1].dir, dot.join("ws-a/2"));
        assert_eq!(b.workspaces[0].dir, dot.join("ws-b/1"));
        // Each session's P33 stat cache sits in its own root, beside its checkouts.
        assert_eq!(repo.layout().ws_cache_path(None, 1), dot.join("ws/cache-1"));
        assert_eq!(
            repo.layout().ws_cache_path(Some("b"), 1),
            dot.join("ws-b/cache-1")
        );
        for p in ["ws/session.toml", "ws-a/session.toml", "ws-b/session.toml"] {
            assert!(dot.join(p).is_file(), "{p}");
        }

        let all = repo.ws_sessions().unwrap();
        let names: Vec<_> = all.iter().map(|s| s.name.as_deref()).collect();
        assert_eq!(names, [None, Some("a"), Some("b")]);
        assert_eq!(
            repo.ws_session(Some("a"))
                .unwrap()
                .unwrap()
                .workspaces
                .len(),
            2
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn session_name_collisions_and_bad_names_are_refused() {
        let root = tmp_root("named-collide");
        let repo = init(&root);
        repo.ws_fork(Some("a"), 1, "t", None).unwrap();

        match repo.ws_fork(Some("a"), 1, "t", None).unwrap_err() {
            Error::InvalidArgument(m) => {
                assert!(m.contains("session 'a' is already open"), "{m}");
                assert!(m.contains("sc ws abandon --session a"), "{m}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        // A named session does not occupy the unnamed slot, nor vice versa.
        repo.ws_fork(None, 1, "t", None).unwrap();
        assert!(repo.ws_fork(None, 1, "t", None).is_err());
        repo.ws_fork(Some("b"), 1, "t", None).unwrap();

        for bad in ["", "a/b", "..", ".hidden", "has space"] {
            assert!(
                matches!(
                    repo.ws_fork(Some(bad), 1, "t", None),
                    Err(Error::InvalidArgument(_))
                ),
                "{bad:?} must be refused"
            );
        }
        // A refused fork leaves nothing behind.
        assert_eq!(repo.ws_sessions().unwrap().len(), 3);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn addressing_a_missing_session_names_what_is_open() {
        let root = tmp_root("named-missing");
        let repo = init(&root);
        assert!(matches!(
            repo.ws_abandon(Some("x"), None),
            Err(Error::InvalidArgument(m)) if m == "no workspace session open"
        ));
        repo.ws_fork(Some("a"), 1, "t", None).unwrap();
        // No unnamed session: the default does not silently pick a named one.
        for err in [
            repo.ws_harvest(None, None, "t", None).unwrap_err(),
            repo.ws_abandon(None, None).unwrap_err(),
            repo.ws_run(None, 1, &["true".into()], false, None)
                .unwrap_err(),
        ] {
            let Error::InvalidArgument(m) = err else {
                panic!("{err:?}")
            };
            assert!(m.contains("open: a") && m.contains("--session"), "{m}");
        }
        match repo.ws_harvest(Some("nope"), None, "t", None).unwrap_err() {
            Error::InvalidArgument(m) => assert!(m.contains("named 'nope'"), "{m}"),
            other => panic!("{other:?}"),
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Two sessions edit the same file from the same base. Whichever harvest
    /// runs first lands; the second finds the landing branch moved on, cannot
    /// merge cleanly, and falls back to its own `<name>-<i>` branch.
    #[test]
    fn first_harvest_wins_and_the_later_conflicting_one_falls_back() {
        for (tag, first, second) in [("ab", "a", "b"), ("ba", "b", "a")] {
            let root = tmp_root(&format!("order-conflict-{tag}"));
            let repo = init(&root);
            fork_and_edit(&repo, Some("a"), "a.txt", "from a\n");
            fork_and_edit(&repo, Some("b"), "a.txt", "from b\n");
            let base = repo.head_tip().unwrap().unwrap();

            let out = repo.ws_harvest(Some(first), None, "t", None).unwrap();
            assert!(matches!(
                out[..],
                [WsHarvestOutcome::Landed { index: 1, .. }]
            ));
            let out = repo.ws_harvest(Some(second), None, "t", None).unwrap();
            match &out[..] {
                [WsHarvestOutcome::FallbackBranch { index: 1, branch }] => {
                    assert_eq!(*branch, format!("{second}-1"));
                }
                other => panic!("expected a fallback, got {other:?}"),
            }

            let want = format!("from {first}\n");
            assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), want);
            assert_ne!(repo.head_tip().unwrap().unwrap(), base);
            // The loser's work is intact on its branch, parented on the base.
            let kept = crate::refs::read_branch_tip(repo.layout(), &format!("{second}-1"))
                .unwrap()
                .unwrap();
            assert_eq!(repo.snapshot(&kept).unwrap().parents, vec![base]);
            // Both sessions ended; nothing is left under .sc.
            assert!(repo.ws_sessions().unwrap().is_empty());
            assert!(!repo.layout().dot_sc.join("ws-a").exists());
            assert!(!repo.layout().dot_sc.join("ws-b").exists());

            drop(repo);
            std::fs::remove_dir_all(&root).unwrap();
        }
    }

    /// Disjoint edits from two sessions land in either order, to the same tree;
    /// the second landing is a real merge over the first.
    #[test]
    fn disjoint_sessions_land_in_either_order_to_the_same_tree() {
        let mut trees = Vec::new();
        for (tag, first, second) in [("ab", "a", "b"), ("ba", "b", "a")] {
            let root = tmp_root(&format!("order-disjoint-{tag}"));
            let repo = init(&root);
            fork_and_edit(&repo, Some("a"), "file-a.txt", "A\n");
            fork_and_edit(&repo, Some("b"), "file-b.txt", "B\n");

            repo.ws_harvest(Some(first), None, "t", None).unwrap();
            let one = repo.head_tip().unwrap().unwrap();
            // The other session is untouched by the first landing.
            assert!(repo.ws_session(Some(second)).unwrap().unwrap().workspaces[0].live);

            let out = repo.ws_harvest(Some(second), None, "t", None).unwrap();
            let tip = match out[..] {
                [WsHarvestOutcome::Landed { merged_tip, .. }] => merged_tip,
                ref other => panic!("expected a landing, got {other:?}"),
            };
            let snap = repo.snapshot(&tip).unwrap();
            assert_eq!(snap.parents.len(), 2, "second landing is a merge");
            assert_eq!(snap.parents[0], one);
            for f in ["file-a.txt", "file-b.txt"] {
                assert!(root.join(f).exists());
            }
            trees.push(snap.root);

            drop(repo);
            std::fs::remove_dir_all(&root).unwrap();
        }
        assert_eq!(
            trees[0], trees[1],
            "same content whichever session lands first"
        );
    }

    #[test]
    fn abandoning_one_session_leaves_another_usable() {
        let root = tmp_root("named-abandon");
        let repo = init(&root);
        let a = fork_and_edit(&repo, Some("a"), "file-a.txt", "A\n");
        let b = fork_and_edit(&repo, Some("b"), "file-b.txt", "B\n");
        let plain = fork_and_edit(&repo, None, "file-p.txt", "P\n");
        let b_manifest = repo.layout().ws_root(Some("b")).join("session.toml");

        // Abandon the whole of `a` and the unnamed session while `b` is live.
        assert_eq!(repo.ws_abandon(Some("a"), None).unwrap(), 0);
        assert_eq!(repo.ws_abandon(None, None).unwrap(), 0);
        assert!(!a.dir.exists() && !plain.dir.exists());
        assert!(!repo.layout().dot_sc.join("ws-a").exists());
        assert!(!repo.layout().dot_sc.join("ws").exists());

        // `b` still has its checkout, its edit and its manifest, and still runs.
        assert_eq!(
            std::fs::read_to_string(b.dir.join("file-b.txt")).unwrap(),
            "B\n"
        );
        assert!(b_manifest.is_file());
        assert_eq!(
            repo.ws_run(Some("b"), 1, &["true".into()], false, None)
                .unwrap(),
            0
        );
        assert!(repo
            .ws_run(Some("a"), 1, &["true".into()], false, None)
            .is_err());

        // ...and still harvests.
        let out = repo.ws_harvest(Some("b"), None, "t", None).unwrap();
        assert!(matches!(
            out[..],
            [WsHarvestOutcome::Landed { index: 1, .. }]
        ));
        assert!(root.join("file-b.txt").exists());
        assert!(!root.join("file-a.txt").exists() && !root.join("file-p.txt").exists());
        assert!(repo.ws_sessions().unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn abandoning_one_workspace_of_a_named_session_keeps_its_siblings() {
        let root = tmp_root("named-abandon-one");
        let repo = init(&root);
        let s = repo.ws_fork(Some("a"), 2, "t", None).unwrap();
        assert_eq!(repo.ws_abandon(Some("a"), Some(1)).unwrap(), 1);
        assert!(!s.workspaces[0].dir.exists() && s.workspaces[1].dir.exists());
        let after = repo.ws_session(Some("a")).unwrap().unwrap();
        assert!(!after.workspaces[0].live && after.workspaces[1].live);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_named_session_labels_its_workspaces_and_branches_with_its_name() {
        let root = tmp_root("named-label");
        let repo = init(&root);
        let out_file = root.join("label.txt");
        repo.ws_fork(Some("feat"), 1, "t", None).unwrap();
        let script = format!("printf %s \"$SC_WORKSPACE\" > {}", out_file.display());
        let code = repo
            .ws_run(
                Some("feat"),
                1,
                &["sh".into(), "-c".into(), script],
                false,
                None,
            )
            .unwrap();
        assert_eq!(code, 0);
        assert_eq!(std::fs::read_to_string(&out_file).unwrap(), "feat-1");
        std::fs::remove_file(&out_file).unwrap();

        // A pre-existing branch of the fallback name is suffixed, not clobbered.
        repo.ws_abandon(Some("feat"), None).unwrap();
        let entry = fork_and_edit(&repo, Some("feat"), "a.txt", "ws\n");
        std::fs::write(root.join("a.txt"), "host\n").unwrap();
        repo.commit("t", "host edit").unwrap();
        repo.branch("feat-1").unwrap();
        let out = repo.ws_harvest(Some("feat"), None, "t", None).unwrap();
        match &out[..] {
            [WsHarvestOutcome::FallbackBranch { branch, .. }] => assert_eq!(branch, "feat-1-2"),
            other => panic!("{other:?}"),
        }
        assert!(!entry.dir.exists());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gc_roots_the_base_of_every_open_session() {
        let root = tmp_root("gc-named");
        let repo = init(&root);
        let base = repo.head_tip().unwrap().unwrap();
        let standalone = |msg: &str| {
            let arc = repo.vfs().store();
            let mut s = arc.lock().unwrap();
            let snap = s.get_snapshot(&base).unwrap();
            s.put(scl_core::Object::Snapshot(scl_core::Snapshot {
                root: snap.root,
                parents: vec![base],
                author: "t".into(),
                timestamp: snap.timestamp,
                message: msg.into(),
                secrets: Default::default(),
                protection: Default::default(),
            }))
            .unwrap()
        };
        // Each session's base is reachable from no ref: only its manifest keeps it.
        let mut tips = Vec::new();
        for name in [None, Some("a"), Some("b")] {
            let tip = standalone(name.unwrap_or("plain"));
            crate::refs::write_branch_tip(repo.layout(), "main", &tip).unwrap();
            repo.ws_fork(name, 1, "t", None).unwrap();
            tips.push((name, tip));
        }
        crate::refs::write_branch_tip(repo.layout(), "main", &base).unwrap();

        let has = |tip: &ObjectId| repo.vfs().store().lock().unwrap().contains(tip);
        repo.gc(std::time::Duration::from_secs(0)).unwrap();
        assert!(
            tips.iter().all(|(_, t)| has(t)),
            "every open base survives gc"
        );

        repo.ws_abandon(Some("a"), None).unwrap();
        repo.gc(std::time::Duration::from_secs(0)).unwrap();
        for (name, tip) in &tips {
            assert_eq!(has(tip), *name != Some("a"), "{name:?}");
        }

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_running_command_blocks_harvest_and_abandon_of_its_workspace_only() {
        let root = tmp_root("named-busy");
        let repo = init(&root);
        fork_and_edit(&repo, Some("a"), "file-a.txt", "A\n");
        fork_and_edit(&repo, Some("b"), "file-b.txt", "B\n");

        let plan = repo.ws_run_plan(Some("a"), 1, false, None).unwrap();
        let busy = |e: Error| match e {
            Error::InvalidArgument(m) => assert!(m.contains("still running"), "{m}"),
            other => panic!("{other:?}"),
        };
        busy(repo.ws_harvest(Some("a"), None, "t", None).unwrap_err());
        busy(repo.ws_abandon(Some("a"), None).unwrap_err());
        busy(repo.ws_abandon(Some("a"), Some(1)).unwrap_err());
        // A second run in the same workspace is refused too.
        busy(repo.ws_run_plan(Some("a"), 1, false, None).err().unwrap());
        // Nothing was touched, and the other session is unaffected.
        assert!(repo.ws_session(Some("a")).unwrap().unwrap().workspaces[0].live);
        let out = repo.ws_harvest(Some("b"), None, "t", None).unwrap();
        assert!(matches!(out[..], [WsHarvestOutcome::Landed { .. }]));

        // Once the command is over, the workspace harvests normally.
        assert_eq!(plan.run(&["true".into()]).unwrap(), 0);
        let out = repo.ws_harvest(Some("a"), None, "t", None).unwrap();
        assert!(matches!(out[..], [WsHarvestOutcome::Landed { .. }]));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn dropping_an_unused_run_plan_releases_the_workspace() {
        let root = tmp_root("named-busy-drop");
        let repo = init(&root);
        repo.ws_fork(None, 1, "t", None).unwrap();
        drop(repo.ws_run_plan(None, 1, false, None).unwrap());
        assert_eq!(repo.ws_abandon(None, None).unwrap(), 0);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_run_marker_from_a_dead_process_is_cleared() {
        let root = tmp_root("named-busy-stale");
        let repo = init(&root);
        repo.ws_fork(None, 1, "t", None).unwrap();
        // The pid of a child that has already exited.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        std::fs::write(running_path(repo.layout(), None, 1), pid.to_string()).unwrap();
        assert_eq!(repo.ws_abandon(None, None).unwrap(), 0);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// `sc` is killed but the command it started lives on: the workspace stays busy.
    #[cfg(unix)]
    #[test]
    fn an_orphaned_child_keeps_its_workspace_busy() {
        let root = tmp_root("named-busy-orphan");
        let repo = init(&root);
        repo.ws_fork(None, 1, "t", None).unwrap();
        let mut dead = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = dead.id();
        dead.wait().unwrap();
        let mut orphan = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        std::fs::write(
            running_path(repo.layout(), None, 1),
            format!("{dead_pid} {}", orphan.id()),
        )
        .unwrap();
        assert!(repo.ws_abandon(None, None).is_err(), "child still runs");
        orphan.kill().unwrap();
        orphan.wait().unwrap();
        assert_eq!(repo.ws_abandon(None, None).unwrap(), 0);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn session_names_from_the_command_line_cannot_leave_the_sc_dir() {
        let root = tmp_root("named-escape");
        let repo = init(&root);
        repo.ws_fork(Some("a"), 1, "t", None).unwrap();
        for bad in ["a/../../ws", "../x", ".."] {
            assert!(matches!(
                repo.ws_abandon(Some(bad), None),
                Err(Error::InvalidArgument(_))
            ));
            assert!(repo.ws_session(Some(bad)).is_err());
        }
        // A stray file or oddly named entry does not hide the real sessions.
        std::fs::write(repo.layout().dot_sc.join("ws-stray"), "x").unwrap();
        std::fs::create_dir(repo.layout().dot_sc.join("ws-.hidden")).unwrap();
        let names: Vec<_> = repo
            .ws_sessions()
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, [Some("a".to_string())]);
        repo.gc(std::time::Duration::from_secs(0)).unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
