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

/// The session manifest (`.sc/ws/session.toml`). Never stores key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsSession {
    /// The snapshot every workspace was forked from.
    pub base_snapshot: ObjectId,
    /// The branch `base_snapshot` was the tip of at fork time (display only).
    pub base_branch: String,
    /// The author recorded on any commit a later harvest produces.
    pub author: String,
    pub workspaces: Vec<WsEntry>,
}

fn ws_dir(layout: &Layout) -> PathBuf {
    layout.dot_sc.join("ws")
}

fn manifest_path(layout: &Layout) -> PathBuf {
    ws_dir(layout).join("session.toml")
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
    #[serde(default)]
    workspace: Vec<EntryToml>,
}

impl From<&WsSession> for SessionToml {
    fn from(s: &WsSession) -> Self {
        SessionToml {
            base_snapshot: s.base_snapshot.to_hex(),
            base_branch: s.base_branch.clone(),
            author: s.author.clone(),
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

impl TryFrom<SessionToml> for WsSession {
    type Error = Error;
    fn try_from(raw: SessionToml) -> Result<WsSession> {
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
                Ok(WsEntry { index: e.index, dir: PathBuf::from(e.dir), live: e.live, landed_tip })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(WsSession {
            base_snapshot,
            base_branch: raw.base_branch,
            author: raw.author,
            workspaces,
        })
    }
}

/// Read the open session's manifest, if any. `pub(crate)` so `gc.rs` can root
/// the base snapshot without going through a `Repo`.
pub(crate) fn read_manifest(layout: &Layout) -> Result<Option<WsSession>> {
    match std::fs::read_to_string(manifest_path(layout)) {
        Ok(text) => {
            let raw: SessionToml =
                toml::from_str(&text).map_err(|e| bad(format!("malformed: {e}")))?;
            raw.try_into().map(Some)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Write the session manifest atomically. The parent dir must already exist
/// (fork/abandon create it before the first write).
fn write_manifest(layout: &Layout, session: &WsSession) -> Result<()> {
    let raw: SessionToml = session.into();
    let text = toml::to_string(&raw).map_err(|e| Error::BadConfig(e.to_string()))?;
    scl_core::fsutil::atomic_write_durable(&manifest_path(layout), text.as_bytes())?;
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
        agents: u32,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<WsSession> {
        if agents == 0 {
            return Err(Error::InvalidArgument("agents must be >= 1".into()));
        }
        if let Some(existing) = read_manifest(self.layout())? {
            return Err(Error::InvalidArgument(format!(
                "a workspace session is already open ({} workspace(s) forked from branch {} @ {}); \
                 run `sc ws abandon` first",
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

        let root = ws_dir(self.layout());
        // No manifest proves any .sc/ws content is crash residue from a
        // killed fork — always safe to clear before materializing.
        let _ = std::fs::remove_dir_all(&root);
        let mut workspaces = Vec::with_capacity(agents as usize);
        for i in 1..=agents {
            let dir = root.join(i.to_string());
            if let Err(e) =
                crate::workspace::materialize_workspace(self, tip, &dir, identity, &sparse)
            {
                // Nothing announced yet (no manifest written) — tear down
                // whatever partial checkouts exist so a failed fork leaves
                // no residue under .sc/ws.
                let _ = std::fs::remove_dir_all(&root);
                return Err(e);
            }
            workspaces.push(WsEntry {
                index: i,
                dir,
                live: true,
                landed_tip: None,
            });
        }

        let session = WsSession {
            base_snapshot: tip,
            base_branch: branch,
            author: author.to_string(),
            workspaces,
        };
        write_manifest(self.layout(), &session)?;
        Ok(session)
    }

    /// The open session's manifest, if any.
    pub fn ws_session(&self) -> Result<Option<WsSession>> {
        read_manifest(self.layout())
    }

    /// True if `entry`'s checkout has diverged from the session's base
    /// snapshot. Mirrors `harvest_workspace`'s diff check exactly (repeated,
    /// not extracted — `harvest_workspace` diffs against the harvest's own
    /// `tip` argument, not a manifest, and the two call sites have no shared
    /// caller worth threading a helper through for five lines). Re-reads and
    /// re-parses the manifest on every call; callers that already hold a
    /// loaded `WsSession` (e.g. `sc ws list`'s and `ws_harvest`'s per-entry
    /// loops) should call [`Self::ws_changed_for`] instead (P21).
    pub fn ws_changed(&self, entry: &WsEntry) -> Result<bool> {
        let session = read_manifest(self.layout())?
            .ok_or_else(|| Error::InvalidArgument("no workspace session open".into()))?;
        self.ws_changed_for(&session, entry)
    }

    /// Like [`Self::ws_changed`], but takes an already-loaded `session`
    /// instead of re-reading and re-parsing `session.toml` — a `sc ws list`
    /// over N workspaces used to parse the manifest N times for one listing
    /// (P21).
    pub fn ws_changed_for(&self, session: &WsSession, entry: &WsEntry) -> Result<bool> {
        let base = self.snapshot(&session.base_snapshot)?;
        let ws = Layout::at(&entry.dir);
        // Sparse-aware (P24 Task 4), same reasoning as `ws_fork`: a workspace
        // inherits the host's sparse view, so an absent out-of-sparse path
        // must diff as clean, not as a deletion (mirrors `Repo::status`'s
        // fix in Task 3).
        let sparse = self.sparse_spec()?;
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let d = worktree::diff_worktree(&ws, &mut store, Some(base.root), &base.protection, &sparse)?;
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
    pub fn ws_abandon(&self, index: Option<u32>) -> Result<usize> {
        let mut session = read_manifest(self.layout())?
            .ok_or_else(|| Error::InvalidArgument("no workspace session open".into()))?;
        match index {
            Some(i) => {
                let entry = session
                    .workspaces
                    .iter_mut()
                    .find(|e| e.index == i)
                    .ok_or_else(|| Error::InvalidArgument(format!("no such workspace: {i}")))?;
                if entry.live {
                    let _ = std::fs::remove_dir_all(&entry.dir);
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
            let _ = std::fs::remove_dir_all(ws_dir(self.layout()));
        } else {
            write_manifest(self.layout(), &session)?;
        }
        Ok(remaining)
    }

    /// Run a command in one workspace checkout: spawns `cmd` in `entry.dir`
    /// with SC_WORKSPACE and SC_WORKSPACE_DIR env vars set, optionally injecting
    /// decrypted secrets, and returns the child's exit code. The workspace must be
    /// live (not abandoned); the session must be open. No oplog record, no harvest,
    /// no manifest rewrite — the workspace checkout persists for later harvest.
    pub fn ws_run(
        &self,
        index: u32,
        cmd: &[String],
        with_secrets: bool,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<i32> {
        let session = read_manifest(self.layout())?
            .ok_or_else(|| Error::InvalidArgument("no workspace session open".into()))?;
        let entry = session
            .workspaces
            .iter()
            .find(|e| e.index == index)
            .ok_or_else(|| Error::InvalidArgument(format!("no such workspace: {index}")))?;
        if !entry.live {
            return Err(Error::InvalidArgument(format!("no such workspace: {index}")));
        }

        // Build secret env vars if requested (strict mode, mirroring `sc work`).
        let secret_envs = if with_secrets {
            let sk = identity.ok_or_else(|| {
                Error::InvalidArgument("--with-secrets requires an identity".into())
            })?;
            self.secret_env(sk, /*strict=*/ true)?
        } else {
            Vec::new()
        };

        // Spawn the command in the workspace directory with env vars set.
        let (exe, args) = cmd
            .split_first()
            .ok_or_else(|| Error::InvalidArgument("empty command".into()))?;
        let mut command = std::process::Command::new(exe);
        command
            .args(args)
            .current_dir(&entry.dir)
            // Label matches the work-<i> branch namespace a harvest fallback would mint (P13 parity: label == branch name).
            .env("SC_WORKSPACE", format!("work-{}", entry.index))
            .env("SC_WORKSPACE_DIR", &entry.dir);
        for (k, v) in &secret_envs {
            command.env(k, v);
        }

        let status = command.status()?;
        Ok(status.code().unwrap_or(1))
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
            Err(Error::ProtectedMergeNeedsIdentity(_)) | Err(Error::NotAuthorized(_)) => Ok(false),
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

        let mut session = read_manifest(self.layout())?
            .ok_or_else(|| Error::InvalidArgument("no workspace session open".into()))?;

        let landing = into.unwrap_or(&session.base_branch).to_string();
        let current = refs::current_branch(self.layout())?;
        if current != landing {
            return Err(Error::InvalidArgument(format!(
                "landing branch '{landing}' is not checked out; run `sc switch {landing}` first"
            )));
        }

        let mut live_indices: Vec<u32> =
            session.workspaces.iter().filter(|e| e.live).map(|e| e.index).collect();
        live_indices.sort_unstable();

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

        let mut outcomes = Vec::with_capacity(live_indices.len());
        for i in live_indices {
            let dir = session
                .workspaces
                .iter()
                .find(|e| e.index == i)
                .expect("index came from this session's own live list")
                .dir
                .clone();
            let entry = WsEntry { index: i, dir: dir.clone(), live: true, landed_tip: None };

            // Step 1: unchanged workspaces resolve with no branch created.
            if !self.ws_changed_for(&session, &entry)? {
                resolve_and_teardown(self.layout(), &mut session, i, &dir, None)?;
                outcomes.push(WsHarvestOutcome::Unchanged { index: i });
                continue;
            }

            // Step 2: pick a fallback candidate branch name, suffixed on
            // collision (a prior harvest or a pre-existing branch of the
            // same name).
            let mut branch = format!("work-{i}");
            let mut suffix = 2;
            while refs::resolve_tip(self.layout(), &branch)?.is_some() {
                branch = format!("work-{i}-{suffix}");
                suffix += 1;
            }

            // Step 3: run the workspace through the full commit pipeline
            // (scanner gate, protected-path re-encryption) onto the
            // candidate branch. `tip` is the candidate's parent, which per
            // P13's contract is the session's base snapshot, not the
            // landing branch's current (possibly since-advanced) tip.
            let msg = format!("ws-{i} harvest");
            match crate::workspace::harvest_workspace(
                self,
                session.base_snapshot,
                &dir,
                &branch,
                author,
                &msg,
                &self.sparse_spec()?,
            )? {
                crate::workspace::HarvestResult::Rejected(report) => {
                    // DESIGN DECISION (spec precision note, Task 5): a
                    // scanner-rejected workspace stays LIVE so the offending
                    // file can be fixed in place and re-harvested, unlike
                    // P13's one-shot `sc work` which treats rejection as
                    // terminal. No candidate branch was created
                    // (`harvest_workspace` never calls `write_branch_tip` on
                    // the `SecretDetected` path), so nothing to clean up; the
                    // manifest is untouched for this entry.
                    outcomes.push(WsHarvestOutcome::Rejected { index: i, report: report.to_string() });
                }
                crate::workspace::HarvestResult::Unchanged => {
                    // `ws_changed` already confirmed a diff, but
                    // `harvest_workspace` re-diffs independently against its
                    // own `tip` argument (session.base_snapshot, same value
                    // here) — so this arm is unreachable in practice, kept
                    // only so the match is exhaustive without a panic.
                    resolve_and_teardown(self.layout(), &mut session, i, &dir, None)?;
                    outcomes.push(WsHarvestOutcome::Unchanged { index: i });
                }
                crate::workspace::HarvestResult::Committed(id) => {
                    let current_tip = refs::read_branch_tip(self.layout(), &landing)?
                        .ok_or(Error::Unborn)?;
                    let clean = self.would_merge_cleanly(current_tip, id, identity)?;
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
                                resolve_and_teardown(self.layout(), &mut session, i, &dir, Some(merged))?;
                                outcomes.push(WsHarvestOutcome::Landed { index: i, merged_tip: merged });
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
            let _ = std::fs::remove_dir_all(ws_dir(self.layout()));
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
    Ok(())
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

        let session = repo.ws_fork(2, "t", None).unwrap();
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

        let err = repo.ws_fork(1, "t", None).unwrap_err();
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

        let session = repo.ws_fork(1, "t", None).unwrap();
        let entry = &session.workspaces[0];
        assert!(entry.dir.join("src/a.txt").exists(), "in-sparse file must materialize");
        assert!(!entry.dir.join("docs/x").exists(), "out-of-sparse file must not materialize");

        // Harvest carries the untouched out-of-sparse subtree verbatim.
        std::fs::write(entry.dir.join("src/a.txt"), b"a v2").unwrap();
        let outcomes = repo.ws_harvest(None, "t", None).unwrap();
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
        assert!(entries.contains_key("docs/x"), "harvest must carry the out-of-sparse subtree");
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
    fn fork_clears_manifestless_crash_residue() {
        let root = tmp_root("fork-residue");
        let repo = init(&root);
        let tip = repo.head_tip().unwrap().unwrap();

        // Simulate a kill -9 mid-fork: a workspace dir exists with a stray
        // file but no manifest was ever written to announce the session.
        let ws_root = ws_dir(repo.layout());
        std::fs::create_dir_all(ws_root.join("1")).unwrap();
        std::fs::write(ws_root.join("1").join("residue.txt"), "stale\n").unwrap();
        assert!(repo.ws_session().unwrap().is_none());

        let session = repo.ws_fork(2, "t", None).unwrap();
        assert_eq!(session.base_snapshot, tip);
        assert_eq!(session.workspaces.len(), 2);

        // Neither freshly forked workspace shows the residue as a change.
        for entry in &session.workspaces {
            assert!(
                !repo.ws_changed(entry).unwrap(),
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
        let outcomes = repo.ws_harvest(None, "t", None).unwrap();
        assert!(outcomes
            .iter()
            .all(|o| matches!(o, WsHarvestOutcome::Unchanged { .. })));
        assert!(repo.ws_session().unwrap().is_none());
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
            repo.ws_fork(2, "t", None).unwrap();
        } // repo (and its lock) dropped: simulates the process exiting

        let repo = Repo::open(&root).unwrap();
        let session = repo
            .ws_session()
            .unwrap()
            .expect("manifest must survive reopen");
        assert_eq!(session.workspaces.len(), 2);
        for entry in &session.workspaces {
            assert!(
                !repo.ws_changed(entry).unwrap(),
                "freshly forked checkout must be unchanged"
            );
        }

        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited\n").unwrap();
        assert!(repo.ws_changed(&session.workspaces[0]).unwrap());
        assert!(!repo.ws_changed(&session.workspaces[1]).unwrap());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn abandon_one_and_all() {
        let root = tmp_root("abandon");
        let repo = init(&root);
        let session = repo.ws_fork(2, "t", None).unwrap();
        let dir1 = session.workspaces[0].dir.clone();
        let dir2 = session.workspaces[1].dir.clone();

        let remaining = repo.ws_abandon(Some(1)).unwrap();
        assert_eq!(remaining, 1);
        assert!(!dir1.exists());
        let after = repo.ws_session().unwrap().expect("session still open");
        let e1 = after.workspaces.iter().find(|e| e.index == 1).unwrap();
        assert!(!e1.live);
        assert!(dir2.exists());

        let remaining = repo.ws_abandon(None).unwrap();
        assert_eq!(remaining, 0);
        assert!(!dir2.exists());
        assert!(repo.ws_session().unwrap().is_none());

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

        repo.ws_fork(1, "t", Some(&sk)).unwrap();
        let text = std::fs::read_to_string(manifest_path(repo.layout())).unwrap();
        assert!(
            !text.contains("scl-sk"),
            "manifest must never contain key material: {text}"
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
        repo.ws_fork(1, "t", None).unwrap();
        crate::refs::write_branch_tip(repo.layout(), "main", &base).unwrap();

        repo.gc(std::time::Duration::from_secs(0)).unwrap();
        let arc = repo.vfs().store();
        let s = arc.lock().unwrap();
        assert!(
            s.contains(&tip),
            "an open session's base snapshot must survive gc"
        );
        drop(s);

        repo.ws_abandon(None).unwrap();
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
        let session = repo.ws_fork(2, "t", None).unwrap();
        let entry = &session.workspaces[1]; // work-2

        // Run a command that writes SC_WORKSPACE and pwd to files.
        let exit = repo
            .ws_run(
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

        let session = repo.ws_fork(1, "t", Some(&sk)).unwrap();
        let entry = &session.workspaces[0];

        let exit = repo
            .ws_run(
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
        let _session = repo.ws_fork(2, "t", None).unwrap();

        // Non-existent workspace index.
        let err = repo
            .ws_run(
                999,
                &["sh".to_string(), "-c".to_string(), "true".to_string()],
                false,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
        assert!(err.to_string().contains("no such workspace: 999"));

        // Abandon workspace 1, then try to run in it.
        repo.ws_abandon(Some(1)).unwrap();
        let err = repo
            .ws_run(
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
        let session = repo.ws_fork(2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        std::fs::write(session.workspaces[1].dir.join("b.txt"), "new-b\n").unwrap();

        let oplog_before = repo.oplog().unwrap().len();
        let outcomes = repo.ws_harvest(None, "t", None).unwrap();
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
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "edited-a\n");
        assert_eq!(std::fs::read_to_string(root.join("b.txt")).unwrap(), "new-b\n");

        // Exactly 2 new oplog records (one per landing).
        let oplog_after = repo.oplog().unwrap().len();
        assert_eq!(oplog_after - oplog_before, 2);

        // No work-1/work-2 branches remain (candidate refs deleted after landing).
        assert!(crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap().is_none());
        assert!(crate::refs::read_branch_tip(repo.layout(), "work-2").unwrap().is_none());

        // Session ended.
        assert!(repo.ws_session().unwrap().is_none());
        assert!(!repo.layout().dot_sc.join("ws").exists());

        // sc undo reverts ONLY the second landing: a.txt edit still present,
        // b.txt edit gone.
        repo.undo().unwrap();
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "edited-a\n");
        assert!(!root.join("b.txt").exists());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_conflict_falls_back_without_touching_anything() {
        let root = tmp_root("harvest-conflict");
        let repo = init(&root);
        std::fs::write(root.join("x.txt"), "base-x\n").unwrap();
        repo.commit("t", "add x").unwrap();

        let session = repo.ws_fork(2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        std::fs::write(session.workspaces[1].dir.join("x.txt"), "ws2-x\n").unwrap();

        // A conflicting x.txt change lands on main AFTER fork, so ws-2's
        // eventual merge (base = the fork-time tip) conflicts on x.txt.
        std::fs::write(root.join("x.txt"), "main-x\n").unwrap();
        repo.commit("t", "conflict x on main").unwrap();

        let outcomes = repo.ws_harvest(None, "t", None).unwrap();
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
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "edited-a\n");
        assert_eq!(std::fs::read_to_string(root.join("x.txt")).unwrap(), "main-x\n");

        // work-2 branch exists with ws-2's commit.
        assert!(crate::refs::read_branch_tip(repo.layout(), "work-2").unwrap().is_some());

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
        assert!(repo.ws_session().unwrap().is_none());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_requires_landing_branch_checked_out() {
        let root = tmp_root("harvest-notcheckedout");
        let repo = init(&root);
        repo.branch("other").unwrap();
        let session = repo.ws_fork(1, "t", None).unwrap();
        repo.switch("other").unwrap();

        let err = repo.ws_harvest(None, "t", None).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => {
                assert!(msg.contains("main"), "message must name the landing branch: {msg}");
                assert!(msg.contains("sc switch"), "message must suggest sc switch: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        // Session still open; nothing moved.
        let after = repo.ws_session().unwrap().expect("session must still be open");
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

        let session = repo.ws_fork(2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        std::fs::write(session.workspaces[1].dir.join("x.txt"), "ws2-x\n").unwrap();
        std::fs::write(root.join("x.txt"), "main-x\n").unwrap();
        repo.commit("t", "conflict x on main").unwrap();

        // Pre-create branch "work-2" so ws-2's fallback must suffix.
        repo.branch("work-2").unwrap();

        // --into with the checked-out branch name behaves as default.
        let outcomes = repo.ws_harvest(Some("main"), "t", None).unwrap();
        match &outcomes[1] {
            WsHarvestOutcome::FallbackBranch { index: 2, branch } => {
                assert_eq!(branch, "work-2-2");
            }
            other => panic!("expected FallbackBranch(2, \"work-2-2\"), got {other:?}"),
        }

        // --into a non-checked-out branch errors.
        let _session2 = repo.ws_fork(1, "t", None).unwrap();
        let err = repo.ws_harvest(Some("nonexistent-branch"), "t", None).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_guards_and_dirty_tree() {
        let root = tmp_root("harvest-guards");
        let repo = init(&root);
        let session = repo.ws_fork(1, "t", None).unwrap();

        // (a) merge/pick/rebase in progress -> typed errors.
        crate::merge_state::write(repo.layout(), &ObjectId::of(b"theirs"), &[], None).unwrap();
        assert!(matches!(repo.ws_harvest(None, "t", None), Err(Error::MergeInProgress)));
        crate::merge_state::clear(repo.layout()).unwrap();

        crate::pick_state::write(repo.layout(), &ObjectId::of(b"picked"), &[], None, None).unwrap();
        assert!(matches!(repo.ws_harvest(None, "t", None), Err(Error::PickInProgress)));
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
        assert!(matches!(repo.ws_harvest(None, "t", None), Err(Error::RebaseInProgress)));
        crate::rebase_state::clear(repo.layout()).unwrap();

        // (b) dirty user working tree -> InvalidArgument, caught by the
        // up-front preflight (not merge_with_identity's own dirty guard) so
        // no candidate branch is ever minted for the live, changed workspace.
        // Session intact.
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "ws-edit\n").unwrap();
        std::fs::write(root.join("a.txt"), "dirty-uncommitted\n").unwrap();
        let err = repo.ws_harvest(None, "t", None).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        let after = repo.ws_session().unwrap().expect("session must still be open");
        assert!(after.workspaces[0].live, "workspace must remain live after the abort");

        // No stray work-1 branch: the preflight refused before
        // `harvest_workspace` ever ran.
        assert!(
            crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap().is_none(),
            "preflight must refuse before any candidate branch is minted"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_partial_leaves_session_open() {
        let root = tmp_root("harvest-partial");
        let repo = init(&root);
        let session = repo.ws_fork(2, "t", None).unwrap();
        std::fs::write(session.workspaces[0].dir.join("a.txt"), "edited-a\n").unwrap();
        // An AWS-style key id trips the P5 scanner in ws-2's checkout.
        std::fs::write(session.workspaces[1].dir.join("leak.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let outcomes = repo.ws_harvest(None, "t", None).unwrap();
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
        let after = repo.ws_session().unwrap().expect("session must still be open");
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
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "base\n");
        let after_undo =
            repo.ws_session().unwrap().expect("ws-2 still live keeps the session open");
        let e1_after_undo = after_undo.workspaces.iter().find(|e| e.index == 1).unwrap();
        assert_eq!(
            repo.ws_status_label(&after_undo, e1_after_undo).unwrap(),
            "landed (undone by sc undo)"
        );

        // Fixing the file then re-harvesting completes and ends the session.
        std::fs::remove_file(e2.dir.join("leak.txt")).unwrap();
        let outcomes2 = repo.ws_harvest(None, "t", None).unwrap();
        assert_eq!(outcomes2.len(), 1);
        match &outcomes2[0] {
            WsHarvestOutcome::Unchanged { index: 2 } => {}
            other => panic!("expected Unchanged(2) once the leak is removed, got {other:?}"),
        }
        assert!(repo.ws_session().unwrap().is_none());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn harvest_reharvest_after_crash_window_is_idempotent() {
        let root = tmp_root("harvest-reharvest");
        let repo = init(&root);
        let session = repo.ws_fork(1, "t", None).unwrap();
        let dir = session.workspaces[0].dir.clone();
        std::fs::write(dir.join("a.txt"), "edited-a\n").unwrap();

        // Reproduction requires the two `harvest_workspace` calls below to
        // fall in the same `unix_now()` second (both mint a commit from the
        // same parent/tree/author/message; only the timestamp can differ).
        // Align to a fresh second boundary first so the whole sequence below
        // — which takes low tens of milliseconds — has close to a full
        // second of headroom, instead of racing an arbitrary boundary.
        let start_second = crate::repo::unix_now();
        while crate::repo::unix_now() == start_second {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let outcomes = repo.ws_harvest(None, "t", None).unwrap();
        let landed_tip = match &outcomes[0] {
            WsHarvestOutcome::Landed { index: 1, merged_tip } => *merged_tip,
            other => panic!("expected Landed(1), got {other:?}"),
        };
        assert!(repo.ws_session().unwrap().is_none(), "session must have ended");

        // Simulate a kill -9 between the candidate branch landing and the
        // manifest rewrite that would have resolved the entry: re-mark ws-1
        // live and restore its checkout dir with identical content, so a
        // re-harvest re-mints an identical candidate id (same parent, tree,
        // author, and message; timestamp matches too as long as this test
        // doesn't straddle a wall-clock second boundary).
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "edited-a\n").unwrap();
        let crashed = WsSession {
            base_snapshot: session.base_snapshot,
            base_branch: session.base_branch.clone(),
            author: session.author.clone(),
            workspaces: vec![WsEntry { index: 1, dir: dir.clone(), live: true, landed_tip: None }],
        };
        write_manifest(repo.layout(), &crashed).unwrap();

        // Re-harvest: no error, resolves as a no-op Landed at the existing
        // tip, and leaves no stray branch behind.
        let outcomes2 = repo.ws_harvest(None, "t", None).unwrap();
        assert_eq!(outcomes2.len(), 1);
        match &outcomes2[0] {
            WsHarvestOutcome::Landed { index: 1, merged_tip } => {
                assert_eq!(
                    *merged_tip, landed_tip,
                    "re-harvest of an already-landed workspace must resolve to the existing landing tip"
                );
            }
            other => panic!("expected Landed(1), got {other:?}"),
        }
        assert!(
            crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap().is_none(),
            "no stray candidate branch after the UpToDate no-op resolution"
        );
        assert!(repo.ws_session().unwrap().is_none());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
