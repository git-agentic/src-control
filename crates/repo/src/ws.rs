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
            .map(|e| WsEntry {
                index: e.index,
                dir: PathBuf::from(e.dir),
                live: e.live,
            })
            .collect();
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

        let root = ws_dir(self.layout());
        let mut workspaces = Vec::with_capacity(agents as usize);
        for i in 1..=agents {
            let dir = root.join(i.to_string());
            if let Err(e) = crate::workspace::materialize_workspace(self, tip, &dir, identity) {
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
    /// caller worth threading a helper through for five lines).
    pub fn ws_changed(&self, entry: &WsEntry) -> Result<bool> {
        let session = read_manifest(self.layout())?
            .ok_or_else(|| Error::InvalidArgument("no workspace session open".into()))?;
        let base = self.snapshot(&session.base_snapshot)?;
        let ws = Layout::at(&entry.dir);
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let d = worktree::diff_worktree(&ws, &mut store, Some(base.root), &base.protection)?;
        Ok(!(d.added.is_empty() && d.modified.is_empty() && d.deleted.is_empty()))
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
            .env("SC_WORKSPACE", format!("ws-{}", entry.index))
            .env("SC_WORKSPACE_DIR", &entry.dir);
        for (k, v) in &secret_envs {
            command.env(k, v);
        }

        let status = command.status()?;
        Ok(status.code().unwrap_or(1))
    }
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
        let entry = &session.workspaces[1]; // ws-2

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

        // Check SC_WORKSPACE holds the label "ws-2".
        let env_content = std::fs::read_to_string(entry.dir.join("env.txt")).unwrap();
        assert_eq!(env_content.trim(), "ws-2");

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
}
