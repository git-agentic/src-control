//! Agent workspace sessions (P13): fork N in-RAM workspaces from a persistent
//! repo's HEAD, materialize each to an ephemeral checkout, run agent commands,
//! and harvest changed workspaces back as branches. The repo's budget-bounded
//! persistent store is the backing tier — forks share one Arc'd blob cache and
//! eviction is always safe (every object is reconstructible from `.sc/objects`).

use std::path::Path;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::refs;
use crate::repo::Repo;
use crate::worktree;

/// Outcome of harvesting one workspace checkout.
#[derive(Debug)]
pub enum HarvestResult {
    /// Changes committed; the workspace branch points at this snapshot.
    Committed(ObjectId),
    /// Checkout identical to the base snapshot; no branch created.
    Unchanged,
    /// The P5 scanner found plaintext secrets; nothing was committed.
    Rejected(crate::scanner::ScanReport),
}

/// Materialize the snapshot at `tip` into `dir` (created if absent), applying
/// the same P7 protected-path rules as `sc switch`: decrypt with `identity`
/// when possible, otherwise skip. Returns the skipped protected paths.
///
/// `sparse` (P24 Task 4) is caller-chosen, not implicit: `sc work` (P13,
/// one-shot ephemeral agents) always passes `Sparse::default()` — an agent
/// needs the complete tree to operate correctly, and silently narrowing what
/// it sees to the primary repo's sparse view would be a surprising,
/// unrequested behavior change. `sc ws fork` (P20, durable sessions) passes
/// the host repo's own `sparse_spec()` — a durable workspace is closer to a
/// second working tree for the same repo, so it inherits the same view.
pub(crate) fn materialize_workspace(
    repo: &Repo,
    tip: ObjectId,
    dir: &Path,
    identity: Option<&scl_crypto::SecretKey>,
    sparse: &crate::sparse::Sparse,
    cache: Option<&mut crate::cache::ProtectedCache>,
) -> Result<Vec<String>> {
    std::fs::create_dir_all(dir)?;
    let snap = repo.snapshot(&tip)?;
    let ws = Layout::at(dir);
    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();
    // The per-workspace cache (P33 Task 7) is opened by the caller with its
    // `root` set to THIS checkout dir and its file at `Layout::ws_cache_path`
    // (beside the checkout dir, never inside it, so harvest's worktree read
    // can't pick it up). `sc ws fork` passes a persistent cache; `sc work`
    // passes an ephemeral one threaded fork->harvest. A `None` cache still
    // works — a workspace's randomized protected path just re-seals on the
    // next harvest instead of carrying (spurious-but-safe, per `cache.rs`).
    worktree::materialize(
        &ws,
        &mut store,
        snap.root,
        None,
        &snap.protection,
        identity,
        sparse,
        cache,
    )
}

/// Diff the checkout at `dir` against the base snapshot `tip`; if changed,
/// snapshot it through the full commit pipeline (scanner gate, protected-path
/// re-encryption, carry-forward) and point `branch` at the result. Never
/// touches HEAD or the current branch.
pub(crate) fn harvest_workspace(
    repo: &Repo,
    tip: ObjectId,
    dir: &Path,
    branch: &str,
    author: &str,
    message: &str,
    sparse: &crate::sparse::Sparse,
    cache: Option<&mut crate::cache::ProtectedCache>,
) -> Result<HarvestResult> {
    let snap = repo.snapshot(&tip)?;
    let ws = Layout::at(dir);
    let (tracked, changed) = {
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let tracked: std::collections::BTreeSet<String> =
            worktree::tree_file_ids(&mut store, snap.root)?
                .into_keys()
                .collect();
        // The workspace-local cache (P33 Task 7) proves an untouched randomized
        // protected path unchanged, so it isn't spuriously reported modified
        // here (which would send it into the fresh-seal path in `snapshot_files`
        // below). Its `root` is this checkout dir, so its stat lookups resolve
        // against the workspace's own files — unlike the host cache, which
        // would stat the wrong tree.
        let d = worktree::diff_worktree(
            &ws,
            &mut store,
            Some(snap.root),
            &snap.protection,
            sparse,
            cache.as_deref(),
        )?;
        (
            tracked,
            !(d.added.is_empty() && d.modified.is_empty() && d.deleted.is_empty()),
        )
    };
    if !changed {
        return Ok(HarvestResult::Unchanged);
    }
    let files = worktree::read_worktree(&ws, &tracked)?;
    // The same `sparse` the caller used for the diff above is threaded into
    // the commit carry (P24 final-review fix): the workspace's view was
    // fixed at materialize time (or, for `sc work`, is always full), so the
    // carry predicate must see that same view, not the host repo's current
    // `.sc/sparse` — see `snapshot_files`'s doc comment.
    // The workspace-local cache is threaded into the commit too (P33 Task 7):
    // its `root` is this checkout dir, so a randomized protected path the
    // workspace never touched carries the base's exact ciphertext blob id
    // (proven unchanged by the cache) instead of re-sealing. Convergent priors
    // still carry via content-only compare, no cache needed.
    match repo.snapshot_files(
        files,
        Some(tip),
        None,
        None,
        None,
        None,
        None,
        sparse,
        cache,
        author,
        message,
    ) {
        Ok(id) => {
            refs::write_branch_tip(repo.layout(), branch, &id)?;
            Ok(HarvestResult::Committed(id))
        }
        Err(Error::SecretDetected(report)) => Ok(HarvestResult::Rejected(report)),
        Err(e) => Err(e),
    }
}

/// Options for a `sc work` session: fork `agents` in-RAM workspaces from
/// HEAD, run `cmd` in each concurrently, and harvest changed workspaces to
/// `<base_name>-<i>` branches.
pub struct WorkOptions {
    /// Number of parallel agent workspaces to fork (must be >= 1).
    pub agents: usize,
    /// Branch/label base; branches are `<base_name>-1..N`.
    pub base_name: String,
    /// The agent command line; `cmd[0]` is the executable.
    pub cmd: Vec<String>,
    /// Commit author recorded on any harvested workspace commit.
    pub author: String,
    /// Commit message; defaults to the joined agent command line.
    pub message: Option<String>,
    /// Decrypts protected paths at checkout; also required by `with_secrets`.
    pub identity: Option<scl_crypto::SecretKey>,
    /// Decrypt every registered secret and inject it into each agent's
    /// environment. Requires `identity`; fails preflight if any secret is
    /// unauthorized for that identity.
    pub with_secrets: bool,
    /// Session temp root override (tests); default `$TMPDIR/sc-work-<pid>`.
    /// The directory is created fresh (`0700` on unix) and `work` refuses to
    /// run if it already exists — a pre-existing directory at this path is
    /// refused rather than reused, closing a squat-attack window on shared
    /// hosts (predictable name + adopted directory could otherwise leak a
    /// workspace's decrypted protected-path plaintext to another user).
    pub session_root: Option<std::path::PathBuf>,
}

/// Per-workspace session result: what the agent did and what harvest kept.
#[derive(Debug)]
pub struct WorkspaceOutcome {
    /// The workspace's branch label, `<base_name>-<i>`.
    pub label: String,
    /// Agent exit code; `None` if the spawn failed or the exit was signal-killed.
    pub agent_exit: Option<i32>,
    /// The harvest result for this workspace's checkout.
    pub harvest: Result<HarvestResult>,
}

/// Creates the session temp root exclusively: refuses if the path already
/// exists (a predictable name plus a pre-existing directory is exactly the
/// squat-attack scenario — a session must never adopt someone else's
/// directory), and on unix creates it `0700` so it is not world-traversable
/// (the session may hold decrypted protected-path plaintext on shared hosts).
fn create_session_root(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(Error::InvalidArgument(format!(
            "session root already exists (refusing to reuse it): {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)?;
    }
    Ok(())
}

/// Removes the session temp tree however the session exits (success, error,
/// or panic) — the zero-residue guarantee outside `.sc/`.
struct Teardown(std::path::PathBuf);
impl Drop for Teardown {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Repo {
    /// Run a one-command agent-workspace session: fork `agents` in-RAM
    /// workspaces from HEAD, materialize each to an ephemeral checkout, run
    /// `cmd` in each concurrently, and harvest changed workspaces to
    /// `<base_name>-<i>` branches. The current branch, HEAD, and the user's
    /// working tree are never touched. One workspace's failure (agent exit,
    /// scanner rejection, harvest error) never aborts its siblings.
    pub fn work(&self, opts: WorkOptions) -> Result<Vec<WorkspaceOutcome>> {
        self.refuse_on_private("sc work")?;
        if opts.agents == 0 {
            return Err(Error::InvalidArgument("agents must be >= 1".into()));
        }
        if opts.cmd.is_empty() {
            return Err(Error::InvalidArgument("empty agent command".into()));
        }
        // Partial-clone guard (P27 Task 5 review Important fix): `sc work`
        // always materializes each workspace with `Sparse::default()` (full
        // materialization) by design — an agent needs the complete tree,
        // never silently narrowed to the host's sparse view (see
        // `materialize_workspace`'s doc comment). On a partial clone "the
        // complete tree" includes out-of-filter content this clone never
        // fetched, so that materialize call would hit the raw
        // corruption-shaped `NotFound` this guard family exists to
        // eliminate. Refuse loudly up front instead.
        if self.promisor()?.is_some() {
            return Err(crate::promisor::partial_clone_unsupported("sc work"));
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let labels: Vec<String> = (1..=opts.agents)
            .map(|i| format!("{}-{i}", opts.base_name))
            .collect();
        for label in &labels {
            crate::repo::validate_branch_name(label)?;
            if refs::read_branch_tip(self.layout(), label)?.is_some() {
                return Err(Error::BadRef(format!("branch already exists: {label}")));
            }
        }
        let secret_envs = match (opts.with_secrets, &opts.identity) {
            (true, Some(sk)) => self.secret_env(sk, true)?,
            (true, None) => {
                return Err(Error::InvalidArgument(
                    "--with-secrets requires an identity".into(),
                ))
            }
            _ => Vec::new(),
        };

        let session_root = opts.session_root.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("sc-work-{}", std::process::id()))
        });
        create_session_root(&session_root)?;
        let _teardown = Teardown(session_root.clone());

        // The session's in-RAM workspace handles: N forks pin the base
        // snapshot and share the store's Arc'd blobs (asserted zero-copy in
        // tests). Held for the session's lifetime.
        let mut _forks = Vec::with_capacity(labels.len());
        for label in &labels {
            _forks.push(self.vfs().fork(tip, label.clone())?);
        }

        let message = opts.message.clone().unwrap_or_else(|| opts.cmd.join(" "));
        let (exe, args) = opts.cmd.split_first().expect("checked non-empty above");

        // Materialize every checkout before spawning any agent. Materialize
        // is the only `?`-aborting step past this point (spawn failures are
        // captured per-workspace, not propagated), so finishing it up front
        // guarantees no early return can occur while children are running —
        // an interleaved failure would orphan live agents and race the
        // teardown guard's remove_dir_all underneath them.
        // One EPHEMERAL protected-cache per temp checkout (P33 Task 7): `root`
        // is the checkout dir, `path` is `None` so nothing persists (a `sc
        // work` session leaves zero residue outside `.sc/`). Threaded from
        // this materialize loop into the harvest loop below so an untouched
        // randomized protected path carries the base blob instead of resealing.
        let key = crate::cache::local_key(&self.layout)?;
        let mut dirs = Vec::with_capacity(labels.len());
        let mut caches = Vec::with_capacity(labels.len());
        for label in &labels {
            let dir = session_root.join(label);
            let mut cache = crate::cache::ProtectedCache::open(key, dir.clone(), None);
            let skipped = materialize_workspace(
                self,
                tip,
                &dir,
                opts.identity.as_ref(),
                &crate::sparse::Sparse::default(),
                Some(&mut cache),
            )?;
            for path in &skipped {
                eprintln!("workspace {label}: skipped (no key): {path}");
            }
            dirs.push(dir);
            caches.push(cache);
        }

        // Spawn all agents first (they run concurrently), then await each. The
        // ephemeral cache travels alongside each (label, dir) into the harvest.
        let mut children = Vec::with_capacity(labels.len());
        for ((label, dir), cache) in labels.iter().zip(dirs).zip(caches) {
            let mut c = std::process::Command::new(exe);
            c.args(args)
                .current_dir(&dir)
                .env("SC_WORKSPACE", label)
                .env("SC_WORKSPACE_DIR", &dir);
            for (k, v) in &secret_envs {
                c.env(k, v);
            }
            children.push((label.clone(), dir, cache, c.spawn()));
        }

        let mut outcomes = Vec::with_capacity(children.len());
        for (label, dir, mut cache, spawn) in children {
            let agent_exit = match spawn {
                Ok(mut child) => child.wait().ok().and_then(|s| s.code()),
                Err(e) => {
                    eprintln!("workspace {label}: failed to spawn agent: {e}");
                    None
                }
            };
            let harvest = harvest_workspace(
                self,
                tip,
                &dir,
                &label,
                &opts.author,
                &message,
                &crate::sparse::Sparse::default(),
                Some(&mut cache),
            );
            outcomes.push(WorkspaceOutcome {
                label,
                agent_exit,
                harvest,
            });
        }

        let created: Vec<(String, Option<ObjectId>, Option<ObjectId>)> = outcomes
            .iter()
            .filter_map(|o| match &o.harvest {
                Ok(HarvestResult::Committed(id)) => Some((o.label.clone(), None, Some(*id))),
                _ => None,
            })
            .collect();
        if !created.is_empty() {
            let head = refs::current_branch(self.layout())?;
            crate::oplog::record(
                self.layout(),
                &format!("work: {} agents, base {}", opts.agents, opts.base_name),
                &head,
                &head,
                &created,
            )?;
        }

        Ok(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    /// Fresh persistent repo in a unique temp dir with one committed file.
    /// Returns (repo root, workspace scratch dir); caller removes both.
    fn setup(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("sc-ws-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("repo");
        let scratch = base.join("scratch");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        {
            let repo = Repo::init(&root).unwrap();
            std::fs::write(root.join("a.txt"), "base\n").unwrap();
            repo.commit("test", "base").unwrap();
        }
        (root, scratch)
    }

    fn teardown(root: &std::path::Path) {
        let base = root.parent().unwrap();
        std::fs::remove_dir_all(base).unwrap();
        assert!(!base.exists());
    }

    #[test]
    fn materialize_then_harvest_edit_creates_branch() {
        let (root, scratch) = setup("edit");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let dir = scratch.join("ws1");
        let skipped = materialize_workspace(
            &repo,
            tip,
            &dir,
            None,
            &crate::sparse::Sparse::default(),
            None,
        )
        .unwrap();
        assert!(skipped.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join("a.txt")).unwrap(),
            "base\n"
        );

        std::fs::write(dir.join("a.txt"), "edited\n").unwrap();
        let res = harvest_workspace(
            &repo,
            tip,
            &dir,
            "work-1",
            "test",
            "msg",
            &crate::sparse::Sparse::default(),
            None,
        )
        .unwrap();
        let id = match res {
            HarvestResult::Committed(id) => id,
            other => panic!("expected Committed, got {other:?}"),
        };
        // Branch points at the new snapshot; parent is the base tip; HEAD untouched.
        assert_eq!(
            crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(),
            Some(id)
        );
        assert_eq!(repo.snapshot(&id).unwrap().parents, vec![tip]);
        assert_eq!(repo.head_tip().unwrap(), Some(tip));
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn unchanged_workspace_creates_no_branch() {
        let (root, scratch) = setup("unchanged");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let dir = scratch.join("ws1");
        materialize_workspace(
            &repo,
            tip,
            &dir,
            None,
            &crate::sparse::Sparse::default(),
            None,
        )
        .unwrap();
        let res = harvest_workspace(
            &repo,
            tip,
            &dir,
            "work-1",
            "test",
            "msg",
            &crate::sparse::Sparse::default(),
            None,
        )
        .unwrap();
        assert!(matches!(res, HarvestResult::Unchanged));
        assert_eq!(
            crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(),
            None
        );
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn plaintext_secret_in_workspace_is_rejected() {
        let (root, scratch) = setup("scan");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let dir = scratch.join("ws1");
        materialize_workspace(
            &repo,
            tip,
            &dir,
            None,
            &crate::sparse::Sparse::default(),
            None,
        )
        .unwrap();
        // An AWS-style key id trips the P5 pattern rules.
        std::fs::write(dir.join("leak.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let res = harvest_workspace(
            &repo,
            tip,
            &dir,
            "work-1",
            "test",
            "msg",
            &crate::sparse::Sparse::default(),
            None,
        )
        .unwrap();
        assert!(matches!(res, HarvestResult::Rejected(_)));
        assert_eq!(
            crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(),
            None
        );
        drop(repo);
        teardown(&root);
    }

    fn work_opts(agents: usize, cmd: &[&str], scratch: &std::path::Path) -> WorkOptions {
        WorkOptions {
            agents,
            base_name: "work".into(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            author: "test".into(),
            message: None,
            identity: None,
            with_secrets: false,
            session_root: Some(scratch.join("session")),
        }
    }

    #[test]
    fn sc_work_full_agent_deletion_survives_host_sparse() {
        // P24 final-review fix, Important 1: `sc work` agents always get a
        // FULL checkout (`Sparse::default()`), regardless of the host repo's
        // own sparse spec. A genuine deletion of an out-of-host-sparse path
        // by such an agent must land as a real deletion, not be silently
        // reverted because harvest read the host's narrow spec.
        let (root, scratch) = setup("full-agent-deletion");
        let repo = Repo::open(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), "a\n").unwrap();
        std::fs::write(root.join("docs/x.txt"), "doc\n").unwrap();
        repo.commit("test", "add src+docs").unwrap();

        // Host narrows to src/ — docs/x.txt leaves the host's own disk, but
        // `sc work` agents still get the full tree (contract preserved).
        repo.set_sparse(&["src/".into()], None).unwrap();
        assert!(!root.join("docs/x.txt").exists());

        let opts = work_opts(1, &["sh", "-c", "rm docs/x.txt"], &scratch);
        let outcomes = repo.work(opts).unwrap();
        let id = match outcomes[0].harvest.as_ref().unwrap() {
            HarvestResult::Committed(id) => *id,
            other => panic!("expected Committed, got {other:?}"),
        };

        let snap = repo.snapshot(&id).unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = crate::worktree::tree_file_ids(&mut store, snap.root).unwrap();
        assert!(
            !ids.contains_key("docs/x.txt"),
            "the agent's genuine deletion of an out-of-host-sparse file must land, \
             not be silently reverted by the host's narrow spec"
        );
        assert!(
            ids.contains_key("src/a.txt"),
            "untouched in-sparse file still present"
        );
        drop(store);
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn work_session_forks_runs_and_harvests_n_branches() {
        let (root, scratch) = setup("session");
        let repo = Repo::open(&root).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let opts = work_opts(
            3,
            &["sh", "-c", "echo \"$SC_WORKSPACE\" > out.txt"],
            &scratch,
        );
        let session_root = opts.session_root.clone().unwrap();
        let outcomes = repo.work(opts).unwrap();
        assert_eq!(outcomes.len(), 3);
        for (i, o) in outcomes.iter().enumerate() {
            let label = format!("work-{}", i + 1);
            assert_eq!(o.label, label);
            assert_eq!(o.agent_exit, Some(0));
            let id = match o.harvest.as_ref().unwrap() {
                HarvestResult::Committed(id) => *id,
                other => panic!("expected Committed, got {other:?}"),
            };
            assert_eq!(
                crate::refs::read_branch_tip(repo.layout(), &label).unwrap(),
                Some(id)
            );
        }
        // HEAD untouched; session temp dir gone (zero residue).
        assert_eq!(repo.head_tip().unwrap(), Some(tip));
        assert!(!session_root.exists());
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn unchanged_and_failed_agents_are_reported_not_destroyed() {
        let (root, scratch) = setup("mixed");
        let repo = Repo::open(&root).unwrap();
        // Agent 1..N all run the same cmd; use one that edits then fails.
        let opts = work_opts(1, &["sh", "-c", "echo partial > wip.txt; exit 3"], &scratch);
        let outcomes = repo.work(opts).unwrap();
        assert_eq!(outcomes[0].agent_exit, Some(3));
        // Partial work still harvested.
        assert!(matches!(
            outcomes[0].harvest.as_ref().unwrap(),
            HarvestResult::Committed(_)
        ));

        // A no-op agent produces Unchanged and no branch.
        let opts2 = WorkOptions {
            base_name: "idle".into(),
            ..work_opts(1, &["true"], &scratch)
        };
        let outcomes2 = repo.work(opts2).unwrap();
        assert!(matches!(
            outcomes2[0].harvest.as_ref().unwrap(),
            HarvestResult::Unchanged
        ));
        assert_eq!(
            crate::refs::read_branch_tip(repo.layout(), "idle-1").unwrap(),
            None
        );
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn spawn_failure_is_reported_not_fatal() {
        let (root, scratch) = setup("spawnfail");
        let repo = Repo::open(&root).unwrap();
        // A command that cannot be exec'd: the spawn fails, the session still
        // completes with agent_exit None and an untouched (Unchanged) checkout.
        let opts = work_opts(1, &["/nonexistent-binary-sc-test"], &scratch);
        let session_root = opts.session_root.clone().unwrap();
        let outcomes = repo.work(opts).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].agent_exit, None);
        assert!(matches!(
            outcomes[0].harvest.as_ref().unwrap(),
            HarvestResult::Unchanged
        ));
        assert_eq!(
            crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(),
            None
        );
        assert!(!session_root.exists(), "session root must be torn down");
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn preflight_refuses_collision_unborn_and_bad_input() {
        let (root, scratch) = setup("preflight");
        let repo = Repo::open(&root).unwrap();
        // Existing branch work-1 → refuse before running anything.
        repo.branch("work-1").unwrap();
        let opts = work_opts(2, &["true"], &scratch);
        let session_root = opts.session_root.clone().unwrap();
        assert!(matches!(repo.work(opts), Err(Error::BadRef(_))));
        assert!(
            !session_root.exists(),
            "refusal must not leave a session dir"
        );
        // Zero agents / empty command.
        assert!(matches!(
            repo.work(work_opts(0, &["true"], &scratch)),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            repo.work(work_opts(1, &[], &scratch)),
            Err(Error::InvalidArgument(_))
        ));
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn session_root_pre_existing_is_refused() {
        let (root, scratch) = setup("squat");
        let repo = Repo::open(&root).unwrap();
        let opts = work_opts(1, &["true"], &scratch);
        let session_root = opts.session_root.clone().unwrap();
        // Pre-create the session root path — the squat scenario: a predictable
        // name that already exists (e.g. planted by another user on a shared
        // host) must be refused, not adopted.
        std::fs::create_dir_all(&session_root).unwrap();
        assert!(matches!(repo.work(opts), Err(Error::InvalidArgument(_))));
        // No branch/child side effects: work-1 was never created, and the
        // pre-existing dir is left exactly as it was (not torn down by the
        // session's Drop guard, since the guard is only installed after the
        // refusal).
        assert_eq!(
            crate::refs::read_branch_tip(repo.layout(), "work-1").unwrap(),
            None
        );
        assert!(session_root.exists());
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn with_secrets_injects_into_agent_env() {
        let (root, scratch) = setup("secrets");
        let repo = Repo::open(&root).unwrap();
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("DEMO_TOKEN", b"tok-123", &[pk]).unwrap();
        let mut opts = work_opts(
            1,
            &["sh", "-c", "printf %s \"$DEMO_TOKEN\" > tok.txt"],
            &scratch,
        );
        opts.base_name = "sec".into();
        opts.with_secrets = true;
        opts.identity = Some(sk);
        let outcomes = repo.work(opts).unwrap();
        let id = match outcomes[0].harvest.as_ref().unwrap() {
            HarvestResult::Committed(id) => *id,
            other => panic!("expected Committed, got {other:?}"),
        };
        // Prove the decrypted value reached the agent: read tok.txt's blob
        // back out of the harvested snapshot.
        let roots = repo.snapshot(&id).unwrap().root;
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = crate::worktree::tree_file_ids(&mut store, roots).unwrap();
        let blob = store.get(ids.get("tok.txt").unwrap()).unwrap();
        match blob {
            scl_core::Object::Blob(b) => assert_eq!(&b[..], b"tok-123"),
            other => panic!("expected blob, got {other:?}"),
        }
        drop(store);
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn budget_evicts_when_reclaimable_and_fails_loudly_when_not() {
        let (root, scratch) = setup("budget");
        {
            // Two 3 MiB files: total 6 MiB exceeds the 4 MiB budget, but each
            // blob fits individually → the session must succeed via eviction.
            let repo = Repo::open(&root).unwrap();
            std::fs::write(root.join("x.bin"), vec![1u8; 3 * 1024 * 1024]).unwrap();
            std::fs::write(root.join("y.bin"), vec![2u8; 3 * 1024 * 1024]).unwrap();
            repo.commit("test", "two big files").unwrap();
        }
        {
            let repo = Repo::open_with_budget(&root, 4 * 1024 * 1024).unwrap();
            let outcomes = repo.work(work_opts(1, &["true"], &scratch)).unwrap();
            assert!(matches!(
                outcomes[0].harvest.as_ref().unwrap(),
                HarvestResult::Unchanged
            ));
            assert!(
                repo.vfs().stats().evictions > 0,
                "over-budget session must evict"
            );
        }
        {
            // Budget smaller than a single blob: nothing reclaimable → the
            // failure is loud (BudgetExceeded from core), never a silent drop.
            let repo = Repo::open_with_budget(&root, 1024 * 1024).unwrap();
            let err = repo.work(work_opts(1, &["true"], &scratch)).unwrap_err();
            assert!(
                err.to_string().contains("budget"),
                "unexpected error: {err}"
            );
        }
        let repo = Repo::open(&root).unwrap();
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn work_session_appends_oplog_record() {
        let (root, scratch) = setup("oplog");
        let repo = Repo::open(&root).unwrap();
        let opts = work_opts(2, &["sh", "-c", "echo edit > out.txt"], &scratch);
        let outcomes = repo.work(opts).unwrap();
        let ids: Vec<ObjectId> = outcomes
            .iter()
            .map(|o| match o.harvest.as_ref().unwrap() {
                HarvestResult::Committed(id) => *id,
                other => panic!("expected Committed, got {other:?}"),
            })
            .collect();
        let rec = crate::oplog::last(repo.layout())
            .unwrap()
            .expect("work session must log a record");
        assert_eq!(rec.desc, "work: 2 agents, base work");
        assert_eq!(rec.head_before, "main");
        assert_eq!(rec.head_after, "main");
        assert_eq!(
            rec.refs,
            vec![
                ("work-1".to_string(), None, Some(ids[0])),
                ("work-2".to_string(), None, Some(ids[1])),
            ]
        );
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn unchanged_work_session_logs_no_oplog_record() {
        let (root, scratch) = setup("oplog-unchanged");
        let repo = Repo::open(&root).unwrap();
        let before = crate::oplog::last(repo.layout()).unwrap();
        let opts = work_opts(1, &["true"], &scratch);
        repo.work(opts).unwrap();
        let after = crate::oplog::last(repo.layout()).unwrap();
        assert_eq!(
            before.map(|r| r.seq),
            after.map(|r| r.seq),
            "no branch created => no oplog record"
        );
        drop(repo);
        teardown(&root);
    }

    #[test]
    fn forking_workspaces_copies_no_blob_bytes() {
        let (root, scratch) = setup("zerocopy");
        let repo = Repo::open(&root).unwrap();
        // Commit a 1 MiB file so resident bytes are measurable.
        std::fs::write(root.join("big.bin"), vec![0x5Au8; 1024 * 1024]).unwrap();
        repo.commit("test", "big").unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let before = repo.vfs().stats().resident_blob_bytes;
        let _forks: Vec<_> = (0..8)
            .map(|i| repo.vfs().fork(tip, format!("z{i}")).unwrap())
            .collect();
        assert_eq!(
            repo.vfs().stats().resident_blob_bytes,
            before,
            "fork must not copy blob bytes"
        );
        drop(repo);
        let _ = &scratch; // scratch unused here
        teardown(&root);
    }

    /// P27 Task 5 review Important fix: `sc work` always materializes each
    /// workspace with `Sparse::default()` (full materialization) by design
    /// — an agent needs the complete tree. On a partial clone "the complete
    /// tree" includes out-of-filter content this clone never fetched, so
    /// that materialize call used to hit the raw corruption-shaped
    /// `NotFound` this guard family exists to eliminate. Must refuse loudly
    /// up front instead.
    #[test]
    fn work_refuses_on_partial_clone_instead_of_raw_notfound() {
        let base =
            std::env::temp_dir().join(format!("sc-work-partial-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src_root = base.join("src");
        let dst_root = base.join("dst");
        let scratch = base.join("scratch");
        std::fs::create_dir_all(src_root.join("src")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("src/a.txt"), b"src-one").unwrap();
        std::fs::write(src_root.join("docs/b.txt"), b"docs-one").unwrap();
        src.commit("t", "c1").unwrap();

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        let opts = work_opts(1, &["true"], &scratch);
        let err = dst.work(opts).unwrap_err();
        assert!(
            matches!(err, Error::PartialCloneUnsupported(_)),
            "expected the explicit partial-clone-unsupported refusal, got {err:?}"
        );
        assert!(err.to_string().contains("not supported on a partial clone"));
        // Refused before anything was spawned or materialized: no session
        // residue.
        assert!(!scratch.join("session").exists());

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
