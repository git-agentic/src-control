//! The persistent repository: ties a persistent `Store` to the `.sc/` layout.

use std::collections::BTreeMap;
use std::path::Path;

use scl_core::{Object, ObjectId, Protection, Snapshot, Store, WrappedKey};
use scl_vfs::Repo as VfsRepo;

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lock::RepoLock;
use crate::refs;
use crate::worktree::{self, Diff};

const DEFAULT_BRANCH: &str = "main";
pub(crate) const DEFAULT_BUDGET: usize = 512 * 1024 * 1024;

/// A working-tree file headed for encryption at commit time:
/// `(path, plaintext bytes, file mode, recipient pubkeys)`.
type ProtectedFile = (String, Vec<u8>, scl_core::FileMode, Vec<[u8; 32]>);

/// Working-tree status against HEAD.
pub type Status = Diff;

/// A handle to an open persistent repo. Holds the single-writer lock for its
/// lifetime.
pub struct Repo {
    pub(crate) layout: Layout,
    pub(crate) vfs: VfsRepo,
    _lock: RepoLock,
}

impl Repo {
    /// Create a new repo at `root` (errors if `.sc/` already exists).
    pub fn init(root: impl AsRef<Path>) -> Result<Repo> {
        let layout = Layout::at(root.as_ref());
        // The exists-check then create_dir_all is a benign TOCTOU: under the
        // single-writer assumption (one `sc` process per repo at a time) no
        // concurrent creator can race between the two; a second `init` either
        // sees `.sc` and errors here or loses the lock in `open_layout`.
        if layout.dot_sc.exists() {
            return Err(Error::RepoExists(layout.dot_sc.display().to_string()));
        }
        std::fs::create_dir_all(layout.objects_dir())?;
        std::fs::create_dir_all(layout.refs_heads_dir())?;
        refs::write_head(&layout, DEFAULT_BRANCH)?;
        Self::open_layout(layout, DEFAULT_BUDGET)
    }

    /// Open an existing repo by discovering `.sc/` at or above `start`.
    pub fn open(start: impl AsRef<Path>) -> Result<Repo> {
        let layout = Layout::discover(start)?;
        Self::open_layout(layout, DEFAULT_BUDGET)
    }

    /// Open an existing repo with an explicit memory budget for the shared
    /// object cache (bytes). `open` uses `DEFAULT_BUDGET`; workspace sessions
    /// (`sc work --budget-mb`) size the cache to the fleet they fork.
    pub fn open_with_budget(start: impl AsRef<Path>, budget_bytes: usize) -> Result<Repo> {
        let layout = Layout::discover(start)?;
        Self::open_layout(layout, budget_bytes)
    }

    fn open_layout(layout: Layout, budget_bytes: usize) -> Result<Repo> {
        let lock = RepoLock::acquire(&layout)?;
        let store = Store::open_persistent(layout.objects_dir(), budget_bytes)?;
        Ok(Repo { layout, vfs: VfsRepo::new(store), _lock: lock })
    }

    /// The resolved on-disk paths for this repo (root, `.sc/`, refs, etc.).
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The tip snapshot of the current branch (None if unborn).
    pub fn head_tip(&self) -> Result<Option<ObjectId>> {
        refs::head_tip(&self.layout)
    }

    /// The root tree of the current tip (None if unborn). `pub(crate)` so
    /// `oplog::undo` (a different module) can capture the pre-restore root.
    pub(crate) fn head_root(&self) -> Result<Option<ObjectId>> {
        match self.head_tip()? {
            Some(tip) => {
                let store_arc = self.vfs.store();
                let root = store_arc.lock().unwrap().get_snapshot(&tip)?.root;
                Ok(Some(root))
            }
            None => Ok(None),
        }
    }

    /// Scan a set of working-tree files for plaintext secrets, skipping any blob
    /// whose content hash is in `.sc/scanner-allowlist.toml`.
    pub fn scan_files(
        &self,
        files: &[(String, Vec<u8>, scl_core::FileMode)],
    ) -> Result<crate::scanner::ScanReport> {
        let allow =
            crate::scanner::Allowlist::load(&self.layout.dot_sc.join("scanner-allowlist.toml"))?;
        let mut findings = Vec::new();
        for (path, bytes, _mode) in files {
            let id = Object::blob(bytes.clone()).id();
            if allow.is_allowed(&id) {
                continue;
            }
            for hit in crate::scanner::scan(path, bytes) {
                findings.push(crate::scanner::Finding {
                    path: path.clone(),
                    rule: crate::scanner::rule_label(&hit.rule),
                    blob_id: id,
                    line: hit.line,
                });
            }
        }
        Ok(crate::scanner::ScanReport { findings })
    }

    /// Scan the current working tree for plaintext secrets (read-only).
    pub fn scan_worktree(&self) -> Result<crate::scanner::ScanReport> {
        let files = worktree::read_worktree(&self.layout, &self.tracked_paths()?)?;
        self.scan_files(&files)
    }

    /// Paths tracked by HEAD (empty when the branch is unborn). `.scignore`
    /// rules never hide these — same model as git.
    pub(crate) fn tracked_paths(&self) -> Result<std::collections::BTreeSet<String>> {
        self.tracked_paths_at(self.head_tip()?)
    }

    /// Paths tracked by `tip` (empty when `tip` is `None`). Generalizes
    /// `tracked_paths` to an explicit tip rather than HEAD — needed by
    /// `assemble_completion_snapshot`, where the completing parent (a pick's
    /// `tip`, or a rebase fold's `acc_tip`) can differ from the branch's own
    /// unmoved HEAD while a pick/rebase is in progress.
    fn tracked_paths_at(
        &self,
        tip: Option<ObjectId>,
    ) -> Result<std::collections::BTreeSet<String>> {
        match tip {
            None => Ok(Default::default()),
            Some(tip) => {
                let root = self.snapshot(&tip)?.root;
                let store_arc = self.vfs.store();
                let mut store = store_arc.lock().unwrap();
                // Partial clone (P27 Task 4): gap-tolerant when this repo
                // never fetched every subtree — an out-of-sparse path is
                // never materialized on disk in the first place, so it
                // being absent from the tracked set here has no effect on
                // `.scignore` filtering either way.
                let ids = if self.promisor()?.is_some() {
                    worktree::tree_file_ids_sparse(&mut store, root, &self.sparse_spec()?)?
                } else {
                    worktree::tree_file_ids(&mut store, root)?
                };
                Ok(ids.into_keys().collect())
            }
        }
    }

    /// The pick/rebase-completion snapshot assembly, extracted from
    /// `commit`'s pick-completion arm (P19 Task 2 groundwork) so
    /// `Repo::rebase_continue` can reuse it verbatim: read the resolved
    /// working tree (tracked paths computed from `parent`, NOT necessarily
    /// HEAD — a rebase fold's `parent` is the accumulated tip, which can
    /// differ from the branch's own unmoved ref while the rebase is
    /// stopped), then run the same `snapshot_files` pipeline as a pick
    /// completion (`merge_head: None`, `pick_head: Some(completed)`) —
    /// scanner gate on plain files, protected re-encryption under the
    /// unioned rules, decided-root carry-forward. Builds the snapshot only;
    /// callers move the branch ref and record the oplog entry themselves.
    /// `pick_registry_base` (P19 final-review fix I2) is the picked commit's
    /// `--mainline`-resolved parent, persisted by `pick_state` at the
    /// conflict stop: threading it into `snapshot_files`'s registry
    /// three-way keeps a completed mainline pick's secret delta consistent
    /// with the file delta it already landed, instead of silently
    /// re-basing the registry against the picked commit's first parent.
    /// `None` for every non-mainline pick and for rebase's own fold
    /// completion (rebase has no `--mainline` concept).
    pub(crate) fn assemble_completion_snapshot(
        &self,
        parent: ObjectId,
        completed: ObjectId,
        decided_root: Option<ObjectId>,
        pick_registry_base: Option<ObjectId>,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let files = worktree::read_worktree(&self.layout, &self.tracked_paths_at(Some(parent))?)?;
        self.snapshot_files(
            files,
            Some(parent),
            None,
            Some(completed),
            decided_root,
            pick_registry_base,
            None,
            &self.sparse_spec()?,
            author,
            message,
        )
    }

    /// The commit pipeline minus ref movement: split protected/plaintext files,
    /// scan the plaintext (Err(SecretDetected) on a hit), convergently encrypt
    /// protected files, carry forward absent still-protected content from
    /// `tip` (and from `merge_head` when completing a merge), and persist the
    /// resulting snapshot with `tip` (+ `merge_head`) as parents. During merge
    /// completion the protection policy is the UNION of both parents' rules
    /// and wraps. Used by `commit` (HEAD tip) and by workspace harvest (P13,
    /// arbitrary base tip, no merge head). Advances no refs.
    /// `decided_root` is the merge's (or pick's) decided carried tree
    /// (persisted in the merge/pick state by the conflict path): when present,
    /// absent-still-protected files carry forward from IT — the merge already
    /// arbitrated base/ours/theirs, and re-arbitrating by parent order here
    /// silently reverted theirs-side updates. Only meaningful alongside
    /// `merge_head` or `pick_head`.
    /// `pick_head` is the commit being cherry-picked when completing a
    /// conflicted pick (P15 Task 7): the pick has no second parent, but its
    /// rules and wraps must still union into the completion's policy — the
    /// picked commit may carry protected updates (in the decided tree) whose
    /// wraps only IT knows, and rules the tip lacks.
    /// `pick_registry_base` (P19 final-review fix I2), meaningful only
    /// alongside `pick_head`, is the picked commit's `--mainline`-resolved
    /// parent (persisted by `pick_state` at the conflict stop): threaded
    /// into the registry three-way below so a completed mainline pick's
    /// secret delta agrees with the file delta it already landed. `None`
    /// for a non-mainline pick (falls back to the picked commit's own first
    /// parent, unchanged behavior) and for every other caller.
    /// `parents_override`, when `Some`, replaces the parents that would
    /// otherwise be derived from `tip`/`merge_head` on the built snapshot —
    /// `tip` still supplies the protection/secrets/carry-forward source (the
    /// pre-amend commit's own policy), but the recorded parents are the
    /// caller's choice. Used by `amend` (P19 Task 3) to rebuild the tip with
    /// the TIP's OWN parents instead of `[tip]`, replacing rather than
    /// extending history. Every other caller passes `None`, keeping the
    /// original `tip` (+ `merge_head`) derivation.
    /// `sparse` (P24 final-review fix, Critical 1 / Important 1) is the
    /// carry predicate's sparse view, now an explicit input instead of an
    /// ambient `self.sparse_spec()?` read: the host-repo callers (`commit`,
    /// `amend`, `assemble_completion_snapshot`) pass the live host spec —
    /// correct there, since the working tree they read reflects it — but
    /// `sc ws harvest` must pass the WORKSPACE'S OWN fork-time spec (the
    /// checkout was materialized under it, possibly a spec ago) and `sc
    /// work` must pass `Sparse::default()` (its checkouts are always full,
    /// so a genuine out-of-sparse deletion must land, not be carried as if
    /// merely unmaterialized). Reading the host's live spec ambiently here
    /// previously conflated "the view this working tree was actually given"
    /// with "the view the host repo happens to have right now" — the two
    /// diverge exactly when a `sc ws` session outlives a `sparse set/disable`
    /// on the host, or when the caller is `sc work` at all.
    pub(crate) fn snapshot_files(
        &self,
        files: Vec<(String, Vec<u8>, scl_core::FileMode)>,
        tip: Option<ObjectId>,
        merge_head: Option<ObjectId>,
        pick_head: Option<ObjectId>,
        decided_root: Option<ObjectId>,
        pick_registry_base: Option<ObjectId>,
        parents_override: Option<Vec<ObjectId>>,
        sparse: &crate::sparse::Sparse,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        // Read the tip snapshot exactly once; extract both protection and secrets.
        let (mut protection, secrets) = match (tip, merge_head) {
            (None, _) => (Protection::default(), BTreeMap::new()),
            (Some(t), None) => {
                let snap = self.snapshot(&t)?;
                match pick_head {
                    None => (snap.protection, snap.secrets),
                    Some(ph) => {
                        // Pick completion: union tip ∪ picked rules + wraps
                        // (same discipline as the merge-completion arm below,
                        // tip's wrap bytes win on a shared recipient). The
                        // secret registry is merged three-way exactly like the
                        // clean pick path (P15 Task 9): base = the picked
                        // commit's own first parent, ours = tip, theirs =
                        // picked — a picked commit carrying a registry delta
                        // alongside its conflicted files keeps that delta
                        // through the completion, and a name changed
                        // differently on both sides is a typed
                        // `SecretMergeConflict` (the commit fails loudly).
                        let picked_snap = self.snapshot(&ph)?;
                        // `pick_registry_base` (P19 final-review fix I2):
                        // `pick_state` now persists the `--mainline`
                        // selection a conflicted pick was started with, so
                        // completion can recover which parent's registry to
                        // base against instead of always falling back to
                        // the picked commit's own first parent — a
                        // non-mainline pick still passes `None` here and
                        // gets exactly that fallback (unchanged behavior).
                        let secs = crate::replay::merged_registry_for_replay(
                            self,
                            &picked_snap.parents,
                            &picked_snap.secrets,
                            &snap.secrets,
                            pick_registry_base,
                        )?;
                        let picked_p = picked_snap.protection;
                        let prefixes = crate::protect::merge_prefixes(
                            &snap.protection.prefixes,
                            &picked_p.prefixes,
                        );
                        let mut wrapped = snap.protection.wrapped;
                        for (id, wks) in &picked_p.wrapped {
                            let entry = wrapped.entry(*id).or_default();
                            *entry = crate::protect::union_wraps(entry, wks);
                        }
                        (Protection { prefixes, wrapped }, secs)
                    }
                }
            }
            (Some(t), Some(mh)) => {
                // Merge completion (Task 6, P15): protection is the UNION of
                // BOTH parents' policies — prefixes so re-encryption honors
                // theirs-side rules (a file under a rule that only theirs
                // knows must not land as plaintext), and wraps so carried
                // theirs-side ciphertext keeps its DEKs. Same union
                // discipline as the clean-merge path in `merge_with_identity`
                // (ours' wrap bytes win on a shared recipient).
                let ours_p = self.snapshot(&t)?.protection;
                let theirs_p = self.snapshot(&mh)?.protection;
                let prefixes =
                    crate::protect::merge_prefixes(&ours_p.prefixes, &theirs_p.prefixes);
                let mut wrapped = ours_p.wrapped;
                for (id, wks) in &theirs_p.wrapped {
                    let entry = wrapped.entry(*id).or_default();
                    *entry = crate::protect::union_wraps(entry, wks);
                }
                let secs = self.merged_secrets_for_commit(tip, merge_head)?;
                (Protection { prefixes, wrapped }, secs)
            }
        };

        // Single pass: split protected files (capturing each rule's recipients, so
        // the encryption loop needn't look the prefix up again) from plaintext.
        let mut plain: Vec<(String, Vec<u8>, scl_core::FileMode)> = Vec::new();
        let mut protected: Vec<ProtectedFile> = Vec::new();
        for (path, bytes, mode) in files {
            match crate::protect::matching_prefix(&protection, &path) {
                Some(rule) => protected.push((path, bytes, mode, rule.granted_keys())),
                None => plain.push((path, bytes, mode)),
            }
        }

        // Scan only plaintext files (protected files are encrypted on purpose).
        let report = self.scan_files(&plain)?;
        if !report.is_empty() {
            return Err(Error::SecretDetected(report));
        }

        // Encrypt protected files; accumulate fresh wrapped DEKs keyed by blob id.
        let mut all: Vec<(String, Vec<u8>, scl_core::FileMode, u8)> =
            plain.into_iter().map(|(p, b, m)| (p, b, m, 0u8)).collect();
        let (protected_all, mut fresh_wrapped) = crate::protect::encrypt_protected(protected)?;
        all.extend(protected_all);

        // Safe-by-default: carry forward still-protected files that are absent
        // from the working tree. `commit` cannot distinguish "absent because the
        // committer isn't a recipient (skipped at checkout)" from "the committer
        // deleted it" — an absent protected path reads as clean either way (see
        // Task 5 `status`). We therefore never silently drop protected content
        // on a non-merge commit: a still-protected path that is missing from
        // disk is carried forward verbatim from the tip (its exact ciphertext
        // blob and wrapped DEKs). This closes the hole where a non-recipient's
        // unrelated commit would otherwise destroy ciphertext they cannot even
        // read. (Explicit deletion of a protected file is a future operation,
        // out of scope.) Sources, in priority order:
        //
        // 1. The merge's (or pick's) DECIDED tree (`decided_root`, persisted
        //    by the conflict path) when completing a merge or cherry-pick.
        //    The merge already arbitrated base/ours/theirs — e.g. "only
        //    theirs changed → take theirs" — so an absent protected path must
        //    carry the DECIDED blob. (Re-arbitrating by parent order here,
        //    ours first, silently reverted theirs' update to the stale ours
        //    version and recorded theirs as merged — permanently,
        //    undetectably lost. A conflicted pick carrying a picked-side
        //    protected update has the exact same failure: the tip-only scan
        //    committed the stale ours blob.) A path PRESENT in the decided
        //    tree is decided, period: parents are never consulted for it.
        // 2. The parents — `tip` only on a non-merge commit (unchanged
        //    behavior), both parents on merge completion for paths the
        //    decided tree doesn't know (and as full fallback when the merge
        //    state predates the decided-root record, i.e. was written by an
        //    older code path). Ours wins across parents. A pick's non-parent
        //    `pick_head` is NOT a source: any picked-side content the pick
        //    kept is in the decided tree — a protected path in the picked
        //    commit but absent from the decided tree was decided *deleted*
        //    and must not resurrect.
        //
        // P24 Task 2 widening: the same "commit cannot tell absent-because-
        // skipped from absent-because-deleted" ambiguity applies to sparse
        // checkouts once Task 3 stops materializing out-of-sparse paths — an
        // absent path outside the sparse set reads as clean exactly like an
        // absent protected path does today. So an absent HEAD-tracked path is
        // now carried iff it is still-protected-and-not-a-recipient (as
        // before) OR it falls outside the current sparse spec
        // (`!sparse.matches(path)`); when neither holds, absence is a genuine
        // deletion. `sparse` is the caller-supplied spec (see the doc comment
        // on `snapshot_files` for why it must not be read ambiently here), so
        // every path in the loop below is checked against the same spec.
        // This landing is dormant when `sparse` is full: with no narrowing in
        // effect every path matches and the OR term is always false —
        // behavior is unchanged from P15 for a full checkout.
        // Partial clone (P27 Task 4): a promisor-filtered clone never
        // fetched out-of-filter subtrees at all, so the unfiltered
        // enumeration below would `NotFound` on them (it calls
        // `store.get_tree`/`store.get` on every entry regardless of
        // `sparse`). Route through the gap-tolerant sparse-scoped
        // flattener instead — but ONLY on a partial clone: a full clone
        // with an active sparse spec still has every object, and its
        // per-blob byte-carry below (the existing P24 mechanism) must stay
        // exactly as it was to avoid any behavior change for that case.
        let promisor = self.promisor()?;
        let partial = promisor.is_some();
        // Merge/pick completion guard (P27 Task 5, T5-I4): `graft_out_of_sparse`
        // below only splices out-of-filter subtrees back in for a plain
        // single-tip commit (`decided_root.is_none() && merge_head.is_none()`).
        // A merge (`merge_head: Some`) or a CONFLICTED pick/rebase completion
        // (`decided_root: Some`) builds `all`/`root` purely from in-filter
        // content on a partial clone — with no graft to follow, that would
        // silently DROP every out-of-filter subtree from the new snapshot.
        // Refuse loudly instead of ever letting that happen; a clean
        // (non-conflicted) pick/rebase fold still has `decided_root: None`
        // and keeps using the single-tip graft path, unaffected.
        if partial && (decided_root.is_some() || merge_head.is_some()) {
            return Err(crate::promisor::partial_clone_unsupported(
                "merge/pick completion",
            ));
        }
        {
            let mut on_disk: std::collections::BTreeSet<String> =
                all.iter().map(|(p, _, _, _)| p.clone()).collect();
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();

            // Decided tree first (merge completion only), then the parents
            // restricted to paths outside the decided tree.
            let mut sources: Vec<std::collections::BTreeMap<String, (ObjectId, scl_core::FileMode, u8)>> =
                Vec::new();
            let mut decided_paths: std::collections::BTreeSet<String> = Default::default();
            if let Some(dr) = decided_root {
                let decided = if partial {
                    worktree::tree_file_entries_with_perms_sparse(&mut store, dr, sparse)?
                } else {
                    worktree::tree_file_entries_with_perms(&mut store, dr)?
                };
                decided_paths = decided.keys().cloned().collect();
                sources.push(decided);
            }
            for parent in tip.into_iter().chain(merge_head.into_iter()) {
                let parent_root = store.get_snapshot(&parent)?.root;
                let mut entries = if partial {
                    worktree::tree_file_entries_with_perms_sparse(&mut store, parent_root, sparse)?
                } else {
                    worktree::tree_file_entries_with_perms(&mut store, parent_root)?
                };
                entries.retain(|p, _| !decided_paths.contains(p));
                sources.push(entries);
            }

            for entries in sources {
                for (path, (blob_id, mode, perms)) in entries {
                    if on_disk.contains(&path) {
                        continue;
                    }
                    let still_protected = perms & scl_core::PROTECTED != 0
                        && crate::protect::matching_prefix(&protection, &path).is_some();
                    let out_of_sparse = !sparse.matches(&path);
                    if !still_protected && !out_of_sparse {
                        continue;
                    }
                    let bytes = match store.get(&blob_id)? {
                        Object::Blob(b) => b.to_vec(),
                        _ => continue,
                    };
                    // Carry the SOURCE's own perms bit unchanged (was
                    // hardcoded to `scl_core::PROTECTED` before this
                    // widening, which was safe when only protected paths
                    // could reach this arm; a carried plain out-of-sparse
                    // path must land plain, not acquire PROTECTED).
                    all.push((path.clone(), bytes, mode, perms));
                    on_disk.insert(path);
                    // Preserve this blob's wraps. Carried-forward blobs are absent
                    // from `fresh_wrapped` (they never hit the on-disk encrypt loop),
                    // so the prior-wrap reuse below won't cover them — add them here.
                    // `or_insert_with` so an on-disk file already sharing this blob id
                    // keeps its freshly-wrapped DEKs. `protection.wrapped` is the
                    // both-parents union during merge completion, so decided/theirs
                    // blobs find their wraps here too.
                    if let Some(prior_wks) = protection.wrapped.get(&blob_id) {
                        fresh_wrapped.entry(blob_id).or_insert_with(|| prior_wks.clone());
                    }
                }
            }
        }

        let mut root = self.vfs.write_tree_with_perms(&all)?;

        // Partial-clone graft (P27 Task 4): the enumeration above already
        // steered clear of out-of-filter content, but `write_tree_with_perms`
        // still only knows about `all` — on a partial clone that means the
        // freshly-built root is MISSING every out-of-sparse subtree entirely
        // (there was never a byte-carried entry for it to include). Splice
        // those subtrees back in by id from the tip's own root tree, never
        // reading their content (`graft_out_of_sparse`; see its doc comment
        // for the id-only walk). Scoped to a plain single-tip commit —
        // `decided_root`/`merge_head` both absent — matching the carry
        // block's own documented merge/pick boundary above.
        if partial && decided_root.is_none() && merge_head.is_none() {
            if let Some(t) = tip {
                let store_arc = self.vfs.store();
                let mut store = store_arc.lock().unwrap();
                let parent_root = store.get_snapshot(&t)?.root;
                let p = promisor
                    .as_ref()
                    .expect("partial implies promisor().is_some()");
                root = worktree::graft_out_of_sparse(&mut store, root, parent_root, sparse, p, "")?;
                // C1 fix (P27 Task 4 review): the graft above spliced
                // out-of-filter subtrees back in BY ID, so any PROTECTED
                // blob living only under a grafted subtree never went
                // through the encrypt-or-carry loops above and is absent
                // from `fresh_wrapped`. Left alone, the `reuse_prior_wraps`
                // rebuild below (which only REFRESHES ids already present
                // in `fresh_wrapped`, never adds new ones) would silently
                // drop those blobs' wrapped DEKs from the new snapshot —
                // permanently, since this becomes the new tip's
                // `protection.wrapped` and every later push/merge/clone
                // builds on top of it, leaving no identity able to decrypt
                // the grafted ciphertext ever again. `protection.wrapped`
                // here is still the tip's own full map (`prior` is taken
                // below, after this point) and already carries every wrap
                // the tip itself could offer; union in any entry
                // `fresh_wrapped` doesn't already know about. Convergent
                // encryption keeps a blob's id stable regardless of who
                // grafted it, so reusing the prior wrap bytes verbatim is
                // correct, not just convenient — no re-encryption, no key
                // material touched.
                for (id, wks) in &protection.wrapped {
                    fresh_wrapped.entry(*id).or_insert_with(|| wks.clone());
                }
            }
        }

        // Rebuild policy.wrapped from only this commit's protected blobs, dropping
        // any stale entries. Crucially, reuse the prior wrap bytes for an unchanged
        // (blob_id, recipient_id): convergent encryption keeps blob ids stable, but
        // `wrap_dek_for` randomizes its ephemeral key — re-wrapping every commit
        // would change the `protection` encoding (and thus the snapshot id) for
        // identical content, breaking "same content -> stable history". Carrying the
        // prior wrap forward keeps it stable; only a newly-added recipient (or a new
        // blob) gets a fresh wrap, and a revoked recipient is already absent here.
        let prior = std::mem::take(&mut protection.wrapped);
        crate::protect::reuse_prior_wraps(&mut fresh_wrapped, &prior);
        protection.wrapped = fresh_wrapped;

        let parents: Vec<ObjectId> = match parents_override {
            Some(p) => p,
            None => {
                let mut v: Vec<ObjectId> = tip.into_iter().collect();
                if let Some(theirs) = merge_head {
                    v.push(theirs);
                }
                v
            }
        };
        self.build_snapshot(root, parents, secrets, protection, author, message)
    }

    /// Snapshot the working tree into a new commit on the current branch. When a
    /// merge is in progress, records both parents and clears the merge state.
    /// Files under a protected prefix are convergently encrypted (scanner-exempt);
    /// only plaintext files are scanned.
    pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let head = refs::current_branch(&self.layout)?;
        let before = refs::read_branch_tip(&self.layout, &head)?;
        let tip = self.head_tip()?;
        let merge_head = crate::merge_state::read_merge_head(&self.layout)?;
        let pick_head = crate::pick_state::read_pick_head(&self.layout)?;
        // The merge's (or pick's) decided carried tree, when the conflict
        // path recorded one (absent for state written before the record
        // existed). Merge and pick are mutually exclusive (each refuses to
        // start while the other is in progress), so at most one HEAD is set.
        // Each decided root is read ONLY under its own in-progress HEAD: the
        // conflict paths write the decided root BEFORE the HEAD (crash
        // discipline — the HEAD is the in-progress signal), so a crash in
        // that window leaves a decided-root file with NO matching HEAD. Such
        // residue must be inert — an ungated read here let a stale
        // MERGE_DECIDED_ROOT hijack a later pick's completion, carrying
        // stale blobs over the pick's decided ones.
        let decided_root = if merge_head.is_some() {
            crate::merge_state::read_decided_root(&self.layout)?
        } else if pick_head.is_some() {
            crate::pick_state::read_decided_root(&self.layout)?
        } else {
            None
        };
        // The pick's `--mainline`-resolved parent, if it was started with
        // one (P19 final-review fix I2) — same gating as `decided_root`:
        // only meaningful, and only read, while a pick is actually in
        // progress.
        let pick_registry_base =
            if pick_head.is_some() { crate::pick_state::read_mainline_base(&self.layout)? } else { None };
        let merging = merge_head.is_some();
        let picking = pick_head.is_some();
        // Pick completion (no merge in progress) is the extracted assembly
        // (P19 Task 2 groundwork), shared with `rebase_continue`. Every
        // other case (plain commit, merge completion) still calls
        // `snapshot_files` directly with a freshly read working tree.
        let id = match (tip, merge_head, pick_head) {
            (Some(t), None, Some(ph)) => self.assemble_completion_snapshot(
                t,
                ph,
                decided_root,
                pick_registry_base,
                author,
                message,
            )?,
            _ => {
                let files = worktree::read_worktree(&self.layout, &self.tracked_paths()?)?;
                self.snapshot_files(
                    files,
                    tip,
                    merge_head,
                    pick_head,
                    decided_root,
                    pick_registry_base,
                    None,
                    &self.sparse_spec()?,
                    author,
                    message,
                )?
            }
        };
        refs::write_branch_tip(&self.layout, &head, &id)?;
        crate::merge_state::clear(&self.layout)?;
        crate::pick_state::clear(&self.layout)?;
        let label = if merging {
            "commit (merge)"
        } else if picking {
            "commit (pick)"
        } else {
            "commit"
        };
        let first_line = message.lines().next().unwrap_or("");
        crate::oplog::record(
            &self.layout,
            &format!("{label}: {first_line}"),
            &head,
            &head,
            &[(head.clone(), before, Some(id))],
        )?;
        Ok(id)
    }

    /// Replace the tip commit with one built from the current working tree:
    /// same parents as the tip (merge and root commits amend naturally —
    /// `tip_snap.parents` is `[]`, `[p]`, or `[p1, p2]` and is carried
    /// through unchanged), message kept unless `message` overrides. Reuses
    /// the plain-commit assembly (`snapshot_files`) so the scanner gate,
    /// `.scignore`, and protected re-encryption are the exact pipeline
    /// `commit` uses — one gated path, two callers. `tip` (the pre-amend
    /// commit) still supplies the protection/secrets/carry-forward source
    /// (the working tree's protection state doesn't change just because the
    /// tip is being replaced); only the recorded parents are overridden, via
    /// `parents_override`, to the tip's own parents rather than `[tip]` —
    /// that's what makes this a replacement instead of a second commit.
    /// Amend does not materialize: the tree came FROM the working tree, so
    /// there's nothing to write back. Oplog-recorded as "amend"; one `undo`
    /// restores the old tip. No pushed-commit guard — sc has no
    /// authoritative record of remote observers (ADR-0029).
    pub fn amend(&self, author: &str, message: Option<&str>) -> Result<ObjectId> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let tip_snap = self.snapshot(&tip)?;
        let msg = message.map(|m| m.to_string()).unwrap_or_else(|| tip_snap.message.clone());

        let head = refs::current_branch(&self.layout)?;
        let before = refs::read_branch_tip(&self.layout, &head)?;

        let files = worktree::read_worktree(&self.layout, &self.tracked_paths()?)?;
        let id = self.snapshot_files(
            files,
            Some(tip),
            None,
            None,
            None,
            None,
            Some(tip_snap.parents.clone()),
            &self.sparse_spec()?,
            author,
            &msg,
        )?;

        refs::write_branch_tip(&self.layout, &head, &id)?;
        crate::oplog::record(&self.layout, "amend", &head, &head, &[(head.clone(), before, Some(id))])?;
        Ok(id)
    }

    /// Decode the snapshot at `id` from the store. Small utility reused across
    /// commit, grant/revoke (Task 6), and tests.
    pub(crate) fn snapshot(&self, id: &ObjectId) -> Result<Snapshot> {
        let store_arc = self.vfs.store();
        let snap = store_arc.lock().unwrap().get_snapshot(id)?;
        Ok(snap)
    }

    /// Secrets to record on a commit: during a merge, the conflict-free merged
    /// registry of the two parents; otherwise the tip's registry.
    fn merged_secrets_for_commit(
        &self,
        tip: Option<ObjectId>,
        merge_head: Option<ObjectId>,
    ) -> Result<BTreeMap<String, ObjectId>> {
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        match (tip, merge_head) {
            (Some(ours), Some(theirs)) => {
                let base = crate::merge::merge_base(&mut store, ours, theirs)?
                    .ok_or(Error::NoCommonAncestor)?;
                let bs = store.get_snapshot(&base)?.secrets;
                let os = store.get_snapshot(&ours)?.secrets;
                let ts = store.get_snapshot(&theirs)?.secrets;
                crate::merge::merge_secrets(&bs, &os, &ts)
            }
            (Some(ours), None) => Ok(store.get_snapshot(&ours)?.secrets),
            (None, _) => Ok(BTreeMap::new()),
        }
    }

    /// Persist a snapshot object (no ref movement). The workspace harvest
    /// (P13) commits to non-HEAD branches, so snapshot construction must not
    /// be welded to "advance the current branch".
    pub(crate) fn build_snapshot(
        &self,
        root: ObjectId,
        parents: Vec<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        protection: Protection,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let snap = Object::Snapshot(Snapshot {
            root,
            parents,
            author: author.to_string(),
            timestamp: unix_now(),
            message: message.to_string(),
            secrets,
            protection,
        });
        let store_arc = self.vfs.store();
        let id = store_arc.lock().unwrap().put(snap)?;
        Ok(id)
    }

    /// Build + persist a snapshot and advance the current branch ref.
    pub(crate) fn commit_snapshot(
        &self,
        root: ObjectId,
        parents: Vec<ObjectId>,
        secrets: BTreeMap<String, ObjectId>,
        protection: Protection,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let id = self.build_snapshot(root, parents, secrets, protection, author, message)?;
        let branch = refs::current_branch(&self.layout)?;
        refs::write_branch_tip(&self.layout, &branch, &id)?;
        Ok(id)
    }

    /// Working-tree status against HEAD, plus merge-in-progress info.
    pub fn status(&self) -> Result<Status> {
        let (head_root, protection) = match self.head_tip()? {
            Some(tip) => {
                let snap = self.snapshot(&tip)?;
                (Some(snap.root), snap.protection)
            }
            None => (None, Protection::default()),
        };
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        worktree::diff_worktree(&self.layout, &mut store, head_root, &protection, &self.sparse_spec()?)
    }

    /// Line-level unified diff of the working tree against HEAD (`sc diff`).
    ///
    /// Text files get standard `---`/`+++`/`@@` hunks; a file with a NUL byte
    /// on either side is reported as binary. `PROTECTED` HEAD entries follow
    /// the same rules as [`Repo::status`]: absent-on-disk is clean (skipped
    /// checkout, not a deletion), an on-disk edit is detected by convergent
    /// re-encryption — but the content is never shown (it would be ciphertext
    /// vs plaintext noise at best, a leak at worst). A HEAD path outside the
    /// sparse spec is absent on disk by design (see `materialize`), so it
    /// gets the same "absent is clean, not a deletion" treatment — otherwise
    /// `sc diff` right after `sc sparse set` would render the whole
    /// out-of-sparse subtree as deleted.
    pub fn diff_unified(&self) -> Result<String> {
        use scl_core::PROTECTED;
        let sparse = self.sparse_spec()?;
        let head_root = self.head_tip()?.map(|t| self.snapshot(&t)).transpose()?.map(|s| s.root);
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let head = match head_root {
            // Sparse-aware flattener (P27 Task 5, T5-I3): mirrors
            // `diff_worktree`'s fix — never touches a gapped out-of-filter
            // object on a partial clone; identical to the old unfiltered
            // walk whenever `sparse` is full.
            Some(root) => worktree::tree_file_entries_with_perms_sparse(&mut store, root, &sparse)?,
            None => BTreeMap::new(),
        };
        let tracked: std::collections::BTreeSet<String> = head.keys().cloned().collect();
        let wt: BTreeMap<String, Vec<u8>> = worktree::read_worktree(&self.layout, &tracked)?
            .into_iter()
            .map(|(p, b, _)| (p, b))
            .collect();

        let mut paths: std::collections::BTreeSet<&String> = wt.keys().collect();
        paths.extend(head.keys());

        let mut out = String::new();
        for path in paths {
            let disk = wt.get(path);
            match head.get(path) {
                None => {
                    // Added file.
                    let bytes = disk.expect("path came from one of the two maps");
                    push_file_diff(&mut out, path, &[], bytes);
                }
                Some((blob_id, _mode, perms)) if *perms & PROTECTED != 0 => {
                    // Never show protected content; report the change status only.
                    if let Some(bytes) = disk {
                        let disk_id = Object::blob(scl_crypto::encrypt_path(bytes).0).id();
                        if disk_id != *blob_id {
                            out.push_str(&format!(
                                "protected file changed: {path} (content not shown)\n"
                            ));
                        }
                    }
                }
                Some((blob_id, _mode, _perms)) => {
                    if disk.is_none() && !sparse.matches(path) {
                        // Out-of-sparse: expected-absent, not a deletion.
                        continue;
                    }
                    let old = match store.get(blob_id)? {
                        Object::Blob(b) => b,
                        _ => continue,
                    };
                    match disk {
                        None => push_file_diff(&mut out, path, &old, &[]),
                        Some(bytes) => {
                            if Object::blob(bytes.clone()).id() != *blob_id {
                                push_file_diff(&mut out, path, &old, bytes);
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Conflicted paths if a merge is in progress (empty otherwise).
    pub fn merge_conflicts(&self) -> Result<Vec<String>> {
        crate::merge_state::read_conflicts(&self.layout)
    }

    /// Whether a merge is currently in progress.
    pub fn merge_in_progress(&self) -> bool {
        crate::merge_state::in_progress(&self.layout)
    }

    /// Whether a cherry-pick is currently in progress.
    pub fn pick_in_progress(&self) -> bool {
        crate::pick_state::in_progress(&self.layout)
    }

    /// The commit being cherry-picked, if a cherry-pick is in progress.
    pub fn pick_head(&self) -> Result<Option<ObjectId>> {
        crate::pick_state::read_pick_head(&self.layout)
    }

    /// Conflicted paths if a cherry-pick is in progress (empty otherwise).
    pub fn pick_conflicts(&self) -> Result<Vec<String>> {
        crate::pick_state::read_conflicts(&self.layout)
    }

    /// Whether a rebase is currently stopped mid-flight.
    pub fn rebase_in_progress(&self) -> bool {
        crate::rebase_state::in_progress(&self.layout)
    }

    /// The stopped rebase's progress, if any: (conflicted commit, done
    /// count, total count). `done` counts the commits landed before the
    /// stopped one — `total - remaining.len() - 1` — so callers display
    /// "stopped at commit X (done + 1 of total)". Saturating: a
    /// semantically-inconsistent state file (`remaining.len() + 1 > total`,
    /// which a hand-corrupted or foreign-written `REBASE_STATE` could
    /// produce) reports `done = 0` instead of panicking `sc status` on
    /// underflow — `write` never produces such a file itself.
    pub fn rebase_progress(&self) -> Result<Option<(ObjectId, usize, usize)>> {
        Ok(crate::rebase_state::read(&self.layout)?.map(|st| {
            let done = st.total.saturating_sub(st.remaining.len()).saturating_sub(1);
            (st.conflicted, done, st.total)
        }))
    }

    /// Whether the stopped rebase's conflicted commit has already been
    /// resolved and completed by a prior `sc rebase --continue`, but the
    /// fold over the REMAINING commits then errored (e.g. a later commit
    /// needs `--identity`) — `RebaseState::resolved` (P21). `false` when no
    /// rebase is in progress or the conflicted commit is still unresolved.
    /// Distinct from [`rebase_progress`][Repo::rebase_progress]'s "stopped at
    /// commit X" window: in THIS window there is nothing left to resolve on
    /// disk — the working tree already reflects the resolution — the user
    /// just needs to re-run `--continue` (optionally with the identity the
    /// later commit needs), not touch conflict markers.
    pub fn rebase_resolved(&self) -> Result<bool> {
        Ok(crate::rebase_state::read(&self.layout)?.is_some_and(|st| st.resolved))
    }

    /// Merge `branch` into the current branch. Fast-forwards when possible;
    /// auto-commits a two-parent snapshot on a clean merge; on conflicts writes
    /// markers + merge state and returns `MergeConflicts`. If the current
    /// branch is unborn (no commits yet), adopts `theirs` wholesale — the same
    /// fast-forward-from-empty behavior Git uses when merging into an unborn
    /// branch — so `sc init` followed directly by `sc fetch` + `sc merge`
    /// (e.g. from a freshly imported git remote) works without an intervening
    /// local commit.
    pub fn merge(&self, branch: &str, author: &str) -> Result<ObjectId> {
        self.merge_with_identity(branch, author, None).map(|(id, _)| id)
    }

    /// Like [`merge`][Repo::merge] but threads `identity` through the
    /// real-three-way path so protected paths that diverged in *content* on
    /// both sides can be decrypted, diff3'd, and re-encrypted (P15). Clean
    /// ciphertext-id fast paths (ADR: [`crate::merge::three_way_files`]) still
    /// need no identity at all. A conflicted merge carrying protection writes
    /// plaintext markers to the working tree only (never through the CAS) and
    /// is completed by `sc commit`, which re-encrypts under the union of both
    /// parents' rules (Task 6).
    ///
    /// Returns the merged tip plus the protected paths that could not be
    /// materialized to disk for lack of a matching key (skipped, exactly like
    /// [`switch_with_identity`][Repo::switch_with_identity]); [`merge`]
    /// drops the list.
    pub fn merge_with_identity(
        &self,
        branch: &str,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<(ObjectId, Vec<String>)> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before merging".into(),
            ));
        }
        let head = refs::current_branch(&self.layout)?;
        let before = refs::read_branch_tip(&self.layout, &head)?;
        let theirs = refs::resolve_tip(&self.layout, branch)?
            .ok_or_else(|| Error::NoSuchBranch(branch.to_string()))?;
        let ours = match self.head_tip()? {
            Some(ours) => ours,
            None => {
                // Unborn local branch: adopt theirs wholesale (fast-forward from empty).
                let store_arc = self.vfs.store();
                let mut store = store_arc.lock().unwrap();
                let theirs_snap = store.get_snapshot(&theirs)?;
                let theirs_root = theirs_snap.root;
                let theirs_protection = theirs_snap.protection;
                let skipped = worktree::materialize(
                    &self.layout,
                    &mut store,
                    theirs_root,
                    None,
                    &theirs_protection,
                    identity,
                    &self.sparse_spec()?,
                )?;
                drop(store);
                refs::write_branch_tip(&self.layout, &head, &theirs)?;
                crate::oplog::record(
                    &self.layout,
                    &format!("merge {branch} (adopt)"),
                    &head,
                    &head,
                    &[(head.clone(), before, Some(theirs))],
                )?;
                return Ok((theirs, skipped));
            }
        };

        // Ancestor short-circuits.
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            if crate::merge::is_ancestor(&mut store, theirs, ours)? {
                return Err(Error::UpToDate);
            }
            if crate::merge::is_ancestor(&mut store, ours, theirs)? {
                // fast-forward: advance ref + materialize, no merge commit
                let theirs_snap = store.get_snapshot(&theirs)?;
                let theirs_root = theirs_snap.root;
                let theirs_protection = theirs_snap.protection;
                let ours_root = store.get_snapshot(&ours)?.root;
                let skipped = worktree::materialize(
                    &self.layout,
                    &mut store,
                    theirs_root,
                    Some(ours_root),
                    &theirs_protection,
                    identity,
                    &self.sparse_spec()?,
                )?;
                drop(store);
                refs::write_branch_tip(&self.layout, &head, &theirs)?;
                crate::oplog::record(
                    &self.layout,
                    &format!("merge {branch} (ff)"),
                    &head,
                    &head,
                    &[(head.clone(), before, Some(theirs))],
                )?;
                return Ok((theirs, skipped));
            }
        }

        // Merge/pick completion guard (P27 Task 5, T5-I4): a real three-way
        // merge flattens BOTH sides' full trees (`crate::merge::three_way`);
        // on a partial clone that would touch out-of-filter content this
        // clone never fetched. `three_way`'s unfiltered walk already fails
        // with a raw `NotFound` there today — refuse explicitly and loudly
        // here instead, before ever calling it, so the failure names the
        // real cause (a partial clone) and points at `sc backfill` rather
        // than surfacing as a confusing corruption-shaped error. Only the
        // fast-forward/adopt paths above (which never rebuild a tree, only
        // gap-tolerant `materialize`) are exempt.
        if self.promisor()?.is_some() {
            return Err(crate::promisor::partial_clone_unsupported("merge"));
        }

        // Real three-way merge.
        let (merge_result, ours_root, ours_protection, theirs_protection) = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let base = crate::merge::merge_base(&mut store, ours, theirs)?
                .ok_or(Error::NoCommonAncestor)?;

            let m = crate::merge::three_way(&mut store, base, ours, theirs, identity)?;
            let ours_root = store.get_snapshot(&ours)?.root;
            let ours_protection = store.get_snapshot(&ours)?.protection;
            let theirs_protection = store.get_snapshot(&theirs)?.protection;
            (m, ours_root, ours_protection, theirs_protection)
        };

        // Union protection rules across both sides: governs which recipients a
        // needs_encrypt output (or a carried-plain file whose path is still
        // ruled on the other side) is encrypted for, and becomes the merged
        // snapshot's policy so future commits under either side's rules stay
        // protected. `union_prot` exists only to drive `matching_prefix`
        // lookups below — its `wrapped` map is irrelevant here.
        let union_prefixes =
            crate::protect::merge_prefixes(&ours_protection.prefixes, &theirs_protection.prefixes);
        let union_prot = scl_core::Protection { prefixes: union_prefixes.clone(), wrapped: Default::default() };

        // Split the resolved file set: carried ciphertext (needs_encrypt:
        // false, PROTECTED) stays byte-for-byte as-is; needs_encrypt outputs
        // (content-merged protected plaintext) get encrypted; a carried PLAIN
        // file (perms 0) whose path still matches a union rule is ALSO routed
        // through encryption — one side unprotecting a path the other side
        // still rules must not let plaintext land in the merged snapshot
        // (bit<->rule invariant, Task 4 review I2).
        let mut carried: Vec<(String, Vec<u8>, scl_core::FileMode, u8)> = Vec::new();
        let mut to_encrypt: Vec<(String, Vec<u8>, scl_core::FileMode, Vec<[u8; 32]>)> = Vec::new();
        for f in &merge_result.files {
            if f.needs_encrypt {
                let recipients = crate::protect::matching_prefix(&union_prot, &f.path)
                    .map(|r| r.granted_keys())
                    .ok_or_else(|| Error::NotProtected(f.path.clone()))?;
                to_encrypt.push((f.path.clone(), f.bytes.clone(), f.mode, recipients));
            } else if f.perms & scl_core::PROTECTED == 0 {
                match crate::protect::matching_prefix(&union_prot, &f.path) {
                    Some(rule) => {
                        to_encrypt.push((f.path.clone(), f.bytes.clone(), f.mode, rule.granted_keys()))
                    }
                    None => carried.push((f.path.clone(), f.bytes.clone(), f.mode, 0)),
                }
            } else {
                // Carried ciphertext: bytes are already the surviving blob's
                // raw ciphertext (fast path), never decrypted, perms verbatim.
                carried.push((f.path.clone(), f.bytes.clone(), f.mode, f.perms));
            }
        }

        if !merge_result.conflicts.is_empty() {
            // Conflicted merge (Task 6, P15). The working set holds plaintext
            // `needs_encrypt` entries — conflict markers and clean content
            // merges of protected paths (reachable only with an identity;
            // `three_way` enforces that). Plaintext must NEVER transit the
            // CAS: a marker blob written "just to materialize" would persist
            // in `.sc/objects/` long after resolution. So the CAS tree used
            // for materialization is built from the carried entries ONLY
            // (surviving ciphertext + plain files, all already CAS-safe), and
            // every `needs_encrypt` file — conflicted or not — is written
            // straight to the working tree via `safe_join`, exactly like
            // sidecars. Re-encryption happens at completion: `sc commit`
            // unions both parents' rules (`snapshot_files`).
            //
            // `to_encrypt` also holds ours' carried-plain files under a
            // theirs-only rule (the I2 case): they land back on disk as the
            // plaintext the user already had, and the completion commit
            // encrypts them under the union rule.
            let conflict_prot = scl_core::Protection {
                prefixes: union_prefixes,
                wrapped: merge_result.wrapped_carry.clone(),
            };
            let conflict_root = self.materialize_conflict_state(
                &carried,
                &to_encrypt,
                &merge_result.sidecars,
                &conflict_prot,
                ours_root,
                identity,
                &merge_result.conflicts,
            )?;
            // Conflict markers are on disk; record merge state last (its
            // MERGE_HEAD write is the in-progress signal). A crash in this
            // window leaves marked files but NO merge state — re-running
            // `merge` is then refused by the dirty-tree check (the markers
            // read as uncommitted changes), so recovery is manual: restore
            // the working tree (e.g. `sc switch` back to this branch to
            // re-materialize HEAD) and rerun the merge. The decided carried
            // tree (`conflict_root`) is persisted alongside so completion
            // carries absent protected files from the merge's DECISION rather
            // than re-arbitrating by parent order.
            crate::merge_state::write(
                &self.layout,
                &theirs,
                &merge_result.conflicts,
                Some(&conflict_root),
            )?;
            return Err(Error::MergeConflicts(merge_result.conflicts.len()));
        }

        let (encrypted, fresh_wrapped) = crate::protect::encrypt_protected(to_encrypt)?;
        carried.extend(encrypted);
        let all = carried;

        let merged_root = self.vfs.write_tree_with_perms(&all)?;

        // Merged wrap map: union the carried wraps (from `wrapped_carry`, for
        // ciphertext that survived unchanged/one-sided) with the freshly
        // encrypted entries' wraps, then reuse ours' prior wrap bytes for any
        // (blob, recipient) that's unchanged — same stability discipline as
        // `snapshot_files`' commit-time rebuild, so a convergent re-merge in
        // an independent repo produces byte-identical wraps.
        let mut wrapped: BTreeMap<ObjectId, Vec<WrappedKey>> = merge_result.wrapped_carry.clone();
        for (id, wks) in fresh_wrapped {
            let entry = wrapped.entry(id).or_default();
            *entry = crate::protect::union_wraps(entry, &wks);
        }
        crate::protect::reuse_prior_wraps(&mut wrapped, &ours_protection.wrapped);
        // Prune to blobs actually reachable in the merged tree (commit's
        // rebuild discipline — a path that lost its rule mid-merge and no
        // longer resolves to that blob must not leave a stale wrap entry).
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let reachable: std::collections::BTreeSet<ObjectId> =
                worktree::tree_file_entries_with_perms(&mut store, merged_root)?
                    .values()
                    .map(|(id, _, _)| *id)
                    .collect();
            wrapped.retain(|id, _| reachable.contains(id));
        }
        let merged_protection = scl_core::Protection { prefixes: union_prefixes, wrapped };

        // Materialize the merged tree into the working dir. Protection-aware:
        // a merged PROTECTED entry decrypts for `identity` when possible, else
        // is skipped (never writes ciphertext to disk) and reported to the
        // caller. (Sidecars exist only on the conflict path, handled above.)
        let skipped = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(
                &self.layout,
                &mut store,
                merged_root,
                Some(ours_root),
                &merged_protection,
                identity,
                &self.sparse_spec()?,
            )?
        };

        // Clean merge: two-parent snapshot now, carrying the merged
        // (union rules + union/fresh wraps) protection policy forward.
        let id = self.commit_snapshot(
            merged_root,
            vec![ours, theirs],
            merge_result.secrets,
            merged_protection,
            author,
            &format!("merge {branch}"),
        )?;
        crate::oplog::record(
            &self.layout,
            &format!("merge {branch}"),
            &head,
            &head,
            &[(head.clone(), before, Some(id))],
        )?;
        Ok((id, skipped))
    }

    /// Shared write sequence for a conflicted merge/replay's decided working
    /// set (P21): write the carried (already CAS-safe: surviving ciphertext +
    /// plain files) entries to a fresh CAS tree, materialize that tree into
    /// the working dir (deleting anything `old_root` tracked but the new tree
    /// doesn't, decrypting what `identity` can), then write the plaintext
    /// `to_encrypt` entries and `sidecars` straight to disk. Plaintext must
    /// NEVER transit the CAS, so this ordering matters: the direct writes
    /// happen AFTER materialize, whose deletion pass (old-tracked paths
    /// absent from the carried-only tree) would otherwise remove what they
    /// just wrote.
    ///
    /// Shared by `merge_with_identity`'s conflict arm, `cherry_pick`'s
    /// Conflicts arm, and the rebase fold's stop arm (P15 Tasks 6/7/8) — all
    /// three assemble `conflict_prot`'s wrap map differently (the merge path
    /// already has a precomputed `wrapped_carry` from `three_way`; the replay
    /// paths union `ours`'/`theirs`' wrap maps by hand, since
    /// `three_way_files`'s `Conflicts` outcome doesn't expose one) and
    /// persist different in-progress state afterward (`merge_state` vs
    /// `pick_state` vs `rebase_state`, with different return types), so only
    /// this write sequence — genuinely identical across all three — is
    /// extracted. Returns the CAS `conflict_root` so the caller can persist
    /// it as decided-root state.
    ///
    /// `conflicted_paths` (P24 Task 4) is the operation's own conflict list —
    /// NOT `carried`/`to_encrypt`'s path sets, which also include stable
    /// carried survivors that never needed a marker. Before any marker or
    /// sidecar is written, every conflicted path is checked against the
    /// repo's sparse spec: a conflict outside the sparse view can't be shown
    /// to the user (there's nowhere on disk to put the markers without
    /// silently materializing a path they asked to exclude), so this refuses
    /// up front with a widen hint, before `carried` is even written to the
    /// CAS — no out-of-sparse marker is ever written, not even transiently.
    /// A CLEAN out-of-sparse change never reaches here at all: it resolves
    /// on tree ids inside `three_way`/replay and lands via the ordinary
    /// materialize skip-write path (P24 Task 3), no markers involved.
    pub(crate) fn materialize_conflict_state(
        &self,
        carried: &[(String, Vec<u8>, scl_core::FileMode, u8)],
        to_encrypt: &[(String, Vec<u8>, scl_core::FileMode, Vec<[u8; 32]>)],
        sidecars: &[(String, Vec<u8>)],
        conflict_prot: &scl_core::Protection,
        old_root: ObjectId,
        identity: Option<&scl_crypto::SecretKey>,
        conflicted_paths: &[String],
    ) -> Result<ObjectId> {
        let sparse = self.sparse_spec()?;
        let needs_widen: Vec<&String> =
            conflicted_paths.iter().filter(|p| !sparse.matches(p)).collect();
        if !needs_widen.is_empty() {
            let names = needs_widen
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::InvalidArgument(format!(
                "conflict in {names} is outside your sparse checkout; run `sc sparse set` to include it, then retry"
            )));
        }
        let conflict_root = self.vfs.write_tree_with_perms(carried)?;
        {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            // Carried PROTECTED entries decrypt for `identity` where its key
            // matches; the rest are skipped (absent from disk). The
            // completion commit's decided-tree carry-forward preserves
            // skipped content, so nothing is lost by not surfacing the list
            // here (the `Err`/`Stopped` return can't carry it).
            let _skipped = worktree::materialize(
                &self.layout,
                &mut store,
                conflict_root,
                Some(old_root),
                conflict_prot,
                identity,
                &self.sparse_spec()?,
            )?;
        }
        for (path, bytes, _mode, _recipients) in to_encrypt {
            let full = worktree::safe_join(&self.layout.root, path)?;
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(full, bytes)?;
        }
        for (rel, bytes) in sidecars {
            let full = self.layout.root.join(rel);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(full, bytes)?;
        }
        Ok(conflict_root)
    }

    /// Abandon an in-progress merge: restore the working tree to the current tip
    /// and clear merge state. Errors if no merge is in progress.
    ///
    /// Returns the protected paths that could not be restored. No identity is
    /// available at abort time, so protected files are skipped (left absent)
    /// rather than decrypted — that's expected; re-supply an identity via a
    /// `switch_with_identity` back to the branch to materialize them.
    pub fn merge_abort(&self) -> Result<Vec<String>> {
        if !crate::merge_state::in_progress(&self.layout) {
            return Err(Error::InvalidArgument("no merge in progress".into()));
        }
        let theirs_id = crate::merge_state::read_merge_head(&self.layout)?
            .expect("in_progress is true but MERGE_HEAD is absent");
        // Remove any .theirs sidecars recorded as conflicts.
        for path in crate::merge_state::read_conflicts(&self.layout)? {
            let _ = std::fs::remove_file(self.layout.root.join(format!("{path}.theirs")));
        }
        // Restore working tree to ours tip. Pass theirs' root as `old_root` so
        // the deletion pass drops files the conflicted merge pulled in from
        // theirs; materializing against ours==old would delete nothing.
        let mut skipped = Vec::new();
        let ours_tip = self.head_tip()?;
        if let Some(ours_id) = ours_tip {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let ours_snap = store.get_snapshot(&ours_id)?;
            let ours_root = ours_snap.root;
            let ours_protection = ours_snap.protection;
            let theirs_root = store.get_snapshot(&theirs_id)?.root;
            // No identity at abort time: protected files in ours are skipped (not decrypted).
            skipped = worktree::materialize(
                &self.layout,
                &mut store,
                ours_root,
                Some(theirs_root),
                &ours_protection,
                None,
                &self.sparse_spec()?,
            )?;
        }
        crate::merge_state::clear(&self.layout)?;
        Ok(skipped)
    }

    /// Snapshots from the current tip back through parents (newest first).
    pub fn log(&self) -> Result<Vec<(ObjectId, Snapshot)>> {
        let mut out = Vec::new();
        let mut next = self.head_tip()?;
        while let Some(id) = next {
            let store_arc = self.vfs.store();
            let snap = store_arc.lock().unwrap().get_snapshot(&id)?;
            next = snap.parents.first().copied();
            out.push((id, snap));
        }
        Ok(out)
    }

    /// List branch names (sorted) and whether each is the current HEAD branch.
    pub fn branches(&self) -> Result<Vec<(String, bool)>> {
        let current = refs::current_branch(&self.layout)?;
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.layout.refs_heads_dir()) {
            for e in entries {
                let e = e?;
                if e.file_type()?.is_file() {
                    names.push(e.file_name().to_string_lossy().into_owned());
                }
            }
        }
        names.sort();
        Ok(names.into_iter().map(|n| (n.clone(), n == current)).collect())
    }

    /// Create `name` pointing at the current tip (errors if unborn or exists).
    pub fn branch(&self, name: &str) -> Result<()> {
        validate_branch_name(name)?;
        if self.layout.ref_path(name).exists() {
            return Err(Error::BadRef(format!("branch already exists: {name}")));
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        refs::write_branch_tip(&self.layout, name, &tip)?;
        let head = refs::current_branch(&self.layout)?;
        crate::oplog::record(
            &self.layout,
            &format!("branch {name}"),
            &head,
            &head,
            &[(name.to_string(), None, Some(tip))],
        )
    }

    /// Switch HEAD to `name` and materialize its tip into the working tree.
    ///
    /// Refuses to switch when the working tree has uncommitted modifications or
    /// deletions, because `materialize` would silently overwrite them. (New,
    /// untracked files are left in place and so don't block the switch.) The
    /// dirty check is protection-aware (see `status`/`diff_worktree`): a
    /// decrypted protected file that matches HEAD is clean and a skipped/absent
    /// protected file is clean, but a genuine edit to a protected file blocks
    /// the switch like any other uncommitted change.
    ///
    /// Returns the list of protected paths skipped (not decrypted) because no
    /// identity was provided. Use `switch_with_identity` to supply one.
    pub fn switch(&self, name: &str) -> Result<Vec<String>> {
        self.switch_with_identity(name, None)
    }

    /// Like [`switch`][Repo::switch] but decrypts `PROTECTED` files using
    /// `identity` when possible. Returns the list of protected paths that were
    /// skipped because the identity could not unwrap their DEK.
    pub fn switch_with_identity(
        &self,
        name: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<Vec<String>> {
        validate_branch_name(name)?;
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let head_before = refs::current_branch(&self.layout)?;
        // The protection-aware dirty check (status) already treats unchanged
        // decrypted protected files and skipped/absent protected files as clean,
        // so a reported modification/deletion is a genuine uncommitted change.
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before switching".into(),
            ));
        }
        let target_tip = refs::read_branch_tip(&self.layout, name)?
            .ok_or_else(|| Error::NoSuchBranch(name.to_string()))?;
        let old_root = self.head_root()?;
        let (target_root, target_protection) = {
            let store_arc = self.vfs.store();
            let snap = store_arc.lock().unwrap().get_snapshot(&target_tip)?;
            (snap.root, snap.protection)
        };
        let skipped = {
            let store_arc = self.vfs.store();
            let mut store = store_arc.lock().unwrap();
            worktree::materialize(
                &self.layout,
                &mut store,
                target_root,
                old_root,
                &target_protection,
                identity,
                &self.sparse_spec()?,
            )?
        };
        refs::write_head(&self.layout, name)?;
        crate::oplog::record(
            &self.layout,
            &format!("switch {name}"),
            &head_before,
            name,
            &[],
        )?;
        Ok(skipped)
    }


    /// Expose the underlying VFS repo handle (needed by secrets.rs methods).
    pub(crate) fn vfs_handle(&self) -> &VfsRepo {
        &self.vfs
    }

    /// The underlying VFS handle (objects live behind its `Store`). Test/gc use.
    pub fn vfs(&self) -> &VfsRepo {
        &self.vfs
    }

    /// Garbage-collect this repo: pack the reachable set and prune unreachable
    /// loose objects older than `grace`. Persistent repos only. The open `Repo`
    /// already holds the single-writer lock, so the whole pass is serialized
    /// against other writers.
    pub fn gc(&self, grace: std::time::Duration) -> Result<crate::gc::GcStats> {
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        crate::gc::run(&self.layout, &mut store, grace)
    }

}

/// Current unix time in seconds, for snapshot timestamps. Snapshot ids
/// legitimately depend on commit time (as in Git); nothing in the system
/// requires two separate commits of identical content to share an id.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Append one file's diff to `out`: unified hunks for text, a one-line notice
/// for binary content (NUL byte on either side).
fn push_file_diff(out: &mut String, path: &str, old: &[u8], new: &[u8]) {
    if old.contains(&0) || new.contains(&0) {
        out.push_str(&format!("Binary files a/{path} and b/{path} differ\n"));
        return;
    }
    let old_s = String::from_utf8_lossy(old);
    let new_s = String::from_utf8_lossy(new);
    out.push_str(&crate::textdiff::unified(path, &old_s, &new_s));
}


/// Reject branch names that would escape or corrupt `refs/heads/` or the
/// oplog grammar. A branch name becomes a single path component under
/// `refs/heads/`, so names containing path separators, the special `.`/`..`
/// components, or a leading dot are refused. The oplog's on-disk format
/// (`oplog.rs`) is space-delimited and one-line-per-field, so a name
/// containing whitespace or control characters would write an unparseable
/// `ref <name> ...` line — refuse those too, before they ever reach the log.
pub(crate) fn validate_branch_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::BadRef(format!("invalid branch name: {name:?}")));
    }
    Ok(())
}

/// Test seam: commit a snapshot that adds or replaces a protected prefix rule in
/// the current tip's protection policy. Used by tests that need a prefix rule
/// in place before calling `commit`; Task 6 provides the real `protect` API.
#[cfg(test)]
impl Repo {
    pub(crate) fn test_set_protected_prefix(
        &self,
        prefix: &str,
        recipients: &[scl_crypto::PublicKey],
    ) -> Result<ObjectId> {
        use scl_core::{ProtectPrefix, Protection};
        let (root, parents, secrets, mut protection) = match self.head_tip()? {
            Some(t) => {
                let snap = self.snapshot(&t)?;
                (snap.root, vec![t], snap.secrets, snap.protection)
            }
            None => {
                let root = self.vfs.write_tree(&[])?;
                (root, vec![], BTreeMap::new(), Protection::default())
            }
        };
        protection.prefixes.retain(|p| p.prefix != prefix);
        protection.prefixes.push(ProtectPrefix {
            prefix: prefix.to_string(),
            recipients: recipients
                .iter()
                .map(|pk| scl_core::RecipientEntry {
                    key: pk.to_bytes(),
                    epoch: 1,
                    state: scl_core::RecipientState::Granted,
                })
                .collect(),
        });
        self.commit_snapshot(root, parents, secrets, protection, "system", "set protected prefix")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-cmd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn scignore_hides_untracked_from_status_and_commit_but_not_tracked() {
        let root = tmp_root("scignore");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join(".scignore"), "junk\n").unwrap();
        std::fs::create_dir_all(root.join("junk")).unwrap();
        std::fs::write(root.join("junk/big.bin"), b"x").unwrap();
        std::fs::write(root.join("real.txt"), b"content").unwrap();

        // status: the ignored path is invisible; the real file and .scignore show.
        let st = repo.status().unwrap();
        assert_eq!(st.added, vec![".scignore".to_string(), "real.txt".to_string()]);

        // commit: the snapshot tree must not contain the ignored path.
        let id = repo.commit("t", "c1").unwrap();
        let store_arc = repo.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let snap_root = store.get_snapshot(&id).unwrap().root;
        let entries = worktree::tree_file_ids(&mut store, snap_root).unwrap();
        drop(store);
        assert!(entries.contains_key("real.txt"));
        assert!(!entries.keys().any(|p| p.starts_with("junk/")), "ignored path committed");

        // A tracked file stays tracked even when a later rule matches it.
        std::fs::write(root.join(".scignore"), "junk\nreal.txt\n").unwrap();
        std::fs::write(root.join("real.txt"), b"changed").unwrap();
        let st = repo.status().unwrap();
        assert!(
            st.modified.contains(&"real.txt".to_string()),
            "tracked file must not be ignored: {:?}",
            st
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rejects_unsafe_branch_names() {
        // Direct checks on the validator.
        for bad in ["", ".", "..", "a/b", "a\\b", ".hidden", "a b", "a\tb"] {
            assert!(
                matches!(validate_branch_name(bad), Err(Error::BadRef(_))),
                "expected {bad:?} to be rejected"
            );
        }
        assert!(validate_branch_name("feature").is_ok());

        // And via the public API, so a traversal name can't reach the ref path.
        let root = tmp_root("badbranch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();
        assert!(matches!(repo.branch(".."), Err(Error::BadRef(_))));
        assert!(matches!(repo.switch("a/b"), Err(Error::BadRef(_))));
        // Whitespace in a branch name would corrupt the oplog's space-delimited
        // grammar (see oplog.rs) — reject it before it's ever written.
        assert!(matches!(repo.branch("a b"), Err(Error::BadRef(_))));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn init_commit_reopen_log() {
        let root = tmp_root("commit");
        {
            let repo = Repo::init(&root).unwrap();
            std::fs::write(root.join("README.md"), b"hello").unwrap();
            repo.commit("me", "first").unwrap();
        } // drop releases lock + Store
        let repo2 = Repo::open(&root).unwrap();
        let log = repo2.log().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1.message, "first");
        drop(repo2);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn status_reports_add_modify_delete() {
        let root = tmp_root("status");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("keep.txt"), b"v1").unwrap();
        std::fs::write(root.join("gone.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();
        // modify keep, delete gone, add new
        std::fs::write(root.join("keep.txt"), b"v2").unwrap();
        std::fs::remove_file(root.join("gone.txt")).unwrap();
        std::fs::write(root.join("new.txt"), b"n").unwrap();
        let s = repo.status().unwrap();
        assert_eq!(s.added, vec!["new.txt"]);
        assert_eq!(s.modified, vec!["keep.txt"]);
        assert_eq!(s.deleted, vec!["gone.txt"]);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn branch_switch_materializes_and_repoints_head() {
        let root = tmp_root("branch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"on-main").unwrap();
        repo.commit("me", "main work").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        // commit a feature-only file
        std::fs::write(root.join("feature.txt"), b"f").unwrap();
        repo.commit("me", "feature work").unwrap();
        assert!(root.join("feature.txt").exists());
        // switch back to main: feature.txt must disappear, a.txt remain
        repo.switch("main").unwrap();
        assert!(!root.join("feature.txt").exists());
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"on-main");
        let branches = repo.branches().unwrap();
        assert!(branches.contains(&("main".to_string(), true)));
        assert!(branches.contains(&("feature".to_string(), false)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switch_refuses_to_clobber_uncommitted_changes() {
        let root = tmp_root("switch-dirty");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        // Uncommitted edit to a tracked file.
        std::fs::write(root.join("a.txt"), b"local-edit").unwrap();
        let err = repo.switch("feature").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        // The uncommitted edit must be preserved (switch did not materialize).
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"local-edit");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fast_forward_advances_without_merge_commit() {
        let root = tmp_root("ff");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("b.txt"), b"new").unwrap();
        let feat = repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();
        let merged = repo.merge("feature", "me").unwrap();
        assert_eq!(merged, feat, "fast-forward points main at feature tip");
        assert!(root.join("b.txt").exists());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clean_merge_creates_two_parent_snapshot() {
        let root = tmp_root("clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        // ours: change line 2 on main
        std::fs::write(root.join("shared.txt"), b"a\nB\nc\n").unwrap();
        let ours = repo.commit("me", "ours").unwrap();
        // theirs: change line 3 on feature
        repo.switch("feature").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nC\n").unwrap();
        let theirs = repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        let merge = repo.merge("feature", "me").unwrap();
        assert_eq!(std::fs::read(root.join("shared.txt")).unwrap(), b"a\nB\nC\n");
        let store_arc = repo.vfs_handle().store();
        let snap = store_arc.lock().unwrap().get_snapshot(&merge).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs]);
        let _ = base;
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_appends_oplog_record() {
        let root = tmp_root("oplog-commit");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        let id = repo.commit("me", "first commit\nsecond line").unwrap();
        let rec = crate::oplog::last(repo.layout()).unwrap().expect("commit must log a record");
        assert!(rec.desc.starts_with("commit: "), "got {:?}", rec.desc);
        assert_eq!(rec.desc, "commit: first commit");
        assert_eq!(rec.head_before, "main");
        assert_eq!(rec.head_after, "main");
        assert_eq!(rec.refs, vec![("main".to_string(), None, Some(id))]);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_ff_and_clean_merge_append_oplog_records() {
        // Fast-forward merge.
        let root = tmp_root("oplog-merge-ff");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("b.txt"), b"new").unwrap();
        let feat = repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();
        let merged = repo.merge("feature", "me").unwrap();
        assert_eq!(merged, feat);
        let rec = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(rec.desc, "merge feature (ff)");
        assert_eq!(rec.head_before, "main");
        assert_eq!(rec.head_after, "main");
        assert_eq!(rec.refs.len(), 1);
        assert_eq!(rec.refs[0].2, Some(feat));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();

        // Clean (real) three-way merge.
        let root2 = tmp_root("oplog-merge-clean");
        let repo2 = Repo::init(&root2).unwrap();
        std::fs::write(root2.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo2.commit("me", "base").unwrap();
        repo2.branch("feature").unwrap();
        std::fs::write(root2.join("shared.txt"), b"a\nB\nc\n").unwrap();
        let ours = repo2.commit("me", "ours").unwrap();
        repo2.switch("feature").unwrap();
        std::fs::write(root2.join("shared.txt"), b"a\nb\nC\n").unwrap();
        repo2.commit("me", "theirs").unwrap();
        repo2.switch("main").unwrap();
        let merge = repo2.merge("feature", "me").unwrap();
        let rec2 = crate::oplog::last(repo2.layout()).unwrap().unwrap();
        assert_eq!(rec2.desc, "merge feature");
        assert_eq!(rec2.head_before, "main");
        assert_eq!(rec2.head_after, "main");
        assert_eq!(rec2.refs, vec![("main".to_string(), Some(ours), Some(merge))]);
        drop(repo2);
        std::fs::remove_dir_all(&root2).unwrap();

        // Conflicted merge: no record appended (no refs moved).
        let root3 = tmp_root("oplog-merge-conflict");
        let repo3 = Repo::init(&root3).unwrap();
        std::fs::write(root3.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo3.commit("me", "base").unwrap();
        repo3.branch("feature").unwrap();
        std::fs::write(root3.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo3.commit("me", "ours").unwrap();
        repo3.switch("feature").unwrap();
        std::fs::write(root3.join("f.txt"), b"a\nY\nc\n").unwrap();
        repo3.commit("me", "theirs").unwrap();
        repo3.switch("main").unwrap();
        let before_conflict = crate::oplog::last(repo3.layout()).unwrap().unwrap();
        let err = repo3.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)));
        let after_conflict = crate::oplog::last(repo3.layout()).unwrap().unwrap();
        assert_eq!(before_conflict.seq, after_conflict.seq, "conflicted merge must log nothing");
        drop(repo3);
        std::fs::remove_dir_all(&root3).unwrap();
    }

    #[test]
    fn branch_and_switch_append_oplog_records() {
        let root = tmp_root("oplog-branch-switch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        let tip = repo.commit("me", "base").unwrap();

        repo.branch("feature").unwrap();
        let branch_rec = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(branch_rec.desc, "branch feature");
        assert_eq!(branch_rec.head_before, "main");
        assert_eq!(branch_rec.head_after, "main");
        assert_eq!(branch_rec.refs, vec![("feature".to_string(), None, Some(tip))]);

        repo.switch("feature").unwrap();
        let switch_rec = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(switch_rec.desc, "switch feature");
        assert_eq!(switch_rec.head_before, "main");
        assert_eq!(switch_rec.head_after, "feature");
        assert!(switch_rec.refs.is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn conflict_marks_tree_and_finalizes_on_commit() {
        let root = tmp_root("conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        let ours = repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        let theirs = repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert!(repo.merge_in_progress());
        let marked = std::fs::read_to_string(root.join("f.txt")).unwrap();
        assert!(marked.contains("<<<<<<< ours") && marked.contains(">>>>>>> theirs"));

        // resolve and commit -> two-parent merge snapshot, state cleared
        std::fs::write(root.join("f.txt"), b"a\nZ\nc\n").unwrap();
        let merge = repo.commit("me", "resolve").unwrap();
        assert!(!repo.merge_in_progress());
        let store_arc = repo.vfs_handle().store();
        let snap = store_arc.lock().unwrap().get_snapshot(&merge).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs]);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_abort_restores_and_clears() {
        let root = tmp_root("abort");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        let _ = repo.merge("feature", "me").unwrap_err();
        repo.merge_abort().unwrap();
        assert!(!repo.merge_in_progress());
        // working tree restored to ours' content (no markers)
        assert_eq!(std::fs::read(root.join("f.txt")).unwrap(), b"a\nX\nc\n");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_refuses_dirty_tree() {
        let root = tmp_root("dirty-merge");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"feat").unwrap();
        repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();
        std::fs::write(root.join("a.txt"), b"dirty-local").unwrap();
        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_abort_drops_theirs_only_files() {
        let root = tmp_root("abort-theirs-only");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        // ours: modify f.txt on main
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours").unwrap();
        // theirs: modify f.txt AND add new.txt on feature
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        std::fs::write(root.join("new.txt"), b"from-theirs").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let _ = repo.merge("feature", "me").unwrap_err();
        assert!(root.join("new.txt").exists(), "merge pulled in theirs' new.txt");
        repo.merge_abort().unwrap();
        assert!(!repo.merge_in_progress());
        // theirs-only file must be gone, f.txt restored to ours' content
        assert!(!root.join("new.txt").exists(), "abort must drop theirs-only new.txt");
        assert_eq!(std::fs::read(root.join("f.txt")).unwrap(), b"a\nX\nc\n");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ---- P15 Task 5: `Repo::merge_with_identity` — clean protected merges ----

    #[test]
    fn non_recipient_merges_disjoint_protected_branches() {
        // alice protects secret/ and commits secret/a.txt; main edits
        // secret/a.txt, feature (from the same base) adds secret/b.txt — both
        // resolve by the ciphertext-id fast path (one side unchanged/one-sided
        // add), so a merge with NO identity at all must still succeed: nothing
        // is ever decrypted. Alice can still read both files afterward.
        let root = tmp_root("p15-merge-disjoint-protected");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"a1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b2").unwrap();

        // main (ours): edit secret/a.txt.
        std::fs::write(root.join("secret/a.txt"), b"a2").unwrap();
        let ours = repo.commit("me", "main edits a.txt").unwrap();

        // b2 (theirs): add secret/b.txt.
        repo.switch_with_identity("b2", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/b.txt"), b"b1").unwrap();
        repo.commit("me", "b2 adds b.txt").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        // Merge with NO identity: must succeed (no content divergence to decrypt).
        let id = repo.merge("b2", "me").unwrap();
        assert!(!repo.merge_in_progress());
        let _ = ours;

        let snap = repo.snapshot(&id).unwrap();
        let (a_id, a_perms, b_id, b_perms) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (aid, _, aperms) = entries["secret/a.txt"];
            let (bid, _, bperms) = entries["secret/b.txt"];
            (aid, aperms, bid, bperms)
        };
        assert_ne!(a_perms & scl_core::PROTECTED, 0);
        assert_ne!(b_perms & scl_core::PROTECTED, 0);
        {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            if let Object::Blob(b) = s.get(&a_id).unwrap() {
                assert_ne!(&b[..], b"a2", "a.txt blob must be ciphertext");
            } else {
                panic!("expected Blob");
            }
            if let Object::Blob(b) = s.get(&b_id).unwrap() {
                assert_ne!(&b[..], b"b1", "b.txt blob must be ciphertext");
            } else {
                panic!("expected Blob");
            }
        }

        // Alice, with her identity, can decrypt both merged files.
        let skipped = repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        assert!(skipped.is_empty(), "alice must decrypt both: {skipped:?}");
        assert_eq!(std::fs::read(root.join("secret/a.txt")).unwrap(), b"a2");
        assert_eq!(std::fs::read(root.join("secret/b.txt")).unwrap(), b"b1");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn content_divergent_merge_without_identity_refuses_cleanly() {
        // Both branches edit secret/a.txt's content: a genuine content merge,
        // which needs an identity to decrypt and diff3 the plaintexts. Without
        // one, the merge must refuse, and leave refs/working tree/merge state
        // completely untouched.
        let root = tmp_root("p15-merge-refuse-no-identity");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"v2").unwrap();
        let ours = repo.commit("me", "main edits").unwrap();
        // Switch WITH identity so the protected file stays materialized on
        // disk across the branch hop (a keyless switch would skip/remove it,
        // which is not what this test is about).
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"v3").unwrap();
        repo.commit("me", "feature edits").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(&err, Error::ProtectedMergeNeedsIdentity(p) if p == "secret/a.txt"), "got {err:?}");

        // Refs untouched.
        assert_eq!(repo.head_tip().unwrap(), Some(ours));
        // No merge state recorded.
        assert!(!repo.merge_in_progress());
        // Working tree untouched: main's own edit ("v2", written directly by
        // `std::fs::write` — commit never rewrites the working copy) is intact.
        assert_eq!(std::fs::read(root.join("secret/a.txt")).unwrap(), b"v2");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn content_merge_with_identity_reencrypts_for_all_recipients() {
        // secret/ protected to BOTH alice and bob; colliding-but-mergeable
        // edits (non-overlapping lines). `merge_with_identity(alice)` must
        // produce a clean two-parent snapshot whose re-encrypted blob decrypts
        // for BOTH recipients, not just the one who ran the merge.
        let root = tmp_root("p15-merge-content-both-recipients");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk, bob_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"L1\nl2\nl3\n").unwrap();
        repo.commit("me", "main edits line 1").unwrap();
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nL3\n").unwrap();
        repo.commit("me", "feature edits line 3").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let (id, skipped) = repo.merge_with_identity("feature", "me", Some(&alice_sk)).unwrap();
        assert!(skipped.is_empty(), "alice holds the key; nothing skipped: {skipped:?}");
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents.len(), 2, "clean merge is a two-parent snapshot");

        let (blob_id, bytes) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (id, _, perms) = entries["secret/a.txt"];
            assert_ne!(perms & scl_core::PROTECTED, 0);
            let bytes = match s.get(&id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            };
            (id, bytes)
        };
        let prot = &snap.protection;
        let alice_pt =
            crate::protect::decrypt_with(&bytes, &blob_id, &[prot], &alice_sk, "secret/a.txt").unwrap();
        let bob_pt =
            crate::protect::decrypt_with(&bytes, &blob_id, &[prot], &bob_sk, "secret/a.txt").unwrap();
        assert_eq!(&alice_pt[..], b"L1\nl2\nL3\n");
        assert_eq!(&bob_pt[..], b"L1\nl2\nL3\n");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rules_union_survives_merge_and_governs_future_commits() {
        // feature adds a protect rule for keys/ (+ a protected file) that main
        // never had. After merging feature into main, the merged snapshot's
        // rule set must include keys/ — and a brand-new plaintext file
        // committed under keys/ afterward must land PROTECTED (otherwise a
        // merge would be a silent way to leak future content under a rule the
        // merging side never explicitly adopted).
        let root = tmp_root("p15-merge-rules-union");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main: unrelated addition (keeps the merge a genuine 3-way, not a ff).
        std::fs::write(root.join("main-only.txt"), b"o").unwrap();
        repo.commit("me", "main adds main-only.txt").unwrap();

        // feature: adds the keys/ rule + a protected file under it.
        repo.switch("feature").unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/a.txt"), b"secret-key").unwrap();
        repo.protect("keys/", &[alice_pk], None).unwrap();
        repo.switch("main").unwrap();

        let id = repo.merge("feature", "me").unwrap();
        let snap = repo.snapshot(&id).unwrap();
        assert!(
            snap.protection.prefixes.iter().any(|p| p.prefix == "keys/"),
            "merged policy must carry forward feature's keys/ rule"
        );

        // A NEW plaintext file committed under keys/ must land PROTECTED.
        std::fs::write(root.join("keys/b.txt"), b"another-secret").unwrap();
        let id2 = repo.commit("me", "add keys/b.txt").unwrap();
        let snap2 = repo.snapshot(&id2).unwrap();
        let (b_id, b_perms) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap2.root).unwrap();
            let (id, _, perms) = entries["keys/b.txt"];
            (id, perms)
        };
        assert_ne!(b_perms & scl_core::PROTECTED, 0, "new file under keys/ must be protected");
        // And alice can decrypt it — the rule's recipient was carried too.
        let bytes = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            match s.get(&b_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            }
        };
        let pt = crate::protect::decrypt_with(&bytes, &b_id, &[&snap2.protection], &alice_sk, "keys/b.txt")
            .unwrap();
        assert_eq!(&pt[..], b"another-secret");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn carried_plain_file_under_a_union_rule_lands_protected() {
        // Task 4 review I2 resolution: ours carries a PLAIN winner (perms 0,
        // needs_encrypt false — the ciphertext-id fast path never even looks
        // at the file's content) whose path matches a rule that ONLY theirs
        // knows about. The bit<->rule invariant must still hold in the merged
        // snapshot: this file must land PROTECTED, not plaintext, even though
        // no `needs_encrypt` output was ever produced for it.
        let root = tmp_root("p15-merge-carried-plain-under-rule");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main (ours): a plain file under keys/ — no rule exists yet.
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/a.txt"), b"plain-for-now").unwrap();
        repo.commit("me", "main adds plain keys/a.txt").unwrap();

        // feature (theirs): records the keys/ rule with NO matching file
        // present — `protect` still persists the rule for future commits.
        repo.switch("feature").unwrap();
        repo.protect("keys/", &[alice_pk], None).unwrap();
        repo.switch("main").unwrap();

        // ours' keys/a.txt is unchanged from base on ours' side (tk == bk:
        // theirs never touched it, base never had it either) -> the plain
        // fast-path winner, verbatim ciphertext-id logic transferred from the
        // ordinary all-plain arm. No identity needed for the fast path itself.
        let id = repo.merge("feature", "me").unwrap();
        let snap = repo.snapshot(&id).unwrap();

        let (blob_id, perms) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (id, _, perms) = entries["keys/a.txt"];
            (id, perms)
        };
        assert_ne!(
            perms & scl_core::PROTECTED,
            0,
            "carried-plain file under a union rule must be re-encrypted at merge time"
        );
        let bytes = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            match s.get(&blob_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            }
        };
        assert_ne!(&bytes[..], b"plain-for-now", "must not be the plaintext blob");
        let pt = crate::protect::decrypt_with(&bytes, &blob_id, &[&snap.protection], &alice_sk, "keys/a.txt")
            .unwrap();
        assert_eq!(&pt[..], b"plain-for-now");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn plain_conflict_carries_theirs_protected_content_through_completion() {
        // Task 6 (scenario B, formerly the Task 5 interim-guard refusal): a
        // merge whose conflicts are ALL plain but which carries protected
        // content from theirs (rule + ciphertext file) now COMPLETES keyless.
        // The completion commit reads the UNION of both parents' rules and
        // carries theirs' absent-from-disk ciphertext forward — the reviewer's
        // pre-guard scenario destroyed secret/db.txt and rolled back the rule.
        let root = tmp_root("p15-plain-conflict-theirs-protected");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // ours: plain conflicting edit.
        std::fs::write(root.join("shared.txt"), b"a\nX\nc\n").unwrap();
        let ours = repo.commit("me", "ours edits shared").unwrap();

        // theirs: conflicting plain edit PLUS a protect rule + protected file.
        repo.switch("feature").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nY\nc\n").unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let theirs = repo.protect("secret/", &[alice_pk], None).unwrap();
        repo.switch("main").unwrap();

        // Keyless conflicted merge is now allowed through: markers on disk,
        // merge state recorded, theirs' protected file skipped (no key).
        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert!(repo.merge_in_progress(), "MERGE_HEAD recorded");
        let marked = std::fs::read(root.join("shared.txt")).unwrap();
        assert!(
            marked.windows(7).any(|w| w == b"<<<<<<<"),
            "conflict markers on disk: {}",
            String::from_utf8_lossy(&marked)
        );
        assert!(!root.join("secret/db.txt").exists(), "no key: theirs' file stays off disk");

        // Resolve the plain conflict and complete via commit.
        std::fs::write(root.join("shared.txt"), b"a\nRESOLVED\nc\n").unwrap();
        let id = repo.commit("me", "resolve merge").unwrap();
        assert!(!repo.merge_in_progress());
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs], "two-parent completion");

        // Theirs' rule survives the completion...
        assert!(
            snap.protection.prefixes.iter().any(|p| p.prefix == "secret/"),
            "theirs' secret/ rule must survive completion"
        );
        // ...and theirs' ciphertext is carried forward verbatim, decryptable.
        let (blob_id, perms) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (bid, _, perms) = entries["secret/db.txt"];
            (bid, perms)
        };
        assert_ne!(perms & scl_core::PROTECTED, 0);
        let bytes = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            match s.get(&blob_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            }
        };
        assert_ne!(&bytes[..], b"hunter2", "carried blob must stay ciphertext");
        let pt =
            crate::protect::decrypt_with(&bytes, &blob_id, &[&snap.protection], &alice_sk, "secret/db.txt")
                .unwrap();
        assert_eq!(&pt[..], b"hunter2", "alice still decrypts the carried file");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn plain_conflict_keeps_ours_plain_file_under_theirs_rule_until_completion_encrypts_it() {
        // Task 6 (scenario C, formerly the Task 5 interim-guard refusal): ours
        // holds a PLAIN file whose path a theirs-only rule governs, plus an
        // unrelated all-plain conflict. The conflicted merge now proceeds:
        // keys/a.txt is written straight to the working tree (direct write,
        // not through the CAS materialize that once deleted it), survives the
        // conflict window as editable plaintext, and the completion commit
        // encrypts it under the union (theirs-side) rule — the I2 invariant:
        // no plaintext under a live rule lands in a snapshot.
        let root = tmp_root("p15-plain-conflict-ours-under-theirs-rule");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // ours: plain conflicting edit + a plain file under keys/ (no rule here).
        std::fs::write(root.join("shared.txt"), b"a\nX\nc\n").unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/a.txt"), b"plain-for-now").unwrap();
        let ours = repo.commit("me", "ours edits shared + adds plain keys/a.txt").unwrap();

        // theirs: conflicting plain edit + records the keys/ rule (nothing to
        // encrypt on its side).
        repo.switch("feature").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nY\nc\n").unwrap();
        repo.commit("me", "theirs edits shared").unwrap();
        let theirs = repo.protect("keys/", &[alice_pk], None).unwrap();
        repo.switch("main").unwrap();
        assert_eq!(std::fs::read(root.join("keys/a.txt")).unwrap(), b"plain-for-now");

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert!(repo.merge_in_progress(), "MERGE_HEAD recorded");
        // Ours' own plain file survives the conflict window ON DISK — the
        // pre-fix keyless materialize deleted it.
        assert_eq!(
            std::fs::read(root.join("keys/a.txt")).unwrap(),
            b"plain-for-now",
            "ours' plain file under theirs' rule must stay on disk while conflicted"
        );
        let marked = std::fs::read(root.join("shared.txt")).unwrap();
        assert!(marked.windows(7).any(|w| w == b"<<<<<<<"), "markers written");

        // Resolve and complete: the file must land ENCRYPTED under theirs' rule.
        std::fs::write(root.join("shared.txt"), b"a\nRESOLVED\nc\n").unwrap();
        let id = repo.commit("me", "resolve merge").unwrap();
        assert!(!repo.merge_in_progress());
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs], "two-parent completion");
        assert!(snap.protection.prefixes.iter().any(|p| p.prefix == "keys/"));

        let (blob_id, perms) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (bid, _, perms) = entries["keys/a.txt"];
            (bid, perms)
        };
        assert_ne!(
            perms & scl_core::PROTECTED,
            0,
            "completion must encrypt the plain file under the union rule"
        );
        let bytes = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            match s.get(&blob_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            }
        };
        assert_ne!(&bytes[..], b"plain-for-now", "snapshot blob must be ciphertext");
        let pt =
            crate::protect::decrypt_with(&bytes, &blob_id, &[&snap.protection], &alice_sk, "keys/a.txt")
                .unwrap();
        assert_eq!(&pt[..], b"plain-for-now");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merged_plaintext_never_lands_in_cas() {
        // After a content merge, every PROTECTED entry's stored blob bytes
        // must differ from the known plaintext (only ciphertext ever reaches
        // the CAS) — and decrypting with the right DEK must recover it.
        let root = tmp_root("p15-merge-no-plaintext-leak");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"L1\nl2\nl3\n").unwrap();
        repo.commit("me", "main edits line 1").unwrap();
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nL3\n").unwrap();
        repo.commit("me", "feature edits line 3").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let (id, _skipped) = repo.merge_with_identity("feature", "me", Some(&alice_sk)).unwrap();
        let snap = repo.snapshot(&id).unwrap();
        let expected_plain = b"L1\nl2\nL3\n";

        let store_arc = repo.vfs_handle().store();
        let mut s = store_arc.lock().unwrap();
        let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
        for (path, (blob_id, _mode, perms)) in &entries {
            if perms & scl_core::PROTECTED == 0 {
                continue;
            }
            let bytes = match s.get(blob_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            };
            assert_ne!(&bytes[..], &expected_plain[..], "{path}: plaintext leaked into the CAS");
            let pt = crate::protect::decrypt_with(&bytes, blob_id, &[&snap.protection], &alice_sk, path)
                .unwrap();
            assert_eq!(&pt[..], expected_plain, "{path}: decrypts back to the merged plaintext");
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn convergent_merge_ids_are_stable_across_repos() {
        // Two independent repos build the identical protected divergence
        // (same base plaintext, same edits on both sides) and content-merge
        // with their own (distinct) recipient identity. Convergent encryption
        // means the merged plaintext is identical, so the resulting ciphertext
        // blob id must be IDENTICAL across the two repos — merge output is
        // deterministic content addressing, not per-repo randomness.
        fn build(tag: &str) -> (Repo, std::path::PathBuf, ObjectId, ObjectId) {
            let root = tmp_root(tag);
            let repo = Repo::init(&root).unwrap();
            let (sk, pk) = scl_crypto::generate_keypair();
            repo.protect("secret/", &[pk], None).unwrap();
            std::fs::create_dir_all(root.join("secret")).unwrap();
            std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
            repo.commit("me", "base").unwrap();
            repo.branch("feature").unwrap();

            std::fs::write(root.join("secret/a.txt"), b"L1\nl2\nl3\n").unwrap();
            repo.commit("me", "main edits line 1").unwrap();
            repo.switch_with_identity("feature", Some(&sk)).unwrap();
            std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nL3\n").unwrap();
            repo.commit("me", "feature edits line 3").unwrap();
            repo.switch_with_identity("main", Some(&sk)).unwrap();

            let (id, _skipped) = repo.merge_with_identity("feature", "me", Some(&sk)).unwrap();
            let snap = repo.snapshot(&id).unwrap();
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (blob_id, _, _) = entries["secret/a.txt"];
            drop(s);
            (repo, root, id, blob_id)
        }

        let (repo1, root1, _id1, blob1) = build("p15-merge-convergent-a");
        let (repo2, root2, _id2, blob2) = build("p15-merge-convergent-b");
        assert_eq!(blob1, blob2, "identical merged plaintext must converge to the same blob id");
        drop(repo1);
        drop(repo2);
        std::fs::remove_dir_all(&root1).unwrap();
        std::fs::remove_dir_all(&root2).unwrap();
    }

    // ---- P15 Task 6: conflicted protected merges + completion rules union ----

    /// True iff any loose CAS blob's decoded bytes contain `needle`. Loose
    /// objects are zstd-compressed on disk, so this decodes via `Store::get`
    /// rather than grepping raw files.
    fn cas_blob_contains(repo: &Repo, needle: &[u8]) -> bool {
        let store_arc = repo.vfs_handle().store();
        let mut s = store_arc.lock().unwrap();
        for id in s.list_loose().unwrap() {
            if let Ok(Object::Blob(b)) = s.get(&id) {
                if b.windows(needle.len()).any(|w| w == needle) {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn conflicted_protected_merge_resolves_via_commit_reencryption() {
        // Same-line edits of secret/a.txt on both sides (alice AND bob are
        // recipients): merge_with_identity(alice) conflicts. The plaintext
        // marker file must live on DISK ONLY — no CAS object may contain the
        // marker plaintext — and resolving + committing produces a two-parent
        // snapshot whose re-encrypted blob decrypts for bob too.
        let root = tmp_root("p15-conflicted-protected-merge");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk, bob_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"OURS-EDIT\nl2\nl3\n").unwrap();
        let ours = repo.commit("me", "main edits line 1").unwrap();
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"THEIRS-EDIT\nl2\nl3\n").unwrap();
        let theirs = repo.commit("me", "feature edits line 1").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo.merge_with_identity("feature", "me", Some(&alice_sk)).unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert_eq!(repo.merge_conflicts().unwrap(), vec!["secret/a.txt".to_string()]);

        // Markers are on disk as editable plaintext...
        let marked = std::fs::read(root.join("secret/a.txt")).unwrap();
        assert!(marked.windows(7).any(|w| w == b"<<<<<<<"), "markers on disk");
        assert!(marked.windows(9).any(|w| w == b"OURS-EDIT"));
        assert!(marked.windows(11).any(|w| w == b"THEIRS-EDIT"));
        // ...and NO CAS object contains the marker plaintext (the conflicted
        // working set is written to the worktree directly, never via a tree).
        assert!(!cas_blob_contains(&repo, b"<<<<<<<"), "marker plaintext leaked into the CAS");
        assert!(!cas_blob_contains(&repo, b"OURS-EDIT"), "protected plaintext leaked into the CAS");

        // Resolve and complete via commit: re-encryption happens there.
        std::fs::write(root.join("secret/a.txt"), b"RESOLVED\nl2\nl3\n").unwrap();
        let id = repo.commit("me", "resolve secret conflict").unwrap();
        assert!(!repo.merge_in_progress());
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs], "two-parent completion snapshot");

        let (blob_id, perms) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (bid, _, perms) = entries["secret/a.txt"];
            (bid, perms)
        };
        assert_ne!(perms & scl_core::PROTECTED, 0);
        let bytes = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            match s.get(&blob_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            }
        };
        assert!(!bytes.windows(8).any(|w| w == b"RESOLVED"), "resolved plaintext in CAS blob");
        for (who, sk) in [("alice", &alice_sk), ("bob", &bob_sk)] {
            let pt = crate::protect::decrypt_with(&bytes, &blob_id, &[&snap.protection], sk, "secret/a.txt")
                .unwrap();
            assert_eq!(&pt[..], b"RESOLVED\nl2\nl3\n", "{who} must decrypt the resolution");
        }
        // Still no marker/plaintext residue anywhere in the CAS after completion.
        assert!(!cas_blob_contains(&repo, b"<<<<<<<"));
        assert!(!cas_blob_contains(&repo, b"RESOLVED"));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_completion_honors_theirs_side_rules() {
        // Theirs adds a keys/ rule + file AND a conflicting plain edit, so the
        // merge conflicts on the plain file only. After resolving, a NEW file
        // added under keys/ in the completion commit must land PROTECTED —
        // completion reads the union of both parents' rules, not ours' only.
        let root = tmp_root("p15-completion-theirs-rules");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("shared.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours edits shared").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nY\nc\n").unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/k1.txt"), b"first-key").unwrap();
        repo.protect("keys/", &[alice_pk], None).unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        // Resolve the plain conflict AND add a new file under theirs' rule.
        std::fs::write(root.join("shared.txt"), b"a\nRESOLVED\nc\n").unwrap();
        std::fs::write(root.join("keys/k2.txt"), b"second-key").unwrap();
        let id = repo.commit("me", "resolve + add keys/k2.txt").unwrap();
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents.len(), 2);

        let store_arc = repo.vfs_handle().store();
        let mut s = store_arc.lock().unwrap();
        let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
        // The new file lands PROTECTED under theirs' rule...
        let (k2_id, _, k2_perms) = entries["keys/k2.txt"];
        assert_ne!(k2_perms & scl_core::PROTECTED, 0, "new file under theirs' rule must encrypt");
        let bytes = match s.get(&k2_id).unwrap() {
            Object::Blob(b) => b.to_vec(),
            _ => panic!("expected Blob"),
        };
        drop(s);
        assert_ne!(&bytes[..], b"second-key");
        let pt = crate::protect::decrypt_with(&bytes, &k2_id, &[&snap.protection], &alice_sk, "keys/k2.txt")
            .unwrap();
        assert_eq!(&pt[..], b"second-key");
        // ...and theirs' own protected file + rule survive too.
        let (_, _, k1_perms) = entries["keys/k1.txt"];
        assert_ne!(k1_perms & scl_core::PROTECTED, 0, "theirs' keys/k1.txt carried forward");
        assert!(snap.protection.prefixes.iter().any(|p| p.prefix == "keys/"));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn completion_carries_theirs_updated_protected_file_not_ours_stale() {
        // Reviewer-reproduced Critical (Task 6 review): base+ours hold
        // secret/x.txt v0; theirs updates it to v1, decided by the clean
        // "only theirs changed → take theirs" fast path; an unrelated plain
        // conflict forces the conflict path, and the keyless materialize
        // skips x.txt (absent from disk at commit). Completion must carry
        // THEIRS' v1 from the merge's DECIDED tree — the ours-first parent
        // arbitration carried stale v0, recorded theirs as a parent anyway,
        // and made the loss undetectable (a re-merge reported UpToDate).
        let root = tmp_root("p15-completion-decided-tree");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x.txt"), b"v0").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // ours: only the plain conflicting edit; secret/x.txt stays v0.
        std::fs::write(root.join("shared.txt"), b"a\nX\nc\n").unwrap();
        let ours = repo.commit("me", "ours edits shared").unwrap();

        // theirs: update secret/x.txt to v1 + the conflicting plain edit.
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/x.txt"), b"v1").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nY\nc\n").unwrap();
        let theirs = repo.commit("me", "theirs updates secret + edits shared").unwrap();

        // Theirs' v1 ciphertext id: the decided blob completion must keep.
        let v1_id = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let troot = s.get_snapshot(&theirs).unwrap().root;
            worktree::tree_file_entries_with_perms(&mut s, troot).unwrap()["secret/x.txt"].0
        };

        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        // KEYLESS conflicted merge: x.txt is decided clean (take theirs) but
        // cannot materialize without a key; shared.txt conflicts.
        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert!(!root.join("secret/x.txt").exists(), "keyless: v1 stays off disk");

        std::fs::write(root.join("shared.txt"), b"a\nRESOLVED\nc\n").unwrap();
        let id = repo.commit("me", "resolve").unwrap();
        assert!(!repo.merge_in_progress());
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![ours, theirs]);

        let (got_id, perms) = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap();
            let (bid, _, perms) = entries["secret/x.txt"];
            (bid, perms)
        };
        assert_ne!(perms & scl_core::PROTECTED, 0);
        assert_eq!(
            got_id, v1_id,
            "completion must carry THEIRS' decided v1 ciphertext, not ours' stale v0"
        );
        let bytes = {
            let store_arc = repo.vfs_handle().store();
            let mut s = store_arc.lock().unwrap();
            match s.get(&got_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            }
        };
        let pt =
            crate::protect::decrypt_with(&bytes, &got_id, &[&snap.protection], &alice_sk, "secret/x.txt")
                .unwrap();
        assert_eq!(&pt[..], b"v1", "the carried blob decrypts to theirs' update");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ff_merge_with_identity_materializes_decrypted_protected_files() {
        // Rider M1: the fast-forward path must thread `identity` into its
        // materialize call — a recipient running `sc merge --identity` gets
        // decrypted files on disk, not a skip.
        let root = tmp_root("p15-ff-merge-identity");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"v2").unwrap();
        let theirs = repo.commit("me", "feature edits secret").unwrap();

        // Keyless hop back to main removes the protected file from disk.
        repo.switch("main").unwrap();
        assert!(!root.join("secret/a.txt").exists());

        let (id, skipped) = repo.merge_with_identity("feature", "me", Some(&alice_sk)).unwrap();
        assert_eq!(id, theirs, "fast-forward adopts theirs' tip");
        assert!(skipped.is_empty(), "identity provided; nothing skipped: {skipped:?}");
        assert_eq!(
            std::fs::read(root.join("secret/a.txt")).unwrap(),
            b"v2",
            "ff merge with identity must materialize the decrypted file"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_surfaces_skipped_protected_paths() {
        // Rider M2: a keyless clean merge that cannot decrypt the merged
        // protected files returns their paths as `skipped`, mirroring
        // `switch_with_identity`.
        let root = tmp_root("p15-merge-skipped-surfaced");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"a1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b2").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"a2").unwrap();
        repo.commit("me", "main edits a.txt").unwrap();
        repo.switch_with_identity("b2", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/b.txt"), b"b1").unwrap();
        repo.commit("me", "b2 adds b.txt").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        // Keyless merge succeeds (disjoint fast paths) but can materialize
        // neither protected file — both must be reported.
        let (_id, skipped) = repo.merge_with_identity("b2", "me", None).unwrap();
        assert_eq!(
            skipped,
            vec!["secret/a.txt".to_string(), "secret/b.txt".to_string()],
            "keyless merge must surface every skipped protected path"
        );
        assert!(!root.join("secret/a.txt").exists());
        assert!(!root.join("secret/b.txt").exists());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_rejects_a_plaintext_secret_and_writes_nothing() {
        let root = tmp_root("scan-reject");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("clean.txt"), b"hello").unwrap();
        std::fs::write(root.join("creds.txt"), b"aws = AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let err = repo.commit("me", "leak").unwrap_err();
        assert!(matches!(err, Error::SecretDetected(_)), "got {err:?}");
        // Nothing committed: the branch is still unborn.
        assert_eq!(repo.head_tip().unwrap(), None);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn allowlisted_blob_hash_lets_commit_through() {
        let root = tmp_root("scan-allow");
        let repo = Repo::init(&root).unwrap();
        let secret = b"aws = AKIAIOSFODNN7EXAMPLE\n";
        std::fs::write(root.join("creds.txt"), secret).unwrap();
        // Compute the blob hash the scanner will object to.
        let id = scl_core::Object::blob(secret.to_vec()).id();
        std::fs::create_dir_all(&repo.layout().dot_sc).unwrap();
        std::fs::write(
            repo.layout().dot_sc.join("scanner-allowlist.toml"),
            format!("[[allow]]\nblob = \"{}\"\nnote = \"test fixture\"\n", id.to_hex()),
        )
        .unwrap();
        // Now the commit succeeds.
        let cid = repo.commit("me", "allowed").unwrap();
        assert!(repo.head_tip().unwrap() == Some(cid));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clean_tree_commits_normally() {
        let root = tmp_root("scan-clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"just some text\n").unwrap();
        assert!(repo.commit("me", "ok").is_ok());
        let rep = repo.scan_worktree().unwrap();
        assert!(rep.is_empty());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clone_copies_objects_refs_head_and_worktree() {
        let a = tmp_root("clone-src");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("README.md"), b"hello from A\n").unwrap();
            repo.commit("me", "first").unwrap();
            repo.branch("feature").unwrap();
        }
        let b = tmp_root("clone-dst");
        let _ = std::fs::remove_dir_all(&b); // clone_to inits it
        let cloned = Repo::clone_to(&a, &b).unwrap();
        // HEAD + branches copied
        assert!(cloned.head_tip().unwrap().is_some());
        let branches: Vec<String> =
            cloned.branches().unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(
            branches.contains(&"main".to_string()) && branches.contains(&"feature".to_string())
        );
        // working tree materialized
        assert_eq!(std::fs::read(b.join("README.md")).unwrap(), b"hello from A\n");
        // origin recorded
        assert_eq!(
            cloned.remotes().unwrap(),
            vec![("origin".to_string(), a.display().to_string())]
        );
        // origin/* remote-tracking refs seeded so merge/fetch resolve immediately
        assert_eq!(
            crate::refs::read_remote_tip(cloned.layout(), "origin", "main").unwrap(),
            cloned.head_tip().unwrap()
        );
        drop(cloned);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn clone_preserves_committed_secret_decryptable_only_with_key() {
        let a = tmp_root("clone-secret-src");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"x\n").unwrap();
            repo.commit("me", "base").unwrap();
            repo.secret_add("DB_URL", b"postgres://secret", &[alice_pk]).unwrap();
        }
        let b = tmp_root("clone-secret-dst");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();

        // The secret travelled: it's in the cloned registry...
        let list = brepo.secret_list().unwrap();
        assert!(list.iter().any(|s| s.name == "DB_URL"));
        // ...as ciphertext only an authorized key can read.
        let code_ok = brepo
            .run(
                &alice_sk,
                &["sh".into(), "-c".into(), "test \"$DB_URL\" = postgres://secret".into()],
            )
            .unwrap();
        assert_eq!(code_ok, 0, "alice's key decrypts the cloned secret");
        let code_denied = brepo
            .run(
                &mallory_sk,
                &["sh".into(), "-c".into(), "test -z \"$DB_URL\"".into()],
            )
            .unwrap();
        assert_eq!(code_denied, 0, "non-recipient sees no DB_URL (ciphertext stays sealed)");

        drop(brepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn fetch_updates_remote_tracking_then_merge_integrates() {
        let a = tmp_root("fetch-src");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"base\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("fetch-dst");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();

        // New commit on A.
        let a_tip = {
            let arepo = Repo::open(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"base\nA-change\n").unwrap();
            arepo.commit("me", "A change").unwrap()
        };

        // B fetches: remote-tracking ref advances, local branch does not.
        let updated = brepo.fetch("origin").unwrap();
        assert!(updated.iter().any(|(br, id)| br == "main" && *id == a_tip));
        assert_eq!(
            crate::refs::read_remote_tip(&brepo.layout, "origin", "main").unwrap(),
            Some(a_tip)
        );

        // Merge the fetched ref (fast-forward) and verify the file updated.
        brepo.merge("origin/main", "me").unwrap();
        assert_eq!(std::fs::read(b.join("f.txt")).unwrap(), b"base\nA-change\n");

        drop(brepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn merge_into_unborn_branch_adopts_theirs_wholesale() {
        // A freshly `init`ed repo has an unborn local branch (no commits yet).
        // Merging a branch into it (e.g. after fetching remote history) must
        // adopt that branch's tip directly rather than erroring `Unborn`.
        let a = tmp_root("unborn-merge-src");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"from-theirs\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("unborn-merge-dst");
        let _ = std::fs::remove_dir_all(&b);
        std::fs::create_dir_all(&b).unwrap();
        let unborn = Repo::init(&b).unwrap();
        unborn.remote_add("origin", a.to_str().unwrap()).unwrap();
        let fetched = unborn.fetch("origin").unwrap();
        assert!(fetched.iter().any(|(br, _)| br == "main"));
        assert_eq!(unborn.head_tip().unwrap(), None, "local branch is still unborn before merge");

        let merged = unborn.merge("origin/main", "me").unwrap();
        assert_eq!(std::fs::read(b.join("f.txt")).unwrap(), b"from-theirs\n");
        assert_eq!(unborn.head_tip().unwrap(), Some(merged));

        drop(unborn);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn push_fast_forward_advances_remote_and_rejects_non_ff() {
        let a = tmp_root("push-remote");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"base\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("push-local");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();

        // B commits and pushes (fast-forward).
        std::fs::write(b.join("f.txt"), b"base\nB-change\n").unwrap();
        let b_tip = brepo.commit("me", "B change").unwrap();
        let pushed = brepo.push("origin").unwrap();
        assert_eq!(pushed, b_tip);
        // A's main now points at B's tip and A has the objects.
        let arepo = Repo::open(&a).unwrap();
        assert_eq!(arepo.head_tip().unwrap(), Some(b_tip));

        // An immediate re-push is a no-op (already up to date) and still succeeds.
        assert_eq!(brepo.push("origin").unwrap(), b_tip);

        // A diverges; B's next push is non-ff.
        std::fs::write(a.join("f.txt"), b"base\nB-change\nA-diverge\n").unwrap();
        arepo.commit("me", "A diverge").unwrap();
        std::fs::write(b.join("f.txt"), b"base\nB-change\nB-again\n").unwrap();
        brepo.commit("me", "B again").unwrap();
        assert!(matches!(brepo.push("origin"), Err(Error::NonFastForward)));

        drop(brepo);
        drop(arepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn open_with_budget_bounds_the_store() {
        let dir = std::env::temp_dir().join(format!("sc-test-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            Repo::init(&dir).unwrap();
        } // drop → release lock
        let repo = Repo::open_with_budget(&dir, 4 * 1024 * 1024).unwrap();
        assert_eq!(repo.vfs().stats().budget_bytes, 4 * 1024 * 1024);
        drop(repo);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn commit_encrypts_files_under_a_protected_prefix() {
        let root = tmp_root("p7-commit");
        let repo = Repo::init(&root).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        // Seed a protected prefix via the test seam (Task 6 provides the real `protect`).
        repo.test_set_protected_prefix("secret/", &[pk]).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let cid = repo.commit("me", "add secret").unwrap();
        // The policy must have exactly one wrapped-DEK entry.
        let snap = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            s.get_snapshot(&cid).unwrap()
        };
        assert_eq!(snap.protection.wrapped.len(), 1, "one protected blob");
        // The stored blob bytes must be ciphertext (not the plaintext).
        let blob_id = *snap.protection.wrapped.keys().next().unwrap();
        let obj = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            s.get(&blob_id).unwrap()
        };
        if let scl_core::Object::Blob(b) = obj {
            assert_ne!(&b[..], b"hunter2", "blob must be ciphertext, not plaintext");
        } else {
            panic!("expected Blob object");
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unchanged_protected_file_keeps_stable_wrapped_dek_across_commits() {
        // Regression: `wrap_dek_for` randomizes its ephemeral key, so naively
        // re-wrapping every commit would change `protection.wrapped` (and the
        // snapshot encoding) even when the protected content is identical. The
        // prior wrap must be carried forward for an unchanged (blob, recipient).
        let root = tmp_root("p7-stable-wrap");
        let repo = Repo::init(&root).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.test_set_protected_prefix("secret/", &[pk]).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        std::fs::write(root.join("plain.txt"), b"v1").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let w1 = repo.snapshot(&c1).unwrap().protection.wrapped;

        // Change only the unrelated plaintext file; the protected file is untouched.
        std::fs::write(root.join("plain.txt"), b"v2").unwrap();
        let c2 = repo.commit("me", "touch plain").unwrap();
        let w2 = repo.snapshot(&c2).unwrap().protection.wrapped;

        assert_ne!(c1, c2, "the two commits are distinct");
        // Same blob id (convergent) AND byte-identical wrapped DEKs (carried forward).
        assert_eq!(w1, w2, "wrapped DEKs must be stable for unchanged protected content");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn protect_records_prefix_and_encrypts_matching_file() {
        let root = tmp_root("p7-protect");
        let repo = Repo::init(&root).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        // Commit unrelated history first so `protect` runs against an existing
        // tip (exercises the `Some(tip)` branch, not just the unborn case).
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        repo.commit("me", "base").unwrap();
        // Write a matching file first, then protect: it must be encrypted + wrapped.
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let cid = repo.protect("secret/", &[pk], None).unwrap();
        let snap = repo.snapshot(&cid).unwrap();
        // The prefix is recorded.
        assert!(snap.protection.prefixes.iter().any(|p| p.prefix == "secret/"));
        // Exactly one wrapped protected blob, and it is ciphertext.
        assert_eq!(snap.protection.wrapped.len(), 1, "one protected blob");
        let blob_id = *snap.protection.wrapped.keys().next().unwrap();
        let obj = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            s.get(&blob_id).unwrap()
        };
        match obj {
            scl_core::Object::Blob(b) => assert_ne!(&b[..], b"hunter2", "blob must be ciphertext"),
            _ => panic!("expected Blob"),
        }
        // The tree entry is PROTECTED.
        let entries = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap()
        };
        let (_id, _m, perms) = entries.get("secret/db.txt").copied().unwrap();
        assert_ne!(perms & scl_core::PROTECTED, 0, "db.txt must be PROTECTED");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_adds_recipient_without_changing_file_objects() {
        let root = tmp_root("p7-grant");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let root1 = repo.snapshot(&c1).unwrap().root;
        let c2 = repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        let snap2 = repo.snapshot(&c2).unwrap();
        assert_eq!(snap2.root, root1, "grant must not change the file tree");
        // bob now has a wrapped DEK for the protected blob.
        let any = snap2.protection.wrapped.values().next().unwrap();
        assert_eq!(any.len(), 2, "alice + bob");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn protect_grant_and_revoke_append_oplog_records() {
        let root = tmp_root("oplog-protect");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();

        // `protect` logs its own policy-only record ("protect <prefix>") and
        // then always runs a follow-up `commit` ("commit: encrypt under
        // <prefix>") to sweep matching working-tree files — two ref moves,
        // two records, oldest first.
        let head = crate::refs::current_branch(repo.layout()).unwrap();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        let all = crate::oplog::read_all(repo.layout()).unwrap();
        assert_eq!(all.len(), 2, "protect must log two records: policy + sweep commit");
        let rec = &all[all.len() - 2];
        assert_eq!(rec.desc, "protect secret/");
        assert_eq!(rec.head_before, head);
        assert_eq!(rec.head_after, head);
        assert_eq!(rec.refs.len(), 1);
        assert_eq!(rec.refs[0].0, head);
        let commit_rec = all.last().unwrap();
        assert_eq!(commit_rec.desc, "commit: encrypt under secret/");
        let after_protect = repo.head_tip().unwrap();

        // grant.
        let c2 = repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        let rec2 = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(rec2.desc, "grant secret/");
        assert_eq!(rec2.refs, vec![(head.clone(), after_protect, Some(c2))]);

        // revoke (bob was just granted, so revoking alice still leaves a recipient).
        let recipient = alice_sk.public().recipient_id();
        let c3 = repo.revoke("secret/", &recipient).unwrap();
        let rec3 = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(rec3.desc, "revoke secret/");
        assert_eq!(rec3.refs, vec![(head.clone(), Some(c2), Some(c3))]);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_on_unprotected_prefix_errors_not_protected() {
        let root = tmp_root("p7-grant-noprefix");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, _alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();
        let err = repo.grant("nope/", &alice_sk, &bob_pk).unwrap_err();
        assert!(matches!(err, Error::NotProtected(_)), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_with_non_recipient_identity_errors_not_authorized() {
        let root = tmp_root("p7-grant-unauth");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        // mallory is not a recipient → cannot recover the DEK to grant.
        let err = repo.grant("secret/", &mallory_sk, &bob_pk).unwrap_err();
        assert!(matches!(err, Error::NotAuthorized(_)), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn grant_surfaces_tampered_wrap_as_crypto_error_not_unauthorized() {
        // A wrap addressed to the authorized identity that fails to decrypt
        // (tampered) must surface as a hard crypto error, not be misclassified
        // as NotAuthorized.
        let root = tmp_root("p7-grant-tamper");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let snap = repo.snapshot(&c1).unwrap();

        // Tamper alice's wrap bytes (recipient id intact) and commit it forward.
        let mut protection = snap.protection;
        for wks in protection.wrapped.values_mut() {
            for w in wks.iter_mut() {
                let n = w.wrapped_dek.len();
                w.wrapped_dek[n - 1] ^= 0xFF;
            }
        }
        repo.commit_snapshot(snap.root, vec![c1], snap.secrets, protection, "test", "tamper")
            .unwrap();

        let err = repo.grant("secret/", &alice_sk, &bob_pk).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "tamper must be a crypto error, got {err:?}");
        assert!(!matches!(err, Error::NotAuthorized(_)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn revoke_removes_wrapped_entries_and_prefix_membership() {
        let root = tmp_root("p7-revoke");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add").unwrap();
        let root1 = repo.snapshot(&c1).unwrap().root;
        // Grant bob, then revoke him.
        let c2 = repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        assert_eq!(repo.snapshot(&c2).unwrap().protection.wrapped.values().next().unwrap().len(), 2);
        let bob_id = bob_pk.recipient_id();
        let c3 = repo.revoke("secret/", &bob_id).unwrap();
        let snap3 = repo.snapshot(&c3).unwrap();
        // Root tree unchanged (policy-only).
        assert_eq!(snap3.root, root1, "revoke must not change the file tree");
        // bob's wrap is gone; only alice remains.
        let wks = snap3.protection.wrapped.values().next().unwrap();
        assert_eq!(wks.len(), 1, "only alice remains");
        assert!(!wks.iter().any(|w| w.recipient_id == bob_id.as_str()));
        // bob is no longer in the prefix rule's EFFECTIVE (granted) set, but the
        // rule retains him as a durable `Revoked` tombstone (ADR-0026) — that
        // tombstone is what keeps the revoke durable against merging a
        // pre-revoke branch.
        let rule = snap3.protection.prefixes.iter().find(|p| p.prefix == "secret/").unwrap();
        assert!(!rule.granted_keys().iter().any(|pk| {
            scl_crypto::PublicKey::from_bytes(*pk).recipient_id() == bob_id
        }));
        let bob_entry = rule
            .recipients
            .iter()
            .find(|e| scl_crypto::PublicKey::from_bytes(e.key).recipient_id() == bob_id)
            .expect("bob's tombstone must remain in the rule");
        assert_eq!(bob_entry.state, scl_core::RecipientState::Revoked);
        // protected_prefixes reflects the surviving recipient and bob's revoked standing.
        let listed = repo.protected_prefixes().unwrap();
        let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
        let alice_r = recips.iter().find(|r| r.id == alice_pk.recipient_id()).unwrap();
        assert!(alice_r.granted);
        let bob_r = recips.iter().find(|r| r.id == bob_id).unwrap();
        assert!(!bob_r.granted);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn protect_again_preserves_tombstone() {
        // Regression: re-protecting an already-protected prefix must never
        // rebuild the rule wholesale — that would silently drop a revoked
        // recipient's tombstone (ADR-0026).
        let root = tmp_root("p16-protect-again-preserves-tombstone");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        let bob_id = bob_pk.recipient_id();
        repo.revoke("secret/", &bob_id).unwrap();
        // Re-protect the same prefix for alice again.
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        let listed = repo.protected_prefixes().unwrap();
        let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
        let alice_r = recips.iter().find(|r| r.id == alice_pk.recipient_id()).unwrap();
        assert!(alice_r.granted, "alice must remain granted after re-protect");
        let bob_r = recips.iter().find(|r| r.id == bob_id).unwrap();
        assert!(!bob_r.granted, "bob's tombstone must survive re-protect");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn revoke_last_granted_refused_despite_existing_tombstone() {
        // Regression: the empty-recipient-set guard on revoke must test the
        // EFFECTIVE (granted) set, not raw entry count — a rule with a
        // tombstoned entry plus one granted recipient still has only one
        // effective recipient, and revoking them must be refused.
        let root = tmp_root("p16-revoke-last-granted-despite-tombstone");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        let bob_id = bob_pk.recipient_id();
        repo.revoke("secret/", &bob_id).unwrap();
        // Now only alice is effectively granted (bob is tombstoned). Revoking
        // alice would leave the prefix readable by nobody.
        let alice_id = alice_pk.recipient_id();
        let err = repo.revoke("secret/", &alice_id).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn revoke_survives_merging_a_pre_revoke_branch() {
        // The ADR-0025 boundary scenario, now closed by ADR-0026.
        let root = tmp_root("p16-durable-revoke");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add secret").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap();

        // Fork a branch while bob is still granted, and give it its own commit.
        repo.branch("pre-revoke").unwrap();
        repo.switch("pre-revoke").unwrap();
        std::fs::write(root.join("readme.txt"), b"feature work").unwrap();
        repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();

        // Revoke bob on main, then merge the pre-revoke branch.
        repo.revoke("secret/", &bob_pk.recipient_id()).unwrap();
        repo.merge("pre-revoke", "me").unwrap();

        // Bob stays revoked: tombstone won the register.
        let listed = repo.protected_prefixes().unwrap();
        let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
        let bob = recips.iter().find(|r| r.id == bob_pk.recipient_id()).unwrap();
        assert!(!bob.granted, "merge resurrected a revoked recipient");
        assert!(recips.iter().find(|r| r.id == alice_pk.recipient_id()).unwrap().granted);

        // And a FRESH file under the prefix seals to alice only.
        let before: std::collections::BTreeSet<_> = {
            let tip = repo.head_tip().unwrap().unwrap();
            repo.snapshot(&tip).unwrap().protection.wrapped.keys().cloned().collect()
        };
        std::fs::write(root.join("secret/new.txt"), b"fresh").unwrap();
        let c = repo.commit("me", "post-revoke secret").unwrap();
        let prot = repo.snapshot(&c).unwrap().protection;
        let new_ids: Vec<_> = prot.wrapped.keys().filter(|k| !before.contains(k)).collect();
        assert!(!new_ids.is_empty(), "expected a freshly sealed blob");
        let bob_id = bob_pk.recipient_id();
        for id in new_ids {
            let wks = &prot.wrapped[id];
            assert!(
                !wks.iter().any(|w| w.recipient_id == bob_id.as_str()),
                "fresh DEK sealed to a revoked recipient"
            );
            assert_eq!(wks.len(), 1, "fresh blob must be wrapped for alice only");
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn regrant_after_revoke_wins_against_old_tombstone_branch() {
        let root = tmp_root("p16-regrant");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap(); // bob@2:Granted
        repo.revoke("secret/", &bob_pk.recipient_id()).unwrap(); // bob@3:Revoked

        // Branch carries the tombstone; main deliberately re-grants (bob@4).
        repo.branch("tombstoned").unwrap();
        repo.switch("tombstoned").unwrap();
        std::fs::write(root.join("readme.txt"), b"work").unwrap();
        repo.commit("me", "work").unwrap();
        repo.switch("main").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        repo.merge("tombstoned", "me").unwrap();

        let listed = repo.protected_prefixes().unwrap();
        let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
        assert!(
            recips.iter().find(|r| r.id == bob_pk.recipient_id()).unwrap().granted,
            "a deliberate re-grant must out-epoch the old tombstone"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cherry_pick_of_pre_revoke_commit_does_not_resurrect_recipient() {
        let root = tmp_root("p16-replay-revoke");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap();

        // A branch commit made while bob was granted…
        repo.branch("work").unwrap();
        repo.switch("work").unwrap();
        std::fs::write(root.join("notes.txt"), b"pickme").unwrap();
        repo.commit("me", "pickable").unwrap();
        repo.switch("main").unwrap();

        // …revoke bob on main, then replay that commit onto main.
        repo.revoke("secret/", &bob_pk.recipient_id()).unwrap();
        repo.cherry_pick("work", "me", None, None).unwrap();

        let listed = repo.protected_prefixes().unwrap();
        let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
        assert!(
            !recips.iter().find(|r| r.id == bob_pk.recipient_id()).unwrap().granted,
            "replay resurrected a revoked recipient"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_carries_forward_absent_protected_files_for_non_recipient() {
        // Regression: a non-recipient checks out (protected file skipped/absent),
        // then commits something unrelated. The absent protected file and its
        // wrapped DEKs must SURVIVE — a non-recipient must not silently destroy
        // ciphertext they cannot read.
        let root = tmp_root("p7-carry-forward");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();

        // Seed the prefix on a commit, branch "other" BEFORE the protected file
        // exists so switching there (then back as mallory) leaves it absent.
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        repo.branch("other").unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        let c1 = repo.commit("me", "add secret").unwrap();

        // Capture c1's protected blob id + alice's wrap count.
        let snap1 = repo.snapshot(&c1).unwrap();
        let blob1 = {
            let entries = {
                let a = repo.vfs_handle().store();
                let mut s = a.lock().unwrap();
                worktree::tree_file_entries_with_perms(&mut s, snap1.root).unwrap()
            };
            let (id, _mode, perms) = entries.get("secret/db.txt").copied().unwrap();
            assert_ne!(perms & scl_core::PROTECTED, 0, "db.txt must be PROTECTED in c1");
            id
        };
        assert_eq!(snap1.protection.wrapped.get(&blob1).map(|w| w.len()), Some(1));

        // As mallory: switch away (deletes db.txt) then back (skipped, absent).
        repo.switch_with_identity("other", Some(&mallory_sk)).unwrap();
        let skipped = repo.switch_with_identity("main", Some(&mallory_sk)).unwrap();
        assert!(skipped.contains(&"secret/db.txt".to_string()));
        assert!(!root.join("secret/db.txt").exists(), "protected file absent for mallory");

        // Mallory commits an UNRELATED file.
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        let c2 = repo.commit("mallory", "unrelated").unwrap();

        // The protected ciphertext + its wrap survived mallory's commit.
        let snap2 = repo.snapshot(&c2).unwrap();
        assert_eq!(
            snap2.protection.wrapped.get(&blob1).map(|w| w.len()),
            Some(1),
            "alice's wrapped DEK must survive a non-recipient commit"
        );
        let entries2 = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap2.root).unwrap()
        };
        let (id2, _m, perms2) = entries2.get("secret/db.txt").copied().expect("db.txt still in tree");
        assert_ne!(perms2 & scl_core::PROTECTED, 0, "db.txt must still be PROTECTED");
        assert_eq!(id2, blob1, "same ciphertext blob carried forward unchanged");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_carries_out_of_sparse_absent_path_verbatim() {
        // P24 Task 2: an absent path outside the sparse set is carried
        // forward byte-identical, exactly like an absent still-protected
        // path — simulated here by writing the spec directly and deleting
        // the out-of-sparse file (Task 3's materialize filtering doesn't
        // exist yet, so nothing does this automatically today).
        let root = tmp_root("sparse-carry-out");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v1").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"b v1").unwrap();
        let c1 = repo.commit("me", "base").unwrap();

        // Capture docs/b.txt's blob id and perms from the base commit.
        let snap1 = repo.snapshot(&c1).unwrap();
        let blob1_base = {
            let entries = {
                let a = repo.vfs_handle().store();
                let mut s = a.lock().unwrap();
                worktree::tree_file_entries_with_perms(&mut s, snap1.root).unwrap()
            };
            let (id, _mode, perms) = entries.get("docs/b.txt").copied().unwrap();
            assert_eq!(perms & scl_core::PROTECTED, 0, "docs/b.txt must be plain (PROTECTED) in base");
            id
        };

        crate::sparse::store(repo.layout(), &crate::sparse::Sparse::new(vec!["src/".into()]))
            .unwrap();
        std::fs::remove_file(root.join("docs/b.txt")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v2").unwrap();
        let c2 = repo.commit("me", "edit in-sparse").unwrap();

        let snap2 = repo.snapshot(&c2).unwrap();
        let entries = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap2.root).unwrap()
        };
        assert!(entries.contains_key("docs/b.txt"), "out-of-sparse absent path must be carried");
        let (blob1_carried, _mode, perms_carried) = entries.get("docs/b.txt").copied().unwrap();
        assert_eq!(blob1_carried, blob1_base, "carried blob id must match base commit byte-identically");
        assert_eq!(perms_carried & scl_core::PROTECTED, 0, "carried plain file must not acquire PROTECTED");
        let a_bytes = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            match s.get(&entries["src/a.txt"].0).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected blob"),
            }
        };
        assert_eq!(a_bytes, b"a v2", "in-sparse edit must land");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_treats_in_sparse_absent_path_as_deletion() {
        // Absence INSIDE the sparse set is a genuine deletion — the widening
        // must not carry paths the sparse spec says should be materialized.
        let root = tmp_root("sparse-carry-in-del");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v1").unwrap();
        repo.commit("me", "base").unwrap();

        crate::sparse::store(repo.layout(), &crate::sparse::Sparse::new(vec!["src/".into()]))
            .unwrap();
        std::fs::remove_file(root.join("src/a.txt")).unwrap();
        let c2 = repo.commit("me", "delete in-sparse file").unwrap();

        let snap2 = repo.snapshot(&c2).unwrap();
        let entries = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap2.root).unwrap()
        };
        assert!(!entries.contains_key("src/a.txt"), "in-sparse absence must be a real deletion");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn carry_composes_protected_and_sparse() {
        // Both carry reasons compose independently: a protected path outside
        // the sparse set, absent for a non-recipient, is carried (both
        // reasons apply); a protected path INSIDE the sparse set, absent for
        // a non-recipient, is still carried (protected reason alone, P15
        // behavior unchanged by this widening).
        let root = tmp_root("sparse-carry-compose");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();

        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        repo.branch("other").unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        std::fs::write(root.join("secret/in_sparse.txt"), b"hunter3").unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v1").unwrap();
        let c1 = repo.commit("me", "add secrets").unwrap();

        let snap1 = repo.snapshot(&c1).unwrap();
        let (blob_out, blob_in) = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut s, snap1.root).unwrap();
            (entries["secret/db.txt"].0, entries["secret/in_sparse.txt"].0)
        };

        // Sparse set covers `src/` and `secret/in_sparse.txt` only —
        // `secret/db.txt` is outside the sparse set.
        crate::sparse::store(
            repo.layout(),
            &crate::sparse::Sparse::new(vec!["src/".into(), "secret/in_sparse.txt".into()]),
        )
        .unwrap();

        // As mallory (non-recipient): switch away and back so both protected
        // files are skipped/absent, then commit something unrelated.
        repo.switch_with_identity("other", Some(&mallory_sk)).unwrap();
        repo.switch_with_identity("main", Some(&mallory_sk)).unwrap();
        assert!(!root.join("secret/db.txt").exists());
        assert!(!root.join("secret/in_sparse.txt").exists());
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        let c2 = repo.commit("mallory", "unrelated").unwrap();

        let snap2 = repo.snapshot(&c2).unwrap();
        let entries2 = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap2.root).unwrap()
        };
        assert_eq!(
            entries2.get("secret/db.txt").map(|(id, _, _)| *id),
            Some(blob_out),
            "protected + out-of-sparse must carry"
        );
        assert_eq!(
            entries2.get("secret/in_sparse.txt").map(|(id, _, _)| *id),
            Some(blob_in),
            "protected + in-sparse must still carry (P15 behavior unchanged)"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn no_sparse_spec_behaves_exactly_as_before() {
        // Regression guard: with no sparse spec (the full-checkout default),
        // deleting a plain tracked file is a genuine deletion — the widening
        // must be a total no-op when sparse is off.
        let root = tmp_root("sparse-carry-noop");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"a v1").unwrap();
        std::fs::write(root.join("b.txt"), b"b v1").unwrap();
        repo.commit("me", "base").unwrap();

        std::fs::remove_file(root.join("b.txt")).unwrap();
        let c2 = repo.commit("me", "delete b").unwrap();

        let snap2 = repo.snapshot(&c2).unwrap();
        let entries = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap2.root).unwrap()
        };
        assert!(!entries.contains_key("b.txt"), "deletion with no sparse spec must not be carried");
        assert!(entries.contains_key("a.txt"));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_clean_out_of_sparse_change_lands() {
        // P24 Task 4: a CLEAN merge touching only an out-of-sparse path never
        // materializes it (resolves on tree ids, P15's fast path) but still
        // lands the change in the CAS/snapshot.
        let root = tmp_root("sparse-clean-merge");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v1").unwrap();
        std::fs::write(root.join("docs/x"), b"doc v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        repo.set_sparse(&["src/".into()], None).unwrap();
        assert!(!root.join("docs/x").exists(), "docs/x must not be materialized once sparse");

        repo.switch("feature").unwrap();
        std::fs::write(root.join("docs/x"), b"doc v2").unwrap();
        repo.commit("me", "edit docs/x on feature").unwrap();
        repo.switch("main").unwrap();

        let (id, _skipped) = repo.merge_with_identity("feature", "me", None).unwrap();
        assert!(
            !root.join("docs/x").exists(),
            "clean out-of-sparse merge must not materialize the file"
        );
        let snap = repo.snapshot(&id).unwrap();
        let entries = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            worktree::tree_file_entries_with_perms(&mut s, snap.root).unwrap()
        };
        let blob = entries.get("docs/x").map(|(id, _, _)| *id).unwrap();
        let bytes = {
            let a = repo.vfs_handle().store();
            let mut s = a.lock().unwrap();
            match s.get(&blob).unwrap() {
                scl_core::Object::Blob(b) => b,
                _ => panic!("expected blob"),
            }
        };
        assert_eq!(&*bytes, b"doc v2", "merged content must land in the CAS");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_conflict_out_of_sparse_reports_widen_hint() {
        // P24 Task 4: a CONFLICTED merge on an out-of-sparse path must not
        // write markers to disk — it refuses up front with a widen hint.
        let root = tmp_root("sparse-conflict-merge");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a v1").unwrap();
        std::fs::write(root.join("docs/x"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("docs/x"), b"ours\n").unwrap();
        repo.commit("me", "ours edits docs/x").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("docs/x"), b"theirs\n").unwrap();
        repo.commit("me", "theirs edits docs/x").unwrap();
        repo.switch("main").unwrap();

        repo.set_sparse(&["src/".into()], None).unwrap();
        assert!(!root.join("docs/x").exists());

        let err = repo.merge_with_identity("feature", "me", None).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => {
                assert!(msg.contains("docs/x"), "message must name the path: {msg}");
                assert!(
                    msg.contains("sc sparse set"),
                    "message must suggest widening the sparse set: {msg}"
                );
            }
            other => panic!("expected InvalidArgument widen hint, got {other:?}"),
        }
        assert!(!root.join("docs/x").exists(), "no marker may land outside the sparse view");
        assert!(!repo.merge_in_progress(), "the refused merge must not start an in-progress merge");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn push_creates_a_new_remote_branch() {
        let a = tmp_root("push-newbr-remote");
        {
            let repo = Repo::init(&a).unwrap();
            std::fs::write(a.join("f.txt"), b"x\n").unwrap();
            repo.commit("me", "base").unwrap();
        }
        let b = tmp_root("push-newbr-local");
        let _ = std::fs::remove_dir_all(&b);
        let brepo = Repo::clone_to(&a, &b).unwrap();
        brepo.branch("feature").unwrap();
        brepo.switch("feature").unwrap();
        std::fs::write(b.join("g.txt"), b"feat\n").unwrap();
        let tip = brepo.commit("me", "feature").unwrap();
        brepo.push("origin").unwrap();
        let arepo = Repo::open(&a).unwrap();
        assert_eq!(crate::refs::read_branch_tip(arepo.layout(), "feature").unwrap(), Some(tip));
        drop(brepo);
        drop(arepo);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn authorized_checkout_decrypts_unauthorized_skips() {
        // Setup: init repo, generate alice + mallory key pairs.
        let root = tmp_root("p7-checkout");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();

        // Seed the protection prefix via the test seam (Task 6 will provide
        // the real `protect` API). Branch "other" at this policy-only commit so
        // it has no protected files — switching to it will delete secret/db.txt
        // from the working tree and switching back as mallory will skip writing it.
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        repo.branch("other").unwrap();

        // Add the protected file and commit on "main": it is encrypted for alice.
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();

        // Switch away (deletes working-tree secret/db.txt) then back as alice → decrypts.
        repo.switch_with_identity("other", Some(&alice_sk)).unwrap();
        assert!(!root.join("secret/db.txt").exists(), "switch to other must clear the protected file");
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        assert_eq!(
            std::fs::read(root.join("secret/db.txt")).unwrap(),
            b"hunter2",
            "alice's key must decrypt the protected file on switch back to main"
        );

        // Switch away again (clears file), then back as mallory → skipped (file absent).
        repo.switch_with_identity("other", Some(&mallory_sk)).unwrap();
        let skipped = repo.switch_with_identity("main", Some(&mallory_sk)).unwrap();
        assert!(
            skipped.contains(&"secret/db.txt".to_string()),
            "mallory's switch must report secret/db.txt as skipped"
        );
        assert!(
            !root.join("secret/db.txt").exists(),
            "unauthorized switch must not write the protected file"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn status_clean_for_decrypted_protected_file() {
        // A decrypted protected file on disk must read as CLEAN: status compares
        // the convergent re-encryption of the disk bytes to the stored ciphertext.
        let root = tmp_root("p7-status-clean");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        // The working file is plaintext while HEAD holds ciphertext, yet status
        // must report no changes (no spurious modified/deleted/added).
        let s = repo.status().unwrap();
        assert!(s.modified.is_empty(), "decrypted protected file must not show as modified: {s:?}");
        assert!(s.deleted.is_empty(), "protected file present on disk must not show as deleted: {s:?}");
        assert!(s.added.is_empty(), "{s:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switch_refuses_genuine_edit_to_protected_file() {
        // A real edit to a decrypted protected file must BLOCK the switch (no
        // silent data loss) and the edit must be preserved.
        let root = tmp_root("p7-switch-edit");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.test_set_protected_prefix("secret/", &[alice_pk]).unwrap();
        repo.branch("other").unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        // Genuinely edit the protected file (still plaintext on disk).
        std::fs::write(root.join("secret/db.txt"), b"edited-secret").unwrap();
        // status must report it modified (convergent re-encryption differs).
        assert!(repo.status().unwrap().modified.contains(&"secret/db.txt".to_string()));
        // switch must refuse and preserve the edit.
        let err = repo.switch("other").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(root.join("secret/db.txt")).unwrap(),
            b"edited-secret",
            "the uncommitted edit to the protected file must be preserved"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switching_to_protected_branch_removes_stale_plaintext_for_non_recipient() {
        // A path that is plaintext on branch A and protected on branch B must be
        // ABSENT (not the stale A plaintext) after a non-recipient switches A->B.
        let root = tmp_root("p7-stale-plaintext");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();

        // Branch A (main): data/x.txt as plaintext.
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::write(root.join("data/x.txt"), b"plaintext-A").unwrap();
        repo.commit("me", "plaintext on A").unwrap();

        // Branch B: same path, but data/ is protected -> committed as ciphertext.
        repo.branch("b").unwrap();
        repo.switch("b").unwrap();
        repo.test_set_protected_prefix("data/", &[alice_pk]).unwrap();
        repo.commit("me", "encrypt on B").unwrap();

        // Back on A: the working file is plaintext again.
        repo.switch("main").unwrap();
        assert_eq!(std::fs::read(root.join("data/x.txt")).unwrap(), b"plaintext-A");

        // Switch A->B as mallory (non-recipient): the file is skipped AND the
        // stale plaintext must be removed (confidentiality).
        let skipped = repo.switch_with_identity("b", Some(&mallory_sk)).unwrap();
        assert!(skipped.contains(&"data/x.txt".to_string()), "mallory must skip the protected file");
        assert!(
            !root.join("data/x.txt").exists(),
            "stale A plaintext must be removed when the path becomes protected for a non-recipient"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn push_then_clone_via_pack_roundtrips_history() {
        let origin = std::env::temp_dir().join(format!("scl-bulk-origin-{}", std::process::id()));
        let work = std::env::temp_dir().join(format!("scl-bulk-work-{}", std::process::id()));
        let clone = std::env::temp_dir().join(format!("scl-bulk-clone-{}", std::process::id()));
        for p in [&origin, &work, &clone] { let _ = std::fs::remove_dir_all(p); }

        // origin is an empty remote; work pushes two commits to it.
        Repo::init(&origin).unwrap();
        let w = Repo::init(&work).unwrap();
        w.remote_add("origin", &origin.display().to_string()).unwrap();
        std::fs::write(work.join("a.txt"), b"one").unwrap();
        w.commit("t", "c1").unwrap();
        std::fs::write(work.join("a.txt"), b"two").unwrap();
        let tip = w.commit("t", "c2").unwrap();
        w.push("origin").unwrap();

        // Clone the origin elsewhere; HEAD tip + its objects must be present.
        let c = Repo::clone_to(&origin, &clone).unwrap();
        assert_eq!(c.head_tip().unwrap(), Some(tip));

        for p in [&origin, &work, &clone] { std::fs::remove_dir_all(p).unwrap(); }
    }

    #[test]
    fn merge_and_switch_refuse_while_merge_in_progress() {
        let root = tmp_root("guard-in-progress");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        // Trigger a conflict so a merge is in progress.
        let _ = repo.merge("feature", "me").unwrap_err();
        assert!(repo.merge_in_progress());
        // Both `merge` and `switch` must refuse mid-merge.
        assert!(matches!(repo.merge("feature", "me"), Err(Error::MergeInProgress)));
        assert!(matches!(repo.switch("feature"), Err(Error::MergeInProgress)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_clears_pick_state_and_is_single_parent() {
        let root = tmp_root("pick-commit");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let base = repo.commit("me", "base").unwrap();

        // Simulate a cherry-pick in progress: a REAL commit is being picked —
        // completion reads the picked commit's protection rules (P15 Task 7),
        // so a synthetic id would (rightly) fail the completing commit.
        // Conflict markers (none, here) are on disk.
        let picked = base;
        crate::pick_state::write(&repo.layout, &picked, &[], None, None).unwrap();
        assert!(repo.pick_in_progress());
        assert_eq!(repo.pick_head().unwrap(), Some(picked));

        std::fs::write(root.join("a.txt"), b"two").unwrap();
        let id = repo.commit("me", "picked change").unwrap();

        // Pick state is cleared, and unlike a merge commit, this stays
        // single-parent — pick state is provenance + a guard only.
        assert!(!repo.pick_in_progress());
        assert_eq!(repo.pick_head().unwrap(), None);
        let store_arc = repo.vfs.store();
        let snap = store_arc.lock().unwrap().get_snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![base]);

        let log = repo.oplog().unwrap();
        assert!(
            log.last().unwrap().desc.starts_with("commit (pick):"),
            "expected pick-labeled oplog entry, got {:?}",
            log.last()
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn merge_switch_and_undo_refuse_during_pick() {
        let root = tmp_root("pick-guards");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        let picked = ObjectId::of(b"some-picked-commit");
        crate::pick_state::write(&repo.layout, &picked, &[], None, None).unwrap();
        assert!(repo.pick_in_progress());

        assert!(matches!(repo.merge("feature", "me"), Err(Error::PickInProgress)));
        assert!(matches!(repo.switch("feature"), Err(Error::PickInProgress)));
        assert!(matches!(repo.undo(), Err(Error::PickInProgress)));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn commit_merge_pick_rebase_and_rewrap_refuse_during_rebase() {
        // P19 Task 1: no other ref-moving or cutover operation may proceed
        // while a rebase is stopped mid-fold — `sc rebase --continue` (Task
        // 2) or `sc rebase --abort` are the only ways forward.
        let root = tmp_root("rebase-guards");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();

        let st = crate::rebase_state::RebaseState {
            branch: "main".into(),
            original_tip: ObjectId::of(b"orig"),
            target: "feature".into(),
            acc_tip: ObjectId::of(b"acc"),
            conflicted: ObjectId::of(b"conflicted"),
            remaining: vec![],
            total: 2,
            author: "me".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        };
        crate::rebase_state::write(&repo.layout, &st).unwrap();
        assert!(repo.rebase_in_progress());

        assert!(matches!(repo.commit("me", "should refuse"), Err(Error::RebaseInProgress)));
        assert!(matches!(repo.merge("feature", "me"), Err(Error::RebaseInProgress)));
        assert!(matches!(repo.cherry_pick("feature", "me", None, None), Err(Error::RebaseInProgress)));
        assert!(matches!(repo.rebase("feature", "me", None), Err(Error::RebaseInProgress)));
        assert!(matches!(
            repo.rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false),
            Err(Error::RebaseInProgress)
        ));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switch_refused_during_stopped_rebase() {
        // P19 final-review C1: `switch` was missing the rebase guard that
        // `merge`/`pick` already have — probe P1 proved a stopped rebase's
        // resolution could be silently discarded by switching branches and
        // then completing the rebase against the other branch's tree.
        let root = tmp_root("rebase-guard-switch");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        let before_tip = refs::read_branch_tip(&repo.layout, "main").unwrap();

        let st = crate::rebase_state::RebaseState {
            branch: "main".into(),
            original_tip: ObjectId::of(b"orig"),
            target: "feature".into(),
            acc_tip: ObjectId::of(b"acc"),
            conflicted: ObjectId::of(b"conflicted"),
            remaining: vec![],
            total: 2,
            author: "me".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        };
        crate::rebase_state::write(&repo.layout, &st).unwrap();
        assert!(repo.rebase_in_progress());

        assert!(matches!(repo.switch("feature"), Err(Error::RebaseInProgress)));

        // Branch ref and current branch untouched; rebase state still present.
        assert_eq!(refs::current_branch(&repo.layout).unwrap(), "main");
        assert_eq!(refs::read_branch_tip(&repo.layout, "main").unwrap(), before_tip);
        assert!(repo.rebase_in_progress());
        let reread = crate::rebase_state::read(&repo.layout).unwrap().unwrap();
        assert_eq!(reread.original_tip, st.original_tip);
        assert_eq!(reread.acc_tip, st.acc_tip);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn undo_refused_during_stopped_rebase() {
        // P19 final-review C1: `undo` was missing the rebase guard — probe P2
        // proved a stopped rebase's resolution could be undone and then
        // `--continue` would force-write over the undo, discarding it and
        // desyncing the oplog's recorded `before` state from reality.
        let root = tmp_root("rebase-guard-undo");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        let before_tip = refs::read_branch_tip(&repo.layout, "main").unwrap();

        let st = crate::rebase_state::RebaseState {
            branch: "main".into(),
            original_tip: ObjectId::of(b"orig"),
            target: "feature".into(),
            acc_tip: ObjectId::of(b"acc"),
            conflicted: ObjectId::of(b"conflicted"),
            remaining: vec![],
            total: 2,
            author: "me".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        };
        crate::rebase_state::write(&repo.layout, &st).unwrap();
        assert!(repo.rebase_in_progress());

        assert!(matches!(repo.undo(), Err(Error::RebaseInProgress)));

        // Branch ref untouched; rebase state still present.
        assert_eq!(refs::read_branch_tip(&repo.layout, "main").unwrap(), before_tip);
        assert!(repo.rebase_in_progress());
        let reread = crate::rebase_state::read(&repo.layout).unwrap().unwrap();
        assert_eq!(reread.original_tip, st.original_tip);
        assert_eq!(reread.acc_tip, st.acc_tip);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn policy_ops_refused_during_in_progress_states() {
        // P21 Task 1: `protect`/`grant`/`revoke` (path-protection) and
        // `secret_add`/`secret_rotate` are policy-only ref-moving ops with no
        // in-progress guard of their own — the same P19-I1 hazard class as
        // the unguarded `switch`/`undo` findings, just on a different set of
        // callers. Each must refuse up front, before any work, while a
        // merge/pick/rebase is stopped mid-fold.
        let root = tmp_root("policy-guards");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();

        // Every op needs a real prefix/secret to exist so the guard is what's
        // actually hit, not an earlier `NotProtected`/`NoSuchSecret` error.
        repo.protect("vault/", std::slice::from_ref(&alice_pk), None).unwrap();
        repo.secret_add("K", b"v", std::slice::from_ref(&alice_pk)).unwrap();
        let recipient = alice_pk.recipient_id();

        // (state name, setup fn, teardown fn) — each policy op is exercised
        // against all three, asserting the exact typed error per state.
        let states: [(&str, fn(&Layout), fn(&Layout)); 3] = [
            ("merge", |layout| {
                crate::merge_state::write(layout, &ObjectId::of(b"theirs"), &[], None).unwrap();
            }, |layout| crate::merge_state::clear(layout).unwrap()),
            ("pick", |layout| {
                crate::pick_state::write(layout, &ObjectId::of(b"picked"), &[], None, None).unwrap();
            }, |layout| crate::pick_state::clear(layout).unwrap()),
            ("rebase", |layout| {
                crate::rebase_state::write(
                    layout,
                    &crate::rebase_state::RebaseState {
                        branch: "main".into(),
                        original_tip: ObjectId::of(b"orig"),
                        target: "feature".into(),
                        acc_tip: ObjectId::of(b"acc"),
                        conflicted: ObjectId::of(b"conflicted"),
                        remaining: vec![],
                        total: 1,
                        author: "me".into(),
                        resolved: false,
                        replayed: 0,
                        skipped: 0,
                    },
                )
                .unwrap();
            }, |layout| crate::rebase_state::clear(layout).unwrap()),
        ];

        for (state_name, write_state, clear_state) in states {
            write_state(&repo.layout);

            macro_rules! assert_refused {
                ($result:expr, $op:literal) => {
                    let err = $result.unwrap_err();
                    match state_name {
                        "merge" => assert!(
                            matches!(err, Error::MergeInProgress),
                            "{} must refuse with MergeInProgress during merge, got {err:?}",
                            $op
                        ),
                        "pick" => assert!(
                            matches!(err, Error::PickInProgress),
                            "{} must refuse with PickInProgress during pick, got {err:?}",
                            $op
                        ),
                        "rebase" => assert!(
                            matches!(err, Error::RebaseInProgress),
                            "{} must refuse with RebaseInProgress during rebase, got {err:?}",
                            $op
                        ),
                        _ => unreachable!(),
                    }
                };
            }

            assert_refused!(repo.protect("vault/", std::slice::from_ref(&alice_pk), None), "protect");
            assert_refused!(repo.grant("vault/", &alice_sk, &alice_pk), "grant");
            assert_refused!(repo.revoke("vault/", &recipient), "revoke");
            assert_refused!(repo.secret_add("K2", b"v2", std::slice::from_ref(&alice_pk)), "secret_add");
            assert_refused!(repo.secret_grant("K", &alice_sk, &alice_pk), "secret_grant");
            assert_refused!(
                repo.secret_rotate("K", Some(b"v3"), std::slice::from_ref(&alice_pk), None),
                "secret_rotate"
            );

            clear_state(&repo.layout);
        }

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn secret_add_refused_during_stopped_rebase_p19_i1_repro() {
        // P19-I1, pinned end to end: a REAL stopped rebase (not a hand-written
        // state file) must refuse `secret_add`, not silently move the branch
        // tip out from under it. Setup mirrors
        // `rebase_stops_on_conflict_and_continue_completes` (replay.rs).
        let root = tmp_root("secret-add-rebase-i1");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();
        let original_feature_tip = repo.head_tip().unwrap().unwrap();

        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let _ = alice_sk;

        // Stop on conflict.
        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(matches!(outcome, crate::replay::RebaseResult::Stopped { .. }));
        assert_eq!(repo.head_tip().unwrap(), Some(original_feature_tip));
        assert!(repo.rebase_in_progress());

        // The hazard: secret_add must refuse, not force a registry commit
        // over the stopped rebase's branch tip.
        let err = repo.secret_add("DB_URL", b"v", std::slice::from_ref(&alice_pk)).unwrap_err();
        assert!(matches!(err, Error::RebaseInProgress), "expected RebaseInProgress, got {err:?}");

        // State untouched: still in progress, tip unmoved, registry doesn't
        // carry the refused secret.
        assert!(repo.rebase_in_progress());
        assert_eq!(repo.head_tip().unwrap(), Some(original_feature_tip));
        assert!(!repo.registry().unwrap().contains_key("DB_URL"));

        // Resolve and continue: completes normally, and the refused secret is
        // still absent from the completed tip's registry (it was never
        // written anywhere, not even discarded state).
        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();
        let outcome = repo.rebase_continue("me", None).unwrap();
        assert!(matches!(outcome, crate::replay::RebaseResult::Rebased { .. }));
        assert!(!repo.rebase_in_progress());
        assert!(!repo.registry().unwrap().contains_key("DB_URL"), "refused secret must not resurface");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Regression: after a clone, an incremental fetch must send only the new
    /// delta — not the full history. Under the old bug, `transfer_objects`
    /// derived `haves` from the remote's tips (the objects being fetched), so
    /// on a clone→advance→fetch cycle the intersection would be empty and the
    /// remote would re-send the entire reachable closure. The fix derives haves
    /// from the local repo's refs, which are closure-complete by construction.
    ///
    /// This test proves the property directly against `LocalTransport::get_pack`:
    /// with correct local haves the pack for the new tip MUST exclude objects
    /// that were already present in the clone.
    #[test]
    fn fetch_transfers_only_delta_not_full_history() {
        let remote_root = tmp_root("delta-remote");
        let local_root = tmp_root("delta-local");
        let _ = std::fs::remove_dir_all(&local_root); // clone_to inits it

        // ── step 1: remote gets c1 with a distinctive large blob ─────────────
        let big_blob_bytes: Vec<u8> = vec![0xCDu8; 4096];
        let big_blob_id = scl_core::Object::blob(big_blob_bytes.clone()).id();
        {
            let remote = Repo::init(&remote_root).unwrap();
            std::fs::write(remote_root.join("large.bin"), &big_blob_bytes).unwrap();
            remote.commit("me", "c1 large").unwrap();
        }

        // ── step 2: clone the remote to local (local holds c1 and its objects) ─
        let local = Repo::clone_to(&remote_root, &local_root).unwrap();
        let c1 = local.head_tip().unwrap().expect("clone should have a HEAD tip");

        // ── step 3: remote advances with a small new file (c2) ──────────────
        let c2 = {
            let remote = Repo::open(&remote_root).unwrap();
            std::fs::write(remote_root.join("small.txt"), b"delta").unwrap();
            remote.commit("me", "c2 small").unwrap()
        };

        // ── step 4: verify correct haves and delta pack ───────────────────────
        // Open local store and compute local_have_tips (the fix path).
        let store_arc = local.vfs.store();
        let store = store_arc.lock().unwrap();

        let haves = crate::sync::local_have_tips(&local.layout, &store).unwrap();
        assert!(haves.contains(&c1), "local haves must include c1 ({c1})");

        // Build the delta pack: remote only sends what local doesn't have.
        use crate::transport::Transport as _;
        let transport = crate::transport::LocalTransport::open(&remote_root).unwrap();
        let mut pack = Vec::new();
        transport.get_pack(&[c2], &haves, None, &mut pack).unwrap();
        let entries: Vec<scl_core::ObjectId> = scl_core::pack::parse_pack(&pack)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        // The pack MUST include the new tip snapshot.
        assert!(
            entries.contains(&c2),
            "delta pack must contain c2; got {entries:?}"
        );
        // The pack MUST NOT contain c1 (local already has it).
        assert!(
            !entries.contains(&c1),
            "delta pack must not re-send c1 that local already holds"
        );
        // The pack MUST NOT contain the large distinctive blob (part of c1's closure).
        assert!(
            !entries.contains(&big_blob_id),
            "delta pack must not re-send the large blob that was in c1"
        );

        drop(store);
        drop(local);
        std::fs::remove_dir_all(&remote_root).unwrap();
        std::fs::remove_dir_all(&local_root).unwrap();
    }

    // ---- P19 Task 3: sc amend ----

    #[test]
    fn amend_replaces_tip_preserving_parents_and_message() {
        let root = tmp_root("amend-basic");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let a = repo.commit("me", "commit A").unwrap();
        std::fs::write(root.join("a.txt"), b"two").unwrap();
        let b = repo.commit("me", "commit B").unwrap();

        // Edit the working tree, then amend with no message override.
        std::fs::write(root.join("a.txt"), b"three").unwrap();
        let b_amended = repo.amend("me", None).unwrap();

        assert_ne!(b_amended, b, "amend must produce a new snapshot id");
        let snap = repo.snapshot(&b_amended).unwrap();
        assert_eq!(snap.parents, vec![a], "amended parents must match B's parents");
        assert_eq!(snap.message, "commit B", "message kept unless overridden");

        // The edit landed in B', and B is no longer the branch tip.
        assert_eq!(repo.head_tip().unwrap(), Some(b_amended));
        let store_arc = repo.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let entries = worktree::tree_file_ids(&mut store, snap.root).unwrap();
        let a_blob = entries["a.txt"];
        match store.get(&a_blob).unwrap() {
            Object::Blob(bytes) => assert_eq!(&bytes[..], b"three"),
            _ => panic!("expected Blob"),
        }
        drop(store);

        // Oplog has an "amend" record, and one undo restores B as tip.
        let log = repo.oplog().unwrap();
        assert_eq!(log.last().unwrap().desc, "amend");
        let outcome = repo.undo().unwrap();
        assert_eq!(outcome.desc, "amend");
        assert_eq!(repo.head_tip().unwrap(), Some(b));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn amend_with_message_overrides() {
        let root = tmp_root("amend-message");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "original message").unwrap();
        std::fs::write(root.join("a.txt"), b"two").unwrap();

        let id = repo.amend("me", Some("new")).unwrap();
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.message, "new");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn amend_merge_commit_keeps_both_parents() {
        let root = tmp_root("amend-merge");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("main-only.txt"), b"m").unwrap();
        let ours = repo.commit("me", "main work").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("feature-only.txt"), b"f").unwrap();
        let theirs = repo.commit("me", "feature work").unwrap();
        repo.switch("main").unwrap();

        let m = repo.merge("feature", "me").unwrap();
        let m_snap = repo.snapshot(&m).unwrap();
        assert_eq!(m_snap.parents, vec![ours, theirs]);

        // Edit, then amend the merge tip: parents must be preserved exactly.
        std::fs::write(root.join("main-only.txt"), b"m-edited").unwrap();
        let m_amended = repo.amend("me", None).unwrap();
        let amended_snap = repo.snapshot(&m_amended).unwrap();
        assert_eq!(amended_snap.parents, vec![ours, theirs], "merge amend must keep both parents");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn amend_root_commit_keeps_empty_parents() {
        let root = tmp_root("amend-root");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "root").unwrap();

        std::fs::write(root.join("a.txt"), b"two").unwrap();
        let id = repo.amend("me", None).unwrap();
        let snap = repo.snapshot(&id).unwrap();
        assert!(snap.parents.is_empty(), "amended root commit must keep empty parents");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn amend_refuses_unborn_and_in_progress_states() {
        let root = tmp_root("amend-guards");
        let repo = Repo::init(&root).unwrap();

        // Unborn: no commits yet.
        assert!(matches!(repo.amend("me", None), Err(Error::Unborn)));

        std::fs::write(root.join("a.txt"), b"one").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // Merge in progress.
        crate::merge_state::write(&repo.layout, &ObjectId::of(b"theirs"), &[], None).unwrap();
        assert!(matches!(repo.amend("me", None), Err(Error::MergeInProgress)));
        crate::merge_state::clear(&repo.layout).unwrap();

        // Cherry-pick in progress.
        crate::pick_state::write(&repo.layout, &ObjectId::of(b"picked"), &[], None, None).unwrap();
        assert!(matches!(repo.amend("me", None), Err(Error::PickInProgress)));
        crate::pick_state::clear(&repo.layout).unwrap();

        // Rebase in progress.
        let st = crate::rebase_state::RebaseState {
            branch: "main".into(),
            original_tip: ObjectId::of(b"orig"),
            target: "feature".into(),
            acc_tip: ObjectId::of(b"acc"),
            conflicted: ObjectId::of(b"conflicted"),
            remaining: vec![],
            total: 2,
            author: "me".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        };
        crate::rebase_state::write(&repo.layout, &st).unwrap();
        assert!(matches!(repo.amend("me", None), Err(Error::RebaseInProgress)));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn amend_runs_scanner_and_protection() {
        let root = tmp_root("amend-scan-protect");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();

        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/a.txt"), b"secret-key").unwrap();
        repo.protect("keys/", &[alice_pk], None).unwrap();

        // A plaintext secret introduced via amend must be caught by the scanner.
        std::fs::write(root.join("readme.txt"), b"key = AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let err = repo.amend("me", None).unwrap_err();
        assert!(matches!(err, Error::SecretDetected(_)), "expected SecretDetected, got {err:?}");

        // Fix the plaintext file, and edit the protected one: the amended tip's
        // blob must remain PROTECTED ciphertext, wrapped for the granted key.
        std::fs::write(root.join("readme.txt"), b"hi again").unwrap();
        std::fs::write(root.join("keys/a.txt"), b"rotated-secret-key").unwrap();
        let id = repo.amend("me", None).unwrap();
        let snap = repo.snapshot(&id).unwrap();

        let (blob_id, perms) = {
            let store_arc = repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            let entries = worktree::tree_file_entries_with_perms(&mut store, snap.root).unwrap();
            let (id, _, perms) = entries["keys/a.txt"];
            (id, perms)
        };
        assert_ne!(perms & scl_core::PROTECTED, 0, "amended protected file must stay protected");

        let bytes = {
            let store_arc = repo.vfs.store();
            let mut store = store_arc.lock().unwrap();
            match store.get(&blob_id).unwrap() {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("expected Blob"),
            }
        };
        let pt =
            crate::protect::decrypt_with(&bytes, &blob_id, &[&snap.protection], &alice_sk, "keys/a.txt")
                .unwrap();
        assert_eq!(&pt[..], b"rotated-secret-key");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn set_sparse_materializes_only_the_subset() {
        let root = tmp_root("sparse-set");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"b").unwrap();
        repo.commit("me", "base").unwrap();

        repo.set_sparse(&["src/".to_string()], None).unwrap();

        assert!(root.join("src/a.txt").exists(), "in-sparse file must stay materialized");
        assert!(!root.join("docs/b.txt").exists(), "out-of-sparse file must be pruned from disk");
        assert!(repo.layout().sparse_path().exists(), "sparse spec must persist");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn disable_sparse_rematerializes_fully() {
        let root = tmp_root("sparse-disable");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"b").unwrap();
        repo.commit("me", "base").unwrap();
        repo.set_sparse(&["src/".to_string()], None).unwrap();
        assert!(!root.join("docs/b.txt").exists());

        repo.disable_sparse(None).unwrap();

        assert!(root.join("src/a.txt").exists());
        assert!(root.join("docs/b.txt").exists(), "disable must restore the full tree");
        assert!(!repo.layout().sparse_path().exists(), "sparse spec must be cleared");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn switch_honors_persisted_sparse() {
        let root = tmp_root("sparse-switch");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"b").unwrap();
        repo.commit("me", "base").unwrap();
        repo.set_sparse(&["src/".to_string()], None).unwrap();
        assert!(!root.join("docs/b.txt").exists());

        repo.branch("other").unwrap();
        repo.switch("other").unwrap();
        assert!(root.join("src/a.txt").exists());
        assert!(!root.join("docs/b.txt").exists(), "spec persists across switch away");

        repo.switch("main").unwrap();
        assert!(root.join("src/a.txt").exists());
        assert!(!root.join("docs/b.txt").exists(), "spec persists across switch back");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sparse_roundtrip_commit_then_full_clone_sees_all() {
        let root = tmp_root("sparse-roundtrip");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"original").unwrap();
        repo.commit("me", "base").unwrap();

        repo.set_sparse(&["src/".to_string()], None).unwrap();
        assert!(!root.join("docs/b.txt").exists());

        // Edit an in-sparse file and commit while sparse (docs/b.txt is
        // carried verbatim by the P24 Task 2 carry generalization).
        std::fs::write(root.join("src/a.txt"), b"edited").unwrap();
        repo.commit("me", "edit under sparse").unwrap();

        // A full checkout (disable) must see the out-of-sparse subtree
        // byte-identical to what was last on disk before sparse narrowed it.
        repo.disable_sparse(None).unwrap();
        assert!(root.join("docs/b.txt").exists());
        assert_eq!(std::fs::read(root.join("docs/b.txt")).unwrap(), b"original");
        assert_eq!(std::fs::read(root.join("src/a.txt")).unwrap(), b"edited");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sparse_out_of_view_file_is_clean_not_deleted_in_status_and_diff() {
        // Regression coverage for the gap the advisor caught: diff_unified is
        // an independent HEAD-vs-disk reader from diff_worktree/status, and
        // must not report an out-of-sparse path as a deletion either.
        let root = tmp_root("sparse-diff");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"b").unwrap();
        repo.commit("me", "base").unwrap();

        repo.set_sparse(&["src/".to_string()], None).unwrap();
        assert!(!root.join("docs/b.txt").exists());

        let st = repo.status().unwrap();
        assert!(st.deleted.is_empty(), "out-of-sparse path must not read as deleted: {:?}", st);

        let diff = repo.diff_unified().unwrap();
        assert!(!diff.contains("docs/b.txt"), "sc diff must not show the out-of-sparse path: {diff}");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn status_shows_sparse_spec() {
        // P24 Task 4: `sc status` (`run_status` in the CLI) reuses
        // `Repo::sparse_spec()` to print the active prefixes; this pins the
        // accessor contract the CLI line depends on. The absent out-of-sparse
        // subtree must not be listed as a deletion (Task 3's status fix,
        // reconfirmed here alongside the accessor).
        let root = tmp_root("sparse-status-line");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(root.join("docs/b.txt"), b"b").unwrap();
        repo.commit("me", "base").unwrap();

        // No sparse spec: the accessor reports empty (full checkout).
        assert!(repo.sparse_spec().unwrap().prefixes().is_empty());

        repo.set_sparse(&["src/".to_string()], None).unwrap();
        assert_eq!(repo.sparse_spec().unwrap().prefixes(), &["src/".to_string()]);

        let st = repo.status().unwrap();
        assert!(
            st.deleted.is_empty(),
            "absent out-of-sparse subtree must not be listed as a deletion: {st:?}"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn set_sparse_and_disable_sparse_refuse_a_dirty_working_tree() {
        let root = tmp_root("sparse-dirty-guard");
        let repo = Repo::init(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a").unwrap();
        repo.commit("me", "base").unwrap();

        // Uncommitted edit to a tracked file must block set_sparse...
        std::fs::write(root.join("src/a.txt"), b"dirty edit").unwrap();
        assert!(matches!(
            repo.set_sparse(&["src/".to_string()], None),
            Err(Error::InvalidArgument(_))
        ));
        // ...and it must not have persisted the spec or touched the file.
        assert!(!repo.layout().sparse_path().exists());
        assert_eq!(std::fs::read(root.join("src/a.txt")).unwrap(), b"dirty edit");

        // Clean up the dirty state, set sparse, then dirty again to check disable_sparse.
        repo.commit("me", "commit the edit").unwrap();
        repo.set_sparse(&["src/".to_string()], None).unwrap();
        std::fs::write(root.join("src/a.txt"), b"dirty again").unwrap();
        assert!(matches!(repo.disable_sparse(None), Err(Error::InvalidArgument(_))));
        assert!(repo.layout().sparse_path().exists(), "disable must not have cleared the spec");

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ── P27 Task 5: gap-tolerant status/diff, verify, export, and the
    // merge/pick out-of-filter guard on a partial clone. ──

    fn tmp_repo_with_src_and_docs_partial(tag: &str) -> (Repo, std::path::PathBuf, Repo, std::path::PathBuf) {
        let src_root = tmp_root(&format!("{tag}-src"));
        let dst_root = tmp_root(&format!("{tag}-dst"));
        std::fs::create_dir_all(src_root.join("src")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
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
        (src, src_root, dst, dst_root)
    }

    #[test]
    fn status_and_diff_succeed_on_fresh_partial_clone_no_spurious_deletions() {
        // T5-I3 (P27 Task 5, mandatory reassignment from the Task 4 review):
        // `status`/`diff_unified` used to flatten HEAD's FULL tree via the
        // unfiltered walker, which `NotFound`s on the out-of-filter `docs/`
        // gap a partial clone never fetched. Both must now succeed and
        // report no spurious deletion for the gapped path.
        let (src, src_root, dst, dst_root) = tmp_repo_with_src_and_docs_partial("status-diff-partial");

        let st = dst.status().unwrap();
        assert!(st.deleted.is_empty(), "out-of-filter docs/ must not read as deleted: {st:?}");
        assert!(st.modified.is_empty());
        assert!(st.added.is_empty());

        let diff = dst.diff_unified().unwrap();
        assert!(diff.is_empty(), "a clean partial-clone checkout must diff empty: {diff}");
        assert!(!diff.contains("docs/b.txt"));

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn verify_reports_partial_not_corrupt() {
        let (src, src_root, dst, dst_root) = tmp_repo_with_src_and_docs_partial("verify-partial");

        let tip = dst.head_tip().unwrap().unwrap();
        let gaps = dst.partial_gap_count(&[tip]).unwrap();
        assert!(gaps.is_some(), "a partial clone must report Some gap count");
        assert!(gaps.unwrap() >= 1, "the out-of-filter docs/ subtree must show up as a gap");

        // A full clone reports no partial-clone gap count at all.
        let full_gaps = src.partial_gap_count(&[src.head_tip().unwrap().unwrap()]).unwrap();
        assert_eq!(full_gaps, None, "a full clone is not partial");

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn merge_refuses_on_partial_clone_instead_of_silently_dropping_gaps() {
        // T5-I4 (mandatory reassignment): a two-parent merge completion on a
        // partial clone would silently DROP out-of-filter subtrees (the
        // Task 4 graft is single-tip-scoped). Refuse loudly instead of
        // relying on an incidental NotFound from deep inside `three_way`.
        let (src, src_root, dst, dst_root) = tmp_repo_with_src_and_docs_partial("merge-guard-partial");

        // Fork a second branch off the initial commit, then diverge both
        // sides so `merge` needs a genuine (non-FF) three-way, not just an
        // adopt/fast-forward (both of which stay gap-tolerant via
        // `materialize` and don't need this guard). `switch` between them
        // (exercising its own P27 Task 5 fix to `materialize`'s old-root
        // walk, below).
        dst.branch("feature").unwrap();
        dst.switch("feature").unwrap();
        std::fs::write(dst_root.join("src/a.txt"), b"feature-side-edit").unwrap();
        dst.commit("t", "feature edit").unwrap();

        dst.switch("main").unwrap();
        std::fs::write(dst_root.join("src/a.txt"), b"main-side-edit").unwrap();
        dst.commit("t", "main edit").unwrap();

        let err = dst.merge_with_identity("feature", "t", None).unwrap_err();
        assert!(
            matches!(err, Error::PartialCloneUnsupported(_)),
            "expected the explicit partial-clone-unsupported refusal, got {err:?}"
        );
        assert!(err.to_string().contains("backfill"));
        assert!(err.to_string().contains("not supported on a partial clone"));
        assert!(!dst.merge_in_progress(), "the refusal must be a preflight, not a conflict state");

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// P27 Task 5 fix: `switch`'s old-root removal walk used to be
    /// unconditionally unfiltered, so switching branches on ANY partial
    /// clone with a genuine out-of-filter gap elsewhere in the tree
    /// `NotFound`ed — even with no merge/sparse narrowing involved at all.
    #[test]
    fn switch_succeeds_on_partial_clone_with_a_real_gap() {
        let (src, src_root, dst, dst_root) = tmp_repo_with_src_and_docs_partial("switch-partial-gap");

        dst.branch("feature").unwrap();
        dst.switch("feature").unwrap();
        std::fs::write(dst_root.join("src/a.txt"), b"on-feature").unwrap();
        dst.commit("t", "feature edit").unwrap();

        // Switching back to main (a different tree, same out-of-filter gap)
        // must succeed and must not touch the never-fetched docs/ subtree.
        dst.switch("main").unwrap();
        assert_eq!(std::fs::read(dst_root.join("src/a.txt")).unwrap(), b"src-one");
        assert!(!dst_root.join("docs/b.txt").exists());

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn snapshot_files_refuses_merge_head_completion_on_partial_clone() {
        // Defense-in-depth: `snapshot_files`'s own guard fires even if a
        // MERGE_HEAD/decided-root state is present without having gone
        // through `merge_with_identity`'s upfront refusal (mirrors how
        // `gc`'s tests write merge_state directly).
        let (src, src_root, dst, dst_root) = tmp_repo_with_src_and_docs_partial("snapshot-files-guard");
        let tip = dst.head_tip().unwrap().unwrap();

        let err = dst
            .snapshot_files(
                Vec::new(),
                Some(tip),
                Some(tip),
                None,
                None,
                None,
                None,
                &dst.sparse_spec().unwrap(),
                "t",
                "msg",
            )
            .unwrap_err();
        assert!(matches!(err, Error::PartialCloneUnsupported(_)), "got {err:?}");

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn partial_commit_refuses_out_of_filter_new_path() {
        // P27 Task 5 review CRITICAL repro: a brand-new file at a fully
        // out-of-filter path (a name the parent tree has NO entry for at
        // all — not even a gapped one) used to sail straight through
        // `graft_out_of_sparse`'s I1 check, which only fires when the
        // parent tree already has a same-name entry. That let the commit
        // succeed and land content in the new root that this partial clone
        // never fetched and the origin never had — unrecoverable once `sc
        // gc` classified it as a gap and pruned it. Must now refuse loudly
        // instead.
        let (src, src_root, dst, dst_root) =
            tmp_repo_with_src_and_docs_partial("commit-refuses-new-out-of-filter");

        std::fs::create_dir_all(dst_root.join("tools")).unwrap();
        std::fs::write(dst_root.join("tools/z.txt"), b"brand-new-out-of-filter").unwrap();

        let err = dst.commit("t", "add tools/z.txt").unwrap_err();
        assert!(
            matches!(err, Error::GappedPathContent(ref p) if p.contains("tools")),
            "expected a GappedPathContent refusal naming tools/, got {err:?}"
        );
        assert!(err.to_string().contains("backfill"));

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }
}
