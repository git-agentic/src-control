//! Git *export* — the write half of the `gix` interop boundary (import is in
//! `lib.rs`). This is the only place, besides import, that touches `gix`.
//!
//! All `gix` types are confined to this file behind `GitTarget` and the small
//! `GitTreeEntry`/`GitMode`/`GitSig` value types, so the rest of export (and the
//! whole rest of the workspace) stays Git-agnostic.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use scl_core::{EntryKind, FileMode, Object, ObjectId, Snapshot, Store, PROTECTED};

/// A Git repository we write objects and refs into.
pub(crate) struct GitTarget {
    repo: gix::Repository,
    /// True if THIS call created the repo (so we own its `HEAD`). We only point
    /// `HEAD` at the exported ref when we created the repo — never clobber the
    /// `HEAD` of a pre-existing repo (it may be someone's working checkout).
    pub(crate) created: bool,
}

/// One entry for `write_tree`, in our terms (not `gix`'s).
pub(crate) struct GitTreeEntry {
    pub name: String,
    pub mode: GitMode,
    pub oid: gix::ObjectId,
}

/// The four Git entry kinds we emit.
#[derive(Clone, Copy)]
pub(crate) enum GitMode {
    File,
    Exec,
    Link,
    Tree,
}

/// A synthesized Git signature (used for both author and committer).
pub(crate) struct GitSig {
    pub name: String,
    pub email: String,
    pub time_secs: i64,
}

impl GitMode {
    fn to_gix(self) -> gix::objs::tree::EntryMode {
        use gix::objs::tree::EntryKind;
        match self {
            GitMode::File => EntryKind::Blob,
            GitMode::Exec => EntryKind::BlobExecutable,
            GitMode::Link => EntryKind::Link,
            GitMode::Tree => EntryKind::Tree,
        }
        .into()
    }
}

impl GitTarget {
    /// Open an existing Git repo at `path`; if `path` does not exist, create a
    /// bare repo there. A path that exists but is not a Git repo is an error.
    pub(crate) fn open_or_init_bare(path: &Path) -> Result<GitTarget> {
        let (repo, created) = if path.exists() {
            (
                gix::open(path).with_context(|| {
                    format!("{} exists but is not a git repository", path.display())
                })?,
                false,
            )
        } else {
            (
                gix::init_bare(path)
                    .with_context(|| format!("initializing bare git repo at {}", path.display()))?,
                true,
            )
        };
        Ok(GitTarget { repo, created })
    }

    /// Point `HEAD` at `ref_name` (a symbolic ref). Only meaningful on a repo we
    /// created — a fresh `init_bare` HEAD may name `main`/`master` regardless of
    /// our branch, so a mirror needs HEAD pointed at the ref we actually wrote or
    /// `git log`/`import_head` (which resolve HEAD) see nothing.
    pub(crate) fn set_head(&self, ref_name: &str) -> Result<()> {
        use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
        use gix::refs::{FullName, Target};
        let target: FullName = ref_name.try_into().context("ref name for HEAD")?;
        self.repo
            .edit_reference(RefEdit {
                change: Change::Update {
                    log: LogChange {
                        mode: RefLog::AndReference,
                        force_create_reflog: false,
                        message: "sc export".into(),
                    },
                    expected: PreviousValue::Any,
                    new: Target::Symbolic(target),
                },
                name: "HEAD".try_into().context("HEAD name")?,
                deref: false,
            })
            .context("pointing HEAD at exported ref")?;
        Ok(())
    }

    /// True if `id` names an object that actually exists in this repo. Used to
    /// verify a reused mark before trusting it — `git gc` in the target can
    /// prune a commit a stale mark still names.
    ///
    /// Note: verifies the commit object itself, not its tree/blob closure.
    /// Sufficient under git-gc's reachability-atomic pruning; a commit with a
    /// corrupted tree is out of scope.
    pub(crate) fn has_object(&self, id: gix::ObjectId) -> bool {
        self.repo.has_object(id)
    }

    /// Write a blob, returning its Git oid.
    pub(crate) fn write_blob(&self, bytes: &[u8]) -> Result<gix::ObjectId> {
        Ok(self.repo.write_blob(bytes).context("writing git blob")?.detach())
    }

    /// Write a tree from `entries`, canonicalizing entry order to Git's rule.
    ///
    /// Git canonical order: compare entry names bytewise, EXCEPT a **tree** entry
    /// sorts as if its name had a trailing `/` appended. So file `some-dir.txt`
    /// sorts before directory `some-dir/` (`.` = 0x2e < `/` = 0x2f). We sort with
    /// this explicit rule rather than relying on any `gix` `Ord`, then build the
    /// tree in that order. Do NOT additionally call `tree.entries.sort()` — if
    /// `gix`'s ordering is plain-name it would re-scramble our correct order.
    pub(crate) fn write_tree(&self, mut entries: Vec<GitTreeEntry>) -> Result<gix::ObjectId> {
        fn sort_key(e: &GitTreeEntry) -> Vec<u8> {
            let mut k = e.name.as_bytes().to_vec();
            if matches!(e.mode, GitMode::Tree) {
                k.push(b'/');
            }
            k
        }
        entries.sort_by_key(sort_key);

        let mut tree = gix::objs::Tree::empty();
        for e in entries {
            tree.entries.push(gix::objs::tree::Entry {
                mode: e.mode.to_gix(),
                filename: e.name.into(),
                oid: e.oid,
            });
        }
        Ok(self.repo.write_object(&tree).context("writing git tree")?.detach())
    }

    /// Write a commit with explicit author=committer signature (deterministic).
    pub(crate) fn write_commit(
        &self,
        tree: gix::ObjectId,
        parents: &[gix::ObjectId],
        sig: &GitSig,
        message: &str,
    ) -> Result<gix::ObjectId> {
        let signature = gix::actor::Signature {
            name: sig.name.clone().into(),
            email: sig.email.clone().into(),
            time: gix::date::Time::new(sig.time_secs, 0),
        };
        let commit = gix::objs::Commit {
            tree,
            parents: parents.iter().copied().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        Ok(self.repo.write_object(&commit).context("writing git commit")?.detach())
    }

    /// Create or force-overwrite `ref_name` to point at `target` (mirror
    /// semantics — no fast-forward check).
    pub(crate) fn set_ref_force(&self, ref_name: &str, target: gix::ObjectId) -> Result<()> {
        use gix::refs::transaction::PreviousValue;
        self.repo
            .reference(ref_name, target, PreviousValue::Any, "sc export")
            .with_context(|| format!("updating ref {ref_name}"))?;
        Ok(())
    }
}

/// Deterministic Git signature from our freeform author + i64 timestamp. If
/// `author` looks like `Name <email>`, split it; otherwise name=author, empty
/// email. Timezone is fixed at +0000 so re-export is byte-identical.
fn synth_sig(author: &str, timestamp: i64) -> GitSig {
    if let Some((name, rest)) = author.split_once('<') {
        // Edge case: `Name <email> trailing` (text after `>`) fails strip_suffix
        // and falls through to name-only with empty email — acceptable for
        // freeform author strings.
        if let Some(email) = rest.strip_suffix('>') {
            return GitSig { name: name.trim().to_string(), email: email.trim().to_string(), time_secs: timestamp };
        }
    }
    GitSig { name: author.to_string(), email: String::new(), time_secs: timestamp }
}

/// Write our blob to Git once (memoized by our ObjectId).
fn map_blob(
    store: &mut Store,
    target: &GitTarget,
    id: ObjectId,
    blob_memo: &mut HashMap<ObjectId, gix::ObjectId>,
) -> anyhow::Result<gix::ObjectId> {
    if let Some(&g) = blob_memo.get(&id) {
        return Ok(g);
    }
    let bytes = match store.get(&id)? {
        Object::Blob(b) => b,
        other => anyhow::bail!("expected blob for {id}, got {}", other.kind_name()),
    };
    let g = target.write_blob(&bytes)?;
    blob_memo.insert(id, g);
    Ok(g)
}

/// Recursively translate our tree to a Git tree (memoized). Increments
/// `protected_count` for every entry carrying the PROTECTED perms bit (the blob
/// is exported as-is — it is already ciphertext).
fn map_tree(
    store: &mut Store,
    target: &GitTarget,
    id: ObjectId,
    tree_memo: &mut HashMap<ObjectId, gix::ObjectId>,
    blob_memo: &mut HashMap<ObjectId, gix::ObjectId>,
    protected_count: &mut usize,
) -> anyhow::Result<gix::ObjectId> {
    if let Some(&g) = tree_memo.get(&id) {
        return Ok(g);
    }
    let tree = store.get_tree(&id)?;
    let mut git_entries = Vec::with_capacity(tree.entries.len());
    for e in &tree.entries {
        if e.perms & PROTECTED != 0 {
            *protected_count += 1;
        }
        let (mode, oid) = match e.kind {
            EntryKind::Tree => (
                GitMode::Tree,
                map_tree(store, target, e.id, tree_memo, blob_memo, protected_count)?,
            ),
            EntryKind::Blob => {
                let mode = match e.mode {
                    m if m == FileMode::EXEC => GitMode::Exec,
                    FileMode(0o120000) => GitMode::Link,
                    _ => GitMode::File,
                };
                (mode, map_blob(store, target, e.id, blob_memo)?)
            }
        };
        git_entries.push(GitTreeEntry { name: e.name.clone(), mode, oid });
    }
    let g = target.write_tree(git_entries)?;
    tree_memo.insert(id, g);
    Ok(g)
}

/// Write a Git commit for `snap` given its already-mapped tree + parent oids.
fn map_commit(
    target: &GitTarget,
    snap: &Snapshot,
    tree_oid: gix::ObjectId,
    parent_oids: &[gix::ObjectId],
) -> anyhow::Result<gix::ObjectId> {
    let sig = synth_sig(&snap.author, snap.timestamp);
    target.write_commit(tree_oid, parent_oids, &sig, &snap.message)
}

/// Options controlling an export.
pub struct ExportOptions<'a> {
    /// Target Git repo path; an existing bare repo is opened, otherwise one is
    /// created with `git init --bare`.
    pub to: &'a Path,
    /// Fully-qualified Git ref to update, e.g. `"refs/heads/main"`.
    pub ref_name: &'a str,
    /// When true, protected files are exported as their ciphertext blobs and
    /// registry secrets are dropped; when false the export fails closed if any
    /// encrypted content is present in history.
    pub include_encrypted: bool,
    /// sc-snapshot-id → git-oid-hex for commits already present on the target
    /// (learned from the marks map). Snapshots found here reuse their existing
    /// git commit and are not rewritten. Empty for a plain `sc export`.
    pub known_git_commits: &'a std::collections::HashMap<ObjectId, String>,
}

/// Summary of an export. `git_commit` is a hex string so `cli` needs no `gix`.
#[derive(Debug)]
pub struct ExportReport {
    /// Hex Git commit id of the exported tip (the commit `ref_name` now points
    /// at).
    pub git_commit: String,
    /// Total number of commits in the exported history DAG (the full walk from
    /// tip to roots). Because Git deduplicates by content hash, a re-export into
    /// a populated repo still reports the full count — not only newly-written
    /// objects.
    pub commits_written: usize,
    /// Number of tree entries that carried the PROTECTED bit and were written as
    /// ciphertext blobs (only non-zero when `include_encrypted` is true).
    pub protected_blobs_as_ciphertext: usize,
    /// Number of unique registry secret names dropped from history (secrets have
    /// no Git-native equivalent and cannot be exported safely). Deduped by name
    /// across all snapshots.
    pub secrets_dropped: usize,
    /// Number of P22 snapshot-signature objects dropped from history (Git has
    /// no native equivalent for a detached signature over an sc snapshot id,
    /// and re-signing the synthesized Git commit would be a different,
    /// unverifiable claim — so signatures are silently absent from the
    /// exported Git history, counted here like `secrets_dropped`). Counts
    /// every `Object::Signature` in the store whose `snapshot` field is one
    /// of the exported DAG's snapshot ids — not deduped by signer, since
    /// (unlike secret names) two signers signing the same snapshot are two
    /// genuinely distinct dropped signatures, not the same one repeated.
    pub signatures_dropped: usize,
    /// Commits written *this call* as `(git_oid_hex, sc_id)`, for the caller to
    /// persist into the marks map. Excludes reused (already-known) commits.
    pub new_marks: Vec<(String, ObjectId)>,
    /// Marks whose git commit no longer exists in the target (e.g. pruned by a
    /// `git gc` run there). Those sc-ids were re-synthesized instead of reused
    /// — they also appear in `new_marks` with fresh oids.
    pub stale_marks: usize,
}

/// Read-only pre-flight scan of the DAG rooted at `tip`: collect the paths of
/// PROTECTED tree entries and the names of registry secrets, without writing
/// anything. Used to fail closed before any Git repo is created.
///
/// Secret names are deduped across snapshots (the same name in N commits counts
/// once) so `secrets_dropped` in the report reflects unique names, not
/// per-snapshot occurrences.
///
/// Also returns every snapshot id visited — the caller uses it to count P22
/// signature objects covering this DAG (see `count_signatures`): a
/// `SignatureObj` is a leaf referenced by no tree/snapshot, so it can't be
/// discovered by this walk itself, only cross-referenced against the
/// snapshot ids the walk found.
fn scan_encrypted(
    store: &mut Store,
    tip: ObjectId,
) -> anyhow::Result<(Vec<String>, Vec<String>, std::collections::HashSet<ObjectId>)> {
    let mut protected_paths = Vec::new();
    let mut secret_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut seen_snaps: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();
    let mut snaps = vec![tip];
    while let Some(sid) = snaps.pop() {
        if !seen_snaps.insert(sid) {
            continue;
        }
        let snap = store.get_snapshot(&sid)?;
        for name in snap.secrets.keys() {
            secret_names.insert(name.clone());
        }
        scan_tree(store, snap.root, String::new(), &mut protected_paths)?;
        for p in &snap.parents {
            snaps.push(*p);
        }
    }
    Ok((protected_paths, secret_names.into_iter().collect(), seen_snaps))
}

/// Count P22 `Object::Signature` objects covering any snapshot in
/// `seen_snaps` (the exported DAG). Not a reachability walk — a signature is
/// referenced by no tree/parent, so this scans every object the store can
/// resolve (`Store::all_ids`, loose + packed) and filters by kind + snapshot
/// membership. `crates/gitio` has no dependency on `crates/repo` (the
/// dependency rule is `repo -> gitio`, not the reverse) and so cannot read
/// the repo-side `.sc/signatures` index directly — this is the CAS-only
/// substitute, giving the same answer because every indexed signature is
/// also a store object with a `snapshot` field naming what it covers.
fn count_signatures(
    store: &mut Store,
    seen_snaps: &std::collections::HashSet<ObjectId>,
) -> anyhow::Result<usize> {
    let mut count = 0;
    for id in store.all_ids()? {
        if let Object::Signature(sig) = store.get(&id)? {
            if seen_snaps.contains(&sig.snapshot) {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Record PROTECTED entry paths under `prefix`, recursing into subtrees. Uses an
/// explicit stack so deep trees can't overflow. Deduplicates subtree object ids
/// via `seen` so shared subtrees (identical content at multiple paths in a
/// content-addressed store) are visited exactly once.
fn scan_tree(store: &mut Store, root: ObjectId, prefix: String, out: &mut Vec<String>) -> anyhow::Result<()> {
    let mut seen: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();
    let mut stack = vec![(root, prefix)];
    while let Some((id, pre)) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let tree = store.get_tree(&id)?;
        for e in &tree.entries {
            let path = if pre.is_empty() { e.name.clone() } else { format!("{pre}/{}", e.name) };
            if e.perms & PROTECTED != 0 {
                out.push(path.clone());
            }
            if let EntryKind::Tree = e.kind {
                stack.push((e.id, path));
            }
        }
    }
    Ok(())
}

/// Export the snapshot DAG rooted at `tip` into the Git repo named by `opts`,
/// updating `opts.ref_name` to the exported commit. Re-export is idempotent.
///
/// Fails closed if any snapshot contains protected blobs or registry secrets
/// and `opts.include_encrypted` is false — no Git repo is created and no
/// object is written on refusal. With the flag, protected blobs export as
/// ciphertext and secrets are dropped (counted in the report).
pub fn export_branch(store: &mut Store, tip: ObjectId, opts: &ExportOptions) -> anyhow::Result<ExportReport> {
    // Fail closed BEFORE creating or writing anything.
    let (protected_paths, secret_names, seen_snaps) = scan_encrypted(store, tip)?;
    if !opts.include_encrypted && (!protected_paths.is_empty() || !secret_names.is_empty()) {
        anyhow::bail!(
            "refusing to export encrypted content without --include-encrypted:\n  protected paths: {:?}\n  secrets: {:?}",
            protected_paths, secret_names
        );
    }
    let secrets_dropped = secret_names.len();
    // Signatures have no fail-closed gate (unlike protected content/secrets,
    // a dropped signature is a provenance-completeness loss, not a
    // confidentiality one) — always counted, exported or not.
    let signatures_dropped = count_signatures(store, &seen_snaps)?;

    let target = GitTarget::open_or_init_bare(opts.to)?;

    let mut commit_memo: HashMap<ObjectId, gix::ObjectId> = HashMap::new();
    // Seed with commits already on the target (marks map): these are reused, not
    // rewritten. A bad hex here is a corrupt marks file — surface it. Verify each
    // still EXISTS there before reuse: `git gc` in the target can prune commits a
    // stale mark still names, and blindly reusing a pruned oid writes a broken
    // parent chain (P21 follow-on, ADR-0031). A missing one is treated as
    // unknown — the walk below re-synthesizes it — and counted.
    let mut stale_marks = 0usize;
    for (sc_id, git_hex) in opts.known_git_commits {
        let g = gix::ObjectId::from_hex(git_hex.as_bytes())
            .with_context(|| format!("bad git oid in marks for {sc_id}"))?;
        if target.has_object(g) {
            commit_memo.insert(*sc_id, g);
        } else {
            stale_marks += 1;
        }
    }
    let mut new_marks: Vec<(String, ObjectId)> = Vec::new();
    let mut tree_memo: HashMap<ObjectId, gix::ObjectId> = HashMap::new();
    let mut blob_memo: HashMap<ObjectId, gix::ObjectId> = HashMap::new();
    let mut protected = 0usize;

    // Post-order DAG walk: a commit is written only after all its parents have
    // Git oids. Explicit stack (no recursion) so deep history can't overflow.
    let mut stack: Vec<(ObjectId, bool)> = vec![(tip, false)];
    while let Some((sid, ready)) = stack.pop() {
        if commit_memo.contains_key(&sid) {
            continue;
        }
        if ready {
            let snap = store.get_snapshot(&sid)?;
            let tree_oid = map_tree(store, &target, snap.root, &mut tree_memo, &mut blob_memo, &mut protected)?;
            let parent_oids: Vec<gix::ObjectId> =
                snap.parents.iter().map(|p| commit_memo[p]).collect();
            let cid = map_commit(&target, &snap, tree_oid, &parent_oids)?;
            commit_memo.insert(sid, cid);
            new_marks.push((cid.to_hex().to_string(), sid));
        } else {
            stack.push((sid, true));
            let snap = store.get_snapshot(&sid)?;
            for p in &snap.parents {
                if !commit_memo.contains_key(p) {
                    stack.push((*p, false));
                }
            }
        }
    }

    let tip_git = commit_memo[&tip];
    target.set_ref_force(opts.ref_name, tip_git)?;
    // If we created the repo, point HEAD at the exported ref so `git log` and
    // `import_head` (which resolve HEAD) see the history. Never touch HEAD on a
    // pre-existing repo.
    if target.created {
        target.set_head(opts.ref_name)?;
    }

    Ok(ExportReport {
        git_commit: tip_git.to_hex().to_string(),
        commits_written: commit_memo.len(),
        protected_blobs_as_ciphertext: protected,
        secrets_dropped,
        signatures_dropped,
        new_marks,
        stale_marks,
    })
}

/// The current git-oid-hex that `ref_name` points at in the git repo at `path`,
/// or `None` if the ref (or repo) is absent. Used by the push fast-forward gate.
pub fn read_ref(path: &Path, ref_name: &str) -> Result<Option<String>> {
    let repo = match gix::open(path) {
        Ok(r) => r,
        Err(_) => return Ok(None), // absent/uninitialized target => no ref
    };
    match repo.find_reference(ref_name) {
        Ok(mut r) => Ok(Some(r.peel_to_id().context("peeling ref")?.detach().to_hex().to_string())),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e")
            .output()
            .expect("git runs")
    }

    // The reference tree oid produced by canonical git for:
    //   some-dir.txt        (file, content "x")
    //   some-dir/inner.txt  (file, content "y")
    fn git_reference_tree_oid() -> String {
        let dir = std::env::temp_dir().join(format!("scl-gitref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("some-dir")).unwrap();
        std::fs::write(dir.join("some-dir.txt"), b"x").unwrap();
        std::fs::write(dir.join("some-dir/inner.txt"), b"y").unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["add", "-A"]);
        let out = git(&dir, &["write-tree"]);
        let oid = String::from_utf8(out.stdout).unwrap().trim().to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        oid
    }

    #[test]
    fn write_tree_matches_canonical_git_order() {
        let dir = std::env::temp_dir().join(format!("scl-gixwrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = GitTarget::open_or_init_bare(&dir).unwrap();

        let x = t.write_blob(b"x").unwrap();
        let y = t.write_blob(b"y").unwrap();
        let inner = t.write_tree(vec![GitTreeEntry { name: "inner.txt".into(), mode: GitMode::File, oid: y }]).unwrap();
        // Deliberately pass entries in NON-git order to prove write_tree canonicalizes.
        let root = t.write_tree(vec![
            GitTreeEntry { name: "some-dir".into(), mode: GitMode::Tree, oid: inner },
            GitTreeEntry { name: "some-dir.txt".into(), mode: GitMode::File, oid: x },
        ]).unwrap();

        assert_eq!(root.to_hex().to_string(), git_reference_tree_oid());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn single_snapshot_exports_files_and_modes() {
        use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode};
        use std::collections::{BTreeMap, HashMap};
        let mut store = Store::new(StoreConfig::default());
        let blob = store.put(Object::blob(b"fn main(){}".to_vec())).unwrap();
        let exec = store.put(Object::blob(b"#!/bin/sh\n".to_vec())).unwrap();
        let root = store.put(Object::Tree(Tree::new(vec![
            TreeEntry { name: "main.rs".into(), kind: EntryKind::Blob, id: blob, mode: FileMode::FILE, perms: 0 },
            TreeEntry { name: "run.sh".into(), kind: EntryKind::Blob, id: exec, mode: FileMode::EXEC, perms: 0 },
        ]))).unwrap();
        let snap = scl_core::Snapshot { root, parents: vec![], author: "Ada <ada@x>".into(), timestamp: 1_700_000_000, message: "c1".into(), secrets: BTreeMap::new(), protection: Default::default() };

        let dir = std::env::temp_dir().join(format!("scl-map1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let target = GitTarget::open_or_init_bare(&dir).unwrap();
        let mut tree_memo = HashMap::new();
        let mut blob_memo = HashMap::new();
        let mut protected = 0usize;
        let tree_oid = map_tree(&mut store, &target, root, &mut tree_memo, &mut blob_memo, &mut protected).unwrap();
        let cid = map_commit(&target, &snap, tree_oid, &[]).unwrap();
        target.set_ref_force("refs/heads/main", cid).unwrap();

        // git sees both files with correct modes (100644, 100755).
        let out = std::process::Command::new("git")
            .args(["--git-dir", dir.to_str().unwrap(), "ls-tree", "main"]).output().unwrap();
        let listing = String::from_utf8(out.stdout).unwrap();
        assert!(listing.contains("100644 blob") && listing.contains("main.rs"), "{listing}");
        assert!(listing.contains("100755 blob") && listing.contains("run.sh"), "{listing}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn synth_sig_parses_name_email_and_falls_back() {
        let a = synth_sig("Ada <ada@x>", 42);
        assert_eq!((a.name.as_str(), a.email.as_str(), a.time_secs), ("Ada", "ada@x", 42));
        let b = synth_sig("bare-name", 7);
        assert_eq!((b.name.as_str(), b.email.as_str(), b.time_secs), ("bare-name", "", 7));
    }

    #[test]
    fn exports_multi_commit_history_with_parents() {
        use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode, Snapshot};
        use std::collections::BTreeMap;
        let mut store = Store::new(StoreConfig::default());
        let mk = |store: &mut Store, content: &[u8], parents: Vec<scl_core::ObjectId>, msg: &str| {
            let b = store.put(Object::blob(content.to_vec())).unwrap();
            let root = store.put(Object::Tree(Tree::new(vec![
                TreeEntry { name: "a.txt".into(), kind: EntryKind::Blob, id: b, mode: FileMode::FILE, perms: 0 },
            ]))).unwrap();
            store.put(Object::Snapshot(Snapshot { root, parents, author: "t".into(), timestamp: 1, message: msg.into(), secrets: BTreeMap::new(), protection: Default::default() })).unwrap()
        };
        let c1 = mk(&mut store, b"one", vec![], "c1");
        let c2 = mk(&mut store, b"two", vec![c1], "c2");
        let c3 = mk(&mut store, b"three", vec![c2], "c3");

        let dir = std::env::temp_dir().join(format!("scl-hist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let empty = std::collections::HashMap::new();
        let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty };
        let report = export_branch(&mut store, c3, &opts).unwrap();
        assert_eq!(report.commits_written, 3);

        let out = std::process::Command::new("git")
            .args(["--git-dir", dir.to_str().unwrap(), "log", "--format=%s", "main"]).output().unwrap();
        let log = String::from_utf8(out.stdout).unwrap();
        assert_eq!(log.split_whitespace().collect::<Vec<_>>(), vec!["c3", "c2", "c1"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn re_export_is_idempotent() {
        use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode, Snapshot};
        use std::collections::BTreeMap;
        let mut store = Store::new(StoreConfig::default());
        let b = store.put(Object::blob(b"x".to_vec())).unwrap();
        let root = store.put(Object::Tree(Tree::new(vec![TreeEntry { name: "a".into(), kind: EntryKind::Blob, id: b, mode: FileMode::FILE, perms: 0 }]))).unwrap();
        let c = store.put(Object::Snapshot(Snapshot { root, parents: vec![], author: "t".into(), timestamp: 5, message: "m".into(), secrets: BTreeMap::new(), protection: Default::default() })).unwrap();

        let dir = std::env::temp_dir().join(format!("scl-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let empty = std::collections::HashMap::new();
        let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty };
        let a = export_branch(&mut store, c, &opts).unwrap();
        let b2 = export_branch(&mut store, c, &opts).unwrap();
        assert_eq!(a.git_commit, b2.git_commit);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn git_import_export_reimport_roundtrip() {
        use scl_core::{Store, StoreConfig};
        let src = std::env::temp_dir().join(format!("scl-rt-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("top.txt"), b"top").unwrap();
        std::fs::write(src.join("sub/inner.txt"), b"inner").unwrap();
        let g = |args: &[&str]| std::process::Command::new("git").args(args).current_dir(&src)
            .env("GIT_AUTHOR_NAME","t").env("GIT_AUTHOR_EMAIL","t@e")
            .env("GIT_COMMITTER_NAME","t").env("GIT_COMMITTER_EMAIL","t@e").output().unwrap();
        g(&["init","-q"]); g(&["add","."]); g(&["commit","-q","-m","init"]);

        let mut store = Store::new(StoreConfig::default());
        let snap = crate::import_head(&mut store, &src).unwrap();

        let dst = std::env::temp_dir().join(format!("scl-rt-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst);
        let empty = std::collections::HashMap::new();
        let opts = ExportOptions { to: &dst, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty };
        export_branch(&mut store, snap, &opts).unwrap();

        // Re-import our export; the tree must reconstruct the same files.
        let mut store2 = Store::new(StoreConfig::default());
        let snap2 = crate::import_head(&mut store2, &dst).unwrap();
        let root = store2.get_snapshot(&snap2).unwrap().root;
        let t = store2.get_tree(&root).unwrap();
        assert!(t.get("top.txt").is_some() && t.get("sub").is_some());

        std::fs::remove_dir_all(&src).unwrap();
        std::fs::remove_dir_all(&dst).unwrap();
    }

    // Helper: a snapshot with one PROTECTED entry and one registry secret.
    fn encrypted_snapshot(store: &mut scl_core::Store) -> scl_core::ObjectId {
        use scl_core::{Object, Tree, TreeEntry, EntryKind, FileMode, Snapshot, Secret, PROTECTED};
        use std::collections::BTreeMap;
        let ct = store.put(Object::blob(b"ciphertext-bytes".to_vec())).unwrap();
        let root = store.put(Object::Tree(Tree::new(vec![
            TreeEntry { name: "secret.txt".into(), kind: EntryKind::Blob, id: ct, mode: FileMode::FILE, perms: PROTECTED },
        ]))).unwrap();
        let sid = store.put(Object::Secret(Secret { name: "DB_URL".into(), nonce: vec![0;24], ciphertext: vec![1,2,3], wrapped_keys: vec![] })).unwrap();
        let mut secrets = BTreeMap::new();
        secrets.insert("DB_URL".to_string(), sid);
        store.put(Object::Snapshot(Snapshot { root, parents: vec![], author: "t".into(), timestamp: 1, message: "enc".into(), secrets, protection: Default::default() })).unwrap()
    }

    #[test]
    fn refuses_encrypted_without_flag() {
        let mut store = scl_core::Store::new(scl_core::StoreConfig::default());
        let snap = encrypted_snapshot(&mut store);
        let dir = std::env::temp_dir().join(format!("scl-refuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let empty = std::collections::HashMap::new();
        let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty };
        let err = export_branch(&mut store, snap, &opts).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("secret.txt") && msg.contains("DB_URL"), "error must name both the protected path and the secret: {msg}");
        assert!(!dir.exists(), "no git repo should be created on refusal");
    }

    #[test]
    fn exports_encrypted_with_flag_drops_secrets() {
        let mut store = scl_core::Store::new(scl_core::StoreConfig::default());
        let snap = encrypted_snapshot(&mut store);
        let dir = std::env::temp_dir().join(format!("scl-allow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let empty = std::collections::HashMap::new();
        let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: true, known_git_commits: &empty };
        let report = export_branch(&mut store, snap, &opts).unwrap();
        assert_eq!(report.protected_blobs_as_ciphertext, 1);
        assert_eq!(report.secrets_dropped, 1);
        // The protected file exists in git as its ciphertext; no secret file exists.
        let out = std::process::Command::new("git").args(["--git-dir", dir.to_str().unwrap(), "ls-tree", "main"]).output().unwrap();
        let listing = String::from_utf8(out.stdout).unwrap();
        assert!(listing.contains("secret.txt"));
        assert!(!listing.contains("DB_URL"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn scan_dedups_shared_subtree() {
        // Build a snapshot whose root tree references the SAME subtree object
        // under two different names ("a" and "b"). The subtree contains one
        // PROTECTED file ("key"). scan_tree must visit the shared object only
        // once (dedup guard) yet still detect the protected content and cause
        // export_branch to refuse without --include-encrypted.
        use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode, Snapshot, PROTECTED};
        use std::collections::BTreeMap;

        let mut store = Store::new(StoreConfig::default());

        // Protected blob inside the shared subtree.
        let ct = store.put(Object::blob(b"ciphertext".to_vec())).unwrap();
        // The shared subtree — built once, referenced twice.
        let shared_sub = store.put(Object::Tree(Tree::new(vec![
            TreeEntry { name: "key".into(), kind: EntryKind::Blob, id: ct, mode: FileMode::FILE, perms: PROTECTED },
        ]))).unwrap();
        // Root tree: entries "a" and "b" both point at shared_sub.
        let root = store.put(Object::Tree(Tree::new(vec![
            TreeEntry { name: "a".into(), kind: EntryKind::Tree, id: shared_sub, mode: FileMode::FILE, perms: 0 },
            TreeEntry { name: "b".into(), kind: EntryKind::Tree, id: shared_sub, mode: FileMode::FILE, perms: 0 },
        ]))).unwrap();
        let snap = store.put(Object::Snapshot(Snapshot {
            root,
            parents: vec![],
            author: "t".into(),
            timestamp: 1,
            message: "shared".into(),
            secrets: BTreeMap::new(),
            protection: Default::default(),
        })).unwrap();

        let dir = std::env::temp_dir().join(format!("scl-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let empty = std::collections::HashMap::new();
        let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty };
        let err = export_branch(&mut store, snap, &opts).unwrap_err();
        let msg = format!("{err:#}");
        // The scan must have found the protected content and refused.
        assert!(msg.contains("key"), "error must name the protected path: {msg}");
        // No git repo should have been created.
        assert!(!dir.exists(), "no git repo should be created on refusal");
    }

    #[test]
    fn blob_commit_ref_roundtrip() {
        let dir = std::env::temp_dir().join(format!("scl-gixrt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = GitTarget::open_or_init_bare(&dir).unwrap();
        let b = t.write_blob(b"hello").unwrap();
        let tree = t.write_tree(vec![GitTreeEntry { name: "f.txt".into(), mode: GitMode::File, oid: b }]).unwrap();
        let sig = GitSig { name: "Ada".into(), email: "ada@x".into(), time_secs: 1_700_000_000 };
        let c = t.write_commit(tree, &[], &sig, "init").unwrap();
        t.set_ref_force("refs/heads/main", c).unwrap();
        assert!(t.created, "a fresh init_bare must report created=true");
        t.set_head("refs/heads/main").unwrap();
        // git resolves the commit via HEAD (no explicit ref) — proves set_head worked.
        let out = git(&dir, &["--git-dir", dir.to_str().unwrap(), "log", "--format=%s", "-1"]);
        assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "init");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn export_reuses_known_marks_and_reports_new_ones() {
        use crate::{import_history, ImportReport};
        use scl_core::StoreConfig;
        use std::collections::HashMap;

        // Build a 2-commit sc history by importing from a throwaway git repo.
        let gsrc = std::env::temp_dir().join(format!("scl-exp-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&gsrc);
        std::fs::create_dir_all(&gsrc).unwrap();
        git(&gsrc, &["init", "-q", "-b", "main"]);
        std::fs::write(gsrc.join("a"), b"1").unwrap();
        git(&gsrc, &["add", "."]); git(&gsrc, &["commit", "-q", "-m", "c1"]);
        std::fs::write(gsrc.join("a"), b"2").unwrap();
        git(&gsrc, &["add", "."]); git(&gsrc, &["commit", "-q", "-m", "c2"]);

        let mut store = Store::new(StoreConfig::default());
        let ImportReport { tip, .. } = import_history(&mut store, &gsrc, "main", &HashMap::new()).unwrap();

        // First export: empty known-map => all commits written and reported.
        let dst = std::env::temp_dir().join(format!("scl-exp-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst);
        let empty: HashMap<ObjectId, String> = HashMap::new();
        let opts = ExportOptions {
            to: &dst, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty,
        };
        let rep1 = export_branch(&mut store, tip, &opts).unwrap();
        assert_eq!(rep1.new_marks.len(), 2);

        // read_ref sees the tip we just wrote.
        let tip_git = read_ref(&dst, "refs/heads/main").unwrap();
        assert_eq!(tip_git.as_deref(), Some(rep1.git_commit.as_str()));

        // Second export with ALL commits known: nothing new written.
        let known: HashMap<ObjectId, String> =
            rep1.new_marks.iter().map(|(g, s)| (*s, g.clone())).collect();
        let opts2 = ExportOptions {
            to: &dst, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &known,
        };
        let rep2 = export_branch(&mut store, tip, &opts2).unwrap();
        assert!(rep2.new_marks.is_empty());
        assert_eq!(rep2.git_commit, rep1.git_commit); // same tip oid

        std::fs::remove_dir_all(&gsrc).unwrap();
        std::fs::remove_dir_all(&dst).unwrap();
    }

    #[test]
    fn export_drops_signatures_with_count() {
        use scl_core::{Object, Store, StoreConfig, Tree, TreeEntry, EntryKind, FileMode, Snapshot, SignatureObj};
        use std::collections::BTreeMap;

        let mut store = Store::new(StoreConfig::default());
        let b = store.put(Object::blob(b"x".to_vec())).unwrap();
        let root = store.put(Object::Tree(Tree::new(vec![
            TreeEntry { name: "a".into(), kind: EntryKind::Blob, id: b, mode: FileMode::FILE, perms: 0 },
        ]))).unwrap();
        let snap = store.put(Object::Snapshot(Snapshot {
            root, parents: vec![], author: "t".into(), timestamp: 1, message: "m".into(),
            secrets: BTreeMap::new(), protection: Default::default(),
        })).unwrap();
        // A signature object over `snap`, no fail-closed gate over it (unlike
        // protected content/secrets) — bytes don't need to be a real Ed25519
        // signature for this test since export never verifies them.
        store.put(Object::Signature(SignatureObj { snapshot: snap, signer: [1u8; 32], sig: [2u8; 64] })).unwrap();

        let dir = std::env::temp_dir().join(format!("scl-sigdrop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let empty = std::collections::HashMap::new();
        let opts = ExportOptions { to: &dir, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty };
        let report = export_branch(&mut store, snap, &opts).unwrap();
        assert_eq!(report.signatures_dropped, 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stale_mark_mid_chain_resynthesizes_with_valid_parents() {
        use crate::{import_history, ImportReport};
        use scl_core::StoreConfig;
        use std::collections::HashMap;

        // Build a 3-commit sc history A→B→C by importing from a throwaway git repo.
        // Corrupt the mark for the MIDDLE commit B; verify the re-synthesized B has
        // a valid parent chain (C's parent = B', B's parent = A), following the
        // stale_mark_is_skipped_so_pruned_parent_is_reimported pattern from import.rs.
        let gsrc = std::env::temp_dir().join(format!("scl-exp-stale-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&gsrc);
        std::fs::create_dir_all(&gsrc).unwrap();
        git(&gsrc, &["init", "-q", "-b", "main"]);
        std::fs::write(gsrc.join("a"), b"1").unwrap();
        git(&gsrc, &["add", "."]); git(&gsrc, &["commit", "-q", "-m", "A"]);
        std::fs::write(gsrc.join("a"), b"2").unwrap();
        git(&gsrc, &["add", "."]); git(&gsrc, &["commit", "-q", "-m", "B"]);
        std::fs::write(gsrc.join("a"), b"3").unwrap();
        git(&gsrc, &["add", "."]); git(&gsrc, &["commit", "-q", "-m", "C"]);

        let mut store = Store::new(StoreConfig::default());
        let ImportReport { tip: sc_c, .. } = import_history(&mut store, &gsrc, "main", &HashMap::new()).unwrap();

        // Export once and recover marks by message.
        let dst = std::env::temp_dir().join(format!("scl-exp-stale-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst);
        let empty: HashMap<ObjectId, String> = HashMap::new();
        let opts = ExportOptions {
            to: &dst, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &empty,
        };
        let rep1 = export_branch(&mut store, sc_c, &opts).unwrap();
        assert_eq!(rep1.new_marks.len(), 3);

        // Recover sc ids for A, B, C and their git oids by message.
        let mut marks_by_msg: HashMap<String, (ObjectId, String)> = HashMap::new();
        for (git_hex, sc_id) in &rep1.new_marks {
            let snap = store.get_snapshot(sc_id).unwrap();
            marks_by_msg.insert(snap.message, (*sc_id, git_hex.clone()));
        }
        let (sc_a, git_a) = marks_by_msg.get("A").expect("mark for A").clone();
        let (sc_b, _git_b) = marks_by_msg.get("B").expect("mark for B").clone();

        // Corrupt the mark for B (the middle commit). Don't provide C's mark so
        // it gets re-synthesized too (C's parent changes when B is re-synthesized).
        let mut stale: HashMap<ObjectId, String> = HashMap::new();
        stale.insert(sc_a, git_a.clone());
        stale.insert(sc_b, "a".repeat(40)); // valid hex but nonexistent oid

        // Re-export with the stale mark for B: must report stale_marks == 1,
        // re-synthesize B and C (C's parent changes), and leave a valid, unbroken parent chain.
        let opts2 = ExportOptions {
            to: &dst, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &stale,
        };
        let rep2 = export_branch(&mut store, sc_c, &opts2).unwrap();
        assert_eq!(rep2.stale_marks, 1, "exactly one stale mark (B) should be detected");
        assert_eq!(rep2.new_marks.len(), 2, "B and C should be re-synthesized (C's parent changed)");
        // Find B and C in new_marks; both should be present.
        let has_b = rep2.new_marks.iter().any(|(_, sc_id)| *sc_id == sc_b);
        let has_c = rep2.new_marks.iter().any(|(_, sc_id)| *sc_id == sc_c);
        assert!(has_b, "B should be in new_marks");
        assert!(has_c, "C should be in new_marks");

        // Walk the Git history from the ref to prove the parent chain is valid.
        let out = git(&dst, &["--git-dir", dst.to_str().unwrap(), "log", "--format=%H %s", "refs/heads/main"]);
        let log = String::from_utf8(out.stdout).unwrap();
        let mut log_lines: Vec<&str> = log.lines().collect();
        log_lines.reverse(); // root-to-tip order
        assert_eq!(log_lines.len(), 3, "history should have 3 commits");
        assert!(log_lines[0].ends_with(" A"), "commit 0 should be A");
        assert!(log_lines[1].ends_with(" B"), "commit 1 should be B");
        assert!(log_lines[2].ends_with(" C"), "commit 2 should be C");

        // Verify each commit's parent is correct by parsing git log output.
        let out = git(&dst, &["--git-dir", dst.to_str().unwrap(), "log", "--format=%H %P", "refs/heads/main"]);
        let log = String::from_utf8(out.stdout).unwrap();
        let mut commits: Vec<(&str, &str)> = log.lines().map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            (parts[0], if parts.len() > 1 { parts[1] } else { "" })
        }).collect();
        commits.reverse(); // root-to-tip order
        assert_eq!(commits[1].1, commits[0].0, "B's parent should be A");
        assert_eq!(commits[2].1, commits[1].0, "C's parent should be B");
        // A is root, so parent should be empty.
        assert_eq!(commits[0].1, "", "A (root) should have no parent");

        // Third export: use healed marks (original A + new B,C marks from rep2).
        let mut healed: HashMap<ObjectId, String> = HashMap::new();
        healed.insert(sc_a, git_a);
        // Extract new marks for B and C from rep2.
        for (git_hex, sc_id) in &rep2.new_marks {
            healed.insert(*sc_id, git_hex.clone());
        }

        let opts3 = ExportOptions {
            to: &dst, ref_name: "refs/heads/main", include_encrypted: false, known_git_commits: &healed,
        };
        let rep3 = export_branch(&mut store, sc_c, &opts3).unwrap();
        assert_eq!(rep3.stale_marks, 0, "no stale marks after healing");
        assert!(rep3.new_marks.is_empty(), "no new marks after healing (all reused)");

        std::fs::remove_dir_all(&gsrc).unwrap();
        std::fs::remove_dir_all(&dst).unwrap();
    }
}
