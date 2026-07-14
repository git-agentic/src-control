use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use scl_core::{FileMode, Object, ObjectId, Snapshot, PROTECTED};
use scl_repo::{refs, Repo, SigStatus};
use serde::{Deserialize, Serialize};

/// A display-safe error returned across the desktop read-model boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadModelError {
    /// Stable renderer-facing category.
    pub kind: String,
    /// Human-readable detail with no repository bytes or key material.
    pub message: String,
}

impl ReadModelError {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
        }
    }

    fn from_repo(error: scl_repo::Error) -> Self {
        let kind = match &error {
            scl_repo::Error::NotARepo => "not_a_repository",
            scl_repo::Error::Locked(_) => "repository_busy",
            scl_repo::Error::CorruptObject(_)
            | scl_repo::Error::BadRef(_)
            | scl_repo::Error::Core(scl_core::Error::Malformed(_))
            | scl_repo::Error::Core(scl_core::Error::PackCorrupt(_))
            | scl_repo::Error::Core(scl_core::Error::BadPackIndex(_)) => "corrupt_repository",
            scl_repo::Error::Core(scl_core::Error::NotFound(_)) => "unavailable_object",
            _ => "repository_error",
        };
        let message = match kind {
            "not_a_repository" => "The selected directory is not a src-control repository.",
            "repository_busy" => "The repository is busy in another src-control process.",
            "corrupt_repository" => "The repository contains invalid or corrupt native data.",
            "unavailable_object" => "A required object is unavailable in this repository.",
            _ => "The repository could not be read.",
        };
        Self::new(kind, message)
    }
}

impl std::fmt::Display for ReadModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for ReadModelError {}

/// Whether a ref resolves to ordinary public history or an opaque private
/// manifest that this keyless phase deliberately does not open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceAccess {
    Public,
    PrivateOpaque,
}

/// Manifest metadata that is public by the private-branch threat model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueMetadata {
    pub sealed_object_count: usize,
    pub recipient_count: usize,
    pub public_fork_point: String,
}

/// One local or remote-tracking repository reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub current: bool,
    pub tip: String,
    pub access: ReferenceAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<OpaqueMetadata>,
}

/// Initial read model returned after a repository is selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryOverview {
    pub root: String,
    pub name: String,
    pub current_branch: String,
    pub references: Vec<ReferenceView>,
}

/// Signature verification state for a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureView {
    Trusted { signer: String },
    Untrusted { signer: String },
    Invalid,
    Unsigned,
}

/// One node in a native snapshot DAG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotNode {
    pub id: String,
    pub author: String,
    pub timestamp: i64,
    pub message: String,
    pub parents: Vec<String>,
    pub is_merge: bool,
    pub signature: SignatureView,
    pub transcript_count: usize,
    pub secret_count: usize,
    pub labels: Vec<String>,
}

/// Public history selected from the ref rail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryView {
    pub reference: ReferenceView,
    pub snapshots: Vec<SnapshotNode>,
}

/// Renderer-safe content. The protected variant deliberately contains no byte
/// field, so ciphertext cannot be confused with source code by construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ContentView {
    Text { text: String, size: usize },
    Binary { size: usize },
    TooLarge { size: usize },
    ProtectedLocked,
    Unavailable { reason: String },
}

/// Coarse content state used by the repository tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentState {
    PublicAvailable,
    ProtectedLocked,
    Unavailable,
}

/// One flattened public file entry for the renderer's replaceable tree view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeFileView {
    pub path: String,
    pub name: String,
    pub mode: u32,
    pub content_state: ContentState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
}

/// Public file response for a single snapshot path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileView {
    pub path: String,
    pub content: ContentView,
}

/// File-level first-parent change classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Protected,
}

/// One change with renderer-safe old/new content where available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileChangeView {
    pub path: String,
    pub kind: ChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<ContentView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<ContentView>,
}

/// A snapshot compared with its first parent (or the empty tree at the root).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparisonView {
    pub snapshot_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub changes: Vec<FileChangeView>,
}

/// Complete inspector read model for one reachable public snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SnapshotDetails {
    pub snapshot: SnapshotNode,
    pub tree: Vec<TreeFileView>,
    pub comparison: ComparisonView,
}

/// A selected repository root. It retains only a path; every query opens and
/// releases the native repository handle so Phase 35 does not invent a second
/// long-lived locking model.
#[derive(Clone, Debug)]
pub struct DesktopRepository {
    root: PathBuf,
    /// Public snapshots already exposed by a selected history. Clones share
    /// this session cache so subsequent file and diff reads stay O(1) without
    /// weakening the public-reachability check.
    reachable: Arc<RwLock<HashSet<ObjectId>>>,
}

impl DesktopRepository {
    /// Validate and remember an existing native `.sc` repository.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReadModelError> {
        let repo = Repo::open(path).map_err(ReadModelError::from_repo)?;
        let root = repo.layout().root.canonicalize().map_err(|_error| {
            ReadModelError::new(
                "repository_error",
                "The repository path could not be resolved.",
            )
        })?;
        drop(repo);
        Ok(Self {
            root,
            reachable: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    /// Canonical repository root retained in backend state.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// List local and remote-tracking refs without opening any private branch.
    pub fn overview(&self) -> Result<RepositoryOverview, ReadModelError> {
        let repo = self.repo()?;
        let current_branch =
            refs::current_branch(repo.layout()).map_err(ReadModelError::from_repo)?;
        let references = collect_references(&repo, &current_branch)?;
        let name = self
            .root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.root.display().to_string());
        Ok(RepositoryOverview {
            root: self.root.display().to_string(),
            name,
            current_branch,
            references,
        })
    }

    /// Walk all parents of a selected public ref, preserving merge topology.
    pub fn select_reference(&self, reference_id: &str) -> Result<HistoryView, ReadModelError> {
        let repo = self.repo()?;
        let current = refs::current_branch(repo.layout()).map_err(ReadModelError::from_repo)?;
        let references = collect_references(&repo, &current)?;
        let reference = references
            .iter()
            .find(|reference| reference.id == reference_id)
            .cloned()
            .ok_or_else(|| {
                ReadModelError::new(
                    "invalid_selection",
                    "reference is not present in the selected repository",
                )
            })?;
        if reference.access == ReferenceAccess::PrivateOpaque {
            return Ok(HistoryView {
                reference,
                snapshots: Vec::new(),
            });
        }

        let tip = reference.tip.parse::<ObjectId>().map_err(|_| {
            ReadModelError::new(
                "corrupt_repository",
                "selected reference has an invalid object id",
            )
        })?;
        let labels = labels_by_tip(&references);
        let trust = load_trust_map(repo.layout().dot_sc.join("recipients.toml").as_path())?;
        let transcript_index =
            scl_repo::transcripts::load(repo.layout()).map_err(ReadModelError::from_repo)?;
        let mut transcript_counts: HashMap<ObjectId, usize> = HashMap::new();
        for (snapshot, _) in transcript_index {
            *transcript_counts.entry(snapshot).or_default() += 1;
        }

        let mut snapshots = Vec::new();
        let mut stack = vec![tip];
        let mut seen = HashSet::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let snapshot = get_snapshot(&repo, &id)?;
            for parent in snapshot.parents.iter().rev() {
                stack.push(*parent);
            }
            snapshots.push(snapshot_node(
                &repo,
                id,
                snapshot,
                transcript_counts.get(&id).copied().unwrap_or(0),
                labels.get(&id).cloned().unwrap_or_default(),
                &trust,
            )?);
        }
        self.reachable
            .write()
            .map_err(|_| {
                ReadModelError::new(
                    "repository_error",
                    "repository session state is unavailable",
                )
            })?
            .extend(seen);
        Ok(HistoryView {
            reference,
            snapshots,
        })
    }

    /// Metadata, public tree, and first-parent change summary for a reachable
    /// public snapshot.
    pub fn snapshot_details(&self, snapshot_id: &str) -> Result<SnapshotDetails, ReadModelError> {
        let repo = self.repo()?;
        let id = self.reachable_snapshot(&repo, snapshot_id)?;
        let snapshot = get_snapshot(&repo, &id)?;
        let references = collect_references(
            &repo,
            &refs::current_branch(repo.layout()).map_err(ReadModelError::from_repo)?,
        )?;
        let labels = labels_by_tip(&references).remove(&id).unwrap_or_default();
        let transcript_count = scl_repo::transcripts::load(repo.layout())
            .map_err(ReadModelError::from_repo)?
            .into_iter()
            .filter(|(attached, _)| *attached == id)
            .count();
        let trust = load_trust_map(repo.layout().dot_sc.join("recipients.toml").as_path())?;
        let node = snapshot_node(
            &repo,
            id,
            snapshot.clone(),
            transcript_count,
            labels,
            &trust,
        )?;
        let tree = tree_view(&repo, &snapshot)?;
        let comparison = comparison_view(&repo, id, &snapshot)?;
        Ok(SnapshotDetails {
            snapshot: node,
            tree,
            comparison,
        })
    }

    /// Read one public file. Protected entries return a lock state without
    /// loading their blob bytes from the store.
    pub fn read_file(&self, snapshot_id: &str, path: &str) -> Result<FileView, ReadModelError> {
        validate_relative_path(path)?;
        let repo = self.repo()?;
        let id = self.reachable_snapshot(&repo, snapshot_id)?;
        let snapshot = get_snapshot(&repo, &id)?;
        let entries = file_entries(&repo, snapshot.root)?;
        let entry = entries.get(path).ok_or_else(|| {
            ReadModelError::new(
                "invalid_selection",
                "file is not present in the selected snapshot",
            )
        })?;
        Ok(FileView {
            path: path.to_string(),
            content: content_view(&repo, entry)?,
        })
    }

    /// Compare a reachable snapshot with its first parent.
    pub fn compare_first_parent(
        &self,
        snapshot_id: &str,
        path: &str,
    ) -> Result<FileChangeView, ReadModelError> {
        validate_relative_path(path)?;
        let repo = self.repo()?;
        let id = self.reachable_snapshot(&repo, snapshot_id)?;
        let snapshot = get_snapshot(&repo, &id)?;
        let after = file_entries(&repo, snapshot.root)?;
        let before = match snapshot.parents.first().copied() {
            Some(parent) => file_entries(&repo, get_snapshot(&repo, &parent)?.root)?,
            None => Default::default(),
        };
        let old = before.get(path);
        let new = after.get(path);
        if old == new {
            return Err(ReadModelError::new(
                "invalid_selection",
                "file is not changed from the snapshot's first parent",
            ));
        }
        file_change_view(&repo, path, old, new, true)
    }

    fn reachable_snapshot(
        &self,
        repo: &Repo,
        snapshot_id: &str,
    ) -> Result<ObjectId, ReadModelError> {
        let wanted = snapshot_id.parse::<ObjectId>().map_err(|_| {
            ReadModelError::new("invalid_selection", "snapshot id is not a native object id")
        })?;
        if self
            .reachable
            .read()
            .map_err(|_| {
                ReadModelError::new(
                    "repository_error",
                    "repository session state is unavailable",
                )
            })?
            .contains(&wanted)
        {
            return Ok(wanted);
        }
        let current = refs::current_branch(repo.layout()).map_err(ReadModelError::from_repo)?;
        let references = collect_references(repo, &current)?;
        let mut stack = Vec::new();
        for reference in references
            .iter()
            .filter(|reference| reference.access == ReferenceAccess::Public)
        {
            if let Ok(id) = reference.tip.parse::<ObjectId>() {
                stack.push(id);
            }
        }
        let mut seen = HashSet::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if id == wanted {
                self.reachable
                    .write()
                    .map_err(|_| {
                        ReadModelError::new(
                            "repository_error",
                            "repository session state is unavailable",
                        )
                    })?
                    .extend(seen);
                return Ok(id);
            }
            stack.extend(get_snapshot(repo, &id)?.parents);
        }
        Err(ReadModelError::new(
            "invalid_selection",
            "snapshot is not reachable from a public reference in the selected repository",
        ))
    }

    fn repo(&self) -> Result<Repo, ReadModelError> {
        Repo::open(&self.root).map_err(ReadModelError::from_repo)
    }
}

type FileEntry = (ObjectId, FileMode, u8);

fn file_entries(
    repo: &Repo,
    root: ObjectId,
) -> Result<std::collections::BTreeMap<String, FileEntry>, ReadModelError> {
    let store = repo.store();
    let mut store = store.lock().map_err(|_| {
        ReadModelError::new("repository_error", "repository object cache is unavailable")
    })?;
    scl_repo::worktree::tree_file_entries_with_perms(&mut store, root)
        .map_err(ReadModelError::from_repo)
}

fn content_view(repo: &Repo, entry: &FileEntry) -> Result<ContentView, ReadModelError> {
    let (id, _, perms) = entry;
    if perms & PROTECTED != 0 {
        return Ok(ContentView::ProtectedLocked);
    }
    let store = repo.store();
    let mut store = store.lock().map_err(|_| {
        ReadModelError::new("repository_error", "repository object cache is unavailable")
    })?;
    let size = match store.blob_size(id) {
        Ok(size) => size,
        Err(scl_core::Error::NotFound(_)) => {
            return Ok(ContentView::Unavailable {
                reason: "This object is not available in the partial repository.".into(),
            });
        }
        Err(scl_core::Error::WrongKind(_, _)) => {
            return Err(ReadModelError::new(
                "corrupt_repository",
                format!("file object {id} is not a blob"),
            ));
        }
        Err(error) => return Err(ReadModelError::from_repo(error.into())),
    };
    const MAX_RENDER_BYTES: usize = 4 * 1024 * 1024;
    if size > MAX_RENDER_BYTES {
        return Ok(ContentView::TooLarge { size });
    }
    let object = store.get(id);
    let bytes = match object {
        Ok(Object::Blob(bytes)) => bytes,
        Ok(_) => {
            return Err(ReadModelError::new(
                "corrupt_repository",
                format!("file object {id} is not a blob"),
            ))
        }
        Err(scl_core::Error::NotFound(_)) => {
            return Ok(ContentView::Unavailable {
                reason: "This object is not available in the partial repository.".into(),
            })
        }
        Err(error) => return Err(ReadModelError::from_repo(error.into())),
    };
    debug_assert_eq!(bytes.len(), size);
    if bytes.contains(&0) {
        return Ok(ContentView::Binary { size });
    }
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => Ok(ContentView::Text { text, size }),
        Err(_) => Ok(ContentView::Binary { size }),
    }
}

fn tree_view(repo: &Repo, snapshot: &Snapshot) -> Result<Vec<TreeFileView>, ReadModelError> {
    let entries = file_entries(repo, snapshot.root)?;
    let store = repo.store();
    let store = store.lock().map_err(|_| {
        ReadModelError::new("repository_error", "repository object cache is unavailable")
    })?;
    entries
        .into_iter()
        .map(|(path, entry)| {
            // Tree enumeration is metadata-only. Public blob bytes are loaded
            // only after the user selects one file; protected bytes are never
            // loaded by this adapter.
            let content_state = if entry.2 & PROTECTED != 0 {
                ContentState::ProtectedLocked
            } else if !store.contains(&entry.0) {
                ContentState::Unavailable
            } else {
                ContentState::PublicAvailable
            };
            let name = path
                .rsplit('/')
                .next()
                .expect("a tree file path always has a final component")
                .to_string();
            Ok(TreeFileView {
                path,
                name,
                mode: entry.1 .0,
                content_state,
                size: None,
            })
        })
        .collect()
}

fn comparison_view(
    repo: &Repo,
    id: ObjectId,
    snapshot: &Snapshot,
) -> Result<ComparisonView, ReadModelError> {
    let after = file_entries(repo, snapshot.root)?;
    let parent_id = snapshot.parents.first().copied();
    let before = match parent_id {
        Some(parent) => file_entries(repo, get_snapshot(repo, &parent)?.root)?,
        None => Default::default(),
    };
    let mut paths: std::collections::BTreeSet<&String> = before.keys().collect();
    paths.extend(after.keys());
    let mut changes = Vec::new();
    for path in paths {
        let old = before.get(path);
        let new = after.get(path);
        if old == new {
            continue;
        }
        changes.push(file_change_view(repo, path, old, new, false)?);
    }
    Ok(ComparisonView {
        snapshot_id: id.to_hex(),
        parent_id: parent_id.map(|parent| parent.to_hex()),
        changes,
    })
}

fn file_change_view(
    repo: &Repo,
    path: &str,
    old: Option<&FileEntry>,
    new: Option<&FileEntry>,
    include_content: bool,
) -> Result<FileChangeView, ReadModelError> {
    let protected = old.is_some_and(|entry| entry.2 & PROTECTED != 0)
        || new.is_some_and(|entry| entry.2 & PROTECTED != 0);
    let kind = if protected {
        ChangeKind::Protected
    } else {
        match (old, new) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Deleted,
            (Some(_), Some(_)) => ChangeKind::Modified,
            (None, None) => {
                return Err(ReadModelError::new(
                    "invalid_selection",
                    "file is absent from both sides of the comparison",
                ))
            }
        }
    };
    Ok(FileChangeView {
        path: path.to_string(),
        kind,
        before: if include_content {
            old.map(|entry| content_view(repo, entry)).transpose()?
        } else {
            None
        },
        after: if include_content {
            new.map(|entry| content_view(repo, entry)).transpose()?
        } else {
            None
        },
    })
}

fn validate_relative_path(path: &str) -> Result<(), ReadModelError> {
    let valid = !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..");
    if valid {
        Ok(())
    } else {
        Err(ReadModelError::new(
            "invalid_selection",
            "file path is not a canonical repository-relative path",
        ))
    }
}

fn collect_references(repo: &Repo, current: &str) -> Result<Vec<ReferenceView>, ReadModelError> {
    let mut references = Vec::new();
    for (name, tip) in refs::list_heads(repo.layout()).map_err(ReadModelError::from_repo)? {
        references.push(reference_view(
            repo,
            format!("local:{name}"),
            name.clone(),
            "local",
            name == current,
            tip,
        )?);
    }
    for (remote, branch, tip) in
        refs::list_remote_tips(repo.layout()).map_err(ReadModelError::from_repo)?
    {
        let name = format!("{remote}/{branch}");
        references.push(reference_view(
            repo,
            format!("remote:{name}"),
            name,
            "remote",
            false,
            tip,
        )?);
    }
    references.sort_by(|left, right| {
        (left.kind.as_str() != "local", left.name.as_str())
            .cmp(&(right.kind.as_str() != "local", right.name.as_str()))
    });
    Ok(references)
}

fn reference_view(
    repo: &Repo,
    id: String,
    name: String,
    kind: &str,
    current: bool,
    tip: ObjectId,
) -> Result<ReferenceView, ReadModelError> {
    let object = repo
        .store()
        .lock()
        .map_err(|_| {
            ReadModelError::new("repository_error", "repository object cache is unavailable")
        })?
        .get(&tip)
        .map_err(|error| ReadModelError::from_repo(error.into()))?;
    let (access, opaque) = match object {
        Object::Manifest(manifest) => (
            ReferenceAccess::PrivateOpaque,
            Some(OpaqueMetadata {
                sealed_object_count: manifest.closure.len(),
                recipient_count: manifest.kek_wraps.len(),
                public_fork_point: manifest.base.to_hex(),
            }),
        ),
        Object::Snapshot(_) => (ReferenceAccess::Public, None),
        _ => {
            return Err(ReadModelError::new(
                "corrupt_repository",
                format!("reference {name} points to a non-snapshot object"),
            ))
        }
    };
    Ok(ReferenceView {
        id,
        name,
        kind: kind.to_string(),
        current,
        tip: tip.to_hex(),
        access,
        opaque,
    })
}

fn get_snapshot(repo: &Repo, id: &ObjectId) -> Result<Snapshot, ReadModelError> {
    repo.store()
        .lock()
        .map_err(|_| {
            ReadModelError::new("repository_error", "repository object cache is unavailable")
        })?
        .get_snapshot(id)
        .map_err(|error| ReadModelError::from_repo(error.into()))
}

fn labels_by_tip(references: &[ReferenceView]) -> HashMap<ObjectId, Vec<String>> {
    let mut labels: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for reference in references
        .iter()
        .filter(|reference| reference.access == ReferenceAccess::Public)
    {
        if let Ok(tip) = reference.tip.parse::<ObjectId>() {
            labels.entry(tip).or_default().push(reference.name.clone());
        }
    }
    labels
}

fn snapshot_node(
    repo: &Repo,
    id: ObjectId,
    snapshot: Snapshot,
    transcript_count: usize,
    labels: Vec<String>,
    trust: &HashMap<[u8; 32], String>,
) -> Result<SnapshotNode, ReadModelError> {
    let signature = match repo
        .sig_status(&id, trust)
        .map_err(ReadModelError::from_repo)?
    {
        SigStatus::Trusted(signer) => SignatureView::Trusted { signer },
        SigStatus::Untrusted(signer) => SignatureView::Untrusted {
            signer: signer.iter().map(|byte| format!("{byte:02x}")).collect(),
        },
        SigStatus::Invalid => SignatureView::Invalid,
        SigStatus::Unsigned => SignatureView::Unsigned,
    };
    Ok(SnapshotNode {
        id: id.to_hex(),
        author: snapshot.author,
        timestamp: snapshot.timestamp,
        message: snapshot.message,
        parents: snapshot.parents.iter().map(ObjectId::to_hex).collect(),
        is_merge: snapshot.parents.len() > 1,
        signature,
        transcript_count,
        secret_count: snapshot.secrets.len(),
        labels,
    })
}

#[derive(Default, Deserialize)]
struct PublicTrustConfig {
    #[serde(default)]
    signing: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    signers: TrustedSigners,
}

#[derive(Default, Deserialize)]
struct TrustedSigners {
    #[serde(default)]
    trusted: Vec<String>,
}

/// Load only public signing keys and trust labels. The desktop adapter never
/// parses an identity file and therefore cannot introduce private-key bytes
/// into its process state or IPC responses.
fn load_trust_map(path: &Path) -> Result<HashMap<[u8; 32], String>, ReadModelError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(_error) => {
            return Err(ReadModelError::new(
                "repository_error",
                "The public signer configuration could not be read.",
            ));
        }
    };
    let config: PublicTrustConfig = toml::from_str(&text).map_err(|_error| {
        ReadModelError::new(
            "corrupt_repository",
            "The public signer configuration is invalid.",
        )
    })?;
    let mut trust = HashMap::new();
    for name in config.signers.trusted {
        let encoded = config.signing.get(&name).ok_or_else(|| {
            ReadModelError::new(
                "corrupt_repository",
                format!("trusted signer '{name}' has no public signing key"),
            )
        })?;
        let key = scl_crypto::SigPublicKey::from_key_string(encoded).map_err(|_| {
            ReadModelError::new(
                "corrupt_repository",
                format!("trusted signer '{name}' has an invalid public signing key"),
            )
        })?;
        trust.insert(key.to_bytes(), name);
    }
    Ok(trust)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "scl-desktop-{tag}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn native_repository_opens_and_exposes_snapshot_metadata() {
        let root = temp_root("tracer");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("README.md"), "native model\n").unwrap();
        let tip = repo
            .commit("Ada <ada@example.com>", "first snapshot")
            .unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let overview = desktop.overview().unwrap();
        assert_eq!(overview.current_branch, "main");
        assert_eq!(overview.references.len(), 1);
        assert_eq!(overview.references[0].tip, tip.to_hex());

        let history = desktop.select_reference("local:main").unwrap();
        let node = &history.snapshots[0];
        assert_eq!(node.id, tip.to_hex());
        assert_eq!(node.author, "Ada <ada@example.com>");
        assert_eq!(node.message, "first snapshot");
        assert!(!node.is_merge);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn public_trust_configuration_names_a_verified_snapshot_signer() {
        let root = temp_root("trusted-signature");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("README.md"), "signed native model\n").unwrap();
        let tip = repo.commit("Ada", "signed snapshot").unwrap();
        let (_, identity) = scl_crypto::generate_identity_v2();
        let public = identity.signing.as_ref().unwrap().public().to_key_string();
        repo.sign_snapshot(tip, &identity).unwrap();
        std::fs::write(
            repo.layout().dot_sc.join("recipients.toml"),
            format!("[signing]\nada = \"{public}\"\n\n[signers]\ntrusted = [\"ada\"]\n"),
        )
        .unwrap();
        drop(identity);
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let history = desktop.select_reference("local:main").unwrap();
        assert_eq!(
            history.snapshots[0].signature,
            SignatureView::Trusted {
                signer: "ada".into()
            }
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_tracking_branches_and_binary_files_are_read_honestly() {
        let root = temp_root("remote-binary");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("image.bin"), [0_u8, 1, 2, 3]).unwrap();
        let tip = repo.commit("Ada", "binary snapshot").unwrap();
        scl_repo::refs::write_remote_tip(repo.layout(), "origin", "main", &tip).unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let overview = desktop.overview().unwrap();
        assert!(overview.references.iter().any(|reference| {
            reference.id == "remote:origin/main" && reference.kind == "remote"
        }));
        assert_eq!(
            desktop
                .read_file(&tip.to_hex(), "image.bin")
                .unwrap()
                .content,
            ContentView::Binary { size: 4 }
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn merge_history_walks_both_native_parents() {
        let root = temp_root("merge-dag");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), "base\n").unwrap();
        repo.commit("Ada", "base").unwrap();
        repo.branch("feature").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("feature.txt"), "feature\n").unwrap();
        let feature = repo.commit("Ada", "feature").unwrap();
        repo.switch("main").unwrap();
        std::fs::write(root.join("main.txt"), "main\n").unwrap();
        let main = repo.commit("Grace", "main").unwrap();
        let merge = repo.merge("feature", "Ada").unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let history = desktop.select_reference("local:main").unwrap();
        let merge_node = history
            .snapshots
            .iter()
            .find(|snapshot| snapshot.id == merge.to_hex())
            .unwrap();
        assert!(merge_node.is_merge);
        assert_eq!(merge_node.parents, vec![main.to_hex(), feature.to_hex()]);
        assert!(history
            .snapshots
            .iter()
            .any(|node| node.id == main.to_hex()));
        assert!(history
            .snapshots
            .iter()
            .any(|node| node.id == feature.to_hex()));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_repository_and_traversal_are_typed_errors() {
        let empty = temp_root("not-a-repo");
        assert_eq!(
            DesktopRepository::open(&empty).unwrap_err().kind,
            "not_a_repository"
        );
        std::fs::remove_dir_all(empty).unwrap();

        let root = temp_root("traversal");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("public.txt"), "public\n").unwrap();
        let tip = repo.commit("Ada", "safe path").unwrap();
        drop(repo);
        let desktop = DesktopRepository::open(&root).unwrap();
        assert_eq!(
            desktop
                .read_file(&tip.to_hex(), "../public.txt")
                .unwrap_err()
                .kind,
            "invalid_selection"
        );
        let nul_error = desktop
            .read_file(&tip.to_hex(), "public\0.txt")
            .unwrap_err();
        assert_eq!(nul_error.kind, "invalid_selection");
        assert_eq!(
            nul_error.message,
            "file path is not a canonical repository-relative path"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unavailable_partial_clone_blob_is_visible_before_selection() {
        let root = temp_root("partial-tree-state");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("missing.txt"), "promised elsewhere\n").unwrap();
        let tip = repo.commit("Ada", "partial content").unwrap();
        let snapshot = repo.store().lock().unwrap().get_snapshot(&tip).unwrap();
        let blob = scl_repo::worktree::tree_file_entries_with_perms(
            &mut repo.store().lock().unwrap(),
            snapshot.root,
        )
        .unwrap()["missing.txt"]
            .0;
        repo.store().lock().unwrap().delete(&blob).unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let details = desktop.snapshot_details(&tip.to_hex()).unwrap();
        assert_eq!(
            details
                .tree
                .iter()
                .find(|file| file.path == "missing.txt")
                .unwrap()
                .content_state,
            ContentState::Unavailable
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_text_is_not_sent_to_the_renderer_or_diff_surface() {
        let root = temp_root("oversized-render-content");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("large.txt"), "small\n").unwrap();
        repo.commit("Ada", "small file").unwrap();
        let oversized = vec![b'a'; 4 * 1024 * 1024 + 1];
        std::fs::write(root.join("large.txt"), &oversized).unwrap();
        let tip = repo.commit("Ada", "large file").unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        assert_eq!(
            desktop
                .read_file(&tip.to_hex(), "large.txt")
                .unwrap()
                .content,
            ContentView::TooLarge {
                size: oversized.len()
            }
        );
        assert_eq!(
            desktop
                .compare_first_parent(&tip.to_hex(), "large.txt")
                .unwrap()
                .after,
            Some(ContentView::TooLarge {
                size: oversized.len()
            })
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_public_trust_configuration_is_not_silently_untrusted() {
        let root = temp_root("malformed-trust");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("README.md"), "native model\n").unwrap();
        repo.commit("Ada", "snapshot").unwrap();
        std::fs::write(repo.layout().dot_sc.join("recipients.toml"), "[signers\n").unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let error = desktop.select_reference("local:main").unwrap_err();
        assert_eq!(error.kind, "corrupt_repository");
        assert!(error.message.contains("public signer configuration"));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn public_files_render_but_protected_ciphertext_never_crosses_the_read_model() {
        let root = temp_root("content");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("public.txt"), "before\n").unwrap();
        std::fs::write(root.join("locked.txt"), "plaintext marker\n").unwrap();
        let first = repo.commit("Ada", "public files").unwrap();
        std::fs::write(root.join("public.txt"), "after\n").unwrap();
        let (_secret, public) = scl_crypto::generate_keypair();
        let tip = repo.protect("locked.txt", &[public], None).unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let details = desktop.snapshot_details(&tip.to_hex()).unwrap();
        assert!(details
            .tree
            .iter()
            .any(|file| file.path == "locked.txt"
                && file.content_state == ContentState::ProtectedLocked));

        let public = desktop.read_file(&tip.to_hex(), "public.txt").unwrap();
        assert_eq!(
            public.content,
            ContentView::Text {
                text: "after\n".into(),
                size: 6
            }
        );
        let locked = desktop.read_file(&tip.to_hex(), "locked.txt").unwrap();
        assert_eq!(locked.content, ContentView::ProtectedLocked);

        let comparison = desktop.snapshot_details(&tip.to_hex()).unwrap().comparison;
        assert!(comparison
            .changes
            .iter()
            .any(|change| { change.path == "locked.txt" && change.kind == ChangeKind::Protected }));
        // The first parent still held an ordinary public version, so it may be
        // shown as `before`; the protected `after` side has no byte field.
        let protected_change = desktop
            .compare_first_parent(&tip.to_hex(), "locked.txt")
            .unwrap();
        assert_eq!(protected_change.after, Some(ContentView::ProtectedLocked));
        assert_ne!(first, tip);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_branch_stops_at_opaque_manifest_metadata() {
        let root = temp_root("private");
        let repo = scl_repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("public.txt"), "base\n").unwrap();
        repo.commit("Ada", "base").unwrap();
        let (secret, public) = scl_crypto::generate_keypair();
        repo.branch_private("embargo", &secret, &[public], &[])
            .unwrap();
        drop(repo);

        let desktop = DesktopRepository::open(&root).unwrap();
        let overview = desktop.overview().unwrap();
        let private = overview
            .references
            .iter()
            .find(|reference| reference.name == "embargo")
            .unwrap();
        assert_eq!(private.access, ReferenceAccess::PrivateOpaque);
        assert!(private.opaque.is_some());
        let history = desktop.select_reference(&private.id).unwrap();
        assert!(history.snapshots.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }
}
