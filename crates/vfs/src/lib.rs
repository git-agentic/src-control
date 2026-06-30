//! `scl-vfs` — in-memory virtual worktree engine.
//!
//! A [`Worktree`] is a mutable, copy-on-write view over an immutable base
//! snapshot. Forking allocates only a small overlay; base blob bytes are shared
//! through the store and never duplicated, so forking N agents off one snapshot
//! is O(N) in overlay size, not repo size. Content lives only in RAM and touches
//! disk solely on an explicit [`Worktree::checkout`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use scl_core::{
    EntryKind, FileMode, Object, ObjectId, Protection, Secret, Snapshot, Store, StoreStats, Tree,
    TreeEntry,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] scl_core::Error),
    #[error("path not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// A shared object store plus the operations that fork worktrees from it.
#[derive(Clone)]
pub struct Repo {
    store: Arc<Mutex<Store>>,
}

impl Repo {
    pub fn new(store: Store) -> Self {
        Repo { store: Arc::new(Mutex::new(store)) }
    }

    pub fn store(&self) -> Arc<Mutex<Store>> {
        self.store.clone()
    }

    pub fn stats(&self) -> StoreStats {
        self.store.lock().unwrap().stats()
    }

    /// Insert a snapshot's full file set and return its snapshot id. Useful for
    /// seeding a repo without going through Git.
    pub fn commit_files(
        &self,
        files: &[(String, Vec<u8>, FileMode)],
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let mut map: BTreeMap<String, (ObjectId, FileMode)> = BTreeMap::new();
        {
            let mut store = self.store.lock().unwrap();
            for (path, bytes, mode) in files {
                let id = store.put(Object::blob(bytes.clone()))?;
                map.insert(normalize(path), (id, *mode));
            }
        }
        let root = self.build_tree(&map)?;
        let snap = Object::Snapshot(Snapshot {
            root,
            parents: vec![],
            author: author.into(),
            timestamp: 0,
            message: message.into(),
            secrets: BTreeMap::new(),
            protection: Protection::default(),
        });
        Ok(self.store.lock().unwrap().put(snap)?)
    }

    /// Put each file's blob and build the directory trees, returning the root
    /// tree id. Does not create a snapshot. Used by the persistent repo layer to
    /// snapshot a working directory.
    pub fn write_tree(&self, files: &[(String, Vec<u8>, FileMode)]) -> Result<ObjectId> {
        let mut map: BTreeMap<String, (ObjectId, FileMode)> = BTreeMap::new();
        {
            let mut store = self.store.lock().unwrap();
            for (path, bytes, mode) in files {
                let id = store.put(Object::blob(bytes.clone()))?;
                map.insert(normalize(path), (id, *mode));
            }
        }
        self.build_tree(&map)
    }

    /// Fork an in-memory worktree from a base snapshot. Cheap: allocates only an
    /// empty overlay; no file content is copied.
    pub fn fork(&self, snapshot: ObjectId, label: impl Into<String>) -> Result<Worktree> {
        let snap = self.store.lock().unwrap().get_snapshot(&snapshot)?;
        Ok(Worktree {
            store: self.store.clone(),
            base_snapshot: snapshot,
            base_root: snap.root,
            overlay: BTreeMap::new(),
            secrets: snap.secrets,
            protection: snap.protection,
            label: label.into(),
        })
    }

    /// Recursively build directory trees bottom-up from a flat path->(blob, mode)
    /// map, inserting each tree object, and return the root tree id.
    fn build_tree(&self, files: &BTreeMap<String, (ObjectId, FileMode)>) -> Result<ObjectId> {
        self.build_subtree(files, "")
    }

    fn build_subtree(
        &self,
        files: &BTreeMap<String, (ObjectId, FileMode)>,
        prefix: &str,
    ) -> Result<ObjectId> {
        // Partition entries directly under `prefix` into files vs subdirectories.
        let mut entries: Vec<TreeEntry> = Vec::new();
        let mut subdirs: BTreeMap<String, ()> = BTreeMap::new();

        for (path, (id, mode)) in files {
            let Some(rest) = strip_prefix_dir(path, prefix) else { continue };
            match rest.split_once('/') {
                None => entries.push(TreeEntry {
                    name: rest.to_string(),
                    kind: EntryKind::Blob,
                    id: *id,
                    mode: *mode,
                    perms: 0,
                }),
                Some((dir, _)) => {
                    subdirs.insert(dir.to_string(), ());
                }
            }
        }
        for dir in subdirs.keys() {
            let child_prefix = if prefix.is_empty() {
                format!("{dir}/")
            } else {
                format!("{prefix}{dir}/")
            };
            let sub_id = self.build_subtree(files, &child_prefix)?;
            entries.push(TreeEntry {
                name: dir.clone(),
                kind: EntryKind::Tree,
                id: sub_id,
                mode: FileMode(0o755),
                perms: 0,
            });
        }
        let tree = Object::Tree(Tree::new(entries));
        Ok(self.store.lock().unwrap().put(tree)?)
    }
}

/// A copy-on-write overlay entry.
enum Overlay {
    Written(Arc<[u8]>, FileMode),
    Removed,
}

/// A mutable in-RAM view over an immutable base snapshot.
pub struct Worktree {
    store: Arc<Mutex<Store>>,
    base_snapshot: ObjectId,
    base_root: ObjectId,
    overlay: BTreeMap<String, Overlay>,
    /// Committed-secret registry inherited from the base snapshot, plus local
    /// add/revoke edits. `name -> Secret object id`.
    secrets: std::collections::BTreeMap<String, ObjectId>,
    /// Encrypted-path policy carried from the base snapshot (P7).
    protection: Protection,
    label: String,
}

impl Worktree {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn base_snapshot(&self) -> ObjectId {
        self.base_snapshot
    }

    /// Read a file. Overlay wins over the base snapshot.
    pub fn read(&self, path: &str) -> Result<Arc<[u8]>> {
        let path = normalize(path);
        match self.overlay.get(&path) {
            Some(Overlay::Written(b, _)) => return Ok(b.clone()),
            Some(Overlay::Removed) => return Err(Error::NotFound(path)),
            None => {}
        }
        let id = self
            .resolve_base(&path)?
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        match self.store.lock().unwrap().get(&id)? {
            Object::Blob(b) => Ok(b),
            _ => Err(Error::NotFound(path)),
        }
    }

    /// Stage a write into the overlay (in RAM, pinned — never spilled).
    pub fn write(&mut self, path: &str, bytes: impl Into<Vec<u8>>, mode: FileMode) {
        let arc: Arc<[u8]> = Arc::from(bytes.into().into_boxed_slice());
        self.overlay.insert(normalize(path), Overlay::Written(arc, mode));
    }

    /// Tombstone a path in the overlay.
    pub fn remove(&mut self, path: &str) {
        self.overlay.insert(normalize(path), Overlay::Removed);
    }

    /// Store a sealed secret and register it by name (overwriting any prior
    /// secret with the same name). Overwriting a name only updates the registry
    /// pointer; the previous content-addressed Secret object remains in the store.
    pub fn put_secret(&mut self, secret: Secret) -> Result<ObjectId> {
        let name = secret.name.clone();
        let id = self.store.lock().unwrap().put(Object::Secret(secret))?;
        self.secrets.insert(name, id);
        Ok(id)
    }

    /// Drop a secret from the registry.
    pub fn remove_secret(&mut self, name: &str) {
        self.secrets.remove(name);
    }

    /// The committed-secret registry as `(name, id)` pairs.
    pub fn list_secrets(&self) -> Vec<(String, ObjectId)> {
        self.secrets.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// The Secret object id registered under `name`, if any.
    pub fn secret_id(&self, name: &str) -> Option<ObjectId> {
        self.secrets.get(name).copied()
    }

    pub fn exists(&self, path: &str) -> bool {
        let path = normalize(path);
        match self.overlay.get(&path) {
            Some(Overlay::Written(..)) => true,
            Some(Overlay::Removed) => false,
            None => self.resolve_base(&path).ok().flatten().is_some(),
        }
    }

    /// The effective file set: base ∪ overlay-writes − overlay-removals.
    pub fn list(&self) -> Result<Vec<String>> {
        let mut set: BTreeMap<String, ()> = BTreeMap::new();
        for (p, _, _) in self.walk_base()? {
            set.insert(p, ());
        }
        for (p, ov) in &self.overlay {
            match ov {
                Overlay::Written(..) => {
                    set.insert(p.clone(), ());
                }
                Overlay::Removed => {
                    set.remove(p);
                }
            }
        }
        Ok(set.into_keys().collect())
    }

    /// Bytes of dirty overlay content held in this worktree (not counted against
    /// the store's blob budget until flushed by a commit).
    pub fn overlay_footprint(&self) -> usize {
        self.overlay
            .values()
            .map(|o| match o {
                Overlay::Written(b, _) => b.len(),
                Overlay::Removed => 0,
            })
            .sum()
    }

    /// Flush the effective file set into the store as a new snapshot.
    pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
        let mut map: BTreeMap<String, (ObjectId, FileMode)> = BTreeMap::new();
        // Base files first.
        for (path, id, mode) in self.walk_base()? {
            map.insert(path, (id, mode));
        }
        // Apply overlay.
        {
            let mut store = self.store.lock().unwrap();
            for (path, ov) in &self.overlay {
                match ov {
                    Overlay::Written(b, mode) => {
                        let id = store.put(Object::Blob(b.clone()))?;
                        map.insert(path.clone(), (id, *mode));
                    }
                    Overlay::Removed => {
                        map.remove(path);
                    }
                }
            }
        }
        let repo = Repo { store: self.store.clone() };
        let root = repo.build_tree(&map)?;
        let snap = Object::Snapshot(Snapshot {
            root,
            parents: vec![self.base_snapshot],
            author: author.into(),
            timestamp: 0,
            message: message.into(),
            secrets: self.secrets.clone(),
            protection: self.protection.clone(),
        });
        Ok(self.store.lock().unwrap().put(snap)?)
    }

    /// Materialize the effective file set to a real directory on disk. This is
    /// the only operation in the engine that writes files; the caller owns the
    /// destination and is responsible for removing it.
    pub fn checkout(&self, dest: &Path) -> Result<usize> {
        std::fs::create_dir_all(dest)?;
        let mut count = 0;
        for path in self.list()? {
            let bytes = self.read(&path)?;
            let full = dest.join(&path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&full, &bytes[..])?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = self.mode_of(&path);
                std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode.0))?;
            }
            count += 1;
        }
        Ok(count)
    }

    fn mode_of(&self, path: &str) -> FileMode {
        if let Some(Overlay::Written(_, m)) = self.overlay.get(path) {
            return *m;
        }
        self.walk_base()
            .ok()
            .and_then(|v| v.into_iter().find(|(p, _, _)| p == path).map(|(_, _, m)| m))
            .unwrap_or(FileMode::FILE)
    }

    // ---- base snapshot traversal -------------------------------------------

    /// Resolve a path to its blob id in the base snapshot, if present.
    fn resolve_base(&self, path: &str) -> Result<Option<ObjectId>> {
        let mut store = self.store.lock().unwrap();
        let mut tree_id = self.base_root;
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for (i, comp) in comps.iter().enumerate() {
            let tree = store.get_tree(&tree_id)?;
            let Some(entry) = tree.get(comp) else { return Ok(None) };
            let last = i == comps.len() - 1;
            match entry.kind {
                EntryKind::Blob if last => return Ok(Some(entry.id)),
                EntryKind::Tree if !last => tree_id = entry.id,
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Flatten the base snapshot into (path, blob id, mode) triples.
    fn walk_base(&self) -> Result<Vec<(String, ObjectId, FileMode)>> {
        let mut out = Vec::new();
        let mut store = self.store.lock().unwrap();
        walk(&mut store, self.base_root, String::new(), &mut out)?;
        Ok(out)
    }
}

fn walk(
    store: &mut Store,
    tree_id: ObjectId,
    prefix: String,
    out: &mut Vec<(String, ObjectId, FileMode)>,
) -> Result<()> {
    let tree = store.get_tree(&tree_id)?;
    for e in tree.entries {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        match e.kind {
            EntryKind::Blob => out.push((path, e.id, e.mode)),
            EntryKind::Tree => walk(store, e.id, path, out)?,
        }
    }
    Ok(())
}

fn normalize(path: &str) -> String {
    path.trim_start_matches("./")
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// If `path` lies under directory `prefix` (which is "" or ends with '/'),
/// return the remainder; otherwise None.
fn strip_prefix_dir<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        Some(path)
    } else {
        path.strip_prefix(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::StoreConfig;

    fn repo() -> Repo {
        Repo::new(Store::new(StoreConfig::default()))
    }

    fn seed(repo: &Repo) -> ObjectId {
        repo.commit_files(
            &[
                ("README.md".into(), b"hello".to_vec(), FileMode::FILE),
                ("src/main.rs".into(), b"fn main() {}".to_vec(), FileMode::FILE),
                ("src/lib.rs".into(), b"// lib".to_vec(), FileMode::FILE),
            ],
            "seed",
            "init",
        )
        .unwrap()
    }

    #[test]
    fn fork_reads_base_content() {
        let r = repo();
        let snap = seed(&r);
        let wt = r.fork(snap, "agent-0").unwrap();
        assert_eq!(&wt.read("README.md").unwrap()[..], b"hello");
        assert_eq!(&wt.read("src/main.rs").unwrap()[..], b"fn main() {}");
        let mut files = wt.list().unwrap();
        files.sort();
        assert_eq!(files, vec!["README.md", "src/lib.rs", "src/main.rs"]);
    }

    #[test]
    fn parallel_forks_are_isolated() {
        let r = repo();
        let snap = seed(&r);
        let mut a = r.fork(snap, "a").unwrap();
        let mut b = r.fork(snap, "b").unwrap();
        a.write("README.md", b"changed-by-a".to_vec(), FileMode::FILE);
        b.remove("src/lib.rs");
        // Each worktree sees only its own edits.
        assert_eq!(&a.read("README.md").unwrap()[..], b"changed-by-a");
        assert_eq!(&b.read("README.md").unwrap()[..], b"hello");
        assert!(a.exists("src/lib.rs"));
        assert!(!b.exists("src/lib.rs"));
    }

    #[test]
    fn checkout_materializes_then_can_be_removed() {
        let r = repo();
        let snap = seed(&r);
        let mut wt = r.fork(snap, "a").unwrap();
        wt.write("new.txt", b"fresh".to_vec(), FileMode::FILE);
        let dest = std::env::temp_dir().join(format!("scl-co-{}", std::process::id()));
        let n = wt.checkout(&dest).unwrap();
        assert_eq!(n, 4);
        assert_eq!(std::fs::read(dest.join("new.txt")).unwrap(), b"fresh");
        std::fs::remove_dir_all(&dest).unwrap();
        assert!(!dest.exists());
    }

    #[test]
    fn commit_overlay_produces_new_snapshot() {
        let r = repo();
        let snap = seed(&r);
        let mut wt = r.fork(snap, "a").unwrap();
        wt.write("README.md", b"v2".to_vec(), FileMode::FILE);
        let new_snap = wt.commit("a", "update readme").unwrap();
        assert_ne!(new_snap, snap);
        let wt2 = r.fork(new_snap, "verifier").unwrap();
        assert_eq!(&wt2.read("README.md").unwrap()[..], b"v2");
    }

    #[test]
    fn write_tree_then_fork_reads_files() {
        let r = repo();
        let root = r
            .write_tree(&[
                ("a.txt".into(), b"A".to_vec(), FileMode::FILE),
                ("dir/b.txt".into(), b"B".to_vec(), FileMode::FILE),
            ])
            .unwrap();
        let snap = {
            let store_arc = r.store();
            let mut store = store_arc.lock().unwrap();
            store
                .put(Object::Snapshot(scl_core::Snapshot {
                    root,
                    parents: vec![],
                    author: "t".into(),
                    timestamp: 0,
                    message: "m".into(),
                    secrets: std::collections::BTreeMap::new(),
                    protection: Default::default(),
                }))
                .unwrap()
        };
        let wt = r.fork(snap, "v").unwrap();
        assert_eq!(&wt.read("a.txt").unwrap()[..], b"A");
        assert_eq!(&wt.read("dir/b.txt").unwrap()[..], b"B");
    }

    #[test]
    fn secrets_carry_through_fork_and_commit_but_never_check_out() {
        use scl_core::{Secret, WrappedKey};
        let r = repo();
        let snap = seed(&r);
        let mut wt = r.fork(snap, "setup").unwrap();
        wt.put_secret(Secret {
            name: "DB_URL".into(),
            nonce: vec![0; 24],
            ciphertext: vec![1, 2, 3, 4],
            wrapped_keys: vec![WrappedKey { recipient_id: "rid".into(), wrapped_dek: vec![7; 80] }],
        })
        .unwrap();
        let snap2 = wt.commit("setup", "add secret").unwrap();

        // Registry survives a fresh fork.
        let wt2 = r.fork(snap2, "consumer").unwrap();
        assert_eq!(wt2.list_secrets().len(), 1);
        assert!(wt2.secret_id("DB_URL").is_some());

        // The secret is NOT a file: absent from list() and from checkout.
        assert!(!wt2.list().unwrap().iter().any(|p| p.contains("DB_URL")));
        let dest = std::env::temp_dir().join(format!("scl-secret-co-{}", std::process::id()));
        let n = wt2.checkout(&dest).unwrap();
        // Checked-out file count equals the visible file set: secrets excluded.
        assert_eq!(n, wt2.list().unwrap().len());
        assert!(!dest.join("DB_URL").exists());
        std::fs::remove_dir_all(&dest).unwrap();
        assert!(!dest.exists());
    }
}
